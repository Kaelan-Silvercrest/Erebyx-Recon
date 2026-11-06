"""Temukan alamat kontak umum, security.txt (RFC 9116), dan postur header HTTP pada situs organisasi."""

import html
import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from erebyx.core.module_base import ModuleResult, OSINTModule
from erebyx.i18n import t
from erebyx.utils.http_client import HttpClient

MAX_PAGE_BYTES = 512_000
CONTACT_PATHS = (
    "/",
    "/contact",
    "/contact-us",
    "/about",
    "/security",
    "/.well-known/security.txt",
    "/security.txt",
)
SECURITY_TXT_PATHS = ("/.well-known/security.txt", "/security.txt")
ROLE_MAILBOXES = {
    "abuse",
    "admin",
    "billing",
    "cert",
    "compliance",
    "contact",
    "csirt",
    "dpo",
    "hello",
    "help",
    "hostmaster",
    "hr",
    "incident",
    "info",
    "legal",
    "media",
    "noc",
    "office",
    "ops",
    "postmaster",
    "pr",
    "press",
    "privacy",
    "psirt",
    "sales",
    "security",
    "soc",
    "support",
    "team",
    "webmaster",
}
SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Server",
)
EMAIL_PATTERN = re.compile(
    r"(?i)\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9.-]*[A-Z0-9])?\.[A-Z]{2,63}\b"
)
SECURITY_TXT_FIELDS = {
    "contact",
    "expires",
    "encryption",
    "acknowledgments",
    "preferred-languages",
    "canonical",
    "policy",
    "hiring",
}


class PublicContactLookupModule(OSINTModule):
    name = "public_contact_lookup"
    description = (
        "Cari email role organisasi, RFC 9116 security.txt, dan header keamanan HTTP"
    )
    category = "generic"
    requires_api_key = False
    rate_limit_seconds = 0.3

    def validate_target(self, target: str) -> bool:
        candidate = target.strip().lower()
        return _valid_domain(candidate)

    def run(self, target: str) -> ModuleResult:
        domain = target.strip().lower().rstrip(".")
        if not _valid_domain(domain):
            return self._fail(target, t("err.invalid_domain"))
        warnings: list[str] = []
        contacts: set[str] = set()
        pages_checked: list[str] = []
        pages_found: list[str] = []
        security_txt_data: dict[str, list[str]] = {}
        http_security_headers: dict[str, str | None] = {}

        try:
            _require_public_host(domain)
        except (OSError, ValueError) as exc:
            return self._fail(target, t("err.unsafe_host", error=exc))

        allowed_hosts = {domain, f"www.{domain}"}
        client = HttpClient(rate_limit_seconds=self.rate_limit_seconds)
        for path in CONTACT_PATHS:
            url = f"https://{domain}{path}"
            pages_checked.append(url)
            try:
                response = _get_same_site(client, url, allowed_hosts, warnings)
                if response is None:
                    continue
                with response:
                    if path == "/" and not http_security_headers:
                        http_security_headers = _extract_security_headers(
                            response.headers
                        )
                    if response.status_code in (404, 410) and path != "/":
                        # Path opsional (/contact, /security.txt, dll.) wajar jika tidak ada
                        continue
                    if response.status_code != 200:
                        warnings.append(
                            t("warn.http_status", status=response.status_code, url=url)
                        )
                        continue

                    pages_found.append(url)
                    content_type = response.headers.get("Content-Type", "").lower()
                    is_sec_txt = path in SECURITY_TXT_PATHS
                    if not is_sec_txt and "text/html" not in content_type:
                        continue
                    if is_sec_txt and not (
                        "text/plain" in content_type or "text/html" in content_type
                    ):
                        continue

                    chunks: list[bytes] = []
                    size = 0
                    for chunk in response.iter_content(chunk_size=8192):
                        if not chunk:
                            continue
                        remaining = MAX_PAGE_BYTES - size
                        chunks.append(chunk[:remaining])
                        size += min(len(chunk), remaining)
                        if len(chunk) > remaining:
                            warnings.append(t("warn.truncated", url=url))
                            break
                    page = b"".join(chunks).decode(
                        response.encoding or "utf-8", errors="replace"
                    )
                    contacts.update(_public_role_addresses(page, domain))
                    if is_sec_txt and "text/plain" in content_type and not security_txt_data:
                        parsed_sec = _parse_security_txt(page)
                        if parsed_sec:
                            security_txt_data = parsed_sec
            except requests.RequestException as exc:
                warnings.append(t("warn.fetch_failed", url=url, error=exc))
            except (OSError, ValueError) as exc:
                warnings.append(t("warn.fetch_failed", url=url, error=exc))

        return self._success(
            target=domain,
            data={
                "public_role_addresses": sorted(contacts),
                "security_txt": security_txt_data,
                "http_security_headers": http_security_headers,
                "pages_found": pages_found,
                "pages_checked": pages_checked,
                "warnings": warnings,
                "note": t("note.contact"),
            },
            source_urls=pages_found or pages_checked,
        )


def _get_same_site(
    client: HttpClient,
    url: str,
    allowed_hosts: set[str],
    warnings: list[str],
    max_hops: int = 2,
) -> requests.Response | None:
    current = url
    for _ in range(max_hops + 1):
        response = client.get(current, allow_redirects=False, stream=True)
        if not (300 <= response.status_code < 400):
            return response
        location = response.headers.get("Location", "")
        response.close()
        if not location:
            return None
        next_url = urljoin(current, location)
        parsed = urlparse(next_url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or host not in allowed_hosts:
            warnings.append(
                t("warn.redirect_offsite", url=current, location=next_url)
            )
            return None
        current = next_url
    return None


def _require_public_host(hostname: str) -> None:
    addresses = {
        result[4][0]
        for result in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    }
    if not addresses:
        raise OSError(t("err.no_ip"))
    if any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError(t("err.private_ip"))


def _public_role_addresses(page: str, domain: str) -> set[str]:
    addresses: set[str] = set()
    decoded_page = html.unescape(page)
    for match in EMAIL_PATTERN.findall(decoded_page):
        address = match.rstrip(".,;:!?")
        local, separator, email_domain = address.rpartition("@")
        if not separator or email_domain.lower() not in {
            domain,
            f"www.{domain}",
        }:
            continue
        mailbox = local.split("+", 1)[0].lower()
        if mailbox in ROLE_MAILBOXES:
            addresses.add(address.lower())
    return addresses


def _parse_security_txt(content: str) -> dict[str, list[str]]:
    parsed: dict[str, list[str]] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        field_name, _, value = line.partition(":")
        key = field_name.strip().lower()
        val = value.strip()
        if key in SECURITY_TXT_FIELDS and val:
            parsed.setdefault(key, []).append(val)
    return parsed


def _extract_security_headers(headers: Any) -> dict[str, str | None]:
    return {header: headers.get(header) for header in SECURITY_HEADERS}


def _valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
    return bool(re.fullmatch(pattern, domain))
