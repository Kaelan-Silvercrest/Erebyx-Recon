"""Lookup RDAP, record DNS lengkap, postur keamanan email, dan subdomain CT untuk satu domain."""

import re
from typing import Any

import requests

from erebyx.core.module_base import ModuleResult, OSINTModule
from erebyx.i18n import t
from erebyx.utils.dns_lookup import resolve_records
from erebyx.utils.http_client import HttpClient

DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "CNAME")


class DomainLookupModule(OSINTModule):
    name = "domain_lookup"
    description = (
        "Recon mendalam domain: RDAP, DNS lengkap, SPF/DMARC/CAA, & subdomain CT"
    )
    category = "generic"
    requires_api_key = False
    rate_limit_seconds = 0.4

    def validate_target(self, target: str) -> bool:
        candidate = target.strip().lower()
        if not candidate or len(candidate) > 253:
            return False
        pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
        return bool(re.fullmatch(pattern, candidate))

    def run(self, target: str) -> ModuleResult:
        domain = target.strip().lower()
        if not self.validate_target(domain):
            return self._fail(target, t("err.invalid_domain"))
        client = HttpClient(rate_limit_seconds=self.rate_limit_seconds)
        rdap_url = f"https://rdap.org/domain/{domain}"
        warnings: list[str] = []
        source_urls: list[str] = [rdap_url]
        rdap_data: dict[str, Any] = {}

        try:
            response = client.get(rdap_url, headers={"Accept": "application/rdap+json"})
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError(t("err.not_json"))
            secure_dns = payload.get("secureDNS")
            dnssec_signed = (
                secure_dns.get("delegationSigned")
                if isinstance(secure_dns, dict)
                else None
            )
            rdap_data = {
                "handle": payload.get("handle"),
                "status": payload.get("status", []),
                "registrar": _registrar_name(payload.get("entities", [])),
                "abuse_contact": _abuse_contact(payload.get("entities", [])),
                "dnssec_signed": dnssec_signed,
                "dates": _rdap_dates(payload.get("events", [])),
                "nameservers": [
                    item.get("ldhName")
                    for item in payload.get("nameservers", [])
                    if isinstance(item, dict) and item.get("ldhName")
                ],
            }
        except (requests.RequestException, ValueError) as exc:
            warnings.append(t("warn.rdap_unavailable", error=_short_net_error(exc)))

        dns_records: dict[str, list[str]] = {}
        for record_type in DNS_RECORD_TYPES:
            records, error = resolve_records(domain, record_type)
            dns_records[record_type] = records
            if error:
                warnings.append(t("warn.dns", rtype=record_type, error=error))

        dmarc_records, dmarc_error = resolve_records(f"_dmarc.{domain}", "TXT")
        if dmarc_error and dmarc_error not in (
            t("dns.nxdomain"),
            "domain tidak ditemukan",
            "domain does not exist",
        ):
            warnings.append(t("warn.dns", rtype="DMARC", error=dmarc_error))

        email_security = _analyze_email_security(
            txt_records=dns_records.get("TXT", []),
            dmarc_records=dmarc_records,
            caa_records=dns_records.get("CAA", []),
        )

        subdomains, ct_used_url, ct_warning = _fetch_ct_subdomains(client, domain)
        if ct_used_url:
            source_urls.append(ct_used_url)
        if ct_warning:
            warnings.append(ct_warning)

        return self._success(
            target=domain,
            data={
                "rdap": rdap_data,
                "dns_records": dns_records,
                "email_security": email_security,
                "subdomains_discovered": subdomains,
                "subdomain_count": len(subdomains),
                "warnings": warnings,
            },
            source_urls=source_urls,
        )


def _short_net_error(exc: Exception) -> str:
    if isinstance(exc, requests.Timeout):
        return t("net.timeout")
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        return f"HTTP {exc.response.status_code}"
    if isinstance(exc, requests.ConnectionError):
        return t("net.connection")
    return str(exc)


def _rdap_dates(events: list[dict[str, Any]]) -> dict[str, str]:
    date_fields = {
        "registration": "created",
        "expiration": "expires",
        "last changed": "updated",
    }
    dates: dict[str, str] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        action = event.get("eventAction")
        date = event.get("eventDate")
        if isinstance(action, str) and action.lower() in date_fields and isinstance(date, str):
            dates[date_fields[action.lower()]] = date
    return dates


def _registrar_name(entities: list[dict[str, Any]]) -> str | None:
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        if "registrar" not in entity.get("roles", []):
            continue
        vcard = entity.get("vcardArray", [])
        if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
            continue
        for entry in vcard[1]:
            if isinstance(entry, list) and len(entry) >= 4 and entry[0] == "fn":
                return str(entry[3])
    return None


def _abuse_contact(entities: list[dict[str, Any]]) -> str | None:
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        if "abuse" in entity.get("roles", []):
            email = _extract_vcard_field(entity.get("vcardArray", []), "email")
            if email:
                return email
        nested = entity.get("entities", [])
        if isinstance(nested, list):
            found = _abuse_contact(nested)
            if found:
                return found
    return None


def _extract_vcard_field(vcard: Any, field_name: str) -> str | None:
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for entry in vcard[1]:
        if isinstance(entry, list) and len(entry) >= 4 and entry[0] == field_name:
            return str(entry[3])
    return None


def _analyze_email_security(
    txt_records: list[str],
    dmarc_records: list[str],
    caa_records: list[str],
) -> dict[str, Any]:
    cleaned_txt = [r.strip('"') for r in txt_records]
    spf_records = [r for r in cleaned_txt if r.lower().startswith("v=spf1")]
    cleaned_dmarc = [
        r.strip('"') for r in dmarc_records if "v=dmarc1" in r.lower()
    ]

    spf_policy = "missing"
    if spf_records:
        spf_text = " ".join(spf_records).lower()
        if "-all" in spf_text:
            spf_policy = "strict (-all)"
        elif "~all" in spf_text:
            spf_policy = "softfail (~all)"
        elif "?all" in spf_text:
            spf_policy = "neutral (?all)"
        elif "+all" in spf_text:
            spf_policy = "permissive (+all)"
        else:
            spf_policy = "present (no explicit all)"

    dmarc_policy = "missing"
    if cleaned_dmarc:
        match = re.search(r"\bp=([a-zA-Z]+)", " ".join(cleaned_dmarc))
        dmarc_policy = match.group(1).lower() if match else "present"

    return {
        "spf_records": spf_records,
        "spf_policy": spf_policy,
        "dmarc_records": cleaned_dmarc,
        "dmarc_policy": dmarc_policy,
        "has_caa": bool(caa_records),
    }


def _collect_matching_names(raw_names: list[str], domain: str) -> set[str]:
    found: set[str] = set()
    suffix = f".{domain}"
    for raw in raw_names:
        candidate = raw.strip().lower().lstrip("*.")
        if candidate == domain or candidate.endswith(suffix):
            found.add(candidate)
    return found


def _fetch_ct_subdomains(
    client: HttpClient, domain: str
) -> tuple[list[str], str, str | None]:
    """
    Coba ambil subdomain pasif dari crt.sh terlebih dahulu; jika crt.sh lambat/timeout
    atau error, otomatis fallback ke endpoint publik CertSpotter.
    """
    crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
    spotter_url = (
        f"https://api.certspotter.com/v1/issuances"
        f"?domain={domain}&include_subdomains=true&expand=dns_names"
    )

    try:
        response = client.get(
            crt_url, headers={"Accept": "application/json"}, timeout=6
        )
        response.raise_for_status()
        entries = response.json()
        if not isinstance(entries, list):
            raise ValueError(t("err.not_json_list"))
        raw_names: list[str] = []
        for item in entries:
            if isinstance(item, dict):
                raw_names.extend(str(item.get("name_value", "")).splitlines())
        subdomains = _collect_matching_names(raw_names, domain)
        return sorted(subdomains)[:250], crt_url, None
    except (requests.RequestException, ValueError) as crt_exc:
        crt_err = _short_net_error(crt_exc)

    try:
        response = client.get(
            spotter_url, headers={"Accept": "application/json"}, timeout=6
        )
        response.raise_for_status()
        entries = response.json()
        if not isinstance(entries, list):
            raise ValueError(t("err.not_json_list"))
        raw_names = []
        for item in entries:
            if isinstance(item, dict):
                dns_names = item.get("dns_names", [])
                if isinstance(dns_names, list):
                    raw_names.extend(str(n) for n in dns_names)
        subdomains = _collect_matching_names(raw_names, domain)
        return sorted(subdomains)[:250], spotter_url, None
    except (requests.RequestException, ValueError) as spotter_exc:
        spotter_err = _short_net_error(spotter_exc)

    return (
        [],
        crt_url,
        t("warn.ct_unavailable", crt=crt_err, spotter=spotter_err),
    )
