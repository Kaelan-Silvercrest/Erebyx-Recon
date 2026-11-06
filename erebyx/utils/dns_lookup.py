"""Helper untuk lookup DNS dengan error yang bisa dilaporkan pemanggil."""

import os
import shutil
import subprocess
from pathlib import Path

import dns.exception
import dns.resolver

from erebyx.i18n import t

DEFAULT_NAMESERVERS: list[str] = [
    "1.1.1.1",
    "8.8.8.8",
    "1.0.0.1",
    "8.8.4.4",
]

_resolver: dns.resolver.Resolver | None = None


def _get_android_dns_servers() -> list[str]:
    """Cari nameserver DNS dari properti sistem Android via getprop."""
    servers: list[str] = []
    getprop_path = shutil.which("getprop")
    if not getprop_path and os.path.exists("/system/bin/getprop"):
        getprop_path = "/system/bin/getprop"

    if getprop_path:
        for prop in ("net.dns1", "net.dns2", "net.dns3", "net.dns4"):
            try:
                res = subprocess.run(
                    [getprop_path, prop],
                    capture_output=True,
                    text=True,
                    timeout=1.0,
                    check=False,
                )
                val = res.stdout.strip()
                if val and val not in servers:
                    servers.append(val)
            except Exception:
                pass
    return servers


def get_resolver(force_refresh: bool = False) -> dns.resolver.Resolver:
    """
    Buat atau ambil DNS resolver yang dikonfigurasi.

    Mendukung:
    1. Override manual via environment variable EREBYX_DNS_SERVERS (contoh: "1.1.1.1,8.8.8.8")
    2. Konfigurasi bawaan sistem (/etc/resolv.conf)
    3. Lingkungan Termux / Android tanpa /etc/resolv.conf:
       - Membaca $PREFIX/etc/resolv.conf bila ada
       - Membaca properti sistem Android (getprop net.dns*)
       - Fallback otomatis ke public DNS resolver (Cloudflare 1.1.1.1 & Google 8.8.8.8)
    """
    global _resolver
    if _resolver is not None and not force_refresh:
        return _resolver

    # 1. User override via EREBYX_DNS_SERVERS
    env_servers = os.environ.get("EREBYX_DNS_SERVERS")
    if env_servers:
        servers = [
            s.strip()
            for s in env_servers.replace(",", " ").split()
            if s.strip()
        ]
        if servers:
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = servers
            r.timeout = 3.0
            r.lifetime = 4.0
            _resolver = r
            dns.resolver.default_resolver = r
            return r

    # 2. Coba resolver default sistem (/etc/resolv.conf)
    try:
        r = dns.resolver.Resolver()
        if r.nameservers:
            r.timeout = 3.0
            r.lifetime = 4.0
            _resolver = r
            dns.resolver.default_resolver = r
            return r
    except (dns.resolver.NoResolverConfiguration, FileNotFoundError, PermissionError, OSError):
        pass

    # 3. Lingkungan tanpa /etc/resolv.conf (Termux, Android, minimal container)
    r = dns.resolver.Resolver(configure=False)

    # 3a. Periksa $PREFIX/etc/resolv.conf di Termux
    prefix = os.environ.get("PREFIX")
    if prefix:
        termux_resolv = Path(prefix) / "etc" / "resolv.conf"
        if termux_resolv.is_file():
            try:
                r.read_resolv_conf(str(termux_resolv))
            except Exception:
                pass

    # 3b. Periksa properti DNS Android jika belum ada nameserver
    if not r.nameservers:
        android_servers = _get_android_dns_servers()
        if android_servers:
            r.nameservers = android_servers

    # 3c. Fallback ke public resolver jika nameserver masih kosong
    if not r.nameservers:
        r.nameservers = list(DEFAULT_NAMESERVERS)

    r.timeout = 3.0
    r.lifetime = 4.0
    _resolver = r
    dns.resolver.default_resolver = r
    return r


def reset_resolver() -> None:
    """Reset resolver cache (terutama untuk pengujian)."""
    global _resolver
    _resolver = None


def classify_dns_error(error: str | None) -> str | None:
    """Kategorikan pesan error DNS ke kode standar."""
    if not error:
        return None
    err_lower = str(error).strip().lower()
    if (
        "resolver_unavailable" in err_lower
        or "cannot open" in err_lower
        or "resolv.conf" in err_lower
        or "no resolver configuration" in err_lower
        or "network is unreachable" in err_lower
        or "network unreachable" in err_lower
        or "no nameservers" in err_lower
        or "no_nameservers" in err_lower
    ):
        return "RESOLVER_UNAVAILABLE"
    if "timeout" in err_lower:
        return "TIMEOUT"
    if (
        "nxdomain" in err_lower
        or "does not exist" in err_lower
        or "tidak ditemukan" in err_lower
    ):
        return "NXDOMAIN"
    return "DNS_QUERY_FAILED"


class DnsResult(tuple):
    """
    Subclass tuple yang kompatibel penuh dengan format (records, error)
    sekaligus menyediakan atribut `.records`, `.error`, dan `.reason`.
    """

    records: list[str]
    error: str | None
    reason: str | None

    def __new__(
        cls,
        records: list[str],
        error: str | None = None,
        reason: str | None = None,
    ):
        return super().__new__(cls, (records, error))

    def __init__(
        self,
        records: list[str],
        error: str | None = None,
        reason: str | None = None,
    ):
        self.records = records
        self.error = error
        self.reason = reason or (classify_dns_error(error) if error else None)


def resolve_records(
    hostname: str, record_type: str, lifetime: float = 4.0
) -> DnsResult:
    try:
        resolver = get_resolver()
        answers = resolver.resolve(hostname, record_type, lifetime=lifetime)
    except dns.resolver.NoAnswer:
        return DnsResult([], None, None)
    except dns.resolver.NXDOMAIN:
        return DnsResult([], t("dns.nxdomain"), "NXDOMAIN")
    except dns.exception.Timeout:
        return DnsResult([], t("dns.timeout"), "TIMEOUT")
    except dns.resolver.NoResolverConfiguration as exc:
        return DnsResult([], str(exc), "RESOLVER_UNAVAILABLE")
    except dns.resolver.NoNameservers as exc:
        err_msg = str(exc)
        reason = (
            "RESOLVER_UNAVAILABLE"
            if ("network is unreachable" in err_msg.lower() or "cannot open" in err_msg.lower())
            else "NO_NAMESERVERS"
        )
        return DnsResult([], err_msg, reason)
    except dns.exception.DNSException as exc:
        err_msg = str(exc)
        return DnsResult([], err_msg, classify_dns_error(err_msg))
    except Exception as exc:
        err_msg = str(exc)
        return DnsResult([], err_msg, classify_dns_error(err_msg))

    return DnsResult([answer.to_text() for answer in answers], None, None)
