"""Helper untuk lookup DNS dengan error yang bisa dilaporkan pemanggil."""

import dns.exception
import dns.resolver

from erebyx.i18n import t


def resolve_records(
    hostname: str, record_type: str
) -> tuple[list[str], str | None]:
    try:
        answers = dns.resolver.resolve(hostname, record_type, lifetime=4.0)
    except dns.resolver.NoAnswer:
        return [], None
    except dns.resolver.NXDOMAIN:
        return [], t("dns.nxdomain")
    except dns.exception.Timeout:
        return [], t("dns.timeout")
    except dns.exception.DNSException as exc:
        return [], str(exc)

    return [answer.to_text() for answer in answers], None
