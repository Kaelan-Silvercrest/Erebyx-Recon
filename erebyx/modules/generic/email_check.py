"""Validasi format alamat email, profil akun, dan postur keamanan MX/SPF/DMARC domain."""

import re

from erebyx.core.module_base import ModuleResult, OSINTModule
from erebyx.i18n import t
from erebyx.utils.dns_lookup import resolve_records

DISPOSABLE_DOMAINS = {
    "10minutemail.com",
    "guerrillamail.com",
    "mailinator.com",
    "tempmail.com",
    "throwawaymail.com",
    "trashmail.com",
    "yopmail.com",
}

ROLE_ACCOUNTS = {
    "abuse",
    "admin",
    "billing",
    "compliance",
    "contact",
    "csirt",
    "dpo",
    "help",
    "hello",
    "hostmaster",
    "hr",
    "info",
    "legal",
    "media",
    "noc",
    "noreply",
    "no-reply",
    "office",
    "ops",
    "postmaster",
    "press",
    "privacy",
    "sales",
    "security",
    "soc",
    "support",
    "webmaster",
}


class EmailCheckModule(OSINTModule):
    name = "email_check"
    description = (
        "Validasi email, deteksi role/disposable, dan audit MX/SPF/DMARC domain"
    )
    category = "generic"
    requires_api_key = False

    def validate_target(self, target: str) -> bool:
        candidate = target.strip()
        if not candidate or len(candidate) > 254 or candidate.count("@") != 1:
            return False
        local, domain = candidate.rsplit("@", 1)
        if (
            len(local) > 64
            or local.startswith(".")
            or local.endswith(".")
            or ".." in local
        ):
            return False
        pattern = r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$"
        domain_pattern = (
            r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
            r"[A-Za-z]{2,63}$"
        )
        return bool(
            re.fullmatch(pattern, local)
            and re.fullmatch(domain_pattern, domain)
        )

    def run(self, target: str) -> ModuleResult:
        target = target.strip()
        if not self.validate_target(target):
            return self._fail(target, t("err.invalid_email"))

        local_part, domain = target.rsplit("@", 1)
        domain = domain.lower()
        base_mailbox, _, plus_tag = local_part.partition("+")
        is_role = base_mailbox.lower() in {r.lower() for r in ROLE_ACCOUNTS}
        is_disposable = domain in DISPOSABLE_DOMAINS

        mx_records, mx_error = resolve_records(domain, "MX")
        fallback_records: list[str] = []
        fallback_error: str | None = None

        if not mx_records and not mx_error:
            for record_type in ("A", "AAAA"):
                records, error = resolve_records(domain, record_type)
                fallback_records.extend(records)
                if error:
                    fallback_error = error

        if mx_records:
            has_mail_route: bool | None = any(
                record.split()[-1] != "." for record in mx_records
            )
            warning = None if has_mail_route else t("email.null_mx")
        elif mx_error:
            has_mail_route = None
            warning = t("email.mx_failed", error=mx_error)
        elif fallback_records:
            has_mail_route = True
            warning = t("email.mx_fallback")
        elif fallback_error:
            has_mail_route = None
            warning = t("email.mx_fallback_error", error=fallback_error)
        else:
            has_mail_route = False
            warning = t("email.no_route")

        spf_records: list[str] = []
        dmarc_records: list[str] = []
        spoofing_protection = t("spoof.not_applicable")

        if has_mail_route:
            txt_records, _ = resolve_records(domain, "TXT")
            spf_records = [
                r.strip('"')
                for r in txt_records
                if r.strip('"').lower().startswith("v=spf1")
            ]
            raw_dmarc, _ = resolve_records(f"_dmarc.{domain}", "TXT")
            dmarc_records = [
                r.strip('"')
                for r in raw_dmarc
                if "v=dmarc1" in r.lower()
            ]
            spoofing_protection = _evaluate_spoofing_protection(
                spf_records, dmarc_records
            )

        data = {
            "format_valid": True,
            "local_part": local_part,
            "base_mailbox": base_mailbox,
            "plus_tag": plus_tag or None,
            "is_role_account": is_role,
            "is_disposable_provider": is_disposable,
            "domain": domain,
            "mx_records": mx_records,
            "domain_has_mail_route": has_mail_route,
            "fallback_address_records": fallback_records,
            "spf_records": spf_records,
            "dmarc_records": dmarc_records,
            "spoofing_protection": spoofing_protection,
            "warning": warning,
            "note": t("email.note"),
        }

        return self._success(target=target, data=data)


def _evaluate_spoofing_protection(
    spf_records: list[str], dmarc_records: list[str]
) -> str:
    has_strict_spf = any("-all" in r.lower() for r in spf_records)
    has_soft_spf = any("~all" in r.lower() for r in spf_records)
    dmarc_text = " ".join(dmarc_records).lower()
    has_enforced_dmarc = "p=reject" in dmarc_text or "p=quarantine" in dmarc_text

    if (has_strict_spf or has_soft_spf) and has_enforced_dmarc:
        return t("spoof.strong")
    if spf_records and dmarc_records:
        return t("spoof.moderate")
    if spf_records or dmarc_records:
        return t("spoof.partial")
    return t("spoof.weak")
