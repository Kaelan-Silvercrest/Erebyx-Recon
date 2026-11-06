"""Validasi format alamat email, profil akun, dan postur keamanan MX/SPF/DMARC domain."""

import re

from erebyx.core.module_base import ModuleResult, OSINTModule
from erebyx.i18n import t
from erebyx.utils.dns_lookup import classify_dns_error, resolve_records

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

        mx_res = resolve_records(domain, "MX")
        mx_records, mx_error = mx_res
        fallback_records: list[str] = []
        fallback_error: str | None = None
        fallback_reason: str | None = None

        dns_status: str
        dns_reason: str | None = None
        mx_field: list[str] | str
        fallback_field: list[str] | str = []
        spf_field: list[str] | str = []
        dmarc_field: list[str] | str = []
        has_mail_route: bool | None = None
        warning: str | None = None
        spoofing_protection: str

        if mx_error:
            dns_status = "FAILED"
            dns_reason = getattr(mx_res, "reason", None) or classify_dns_error(mx_error)
            has_mail_route = None
            warning = t("email.mx_failed", error=mx_error)
            mx_field = "NOT_CHECKED"
            fallback_field = "NOT_CHECKED"
            spf_field = "NOT_CHECKED"
            dmarc_field = "NOT_CHECKED"
            spoofing_protection = "NOT_CHECKED"
        elif mx_records:
            dns_status = "OK"
            dns_reason = None
            mx_field = mx_records
            fallback_field = []
            has_mail_route = any(
                record.split()[-1] != "." for record in mx_records
            )
            warning = None if has_mail_route else t("email.null_mx")
            if has_mail_route:
                txt_res = resolve_records(domain, "TXT")
                txt_records, txt_error = txt_res
                if txt_error:
                    spf_field = "NOT_CHECKED"
                else:
                    spf_field = [
                        r.strip('"')
                        for r in txt_records
                        if r.strip('"').lower().startswith("v=spf1")
                    ]

                dmarc_res = resolve_records(f"_dmarc.{domain}", "TXT")
                raw_dmarc, dmarc_error = dmarc_res
                if dmarc_error and dmarc_error not in (
                    t("dns.nxdomain"),
                    "domain does not exist",
                    "domain tidak ditemukan",
                ):
                    dmarc_field = "NOT_CHECKED"
                else:
                    dmarc_field = [
                        r.strip('"')
                        for r in raw_dmarc
                        if "v=dmarc1" in r.lower()
                    ]

                if spf_field == "NOT_CHECKED" or dmarc_field == "NOT_CHECKED":
                    spoofing_protection = "NOT_CHECKED"
                else:
                    spoofing_protection = _evaluate_spoofing_protection(
                        spf_field, dmarc_field
                    )
            else:
                spf_field = []
                dmarc_field = []
                spoofing_protection = t("spoof.not_applicable")
        else:
            for record_type in ("A", "AAAA"):
                f_res = resolve_records(domain, record_type)
                records, error = f_res
                fallback_records.extend(records)
                if error:
                    fallback_error = error
                    fallback_reason = getattr(f_res, "reason", None) or classify_dns_error(error)

            if fallback_records:
                dns_status = "OK"
                dns_reason = None
                has_mail_route = True
                warning = t("email.mx_fallback")
                mx_field = []
                fallback_field = fallback_records

                txt_res = resolve_records(domain, "TXT")
                txt_records, txt_error = txt_res
                if txt_error:
                    spf_field = "NOT_CHECKED"
                else:
                    spf_field = [
                        r.strip('"')
                        for r in txt_records
                        if r.strip('"').lower().startswith("v=spf1")
                    ]

                dmarc_res = resolve_records(f"_dmarc.{domain}", "TXT")
                raw_dmarc, dmarc_error = dmarc_res
                if dmarc_error and dmarc_error not in (
                    t("dns.nxdomain"),
                    "domain does not exist",
                    "domain tidak ditemukan",
                ):
                    dmarc_field = "NOT_CHECKED"
                else:
                    dmarc_field = [
                        r.strip('"')
                        for r in raw_dmarc
                        if "v=dmarc1" in r.lower()
                    ]

                if spf_field == "NOT_CHECKED" or dmarc_field == "NOT_CHECKED":
                    spoofing_protection = "NOT_CHECKED"
                else:
                    spoofing_protection = _evaluate_spoofing_protection(
                        spf_field, dmarc_field
                    )
            elif fallback_error:
                dns_status = "FAILED"
                dns_reason = fallback_reason or classify_dns_error(fallback_error)
                has_mail_route = None
                warning = t("email.mx_fallback_error", error=fallback_error)
                mx_field = []
                fallback_field = "NOT_CHECKED"
                spf_field = "NOT_CHECKED"
                dmarc_field = "NOT_CHECKED"
                spoofing_protection = "NOT_CHECKED"
            else:
                dns_status = "OK"
                dns_reason = None
                has_mail_route = False
                warning = t("email.no_route")
                mx_field = []
                fallback_field = []
                spf_field = []
                dmarc_field = []
                spoofing_protection = t("spoof.not_applicable")

        data: dict[str, object] = {
            "format_valid": True,
            "local_part": local_part,
            "base_mailbox": base_mailbox,
            "plus_tag": plus_tag or None,
            "is_role_account": is_role,
            "is_disposable_provider": is_disposable,
            "domain": domain,
            "dns_status": dns_status,
        }
        if dns_reason:
            data["reason"] = dns_reason

        data.update({
            "mx_records": mx_field,
            "domain_has_mail_route": has_mail_route,
            "fallback_address_records": fallback_field,
            "spf_records": spf_field,
            "dmarc_records": dmarc_field,
            "spoofing_protection": spoofing_protection,
            "warning": warning,
            "note": t("email.note"),
        })

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
