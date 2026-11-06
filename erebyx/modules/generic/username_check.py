"""Audit lokal mendalam terhadap format, entropi, pola, dan risiko impersonasi username."""

import math
import re
from collections import Counter

from erebyx.core.module_base import ModuleResult, OSINTModule
from erebyx.i18n import t

RESERVED_HANDLES = {
    "admin",
    "administrator",
    "root",
    "system",
    "support",
    "security",
    "helpdesk",
    "official",
    "moderator",
    "sysadmin",
    "webmaster",
    "postmaster",
    "hostmaster",
    "abuse",
}


class UsernameCheckModule(OSINTModule):
    name = "username_check"
    description = (
        "Audit lokal mendalam format, entropi, konvensi, & risiko impersonasi username"
    )
    category = "generic"
    requires_api_key = False

    def validate_target(self, target: str) -> bool:
        candidate = target.strip()
        return bool(candidate) and len(candidate) <= 64 and not any(
            character.isspace() for character in candidate
        )

    def run(self, target: str) -> ModuleResult:
        username = target.strip()
        if not self.validate_target(username):
            return self._fail(target, t("err.invalid_username"))

        allowed_characters = bool(re.fullmatch(r"[A-Za-z0-9._-]+", username))
        has_non_ascii = not username.isascii()
        normalized = username.lower()
        entropy = _shannon_entropy(username)
        naming_style = _detect_naming_style(username)
        is_reserved = normalized in RESERVED_HANDLES or any(
            normalized.startswith(f"{r}_") or normalized.endswith(f"_{r}")
            for r in ("admin", "official", "support", "security")
        )

        data = {
            "username": username,
            "length": len(username),
            "allowed_characters": allowed_characters,
            "ascii_only": not has_non_ascii,
            "normalized_lowercase": normalized,
            "naming_style": naming_style,
            "shannon_entropy_bits": round(entropy, 3),
            "privileged_or_reserved_pattern": is_reserved,
            "character_breakdown": {
                "letters": sum(c.isalpha() for c in username),
                "digits": sum(c.isdigit() for c in username),
                "separators": sum(c in "._-" for c in username),
            },
            "account_search_performed": False,
            "note": t("note.username"),
        }
        return self._success(target=username, data=data)


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    counts = Counter(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _detect_naming_style(username: str) -> str:
    if "_" in username and "-" not in username and "." not in username:
        return "snake_case"
    if "-" in username and "_" not in username and "." not in username:
        return "kebab-case"
    if "." in username and "_" not in username and "-" not in username:
        return "dot.separated"
    if re.search(r"[a-z][A-Z]", username):
        return "camelCase"
    if username.isalnum():
        return "alphanumeric"
    return "mixed"
