"""
erebyx/core/cli.py

Command-line interface Erebyx. Dipanggil lewat command `erebyx` (entry point
di pyproject.toml), `python -m erebyx`, atau `python main.py` saat development.

Contoh pemakaian:
    erebyx -m domain_lookup -t example.com
    erebyx -m all -t example.co.id --export
    erebyx --list-modules
    erebyx --set-lang en
"""

import argparse
import json
import sys

from erebyx import __version__
from erebyx.core.loader import discover_modules
from erebyx.i18n import (
    SUPPORTED_LANGUAGES,
    label,
    resolve_language,
    save_language,
    set_language,
    t,
)
from erebyx.utils.output import save_combined_report, save_json

FULL_RECON_EXCLUDED = {"ahu_lookup", "npwp_oss_lookup", "sipp_lookup"}


def _preparse_lang(argv: list[str] | None) -> str | None:
    tokens = list(sys.argv[1:] if argv is None else argv)
    for idx, token in enumerate(tokens):
        if token in ("--lang", "--set-lang") and idx + 1 < len(tokens):
            return tokens[idx + 1]
        if token.startswith("--lang=") or token.startswith("--set-lang="):
            return token.split("=", 1)[1]
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="erebyx",
        description=t("cli.description"),
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--module", "-m",
        help=t("cli.help.module"),
    )
    parser.add_argument(
        "--target", "-t",
        help=t("cli.help.target"),
    )
    parser.add_argument(
        "--list-modules", "-l",
        action="store_true",
        help=t("cli.help.list"),
    )
    parser.add_argument(
        "--output", "-o",
        choices=["pretty", "json"],
        default="pretty",
        help=t("cli.help.output"),
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help=t("cli.help.export"),
    )
    parser.add_argument(
        "--lang",
        choices=SUPPORTED_LANGUAGES,
        help=t("cli.help.lang"),
    )
    parser.add_argument(
        "--set-lang",
        choices=SUPPORTED_LANGUAGES,
        help=t("cli.help.set_lang"),
    )
    return parser


def list_modules() -> None:
    registry = discover_modules()
    if not registry:
        print(t("cli.no_modules"))
        return

    by_category: dict[str, list] = {}
    for mod_cls in registry.values():
        by_category.setdefault(mod_cls.category, []).append(mod_cls)

    for category, mods in sorted(by_category.items()):
        print(f"\n[{category}]")
        for mod_cls in sorted(mods, key=lambda cls: cls.name):
            desc_key = f"module_desc.{mod_cls.name}"
            desc = t(desc_key)
            if desc == desc_key:
                desc = mod_cls.description
            print(f"  {mod_cls.name:<25} {desc}")


def run(argv: list[str] | None = None) -> int:
    hint_lang = _preparse_lang(argv)
    set_language(resolve_language(hint_lang))

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.set_lang:
        set_language(args.set_lang)
        try:
            saved_path = save_language(args.set_lang)
        except OSError as exc:
            print(t("cli.lang_save_failed", error=exc), file=sys.stderr)
            return 2
        print(t("cli.lang_saved", lang=args.set_lang, path=saved_path))
        if not args.list_modules and not args.module:
            return 0

    if args.lang:
        set_language(args.lang)

    if args.list_modules:
        list_modules()
        return 0

    if not args.module or not args.target:
        parser.print_help()
        return 1

    registry = discover_modules()

    if args.module == "all":
        return _run_all_matching(registry, args)

    mod_cls = registry.get(args.module)
    if mod_cls is None:
        print(t("cli.module_not_found", module=args.module))
        return 1

    instance = mod_cls()
    if not instance.validate_target(args.target):
        print(t("cli.invalid_target", target=args.target, module=args.module))
        return 1

    result = instance.run(args.target)

    if args.output == "json":
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        _print_pretty(result)

    if args.export:
        try:
            filepath = save_json(result.to_dict(), args.target, args.module)
        except OSError as exc:
            print(t("cli.save_failed", error=exc), file=sys.stderr)
            return 2
        print(
            t("cli.saved", path=filepath),
            file=sys.stderr if args.output == "json" else sys.stdout,
        )

    return 0 if result.success else 2


def _run_all_matching(registry: dict, args: argparse.Namespace) -> int:
    matching_instances = []
    for name, mod_cls in sorted(registry.items()):
        if name in FULL_RECON_EXCLUDED:
            continue
        if name == "username_check" and ("." in args.target or "@" in args.target):
            continue
        instance = mod_cls()
        if instance.validate_target(args.target):
            matching_instances.append(instance)

    if not matching_instances:
        print(t("cli.no_matching", target=args.target))
        return 1

    results = [inst.run(args.target) for inst in matching_instances]
    serialized = [res.to_dict() for res in results]

    if args.output == "json":
        print(json.dumps(serialized, indent=2, ensure_ascii=False))
    else:
        for res in results:
            _print_pretty(res)

    if args.export:
        try:
            filepath = save_combined_report(serialized, label=f"all_{args.target}")
        except OSError as exc:
            print(t("cli.report_failed", error=exc), file=sys.stderr)
            return 2
        print(
            t("cli.report_saved", path=filepath),
            file=sys.stderr if args.output == "json" else sys.stdout,
        )

    return 0 if any(r.success for r in results) else 2


def _print_pretty(result) -> None:
    status = t("cli.status_ok") if result.success else t("cli.status_fail")
    print(f"\n=== [{status}] {result.module_name} -> {result.target} ===")
    if result.success:
        for key, value in result.data.items():
            print(f"  {label(key)}: {value}")
        if result.source_urls:
            print(f"  {t('cli.sources')}: {', '.join(result.source_urls)}")
    else:
        print(f"  {t('cli.error')}: {result.error}")
    print(f"  {t('cli.time')}: {result.timestamp}\n")


def main() -> int:
    """Entry point untuk console script `erebyx`."""
    try:
        return run()
    except KeyboardInterrupt:
        print(f"\n{t('cli.cancelled')}", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
