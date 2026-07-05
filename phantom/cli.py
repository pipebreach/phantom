"""Thin CLI layer over ``phantom.core.scan``. Exit codes: 0 clean, 1 findings
of high/critical severity, 2 execution error, 3 out of scope."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from phantom import __version__, core
from phantom.cache import DiskCache, default_cache_dir
from phantom.errors import OutOfScopeError, PhantomError
from phantom.registry import Registry, build_default_registry
from phantom.report import json_report, sarif_report, table_report

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_OUT_OF_SCOPE = 3

_EXIT_CODES_HELP = """\
exit codes:
  0  no findings (or only medium/low severity)
  1  at least one high/critical finding
  2  execution error
  3  package out of scope (no pure-Python wheel available)
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phantom",
        description=(
            "Detect divergence between a package's declared source and its "
            "published artifact."
        ),
        epilog=_EXIT_CODES_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"phantom {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan",
        help="scan a single package version (e.g. phantom scan requests==2.31.0)",
        epilog=_EXIT_CODES_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan.add_argument("spec", help="package spec in the form <pkg>==<version>")
    scan.add_argument(
        "--ecosystem",
        default="pypi",
        help="package ecosystem (default: pypi)",
    )
    output = scan.add_mutually_exclusive_group()
    output.add_argument(
        "--json", action="store_true", help="emit the versioned JSON schema"
    )
    output.add_argument(
        "--sarif", action="store_true", help="emit SARIF 2.1.0 for code scanning"
    )
    scan.add_argument(
        "--cache-dir",
        type=Path,
        default=None,
        help=f"download cache directory (default: {default_cache_dir()})",
    )

    audit = subparsers.add_parser(
        "audit",
        help="scan every package in a lockfile (requirements.txt / poetry.lock) [M2]",
    )
    audit.add_argument("lockfile", type=Path, help="path to the lockfile")

    return parser


def run(argv: list[str] | None = None, registry: Registry | None = None) -> int:
    """Parse arguments and execute; ``registry`` is injectable for tests."""
    args = build_parser().parse_args(argv)

    if args.command == "audit":
        print(
            "phantom audit is not implemented yet (planned for M2).",
            file=sys.stderr,
        )
        return EXIT_ERROR

    try:
        package, version = _parse_spec(args.spec)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if registry is None:
        cache = DiskCache(args.cache_dir or default_cache_dir())
        registry = build_default_registry(cache)

    try:
        ecosystem = registry.get(args.ecosystem)
        result = core.scan(package, version, ecosystem)
    except OutOfScopeError as exc:
        print(f"out of scope: {exc}", file=sys.stderr)
        return EXIT_OUT_OF_SCOPE
    except PhantomError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.json:
        print(json_report.render(result))
    elif args.sarif:
        print(sarif_report.render(result))
    else:
        print(table_report.render(result))

    return core.exit_code_for(result)


def _parse_spec(spec: str) -> tuple[str, str]:
    package, sep, version = spec.partition("==")
    if not sep or not package or not version:
        raise ValueError(
            f"invalid spec {spec!r}: expected exact pin <pkg>==<version>"
        )
    return package.strip(), version.strip()


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
