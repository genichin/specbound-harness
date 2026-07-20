"""Command-line entry point for the SpecBound bootstrap validator."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .validation import discover_root, preflight, validate


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="specbound")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository root or a child path")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("context", help="print discovered repository context")
    subparsers.add_parser("preflight", help="validate bootstrap configuration")
    subparsers.add_parser("validate", help="validate canonical REQ and approval bindings")
    return parser


def _emit(payload: dict[str, object]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        root = discover_root(args.root)
    except FileNotFoundError as exc:
        _emit({"valid": False, "blockers": [{"code": "missing_config", "detail": str(exc)}]})
        return 2

    if args.command == "context":
        _emit(
            {
                "valid": True,
                "root": str(root),
                "config": str(root / "specbound.yaml"),
                "requirements_root": "docs/requirements",
                "discoveries_root": "docs/discoveries",
                "approvals_root": ".specbound/approvals",
                "discovery_confirmations_root": ".specbound/discovery-confirmations",
            }
        )
        return 0

    result = preflight(root) if args.command == "preflight" else validate(root)
    _emit(result.payload())
    return 0 if result.valid else 2


if __name__ == "__main__":
    sys.exit(main())
