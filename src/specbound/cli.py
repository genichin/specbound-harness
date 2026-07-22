"""Command-line entry point for SpecBound validation and confirmation workflows."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .validation import (
    ConfirmationError,
    create_discovery_confirmation,
    discover_root,
    preflight,
    validate,
)


def _emit(payload: object) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _root_argument(value: str) -> Path:
    return Path(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="specbound")
    parser.add_argument("--root", type=_root_argument, default=Path.cwd(), help="repository root or a descendant")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("context", help="show the discovered repository root and canonical paths")
    commands.add_parser("preflight", help="validate SpecBound configuration")
    validate_command = commands.add_parser("validate", help="validate canonical lifecycle artifacts or a scoped adopted claim")
    validate_command.add_argument("--claim", choices=("iteration", "delivery"), help="validate one adopted evidence claim")
    validate_command.add_argument("--requirement", help="exact adopted REQ: req-<id>-r<revision> (required with --claim)")

    discovery = commands.add_parser("discovery", help="operate on canonical Discovery artifacts")
    discovery_commands = discovery.add_subparsers(dest="discovery_command", required=True)
    confirm = discovery_commands.add_parser("confirm", help="create a non-overwritable Discovery confirmation record")
    confirm.add_argument("target", help="exact target: dcy-<id>-r<revision>")
    confirm.add_argument("--authority", required=True, help="allowlisted confirmation authority")
    confirm.add_argument(
        "--supersession-exception",
        help="substantive reason required to confirm a revision with a newer revision present",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = discover_root(args.root)
    except FileNotFoundError as exc:
        _emit({"valid": False, "blockers": [{"code": "missing_config", "path": "specbound.yaml", "detail": str(exc)}]})
        return 2

    if args.command == "context":
        _emit(
            {
                "root": str(root),
                "requirements_root": "docs/requirements",
                "discoveries_root": ".specbound/discoveries",
                "discovery_confirmations_root": ".specbound/confirmations",
                "micro_specs_root": ".specbound/micro-specs",
                "iteration_qc_root": ".specbound/iteration-qc",
                "delivery_qc_root": ".specbound/delivery-qc",
            }
        )
        return 0

    if args.command == "preflight":
        result = preflight(root)
        _emit(result.payload())
        return 0 if result.valid else 2

    if args.command == "validate":
        result = validate(root, claim=args.claim, requirement=args.requirement)
        _emit(result.payload())
        return 0 if result.valid else 2

    if args.command == "discovery" and args.discovery_command == "confirm":
        try:
            path = create_discovery_confirmation(
                root,
                args.target,
                args.authority,
                args.supersession_exception,
            )
        except ConfirmationError as exc:
            _emit(
                {
                    "valid": False,
                    "blockers": [{"code": exc.code, "path": exc.path, "detail": exc.detail}],
                }
            )
            return 2
        _emit({"valid": True, "confirmation_path": path.relative_to(root).as_posix()})
        return 0

    raise AssertionError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(main())
