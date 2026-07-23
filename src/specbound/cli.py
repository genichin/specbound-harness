"""Command-line entry point for SpecBound validation and confirmation workflows."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .validation import (
    ConfirmationError,
    RequirementDraftError,
    RequirementReviewSubmissionError,
    check_requirement_readiness,
    create_discovery_confirmation,
    create_requirement_draft,
    discover_root,
    preflight,
    submit_requirement_for_review,
    validate,
)
from .requirement_lifecycle import RequirementLifecycleError, approve_requirement, record_review_decision, reconsider_requirement, reject_requirement


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

    req = commands.add_parser("req", help="operate on canonical REQ artifacts")
    req_commands = req.add_subparsers(dest="req_command", required=True)
    req_draft = req_commands.add_parser("draft", help="issue a non-overwritable canonical REQ draft")
    req_draft.add_argument("discovery_target", help="exact parent: dcy-<id>-r<revision>")
    req_draft.add_argument("requirement_target", help="exact target: req-<id>-r<revision>")
    req_reject = req_commands.add_parser("reject", help="reject an in-review REQ with canonical evidence")
    req_reject.add_argument("requirement_target", help="exact target: req-<id>-r<revision>")
    req_reject.add_argument("--authority", required=True, help="allowlisted rejection authority")
    req_reject.add_argument("--reason", required=True, help="substantive rejection reason")
    req_review_decision = req_commands.add_parser("review-decision", help="record a completed digest-bound review verdict")
    req_review_decision.add_argument("requirement_target", help="exact target: req-<id>-r<revision>")
    req_review_decision.add_argument("--authority", required=True)
    req_review_decision.add_argument("--decision", required=True, choices=("approval_ready", "rejected"))
    req_review_decision.add_argument("--reason", required=True)
    for name, help_text in (("reconsider", "append reconsideration evidence and reopen a rejected REQ"), ("approve", "approve an exact in-review snapshot with review evidence")):
        command = req_commands.add_parser(name, help=help_text)
        command.add_argument("requirement_target", help="exact target: req-<id>-r<revision>")
        command.add_argument("--authority", required=True)
        command.add_argument("--reason", required=True)
    req_readiness = req_commands.add_parser("check-readiness", help="validate whether a draft REQ has a closed review handoff")
    req_readiness.add_argument("requirement_target", help="exact target: req-<id>-r<revision>")
    req_submit = req_commands.add_parser("to-in-review", help="atomically submit a ready draft REQ for review")
    req_submit.add_argument("requirement_target", help="exact target: req-<id>-r<revision>")

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

    if args.command == "req" and args.req_command == "draft":
        try:
            path = create_requirement_draft(root, args.discovery_target, args.requirement_target)
        except RequirementDraftError as exc:
            _emit({"valid": False, "blockers": [{"code": exc.code, "path": exc.path, "detail": exc.detail}]})
            return 2
        _emit({"valid": True, "requirement_path": path.relative_to(root).as_posix()})
        return 0

    if args.command == "req" and args.req_command == "check-readiness":
        result = check_requirement_readiness(root, args.requirement_target)
        _emit(result.payload())
        return 0 if result.valid else 2

    if args.command == "req" and args.req_command == "to-in-review":
        try:
            path = submit_requirement_for_review(root, args.requirement_target)
        except RequirementReviewSubmissionError as exc:
            _emit({"valid": False, "blockers": [{"code": exc.code, "path": exc.path, "detail": exc.detail}]})
            return 2
        _emit({"valid": True, "review_submission_path": path.relative_to(root).as_posix()})
        return 0

    if args.command == "req" and args.req_command in {"review-decision", "reconsider", "approve", "reject"}:
        try:
            if args.req_command == "review-decision":
                path = record_review_decision(root, args.requirement_target, args.authority, args.decision, args.reason); field = "review_decision_path"
            elif args.req_command == "reconsider":
                path = reconsider_requirement(root, args.requirement_target, args.authority, args.reason); field = "reconsideration_path"
            elif args.req_command == "approve":
                path = approve_requirement(root, args.requirement_target, args.authority, args.reason); field = "approval_path"
            else:
                path = reject_requirement(root, args.requirement_target, args.authority, args.reason); field = "rejection_path"
        except RequirementLifecycleError as exc:
            _emit({"valid": False, "blockers": [{"code": exc.code, "path": exc.path, "detail": exc.detail}]})
            return 2
        _emit({"valid": True, field: path.relative_to(root).as_posix()})
        return 0

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
