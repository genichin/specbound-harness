"""Append-only, authority-bound Micro-SPEC review issuance."""

from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import re

from .validation import (
    MICRO_SPEC_RE,
    REQUIRED_ROOTS,
    _digest,
    _frontmatter,
    _load_config,
    _safe_relative,
    preflight,
    validate,
)


class MicroSpecReviewError(ValueError):
    def __init__(self, code: str, path: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.path = path
        self.detail = detail


def record_micro_spec_review(root: Path, target: str, authority: str, decision: str, reason: str) -> Path:
    """Write one non-overwritable review record bound to an exact Micro-SPEC snapshot."""
    match = MICRO_SPEC_RE.fullmatch(f"{target}.md")
    if not match:
        raise MicroSpecReviewError("invalid_micro_spec_target", target, "target must use ms-<id>-<slice>")
    if decision not in {"approved_for_implementation", "rework", "blocked"}:
        raise MicroSpecReviewError("invalid_micro_spec_review_decision", target, "decision is not supported")
    if not isinstance(reason, str) or not reason.strip():
        raise MicroSpecReviewError("invalid_micro_spec_review_reason", target, "reason must be substantive")
    initial = preflight(root)
    if not initial.valid:
        raise MicroSpecReviewError("invalid_control_plane", "specbound.yaml", "preflight must pass before review issuance")

    number, slice_text = match.groups()
    requirement_id = f"req-{number}"
    micro_relative = f"{REQUIRED_ROOTS['micro_specs_root']}/{requirement_id}/{target}.md"
    micro_path = root / micro_relative
    try:
        micro = _frontmatter(micro_path)
    except (OSError, ValueError) as exc:
        raise MicroSpecReviewError("missing_micro_spec", micro_relative, str(exc)) from exc
    parent = micro.get("requirement")
    if not isinstance(parent, dict) or set(parent) != {"path", "id", "revision", "sha256"}:
        raise MicroSpecReviewError("invalid_micro_spec_parent", micro_relative, "Micro-SPEC must have an exact parent REQ binding")
    if parent.get("id") != requirement_id or not isinstance(parent.get("path"), str) or not _safe_relative(parent["path"]):
        raise MicroSpecReviewError("invalid_micro_spec_parent", micro_relative, "Micro-SPEC parent must bind its matching canonical REQ")
    parent_path = root / parent["path"]
    try:
        parent_meta = _frontmatter(parent_path)
    except (OSError, ValueError) as exc:
        raise MicroSpecReviewError("missing_parent_requirement", parent["path"], str(exc)) from exc
    if parent_meta.get("status") != "approved" or parent.get("sha256") != _digest(parent_path):
        raise MicroSpecReviewError("invalid_micro_spec_parent", micro_relative, "parent must remain the exact approved REQ snapshot")
    config = _load_config(root)
    risk = parent_meta.get("risk")
    allowlisted = config["policy"]["micro_spec_review_authorities_by_risk"].get(risk, [])
    if authority not in allowlisted:
        raise MicroSpecReviewError("invalid_micro_spec_review_authority", target, "authority is not allowlisted for the parent REQ risk")

    review_relative = f"{REQUIRED_ROOTS['micro_spec_reviews_root']}/{requirement_id}/{target}.review.json"
    review_path = root / review_relative
    record = {
        "schema_version": 1,
        "micro_spec_path": micro_relative,
        "micro_spec_id": target,
        "micro_spec_sha256": _digest(micro_path),
        "requirement_path": parent["path"],
        "requirement_id": parent["id"],
        "revision": parent["revision"],
        "requirement_sha256": parent["sha256"],
        "risk": risk,
        "authority": authority,
        "decided_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "decision": decision,
        "reason": reason.strip(),
        "permitted_next_action": "implement_bound_micro_spec_only" if decision == "approved_for_implementation" else "none",
    }
    review_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with review_path.open("x", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
    except FileExistsError as exc:
        raise MicroSpecReviewError("micro_spec_review_already_exists", review_relative, "review records are append-only and non-overwritable") from exc
    if validate(root).valid:
        return review_path
    review_path.unlink(missing_ok=True)
    raise MicroSpecReviewError("generated_micro_spec_review_invalid", review_relative, "generated record did not pass specbound validate")
