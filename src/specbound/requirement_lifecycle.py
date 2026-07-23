"""Append-only review, reconsideration, and approval controls for REQ lifecycle decisions."""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any

from .validation import (
    PLACEHOLDER_RE,
    REQUIREMENT_RE,
    RequirementRejectionError,
    _atomic_replace_text,
    _frontmatter,
    _load_config,
    _transitioned_discovery_text,
    reject_requirement as _reject_requirement,
    validate,
)


class RequirementLifecycleError(ValueError):
    def __init__(self, code: str, path: str, detail: str) -> None:
        super().__init__(detail)
        self.code, self.path, self.detail = code, path, detail


def _context(root: Path, target: str, expected_status: str) -> tuple[Path, dict[str, Any], str, str, int]:
    match = REQUIREMENT_RE.fullmatch(f"{target}.md")
    if not match:
        raise RequirementLifecycleError("invalid_requirement_target", target, "target must be req-<id>-r<revision>")
    requirement_id, revision_text = match.groups()
    relative = f"docs/requirements/{requirement_id}/{target}.md"
    path = root / relative
    try:
        meta = _frontmatter(path)
        text = path.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        raise RequirementLifecycleError("missing_requirement", relative, str(exc)) from exc
    if meta.get("id") != requirement_id or meta.get("revision") != int(revision_text) or meta.get("status") != expected_status:
        raise RequirementLifecycleError("invalid_requirement_status_transition", relative, f"REQ must be {expected_status} with matching id/revision")
    return path, meta, text, requirement_id, int(revision_text)


def _record_path(root: Path, family: str, target: str, suffix: str) -> Path:
    return root / ".specbound" / family / f"{target}.{suffix}.json"


def _write_once(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise RequirementLifecycleError("record_write_failed", path.as_posix(), str(exc)) from exc


def _read(path: Path, code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RequirementLifecycleError(code, path.as_posix(), str(exc)) from exc
    if not isinstance(value, dict):
        raise RequirementLifecycleError(code, path.as_posix(), "record must be an object")
    return value


def _authority(root: Path, meta: dict[str, Any], policy_key: str, authority: str, target: str) -> None:
    allowed = _load_config(root)["policy"][policy_key].get(meta["risk"], [])
    if authority not in allowed:
        raise RequirementLifecycleError("invalid_lifecycle_authority", target, f"authority is not allowlisted by {policy_key}")


def record_review_decision(root: Path, target: str, authority: str, decision: str, reason: str) -> Path:
    if not validate(root).valid:
        raise RequirementLifecycleError("repository_validation_failed", ".", "repository must validate before review decision")
    path, meta, text, requirement_id, revision = _context(root, target, "in_review")
    if decision not in {"approval_ready", "rejected"} or not reason.strip() or PLACEHOLDER_RE.search(reason):
        raise RequirementLifecycleError("malformed_review_decision", target, "valid decision and substantive reason are required")
    _authority(root, meta, "requirement_review_decision_authorities_by_risk", authority, target)
    out = _record_path(root, "review-decisions", target, "review-decision")
    _write_once(out, {"schema_version": 1, "requirement_path": path.relative_to(root).as_posix(), "requirement_id": requirement_id, "revision": revision, "reviewed_sha256": sha256(text.encode()).hexdigest(), "risk": meta["risk"], "authority": authority, "decided_at": datetime.now().astimezone().isoformat(), "decision": decision, "reason": reason.strip()})
    return out


def _verdict(root: Path, target: str, meta: dict[str, Any], text: str, expected: str) -> None:
    path = _record_path(root, "review-decisions", target, "review-decision")
    record = _read(path, "missing_review_decision")
    if record.get("decision") != expected or record.get("reviewed_sha256") != sha256(text.encode()).hexdigest() or record.get("risk") != meta.get("risk"):
        raise RequirementLifecycleError("review_decision_binding_mismatch", path.as_posix(), "review verdict must bind this exact snapshot and outcome")


def reject_requirement(root: Path, target: str, authority: str, reason: str) -> Path:
    existing = _record_path(root, "rejections", target, "rejection")
    if existing.exists():
        raise RequirementLifecycleError("rejection_already_exists", existing.as_posix(), "rejection record is append-only")
    _, meta, text, _, _ = _context(root, target, "in_review")
    _verdict(root, target, meta, text, "rejected")
    try:
        return _reject_requirement(root, target, authority, reason)
    except RequirementRejectionError as exc:
        raise RequirementLifecycleError(exc.code, exc.path, exc.detail) from exc


def reconsider_requirement(root: Path, target: str, authority: str, reason: str) -> Path:
    if not validate(root).valid:
        raise RequirementLifecycleError("repository_validation_failed", ".", "repository must validate before reconsideration")
    path, meta, rejected, requirement_id, revision = _context(root, target, "rejected")
    if not reason.strip() or PLACEHOLDER_RE.search(reason):
        raise RequirementLifecycleError("malformed_reconsideration", target, "substantive reason is required")
    _authority(root, meta, "requirement_reconsideration_authorities_by_risk", authority, target)
    reviewed = _transitioned_discovery_text(rejected, "rejected", "in_review")
    rejection = _read(_record_path(root, "rejections", target, "rejection"), "missing_rejection")
    if rejection.get("sha256") != sha256(rejected.encode()).hexdigest() or rejection.get("reviewed_sha256") != sha256(reviewed.encode()).hexdigest():
        raise RequirementLifecycleError("rejection_digest_mismatch", target, "rejection does not bind exact snapshots")
    out = _record_path(root, "reconsiderations", target, "reconsideration")
    _write_once(out, {"schema_version": 1, "requirement_path": path.relative_to(root).as_posix(), "requirement_id": requirement_id, "revision": revision, "reviewed_sha256": sha256(reviewed.encode()).hexdigest(), "rejected_sha256": sha256(rejected.encode()).hexdigest(), "reopened_sha256": sha256(reviewed.encode()).hexdigest(), "risk": meta["risk"], "authority": authority, "reconsidered_at": datetime.now().astimezone().isoformat(), "decision": "reopened_for_review", "reason": reason.strip()})
    _atomic_replace_text(path, reviewed)
    if not validate(root).valid:
        _atomic_replace_text(path, rejected)
        out.unlink()
        raise RequirementLifecycleError("generated_reconsideration_invalid", out.as_posix(), "generated reconsideration failed validation")
    return out


def approve_requirement(root: Path, target: str, authority: str, reason: str) -> Path:
    if not validate(root).valid:
        raise RequirementLifecycleError("repository_validation_failed", ".", "repository must validate before approval")
    path, meta, reviewed, requirement_id, revision = _context(root, target, "in_review")
    if not reason.strip() or PLACEHOLDER_RE.search(reason):
        raise RequirementLifecycleError("malformed_approval_reason", target, "substantive reason is required")
    _authority(root, meta, "requirement_approval_authorities_by_risk", authority, target)
    _verdict(root, target, meta, reviewed, "approval_ready")
    approved = _transitioned_discovery_text(reviewed, "in_review", "approved")
    out = _record_path(root, "approvals", target, "approval")
    _atomic_replace_text(path, approved)
    try:
        _write_once(out, {"schema_version": 1, "requirement_path": path.relative_to(root).as_posix(), "requirement_id": requirement_id, "revision": revision, "reviewed_sha256": sha256(reviewed.encode()).hexdigest(), "sha256": sha256(approved.encode()).hexdigest(), "risk": meta["risk"], "authority": authority, "approved_at": datetime.now().astimezone().isoformat(), "decision": "approved", "reason": reason.strip()})
    except RequirementLifecycleError:
        _atomic_replace_text(path, reviewed)
        raise
    if not validate(root).valid:
        out.unlink()
        _atomic_replace_text(path, reviewed)
        raise RequirementLifecycleError("generated_approval_invalid", out.as_posix(), "generated approval failed validation")
    return out
