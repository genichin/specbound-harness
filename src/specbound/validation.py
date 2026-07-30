"""Deterministic, fail-closed checks for SpecBound canonical lifecycle artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from typing import Any

import yaml

from .agent_contract import validate_agent_role_skills, validate_agent_roles_policy
from .control_plane_adoption import resolve_effective_activation_registry

REQUIREMENT_RE = re.compile(r"^(req-[0-9]+)-r([1-9][0-9]*)\.md$")
DISCOVERY_RE = re.compile(r"^(dcy-[0-9]+)-r([1-9][0-9]*)\.md$")
DISCOVERY_CONFIRMATION_RE = re.compile(r"^(dcy-[0-9]+)-r([1-9][0-9]*)\.confirmation\.json$")
REQUIREMENT_REJECTION_RE = re.compile(r"^(req-[0-9]+)-r([1-9][0-9]*)\.rejection\.json$")
REQUIREMENT_REVIEW_SUBMISSION_RE = re.compile(r"^(req-[0-9]+)-r([1-9][0-9]*)\.review-submission\.json$")
REQUIREMENT_REVIEW_DECISION_RE = re.compile(r"^(req-[0-9]+)-r([1-9][0-9]*)\.review-decision\.json$")
REQUIREMENT_RECONSIDERATION_RE = re.compile(r"^(req-[0-9]+)-r([1-9][0-9]*)\.reconsideration\.json$")
MICRO_SPEC_RE = re.compile(r"^ms-([0-9]+)-(0*[1-9][0-9]*)\.md$")
MICRO_SPEC_REVIEW_RE = re.compile(r"^ms-([0-9]+)-(0*[1-9][0-9]*)\.review\.json$")
ITERATION_QC_RE = re.compile(r"^iqc-([0-9]+)-(0*[1-9][0-9]*)-r([1-9][0-9]*)\.json$")
DELIVERY_QC_RE = re.compile(r"^dqc-([0-9]+)-r([1-9][0-9]*)\.json$")
REQUIRED_ROOTS = {
    "requirements_root": ".specbound/requirements",
    "discoveries_root": ".specbound/discoveries",
    "control_root": ".specbound",
    "approvals_root": ".specbound/approvals",
    "rejections_root": ".specbound/rejections",
    "review_submissions_root": ".specbound/review-submissions",
    "review_decisions_root": ".specbound/review-decisions",
    "reconsiderations_root": ".specbound/reconsiderations",
    "micro_spec_reviews_root": ".specbound/micro-spec-reviews",
    "discovery_confirmations_root": ".specbound/confirmations",
    "micro_specs_root": ".specbound/micro-specs",
    "iteration_qc_root": ".specbound/iteration-qc",
    "delivery_qc_root": ".specbound/delivery-qc",
    "adoptions_root": ".specbound/adoptions",
    "canary_outcomes_root": ".specbound/canary-outcomes",
    "activations_root": ".specbound/activations",
}


def canonical_requirement_relative(requirement_id: str, revision: int | str) -> str:
    """Return the single canonical repository-relative path for a REQ revision."""
    return f"{REQUIRED_ROOTS['requirements_root']}/{requirement_id}/{requirement_id}-r{revision}.md"


REQUIREMENT_PATTERN = "req-<id>/req-<id>-r<revision>.md"
DISCOVERY_PATTERN = "dcy-<id>-r<revision>.md"
MICRO_SPEC_PATTERN = "req-<id>/ms-<id>-<slice>.md"
ITERATION_QC_PATTERN = "req-<id>/iqc-<id>-<slice>-r<revision>.json"
DELIVERY_QC_PATTERN = "dqc-<id>-r<revision>.json"
ADOPTION_PATTERN = "req-<id>/adp-<id>-r<revision>-<transition>.json"
CANARY_OUTCOME_PATTERN = "req-<id>/cny-<id>-r<revision>-<transition>-a<sequence>.json"
ACTIVATION_PATTERN = "req-<id>/act-<id>-r<revision>-<transition>.json"
LATEST_ONLY_WITH_EXCEPTION = "latest_only_with_explicit_exception"
CONTROL_PLANE_ADOPTION_SCHEMA_VERSION = 1
REQUIRED_APPROVAL_FIELDS = {
    "requirement_path",
    "requirement_id",
    "revision",
    "sha256",
    "risk",
    "authority",
}
REQUIRED_REJECTION_FIELDS = {
    "schema_version",
    "requirement_path",
    "requirement_id",
    "revision",
    "reviewed_sha256",
    "sha256",
    "risk",
    "authority",
    "rejected_at",
    "decision",
    "reason",
}
REQUIRED_REVIEW_SUBMISSION_FIELDS = {
    "schema_version",
    "requirement_path",
    "requirement_id",
    "revision",
    "draft_sha256",
    "reviewed_sha256",
    "risk",
    "owner",
    "submitted_at",
    "decision",
    "permitted_next_action",
}
REQUIRED_REVIEW_DECISION_FIELDS = {
    "schema_version", "requirement_path", "requirement_id", "revision", "reviewed_sha256",
    "risk", "authority", "decided_at", "decision", "reason",
}
REQUIRED_RECONSIDERATION_FIELDS = {
    "schema_version", "requirement_path", "requirement_id", "revision", "reviewed_sha256",
    "rejected_sha256", "reopened_sha256", "risk", "authority", "reconsidered_at", "decision", "reason",
}
REQUIRED_DISCOVERY_CONFIRMATION_FIELDS = {
    "schema_version",
    "discovery_path",
    "discovery_id",
    "revision",
    "reviewed_sha256",
    "sha256",
    "risk_class",
    "authority",
    "confirmed_at",
    "decision",
    "permitted_next_action",
}
REQUIRED_MICRO_SPEC_REVIEW_FIELDS = {
    "schema_version", "micro_spec_path", "micro_spec_id", "micro_spec_sha256",
    "requirement_path", "requirement_id", "revision", "requirement_sha256", "risk",
    "authority", "decided_at", "decision", "reason", "permitted_next_action",
}
REQUIRED_DISCOVERY_METADATA = {"id", "revision", "status", "title", "issue_ref", "owner", "source_refs", "risk_class"}
REQUIRED_DISCOVERY_HEADINGS = (
    "## 1. User intent",
    "## 2. Problem and target users",
    "## 3. Desired outcome and success signals",
    "## 6. Scope",
    "## 7. Non-goals",
    "## 9. Risks, constraints, and dependencies",
    "## 11. Open questions",
    "## 12. Recommendation",
    "## 12a. REQ drafting readiness",
    "## 13. Proposed next authorized action",
)
PLACEHOLDER_RE = re.compile(r"<[^>]+>|\b(?:TBD|TODO)\b", re.IGNORECASE)


@dataclass
class Result:
    root: Path
    blockers: list[dict[str, str]] = field(default_factory=list)
    checked_requirements: int = 0
    approved_requirements: int = 0
    checked_discoveries: int = 0
    confirmed_discoveries: int = 0
    checked_micro_specs: int = 0
    checked_iteration_qc: int = 0
    checked_delivery_qc: int = 0
    checked_agent_roles: int = 0
    checked_agent_skills: int = 0
    checked_effective_activations: int = 0

    @property
    def valid(self) -> bool:
        return not self.blockers

    def block(self, code: str, path: str, detail: str) -> None:
        self.blockers.append({"code": code, "path": path, "detail": detail})

    def payload(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "root": str(self.root),
            "checked_requirements": self.checked_requirements,
            "approved_requirements": self.approved_requirements,
            "checked_discoveries": self.checked_discoveries,
            "confirmed_discoveries": self.confirmed_discoveries,
            "checked_micro_specs": self.checked_micro_specs,
            "checked_iteration_qc": self.checked_iteration_qc,
            "checked_delivery_qc": self.checked_delivery_qc,
            "checked_agent_roles": self.checked_agent_roles,
            "checked_agent_skills": self.checked_agent_skills,
            "checked_effective_activations": self.checked_effective_activations,
            "blockers": self.blockers,
        }


def discover_root(start: Path) -> Path:
    candidate = start.resolve()
    for directory in (candidate, *candidate.parents):
        if (directory / "specbound.yaml").is_file():
            return directory
    raise FileNotFoundError("specbound.yaml was not found at or above the requested root")


def _load_config(root: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load((root / "specbound.yaml").read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"cannot parse specbound.yaml: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("specbound.yaml must contain a mapping")
    return data


def _require_config_value(result: Result, canonical: dict[str, Any], key: str, expected: str) -> None:
    if canonical.get(key) != expected:
        result.block("malformed_config", "specbound.yaml", f"canonical.{key} must equal {expected!r}")


def preflight(root: Path) -> Result:
    result = Result(root=root)
    try:
        config = _load_config(root)
    except ValueError as exc:
        result.block("malformed_config", "specbound.yaml", str(exc))
        return result

    if config.get("version") != 1:
        result.block("malformed_config", "specbound.yaml", "version must equal integer 1")

    canonical = config.get("canonical")
    if not isinstance(canonical, dict):
        result.block("malformed_config", "specbound.yaml", "canonical must be a mapping")
        return result
    for key, expected in REQUIRED_ROOTS.items():
        _require_config_value(result, canonical, key, expected)
    _require_config_value(result, canonical, "requirement_pattern", REQUIREMENT_PATTERN)
    _require_config_value(result, canonical, "discovery_pattern", DISCOVERY_PATTERN)
    _require_config_value(result, canonical, "micro_spec_pattern", MICRO_SPEC_PATTERN)
    _require_config_value(result, canonical, "iteration_qc_pattern", ITERATION_QC_PATTERN)
    _require_config_value(result, canonical, "delivery_qc_pattern", DELIVERY_QC_PATTERN)
    _require_config_value(result, canonical, "adoption_pattern", ADOPTION_PATTERN)
    _require_config_value(result, canonical, "canary_outcome_pattern", CANARY_OUTCOME_PATTERN)
    _require_config_value(result, canonical, "activation_pattern", ACTIVATION_PATTERN)

    policy = config.get("policy")
    if not isinstance(policy, dict) or policy.get("approved_status") != "approved":
        result.block("malformed_config", "specbound.yaml", "policy.approved_status must equal 'approved'")
    if not isinstance(policy, dict) or policy.get("confirmed_discovery_status") != "confirmed":
        result.block(
            "malformed_config",
            "specbound.yaml",
            "policy.confirmed_discovery_status must equal 'confirmed'",
        )
    if not isinstance(policy, dict) or policy.get("discovery_confirmation_revision_policy") != LATEST_ONLY_WITH_EXCEPTION:
        result.block(
            "malformed_config",
            "specbound.yaml",
            "policy.discovery_confirmation_revision_policy must equal 'latest_only_with_explicit_exception'",
        )
    if not isinstance(policy, dict) or policy.get("requirement_revision_policy") != LATEST_ONLY_WITH_EXCEPTION:
        result.block(
            "malformed_config",
            "specbound.yaml",
            "policy.requirement_revision_policy must equal 'latest_only_with_explicit_exception'",
        )
    _validate_required_field_config(result, policy, "required_approval_fields", REQUIRED_APPROVAL_FIELDS)
    _validate_required_field_config(result, policy, "required_rejection_fields", REQUIRED_REJECTION_FIELDS)
    _validate_required_field_config(result, policy, "required_review_submission_fields", REQUIRED_REVIEW_SUBMISSION_FIELDS)
    _validate_required_field_config(
        result,
        policy,
        "required_discovery_confirmation_fields",
        REQUIRED_DISCOVERY_CONFIRMATION_FIELDS,
    )
    _validate_required_field_config(
        result,
        policy,
        "required_micro_spec_review_fields",
        REQUIRED_MICRO_SPEC_REVIEW_FIELDS,
    )
    authorities_by_risk = policy.get("discovery_confirmation_authorities_by_risk") if isinstance(policy, dict) else None
    if not isinstance(authorities_by_risk, dict) or not authorities_by_risk or not all(
        isinstance(risk_class, str)
        and risk_class.strip()
        and isinstance(authorities, list)
        and authorities
        and all(isinstance(authority, str) and authority.strip() for authority in authorities)
        for risk_class, authorities in authorities_by_risk.items()
    ):
        result.block(
            "malformed_config",
            "specbound.yaml",
            "policy.discovery_confirmation_authorities_by_risk must map each non-empty risk class to a non-empty list of non-empty authority strings",
        )
    requirement_authorities_by_risk = policy.get("requirement_review_authorities_by_risk") if isinstance(policy, dict) else None
    if not isinstance(requirement_authorities_by_risk, dict) or not requirement_authorities_by_risk or not all(
        isinstance(risk, str)
        and risk.strip()
        and isinstance(authorities, list)
        and authorities
        and all(isinstance(authority, str) and authority.strip() for authority in authorities)
        for risk, authorities in requirement_authorities_by_risk.items()
    ):
        result.block(
            "malformed_config",
            "specbound.yaml",
            "policy.requirement_review_authorities_by_risk must map each non-empty risk to a non-empty list of non-empty authority strings",
        )
    delivery_qc_authorities_by_risk = policy.get("delivery_qc_authorities_by_risk") if isinstance(policy, dict) else None
    micro_spec_review_authorities_by_risk = policy.get("micro_spec_review_authorities_by_risk") if isinstance(policy, dict) else None
    if not isinstance(micro_spec_review_authorities_by_risk, dict) or not micro_spec_review_authorities_by_risk or not all(
        isinstance(risk, str)
        and risk.strip()
        and isinstance(authorities, list)
        and authorities
        and all(isinstance(authority, str) and authority.strip() for authority in authorities)
        for risk, authorities in micro_spec_review_authorities_by_risk.items()
    ):
        result.block(
            "malformed_config",
            "specbound.yaml",
            "policy.micro_spec_review_authorities_by_risk must map each non-empty risk to a non-empty list of non-empty authority strings",
        )
    if not isinstance(delivery_qc_authorities_by_risk, dict) or not delivery_qc_authorities_by_risk or not all(
        isinstance(risk, str)
        and risk.strip()
        and isinstance(authorities, list)
        and authorities
        and all(isinstance(authority, str) and authority.strip() for authority in authorities)
        for risk, authorities in delivery_qc_authorities_by_risk.items()
    ):
        result.block(
            "malformed_config",
            "specbound.yaml",
            "policy.delivery_qc_authorities_by_risk must map each non-empty risk to a non-empty list of non-empty authority strings",
        )
    _validate_control_plane_authority_aliases(result, policy)
    _validate_legacy_control_plane_adoption_config(result, policy)
    agent_contract = policy.get("agent_contract") if isinstance(policy, dict) else None
    if agent_contract is not None:
        if (
            not isinstance(agent_contract, dict)
            or set(agent_contract) != {"enabled", "roles_path"}
            or not isinstance(agent_contract.get("enabled"), bool)
            or not isinstance(agent_contract.get("roles_path"), str)
            or not _safe_relative(agent_contract.get("roles_path"))
        ):
            result.block(
                "malformed_config",
                "specbound.yaml",
                "policy.agent_contract must contain exactly boolean enabled and a safe repository-relative roles_path",
            )
    return result


def _validate_required_field_config(
    result: Result, policy: Any, name: str, required: set[str]
) -> None:
    fields = policy.get(name) if isinstance(policy, dict) else None
    if not isinstance(fields, list) or not all(isinstance(field, str) for field in fields):
        result.block("malformed_config", "specbound.yaml", f"policy.{name} must be a list of strings")
    elif not required.issubset(set(fields)):
        result.block("malformed_config", "specbound.yaml", f"policy.{name} must include the bootstrap fields")


def _validate_control_plane_authority_aliases(result: Result, policy: Any) -> None:
    expected = {"inherit": "discovery_confirmation_authorities_by_risk"}
    for name in (
        "control_plane_adoption_authorities_by_risk",
        "control_plane_activation_authorities_by_risk",
    ):
        value = policy.get(name) if isinstance(policy, dict) else None
        if value != expected:
            result.block(
                "malformed_config",
                "specbound.yaml",
                f"policy.{name} must equal the exact discovery-confirmation authority alias",
            )


def _validate_legacy_control_plane_adoption_config(result: Result, policy: Any) -> None:
    """Allow only the historical empty registry shape; it establishes no state."""
    if not isinstance(policy, dict) or "control_plane_adoption" not in policy:
        return
    adoption = policy["control_plane_adoption"]
    if adoption != {"schema_version": CONTROL_PLANE_ADOPTION_SCHEMA_VERSION, "requirements": []}:
        result.block(
            "malformed_config",
            "specbound.yaml",
            "legacy policy.control_plane_adoption must equal the exact empty compatibility shape",
        )


def _safe_relative(path: str) -> bool:
    candidate = PurePosixPath(path)
    return bool(path) and not candidate.is_absolute() and ".." not in candidate.parts and "." not in candidate.parts


def _first_symlink_component(root: Path, path: Path) -> Path | None:
    """Return a symlink in ``path`` below ``root``, including intermediate directories."""
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return path
    current = root
    for part in parts:
        current /= part
        if current.is_symlink():
            return current
    return None


def _frontmatter(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError("missing YAML frontmatter opening delimiter")
    closing_index = text.find("\n---\n", len("---\n"))
    if closing_index < 0:
        raise ValueError("missing YAML frontmatter closing delimiter")
    metadata = yaml.safe_load(text[len("---\n") : closing_index])
    if not isinstance(metadata, dict):
        raise ValueError("frontmatter must be a mapping")
    return metadata


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _transitioned_discovery_text(text: str, expected_status: str, new_status: str) -> str:
    """Return text with exactly one frontmatter status transition applied."""
    if not text.startswith("---\n"):
        raise ValueError("missing YAML frontmatter opening delimiter")
    closing_index = text.find("\n---\n", len("---\n"))
    if closing_index < 0:
        raise ValueError("missing YAML frontmatter closing delimiter")
    frontmatter_end = closing_index + 1
    frontmatter = text[:frontmatter_end]
    pattern = re.compile(rf"(?m)^status:[ \t]*(?:['\"]?{re.escape(expected_status)}['\"]?)[ \t]*$")
    matches = list(pattern.finditer(frontmatter))
    if len(matches) != 1:
        raise ValueError(f"frontmatter must contain exactly one status: {expected_status!r} entry")
    match = matches[0]
    replacement = f"status: {new_status}"
    return frontmatter[: match.start()] + replacement + frontmatter[match.end() :] + text[frontmatter_end:]


def _transitioned_discovery_digest(path: Path, expected_status: str, new_status: str) -> str:
    text = path.read_text(encoding="utf-8")
    return sha256(_transitioned_discovery_text(text, expected_status, new_status).encode("utf-8")).hexdigest()


def _atomic_replace_text(path: Path, text: str) -> None:
    """Atomically replace one UTF-8 file, cleaning a same-directory temporary on failure."""
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except OSError:
        temporary_path.unlink(missing_ok=True)
        raise


def _validate_requirement(root: Path, path: Path, result: Result, latest_approved_revisions: dict[str, int]) -> None:
    relative = path.relative_to(root).as_posix()
    symlink = _first_symlink_component(root, path)
    if symlink:
        result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "canonical REQ path must not contain a symlink")
        return
    path_parts = path.relative_to(root / REQUIRED_ROOTS["requirements_root"]).parts
    if len(path_parts) != 2:
        result.block("invalid_requirement_path", relative, "REQ must be directly below req-<id>/")
        return
    directory_id, filename = path_parts
    match = REQUIREMENT_RE.fullmatch(filename)
    if not match or match.group(1) != directory_id:
        result.block("invalid_requirement_path", relative, "expected req-<id>/req-<id>-r<revision>.md")
        return

    requirement_id, revision_text = match.groups()
    try:
        metadata = _frontmatter(path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        result.block("malformed_requirement", relative, str(exc))
        return
    result.checked_requirements += 1

    revision = metadata.get("revision")
    if (
        metadata.get("id") != requirement_id
        or not isinstance(revision, int)
        or isinstance(revision, bool)
        or revision != int(revision_text)
    ):
        result.block("requirement_binding_mismatch", relative, "frontmatter id/revision differs from path")
        return
    status = metadata.get("status")
    if status not in {"draft", "in_review", "approved", "rejected"}:
        result.block("malformed_requirement", relative, "frontmatter status must be 'draft', 'in_review', 'approved', or 'rejected'")
        return
    if status == "rejected":
        rejection_relative = f".specbound/rejections/{requirement_id}-r{revision_text}.rejection.json"
        rejection_path = root / rejection_relative
        approval_path = root / f".specbound/approvals/{requirement_id}-r{revision_text}.approval.json"
        symlink = _first_symlink_component(root, rejection_path)
        if symlink:
            result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "rejection path must not contain a symlink")
        elif not rejection_path.is_file():
            result.block("missing_rejection", rejection_relative, "rejected REQ has no rejection record")
        if approval_path.exists():
            result.block("conflicting_requirement_decision", relative, "rejected REQ must not retain an approval record")
        return
    if status == "in_review":
        submission_relative = f".specbound/review-submissions/{requirement_id}-r{revision_text}.review-submission.json"
        submission_path = root / submission_relative
        approval_path = root / f".specbound/approvals/{requirement_id}-r{revision_text}.approval.json"
        rejection_path = root / f".specbound/rejections/{requirement_id}-r{revision_text}.rejection.json"
        symlink = _first_symlink_component(root, submission_path)
        if symlink:
            result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "review-submission path must not contain a symlink")
        elif not submission_path.is_file():
            result.block("missing_review_submission", submission_relative, "in_review REQ has no review-submission record")
        reconsideration_path = root / f".specbound/reconsiderations/{requirement_id}-r{revision_text}.reconsideration.json"
        if approval_path.exists() or (rejection_path.exists() and not reconsideration_path.is_file()):
            result.block("conflicting_requirement_decision", relative, "in_review REQ may retain a rejection only with append-only reconsideration evidence")
        return
    if status == "draft":
        submission_path = root / f".specbound/review-submissions/{requirement_id}-r{revision_text}.review-submission.json"
        if submission_path.exists():
            result.block("conflicting_requirement_decision", relative, "draft REQ must not retain a review-submission record")
        return
    if status != "approved":
        return

    initially_valid = len(result.blockers)
    approval_relative = f".specbound/approvals/{requirement_id}-r{revision_text}.approval.json"
    approval_path = root / approval_relative
    symlink = _first_symlink_component(root, approval_path)
    if symlink:
        result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "approval path must not contain a symlink")
        return
    try:
        approval = json.loads(approval_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        result.block("missing_approval", approval_relative, "approved REQ has no approval record")
        return
    except (OSError, json.JSONDecodeError) as exc:
        result.block("malformed_approval", approval_relative, str(exc))
        return
    if not isinstance(approval, dict):
        result.block("malformed_approval", approval_relative, "approval record must be an object")
        return

    missing = sorted(REQUIRED_APPROVAL_FIELDS - set(approval))
    if missing:
        result.block("malformed_approval", approval_relative, f"missing fields: {', '.join(missing)}")
        return
    bound_path = approval["requirement_path"]
    if not isinstance(bound_path, str) or not _safe_relative(bound_path):
        result.block("unsafe_artifact_path", approval_relative, "requirement_path must be safe relative path")
        return
    if bound_path != relative:
        result.block("requirement_binding_mismatch", approval_relative, "requirement_path differs from REQ path")
    approval_revision = approval["revision"]
    if (
        approval["requirement_id"] != requirement_id
        or not isinstance(approval_revision, int)
        or isinstance(approval_revision, bool)
        or approval_revision != int(revision_text)
    ):
        result.block("requirement_binding_mismatch", approval_relative, "approval id/revision differs from REQ")
    if not isinstance(approval["risk"], str) or not approval["risk"].strip() or approval["risk"] != metadata.get("risk"):
        result.block("requirement_binding_mismatch", approval_relative, "approval risk differs from REQ")
    if not isinstance(approval["authority"], str) or not approval["authority"].strip():
        result.block("invalid_approval_authority", approval_relative, "authority must be a non-empty string")
    if not isinstance(approval["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", approval["sha256"]):
        result.block("malformed_approval", approval_relative, "sha256 must be a lowercase 64-character hex digest")
    elif approval["sha256"] != _digest(path):
        result.block("requirement_digest_mismatch", approval_relative, "approval digest differs from REQ content")
    latest_revision = latest_approved_revisions.get(requirement_id, revision)
    if revision < latest_revision and approval.get("issuance_mode") != "manual_bootstrap_exception":
        exception = approval.get("supersession_exception")
        if exception is None:
            result.block(
                "superseded_requirement_revision",
                approval_relative,
                f"r{revision} is not latest r{latest_revision}; require a substantive authority-bound supersession_exception",
            )
        elif (
            not isinstance(exception, dict)
            or set(exception) != {"reason", "authority", "recorded_at"}
            or not isinstance(exception.get("reason"), str)
            or not exception["reason"].strip()
            or PLACEHOLDER_RE.search(exception["reason"])
            or exception.get("authority") != approval.get("authority")
            or not _valid_timestamp(exception.get("recorded_at"))
        ):
            result.block(
                "malformed_supersession_exception",
                approval_relative,
                "supersession_exception must bind a substantive reason, matching authority, and ISO-8601 recorded_at",
            )
    if len(result.blockers) == initially_valid:
        result.approved_requirements += 1


def _validate_requirement_review_submission(root: Path, path: Path, result: Result) -> None:
    """Validate the non-authorizing, exact-snapshot draft-to-review handoff record."""
    relative = path.relative_to(root).as_posix()
    symlink = _first_symlink_component(root, path)
    if symlink:
        result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "review-submission path must not contain a symlink")
        return
    try:
        parts = path.relative_to(root / REQUIRED_ROOTS["review_submissions_root"]).parts
    except ValueError:
        result.block("invalid_review_submission_path", relative, "review submission is outside its canonical root")
        return
    if len(parts) != 1 or not (match := REQUIREMENT_REVIEW_SUBMISSION_RE.fullmatch(parts[0])):
        result.block("invalid_review_submission_path", relative, "expected req-<id>-r<revision>.review-submission.json")
        return
    requirement_id, revision_text = match.groups()
    requirement_relative = canonical_requirement_relative(requirement_id, revision_text)
    requirement_path = root / requirement_relative
    try:
        submission = json.loads(path.read_text(encoding="utf-8"))
        metadata = _frontmatter(requirement_path)
    except FileNotFoundError:
        result.block("missing_requirement", requirement_relative, "review submission references a missing REQ")
        return
    except (OSError, ValueError, yaml.YAMLError, json.JSONDecodeError) as exc:
        result.block("malformed_review_submission", relative, str(exc))
        return
    if not isinstance(submission, dict):
        result.block("malformed_review_submission", relative, "review submission record must be an object")
        return
    missing = sorted(REQUIRED_REVIEW_SUBMISSION_FIELDS - set(submission))
    if missing:
        result.block("malformed_review_submission", relative, f"missing fields: {', '.join(missing)}")
        return
    if (
        submission.get("schema_version") != 1
        or submission.get("requirement_path") != requirement_relative
        or submission.get("requirement_id") != requirement_id
        or submission.get("revision") != int(revision_text)
        or metadata.get("id") != requirement_id
        or metadata.get("revision") != int(revision_text)
        or metadata.get("status") not in {"in_review", "rejected", "approved"}
    ):
        result.block("review_submission_binding_mismatch", relative, "review submission must bind the canonical in_review REQ or a later digest-bound outcome")
    if submission.get("decision") != "submitted_for_review" or submission.get("permitted_next_action") != "review_decision_only":
        result.block("invalid_review_submission_decision", relative, "submission is non-authorizing and must permit only review_decision_only")
    for field in ("risk", "owner"):
        value = submission.get(field)
        if not isinstance(value, str) or not value.strip() or PLACEHOLDER_RE.search(value) or value != metadata.get(field):
            result.block("review_submission_binding_mismatch", relative, f"{field} differs from the REQ")
    if not _valid_timestamp(submission.get("submitted_at")):
        result.block("malformed_review_submission", relative, "submitted_at must be an ISO-8601 timestamp")
    try:
        current_text = requirement_path.read_text(encoding="utf-8")
        if metadata.get("status") == "in_review":
            reviewed_text = current_text
        elif metadata.get("status") == "rejected":
            reviewed_text = _transitioned_discovery_text(current_text, "rejected", "in_review")
        else:
            reviewed_text = _transitioned_discovery_text(current_text, "approved", "in_review")
        draft_text = _transitioned_discovery_text(reviewed_text, "in_review", "draft")
    except (OSError, ValueError) as exc:
        result.block("review_submission_digest_mismatch", relative, f"cannot reconstruct submitted snapshots: {exc}")
        return
    for key, expected in (
        ("draft_sha256", sha256(draft_text.encode("utf-8")).hexdigest()),
        ("reviewed_sha256", sha256(reviewed_text.encode("utf-8")).hexdigest()),
    ):
        value = submission.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
            result.block("malformed_review_submission", relative, f"{key} must be a lowercase 64-character hex digest")
        elif value != expected:
            result.block("review_submission_digest_mismatch", relative, f"{key} differs from the bound REQ content")


def _validate_requirement_rejection(
    root: Path, path: Path, result: Result, allowed_authorities_by_risk: dict[str, set[str]]
) -> None:
    relative = path.relative_to(root).as_posix()
    symlink = _first_symlink_component(root, path)
    if symlink:
        result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "rejection path must not contain a symlink")
        return
    try:
        parts = path.relative_to(root / REQUIRED_ROOTS["rejections_root"]).parts
    except ValueError:
        result.block("invalid_rejection_path", relative, "rejection is outside its canonical root")
        return
    if len(parts) != 1 or not (match := REQUIREMENT_REJECTION_RE.fullmatch(parts[0])):
        result.block("invalid_rejection_path", relative, "expected req-<id>-r<revision>.rejection.json")
        return
    requirement_id, revision_text = match.groups()
    requirement_relative = canonical_requirement_relative(requirement_id, revision_text)
    requirement_path = root / requirement_relative
    try:
        rejection = json.loads(path.read_text(encoding="utf-8"))
        metadata = _frontmatter(requirement_path)
    except FileNotFoundError:
        result.block("missing_requirement", requirement_relative, "rejection references a missing REQ")
        return
    except (OSError, ValueError, yaml.YAMLError, json.JSONDecodeError) as exc:
        result.block("malformed_rejection", relative, str(exc))
        return
    if not isinstance(rejection, dict):
        result.block("malformed_rejection", relative, "rejection record must be an object")
        return
    missing = sorted(REQUIRED_REJECTION_FIELDS - set(rejection))
    if missing:
        result.block("malformed_rejection", relative, f"missing fields: {', '.join(missing)}")
        return
    if (
        rejection.get("schema_version") != 1
        or rejection.get("requirement_path") != requirement_relative
        or rejection.get("requirement_id") != requirement_id
        or rejection.get("revision") != int(revision_text)
        or metadata.get("id") != requirement_id
        or metadata.get("revision") != int(revision_text)
        or metadata.get("status") not in {"rejected", "in_review", "approved"}
    ):
        result.block("rejection_binding_mismatch", relative, "rejection must bind the canonical rejected, reconsidered, or approved REQ")
    risk = metadata.get("risk")
    if not isinstance(rejection.get("risk"), str) or rejection["risk"] != risk:
        result.block("rejection_binding_mismatch", relative, "rejection risk differs from REQ")
    authority = rejection.get("authority")
    if (
        not isinstance(authority, str)
        or not authority.strip()
        or not isinstance(risk, str)
        or authority not in allowed_authorities_by_risk.get(risk, set())
    ):
        result.block("invalid_rejection_authority", relative, "authority is not allowlisted for the REQ risk")
    if rejection.get("decision") != "rejected":
        result.block("invalid_rejection_decision", relative, "decision must equal 'rejected'")
    if not isinstance(rejection.get("reason"), str) or not rejection["reason"].strip() or PLACEHOLDER_RE.search(rejection["reason"]):
        result.block("malformed_rejection", relative, "reason must be substantive and non-placeholder")
    if not _valid_timestamp(rejection.get("rejected_at")):
        result.block("malformed_rejection", relative, "rejected_at must be an ISO-8601 timestamp")
    if metadata.get("status") == "rejected":
        expected_reviewed = _transitioned_discovery_digest(requirement_path, "rejected", "in_review")
        expected_rejected = _digest(requirement_path)
    else:
        reconsideration = root / ".specbound/reconsiderations" / f"{requirement_id}-r{revision_text}.reconsideration.json"
        if not reconsideration.is_file():
            result.block("rejection_reconsideration_missing", relative, "non-rejected REQ retaining rejection evidence requires append-only reconsideration evidence")
            return
        current = requirement_path.read_text(encoding="utf-8")
        reviewed = current if metadata.get("status") == "in_review" else _transitioned_discovery_text(current, "approved", "in_review")
        expected_reviewed = sha256(reviewed.encode("utf-8")).hexdigest()
        expected_rejected = sha256(_transitioned_discovery_text(reviewed, "in_review", "rejected").encode("utf-8")).hexdigest()
    for key, expected in (("reviewed_sha256", expected_reviewed), ("sha256", expected_rejected)):
        value = rejection.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
            result.block("malformed_rejection", relative, f"{key} must be a lowercase 64-character hex digest")
        elif value != expected:
            result.block("rejection_digest_mismatch", relative, f"{key} differs from the bound REQ content")


def _validate_discovery(root: Path, path: Path, result: Result) -> None:
    relative = path.relative_to(root).as_posix()
    symlink = _first_symlink_component(root, path)
    if symlink:
        result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "canonical Discovery path must not contain a symlink")
        return
    path_parts = path.relative_to(root / REQUIRED_ROOTS["discoveries_root"]).parts
    if len(path_parts) != 1:
        result.block("invalid_discovery_path", relative, "Discovery must be directly below its canonical root")
        return
    filename_match = DISCOVERY_RE.fullmatch(path_parts[0])
    if not filename_match:
        result.block("invalid_discovery_path", relative, "expected dcy-<id>-r<revision>.md")
        return

    discovery_id, revision_text = filename_match.groups()
    try:
        metadata = _frontmatter(path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        result.block("malformed_discovery", relative, str(exc))
        return
    result.checked_discoveries += 1
    missing_metadata = sorted(REQUIRED_DISCOVERY_METADATA - set(metadata))
    if missing_metadata:
        result.block("malformed_discovery", relative, f"missing frontmatter fields: {', '.join(missing_metadata)}")
        return
    revision = metadata.get("revision")
    if (
        metadata.get("id") != discovery_id
        or not isinstance(revision, int)
        or isinstance(revision, bool)
        or revision != int(revision_text)
    ):
        result.block("discovery_binding_mismatch", relative, "frontmatter id/revision differs from path")
        return
    status = metadata.get("status")
    if status not in {"draft", "in_review", "confirmed"}:
        result.block("malformed_discovery", relative, "frontmatter status must be 'draft', 'in_review', or 'confirmed'")
    elif status == "confirmed":
        confirmation_relative = f".specbound/confirmations/{discovery_id}-r{revision_text}.confirmation.json"
        confirmation_path = root / confirmation_relative
        symlink = _first_symlink_component(root, confirmation_path)
        if symlink:
            result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "confirmation path must not contain a symlink")
        elif not confirmation_path.is_file():
            result.block("missing_discovery_confirmation", confirmation_relative, "confirmed Discovery has no confirmation record")
    for field in ("title", "issue_ref", "owner", "risk_class"):
        value = metadata.get(field)
        if not isinstance(value, str) or not value.strip() or PLACEHOLDER_RE.search(value):
            result.block("malformed_discovery", relative, f"frontmatter {field} must be a non-placeholder string")
    if not isinstance(metadata.get("source_refs"), list) or not all(isinstance(value, str) for value in metadata["source_refs"]):
        result.block("malformed_discovery", relative, "frontmatter source_refs must be a list of strings")


def _discovery_has_confirmation_evidence(path: Path) -> bool:
    text = path.read_text(encoding="utf-8")
    for heading in REQUIRED_DISCOVERY_HEADINGS:
        marker = f"\n{heading}\n"
        start = text.find(marker)
        if start < 0:
            return False
        content_start = start + len(marker)
        next_heading = text.find("\n## ", content_start)
        content = text[content_start:] if next_heading < 0 else text[content_start:next_heading]
        if not content.strip() or PLACEHOLDER_RE.search(content):
            return False
    return True


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


class RequirementDraftError(ValueError):
    def __init__(self, code: str, path: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.path = path
        self.detail = detail


def create_requirement_draft(root: Path, discovery_target: str, requirement_target: str) -> Path:
    """Create one canonical, non-overwritable draft REQ from exact Discovery evidence."""
    discovery_match = DISCOVERY_RE.fullmatch(f"{discovery_target}.md")
    requirement_match = REQUIREMENT_RE.fullmatch(f"{requirement_target}.md")
    if not discovery_match:
        raise RequirementDraftError("invalid_discovery_target", discovery_target, "target must be dcy-<id>-r<revision>")
    if not requirement_match:
        raise RequirementDraftError("invalid_requirement_target", requirement_target, "target must be req-<id>-r<revision>")
    discovery_id, discovery_revision_text = discovery_match.groups()
    requirement_id, requirement_revision_text = requirement_match.groups()
    discovery_relative = f".specbound/discoveries/{discovery_target}.md"
    confirmation_relative = f".specbound/confirmations/{discovery_target}.confirmation.json"
    requirement_relative = canonical_requirement_relative(requirement_id, requirement_revision_text)
    before = validate(root)
    if not before.valid:
        parent_blocker = next(
            (blocker for blocker in before.blockers if blocker["path"] in {discovery_relative, confirmation_relative}),
            None,
        )
        if parent_blocker:
            raise RequirementDraftError(
                parent_blocker["code"], parent_blocker["path"], parent_blocker["detail"]
            )
        raise RequirementDraftError("repository_validation_failed", ".", "repository must pass specbound validate before draft issuance")
    discovery_path = root / discovery_relative
    confirmation_path = root / confirmation_relative
    requirement_path = root / requirement_relative
    for path, label in ((discovery_path, "Discovery"), (confirmation_path, "confirmation"), (requirement_path.parent, "REQ directory")):
        symlink = _first_symlink_component(root, path)
        if symlink:
            raise RequirementDraftError("unsafe_artifact_path", symlink.relative_to(root).as_posix(), f"canonical {label} path must not contain a symlink")
    if requirement_path.exists():
        raise RequirementDraftError("requirement_already_exists", requirement_relative, "draft issuance is non-overwritable; mint a new revision")
    try:
        discovery = _frontmatter(discovery_path)
        confirmation = json.loads(confirmation_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RequirementDraftError("missing_parent_evidence", discovery_relative, "confirmed Discovery and matching confirmation are required") from exc
    except (OSError, ValueError, yaml.YAMLError, json.JSONDecodeError) as exc:
        raise RequirementDraftError("malformed_parent_evidence", discovery_relative, str(exc)) from exc
    if not isinstance(confirmation, dict):
        raise RequirementDraftError("malformed_parent_evidence", confirmation_relative, "confirmation record must be an object")
    if (
        discovery.get("id") != discovery_id
        or discovery.get("revision") != int(discovery_revision_text)
        or discovery.get("status") != "confirmed"
        or confirmation.get("discovery_path") != discovery_relative
        or confirmation.get("discovery_id") != discovery_id
        or confirmation.get("revision") != int(discovery_revision_text)
        or confirmation.get("decision") != "confirmed"
        or confirmation.get("permitted_next_action") != "draft_req_only"
        or confirmation.get("sha256") != _digest(discovery_path)
    ):
        raise RequirementDraftError("invalid_parent_authorization", confirmation_relative, "parent must be exact, confirmed, digest-bound, and authorize draft_req_only")
    risk = discovery.get("risk_class")
    if not isinstance(risk, str) or not risk.strip():
        raise RequirementDraftError("malformed_parent_evidence", discovery_relative, "Discovery risk_class must be a non-empty string")
    text = (
        "---\n"
        f"id: {requirement_id}\nrevision: {int(requirement_revision_text)}\nstatus: draft\nrisk: {risk}\nowner: repository-maintainer\n"
        "parent_discovery:\n"
        f"  id: {discovery_id}\n  revision: {int(discovery_revision_text)}\n  path: {discovery_relative}\n"
        f"  sha256: {confirmation['sha256']}\n  confirmation_path: {confirmation_relative}\n---\n\n"
        f"# REQ: {requirement_id} r{int(requirement_revision_text)}\n\n"
        "> **Lifecycle boundary:** 이 artifact의 lifecycle state는 frontmatter와 이에 대응하는 content-addressed decision record로만 결정된다. This artifact's lifecycle state is determined only by frontmatter plus its matching content-addressed decision record. `draft` 발급은 review, rejection, approval 또는 implementation 권한이 아니다. Draft issuance is not review, rejection, approval, or implementation authority.\n\n"
        "> **Review handoff:** `draft` REQ는 먼저 `specbound req check-readiness <req-id>-r<revision>`를 통과한 뒤에만 `specbound req to-in-review <req-id>-r<revision>`로 제출한다. canonical CLI는 exact draft/reviewed digest를 가진 non-authorizing review-submission record와 `in_review` 상태를 rollback-safe하게 함께 발급한다. `in_review` REQ는 `specbound req reject`를 통해서만 rejected 처리할 수 있다. Approval, implementation, merge, delivery, and release remain separate actions.\n\n"
        "## 목표 (Goal)\n\n<검증 가능한 결과>\n\n"
        "## Scope (범위)\n\n- <포함되는 동작>\n\n"
        "## Non-goals (비목표)\n\n- approval 발급, implementation, merge, delivery, release는 각각 별도의 action이다. Approval issuance, implementation, merge, delivery, and release are separate actions.\n\n"
        "## Acceptance criteria\n\n"
        "> **AC completion contract:** 각 AC는 독립적으로 검토 가능한 observable behavior를 기술해야 한다. 모든 field의 placeholder를 review 전에 실제 내용으로 교체한다. 이 template은 approval 또는 implementation 권한을 부여하지 않는다.\n\n"
        "### AC-001 — <짧고 구체적인 결과 이름>\n\n"
        "- `observable_success`: <사용자·CLI·fixture가 관찰할 성공 결과>\n"
        "- `required_preconditions`: <필요한 parent, authority, input, state, fixture>\n"
        "- `mutation_boundary`: <허용되는 mutation 및 절대 변경하면 안 되는 대상>\n"
        "- `negative_behavior`: <invalid/failure request의 reject 결과와 no-mutation 보장>\n"
        "- `direct_evidence`: <이 AC의 성공·실패를 직접 증명할 command, fixture, assertion>\n"
        "- `dependencies`: <none 또는 선행 AC ID / shared contract>\n"
        "- `completion_group`: <이 AC만으로 완료 가능한 경우 자체 group; 함께 완료해야 하면 group ID와 이유>\n"
        "- `candidate_micro_spec`: <예상 Micro-SPEC slice ID 또는 아직 미정인 이유>\n"
        "- `non_goals`: <이 AC를 완료해도 주장하지 않는 behavior>\n\n"
        "### AC-002 — <필요한 만큼 같은 completion contract를 복제>\n\n"
        "- `observable_success`: <...>\n"
        "- `required_preconditions`: <...>\n"
        "- `mutation_boundary`: <...>\n"
        "- `negative_behavior`: <...>\n"
        "- `direct_evidence`: <...>\n"
        "- `dependencies`: <none 또는 AC ID>\n"
        "- `completion_group`: <group ID와 이유>\n"
        "- `candidate_micro_spec`: <예상 slice ID 또는 이유>\n"
        "- `non_goals`: <...>\n\n"
        "`draft` REQ must pass `specbound req check-readiness` before review submission. Use `specbound req to-in-review` for the canonical rollback-safe handoff; never patch `status` manually.\n\n"
        "## Approval handoff\n\n이 정확한 draft를 별도로 review한다. artifact 발급 사실만으로 approval을 추론하지 않는다. Review the exact snapshot separately; do not infer approval from issuance.\n"
    )
    if not requirement_path.parent.exists():
        try:
            requirement_path.parent.mkdir()
        except FileExistsError:
            pass
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        requirement_directory_fd = os.open(requirement_path.parent, directory_flags)
    except OSError as exc:
        raise RequirementDraftError(
            "unsafe_artifact_path",
            requirement_path.parent.relative_to(root).as_posix(),
            "canonical REQ directory must remain a non-symlink directory",
        ) from exc
    published_identity: tuple[int, int] | None = None

    def remove_published_draft_if_owned() -> None:
        if published_identity is None:
            return
        try:
            target_stat = os.stat(
                requirement_path.name,
                dir_fd=requirement_directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        if (target_stat.st_dev, target_stat.st_ino) == published_identity:
            os.unlink(requirement_path.name, dir_fd=requirement_directory_fd)

    try:
        target_flags = os.O_WRONLY | os.O_TMPFILE
        try:
            requirement_fd = os.open(".", target_flags, 0o666, dir_fd=requirement_directory_fd)
        except OSError as exc:
            raise RequirementDraftError("requirement_write_failed", requirement_relative, str(exc)) from exc
        try:
            with os.fdopen(requirement_fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
                source_stat = os.fstat(handle.fileno())
                try:
                    os.link(
                        f"/proc/self/fd/{handle.fileno()}",
                        requirement_path.name,
                        dst_dir_fd=requirement_directory_fd,
                        follow_symlinks=True,
                    )
                except FileExistsError as exc:
                    raise RequirementDraftError(
                        "requirement_already_exists",
                        requirement_relative,
                        "draft issuance is non-overwritable; mint a new revision",
                    ) from exc
                published_identity = (source_stat.st_dev, source_stat.st_ino)
                os.fsync(requirement_directory_fd)
        except RequirementDraftError:
            remove_published_draft_if_owned()
            raise
        except OSError as exc:
            remove_published_draft_if_owned()
            raise RequirementDraftError("requirement_write_failed", requirement_relative, str(exc)) from exc
        if validate(root).valid:
            return requirement_path
        remove_published_draft_if_owned()
        raise RequirementDraftError("generated_requirement_invalid", requirement_relative, "generated draft did not pass specbound validate")
    finally:
        os.close(requirement_directory_fd)


class ConfirmationError(ValueError):
    def __init__(self, code: str, path: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.path = path
        self.detail = detail


def _validate_discovery_confirmation(
    root: Path, path: Path, result: Result, allowed_authorities_by_risk: dict[str, set[str]]
) -> None:
    initial_blocker_count = len(result.blockers)
    relative = path.relative_to(root).as_posix()
    symlink = _first_symlink_component(root, path)
    if symlink:
        result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "Discovery confirmation path must not contain a symlink")
        return
    try:
        parts = path.relative_to(root / REQUIRED_ROOTS["discovery_confirmations_root"]).parts
    except ValueError:
        result.block("invalid_discovery_confirmation_path", relative, "confirmation is outside its canonical root")
        return
    if len(parts) != 1:
        result.block("invalid_discovery_confirmation_path", relative, "confirmation must be directly below its canonical root")
        return
    name_match = DISCOVERY_CONFIRMATION_RE.fullmatch(parts[0])
    if not name_match:
        result.block("invalid_discovery_confirmation_path", relative, "expected dcy-<id>-r<revision>.confirmation.json")
        return
    expected_id, revision_text = name_match.groups()
    try:
        confirmation = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result.block("malformed_discovery_confirmation", relative, str(exc))
        return
    if not isinstance(confirmation, dict):
        result.block("malformed_discovery_confirmation", relative, "confirmation record must be an object")
        return
    missing = sorted(REQUIRED_DISCOVERY_CONFIRMATION_FIELDS - set(confirmation))
    if missing:
        result.block("malformed_discovery_confirmation", relative, f"missing fields: {', '.join(missing)}")
        return

    bound_path = confirmation["discovery_path"]
    if not isinstance(bound_path, str) or not _safe_relative(bound_path):
        result.block("unsafe_artifact_path", relative, "discovery_path must be a safe repository-relative path")
        return
    expected_discovery_path = f".specbound/discoveries/{expected_id}-r{revision_text}.md"
    if bound_path != expected_discovery_path:
        result.block("discovery_binding_mismatch", relative, "discovery_path differs from confirmation filename binding")
        return
    discovery_path = root / bound_path
    symlink = _first_symlink_component(root, discovery_path)
    if symlink:
        result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "bound Discovery path must not contain a symlink")
        return
    if not discovery_path.is_file():
        result.block("missing_discovery", bound_path, "confirmation references a missing Discovery")
        return
    try:
        metadata = _frontmatter(discovery_path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        result.block("malformed_discovery", bound_path, str(exc))
        return

    confirmation_revision = confirmation["revision"]
    if (
        confirmation["discovery_id"] != expected_id
        or metadata.get("id") != expected_id
        or not isinstance(confirmation_revision, int)
        or isinstance(confirmation_revision, bool)
        or confirmation_revision != int(revision_text)
        or metadata.get("revision") != int(revision_text)
    ):
        result.block("discovery_binding_mismatch", relative, "discovery id/revision differs from the bound Discovery")
    if confirmation.get("schema_version") != 1:
        result.block("malformed_discovery_confirmation", relative, "schema_version must equal integer 1")
    if metadata.get("status") != "confirmed":
        result.block("discovery_binding_mismatch", relative, "confirmation requires Discovery status 'confirmed'")
    if confirmation["decision"] != "confirmed":
        result.block("invalid_discovery_confirmation_decision", relative, "decision must equal 'confirmed'")
    if confirmation["permitted_next_action"] != "draft_req_only":
        result.block("excessive_discovery_authorization", relative, "permitted_next_action must equal 'draft_req_only'")
    source_risk_class = metadata.get("risk_class")
    if not isinstance(confirmation["authority"], str) or not confirmation["authority"].strip():
        result.block("invalid_discovery_confirmation_authority", relative, "authority must be a non-empty string")
    elif not isinstance(source_risk_class, str) or confirmation["authority"] not in allowed_authorities_by_risk.get(source_risk_class, set()):
        result.block("invalid_discovery_confirmation_authority", relative, "authority is not allowlisted for the Discovery risk class")
    if not _valid_timestamp(confirmation["confirmed_at"]):
        result.block("malformed_discovery_confirmation", relative, "confirmed_at must be an ISO-8601 timestamp")
    exception = confirmation.get("supersession_exception")
    if exception is not None:
        if (
            not isinstance(exception, dict)
            or set(exception) != {"reason", "authority", "recorded_at"}
            or not isinstance(exception.get("reason"), str)
            or not exception["reason"].strip()
            or PLACEHOLDER_RE.search(exception["reason"])
            or exception.get("authority") != confirmation["authority"]
            or not _valid_timestamp(exception.get("recorded_at"))
        ):
            result.block(
                "malformed_supersession_exception",
                relative,
                "supersession_exception must bind a substantive reason, matching authority, and ISO-8601 recorded_at",
            )
    risk_class = confirmation["risk_class"]
    if (
        not isinstance(risk_class, str)
        or not risk_class.strip()
        or PLACEHOLDER_RE.search(risk_class)
        or risk_class != metadata.get("risk_class")
    ):
        result.block("discovery_binding_mismatch", relative, "risk_class differs from the bound Discovery")
    reviewed_digest = confirmation["reviewed_sha256"]
    if not isinstance(reviewed_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", reviewed_digest):
        result.block("malformed_discovery_confirmation", relative, "reviewed_sha256 must be a lowercase 64-character hex digest")
    else:
        try:
            expected_reviewed_digest = _transitioned_discovery_digest(discovery_path, "confirmed", "in_review")
        except (OSError, ValueError) as exc:
            result.block("invalid_discovery_status_transition", bound_path, str(exc))
        else:
            if reviewed_digest != expected_reviewed_digest:
                result.block(
                    "discovery_reviewed_digest_mismatch",
                    relative,
                    "reviewed_sha256 differs from the reconstructed in_review Discovery content",
                )
    digest = confirmation["sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        result.block("malformed_discovery_confirmation", relative, "sha256 must be a lowercase 64-character hex digest")
    elif digest != _digest(discovery_path):
        result.block("discovery_digest_mismatch", relative, "confirmation digest differs from confirmed Discovery content")
    if not _discovery_has_confirmation_evidence(discovery_path):
        result.block("insufficient_discovery_evidence", bound_path, "confirmed Discovery is missing substantive required evidence")
    if len(result.blockers) == initial_blocker_count:
        result.confirmed_discoveries += 1


def _validate_root(root: Path, relative_root: str, result: Result, label: str) -> Path | None:
    path = root / relative_root
    symlink = _first_symlink_component(root, path)
    if symlink:
        result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), f"canonical {label} root path must not contain a symlink")
        return None
    if not path.is_dir():
        result.block("missing_artifact", relative_root, f"canonical {label} root is missing")
        return None
    return path


def _required_micro_spec_sections(text: str, risk: str) -> list[str]:
    headings = (
        "Objective",
        "Scope",
        "Non-goals",
        "Baseline",
        "Verification plan",
        "QC exit rule",
    )
    if risk == "high":
        headings += ("Rollback and containment",)
    missing: list[str] = []
    for heading in headings:
        match = re.search(rf"(?ms)^## {re.escape(heading)}\s*\n(.*?)(?=^## |\Z)", text)
        if not match or not match.group(1).strip() or PLACEHOLDER_RE.search(match.group(1)):
            missing.append(heading)
    return missing


def _requirement_acceptance_criteria(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return set(re.findall(r"(?m)^(?:\s*#{1,6}\s+|\s*-\s+(?:\*\*)?)(AC-[0-9]+)(?:\*\*)?(?:\s+—|:)", text))


def _validate_micro_spec(root: Path, path: Path, result: Result, seen_targets: set[str]) -> None:
    relative = path.relative_to(root).as_posix()
    symlink = _first_symlink_component(root, path)
    if symlink:
        result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "Micro-SPEC path must not contain a symlink")
        return
    parts = path.relative_to(root / REQUIRED_ROOTS["micro_specs_root"]).parts
    directory_match = re.fullmatch(r"req-([0-9]+)", parts[0]) if len(parts) == 2 else None
    name_match = MICRO_SPEC_RE.fullmatch(parts[1]) if len(parts) == 2 else None
    if not directory_match or not name_match:
        result.block("invalid_micro_spec_path", relative, "expected req-<id>/ms-<id>-<slice>.md")
        return
    directory_id = directory_match.group(1)
    filename_id, slice_text = name_match.groups()
    if directory_id != filename_id:
        result.block("micro_spec_binding_mismatch", relative, "Micro-SPEC directory and filename numeric IDs must match")
        return
    try:
        text = path.read_text(encoding="utf-8")
        metadata = _frontmatter(path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        result.block("malformed_micro_spec", relative, str(exc))
        return
    # Historical manual-bootstrap planning remains non-canonical and is not
    # retrospectively relabelled or required to satisfy this schema envelope.
    if metadata.get("kind") == "manual-bootstrap-micro-spec":
        return
    result.checked_micro_specs += 1
    expected_target = f"ms-{directory_id}-{slice_text}"
    if metadata.get("schema_version") != 1 or isinstance(metadata.get("schema_version"), bool):
        result.block("malformed_micro_spec", relative, "frontmatter schema_version must equal integer 1")
    target = metadata.get("id")
    if metadata.get("kind") != "micro-spec" or not isinstance(target, str):
        result.block("micro_spec_binding_mismatch", relative, "frontmatter id/kind differs from canonical Micro-SPEC target")
    else:
        if target in seen_targets:
            result.block("duplicate_micro_spec_target", relative, "duplicate canonical Micro-SPEC target")
        seen_targets.add(target)
        if target != expected_target:
            result.block("micro_spec_binding_mismatch", relative, "frontmatter id differs from canonical Micro-SPEC target")

    requirement = metadata.get("requirement")
    required_requirement_fields = {"path", "id", "revision", "sha256"}
    if not isinstance(requirement, dict) or set(requirement) != required_requirement_fields:
        result.block("malformed_micro_spec", relative, "requirement must contain exactly path, id, revision, and sha256")
        return
    requirement_id = f"req-{directory_id}"
    revision = requirement["revision"]
    requirement_path_value = requirement["path"]
    if (
        not isinstance(requirement_path_value, str)
        or not _safe_relative(requirement_path_value)
        or requirement["id"] != requirement_id
        or not isinstance(revision, int)
        or isinstance(revision, bool)
        or revision < 1
    ):
        result.block("micro_spec_binding_mismatch", relative, "requirement path/id/revision must be canonical and match the Micro-SPEC")
        return
    expected_requirement_path = f"{REQUIRED_ROOTS['requirements_root']}/{requirement_id}/{requirement_id}-r{revision}.md"
    if requirement_path_value != expected_requirement_path:
        result.block("micro_spec_binding_mismatch", relative, "requirement.path differs from canonical REQ path")
        return
    requirement_path = root / requirement_path_value
    requirement_symlink = _first_symlink_component(root, requirement_path)
    if requirement_symlink:
        result.block("unsafe_artifact_path", requirement_symlink.relative_to(root).as_posix(), "bound REQ path must not contain a symlink")
        return
    try:
        requirement_metadata = _frontmatter(requirement_path)
        requirement_criteria = _requirement_acceptance_criteria(requirement_path)
    except FileNotFoundError:
        result.block("missing_bound_requirement", requirement_path_value, "canonical bound REQ does not exist")
        return
    except (OSError, ValueError, yaml.YAMLError) as exc:
        result.block("malformed_micro_spec", relative, f"bound REQ is unreadable: {exc}")
        return
    if (
        requirement_metadata.get("id") != requirement_id
        or requirement_metadata.get("revision") != revision
        or requirement_metadata.get("status") != "approved"
    ):
        result.block("unapproved_micro_spec_parent", relative, "bound REQ must be an exact approved id/revision")
    bound_digest = requirement["sha256"]
    if not isinstance(bound_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", bound_digest):
        result.block("malformed_micro_spec", relative, "requirement.sha256 must be a lowercase 64-character hex digest")
    elif bound_digest != _digest(requirement_path):
        result.block("micro_spec_digest_mismatch", relative, "requirement.sha256 differs from bound REQ content")

    selected = metadata.get("selected_acceptance_criteria")
    if (
        not isinstance(selected, list)
        or not selected
        or not all(isinstance(ac, str) and re.fullmatch(r"AC-[0-9]+", ac) for ac in selected)
        or len(set(selected)) != len(selected)
        or not set(selected).issubset(requirement_criteria)
    ):
        result.block("invalid_selected_acceptance_criteria", relative, "selected ACs must be a unique, non-empty subset of the bound REQ AC IDs")
    missing_sections = _required_micro_spec_sections(text, requirement_metadata.get("risk", ""))
    if missing_sections:
        result.block("incomplete_micro_spec_plan", relative, f"missing substantive sections: {', '.join(missing_sections)}")


def _validate_micro_spec_review(root: Path, path: Path, result: Result, allowed_by_risk: dict[str, set[str]]) -> None:
    """Validate one append-only, exact-byte Micro-SPEC review record."""
    relative = path.relative_to(root).as_posix()
    symlink = _first_symlink_component(root, path)
    if symlink:
        result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "Micro-SPEC review path must not contain a symlink")
        return
    parts = path.relative_to(root / REQUIRED_ROOTS["micro_spec_reviews_root"]).parts
    if len(parts) != 2 or not re.fullmatch(r"req-[0-9]+", parts[0]):
        result.block("invalid_micro_spec_review_path", relative, "expected req-<id>/ms-<id>-<slice>.review.json")
        return
    match = MICRO_SPEC_REVIEW_RE.fullmatch(parts[1])
    if not match or match.group(1) != parts[0][4:]:
        result.block("invalid_micro_spec_review_path", relative, "review directory and filename must bind the same Micro-SPEC target")
        return
    number, slice_text = match.groups()
    target = f"ms-{number}-{slice_text}"
    expected_micro_path = f"{REQUIRED_ROOTS['micro_specs_root']}/req-{number}/{target}.md"
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result.block("malformed_micro_spec_review", relative, str(exc))
        return
    if not isinstance(record, dict) or set(record) != REQUIRED_MICRO_SPEC_REVIEW_FIELDS:
        result.block("malformed_micro_spec_review", relative, "review record must contain exactly the required fields")
        return
    if record.get("schema_version") != 1 or isinstance(record.get("schema_version"), bool):
        result.block("malformed_micro_spec_review", relative, "schema_version must equal integer 1")
    micro_path = root / expected_micro_path
    if record.get("micro_spec_path") != expected_micro_path or record.get("micro_spec_id") != target:
        result.block("micro_spec_review_binding_mismatch", relative, "record Micro-SPEC path/id must match its canonical filename binding")
        return
    try:
        micro_metadata = _frontmatter(micro_path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        result.block("micro_spec_review_binding_mismatch", relative, f"bound Micro-SPEC is unreadable: {exc}")
        return
    requirement = micro_metadata.get("requirement")
    if not isinstance(requirement, dict):
        result.block("micro_spec_review_binding_mismatch", relative, "bound Micro-SPEC has no valid parent REQ binding")
        return
    if (
        record.get("micro_spec_sha256") != _digest(micro_path)
        or record.get("requirement_path") != requirement.get("path")
        or record.get("requirement_id") != requirement.get("id")
        or record.get("revision") != requirement.get("revision")
        or record.get("requirement_sha256") != requirement.get("sha256")
    ):
        result.block("micro_spec_review_binding_mismatch", relative, "record must bind exact Micro-SPEC and parent REQ snapshots")
    risk = record.get("risk")
    parent_path = root / requirement["path"] if isinstance(requirement.get("path"), str) and _safe_relative(requirement["path"]) else None
    try:
        parent_meta = _frontmatter(parent_path) if parent_path else {}
    except (OSError, ValueError, yaml.YAMLError):
        parent_meta = {}
    if risk != parent_meta.get("risk"):
        result.block("micro_spec_review_binding_mismatch", relative, "review risk must match the bound parent REQ")
    if not isinstance(risk, str) or not isinstance(record.get("authority"), str) or record["authority"] not in allowed_by_risk.get(risk, set()):
        result.block("invalid_micro_spec_review_authority", relative, "authority is not allowlisted for the bound parent REQ risk")
    if not _valid_timestamp(record.get("decided_at")):
        result.block("malformed_micro_spec_review", relative, "decided_at must be an ISO-8601 timestamp")
    if not isinstance(record.get("reason"), str) or not record["reason"].strip() or PLACEHOLDER_RE.search(record["reason"]):
        result.block("malformed_micro_spec_review", relative, "reason must be substantive and non-placeholder")
    decision = record.get("decision")
    expected_next_action = "implement_bound_micro_spec_only" if decision == "approved_for_implementation" else "none"
    if decision not in {"approved_for_implementation", "rework", "blocked"} or record.get("permitted_next_action") != expected_next_action:
        result.block("invalid_micro_spec_review_decision", relative, "decision must have its exact narrow permitted_next_action")


def _validate_qc_record(root: Path, path: Path, result: Result, family: str) -> None:
    relative = path.relative_to(root).as_posix()
    root_key = f"{family}_root"
    record_re = ITERATION_QC_RE if family == "iteration_qc" else DELIVERY_QC_RE
    path_code = f"invalid_{family}_path"
    malformed_code = f"malformed_{family}"
    symlink = _first_symlink_component(root, path)
    if symlink:
        result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), f"{family.replace('_', '-')} path must not contain a symlink")
        return
    parts = path.relative_to(root / REQUIRED_ROOTS[root_key]).parts
    expected_depth = 2 if family == "iteration_qc" else 1
    if len(parts) != expected_depth:
        result.block(path_code, relative, "record is outside its canonical family topology")
        return
    name_match = record_re.fullmatch(parts[-1])
    if not name_match:
        expected = "req-<id>/iqc-<id>-<slice>-r<revision>.json" if family == "iteration_qc" else "dqc-<id>-r<revision>.json"
        result.block(path_code, relative, f"expected {expected}")
        return
    if family == "iteration_qc":
        directory_match = re.fullmatch(r"req-([0-9]+)", parts[0])
        if not directory_match:
            result.block(path_code, relative, "iteration-QC must be directly below req-<id>/")
            return
        if directory_match.group(1) != name_match.group(1):
            result.block("iteration_qc_binding_mismatch", relative, "iteration-QC directory and filename numeric IDs must match")
            return
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result.block(malformed_code, relative, str(exc))
        return
    if not isinstance(record, dict):
        result.block(malformed_code, relative, "QC record must be a JSON object")
        return
    if record.get("schema_version") != 1 or isinstance(record.get("schema_version"), bool):
        result.block(malformed_code, relative, "schema_version must equal integer 1")
        return
    if family == "iteration_qc":
        result.checked_iteration_qc += 1
        _validate_iteration_qc_evidence(root, path, record, name_match, result)
    else:
        result.checked_delivery_qc += 1
        _validate_delivery_qc_aggregation(root, path, record, name_match, result)


def _validate_iteration_qc_evidence(
    root: Path,
    path: Path,
    record: dict[str, Any],
    name_match: re.Match[str],
    result: Result,
) -> None:
    """Validate AC-003's exact Micro-SPEC and focused-evidence contract."""
    relative = path.relative_to(root).as_posix()
    requirement_number, slice_text, _record_revision = name_match.groups()
    expected_id = f"ms-{requirement_number}-{slice_text}"
    expected_path = f"{REQUIRED_ROOTS['micro_specs_root']}/req-{requirement_number}/{expected_id}.md"
    micro_spec = record.get("micro_spec")
    if not isinstance(micro_spec, dict) or set(micro_spec) != {"path", "id", "sha256"}:
        result.block("malformed_iteration_qc", relative, "micro_spec must contain exactly path, id, and sha256")
        return
    if micro_spec.get("path") != expected_path or micro_spec.get("id") != expected_id:
        result.block("iteration_qc_micro_spec_mismatch", relative, "micro_spec path/id must match the iteration-QC filename binding")
        return
    digest = micro_spec.get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        result.block("malformed_iteration_qc", relative, "micro_spec.sha256 must be a lowercase 64-character hex digest")
        return
    micro_path = root / expected_path
    symlink = _first_symlink_component(root, micro_path)
    if symlink:
        result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "bound Micro-SPEC path must not contain a symlink")
        return
    try:
        micro_metadata = _frontmatter(micro_path)
    except FileNotFoundError:
        result.block("missing_bound_micro_spec", expected_path, "iteration-QC references a missing canonical Micro-SPEC")
        return
    except (OSError, ValueError, yaml.YAMLError) as exc:
        result.block("malformed_iteration_qc", relative, f"bound Micro-SPEC is unreadable: {exc}")
        return
    if digest != _digest(micro_path):
        result.block("iteration_qc_micro_spec_digest_mismatch", relative, "micro_spec.sha256 differs from bound Micro-SPEC content")
    if (
        micro_metadata.get("schema_version") != 1
        or micro_metadata.get("kind") != "micro-spec"
        or micro_metadata.get("id") != expected_id
    ):
        result.block("iteration_qc_micro_spec_mismatch", relative, "bound Micro-SPEC does not have the expected canonical identity")
        return

    selected = record.get("selected_acceptance_criteria")
    micro_selected = micro_metadata.get("selected_acceptance_criteria")
    micro_selected_valid = (
        isinstance(micro_selected, list)
        and bool(micro_selected)
        and all(isinstance(ac, str) and re.fullmatch(r"AC-[0-9]+", ac) for ac in micro_selected)
        and len(set(micro_selected)) == len(micro_selected)
    )
    if (
        not isinstance(selected, list)
        or not selected
        or not all(isinstance(ac, str) and re.fullmatch(r"AC-[0-9]+", ac) for ac in selected)
        or len(set(selected)) != len(selected)
        or not micro_selected_valid
        or selected != micro_selected
    ):
        result.block("iteration_qc_ac_set_mismatch", relative, "selected ACs must exactly preserve the bound Micro-SPEC selected AC list")

    verification = record.get("verification")
    evidence_valid = isinstance(verification, list) and bool(verification)
    if evidence_valid:
        for entry in verification:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"command", "result", "exit_code"}
                or not isinstance(entry.get("command"), str)
                or not entry["command"].strip()
                or PLACEHOLDER_RE.search(entry["command"])
                or entry.get("result") not in {"passed", "failed"}
                or not isinstance(entry.get("exit_code"), int)
                or isinstance(entry["exit_code"], bool)
                or (entry["result"] == "passed" and entry["exit_code"] != 0)
                or (entry["result"] == "failed" and entry["exit_code"] == 0)
            ):
                evidence_valid = False
                break
    if not evidence_valid:
        result.block("malformed_iteration_qc_evidence", relative, "verification must contain reproducible command/result/exit_code entries")

    verdict = record.get("verdict")
    if verdict not in {"verified", "rework", "blocked"}:
        result.block("invalid_iteration_qc_verdict", relative, "verdict must be verified, rework, or blocked")
    elif verdict == "verified" and (not evidence_valid or any(entry["result"] != "passed" for entry in verification)):
        result.block("invalid_iteration_qc_verdict", relative, "verified requires complete passing focused evidence")

    requirement = micro_metadata.get("requirement")
    requirement_path_value = requirement.get("path") if isinstance(requirement, dict) else None
    requirement_path = root / requirement_path_value if isinstance(requirement_path_value, str) and _safe_relative(requirement_path_value) else None
    if requirement_path is None:
        result.block("iteration_qc_micro_spec_mismatch", relative, "bound Micro-SPEC has no safe requirement path")
        return
    try:
        parent_criteria = _requirement_acceptance_criteria(requirement_path)
        parent_metadata = _frontmatter(requirement_path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        result.block("iteration_qc_micro_spec_mismatch", relative, f"bound Micro-SPEC parent REQ is unreadable: {exc}")
        return
    if parent_metadata.get("risk") == "high":
        review_path = root / REQUIRED_ROOTS["micro_spec_reviews_root"] / f"req-{requirement_path.parent.name.removeprefix('req-')}" / f"{expected_id}.review.json"
        try:
            review = json.loads(review_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            review = None
        if not isinstance(review, dict) or review.get("decision") != "approved_for_implementation" or review.get("micro_spec_sha256") != _digest(micro_path):
            result.block("missing_approved_micro_spec_review", relative, "high-risk iteration-QC requires an exact approved_for_implementation Micro-SPEC review")
    remaining = record.get("remaining_acceptance_criteria")
    micro_selected_list = micro_selected if isinstance(micro_selected, list) else []
    expected_remaining = parent_criteria - set(micro_selected_list)
    if (
        not isinstance(remaining, list)
        or not all(isinstance(ac, str) and re.fullmatch(r"AC-[0-9]+", ac) for ac in remaining)
        or len(set(remaining)) != len(remaining)
        or set(remaining) != expected_remaining
    ):
        result.block("iteration_qc_remaining_ac_mismatch", relative, "remaining ACs must exactly enumerate the bound parent REQ ACs not selected by the Micro-SPEC")


def _validate_delivery_qc_aggregation(
    root: Path,
    path: Path,
    record: dict[str, Any],
    name_match: re.Match[str],
    result: Result,
) -> None:
    """Validate AC-004's REQ-level, non-authorizing delivery-QC aggregation."""
    relative = path.relative_to(root).as_posix()
    requirement_number, revision_text = name_match.groups()
    requirement_id = f"req-{requirement_number}"
    revision = int(revision_text)
    requirement_relative = canonical_requirement_relative(requirement_id, revision)
    expected_keys = {
        "schema_version",
        "requirement",
        "coverage",
        "regression_evidence",
        "authority",
        "residual_risk",
        "verdict",
    }
    if set(record) != expected_keys:
        result.block("malformed_delivery_qc", relative, "delivery-QC must contain exactly the v1 aggregation fields")
        return

    requirement = record.get("requirement")
    if not isinstance(requirement, dict) or set(requirement) != {"path", "id", "revision", "sha256"}:
        result.block("malformed_delivery_qc", relative, "requirement must contain exactly path, id, revision, and sha256")
        return
    if (
        requirement.get("path") != requirement_relative
        or requirement.get("id") != requirement_id
        or requirement.get("revision") != revision
    ):
        result.block("delivery_qc_requirement_mismatch", relative, "requirement path/id/revision must match the delivery-QC filename")
        return
    requirement_digest = requirement.get("sha256")
    if not isinstance(requirement_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", requirement_digest):
        result.block("malformed_delivery_qc", relative, "requirement.sha256 must be a lowercase 64-character hex digest")
        return
    requirement_path = root / requirement_relative
    symlink = _first_symlink_component(root, requirement_path)
    if symlink:
        result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "bound REQ path must not contain a symlink")
        return
    try:
        requirement_metadata = _frontmatter(requirement_path)
        parent_criteria = _requirement_acceptance_criteria(requirement_path)
    except FileNotFoundError:
        result.block("missing_bound_requirement", requirement_relative, "delivery-QC references a missing canonical REQ")
        return
    except (OSError, ValueError, yaml.YAMLError) as exc:
        result.block("malformed_delivery_qc", relative, f"bound REQ is unreadable: {exc}")
        return
    if requirement_digest != _digest(requirement_path):
        result.block("delivery_qc_requirement_digest_mismatch", relative, "requirement.sha256 differs from bound REQ content")
    if (
        requirement_metadata.get("id") != requirement_id
        or requirement_metadata.get("revision") != revision
        or requirement_metadata.get("status") != "approved"
    ):
        result.block("delivery_qc_requirement_mismatch", relative, "bound REQ must match identity and have status: approved")
        return

    authority = record.get("authority")
    risk = requirement_metadata.get("risk")
    allowed = _load_config(root).get("policy", {}).get("delivery_qc_authorities_by_risk", {}).get(risk, [])
    if not isinstance(authority, str) or not authority.strip() or authority not in allowed:
        result.block("invalid_delivery_qc_authority", relative, "authority is not allowlisted for the bound REQ risk")

    residual_risk = record.get("residual_risk")
    unresolved_exceptions = residual_risk.get("unresolved_exceptions") if isinstance(residual_risk, dict) else None
    residual_valid = (
        isinstance(residual_risk, dict)
        and set(residual_risk) == {"unresolved_exceptions", "disposition"}
        and isinstance(unresolved_exceptions, list)
        and all(isinstance(item, str) and item.strip() and not PLACEHOLDER_RE.search(item) for item in unresolved_exceptions)
        and isinstance(residual_risk.get("disposition"), str)
        and residual_risk["disposition"].strip()
        and not PLACEHOLDER_RE.search(residual_risk["disposition"])
    )
    if not residual_valid:
        result.block("malformed_delivery_qc_residual_risk", relative, "residual_risk must state unresolved exceptions and a substantive disposition")

    regression_evidence = record.get("regression_evidence")
    regression_entries = regression_evidence if isinstance(regression_evidence, list) else []
    regression_valid = bool(regression_entries)
    if regression_valid:
        for entry in regression_entries:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"command", "result", "exit_code"}
                or not isinstance(entry.get("command"), str)
                or not entry["command"].strip()
                or PLACEHOLDER_RE.search(entry["command"])
                or entry.get("result") not in {"passed", "failed"}
                or not isinstance(entry.get("exit_code"), int)
                or isinstance(entry["exit_code"], bool)
                or (entry["result"] == "passed" and entry["exit_code"] != 0)
                or (entry["result"] == "failed" and entry["exit_code"] == 0)
            ):
                regression_valid = False
                break
    if not regression_valid:
        result.block("malformed_delivery_qc_regression_evidence", relative, "regression_evidence must contain reproducible command/result/exit_code entries")

    coverage = record.get("coverage")
    coverage_valid = isinstance(coverage, list) and bool(coverage)
    covered: set[str] = set()
    if coverage_valid:
        for entry in coverage:
            if not isinstance(entry, dict) or set(entry) != {"acceptance_criterion", "iteration_qc"}:
                coverage_valid = False
                break
            criterion = entry.get("acceptance_criterion")
            iteration = entry.get("iteration_qc")
            if not isinstance(criterion, str) or not re.fullmatch(r"AC-[0-9]+", criterion):
                coverage_valid = False
                break
            covered.add(criterion)
            if not isinstance(iteration, dict) or set(iteration) != {"path", "sha256"}:
                coverage_valid = False
                break
            iteration_path_value = iteration.get("path")
            iteration_digest = iteration.get("sha256")
            if not isinstance(iteration_path_value, str) or not isinstance(iteration_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", iteration_digest):
                coverage_valid = False
                break
            iteration_path = root / iteration_path_value
            iteration_symlink = _first_symlink_component(root, iteration_path)
            if iteration_symlink:
                result.block("unsafe_artifact_path", iteration_symlink.relative_to(root).as_posix(), "bound iteration-QC path must not contain a symlink")
                coverage_valid = False
                break
            match = ITERATION_QC_RE.fullmatch(iteration_path.name)
            expected_prefix = f"{REQUIRED_ROOTS['iteration_qc_root']}/{requirement_id}/"
            if not match or not iteration_path_value.startswith(expected_prefix):
                coverage_valid = False
                break
            try:
                iteration_record = json.loads(iteration_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                coverage_valid = False
                break
            if iteration_digest != _digest(iteration_path) or not isinstance(iteration_record, dict) or iteration_record.get("schema_version") != 1:
                coverage_valid = False
                break
            micro = iteration_record.get("micro_spec")
            if not isinstance(micro, dict) or set(micro) != {"path", "id", "sha256"}:
                coverage_valid = False
                break
            micro_path_value = micro.get("path")
            if not isinstance(micro_path_value, str) or not _safe_relative(micro_path_value):
                coverage_valid = False
                break
            micro_path = root / micro_path_value
            try:
                micro_metadata = _frontmatter(micro_path)
            except (OSError, ValueError, yaml.YAMLError):
                coverage_valid = False
                break
            if (
                micro.get("sha256") != _digest(micro_path)
                or micro_metadata.get("kind") != "micro-spec"
                or micro_metadata.get("requirement") != requirement
                or criterion not in iteration_record.get("selected_acceptance_criteria", [])
                or iteration_record.get("verdict") != "verified"
                or not isinstance(iteration_record.get("verification"), list)
                or not iteration_record["verification"]
                or any(
                    not isinstance(item, dict) or item.get("result") != "passed" or item.get("exit_code") != 0
                    for item in iteration_record["verification"]
                )
            ):
                coverage_valid = False
                break
    if not coverage_valid or covered != parent_criteria:
        result.block("delivery_qc_ac_coverage_mismatch", relative, "coverage must map every and only parent REQ AC to verified, exact iteration-QC evidence")

    verdict = record.get("verdict")
    if verdict not in {"verified", "rework", "blocked"}:
        result.block("invalid_delivery_qc_verdict", relative, "verdict must be verified, rework, or blocked")
    elif verdict == "verified" and (
        not coverage_valid
        or covered != parent_criteria
        or not regression_valid
        or not residual_valid
        or bool(unresolved_exceptions)
        or any(entry["result"] != "passed" for entry in regression_entries if isinstance(entry, dict))
    ):
        result.block("invalid_delivery_qc_verdict", relative, "verified requires complete coverage, passing regression evidence, and no unresolved exceptions")


def _validate_family_root(root: Path, family_root: Path, result: Result, family: str) -> None:
    seen_micro_spec_targets: set[str] = set()
    for path in sorted(family_root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        symlink = _first_symlink_component(root, path)
        if symlink:
            result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), f"canonical {family.replace('_', '-')} path must not contain a symlink")
            continue
        if path.is_dir():
            if family in {"micro_specs", "iteration_qc"} and len(path.relative_to(family_root).parts) == 1 and re.fullmatch(r"req-[0-9]+", path.name):
                continue
            result.block(f"invalid_{family}_path", relative, "unexpected directory in canonical artifact family")
            continue
        if path.name == ".gitkeep" and path.parent == family_root:
            continue
        if family == "micro_specs":
            _validate_micro_spec(root, path, result, seen_micro_spec_targets)
        else:
            _validate_qc_record(root, path, result, family)


def create_discovery_confirmation(
    root: Path,
    target: str,
    authority: str,
    supersession_exception: str | None = None,
) -> Path:
    """Create one non-overwritable, exact-byte Discovery confirmation record."""
    match = DISCOVERY_RE.fullmatch(f"{target}.md")
    if not match:
        raise ConfirmationError(
            "invalid_discovery_target",
            target,
            "target must be dcy-<id>-r<revision>",
        )
    discovery_id, revision_text = match.groups()
    revision = int(revision_text)
    discovery_relative = f".specbound/discoveries/{target}.md"
    confirmation_relative = f".specbound/confirmations/{target}.confirmation.json"

    before = validate(root)
    if not before.valid:
        raise ConfirmationError("repository_validation_failed", ".", "repository must pass specbound validate before confirmation")

    discovery_path = root / discovery_relative
    confirmation_path = root / confirmation_relative
    for path, label in ((discovery_path, "Discovery"), (confirmation_path.parent, "confirmation directory")):
        symlink = _first_symlink_component(root, path)
        if symlink:
            raise ConfirmationError(
                "unsafe_artifact_path",
                symlink.relative_to(root).as_posix(),
                f"canonical {label} path must not contain a symlink",
            )
    if not discovery_path.is_file():
        raise ConfirmationError("missing_discovery", discovery_relative, "canonical Discovery does not exist")
    if confirmation_path.exists():
        raise ConfirmationError(
            "confirmation_already_exists",
            confirmation_relative,
            "confirmation records are non-overwritable; mint a new Discovery revision instead",
        )

    try:
        metadata = _frontmatter(discovery_path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise ConfirmationError("malformed_discovery", discovery_relative, str(exc)) from exc
    if metadata.get("id") != discovery_id or metadata.get("revision") != revision:
        raise ConfirmationError("discovery_binding_mismatch", discovery_relative, "frontmatter id/revision differs from path")
    if metadata.get("status") != "in_review":
        raise ConfirmationError(
            "discovery_not_in_review",
            discovery_relative,
            "only an in_review Discovery may be confirmed",
        )
    try:
        reviewed_text = discovery_path.read_text(encoding="utf-8")
        confirmed_text = _transitioned_discovery_text(reviewed_text, "in_review", "confirmed")
    except (OSError, ValueError) as exc:
        raise ConfirmationError("invalid_discovery_status_transition", discovery_relative, str(exc)) from exc
    risk_class = metadata.get("risk_class")
    if not isinstance(risk_class, str) or not risk_class.strip():
        raise ConfirmationError("malformed_discovery", discovery_relative, "risk_class must be a non-empty string")

    config = _load_config(root)
    allowed = config["policy"]["discovery_confirmation_authorities_by_risk"].get(risk_class, [])
    if authority not in allowed:
        raise ConfirmationError(
            "invalid_discovery_confirmation_authority",
            confirmation_relative,
            "authority is not allowlisted for the Discovery risk class",
        )

    revisions = [
        int(candidate_match.group(2))
        for candidate in (root / REQUIRED_ROOTS["discoveries_root"]).glob(f"{discovery_id}-r*.md")
        if (candidate_match := DISCOVERY_RE.fullmatch(candidate.name)) and candidate_match.group(1) == discovery_id
    ]
    latest_revision = max(revisions, default=revision)
    if latest_revision > revision and not supersession_exception:
        raise ConfirmationError(
            "superseded_discovery_revision",
            discovery_relative,
            f"r{revision} cannot be confirmed while newer r{latest_revision} exists; provide a substantive supersession exception",
        )
    if supersession_exception and (not supersession_exception.strip() or PLACEHOLDER_RE.search(supersession_exception)):
        raise ConfirmationError(
            "malformed_supersession_exception",
            confirmation_relative,
            "supersession exception must contain a substantive non-placeholder reason",
        )

    timestamp = datetime.now().astimezone().isoformat()
    record: dict[str, Any] = {
        "schema_version": 1,
        "discovery_path": discovery_relative,
        "discovery_id": discovery_id,
        "revision": revision,
        "reviewed_sha256": sha256(reviewed_text.encode("utf-8")).hexdigest(),
        "sha256": sha256(confirmed_text.encode("utf-8")).hexdigest(),
        "risk_class": risk_class,
        "authority": authority,
        "confirmed_at": timestamp,
        "decision": "confirmed",
        "permitted_next_action": "draft_req_only",
    }
    if supersession_exception:
        record["supersession_exception"] = {
            "reason": supersession_exception.strip(),
            "authority": authority,
            "recorded_at": timestamp,
        }

    record_text = json.dumps(record, indent=2, sort_keys=True) + "\n"
    try:
        _atomic_replace_text(discovery_path, confirmed_text)
    except OSError as exc:
        raise ConfirmationError("discovery_transition_failed", discovery_relative, str(exc)) from exc
    try:
        with confirmation_path.open("x", encoding="utf-8") as handle:
            handle.write(record_text)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        _atomic_replace_text(discovery_path, reviewed_text)
        raise ConfirmationError(
            "confirmation_already_exists",
            confirmation_relative,
            "confirmation records are non-overwritable; mint a new Discovery revision instead",
        ) from exc
    except OSError as exc:
        _atomic_replace_text(discovery_path, reviewed_text)
        raise ConfirmationError("confirmation_write_failed", confirmation_relative, str(exc)) from exc

    after = validate(root)
    if after.valid:
        return confirmation_path
    if confirmation_path.read_text(encoding="utf-8") == record_text:
        confirmation_path.unlink()
    _atomic_replace_text(discovery_path, reviewed_text)
    raise ConfirmationError("generated_confirmation_invalid", confirmation_relative, "generated record did not pass specbound validate")


READINESS_AC_FIELDS = (
    "observable_success",
    "required_preconditions",
    "mutation_boundary",
    "negative_behavior",
    "direct_evidence",
    "dependencies",
    "completion_group",
    "candidate_micro_spec",
    "non_goals",
)
READINESS_AC_HEADING_RE = re.compile(r"(?m)^### (AC-0*[1-9][0-9]*) — (.+)$")
READINESS_AC_FIELD_RE = re.compile(r"(?m)^- `([a-z_]+)`: *(.*)$")
CANDIDATE_MICRO_SPEC_RE = re.compile(r"^ms-[0-9]+-[0-9]+$")
COMPLETION_GROUP_RE = re.compile(r"^CG-[1-9][0-9]*: .+")


def _requirement_section_content(text: str, heading: str) -> str | None:
    marker = f"\n{heading}\n"
    start = text.find(marker)
    if start < 0:
        return None
    content_start = start + len(marker)
    next_heading = text.find("\n## ", content_start)
    return text[content_start:] if next_heading < 0 else text[content_start:next_heading]


def _readiness_parent_binding(root: Path, requirement_path: Path, metadata: dict[str, Any], result: Result) -> None:
    """Require an exact confirmed parent, rather than trusting draft frontmatter alone."""
    relative = requirement_path.relative_to(root).as_posix()
    parent = metadata.get("parent_discovery")
    required_parent_fields = {"id", "revision", "path", "sha256", "confirmation_path"}
    if not isinstance(parent, dict) or set(parent) != required_parent_fields:
        result.block("malformed_parent_binding", relative, "parent_discovery must contain exactly id, revision, path, sha256, and confirmation_path")
        return
    parent_id, revision = parent.get("id"), parent.get("revision")
    if (
        not isinstance(parent_id, str)
        or not re.fullmatch(r"dcy-[0-9]+", parent_id)
        or not isinstance(revision, int)
        or isinstance(revision, bool)
        or revision < 1
    ):
        result.block("malformed_parent_binding", relative, "parent_discovery id/revision must be canonical")
        return
    discovery_relative = f".specbound/discoveries/{parent_id}-r{revision}.md"
    confirmation_relative = f".specbound/confirmations/{parent_id}-r{revision}.confirmation.json"
    if parent.get("path") != discovery_relative or parent.get("confirmation_path") != confirmation_relative:
        result.block("parent_binding_mismatch", relative, "parent paths must be the canonical exact Discovery and confirmation paths")
        return
    discovery_path, confirmation_path = root / discovery_relative, root / confirmation_relative
    for path, label in ((discovery_path, "parent Discovery"), (confirmation_path, "parent confirmation")):
        symlink = _first_symlink_component(root, path)
        if symlink:
            result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), f"{label} path must not contain a symlink")
            return
    try:
        discovery = _frontmatter(discovery_path)
        confirmation = json.loads(confirmation_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        result.block("missing_parent_evidence", relative, "exact confirmed parent Discovery and confirmation are required")
        return
    except (OSError, ValueError, yaml.YAMLError, json.JSONDecodeError) as exc:
        result.block("malformed_parent_evidence", relative, str(exc))
        return
    if (
        not isinstance(confirmation, dict)
        or discovery.get("id") != parent_id
        or discovery.get("revision") != revision
        or discovery.get("status") != "confirmed"
        or confirmation.get("discovery_path") != discovery_relative
        or confirmation.get("discovery_id") != parent_id
        or confirmation.get("revision") != revision
        or confirmation.get("decision") != "confirmed"
        or confirmation.get("permitted_next_action") != "draft_req_only"
        or parent.get("sha256") != _digest(discovery_path)
        or confirmation.get("sha256") != _digest(discovery_path)
        or metadata.get("risk") != discovery.get("risk_class")
    ):
        result.block("parent_binding_mismatch", relative, "REQ must remain bound to the exact confirmed parent snapshot and risk")


def check_requirement_readiness(root: Path, target: str) -> Result:
    """Read-only, deterministic readiness check for one canonical draft REQ."""
    result = validate(root)
    match = REQUIREMENT_RE.fullmatch(f"{target}.md")
    if not match:
        result.block("invalid_requirement_target", target, "target must be req-<id>-r<revision>")
        return result
    requirement_id, revision_text = match.groups()
    relative = canonical_requirement_relative(requirement_id, revision_text)
    path = root / relative
    symlink = _first_symlink_component(root, path)
    if symlink:
        result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "canonical REQ path must not contain a symlink")
        return result
    try:
        text = path.read_text(encoding="utf-8")
        metadata = _frontmatter(path)
    except FileNotFoundError:
        result.block("missing_requirement", relative, "canonical REQ does not exist")
        return result
    except (OSError, ValueError, yaml.YAMLError) as exc:
        result.block("malformed_requirement", relative, str(exc))
        return result
    if metadata.get("id") != requirement_id or metadata.get("revision") != int(revision_text):
        result.block("requirement_binding_mismatch", relative, "frontmatter id/revision differs from canonical path")
    if metadata.get("status") != "draft":
        result.block("requirement_not_draft", relative, "only a draft REQ may be submitted for review")
    for field in ("risk", "owner"):
        value = metadata.get(field)
        if not isinstance(value, str) or not value.strip() or PLACEHOLDER_RE.search(value):
            result.block("malformed_requirement", relative, f"frontmatter {field} must be a substantive non-placeholder string")
    _readiness_parent_binding(root, path, metadata, result)
    for heading in ("## 목표 (Goal)", "## Scope (범위)", "## Non-goals (비목표)", "## Approval handoff"):
        content = _requirement_section_content(text, heading)
        if content is None or not content.strip() or PLACEHOLDER_RE.search(content):
            result.block("incomplete_review_handoff", relative, f"{heading} must contain substantive non-placeholder content")
    sections = list(READINESS_AC_HEADING_RE.finditer(text))
    if not sections:
        result.block("missing_acceptance_criteria", relative, "at least one canonical AC-<n> completion contract is required")
        return result
    acs: dict[str, dict[str, str]] = {}
    group_members: dict[str, list[str]] = {}
    for index, heading in enumerate(sections):
        ac_id, title = heading.groups()
        if ac_id in acs:
            result.block("duplicate_acceptance_criterion", relative, f"{ac_id} is repeated")
            continue
        if PLACEHOLDER_RE.search(title):
            result.block("incomplete_acceptance_criterion", relative, f"{ac_id} title remains a placeholder")
        end = sections[index + 1].start() if index + 1 < len(sections) else len(text)
        field_values = {key: value.strip() for key, value in READINESS_AC_FIELD_RE.findall(text[heading.end() : end])}
        acs[ac_id] = field_values
        for field in READINESS_AC_FIELDS:
            value = field_values.get(field)
            if not value or PLACEHOLDER_RE.search(value):
                result.block("incomplete_acceptance_criterion", relative, f"{ac_id}.{field} must be substantive and non-placeholder")
        candidate = field_values.get("candidate_micro_spec", "")
        if candidate and not PLACEHOLDER_RE.search(candidate) and not CANDIDATE_MICRO_SPEC_RE.fullmatch(candidate):
            result.block("invalid_candidate_micro_spec", relative, f"{ac_id}.candidate_micro_spec must use ms-<id>-<slice>")
        group = field_values.get("completion_group", "")
        if group and not PLACEHOLDER_RE.search(group):
            if group != ac_id and not COMPLETION_GROUP_RE.fullmatch(group):
                result.block("unbounded_completion_group", relative, f"{ac_id}.completion_group must be its AC ID or CG-<n>: <reason>")
            group_members.setdefault(group, []).append(ac_id)
    for group, members in group_members.items():
        if group.startswith("CG-") and len(members) < 2:
            result.block("unbounded_completion_group", relative, f"{group} must bind two or more ACs")
    dependencies: dict[str, set[str]] = {}
    for ac_id, fields in acs.items():
        dependency_text = fields.get("dependencies", "")
        if dependency_text.lower() == "none":
            dependencies[ac_id] = set()
            continue
        referenced = set(re.findall(r"AC-0*[1-9][0-9]*", dependency_text))
        if not referenced or re.sub(r"AC-0*[1-9][0-9]*(?:[ ,]+AC-0*[1-9][0-9]*)*", "", dependency_text).strip(" ,"):
            result.block("invalid_acceptance_criterion_dependency", relative, f"{ac_id}.dependencies must be none or a comma-separated AC ID list")
        unknown = referenced - set(acs)
        if unknown:
            result.block("unknown_acceptance_criterion_dependency", relative, f"{ac_id} references unknown {', '.join(sorted(unknown))}")
        dependencies[ac_id] = referenced
        for dependency in referenced & set(acs):
            if fields.get("candidate_micro_spec") != acs[dependency].get("candidate_micro_spec"):
                result.block("candidate_micro_spec_dependency_closure", relative, f"{ac_id} and dependency {dependency} must share one candidate_micro_spec")
    active: set[str] = set()
    complete: set[str] = set()
    def visit(ac_id: str) -> None:
        if ac_id in complete:
            return
        if ac_id in active:
            result.block("acceptance_criterion_dependency_cycle", relative, f"cycle includes {ac_id}")
            return
        active.add(ac_id)
        for dependency in dependencies.get(ac_id, set()) & set(acs):
            visit(dependency)
        active.remove(ac_id)
        complete.add(ac_id)
    for ac_id in acs:
        visit(ac_id)
    if metadata.get("risk") == "high" and re.search(r"\bDECIDE\b", text, re.IGNORECASE):
        result.block("unresolved_high_risk_decide", relative, "high-risk REQ cannot enter review while DECIDE remains unresolved")
    return result


class RequirementReviewSubmissionError(ValueError):
    def __init__(self, code: str, path: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.path = path
        self.detail = detail


def _publish_review_submission_record(directory: Path, name: str, text: str) -> tuple[int, tuple[int, int]]:
    """Publish a non-overwritable record from an unnamed, fsynced inode."""
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        record_fd = os.open(".", os.O_WRONLY | os.O_TMPFILE, 0o666, dir_fd=directory_fd)
        try:
            with os.fdopen(record_fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
                identity = (os.fstat(handle.fileno()).st_dev, os.fstat(handle.fileno()).st_ino)
                os.link(f"/proc/self/fd/{handle.fileno()}", name, dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
        except BaseException:
            raise
    except BaseException:
        os.close(directory_fd)
        raise
    return directory_fd, identity


def _unlink_review_submission_if_owned(directory_fd: int, name: str, identity: tuple[int, int]) -> None:
    """Remove only the record inode published by this submission attempt."""
    current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if (current.st_dev, current.st_ino) != identity:
        raise OSError("review-submission record ownership changed during rollback")
    os.unlink(name, dir_fd=directory_fd)
    os.fsync(directory_fd)


def submit_requirement_for_review(root: Path, target: str) -> Path:
    """Publish one exact ready draft and its non-authorizing review-submission record."""
    match = REQUIREMENT_RE.fullmatch(f"{target}.md")
    assert match is not None
    requirement_id, revision_text = match.groups()
    relative = canonical_requirement_relative(requirement_id, revision_text)
    submission_relative = f".specbound/review-submissions/{target}.review-submission.json"
    requirement_path, submission_path = root / relative, root / submission_relative
    for path, label in ((requirement_path, "REQ"), (submission_path.parent, "review-submission directory")):
        symlink = _first_symlink_component(root, path)
        if symlink:
            raise RequirementReviewSubmissionError("unsafe_artifact_path", symlink.relative_to(root).as_posix(), f"canonical {label} path must not contain a symlink")
    if submission_path.exists():
        raise RequirementReviewSubmissionError("review_submission_already_exists", submission_relative, "review-submission records are non-overwritable")
    try:
        draft_text = requirement_path.read_text(encoding="utf-8")
        metadata = _frontmatter(requirement_path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise RequirementReviewSubmissionError("invalid_requirement_status_transition", relative, str(exc)) from exc
    readiness = check_requirement_readiness(root, target)
    if not readiness.valid:
        blocker = readiness.blockers[0]
        raise RequirementReviewSubmissionError("readiness_failed", blocker["path"], blocker["detail"])
    try:
        if requirement_path.read_text(encoding="utf-8") != draft_text:
            raise RequirementReviewSubmissionError(
                "concurrent_requirement_mutation", relative, "REQ changed while readiness was being evaluated; rerun submission"
            )
        reviewed_text = _transitioned_discovery_text(draft_text, "draft", "in_review")
    except RequirementReviewSubmissionError:
        raise
    except (OSError, ValueError) as exc:
        raise RequirementReviewSubmissionError("invalid_requirement_status_transition", relative, str(exc)) from exc
    record = {
        "schema_version": 1,
        "requirement_path": relative,
        "requirement_id": requirement_id,
        "revision": int(revision_text),
        "draft_sha256": sha256(draft_text.encode("utf-8")).hexdigest(),
        "reviewed_sha256": sha256(reviewed_text.encode("utf-8")).hexdigest(),
        "risk": metadata["risk"],
        "owner": metadata["owner"],
        "submitted_at": datetime.now().astimezone().isoformat(),
        "decision": "submitted_for_review",
        "permitted_next_action": "review_decision_only",
    }
    record_text = json.dumps(record, indent=2, sort_keys=True) + "\n"
    directory_fd: int | None = None
    identity: tuple[int, int] | None = None
    transitioned = False
    committed = False
    try:
        directory_fd, identity = _publish_review_submission_record(submission_path.parent, submission_path.name, record_text)
        _atomic_replace_text(requirement_path, reviewed_text)
        transitioned = True
        if validate(root).valid:
            committed = True
            return submission_path
        error = RequirementReviewSubmissionError(
            "generated_review_submission_invalid", submission_relative, "generated handoff did not pass specbound validate"
        )
    except FileExistsError as exc:
        error = RequirementReviewSubmissionError(
            "review_submission_already_exists", submission_relative, "review-submission records are non-overwritable"
        )
    except OSError as exc:
        error = RequirementReviewSubmissionError("review_submission_write_failed", submission_relative, str(exc))
    finally:
        if not committed and identity is not None and directory_fd is not None:
            try:
                if transitioned:
                    _atomic_replace_text(requirement_path, draft_text)
                _unlink_review_submission_if_owned(directory_fd, submission_path.name, identity)
            except OSError as rollback_exc:
                if submission_path.exists():
                    try:
                        _atomic_replace_text(requirement_path, reviewed_text)
                    except OSError:
                        pass
                raise RequirementReviewSubmissionError(
                    "review_submission_rollback_failed", submission_relative, str(rollback_exc)
                ) from rollback_exc
        if directory_fd is not None:
            os.close(directory_fd)
    raise error


class RequirementRejectionError(ValueError):
    def __init__(self, code: str, path: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.path = path
        self.detail = detail


def reject_requirement(root: Path, target: str, authority: str, reason: str) -> Path:
    """Atomically reject one exact in-review REQ with immutable decision evidence."""
    match = REQUIREMENT_RE.fullmatch(f"{target}.md")
    if not match:
        raise RequirementRejectionError("invalid_requirement_target", target, "target must be req-<id>-r<revision>")
    requirement_id, revision_text = match.groups()
    revision = int(revision_text)
    requirement_relative = canonical_requirement_relative(requirement_id, revision_text)
    rejection_relative = f".specbound/rejections/{target}.rejection.json"
    before = validate(root)
    if not before.valid:
        raise RequirementRejectionError("repository_validation_failed", ".", "repository must pass specbound validate before rejection")
    requirement_path = root / requirement_relative
    rejection_path = root / rejection_relative
    for path, label in ((requirement_path, "REQ"), (rejection_path.parent, "rejection directory")):
        symlink = _first_symlink_component(root, path)
        if symlink:
            raise RequirementRejectionError("unsafe_artifact_path", symlink.relative_to(root).as_posix(), f"canonical {label} path must not contain a symlink")
    if not requirement_path.is_file():
        raise RequirementRejectionError("missing_requirement", requirement_relative, "canonical REQ does not exist")
    if rejection_path.exists():
        raise RequirementRejectionError("rejection_already_exists", rejection_relative, "rejection records are non-overwritable")
    approval_path = root / f".specbound/approvals/{target}.approval.json"
    if approval_path.exists():
        raise RequirementRejectionError("conflicting_requirement_decision", requirement_relative, "REQ with an approval record cannot be rejected")
    if not reason.strip() or PLACEHOLDER_RE.search(reason):
        raise RequirementRejectionError("malformed_rejection_reason", rejection_relative, "reason must be substantive and non-placeholder")
    try:
        metadata = _frontmatter(requirement_path)
        reviewed_text = requirement_path.read_text(encoding="utf-8")
        rejected_text = _transitioned_discovery_text(reviewed_text, "in_review", "rejected")
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise RequirementRejectionError("invalid_requirement_status_transition", requirement_relative, str(exc)) from exc
    if metadata.get("id") != requirement_id or metadata.get("revision") != revision:
        raise RequirementRejectionError("requirement_binding_mismatch", requirement_relative, "frontmatter id/revision differs from path")
    if metadata.get("status") != "in_review":
        raise RequirementRejectionError("requirement_not_in_review", requirement_relative, "only an in_review REQ may be rejected")
    risk = metadata.get("risk")
    if not isinstance(risk, str) or not risk.strip():
        raise RequirementRejectionError("malformed_requirement", requirement_relative, "risk must be a non-empty string")
    allowed = _load_config(root)["policy"]["requirement_review_authorities_by_risk"].get(risk, [])
    if authority not in allowed:
        raise RequirementRejectionError("invalid_rejection_authority", rejection_relative, "authority is not allowlisted for the REQ risk")
    timestamp = datetime.now().astimezone().isoformat()
    record = {
        "schema_version": 1,
        "requirement_path": requirement_relative,
        "requirement_id": requirement_id,
        "revision": revision,
        "reviewed_sha256": sha256(reviewed_text.encode("utf-8")).hexdigest(),
        "sha256": sha256(rejected_text.encode("utf-8")).hexdigest(),
        "risk": risk,
        "authority": authority,
        "rejected_at": timestamp,
        "decision": "rejected",
        "reason": reason.strip(),
    }
    record_text = json.dumps(record, indent=2, sort_keys=True) + "\n"
    try:
        _atomic_replace_text(requirement_path, rejected_text)
        with rejection_path.open("x", encoding="utf-8") as handle:
            handle.write(record_text)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        _atomic_replace_text(requirement_path, reviewed_text)
        raise RequirementRejectionError("rejection_already_exists", rejection_relative, "rejection records are non-overwritable") from exc
    except OSError as exc:
        _atomic_replace_text(requirement_path, reviewed_text)
        raise RequirementRejectionError("rejection_write_failed", rejection_relative, str(exc)) from exc
    if validate(root).valid:
        return rejection_path
    if rejection_path.exists() and rejection_path.read_text(encoding="utf-8") == record_text:
        rejection_path.unlink()
    _atomic_replace_text(requirement_path, reviewed_text)
    raise RequirementRejectionError("generated_rejection_invalid", rejection_relative, "generated rejection did not pass specbound validate")


def _adopted_requirement_entries(root: Path, config: dict[str, Any], result: Result) -> dict[str, dict[str, Any]]:
    """Read only the exact empty legacy registry until the derived resolver lands."""
    legacy = config["policy"].get("control_plane_adoption")
    if legacy is None:
        return {}
    entries = legacy["requirements"]
    adopted: dict[str, dict[str, Any]] = {}
    for entry in entries:
        requirement_id = entry["id"]
        revision = entry["revision"]
        target = f"{requirement_id}-r{revision}"
        relative = entry["path"]
        requirement_path = root / relative
        symlink = _first_symlink_component(root, requirement_path)
        if symlink:
            result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "adopted REQ path must not contain a symlink")
            continue
        try:
            metadata = _frontmatter(requirement_path)
        except FileNotFoundError:
            result.block("adoption_binding_mismatch", "specbound.yaml", f"adopted {target} does not exist at its bound path")
            continue
        except (OSError, ValueError, yaml.YAMLError) as exc:
            result.block("adoption_binding_mismatch", "specbound.yaml", f"adopted {target} is unreadable: {exc}")
            continue
        if (
            metadata.get("id") != requirement_id
            or metadata.get("revision") != revision
            or metadata.get("status") != "approved"
            or _digest(requirement_path) != entry["sha256"]
        ):
            result.block("adoption_binding_mismatch", "specbound.yaml", f"adopted {target} must remain the exact approved REQ snapshot")
            continue
        adopted[target] = entry
    return adopted


def _validate_adoption_claim(
    root: Path,
    result: Result,
    claim: str | None,
    requirement_target: str | None,
    adopted: dict[str, dict[str, Any]],
) -> None:
    """Enforce evidence only when a caller makes a scoped iteration/delivery claim."""
    if claim is None and requirement_target is None:
        return
    if claim not in {"iteration", "delivery"} or not isinstance(requirement_target, str):
        result.block("invalid_claim_request", "cli", "claim must be iteration or delivery and require req-<id>-r<revision>")
        return
    match = REQUIREMENT_RE.fullmatch(f"{requirement_target}.md")
    if not match:
        result.block("invalid_claim_request", "cli", "requirement must use req-<id>-r<revision>")
        return
    requirement_id, revision_text = match.groups()
    if requirement_target not in adopted:
        result.block("control_plane_not_adopted", requirement_target, "iteration and delivery claims require explicit exact-REQ adoption")
        return

    requirement_number = requirement_id.removeprefix("req-")
    canonical_micro_specs: dict[str, Path] = {}
    micro_root = root / REQUIRED_ROOTS["micro_specs_root"] / requirement_id
    if micro_root.is_dir():
        for micro_path in micro_root.glob(f"ms-{requirement_number}-*.md"):
            try:
                metadata = _frontmatter(micro_path)
            except (OSError, ValueError, yaml.YAMLError):
                continue
            parent = metadata.get("requirement")
            if (
                metadata.get("kind") == "micro-spec"
                and metadata.get("schema_version") == 1
                and isinstance(metadata.get("id"), str)
                and isinstance(parent, dict)
                and parent.get("id") == requirement_id
                and parent.get("revision") == int(revision_text)
                and parent.get("sha256") == adopted[requirement_target]["sha256"]
            ):
                canonical_micro_specs[metadata["id"]] = micro_path

    verified_iteration = False
    iteration_root = root / REQUIRED_ROOTS["iteration_qc_root"] / requirement_id
    if iteration_root.is_dir():
        for record_path in iteration_root.glob(f"iqc-{requirement_number}-*-r*.json"):
            try:
                record = json.loads(record_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            micro_spec = record.get("micro_spec") if isinstance(record, dict) else None
            if (
                isinstance(micro_spec, dict)
                and micro_spec.get("id") in canonical_micro_specs
                and micro_spec.get("path") == canonical_micro_specs[micro_spec["id"]].relative_to(root).as_posix()
                and micro_spec.get("sha256") == _digest(canonical_micro_specs[micro_spec["id"]])
                and record.get("verdict") == "verified"
            ):
                verified_iteration = True
                break

    if claim == "iteration" and not verified_iteration:
        result.block(
            "missing_adopted_iteration_evidence",
            requirement_target,
            "adopted iteration claim requires a canonical Micro-SPEC and verified canonical iteration-QC bound to this REQ snapshot",
        )
    if claim == "delivery":
        delivery_path = root / REQUIRED_ROOTS["delivery_qc_root"] / f"dqc-{requirement_number}-r{revision_text}.json"
        try:
            delivery_record = json.loads(delivery_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            delivery_record = None
        if not isinstance(delivery_record, dict) or delivery_record.get("verdict") != "verified":
            result.block(
                "missing_adopted_delivery_evidence",
                requirement_target,
                "adopted delivery claim requires a verified canonical delivery-QC bound to this REQ snapshot",
            )


def validate(root: Path, claim: str | None = None, requirement: str | None = None) -> Result:
    result = preflight(root)
    if not result.valid:
        return result
    config = _load_config(root)
    agent_contract = config["policy"].get("agent_contract")
    if isinstance(agent_contract, dict) and agent_contract.get("enabled") is True:
        policy_result = validate_agent_roles_policy(root, agent_contract["roles_path"])
        result.checked_agent_roles = policy_result.checked_roles
        result.blockers.extend(policy_result.blockers)
        if policy_result.valid:
            skill_result = validate_agent_role_skills(root, agent_contract["roles_path"])
            result.checked_agent_skills = skill_result.checked_skills
            result.blockers.extend(skill_result.blockers)
    adopted_requirements = _adopted_requirement_entries(root, config, result)
    allowed_authorities_by_risk = {
        risk_class: set(authorities)
        for risk_class, authorities in config["policy"]["discovery_confirmation_authorities_by_risk"].items()
    }
    allowed_requirement_authorities_by_risk = {
        risk: set(authorities)
        for risk, authorities in config["policy"]["requirement_review_authorities_by_risk"].items()
    }
    allowed_micro_spec_review_authorities_by_risk = {
        risk: set(authorities)
        for risk, authorities in config["policy"]["micro_spec_review_authorities_by_risk"].items()
    }
    requirement_root = _validate_root(root, REQUIRED_ROOTS["requirements_root"], result, "requirements")
    discovery_root = _validate_root(root, REQUIRED_ROOTS["discoveries_root"], result, "discoveries")
    confirmation_root = _validate_root(
        root,
        REQUIRED_ROOTS["discovery_confirmations_root"],
        result,
        "discovery confirmations",
    )
    rejection_root = _validate_root(root, REQUIRED_ROOTS["rejections_root"], result, "rejections")
    review_submission_root = _validate_root(
        root,
        REQUIRED_ROOTS["review_submissions_root"],
        result,
        "review submissions",
    )
    micro_spec_root = _validate_root(root, REQUIRED_ROOTS["micro_specs_root"], result, "Micro-SPECs")
    micro_spec_review_root = _validate_root(root, REQUIRED_ROOTS["micro_spec_reviews_root"], result, "Micro-SPEC reviews")
    iteration_qc_root = _validate_root(root, REQUIRED_ROOTS["iteration_qc_root"], result, "iteration-QC")
    delivery_qc_root = _validate_root(root, REQUIRED_ROOTS["delivery_qc_root"], result, "delivery-QC")
    if requirement_root:
        requirement_paths = sorted(requirement_root.rglob("*.md"))
        latest_approved_revisions: dict[str, int] = {}
        seen_identities: set[tuple[str, int]] = set()
        for path in requirement_paths:
            match = REQUIREMENT_RE.fullmatch(path.name)
            if not match:
                continue
            requirement_id, revision_text = match.groups()
            identity = (requirement_id, int(revision_text))
            relative = path.relative_to(root).as_posix()
            if identity in seen_identities:
                result.block("duplicate_requirement_revision", relative, "duplicate REQ id/revision artifact")
            seen_identities.add(identity)
            try:
                metadata = _frontmatter(path)
            except (OSError, ValueError, yaml.YAMLError):
                continue
            if metadata.get("status") == "approved":
                latest_approved_revisions[requirement_id] = max(
                    latest_approved_revisions.get(requirement_id, 0), identity[1]
                )
        for path in requirement_paths:
            _validate_requirement(root, path, result, latest_approved_revisions)
    if discovery_root:
        for path in sorted(discovery_root.rglob("*.md")):
            _validate_discovery(root, path, result)
    if confirmation_root:
        for path in sorted(confirmation_root.rglob("*.json")):
            _validate_discovery_confirmation(root, path, result, allowed_authorities_by_risk)
    if rejection_root:
        for path in sorted(rejection_root.rglob("*.json")):
            _validate_requirement_rejection(root, path, result, allowed_requirement_authorities_by_risk)
    if review_submission_root:
        for path in sorted(review_submission_root.rglob("*.json")):
            _validate_requirement_review_submission(root, path, result)
    if micro_spec_root:
        _validate_family_root(root, micro_spec_root, result, "micro_specs")
    if micro_spec_review_root:
        for path in sorted(micro_spec_review_root.rglob("*.json")):
            _validate_micro_spec_review(root, path, result, allowed_micro_spec_review_authorities_by_risk)
    if iteration_qc_root:
        _validate_family_root(root, iteration_qc_root, result, "iteration_qc")
    if delivery_qc_root:
        _validate_family_root(root, delivery_qc_root, result, "delivery_qc")
    activation_root = root / REQUIRED_ROOTS["activations_root"]
    if (root / ".git").exists() and activation_root.is_dir():
        effective_registry = resolve_effective_activation_registry(root)
        result.checked_effective_activations = len(effective_registry.activations)
        for blocker in effective_registry.blockers:
            result.block(blocker.code, blocker.path, blocker.detail)
        claim_transition = {
            "iteration": "iteration_qc",
            "delivery": "delivery_qc",
        }.get(claim)
        if claim_transition is not None and effective_registry.valid:
            adopted_requirements = {
                f"{state.requirement_id}-r{state.revision}": {
                    "id": state.requirement_id,
                    "revision": state.revision,
                    "path": state.requirement_path,
                    "sha256": state.requirement_sha256,
                }
                for state in effective_registry.activations
                if state.transition == claim_transition
            }
    _validate_adoption_claim(root, result, claim, requirement, adopted_requirements)
    return result
