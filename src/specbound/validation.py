"""Deterministic, fail-closed checks for SpecBound canonical lifecycle artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

import yaml

REQUIREMENT_RE = re.compile(r"^(req-[0-9]+)-r([1-9][0-9]*)\.md$")
DISCOVERY_RE = re.compile(r"^disc-([0-9]+)-r([1-9][0-9]*)\.md$")
DISCOVERY_DIRECTORY_RE = re.compile(r"^dcy-([0-9]+)$")
DISCOVERY_CONFIRMATION_RE = re.compile(r"^(disc-[0-9]+)-r([1-9][0-9]*)\.confirmation\.json$")
REQUIRED_ROOTS = {
    "requirements_root": "docs/requirements",
    "discoveries_root": "docs/discoveries",
    "control_root": ".specbound",
    "approvals_root": ".specbound/approvals",
    "discovery_confirmations_root": ".specbound/discovery-confirmations",
}
REQUIREMENT_PATTERN = "req-<id>/req-<id>-r<revision>.md"
DISCOVERY_PATTERN = "dcy-<id>/disc-<id>-r<revision>.md"
REQUIRED_APPROVAL_FIELDS = {
    "requirement_path",
    "requirement_id",
    "revision",
    "sha256",
    "risk",
    "authority",
}
REQUIRED_DISCOVERY_CONFIRMATION_FIELDS = {
    "schema_version",
    "discovery_path",
    "discovery_id",
    "revision",
    "sha256",
    "risk_class",
    "authority",
    "confirmed_at",
    "decision",
    "permitted_next_action",
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

    policy = config.get("policy")
    if not isinstance(policy, dict) or policy.get("approved_status") != "approved":
        result.block("malformed_config", "specbound.yaml", "policy.approved_status must equal 'approved'")
    if not isinstance(policy, dict) or policy.get("confirmed_discovery_status") != "in_review":
        result.block(
            "malformed_config",
            "specbound.yaml",
            "policy.confirmed_discovery_status must equal 'in_review'",
        )
    _validate_required_field_config(result, policy, "required_approval_fields", REQUIRED_APPROVAL_FIELDS)
    _validate_required_field_config(
        result,
        policy,
        "required_discovery_confirmation_fields",
        REQUIRED_DISCOVERY_CONFIRMATION_FIELDS,
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
    return result


def _validate_required_field_config(
    result: Result, policy: Any, name: str, required: set[str]
) -> None:
    fields = policy.get(name) if isinstance(policy, dict) else None
    if not isinstance(fields, list) or not all(isinstance(field, str) for field in fields):
        result.block("malformed_config", "specbound.yaml", f"policy.{name} must be a list of strings")
    elif not required.issubset(set(fields)):
        result.block("malformed_config", "specbound.yaml", f"policy.{name} must include the bootstrap fields")


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


def _validate_requirement(root: Path, path: Path, result: Result) -> None:
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
    if not isinstance(status, str):
        result.block("malformed_requirement", relative, "frontmatter status must be a string")
        return
    if status != "approved":
        return

    result.approved_requirements += 1
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


def _validate_discovery(root: Path, path: Path, result: Result) -> None:
    relative = path.relative_to(root).as_posix()
    symlink = _first_symlink_component(root, path)
    if symlink:
        result.block("unsafe_artifact_path", symlink.relative_to(root).as_posix(), "canonical Discovery path must not contain a symlink")
        return
    path_parts = path.relative_to(root / REQUIRED_ROOTS["discoveries_root"]).parts
    if len(path_parts) != 2:
        result.block("invalid_discovery_path", relative, "Discovery must be directly below dcy-<id>/")
        return
    directory, filename = path_parts
    directory_match = DISCOVERY_DIRECTORY_RE.fullmatch(directory)
    filename_match = DISCOVERY_RE.fullmatch(filename)
    if not directory_match or not filename_match or directory_match.group(1) != filename_match.group(1):
        result.block("invalid_discovery_path", relative, "expected dcy-<id>/disc-<id>-r<revision>.md")
        return

    numeric_id, revision_text = filename_match.groups()
    discovery_id = f"disc-{numeric_id}"
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
    if metadata.get("status") not in {"draft", "in_review"}:
        result.block("malformed_discovery", relative, "frontmatter status must be 'draft' or 'in_review'")
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
        result.block("invalid_discovery_confirmation_path", relative, "expected disc-<id>-r<revision>.confirmation.json")
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
    expected_discovery_path = f"docs/discoveries/dcy-{expected_id.removeprefix('disc-')}/{expected_id}-r{revision_text}.md"
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
    if metadata.get("status") != "in_review":
        result.block("discovery_binding_mismatch", relative, "confirmed Discovery must retain status 'in_review'")
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
    risk_class = confirmation["risk_class"]
    if (
        not isinstance(risk_class, str)
        or not risk_class.strip()
        or PLACEHOLDER_RE.search(risk_class)
        or risk_class != metadata.get("risk_class")
    ):
        result.block("discovery_binding_mismatch", relative, "risk_class differs from the bound Discovery")
    digest = confirmation["sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        result.block("malformed_discovery_confirmation", relative, "sha256 must be a lowercase 64-character hex digest")
    elif digest != _digest(discovery_path):
        result.block("discovery_digest_mismatch", relative, "confirmation digest differs from Discovery content")
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


def validate(root: Path) -> Result:
    result = preflight(root)
    if not result.valid:
        return result
    config = _load_config(root)
    allowed_authorities_by_risk = {
        risk_class: set(authorities)
        for risk_class, authorities in config["policy"]["discovery_confirmation_authorities_by_risk"].items()
    }
    requirement_root = _validate_root(root, REQUIRED_ROOTS["requirements_root"], result, "requirements")
    discovery_root = _validate_root(root, REQUIRED_ROOTS["discoveries_root"], result, "discoveries")
    confirmation_root = _validate_root(
        root,
        REQUIRED_ROOTS["discovery_confirmations_root"],
        result,
        "discovery confirmations",
    )
    if requirement_root:
        for path in sorted(requirement_root.rglob("*.md")):
            _validate_requirement(root, path, result)
    if discovery_root:
        for path in sorted(discovery_root.rglob("*.md")):
            _validate_discovery(root, path, result)
    if confirmation_root:
        for path in sorted(confirmation_root.rglob("*.json")):
            _validate_discovery_confirmation(root, path, result, allowed_authorities_by_risk)
    return result
