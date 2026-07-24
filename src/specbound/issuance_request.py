"""Read-only pre-publication validation for canonical evidence issuance requests."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

import yaml

from .validation import REQUIRED_ROOTS, _frontmatter, _required_micro_spec_sections, _requirement_acceptance_criteria, preflight


@dataclass(frozen=True)
class IssuanceBlocker:
    code: str
    path: str
    detail: str

    def payload(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "detail": self.detail}


@dataclass(frozen=True)
class IssuanceRequestResult:
    artifact_kind: str
    canonical_target: str | None
    blockers: tuple[IssuanceBlocker, ...]

    @property
    def valid(self) -> bool:
        return not self.blockers

    def payload(self) -> dict[str, Any]:
        if not self.valid:
            return {"valid": False, "blockers": [blocker.payload() for blocker in self.blockers]}
        return {
            "valid": True,
            "operation": "prevalidation_only",
            "artifact_kind": self.artifact_kind,
            "canonical_target": self.canonical_target,
        }


_KIND_PATTERNS = {
    "micro-spec": re.compile(r"^ms-([0-9]+)-(0*[1-9][0-9]*)$"),
    "iteration-qc": re.compile(r"^iqc-([0-9]+)-(0*[1-9][0-9]*)-r([1-9][0-9]*)$"),
    "delivery-qc": re.compile(r"^dqc-([0-9]+)-r([1-9][0-9]*)$"),
}


def _safe_identity(identity: str) -> bool:
    value = PurePosixPath(identity)
    return bool(identity) and not value.is_absolute() and len(value.parts) == 1 and value.parts[0] not in {".", ".."}


def _canonical_target(kind: str, identity: str) -> tuple[str | None, IssuanceBlocker | None]:
    pattern = _KIND_PATTERNS.get(kind)
    if pattern is None:
        return None, IssuanceBlocker("unknown_artifact_kind", "artifact_kind", "supported kinds are micro-spec, iteration-qc, and delivery-qc")
    if not _safe_identity(identity) or not pattern.fullmatch(identity):
        return None, IssuanceBlocker("invalid_canonical_target", "target_identity", f"invalid canonical {kind} target identity")
    match = pattern.fullmatch(identity)
    assert match is not None
    number = match.group(1)
    if kind == "micro-spec":
        return f"{REQUIRED_ROOTS['micro_specs_root']}/req-{number}/{identity}.md", None
    if kind == "iteration-qc":
        return f"{REQUIRED_ROOTS['iteration_qc_root']}/req-{number}/{identity}.json", None
    return f"{REQUIRED_ROOTS['delivery_qc_root']}/{identity}.json", None


def _micro_spec_candidate(root: Path, target: str, candidate: str) -> list[IssuanceBlocker]:
    blockers: list[IssuanceBlocker] = []
    try:
        if not candidate.startswith("---\n"):
            raise ValueError("missing YAML frontmatter opening delimiter")
        end = candidate.find("\n---\n", len("---\n"))
        if end < 0:
            raise ValueError("missing YAML frontmatter closing delimiter")
        metadata = yaml.safe_load(candidate[len("---\n") : end])
        if not isinstance(metadata, dict):
            raise ValueError("frontmatter must be a mapping")
    except (ValueError, yaml.YAMLError) as exc:
        return [IssuanceBlocker("invalid_candidate_schema", target, str(exc))]

    target_id = target.rsplit("/", 1)[-1][:-3]
    number = target_id.split("-")[1]
    if metadata.get("schema_version") != 1 or metadata.get("kind") != "micro-spec" or metadata.get("id") != target_id:
        blockers.append(IssuanceBlocker("candidate_target_binding_mismatch", target, "candidate id, kind, and schema_version must match canonical target"))
    requirement = metadata.get("requirement")
    if not isinstance(requirement, dict) or set(requirement) != {"path", "id", "revision", "sha256"}:
        return blockers + [IssuanceBlocker("invalid_candidate_schema", target, "candidate requirement binding must contain exactly path, id, revision, and sha256")]
    requirement_id = f"req-{number}"
    revision = requirement.get("revision")
    expected_path = f"{REQUIRED_ROOTS['requirements_root']}/{requirement_id}/{requirement_id}-r{revision}.md" if isinstance(revision, int) and not isinstance(revision, bool) and revision >= 1 else None
    if requirement.get("id") != requirement_id or requirement.get("path") != expected_path or expected_path is None:
        blockers.append(IssuanceBlocker("candidate_parent_binding_mismatch", target, "candidate parent must be the target-matching canonical REQ path/id/revision"))
        return blockers
    parent = root / expected_path
    try:
        parent_meta = _frontmatter(parent)
    except FileNotFoundError:
        return blockers + [IssuanceBlocker("missing_parent_requirement", expected_path, "bound canonical REQ does not exist")]
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return blockers + [IssuanceBlocker("invalid_parent_requirement", expected_path, str(exc))]
    if parent_meta.get("id") != requirement_id or parent_meta.get("revision") != revision or parent_meta.get("status") != "approved":
        blockers.append(IssuanceBlocker("invalid_parent_requirement", expected_path, "bound parent must be the exact approved REQ snapshot"))
    digest = requirement.get("sha256")
    actual_digest = sha256(parent.read_bytes()).hexdigest()
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        blockers.append(IssuanceBlocker("invalid_candidate_schema", target, "candidate parent sha256 must be lowercase 64-character hex"))
    elif digest != actual_digest:
        blockers.append(IssuanceBlocker("stale_parent_digest", expected_path, "candidate parent sha256 differs from exact current REQ bytes"))
    selected = metadata.get("selected_acceptance_criteria")
    try:
        known_criteria = _requirement_acceptance_criteria(parent)
    except OSError:
        known_criteria = set()
    if not isinstance(selected, list) or not selected or len(set(selected)) != len(selected) or not all(isinstance(item, str) and re.fullmatch(r"AC-[0-9]+", item) for item in selected) or not set(selected).issubset(known_criteria):
        blockers.append(IssuanceBlocker("invalid_candidate_semantics", target, "selected ACs must be a unique non-empty subset of the bound REQ"))
    missing = _required_micro_spec_sections(candidate, parent_meta.get("risk", ""))
    if missing:
        blockers.append(IssuanceBlocker("incomplete_candidate_content", target, f"missing substantive sections: {', '.join(missing)}"))
    return blockers


def _json_candidate(kind: str, target: str, candidate: str) -> list[IssuanceBlocker]:
    try:
        record = json.loads(candidate)
    except json.JSONDecodeError as exc:
        return [IssuanceBlocker("invalid_candidate_schema", target, str(exc))]
    if not isinstance(record, dict) or record.get("schema_version") != 1:
        return [IssuanceBlocker("invalid_candidate_schema", target, "candidate must be a schema_version 1 JSON object")]
    return [IssuanceBlocker("family_prerequisite_unmet", target, f"{kind} parent/adoption graph validation is deferred until AC-004")]


def prevalidate_issuance_request(root: Path, artifact_kind: str, target_identity: str, candidate_file: Path | None) -> IssuanceRequestResult:
    """Validate exactly one request without creating or modifying a canonical target."""
    target, blocker = _canonical_target(artifact_kind, target_identity)
    if blocker:
        return IssuanceRequestResult(artifact_kind, None, (blocker,))
    assert target is not None
    configuration = preflight(root)
    if not configuration.valid:
        blockers = tuple(IssuanceBlocker(item["code"], item["path"], item["detail"]) for item in configuration.blockers)
        return IssuanceRequestResult(artifact_kind, target, blockers)
    if candidate_file is None:
        return IssuanceRequestResult(artifact_kind, target, (IssuanceBlocker("incomplete_candidate_content", target, "--candidate-file is required"),))
    try:
        candidate = candidate_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return IssuanceRequestResult(artifact_kind, target, (IssuanceBlocker("unreadable_candidate_content", str(candidate_file), str(exc)),))
    if not candidate.strip():
        return IssuanceRequestResult(artifact_kind, target, (IssuanceBlocker("incomplete_candidate_content", target, "candidate content must not be empty"),))
    blockers = _micro_spec_candidate(root, target, candidate) if artifact_kind == "micro-spec" else _json_candidate(artifact_kind, target, candidate)
    return IssuanceRequestResult(artifact_kind, target, tuple(blockers))
