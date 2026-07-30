"""Read-only pre-publication validation for canonical evidence issuance requests."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import errno
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any

import yaml

from .control_plane_adoption import check_effective_adoption
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
    operation: str = "prevalidation_only"
    canonical_identity: str | None = None
    published_sha256: str | None = None

    @property
    def valid(self) -> bool:
        return not self.blockers

    def payload(self) -> dict[str, Any]:
        if not self.valid:
            return {"valid": False, "blockers": [blocker.payload() for blocker in self.blockers]}
        payload = {
            "valid": True,
            "operation": self.operation,
            "artifact_kind": self.artifact_kind,
            "canonical_target": self.canonical_target,
        }
        if self.canonical_identity is not None:
            payload["canonical_identity"] = self.canonical_identity
        if self.published_sha256 is not None:
            payload["published_sha256"] = self.published_sha256
        return payload


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


def _valid_micro_spec_approval(root: Path, target: str, candidate: str) -> list[IssuanceBlocker]:
    """Require the candidate's exact approved REQ snapshot to have a valid approval binding."""
    metadata = yaml.safe_load(candidate.split("\n---\n", 1)[0].removeprefix("---\n"))
    assert isinstance(metadata, dict)
    requirement = metadata["requirement"]
    assert isinstance(requirement, dict)
    parent_path = requirement["path"]
    parent = root / parent_path
    approval_path = root / f".specbound/approvals/{requirement['id']}-r{requirement['revision']}.approval.json"
    try:
        approval = json.loads(approval_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [IssuanceBlocker("missing_parent_approval", approval_path.relative_to(root).as_posix(), "approved parent REQ has no canonical approval record")]
    except (OSError, json.JSONDecodeError) as exc:
        return [IssuanceBlocker("malformed_parent_approval", approval_path.relative_to(root).as_posix(), str(exc))]
    if not isinstance(approval, dict):
        return [IssuanceBlocker("malformed_parent_approval", approval_path.relative_to(root).as_posix(), "approval record must be an object")]
    try:
        parent_metadata = _frontmatter(parent)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [IssuanceBlocker("invalid_parent_requirement", parent_path, str(exc))]
    expected = {
        "requirement_path": parent_path,
        "requirement_id": requirement["id"],
        "revision": requirement["revision"],
        "sha256": sha256(parent.read_bytes()).hexdigest(),
        "risk": parent_metadata.get("risk"),
    }
    mismatches = [field for field, value in expected.items() if approval.get(field) != value]
    if mismatches or not isinstance(approval.get("authority"), str) or not approval["authority"].strip():
        return [IssuanceBlocker("invalid_parent_approval_binding", approval_path.relative_to(root).as_posix(), "approval must exactly bind parent path, id, revision, digest, risk, and authority")]
    newer_approved = False
    requirement_id = requirement["id"]
    for path in (root / REQUIRED_ROOTS["requirements_root"] / requirement_id).glob(f"{requirement_id}-r*.md"):
        try:
            other = _frontmatter(path)
        except (OSError, ValueError, yaml.YAMLError):
            continue
        if other.get("status") == "approved" and isinstance(other.get("revision"), int) and other["revision"] > requirement["revision"]:
            newer_approved = True
    if newer_approved:
        return [IssuanceBlocker("superseded_parent_requirement", parent_path, "bound parent is not the latest approved REQ revision")]
    return []


def _json_candidate(root: Path, kind: str, target: str, candidate: str) -> list[IssuanceBlocker]:
    try:
        record = json.loads(candidate)
    except json.JSONDecodeError as exc:
        return [IssuanceBlocker("invalid_candidate_schema", target, str(exc))]
    if not isinstance(record, dict) or record.get("schema_version") != 1:
        return [IssuanceBlocker("invalid_candidate_schema", target, "candidate must be a schema_version 1 JSON object")]
    if kind == "iteration-qc":
        micro = record.get("micro_spec")
        if not isinstance(micro, dict) or not isinstance(micro.get("path"), str):
            return [IssuanceBlocker("invalid_candidate_semantics", target, "iteration-QC requires a canonical Micro-SPEC binding")]
        micro_path = root / micro["path"]
        if not micro_path.is_file() or sha256(micro_path.read_bytes()).hexdigest() != micro.get("sha256"):
            return [IssuanceBlocker("missing_or_mismatched_micro_spec", micro["path"], "exact canonical Micro-SPEC parent is required")]
        metadata = _frontmatter(micro_path)
        selected = record.get("selected_acceptance_criteria")
        expected = metadata.get("selected_acceptance_criteria")
        if selected != expected:
            return [
                IssuanceBlocker(
                    "iteration_qc_ac_set_mismatch",
                    target,
                    "iteration-QC selected acceptance criteria must exactly match its canonical Micro-SPEC",
                )
            ]
        requirement = metadata.get("requirement")
    else:
        requirement = record.get("requirement")
    if not isinstance(requirement, dict) or not all(key in requirement for key in ("path", "id", "revision", "sha256")):
        return [IssuanceBlocker("invalid_candidate_semantics", target, "candidate must bind an exact canonical approved REQ")]
    parent = root / requirement["path"]
    if not parent.is_file() or sha256(parent.read_bytes()).hexdigest() != requirement["sha256"] or _frontmatter(parent).get("status") != "approved":
        return [IssuanceBlocker("invalid_parent_requirement", str(requirement["path"]), "exact approved parent REQ is required")]
    transition = "iteration_qc" if kind == "iteration-qc" else "delivery_qc"
    adoption = check_effective_adoption(
        root,
        f"{requirement['id']}-r{requirement['revision']}",
        transition,
    )
    if adoption.blockers:
        return [
            IssuanceBlocker(blocker.code, blocker.path, blocker.detail)
            for blocker in adoption.blockers
        ]
    adopted = next(
        (
            state
            for state in adoption.adoptions
            if state.requirement_path == requirement.get("path")
            and state.requirement_id == requirement.get("id")
            and state.revision == requirement.get("revision")
            and state.requirement_sha256 == requirement.get("sha256")
            and state.transition == transition
        ),
        None,
    )
    if adopted is None:
        return [IssuanceBlocker("unadopted_parent", str(requirement["path"]), "QC publication requires exact copied-fixture adoption")]
    if kind == "delivery-qc":
        coverage = record.get("coverage")
        if not isinstance(coverage, list) or not coverage:
            return [IssuanceBlocker("invalid_candidate_semantics", target, "delivery-QC requires iteration-QC coverage")]
        for edge in coverage:
            iteration = edge.get("iteration_qc") if isinstance(edge, dict) else None
            if not isinstance(iteration, dict) or not isinstance(iteration.get("path"), str):
                return [IssuanceBlocker("invalid_delivery_graph_edge", target, "delivery-QC coverage requires canonical iteration-QC edges")]
            path = root / iteration["path"]
            if not path.is_file() or sha256(path.read_bytes()).hexdigest() != iteration.get("sha256"):
                return [IssuanceBlocker("missing_or_mismatched_iteration_qc", iteration["path"], "exact iteration-QC edge is required")]
    return []


def prevalidate_issuance_request(
    root: Path,
    artifact_kind: str,
    target_identity: str,
    candidate_file: Path | None,
    *,
    require_valid_approval: bool = False,
) -> IssuanceRequestResult:
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
    blockers = _micro_spec_candidate(root, target, candidate) if artifact_kind == "micro-spec" else _json_candidate(root, artifact_kind, target, candidate)
    if not blockers and artifact_kind == "micro-spec" and require_valid_approval:
        blockers.extend(_valid_micro_spec_approval(root, target, candidate))
    return IssuanceRequestResult(artifact_kind, target, tuple(blockers))


def _write_published_bytes(output: Any, content: bytes) -> None:
    output.write(content)


def _flush_published_output(output: Any) -> None:
    output.flush()


def _fsync_descriptor(descriptor: int) -> None:
    os.fsync(descriptor)


def _final_published_digest(parent_fd: int, name: str) -> str:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        digest = sha256()
        while block := os.read(descriptor, 65536):
            digest.update(block)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _exclusive_fixture_publish(root: Path, canonical_target: str, content: bytes) -> IssuanceBlocker | str:
    """Create one canonical fixture leaf, fsync it, and remove only an owned failed leaf."""
    parts = PurePosixPath(canonical_target).parts
    parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    leaf_fd: int | None = None
    owned: tuple[int, int] | None = None
    published_digest: str | None = None
    try:
        for part in parts[:-1]:
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            except FileNotFoundError:
                return IssuanceBlocker("missing_canonical_target_directory", canonical_target, "canonical target parent directory must already exist")
            except OSError as exc:
                return IssuanceBlocker("unsafe_canonical_target_path", canonical_target, str(exc))
            os.close(parent_fd)
            parent_fd = next_fd
        try:
            leaf_fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=parent_fd)
        except FileExistsError:
            return IssuanceBlocker("duplicate_canonical_target", canonical_target, "canonical target already exists or was won by a competing publisher")
        except OSError as exc:
            return IssuanceBlocker("unsafe_canonical_target_path" if exc.errno in {errno.ELOOP, errno.ENOTDIR} else "publication_failed", canonical_target, str(exc))
        state = os.fstat(leaf_fd)
        owned = (state.st_dev, state.st_ino)
        try:
            with os.fdopen(leaf_fd, "wb", closefd=False) as output:
                _write_published_bytes(output, content)
                _flush_published_output(output)
                _fsync_descriptor(output.fileno())
            _fsync_descriptor(parent_fd)
            published_digest = _final_published_digest(parent_fd, parts[-1])
        except OSError as exc:
            try:
                current = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == owned:
                    os.unlink(parts[-1], dir_fd=parent_fd)
                    _fsync_descriptor(parent_fd)
            except OSError:
                pass
            return IssuanceBlocker("publication_failed", canonical_target, str(exc))
    finally:
        if leaf_fd is not None:
            os.close(leaf_fd)
        os.close(parent_fd)
    assert published_digest is not None
    return published_digest


def publish_issuance(root: Path, artifact_kind: str, target_identity: str, candidate_file: Path | None) -> IssuanceRequestResult:
    """Publish one validated fixture-only planning/QC artifact; no lifecycle authority is created."""
    marker = root / ".specbound/pre-adoption-fixture"
    if not marker.is_file():
        return IssuanceRequestResult(artifact_kind, None, (IssuanceBlocker("fixture_publication_required", ".specbound/pre-adoption-fixture", "publication is limited to an explicitly marked copied fixture"),))
    result = prevalidate_issuance_request(root, artifact_kind, target_identity, candidate_file, require_valid_approval=artifact_kind == "micro-spec")
    if not result.valid:
        return result
    assert result.canonical_target is not None
    assert candidate_file is not None
    try:
        content = candidate_file.read_bytes()
    except OSError as exc:
        return IssuanceRequestResult(artifact_kind, result.canonical_target, (IssuanceBlocker("unreadable_candidate_content", str(candidate_file), str(exc)),))
    outcome = _exclusive_fixture_publish(root, result.canonical_target, content)
    if isinstance(outcome, IssuanceBlocker):
        return IssuanceRequestResult(artifact_kind, result.canonical_target, (outcome,))
    return IssuanceRequestResult(
        artifact_kind,
        result.canonical_target,
        (),
        operation=f"published_pre_adoption_{artifact_kind.replace('-', '_')}",
        canonical_identity=target_identity,
        published_sha256=outcome,
    )
