"""Authority-bound, failure-atomic live iteration-QC publication."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import errno
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import unicodedata

from jsonschema import Draft202012Validator
import yaml

from .control_plane_adoption import check_effective_adoption

_TARGET_RE = re.compile(r"iqc-([0-9]+)-(0*[1-9][0-9]*)-r1")
_SHA_RE = re.compile(r"[a-f0-9]{64}")
_SHA1_RE = re.compile(r"[a-f0-9]{40}")
_PLACEHOLDER_RE = re.compile(r"<[^>]+>|\b(?:TODO|TBD|placeholder)\b", re.IGNORECASE)
_POLICY = {
    "low": ["repository-maintainer"],
    "medium": ["repository-maintainer"],
    "high": ["independent-advanced-llm-reviewer"],
}
_LIBC = ctypes.CDLL(None, use_errno=True)
_RENAMEAT2 = getattr(_LIBC, "renameat2", None)
if _RENAMEAT2 is not None:
    _RENAMEAT2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    _RENAMEAT2.restype = ctypes.c_int
_APPROVAL_FIELDS = {
    "requirement_path", "requirement_id", "revision", "sha256", "risk", "authority",
}
_MICRO_SPEC_REVIEW_FIELDS = {
    "schema_version", "micro_spec_path", "micro_spec_id", "micro_spec_sha256",
    "requirement_path", "requirement_id", "revision", "requirement_sha256", "risk",
    "authority", "decided_at", "decision", "reason", "permitted_next_action",
}
_LEGACY_IQC_FIELDS = {
    "schema_version", "micro_spec", "selected_acceptance_criteria",
    "verification", "verdict", "remaining_acceptance_criteria",
}


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True)
class IQCBlocker:
    code: str
    path: str
    detail: str


@dataclass(frozen=True)
class IterationQCDecisionResult:
    blockers: tuple[IQCBlocker, ...]
    canonical_target: str
    published_sha256: str | None = None

    @property
    def valid(self) -> bool:
        return not self.blockers

    def payload(self) -> dict[str, object]:
        if self.blockers:
            return {
                "valid": False,
                "blockers": [
                    {"code": item.code, "path": item.path, "detail": item.detail}
                    for item in self.blockers
                ],
            }
        return {
            "valid": True,
            "canonical_target": self.canonical_target,
            "published_sha256": self.published_sha256,
        }


@dataclass(frozen=True)
class _PublishedLeaf:
    owned: tuple[int, int]
    digest: str
    fd: int


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _strict_load(blob: bytes) -> object:
    if blob.startswith(b"\xef\xbb\xbf"):
        raise ValueError("UTF-8 BOM is forbidden")
    text = blob.decode("utf-8", errors="strict")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateKey(f"duplicate key: {key}")
            result[key] = value
        return result

    value = json.loads(text, object_pairs_hook=unique)
    if blob != _canonical(value):
        raise ValueError("input must use canonical JSON bytes")
    return value


def _normalized_nonplaceholder(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and unicodedata.normalize("NFC", value) == value
        and _PLACEHOLDER_RE.search(value) is None
    )


def _all_nfc(value: object) -> bool:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value) == value
    if isinstance(value, list):
        return all(_all_nfc(item) for item in value)
    if isinstance(value, dict):
        return all(_all_nfc(key) and _all_nfc(item) for key, item in value.items())
    return True


def _all_strings_nonplaceholder(value: object) -> bool:
    if isinstance(value, str):
        return _normalized_nonplaceholder(value)
    if isinstance(value, list):
        return all(_all_strings_nonplaceholder(item) for item in value)
    if isinstance(value, dict):
        return all(
            _normalized_nonplaceholder(key)
            and _all_strings_nonplaceholder(item)
            for key, item in value.items()
        )
    return True


def _valid_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return (
        parsed.tzinfo is not None
        and parsed.utcoffset() == timezone.utc.utcoffset(parsed)
    )


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=root, check=False, capture_output=True, text=True
    )


def _frontmatter(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        raise ValueError("missing YAML frontmatter")
    value = yaml.safe_load(text.split("\n---\n", 1)[0][4:])
    if not isinstance(value, dict):
        raise ValueError("frontmatter must be a mapping")
    return value


def _parent_acceptance_criteria(path: Path) -> list[str]:
    criteria = re.findall(
        r"^(?:###\s+|-\s+)(AC-[0-9]+)\b",
        path.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if not criteria or len(criteria) != len(set(criteria)):
        raise ValueError("parent REQ must have a unique ordered AC set")
    return criteria


def _load_schema(name: str) -> dict[str, object]:
    return json.loads(
        (Path(__file__).resolve().parent / "schemas" / name).read_text(encoding="utf-8")
    )


def _load_candidate(path: Path, schema_name: str, target: str) -> tuple[dict[str, object] | None, bytes | None, IQCBlocker | None]:
    try:
        blob = Path(path).read_bytes()
        value = _strict_load(blob)
        if (
            not isinstance(value, dict)
            or not _all_nfc(value)
            or not _all_strings_nonplaceholder(value)
        ):
            raise ValueError(
                "candidate must be one NFC-normalized JSON object without blank or placeholder strings"
            )
        errors = tuple(Draft202012Validator(_load_schema(schema_name)).iter_errors(value))
        if errors:
            raise ValueError("; ".join(error.message for error in errors))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, _DuplicateKey) as exc:
        return None, None, IQCBlocker("malformed_iteration_qc_input", str(path), str(exc))
    return value, blob, None


def _git_contract(root: Path, target: str) -> tuple[str | None, IQCBlocker | None]:
    fmt = _git(root, "rev-parse", "--show-object-format")
    if fmt.returncode != 0:
        return None, IQCBlocker("not_git_repository", ".git", fmt.stderr.strip())
    if fmt.stdout.strip() != "sha1":
        return None, IQCBlocker("unsupported_git_object_format", ".git", "iteration-QC v1 requires SHA-1 Git object IDs")
    shallow = _git(root, "rev-parse", "--is-shallow-repository")
    if shallow.returncode != 0 or shallow.stdout.strip() != "false":
        return None, IQCBlocker("shallow_repository", ".git", "complete history is required")
    head = _git(root, "rev-parse", "--verify", "HEAD^{commit}")
    if head.returncode != 0 or _SHA1_RE.fullmatch(head.stdout.strip()) is None:
        return None, IQCBlocker("git_query_failed", "HEAD", head.stderr.strip() or "invalid HEAD")
    status = _git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        ".",
        f":(exclude){target}",
    )
    if status.returncode != 0:
        return None, IQCBlocker("git_query_failed", ".", status.stderr.strip())
    if status.stdout:
        return None, IQCBlocker("dirty_worktree", ".", "tracked and untracked worktree bytes must be clean before publication")
    return head.stdout.strip(), None


def _write_published_bytes(fd: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError("short iteration-QC write")
        view = view[count:]


def _fsync_descriptor(fd: int) -> None:
    os.fsync(fd)


def _final_published_bytes(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _open_parent(root: Path, target: str) -> tuple[int | None, IQCBlocker | None]:
    parts = PurePosixPath(target).parts
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        for part in parts[:-1]:
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError as exc:
                os.close(fd)
                detail = "canonical iteration-QC parent must exist without symlinks" if exc.errno in {errno.ENOENT, errno.ELOOP, errno.ENOTDIR} else str(exc)
                return None, IQCBlocker("unsafe_iteration_qc_target", target, detail)
            os.close(fd)
            fd = next_fd
        return fd, None
    except OSError as exc:
        return None, IQCBlocker("iteration_qc_publication_failed", target, str(exc))


def _rename_noreplace(parent_fd: int, source: str, destination: str) -> None:
    if _RENAMEAT2 is None:
        raise OSError(errno.ENOSYS, "renameat2(RENAME_NOREPLACE) is unavailable")
    result = _RENAMEAT2(
        parent_fd,
        os.fsencode(source),
        parent_fd,
        os.fsencode(destination),
        1,  # RENAME_NOREPLACE
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


def _supports_atomic_noreplace(root: Path) -> bool:
    if _RENAMEAT2 is None:
        return False
    root_fd: int | None = None
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        # Same-source/destination RENAME_NOREPLACE must fail with EEXIST and
        # cannot mutate bytes. This exercises libc, kernel, seccomp, and the
        # target filesystem before any canonical publication mutation.
        _rename_noreplace(root_fd, "specbound.yaml", "specbound.yaml")
    except FileExistsError:
        return True
    except OSError:
        return False
    finally:
        if root_fd is not None:
            os.close(root_fd)
    return False


def _quarantine_remove_if_owned(
    parent_fd: int, leaf: str, owned: tuple[int, int]
) -> None:
    quarantine = f".{leaf}.rollback-{os.getpid()}-{os.urandom(16).hex()}"
    try:
        # Move the current occupant without deleting it, then inspect the moved
        # inode. RENAME_NOREPLACE restores any replacement type atomically and
        # never overwrites a later winner at the canonical path.
        os.rename(
            leaf,
            quarantine,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        moved = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
        moved_identity = (moved.st_dev, moved.st_ino)
        if moved_identity == owned:
            os.unlink(quarantine, dir_fd=parent_fd)
            os.fsync(parent_fd)
            return
        try:
            _rename_noreplace(parent_fd, quarantine, leaf)
        except FileExistsError:
            # A later winner occupies the canonical leaf. Preserve the earlier
            # winner under quarantine rather than deleting either actor's bytes.
            os.fsync(parent_fd)
            return
        os.fsync(parent_fd)
    except OSError:
        pass


def _remove_if_owned(root: Path, target: str, owned: tuple[int, int]) -> None:
    parent_fd, blocker = _open_parent(root, target)
    if blocker is not None or parent_fd is None:
        return
    try:
        _quarantine_remove_if_owned(parent_fd, PurePosixPath(target).name, owned)
    finally:
        os.close(parent_fd)


def _publish(
    root: Path, target: str, content: bytes
) -> tuple[_PublishedLeaf | None, IQCBlocker | None]:
    parent_fd, blocker = _open_parent(root, target)
    if blocker is not None or parent_fd is None:
        return None, blocker
    leaf = PurePosixPath(target).name
    fd: int | None = None
    owned: tuple[int, int] | None = None
    complete = False
    try:
        fd = os.open(leaf, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=parent_fd)
        stat = os.fstat(fd)
        owned = (stat.st_dev, stat.st_ino)
        _write_published_bytes(fd, content)
        _fsync_descriptor(fd)
        _fsync_descriptor(parent_fd)
        final = _final_published_bytes(fd)
        final_stat = os.fstat(fd)
        current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != owned or (final_stat.st_dev, final_stat.st_ino) != owned or final != content:
            raise OSError("final inode or digest binding changed")
        digest = sha256(final).hexdigest()
        complete = True
        return _PublishedLeaf(owned=owned, digest=digest, fd=fd), None
    except FileExistsError:
        return None, IQCBlocker("iteration_qc_already_exists", target, "canonical target already exists")
    except OSError as exc:
        return None, IQCBlocker("iteration_qc_publication_failed", target, str(exc))
    finally:
        # Keep the successfully created descriptor open through post-validation.
        # An unlinked inode cannot then be recycled into a replacement winner
        # before rollback ownership is checked.
        if owned is not None and not complete:
            _quarantine_remove_if_owned(parent_fd, leaf, owned)
        if fd is not None and not complete:
            os.close(fd)
        os.close(parent_fd)


def _post_write_validation(root: Path, target: str) -> tuple[IQCBlocker, ...]:
    try:
        from .validation import validate
        result = validate(root)
    except Exception as exc:
        return (IQCBlocker("iteration_qc_post_validation_failed", target, str(exc)),)
    if result.valid:
        return ()
    detail = "; ".join(
        f"{item.get('code')}:{item.get('path')}:{item.get('detail')}"
        for item in result.blockers
    )
    return (IQCBlocker("iteration_qc_post_validation_failed", target, detail),)


def decide_iteration_qc(
    root: Path,
    target_identity: str,
    implementation_result_path: Path,
    evaluation_result_path: Path,
    authority_identity: str,
    authority_action_id: str,
    authority_context_id: str,
) -> IterationQCDecisionResult:
    """Validate immutable evidence and exclusively create one fixed-r1 IQC record."""
    match = _TARGET_RE.fullmatch(target_identity)
    number = match.group(1) if match else "invalid"
    slice_text = match.group(2) if match else "invalid"
    target = f".specbound/iteration-qc/req-{number}/iqc-{number}-{slice_text}-r1.json"
    invalid = lambda code, path, detail: IterationQCDecisionResult((IQCBlocker(code, path, detail),), target)
    if (
        os.name != "posix"
        or not all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW"))
        or not _supports_atomic_noreplace(root)
    ):
        return invalid(
            "unsupported_platform",
            target,
            "directory-relative no-follow and atomic no-replace rename publication primitives are required",
        )
    if match is None:
        return invalid("invalid_iteration_qc_target", target_identity, "target must be exact iqc-<numeric-id>-<positive-slice>-r1")
    if not all(_normalized_nonplaceholder(value) for value in (authority_identity, authority_action_id, authority_context_id)):
        return invalid("malformed_iteration_qc_authority", target, "authority identity, action, and context must be NFC non-placeholders")
    root = Path(root).resolve()
    head, blocker = _git_contract(root, target)
    if blocker is not None or head is None:
        return IterationQCDecisionResult((blocker,) if blocker else (), target)
    family_root = root / ".specbound/iteration-qc" / f"req-{number}"
    if family_root.is_symlink() or not family_root.is_dir():
        return invalid("unsafe_iteration_qc_target", target, "canonical target parent must already exist without symlinks")
    siblings = sorted(family_root.glob(f"iqc-{number}-{slice_text}-r*.json"))
    exact_target = root / target
    for sibling in siblings:
        relative_sibling = sibling.relative_to(root).as_posix()
        if sibling == exact_target:
            return invalid(
                "iteration_qc_already_exists",
                relative_sibling,
                "canonical fixed-r1 target already exists",
            )
        try:
            sibling_record = json.loads(sibling.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return invalid(
                "invalid_existing_iteration_qc",
                relative_sibling,
                "conflicting revision is not a readable compatibility record",
            )
        if not isinstance(sibling_record, dict) or set(sibling_record) != _LEGACY_IQC_FIELDS:
            return invalid(
                "iteration_qc_already_exists",
                relative_sibling,
                "one authority-bound result per Micro-SPEC is allowed",
            )

    implementation, implementation_blob, blocker = _load_candidate(Path(implementation_result_path), "iteration-qc-implementation-result.schema.json", target)
    if blocker or implementation is None or implementation_blob is None:
        return IterationQCDecisionResult((blocker,) if blocker else (), target)
    evaluation, evaluation_blob, blocker = _load_candidate(Path(evaluation_result_path), "iteration-qc-evaluation-result.schema.json", target)
    if blocker or evaluation is None or evaluation_blob is None:
        return IterationQCDecisionResult((blocker,) if blocker else (), target)
    if implementation.get("source_commit") != head:
        return invalid("stale_iteration_qc_source_commit", str(implementation_result_path), "implementation source_commit must equal HEAD")

    requirement_id = f"req-{number}"
    micro_id = f"ms-{number}-{slice_text}"
    micro_path = f".specbound/micro-specs/{requirement_id}/{micro_id}.md"
    review_path = f".specbound/micro-spec-reviews/{requirement_id}/{micro_id}.review.json"
    try:
        micro_bytes = (root / micro_path).read_bytes()
        micro = _frontmatter(root / micro_path)
        requirement_binding = micro.get("requirement")
        if not isinstance(requirement_binding, dict):
            raise ValueError("Micro-SPEC must bind one exact parent REQ")
        requirement_revision = requirement_binding.get("revision")
        if (
            not isinstance(requirement_revision, int)
            or isinstance(requirement_revision, bool)
            or requirement_revision < 1
        ):
            raise ValueError("Micro-SPEC parent revision must be a positive integer")
        requirement_path = (
            f".specbound/requirements/{requirement_id}/"
            f"{requirement_id}-r{requirement_revision}.md"
        )
        if (
            requirement_binding.get("path") != requirement_path
            or requirement_binding.get("id") != requirement_id
        ):
            raise ValueError("Micro-SPEC parent path, ID, and revision must agree")
        approval_path = (
            f".specbound/approvals/{requirement_id}-r{requirement_revision}.approval.json"
        )
        requirement_bytes = (root / requirement_path).read_bytes()
        requirement = _frontmatter(root / requirement_path)
        approval_bytes = (root / approval_path).read_bytes()
        approval = _strict_load(approval_bytes)
        review_bytes = (root / review_path).read_bytes()
        review = _strict_load(review_bytes)
        config_bytes = (root / "specbound.yaml").read_bytes()
        config = yaml.safe_load(config_bytes.decode("utf-8"))
        parent_criteria = _parent_acceptance_criteria(root / requirement_path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, yaml.YAMLError, _DuplicateKey) as exc:
        return invalid("malformed_iteration_qc_bindings", target, str(exc))
    requirement_digest = sha256(requirement_bytes).hexdigest()
    policy = config.get("policy") if isinstance(config, dict) else None
    review_authorities = (
        policy.get("micro_spec_review_authorities_by_risk")
        if isinstance(policy, dict)
        else None
    )
    approval_authorities = (
        policy.get("requirement_approval_authorities_by_risk")
        if isinstance(policy, dict)
        else None
    )
    risk_value = requirement.get("risk")
    if (
        not isinstance(approval, dict)
        or approval_bytes != _canonical(approval)
        or not _APPROVAL_FIELDS.issubset(approval)
        or not _normalized_nonplaceholder(approval.get("authority"))
        or not isinstance(approval_authorities, dict)
        or approval.get("authority") not in approval_authorities.get(risk_value, [])
        or any(
            (
                requirement.get("id") != requirement_id,
                requirement.get("revision") != requirement_revision,
                requirement.get("status") != "approved",
                risk_value not in _POLICY,
                approval.get("requirement_path") != requirement_path,
                approval.get("requirement_id") != requirement_id,
                approval.get("revision") != requirement_revision,
                approval.get("sha256") != requirement_digest,
                approval.get("risk") != risk_value,
            )
        )
    ):
        return invalid("invalid_iteration_qc_requirement_binding", requirement_path, "approved REQ and approval must bind exact current bytes")
    micro_digest = sha256(micro_bytes).hexdigest()
    selected = micro.get("selected_acceptance_criteria")
    if (
        not isinstance(review, dict)
        or set(review) != _MICRO_SPEC_REVIEW_FIELDS
        or review.get("schema_version") != 1
        or isinstance(review.get("schema_version"), bool)
        or not isinstance(review_authorities, dict)
        or review.get("authority") not in review_authorities.get(risk_value, [])
        or not _valid_utc_timestamp(review.get("decided_at"))
        or not _normalized_nonplaceholder(review.get("reason"))
        or any(
            (
                micro.get("id") != micro_id,
                micro.get("kind") != "micro-spec",
                micro.get("requirement")
                != {
                    "path": requirement_path,
                    "id": requirement_id,
                    "revision": requirement_revision,
                    "sha256": requirement_digest,
                },
                not isinstance(selected, list),
                not selected,
                review.get("micro_spec_path") != micro_path,
                review.get("micro_spec_id") != micro_id,
                review.get("micro_spec_sha256") != micro_digest,
                review.get("requirement_path") != requirement_path,
                review.get("requirement_id") != requirement_id,
                review.get("revision") != requirement_revision,
                review.get("requirement_sha256") != requirement_digest,
                review.get("risk") != risk_value,
                review.get("decision") != "approved_for_implementation",
                review.get("permitted_next_action")
                != "implement_bound_micro_spec_only",
            )
        )
    ):
        return invalid("invalid_iteration_qc_micro_spec_review_binding", review_path, "Micro-SPEC and approved review must bind exact bytes")
    if implementation.get("micro_spec") != {"path": micro_path, "id": micro_id, "sha256": micro_digest} or implementation.get("selected_acceptance_criteria") != selected:
        return invalid("iteration_qc_implementation_binding_mismatch", str(implementation_result_path), "implementation result must bind exact Micro-SPEC and selected ACs")
    evidence = implementation.get("verification")
    covered = {entry.get("acceptance_criterion") for entry in evidence} if isinstance(evidence, list) else set()
    if covered != set(selected):
        return invalid("iteration_qc_evidence_coverage_mismatch", str(implementation_result_path), "every selected AC requires passing evidence and unknown ACs are forbidden")
    implementation_digest = sha256(implementation_blob).hexdigest()
    expected_edge = {"result_id": implementation.get("result_id"), "sha256": implementation_digest}
    if any((evaluation.get("micro_spec") != implementation.get("micro_spec"), evaluation.get("implementation_result") != expected_edge,
            evaluation.get("selected_acceptance_criteria") != selected,
            evaluation.get("verification_sha256") != sha256(_canonical(evidence)).hexdigest())):
        return invalid("iteration_qc_evaluation_binding_mismatch", str(evaluation_result_path), "evaluation must bind exact implementation result and verification bytes")
    matrix = policy.get("iteration_qc_authorities_by_risk") if isinstance(policy, dict) else None
    risk = str(risk_value)
    if matrix != _POLICY or not isinstance(matrix, dict) or list(matrix) != [
        "low",
        "medium",
        "high",
    ]:
        return invalid("malformed_iteration_qc_policy", "specbound.yaml", "current IQC authority matrix must be exact and closed")
    actor = implementation.get("actor")
    if authority_identity == actor or evaluation.get("evaluator") == actor:
        return invalid(
            "iteration_qc_self_qc",
            target,
            "implementation actor cannot be evaluator or canonical IQC authority",
        )
    if authority_identity not in _POLICY[risk]:
        return invalid("unauthorized_iteration_qc_authority", target, "authority is not allowlisted for the approved REQ risk")
    actions = [implementation.get("action_id"), evaluation.get("action_id"), authority_action_id]
    contexts = [implementation.get("context_id"), evaluation.get("context_id"), authority_context_id]
    if len(set(actions)) != 3:
        return invalid("iteration_qc_action_collision", target, "implementation, evaluation, and authority actions must be pairwise distinct")
    if len(set(contexts)) != 3:
        return invalid("iteration_qc_context_collision", target, "implementation, evaluation, and authority contexts must be pairwise distinct")

    adoption_query = check_effective_adoption(
        root, f"{requirement_id}-r{requirement_revision}", "iteration_qc"
    )
    if not adoption_query.valid or len(adoption_query.adoptions) != 1:
        detail = "; ".join(getattr(item, "code", "invalid_adoption") for item in adoption_query.blockers)
        return invalid("invalid_iteration_qc_adoption", target, detail or "one exact effective iteration_qc adoption is required")
    adoption = adoption_query.adoptions[0]
    if any((adoption.requirement_path != requirement_path, adoption.requirement_id != requirement_id,
            adoption.revision != requirement_revision,
            adoption.requirement_sha256 != requirement_digest,
            adoption.transition != "iteration_qc", adoption.risk != risk)):
        return invalid("invalid_iteration_qc_adoption", target, "effective adoption does not exactly bind the approved REQ and transition")
    try:
        adoption_bytes = (root / adoption.path).read_bytes()
    except OSError as exc:
        return invalid("invalid_iteration_qc_adoption", str(adoption.path), str(exc))
    if sha256(adoption_bytes).hexdigest() != adoption.sha256:
        return invalid("invalid_iteration_qc_adoption", str(adoption.path), "effective adoption digest differs from repository bytes")
    adoption_source_commit = getattr(adoption, "source_commit", None)
    if not isinstance(adoption_source_commit, str) or _SHA1_RE.fullmatch(
        adoption_source_commit
    ) is None:
        return invalid(
            "invalid_iteration_qc_adoption",
            str(adoption.path),
            "effective adoption must expose one exact SHA-1 source commit",
        )
    adopted_approval = _git(
        root,
        "show",
        f"{adoption_source_commit}:{approval_path}",
    )
    if (
        adopted_approval.returncode != 0
        or adopted_approval.stdout.encode("utf-8") != approval_bytes
    ):
        return invalid(
            "invalid_iteration_qc_adoption",
            approval_path,
            "current approval bytes must equal the approval bound by the effective adoption source commit",
        )

    remaining = [criterion for criterion in parent_criteria if criterion not in set(selected)]
    record = {
        "schema_version": 1,
        "requirement": {
            "path": requirement_path,
            "id": requirement_id,
            "revision": requirement_revision,
            "sha256": requirement_digest,
        },
        "adoption": {"path": adoption.path, "sha256": adoption.sha256, "transition": "iteration_qc"},
        "micro_spec": {"path": micro_path, "id": micro_id, "sha256": micro_digest},
        "micro_spec_review": {"path": review_path, "sha256": sha256(review_bytes).hexdigest()},
        "selected_acceptance_criteria": selected,
        "implementation_result": {"result_id": implementation["result_id"], "sha256": implementation_digest, "source_commit": head, "actor": actor, "action_id": implementation["action_id"], "context_id": implementation["context_id"]},
        "evaluation_result": {"result_id": evaluation["result_id"], "sha256": sha256(evaluation_blob).hexdigest(), "implementation_result_id": implementation["result_id"], "implementation_result_sha256": implementation_digest, "evaluator": evaluation["evaluator"], "action_id": evaluation["action_id"], "context_id": evaluation["context_id"]},
        "authority": {"identity": authority_identity, "authority_action_id": authority_action_id, "context_id": authority_context_id},
        "policy": {"path": "specbound.yaml", "sha256": sha256(config_bytes).hexdigest(), "selector": "iteration_qc_authorities_by_risk"},
        "verification": [{"command": item["command"], "result": "passed", "exit_code": 0} for item in evidence],
        "verdict": "verified", "remaining_acceptance_criteria": remaining,
        "decided_at": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
    }
    content = _canonical(record)
    schema_errors = tuple(Draft202012Validator(_load_schema("iteration-qc.schema.json")).iter_errors(record))
    if schema_errors:
        return invalid("malformed_iteration_qc", target, "; ".join(item.message for item in schema_errors))
    publication_head, publication_blocker = _git_contract(root, target)
    if publication_blocker is not None:
        return IterationQCDecisionResult((publication_blocker,), target)
    if publication_head != head:
        return invalid(
            "stale_iteration_qc_source_commit",
            "HEAD",
            "repository HEAD changed before publication",
        )
    published, blocker = _publish(root, target, content)
    if blocker is not None or published is None:
        return IterationQCDecisionResult((blocker,) if blocker else (IQCBlocker("iteration_qc_publication_failed", target, "missing publication identity"),), target)
    try:
        try:
            post_blockers = _post_write_validation(root, target)
        except Exception as exc:
            post_blockers = (
                IQCBlocker(
                    "iteration_qc_post_validation_failed", target, str(exc)
                ),
            )
        if post_blockers:
            _remove_if_owned(root, target, published.owned)
            return IterationQCDecisionResult(post_blockers, target)
        final_head, repository_blocker = _git_contract(root, target)
        if repository_blocker is not None:
            _remove_if_owned(root, target, published.owned)
            return IterationQCDecisionResult((repository_blocker,), target)
        if final_head != head:
            _remove_if_owned(root, target, published.owned)
            return invalid(
                "stale_iteration_qc_source_commit",
                "HEAD",
                "repository HEAD changed during publication",
            )
        # Re-check the pathname after post-validation so a handoff replacement is never reported as ours.
        try:
            final_state_before = os.stat(root / target, follow_symlinks=False)
            final_bytes = (root / target).read_bytes()
            final_state_after = os.stat(root / target, follow_symlinks=False)
        except OSError as exc:
            _remove_if_owned(root, target, published.owned)
            return invalid("iteration_qc_publication_handoff_failed", target, str(exc))
        if (
            (final_state_before.st_dev, final_state_before.st_ino)
            != published.owned
            or (final_state_after.st_dev, final_state_after.st_ino)
            != published.owned
            or sha256(final_bytes).hexdigest() != published.digest
        ):
            _remove_if_owned(root, target, published.owned)
            return invalid("iteration_qc_publication_handoff_failed", target, "published target identity changed before return")
        return IterationQCDecisionResult((), target, published.digest)
    finally:
        os.close(published.fd)
