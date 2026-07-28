"""Deterministic Git evidence freezing for control-plane adoption."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path, PurePosixPath
import re
import subprocess


_FULL_SHA1_RE = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class GitEvidenceBlocker:
    """A stable, structured reason that Git evidence could not be frozen."""

    code: str
    path: str
    detail: str


@dataclass(frozen=True)
class FrozenGitEvidence:
    """Immutable identities and blob digests read from one clean Git HEAD."""

    blockers: tuple[GitEvidenceBlocker, ...]
    object_format: str | None = None
    head_commit: str | None = None
    baseline_commit: str | None = None
    baseline_at: datetime | None = None
    requirement_first_commit: str | None = None
    approval_first_commit: str | None = None
    blob_sha256: dict[str, str] = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        return not self.blockers


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _git_text(root: Path, *args: str) -> tuple[str | None, str | None]:
    completed = _git(root, *args)
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        return None, detail or f"git {' '.join(args)} exited {completed.returncode}"
    try:
        return completed.stdout.decode("utf-8", errors="strict").strip(), None
    except UnicodeDecodeError as exc:
        return None, f"git {' '.join(args)} returned non-UTF-8 output: {exc}"


def _safe_repository_path(value: str) -> bool:
    if not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _parse_utc_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _first_introduction(root: Path, source_commit: str, path: str) -> tuple[str | None, str | None]:
    output, error = _git_text(
        root,
        "log",
        "--reverse",
        "--format=%H",
        "--diff-filter=A",
        source_commit,
        "--",
        path,
    )
    if error is not None:
        return None, error
    commits = output.splitlines() if output else []
    if not commits or not _FULL_SHA1_RE.fullmatch(commits[0]):
        return None, "path has no full SHA-1 introduction commit reachable from frozen HEAD"
    return commits[0], None


def freeze_git_evidence(
    root: Path,
    *,
    requirement_path: str,
    approval_path: str,
    baseline_commit: str,
    baseline_at: str,
    repository_source_paths: tuple[str, ...] = (),
) -> FrozenGitEvidence:
    """Freeze clean-HEAD identities and Git-tree blob digests for adoption checks.

    The checkout is used only to locate the repository. Commit identities,
    timestamps, introduction history, and bytes all come from Git objects.
    """

    root = Path(root).resolve()
    blockers: list[GitEvidenceBlocker] = []

    object_format, error = _git_text(root, "rev-parse", "--show-object-format")
    if error is not None:
        return FrozenGitEvidence(
            blockers=(GitEvidenceBlocker("not_git_repository", ".", error),)
        )
    if object_format != "sha1":
        blockers.append(
            GitEvidenceBlocker(
                "unsupported_git_object_format",
                ".git",
                "control-plane adoption V1 requires exact sha1 Git object format",
            )
        )

    shallow, error = _git_text(root, "rev-parse", "--is-shallow-repository")
    if error is not None:
        blockers.append(GitEvidenceBlocker("git_query_failed", ".git", error))
    elif shallow != "false":
        blockers.append(
            GitEvidenceBlocker(
                "shallow_repository",
                ".git",
                "complete reachable history is required to freeze introduction evidence",
            )
        )

    head_commit, error = _git_text(root, "rev-parse", "--verify", "HEAD^{commit}")
    if error is not None or head_commit is None or not _FULL_SHA1_RE.fullmatch(head_commit):
        blockers.append(
            GitEvidenceBlocker(
                "invalid_head_commit",
                "HEAD",
                error or "HEAD is not a full lowercase SHA-1 commit",
            )
        )
        head_commit = None

    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if status.returncode != 0:
        detail = status.stderr.decode("utf-8", errors="replace").strip()
        blockers.append(
            GitEvidenceBlocker("git_query_failed", ".", detail or "could not inspect worktree")
        )
    elif status.stdout:
        blockers.append(
            GitEvidenceBlocker(
                "dirty_worktree",
                ".",
                "tracked and untracked worktree changes must be absent before evidence freeze",
            )
        )

    verified_baseline: str | None = None
    if not _FULL_SHA1_RE.fullmatch(baseline_commit):
        blockers.append(
            GitEvidenceBlocker(
                "invalid_baseline_commit",
                "baseline_commit",
                "baseline must be a full lowercase 40-hex SHA-1 commit",
            )
        )
    else:
        verified_baseline, error = _git_text(
            root, "rev-parse", "--verify", f"{baseline_commit}^{{commit}}"
        )
        if error is not None or verified_baseline != baseline_commit:
            blockers.append(
                GitEvidenceBlocker(
                    "invalid_baseline_commit",
                    "baseline_commit",
                    error or "baseline did not resolve to the exact requested commit",
                )
            )
            verified_baseline = None

    derived_baseline_at: datetime | None = None
    if verified_baseline is not None:
        timestamp, error = _git_text(root, "show", "-s", "--format=%cI", verified_baseline)
        if error is not None or timestamp is None:
            blockers.append(
                GitEvidenceBlocker(
                    "git_query_failed", "baseline_commit", error or "missing committer timestamp"
                )
            )
        else:
            try:
                derived_baseline_at = _parse_utc_timestamp(timestamp)
                requested_baseline_at = _parse_utc_timestamp(baseline_at)
            except ValueError as exc:
                blockers.append(
                    GitEvidenceBlocker("invalid_baseline_timestamp", "baseline_at", str(exc))
                )
            else:
                if requested_baseline_at != derived_baseline_at:
                    blockers.append(
                        GitEvidenceBlocker(
                            "baseline_timestamp_mismatch",
                            "baseline_at",
                            "caller timestamp differs from the baseline commit committer timestamp",
                        )
                    )

    if head_commit is not None and verified_baseline is not None:
        ancestry = _git(root, "merge-base", "--is-ancestor", verified_baseline, head_commit)
        if ancestry.returncode == 1:
            blockers.append(
                GitEvidenceBlocker(
                    "baseline_not_ancestor",
                    "baseline_commit",
                    "baseline commit is not an ancestor of frozen HEAD",
                )
            )
        elif ancestry.returncode != 0:
            detail = ancestry.stderr.decode("utf-8", errors="replace").strip()
            blockers.append(
                GitEvidenceBlocker(
                    "git_query_failed",
                    "baseline_commit",
                    detail or "could not verify baseline ancestry",
                )
            )

    paths = (requirement_path, approval_path, *repository_source_paths)
    seen: set[str] = set()
    for path in paths:
        if not _safe_repository_path(path):
            blockers.append(
                GitEvidenceBlocker(
                    "unsafe_repository_path",
                    path,
                    "path must use canonical safe repository-relative POSIX spelling",
                )
            )
        elif path in seen:
            blockers.append(
                GitEvidenceBlocker(
                    "duplicate_repository_path", path, "evidence paths must be unique"
                )
            )
        seen.add(path)

    blob_sha256: dict[str, str] = {}
    if head_commit is not None:
        for path in paths:
            if not _safe_repository_path(path) or path in blob_sha256:
                continue
            blob = _git(root, "show", f"{head_commit}:{path}")
            if blob.returncode != 0:
                detail = blob.stderr.decode("utf-8", errors="replace").strip()
                blockers.append(
                    GitEvidenceBlocker(
                        "missing_repository_blob",
                        path,
                        detail or "path is absent from frozen HEAD tree",
                    )
                )
                continue
            blob_sha256[path] = sha256(blob.stdout).hexdigest()

    requirement_first_commit: str | None = None
    approval_first_commit: str | None = None
    if head_commit is not None and _safe_repository_path(requirement_path):
        requirement_first_commit, error = _first_introduction(
            root, head_commit, requirement_path
        )
        if error is not None:
            blockers.append(
                GitEvidenceBlocker("missing_introduction_commit", requirement_path, error)
            )
    if head_commit is not None and _safe_repository_path(approval_path):
        approval_first_commit, error = _first_introduction(root, head_commit, approval_path)
        if error is not None:
            blockers.append(
                GitEvidenceBlocker("missing_introduction_commit", approval_path, error)
            )

    return FrozenGitEvidence(
        blockers=tuple(blockers),
        object_format=object_format,
        head_commit=head_commit,
        baseline_commit=verified_baseline,
        baseline_at=derived_baseline_at,
        requirement_first_commit=requirement_first_commit,
        approval_first_commit=approval_first_commit,
        blob_sha256=blob_sha256,
    )
