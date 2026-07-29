from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess

from jsonschema import Draft202012Validator, ValidationError
import pytest
import yaml

from specbound import validation


ROOT = Path(__file__).resolve().parents[1]
TOPOLOGY_CONFIGS = (
    ROOT / "specbound.yaml",
    ROOT / "templates/specbound.yaml",
    ROOT / "fixtures/valid-minimal/specbound.yaml",
    ROOT / "fixtures/invalid-unsafe-path/specbound.yaml",
)
ALIAS_CONFIGS = TOPOLOGY_CONFIGS + (ROOT / "fixtures/agent-contract/specbound.yaml",)

EXPECTED_CONTROL_PLANE_TOPOLOGY = {
    "adoptions_root": ".specbound/adoptions",
    "canary_outcomes_root": ".specbound/canary-outcomes",
    "activations_root": ".specbound/activations",
}
EXPECTED_CONTROL_PLANE_PATTERNS = {
    "adoption_pattern": "req-<id>/adp-<id>-r<revision>-<transition>.json",
    "canary_outcome_pattern": "req-<id>/cny-<id>-r<revision>-<transition>-a<sequence>.json",
    "activation_pattern": "req-<id>/act-<id>-r<revision>-<transition>.json",
}
EXPECTED_ALIAS = {"inherit": "discovery_confirmation_authorities_by_risk"}


def _schema(name: str) -> dict:
    root_path = ROOT / "schemas" / name
    packaged_path = ROOT / "src/specbound/schemas" / name
    assert root_path.read_bytes() == packaged_path.read_bytes()
    schema = json.loads(root_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return schema


def _git_bytes(root: Path, *args: str, env: dict[str, str] | None = None) -> bytes:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout


def _git(root: Path, *args: str, env: dict[str, str] | None = None) -> str:
    return _git_bytes(root, *args, env=env).decode("utf-8", errors="strict").strip()


def _git_env(when: str) -> dict[str, str]:
    return dict(
        os.environ,
        GIT_AUTHOR_NAME="SpecBound Test",
        GIT_AUTHOR_EMAIL="specbound@example.invalid",
        GIT_COMMITTER_NAME="SpecBound Test",
        GIT_COMMITTER_EMAIL="specbound@example.invalid",
        GIT_AUTHOR_DATE=when,
        GIT_COMMITTER_DATE=when,
    )


def _init_git_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "--quiet", "--object-format=sha1")
    _git(root, "config", "core.autocrlf", "false")
    return root


def _commit_minimal_adoption_inputs(
    root: Path,
    *,
    introduced_at: str = "2026-07-01T00:00:00+00:00",
) -> tuple[Path, Path, str, str]:
    requirement = Path(".specbound/requirements/req-0042/req-0042-r1.md")
    approval = Path(".specbound/approvals/req-0042-r1.approval.json")
    for relative, content in (
        (requirement, "---\nid: req-0042\nrevision: 1\nstatus: approved\n---\n"),
        (
            approval,
            '{"schema_version":1,"requirement_id":"req-0042",'
            '"revision":1,"approved_at":"2026-07-01T00:00:01+00:00"}\n',
        ),
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    _git(root, "add", "--", requirement.as_posix(), approval.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "introduce exact adoption inputs",
        env=_git_env(introduced_at),
    )
    return requirement, approval, _git(root, "rev-parse", "HEAD"), introduced_at


def _config(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_control_plane_topology_and_aliases_are_declared_without_manual_registry() -> None:
    for key, value in EXPECTED_CONTROL_PLANE_TOPOLOGY.items():
        assert validation.REQUIRED_ROOTS[key] == value

    for name, value in EXPECTED_CONTROL_PLANE_PATTERNS.items():
        assert getattr(validation, name.upper()) == value

    for path in TOPOLOGY_CONFIGS:
        config = _config(path)
        canonical = config["canonical"]
        for key, value in EXPECTED_CONTROL_PLANE_TOPOLOGY.items():
            assert canonical[key] == value, path
        for key, value in EXPECTED_CONTROL_PLANE_PATTERNS.items():
            assert canonical[key] == value, path

    for path in ALIAS_CONFIGS:
        policy = _config(path)["policy"]
        assert policy["control_plane_adoption_authorities_by_risk"] == EXPECTED_ALIAS, path
        assert policy["control_plane_activation_authorities_by_risk"] == EXPECTED_ALIAS, path
        assert "control_plane_adoption" not in policy, path


def test_preflight_accepts_only_exact_inherit_aliases_and_empty_legacy_shape(tmp_path: Path) -> None:
    base = _config(ROOT / "templates/specbound.yaml")

    def run(config: dict) -> validation.Result:
        root = tmp_path / str(len(list(tmp_path.iterdir())))
        root.mkdir()
        (root / "specbound.yaml").write_text(
            yaml.safe_dump(config, sort_keys=False), encoding="utf-8", newline="\n"
        )
        return validation.preflight(root)

    assert run(base).valid

    legacy = deepcopy(base)
    legacy["policy"]["control_plane_adoption"] = {"schema_version": 1, "requirements": []}
    assert run(legacy).valid

    for key in (
        "control_plane_adoption_authorities_by_risk",
        "control_plane_activation_authorities_by_risk",
    ):
        missing = deepcopy(base)
        del missing["policy"][key]
        assert {item["code"] for item in run(missing).blockers} == {"malformed_config"}

        widened = deepcopy(base)
        widened["policy"][key] = {
            "inherit": "discovery_confirmation_authorities_by_risk",
            "fallback": ["fixture-maintainer"],
        }
        assert {item["code"] for item in run(widened).blockers} == {"malformed_config"}

        explicit = deepcopy(base)
        explicit["policy"][key] = {"low": ["repository-maintainer"]}
        assert {item["code"] for item in run(explicit).blockers} == {"malformed_config"}

    nonempty = deepcopy(base)
    nonempty["policy"]["control_plane_adoption"] = {
        "schema_version": 1,
        "requirements": [
            {
                "path": ".specbound/requirements/req-1/req-1-r1.md",
                "id": "req-1",
                "revision": 1,
                "sha256": "0" * 64,
            }
        ],
    }
    assert {item["code"] for item in run(nonempty).blockers} == {"malformed_config"}

    extra = deepcopy(base)
    extra["policy"]["control_plane_adoption"] = {
        "schema_version": 1,
        "requirements": [],
        "generated": True,
    }
    assert {item["code"] for item in run(extra).blockers} == {"malformed_config"}


def test_adoption_schema_is_closed_and_binds_exact_canary_authority() -> None:
    schema = _schema("adoption-decision.schema.json")
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        "schema_version",
        "adoption_id",
        "requirement",
        "scope_mode",
        "transition",
        "risk",
        "authority",
        "authority_action_id",
        "context_id",
        "decision",
        "reason",
        "decided_at",
        "permitted_next_action",
        "adoption_source_commit",
        "canary_capability_baseline_commit",
        "canary_capability_baseline_at",
        "canary_work_state",
        "canary_work_attested_by",
        "canary_work_attested_at",
        "canary_work_source_refs",
        "authority_policy",
    }
    properties = schema["properties"]
    assert properties["scope_mode"] == {"const": "exact_canary"}
    assert properties["transition"]["enum"] == ["iteration_qc", "delivery_qc"]
    assert properties["decision"] == {"const": "adopted_for_exact_canary"}
    assert properties["permitted_next_action"] == {
        "const": "approve_bootstrap_exception_for_exact_canary"
    }
    assert properties["canary_work_state"] == {"const": "not_started"}
    assert properties["reason"]["minLength"] >= 1


def test_canary_outcome_schema_is_closed_and_non_authorizing() -> None:
    schema = _schema("canary-outcome.schema.json")
    assert schema["additionalProperties"] is False
    properties = schema["properties"]
    required = set(schema["required"])
    assert properties["scope_mode"] == {"const": "exact_canary"}
    assert properties["transition"]["enum"] == ["iteration_qc", "delivery_qc"]
    assert properties["outcome"]["enum"] == ["passed", "failed"]
    assert properties["attempt_sequence"]["minimum"] == 1
    assert {"authority", "authority_action_id", "context_id", "bootstrap_exception"} <= required
    assert "pre_close_commit" in properties["bootstrap_exception"]["required"]
    assert {"reason", "decision", "permitted_next_action", "passed_outcome_commit"}.isdisjoint(
        properties
    )


def test_activation_schema_is_closed_and_prospective_only() -> None:
    schema = _schema("activation-decision.schema.json")
    assert schema["additionalProperties"] is False
    properties = schema["properties"]
    required = set(schema["required"])
    assert properties["scope_mode"] == {"const": "prospective_after_baseline"}
    assert properties["transition"]["enum"] == ["iteration_qc", "delivery_qc"]
    assert properties["decision"] == {"const": "activated_for_prospective_scope"}
    assert {
        "adoption",
        "canary_outcome",
        "passed_outcome_commit",
        "prospective_baseline_commit",
        "prospective_baseline_at",
        "authority",
        "authority_action_id",
        "context_id",
        "authority_policy",
    } <= required
    assert {"reason", "permitted_next_action"}.isdisjoint(properties)


def test_control_plane_canonical_roots_have_tracked_placeholders() -> None:
    roots = (
        ROOT,
        ROOT / "fixtures/valid-minimal",
        ROOT / "fixtures/agent-contract",
        ROOT / "fixtures/invalid-unsafe-path",
    )
    for root in roots:
        for relative in (
            ".specbound/adoptions/.gitkeep",
            ".specbound/canary-outcomes/.gitkeep",
            ".specbound/activations/.gitkeep",
        ):
            marker = root / relative
            assert marker.is_file(), marker
            assert marker.read_bytes() == b""


@pytest.mark.parametrize(
    ("schema_name", "template_name"),
    (
        ("adoption-decision.schema.json", "adoption-decision.json"),
        ("canary-outcome.schema.json", "canary-outcome.json"),
        ("activation-decision.schema.json", "activation-decision.json"),
    ),
)
def test_record_templates_are_canonical_closed_schema_instances(
    schema_name: str, template_name: str
) -> None:
    schema = _schema(schema_name)
    path = ROOT / "templates" / template_name
    record = json.loads(path.read_text(encoding="utf-8"))
    canonical = (
        json.dumps(record, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    assert path.read_bytes() == canonical
    Draft202012Validator(schema).validate(record)

    widened = deepcopy(record)
    widened["unexpected"] = True
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(widened)


def test_root_validate_does_not_require_the_removed_manual_registry() -> None:
    result = validation.validate(ROOT)
    assert result.valid, result.blockers


def test_freeze_git_evidence_binds_sha1_history_blobs_and_clean_head(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    requirement = Path(".specbound/requirements/req-0042/req-0042-r1.md")
    approval = Path(".specbound/approvals/req-0042-r1.approval.json")
    source = Path("evidence/source.txt")
    for relative, content in (
        (requirement, "---\nid: req-0042\nrevision: 1\nstatus: approved\n---\n"),
        (
            approval,
            '{"schema_version":1,"requirement_id":"req-0042",'
            '"revision":1,"approved_at":"2026-07-01T00:00:00+00:00"}\n',
        ),
        (source, "immutable source\n"),
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    _git(root, "add", "--", requirement.as_posix(), approval.as_posix(), source.as_posix())
    _git(root, "commit", "--quiet", "-m", "introduce exact adoption inputs", env=_git_env("2026-07-01T00:00:00+00:00"))
    head = _git(root, "rev-parse", "HEAD")

    module_path = ROOT / "src/specbound/control_plane_adoption.py"
    assert module_path.is_file(), "Git evidence adapter is not implemented"
    module = importlib.import_module("specbound.control_plane_adoption")
    result = module.freeze_git_evidence(
        root,
        requirement_path=requirement.as_posix(),
        approval_path=approval.as_posix(),
        baseline_commit=head,
        baseline_at="2026-07-01T00:00:00+00:00",
        repository_source_paths=(source.as_posix(),),
    )

    assert result.blockers == ()
    assert result.object_format == "sha1"
    assert result.head_commit == head
    assert result.baseline_commit == head
    assert result.baseline_at == datetime(2026, 7, 1, tzinfo=timezone.utc)
    assert result.requirement_first_commit == head
    assert result.approval_first_commit == head
    for relative in (requirement, approval, source):
        frozen_blob = _git_bytes(root, "show", f"{head}:{relative.as_posix()}")
        assert result.blob_sha256[relative.as_posix()] == hashlib.sha256(
            frozen_blob
        ).hexdigest()


def test_freeze_git_evidence_rejects_tracked_worktree_changes_independently(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    requirement, approval, head, baseline_at = _commit_minimal_adoption_inputs(root)
    (root / requirement).write_text("changed\n", encoding="utf-8", newline="\n")

    module = importlib.import_module("specbound.control_plane_adoption")
    result = module.freeze_git_evidence(
        root,
        requirement_path=requirement.as_posix(),
        approval_path=approval.as_posix(),
        baseline_commit=head,
        baseline_at=baseline_at,
    )

    assert {blocker.code for blocker in result.blockers} == {"dirty_tracked_worktree"}


def test_freeze_git_evidence_rejects_untracked_worktree_changes_independently(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    requirement, approval, head, baseline_at = _commit_minimal_adoption_inputs(root)
    (root / "untracked.txt").write_text("not frozen\n", encoding="utf-8", newline="\n")

    module = importlib.import_module("specbound.control_plane_adoption")
    result = module.freeze_git_evidence(
        root,
        requirement_path=requirement.as_posix(),
        approval_path=approval.as_posix(),
        baseline_commit=head,
        baseline_at=baseline_at,
    )

    assert {blocker.code for blocker in result.blockers} == {"untracked_worktree"}


def test_freeze_git_evidence_reports_tracked_and_untracked_changes_independently(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    requirement, approval, head, baseline_at = _commit_minimal_adoption_inputs(root)
    (root / requirement).write_text("changed\n", encoding="utf-8", newline="\n")
    (root / "untracked.txt").write_text("not frozen\n", encoding="utf-8", newline="\n")

    module = importlib.import_module("specbound.control_plane_adoption")
    result = module.freeze_git_evidence(
        root,
        requirement_path=requirement.as_posix(),
        approval_path=approval.as_posix(),
        baseline_commit=head,
        baseline_at=baseline_at,
    )

    assert {blocker.code for blocker in result.blockers} == {
        "dirty_tracked_worktree",
        "untracked_worktree",
    }


def test_freeze_git_evidence_reports_only_unsupported_git_object_format(
    tmp_path: Path,
) -> None:
    root = tmp_path / "sha256-repo"
    root.mkdir()
    initialized = subprocess.run(
        ["git", "init", "--quiet", "--object-format=sha256"],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if initialized.returncode != 0:
        pytest.skip("installed Git does not support SHA-256 repositories")
    _git(root, "config", "core.autocrlf", "false")
    requirement, approval, head, baseline_at = _commit_minimal_adoption_inputs(root)

    module = importlib.import_module("specbound.control_plane_adoption")
    result = module.freeze_git_evidence(
        root,
        requirement_path=requirement.as_posix(),
        approval_path=approval.as_posix(),
        baseline_commit=head,
        baseline_at=baseline_at,
    )

    assert {blocker.code for blocker in result.blockers} == {
        "unsupported_git_object_format"
    }


def test_freeze_git_evidence_normalizes_non_utc_git_committer_timestamp(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    requirement, approval, head, _ = _commit_minimal_adoption_inputs(
        root, introduced_at="2026-07-01T09:00:00+09:00"
    )

    module = importlib.import_module("specbound.control_plane_adoption")
    result = module.freeze_git_evidence(
        root,
        requirement_path=requirement.as_posix(),
        approval_path=approval.as_posix(),
        baseline_commit=head,
        baseline_at="2026-07-01T00:00:00+00:00",
    )

    assert result.blockers == ()
    assert result.baseline_at == datetime(2026, 7, 1, tzinfo=timezone.utc)


def test_freeze_git_evidence_rejects_non_utc_baseline_timestamp(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    requirement, approval, head, _ = _commit_minimal_adoption_inputs(root)

    module = importlib.import_module("specbound.control_plane_adoption")
    result = module.freeze_git_evidence(
        root,
        requirement_path=requirement.as_posix(),
        approval_path=approval.as_posix(),
        baseline_commit=head,
        baseline_at="2026-07-01T09:00:00+09:00",
    )

    assert {blocker.code for blocker in result.blockers} == {
        "invalid_baseline_timestamp"
    }


def test_freeze_git_evidence_rejects_non_rfc3339_baseline_timestamp(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    requirement, approval, head, _ = _commit_minimal_adoption_inputs(root)

    module = importlib.import_module("specbound.control_plane_adoption")
    result = module.freeze_git_evidence(
        root,
        requirement_path=requirement.as_posix(),
        approval_path=approval.as_posix(),
        baseline_commit=head,
        baseline_at="2026-07-01 00:00:00+00:00",
    )

    assert {blocker.code for blocker in result.blockers} == {
        "invalid_baseline_timestamp"
    }


def test_resolve_adoption_eligibility_accepts_inputs_introduced_after_baseline(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, source, _ = _commit_minimal_adoption_inputs(
        root, introduced_at="2026-07-01T00:00:00+00:00"
    )

    module = importlib.import_module("specbound.control_plane_adoption")
    evidence = module.freeze_git_evidence(
        root,
        requirement_path=requirement.as_posix(),
        approval_path=approval.as_posix(),
        baseline_commit=baseline,
        baseline_at=baseline_at,
    )
    assert evidence.head_commit == source

    result = module.resolve_adoption_eligibility(
        root,
        evidence=evidence,
        approved_at="2026-07-01T00:00:01+00:00",
    )

    assert result.eligible
    assert result.blockers == ()


def test_resolve_adoption_eligibility_rejects_requirement_in_baseline_history(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    requirement = Path(".specbound/requirements/req-0042/req-0042-r1.md")
    historical = root / requirement
    historical.parent.mkdir(parents=True)
    historical.write_text("historical candidate\n", encoding="utf-8", newline="\n")
    _git(root, "add", "--", requirement.as_posix())
    _git(root, "commit", "--quiet", "-m", "historical candidate", env=_git_env("2026-05-01T00:00:00+00:00"))
    historical.unlink()
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--all")
    baseline_at = "2026-06-01T00:00:00+00:00"
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(
        root, introduced_at="2026-07-01T00:00:00+00:00"
    )

    module = importlib.import_module("specbound.control_plane_adoption")
    evidence = module.freeze_git_evidence(
        root,
        requirement_path=requirement.as_posix(),
        approval_path=approval.as_posix(),
        baseline_commit=baseline,
        baseline_at=baseline_at,
    )
    result = module.resolve_adoption_eligibility(
        root,
        evidence=evidence,
        approved_at="2026-07-01T00:00:01+00:00",
    )

    assert {blocker.code for blocker in result.blockers} == {
        "requirement_existed_at_or_before_baseline"
    }


def test_resolve_adoption_eligibility_rejects_approval_in_baseline_history(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    approval = Path(".specbound/approvals/req-0042-r1.approval.json")
    historical = root / approval
    historical.parent.mkdir(parents=True)
    historical.write_text("{}\n", encoding="utf-8", newline="\n")
    _git(root, "add", "--", approval.as_posix())
    _git(root, "commit", "--quiet", "-m", "historical approval", env=_git_env("2026-05-01T00:00:00+00:00"))
    historical.unlink()
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--all")
    baseline_at = "2026-06-01T00:00:00+00:00"
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(
        root, introduced_at="2026-07-01T00:00:00+00:00"
    )

    module = importlib.import_module("specbound.control_plane_adoption")
    evidence = module.freeze_git_evidence(
        root,
        requirement_path=requirement.as_posix(),
        approval_path=approval.as_posix(),
        baseline_commit=baseline,
        baseline_at=baseline_at,
    )
    result = module.resolve_adoption_eligibility(
        root,
        evidence=evidence,
        approved_at="2026-07-01T00:00:01+00:00",
    )

    assert {blocker.code for blocker in result.blockers} == {
        "approval_existed_at_or_before_baseline"
    }


@pytest.mark.parametrize(
    ("historical_family", "expected_blocker"),
    (
        ("requirement", "requirement_existed_at_or_before_baseline"),
        ("approval", "approval_existed_at_or_before_baseline"),
    ),
)
def test_resolve_adoption_eligibility_rejects_side_branch_history_merged_into_baseline(
    tmp_path: Path,
    historical_family: str,
    expected_blocker: str,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "baseline parent", env=_git_env("2026-05-01T00:00:00+00:00"))
    _git(root, "checkout", "--quiet", "-b", "historical-side-branch")

    historical_paths = {
        "requirement": Path(".specbound/requirements/req-0042/req-0042-r1.md"),
        "approval": Path(".specbound/approvals/req-0042-r1.approval.json"),
    }
    historical = historical_paths[historical_family]
    historical_file = root / historical
    historical_file.parent.mkdir(parents=True, exist_ok=True)
    historical_file.write_bytes(b"historical exact candidate\n")
    _git(root, "add", "--", historical.as_posix())
    _git(root, "commit", "--quiet", "-m", "add historical exact candidate", env=_git_env("2026-05-02T00:00:00+00:00"))
    historical_file.unlink()
    _git(root, "add", "--all")
    _git(root, "commit", "--quiet", "-m", "delete historical exact candidate", env=_git_env("2026-05-03T00:00:00+00:00"))

    _git(root, "checkout", "--quiet", "master")
    (root / "baseline.txt").write_bytes(b"capability baseline\n")
    _git(root, "add", "--", "baseline.txt")
    _git(root, "commit", "--quiet", "-m", "baseline mainline", env=_git_env("2026-05-04T00:00:00+00:00"))
    _git(
        root,
        "merge",
        "--quiet",
        "--no-ff",
        "historical-side-branch",
        "-m",
        "capability baseline merge",
        env=_git_env(baseline_at),
    )
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(
        root, introduced_at="2026-07-01T00:00:00+00:00"
    )

    module = importlib.import_module("specbound.control_plane_adoption")
    evidence = module.freeze_git_evidence(
        root,
        requirement_path=requirement.as_posix(),
        approval_path=approval.as_posix(),
        baseline_commit=baseline,
        baseline_at=baseline_at,
    )
    result = module.resolve_adoption_eligibility(
        root,
        evidence=evidence,
        approved_at="2026-07-01T00:00:01+00:00",
    )

    assert {blocker.code for blocker in result.blockers} == {expected_blocker}


def test_resolve_adoption_eligibility_requires_approval_after_baseline(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(
        root, introduced_at="2026-07-01T00:00:00+00:00"
    )

    module = importlib.import_module("specbound.control_plane_adoption")
    evidence = module.freeze_git_evidence(
        root,
        requirement_path=requirement.as_posix(),
        approval_path=approval.as_posix(),
        baseline_commit=baseline,
        baseline_at=baseline_at,
    )
    result = module.resolve_adoption_eligibility(
        root,
        evidence=evidence,
        approved_at=baseline_at,
    )

    assert {blocker.code for blocker in result.blockers} == {
        "approval_not_after_baseline"
    }


def test_resolve_adoption_eligibility_rejects_non_utc_approved_at(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)

    module = importlib.import_module("specbound.control_plane_adoption")
    evidence = module.freeze_git_evidence(
        root,
        requirement_path=requirement.as_posix(),
        approval_path=approval.as_posix(),
        baseline_commit=baseline,
        baseline_at=baseline_at,
    )
    result = module.resolve_adoption_eligibility(
        root,
        evidence=evidence,
        approved_at="2026-07-01T09:00:01+09:00",
    )

    assert {blocker.code for blocker in result.blockers} == {"invalid_approved_at"}


def test_resolve_adoption_eligibility_requires_introductions_after_baseline(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(
        root, introduced_at=baseline_at
    )

    module = importlib.import_module("specbound.control_plane_adoption")
    evidence = module.freeze_git_evidence(
        root,
        requirement_path=requirement.as_posix(),
        approval_path=approval.as_posix(),
        baseline_commit=baseline,
        baseline_at=baseline_at,
    )
    result = module.resolve_adoption_eligibility(
        root,
        evidence=evidence,
        approved_at="2026-07-01T00:00:01+00:00",
    )

    assert {blocker.code for blocker in result.blockers} == {
        "requirement_introduction_not_after_baseline",
        "approval_introduction_not_after_baseline",
    }
