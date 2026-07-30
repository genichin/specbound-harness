from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import shutil
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


@pytest.mark.skipif(os.name == "posix", reason="unsupported-platform contract requires a non-POSIX host")
def test_adoption_decide_refuses_unsupported_platform_before_mutation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = _init_git_repo(tmp_path)
    (root / "specbound.yaml").write_bytes((ROOT / "specbound.yaml").read_bytes())
    adoption_root = root / ".specbound/adoptions/req-0042"
    adoption_root.mkdir(parents=True)
    cli = importlib.import_module("specbound.cli")

    exit_code = cli.main(
        [
            "--root",
            str(root),
            "adoption",
            "decide",
            "req-0042-r1",
            "--transition",
            "iteration_qc",
            "--authority",
            "repository-maintainer",
            "--authority-action-id",
            "act-ref-adoption-0042-r1",
            "--context-id",
            "ctx-adoption-0042-r1",
            "--capability-baseline-commit",
            "0" * 40,
            "--reason",
            "Exercise the exact prospective IQC adoption boundary.",
            "--source-ref-json",
            '{"kind":"external","id":"ticket:42","digest":"sha256:42"}',
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["blockers"][0]["code"] == "unsupported_platform"
    assert not list(adoption_root.iterdir())


@pytest.mark.skipif(
    os.name != "posix" or not all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW")),
    reason="safe publication primitives are unavailable",
)
def test_adoption_decide_publishes_one_derived_canonical_record_in_copied_git(
    tmp_path: Path,
) -> None:
    source_parent = tmp_path / "source"
    source_parent.mkdir()
    source = _init_git_repo(source_parent)
    config_bytes = (ROOT / "specbound.yaml").read_bytes()
    (source / "specbound.yaml").write_bytes(config_bytes)
    source_ref = Path("docs/evidence/canary-source.txt")
    (source / source_ref).parent.mkdir(parents=True)
    source_bytes = b"exact canary source\n"
    (source / source_ref).write_bytes(source_bytes)
    _git(source, "add", "--", "specbound.yaml", source_ref.as_posix())
    _git(source, "commit", "--quiet", "-m", "baseline", env=_git_env("2026-06-30T00:00:00+00:00"))
    baseline = _git(source, "rev-parse", "HEAD")

    requirement = Path(".specbound/requirements/req-0042/req-0042-r1.md")
    requirement_bytes = b"---\nid: req-0042\nrevision: 1\nrisk: high\nstatus: approved\n---\n"
    (source / requirement).parent.mkdir(parents=True)
    (source / requirement).write_bytes(requirement_bytes)
    approval = Path(".specbound/approvals/req-0042-r1.approval.json")
    _write_canonical_json(source, approval, {
        "approved_at": "2026-07-01T00:00:00+00:00",
        "authority": "repository-maintainer",
        "requirement_id": "req-0042",
        "requirement_path": requirement.as_posix(),
        "revision": 1,
        "risk": "high",
        "schema_version": 1,
        "sha256": hashlib.sha256(requirement_bytes).hexdigest(),
    })
    _git(source, "add", "--", requirement.as_posix(), approval.as_posix())
    _git(source, "commit", "--quiet", "-m", "approve", env=_git_env("2026-07-01T00:00:00+00:00"))
    source_commit = _git(source, "rev-parse", "HEAD")

    copied = tmp_path / "copied-git"
    shutil.copytree(source, copied)
    target = Path(".specbound/adoptions/req-0042/adp-0042-r1-iteration_qc.json")
    (copied / target.parent).mkdir(parents=True)
    module = importlib.import_module("specbound.control_plane_adoption")
    assert not ({"output_path", "decided_at", "source_commit", "attester", "policy_selector"} & set(inspect.signature(module.decide_adoption).parameters))

    result = module.decide_adoption(
        copied,
        "req-0042-r1",
        "iteration_qc",
        "repository-maintainer",
        "act-ref-adoption-0042-r1",
        "ctx-adoption-0042-r1",
        baseline,
        "Exercise the exact prospective IQC adoption boundary.",
        (
            json.dumps({"kind": "external", "id": "urn:ticket:42", "digest_algorithm": "sha256", "digest": "2" * 64}),
            json.dumps({"kind": "repository", "path": source_ref.as_posix()}),
        ),
    )

    assert result.valid
    assert [path.relative_to(copied).as_posix() for path in (copied / ".specbound/adoptions").rglob("*.json")] == [target.as_posix()]
    payload = (copied / target).read_bytes()
    record = json.loads(payload)
    assert payload == (json.dumps(record, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
    Draft202012Validator(_schema("adoption-decision.schema.json")).validate(record)
    assert record["adoption_source_commit"] == source_commit
    assert record["decided_at"] == "2026-07-01T00:00:00+00:00"
    assert record["canary_work_attested_at"] == record["decided_at"]
    assert record["canary_work_attested_by"] == "repository-maintainer"
    assert record["authority_policy"] == {
        "path": "specbound.yaml",
        "selector": "control_plane_adoption_authorities_by_risk",
        "sha256": hashlib.sha256(config_bytes).hexdigest(),
    }
    assert record["canary_work_source_refs"] == [
        {"digest": "2" * 64, "digest_algorithm": "sha256", "id": "urn:ticket:42", "kind": "external"},
        {"kind": "repository", "path": source_ref.as_posix(), "sha256": hashlib.sha256(source_bytes).hexdigest()},
    ]
    state, blockers = module.resolve_adoption_read_state(copied, target.as_posix())
    assert blockers == ()
    assert state is not None and state.path == target.as_posix()


@pytest.mark.skipif(
    os.name != "posix" or not all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW")),
    reason="safe publication primitives are unavailable",
)
def test_adoption_publication_file_fsync_failure_removes_owned_leaf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = ".specbound/adoptions/req-0042/adp-0042-r1-iteration_qc.json"
    (tmp_path / ".specbound/adoptions/req-0042").mkdir(parents=True)
    module = importlib.import_module("specbound.control_plane_adoption")

    def fail_fsync(_: int) -> None:
        raise OSError("injected file fsync failure")

    monkeypatch.setattr(module.os, "fsync", fail_fsync)
    blocker = module._publish_adoption_leaf(tmp_path, target, b"{}\n")

    assert blocker is not None
    assert blocker.code == "adoption_publication_failed"
    assert not (tmp_path / target).exists()


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


def _write_canonical_json(root: Path, relative: Path, record: dict) -> bytes:
    payload = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode()
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return payload


@pytest.mark.parametrize(
    ("template_name", "relative"),
    (
        (
            "adoption-decision.json",
            ".specbound/adoptions/req-0042/adp-0042-r1-iteration_qc.json",
        ),
        (
            "canary-outcome.json",
            ".specbound/canary-outcomes/req-0042/"
            "cny-0042-r1-iteration_qc-a1.json",
        ),
        (
            "activation-decision.json",
            ".specbound/activations/req-0042/act-0042-r1-iteration_qc.json",
        ),
    ),
)
def test_control_plane_record_loader_accepts_exact_canonical_family_bytes(
    tmp_path: Path,
    template_name: str,
    relative: str,
) -> None:
    root = tmp_path / "repo"
    target = root / relative
    target.parent.mkdir(parents=True)
    payload = (ROOT / "templates" / template_name).read_bytes()
    target.write_bytes(payload)
    module = importlib.import_module("specbound.control_plane_adoption")

    loaded, blockers = module._load_control_plane_record(root, relative)

    assert blockers == ()
    assert loaded is not None
    assert loaded.path == relative
    assert loaded.sha256 == hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize(
    ("label", "mutate"),
    (
        ("bom", lambda payload: b"\xef\xbb\xbf" + payload),
        ("crlf", lambda payload: payload.replace(b"\n", b"\r\n")),
        ("compact", lambda payload: json.dumps(json.loads(payload)).encode() + b"\n"),
        ("missing-final-lf", lambda payload: payload.rstrip(b"\n")),
        ("extra-final-lf", lambda payload: payload + b"\n"),
        (
            "duplicate-key",
            lambda payload: payload.replace(
                b'{\n  "adoption_id"',
                b'{\n  "schema_version": 1,\n  "adoption_id"',
                1,
            ),
        ),
    ),
)
def test_control_plane_record_loader_rejects_noncanonical_adoption_bytes(
    tmp_path: Path,
    label: str,
    mutate,
) -> None:
    del label
    root = tmp_path / "repo"
    relative = ".specbound/adoptions/req-0042/adp-0042-r1-iteration_qc.json"
    target = root / relative
    target.parent.mkdir(parents=True)
    payload = (ROOT / "templates/adoption-decision.json").read_bytes()
    target.write_bytes(mutate(payload))
    module = importlib.import_module("specbound.control_plane_adoption")

    loaded, blockers = module._load_control_plane_record(root, relative)

    assert loaded is None
    assert [(blocker.code, blocker.path) for blocker in blockers] == [
        ("malformed_control_plane_record", relative)
    ]


@pytest.mark.parametrize(
    ("template_name", "relative"),
    (
        (
            "adoption-decision.json",
            ".specbound/adoptions/req-0042/adp-0042-r1-iteration_qc.json",
        ),
        (
            "activation-decision.json",
            ".specbound/activations/req-0042/act-0042-r1-iteration_qc.json",
        ),
    ),
)
def test_control_plane_record_policy_accepts_only_current_production_binding(
    tmp_path: Path,
    template_name: str,
    relative: str,
) -> None:
    root = tmp_path / "repo"
    config_bytes = (ROOT / "specbound.yaml").read_bytes()
    (root / "specbound.yaml").parent.mkdir(parents=True)
    (root / "specbound.yaml").write_bytes(config_bytes)
    record = json.loads((ROOT / "templates" / template_name).read_text(encoding="utf-8"))
    record["authority_policy"]["sha256"] = hashlib.sha256(config_bytes).hexdigest()
    _write_canonical_json(root, Path(relative), record)
    module = importlib.import_module("specbound.control_plane_adoption")
    loaded, load_blockers = module._load_control_plane_record(root, relative)
    assert load_blockers == ()
    assert loaded is not None

    assert module._validate_record_policy(root, loaded, risk="high") == ()

    record["authority"] = "fixture-maintainer"
    _write_canonical_json(root, Path(relative), record)
    loaded, load_blockers = module._load_control_plane_record(root, relative)
    assert load_blockers == ()
    assert loaded is not None
    assert [blocker.code for blocker in module._validate_record_policy(root, loaded, risk="high")] == [
        "unauthorized_control_plane_record"
    ]


def _commit_valid_adoption_read_state(
    tmp_path: Path,
    *,
    approval_authority: str = "repository-maintainer",
    approved_at: str = "2026-07-01T00:00:00+00:00",
    attester: str = "repository-maintainer",
    duplicate_source_ref: bool = False,
) -> tuple[Path, str]:
    root = _init_git_repo(tmp_path)
    config_bytes = (ROOT / "specbound.yaml").read_bytes()
    source_relative = Path("docs/evidence/req-0042-source.txt")
    (root / "specbound.yaml").write_bytes(config_bytes)
    (root / source_relative).parent.mkdir(parents=True)
    source_bytes = b"exact immutable canary source\n"
    (root / source_relative).write_bytes(source_bytes)
    _git(root, "add", "--", "specbound.yaml", source_relative.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "establish canary capability baseline",
        env=_git_env("2026-06-30T00:00:00+00:00"),
    )
    baseline_commit = _git(root, "rev-parse", "HEAD")

    requirement_relative = Path(
        ".specbound/requirements/req-0042/req-0042-r1.md"
    )
    requirement_bytes = (
        b"---\nid: req-0042\nrevision: 1\nrisk: high\nstatus: approved\n---\n"
    )
    requirement_path = root / requirement_relative
    requirement_path.parent.mkdir(parents=True)
    requirement_path.write_bytes(requirement_bytes)
    approval_relative = Path(".specbound/approvals/req-0042-r1.approval.json")
    approval = {
        "approved_at": approved_at,
        "authority": approval_authority,
        "requirement_id": "req-0042",
        "requirement_path": requirement_relative.as_posix(),
        "revision": 1,
        "risk": "high",
        "schema_version": 1,
        "sha256": hashlib.sha256(requirement_bytes).hexdigest(),
    }
    _write_canonical_json(root, approval_relative, approval)
    _git(root, "add", "--", requirement_relative.as_posix(), approval_relative.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "approve exact requirement",
        env=_git_env("2026-07-01T00:00:00+00:00"),
    )
    source_commit = _git(root, "rev-parse", "HEAD")

    adoption_relative = Path(
        ".specbound/adoptions/req-0042/adp-0042-r1-iteration_qc.json"
    )
    adoption = json.loads(
        (ROOT / "templates/adoption-decision.json").read_text(encoding="utf-8")
    )
    adoption["adoption_source_commit"] = source_commit
    adoption["authority_policy"]["sha256"] = hashlib.sha256(config_bytes).hexdigest()
    adoption["canary_capability_baseline_at"] = "2026-06-30T00:00:00+00:00"
    adoption["canary_capability_baseline_commit"] = baseline_commit
    adoption["canary_work_attested_at"] = "2026-07-02T00:00:00+00:00"
    adoption["canary_work_attested_by"] = attester
    adoption["decided_at"] = "2026-07-02T00:00:00+00:00"
    adoption["requirement"]["sha256"] = hashlib.sha256(requirement_bytes).hexdigest()
    adoption["canary_work_source_refs"] = [
        {
            "kind": "repository",
            "path": source_relative.as_posix(),
            "sha256": hashlib.sha256(source_bytes).hexdigest(),
        }
    ]
    if duplicate_source_ref:
        adoption["canary_work_source_refs"].append(
            deepcopy(adoption["canary_work_source_refs"][0])
        )
    _write_canonical_json(root, adoption_relative, adoption)
    _git(root, "add", "--", adoption_relative.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record exact canary adoption",
        env=_git_env("2026-07-02T00:00:00+00:00"),
    )
    return root, adoption_relative.as_posix()


def test_resolve_adoption_read_state_accepts_exact_valid_record(tmp_path: Path) -> None:
    root, adoption_path = _commit_valid_adoption_read_state(tmp_path)
    module = importlib.import_module("specbound.control_plane_adoption")

    state, blockers = module.resolve_adoption_read_state(root, adoption_path)

    assert blockers == ()
    assert state is not None
    assert state.path == adoption_path
    assert state.requirement_path == ".specbound/requirements/req-0042/req-0042-r1.md"
    assert state.transition == "iteration_qc"
    assert state.risk == "high"
    assert state.source_commit == _git(root, "rev-parse", "HEAD^")


def test_resolve_adoption_read_state_rejects_mismatched_approval_authority(
    tmp_path: Path,
) -> None:
    root, adoption_path = _commit_valid_adoption_read_state(
        tmp_path,
        approval_authority="fixture-maintainer",
    )
    module = importlib.import_module("specbound.control_plane_adoption")

    state, blockers = module.resolve_adoption_read_state(root, adoption_path)

    assert state is None
    assert [blocker.code for blocker in blockers] == [
        "invalid_adoption_approval_binding"
    ]


def test_resolve_adoption_read_state_rejects_non_authority_attester(
    tmp_path: Path,
) -> None:
    root, adoption_path = _commit_valid_adoption_read_state(
        tmp_path,
        attester="fixture-maintainer",
    )
    module = importlib.import_module("specbound.control_plane_adoption")

    state, blockers = module.resolve_adoption_read_state(root, adoption_path)

    assert state is None
    assert [blocker.code for blocker in blockers] == [
        "invalid_canary_work_attestation"
    ]


def test_resolve_adoption_read_state_rejects_approval_not_after_baseline(
    tmp_path: Path,
) -> None:
    root, adoption_path = _commit_valid_adoption_read_state(
        tmp_path,
        approved_at="2026-06-30T00:00:00+00:00",
    )
    module = importlib.import_module("specbound.control_plane_adoption")

    state, blockers = module.resolve_adoption_read_state(root, adoption_path)

    assert state is None
    assert [blocker.code for blocker in blockers] == [
        "invalid_adoption_approval_timing"
    ]


def test_resolve_adoption_read_state_rejects_duplicate_source_refs(
    tmp_path: Path,
) -> None:
    root, adoption_path = _commit_valid_adoption_read_state(
        tmp_path,
        duplicate_source_ref=True,
    )
    module = importlib.import_module("specbound.control_plane_adoption")

    state, blockers = module.resolve_adoption_read_state(root, adoption_path)

    assert state is None
    assert [blocker.code for blocker in blockers] == ["invalid_canary_source_refs"]


def _commit_passed_canary_outcome(
    tmp_path: Path,
    *,
    attempt_sequence: int = 1,
) -> tuple[Path, str]:
    root, adoption_path = _commit_valid_adoption_read_state(tmp_path)
    exception_relative = Path(
        "docs/governance/bootstrap-exceptions/req-0042-r1-iteration-qc-001.md"
    )
    exception_bytes = (
        b"# Bootstrap exception: req-0042-r1-iteration-qc-001\n\n"
        b"- Status: `active`\n"
        b"- Transition: `iteration_qc`\n"
        b"- Target artifact: `.specbound/requirements/req-0042/req-0042-r1.md`\n"
        b"- Authority identity: `repository-maintainer`\n"
        b"- Maximum review/attempt budget: `1`\n"
    )
    exception_path = root / exception_relative
    exception_path.parent.mkdir(parents=True, exist_ok=True)
    exception_path.write_bytes(exception_bytes)
    _git(root, "add", "--", exception_relative.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "open exact IQC canary exception",
        env=_git_env("2026-07-03T00:00:00+00:00"),
    )
    pre_close_commit = _git(root, "rev-parse", "HEAD")

    outcome_relative = Path(
        ".specbound/canary-outcomes/req-0042/"
        f"cny-0042-r1-iteration_qc-a{attempt_sequence}.json"
    )
    outcome = json.loads(
        (ROOT / "templates/canary-outcome.json").read_text(encoding="utf-8")
    )
    outcome["adoption"]["path"] = adoption_path
    outcome["adoption"]["sha256"] = hashlib.sha256(
        (root / adoption_path).read_bytes()
    ).hexdigest()
    outcome["bootstrap_exception"]["path"] = exception_relative.as_posix()
    outcome["bootstrap_exception"]["pre_close_commit"] = pre_close_commit
    outcome["bootstrap_exception"]["pre_close_sha256"] = hashlib.sha256(
        exception_bytes
    ).hexdigest()
    outcome["attempt_sequence"] = attempt_sequence
    outcome["canary_outcome_id"] = (
        f"cny-0042-r1-iteration_qc-a{attempt_sequence}"
    )
    outcome["recorded_at"] = "2026-07-04T00:00:00+00:00"
    _write_canonical_json(root, outcome_relative, outcome)
    _git(root, "add", "--", outcome_relative.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record passed IQC canary outcome",
        env=_git_env("2026-07-04T00:00:00+00:00"),
    )
    return root, outcome_relative.as_posix()


def test_resolve_passed_canary_outcome_accepts_exact_lineage(tmp_path: Path) -> None:
    root, outcome_path = _commit_passed_canary_outcome(tmp_path)
    module = importlib.import_module("specbound.control_plane_adoption")

    state, blockers = module.resolve_passed_canary_outcome(root, outcome_path)

    assert blockers == ()
    assert state is not None
    assert state.path == outcome_path
    assert state.adoption_path == (
        ".specbound/adoptions/req-0042/adp-0042-r1-iteration_qc.json"
    )
    assert state.transition == "iteration_qc"
    assert state.attempt_sequence == 1
    assert state.pre_close_commit == _git(root, "rev-parse", "HEAD^")


def test_resolve_passed_canary_outcome_rejects_attempt_sequence_gap(
    tmp_path: Path,
) -> None:
    root, outcome_path = _commit_passed_canary_outcome(
        tmp_path,
        attempt_sequence=2,
    )
    module = importlib.import_module("specbound.control_plane_adoption")

    state, blockers = module.resolve_passed_canary_outcome(root, outcome_path)

    assert state is None
    assert [blocker.code for blocker in blockers] == [
        "noncontiguous_canary_attempt_sequence"
    ]


def _commit_successful_iqc_activation(
    tmp_path: Path,
    *,
    separate_prospective_baseline: bool = True,
) -> tuple[Path, str]:
    root, outcome_path = _commit_passed_canary_outcome(tmp_path)
    outcome_commit = _git(root, "rev-parse", "HEAD")
    outcome = json.loads((root / outcome_path).read_text(encoding="utf-8"))
    exception_relative = Path(outcome["bootstrap_exception"]["path"])
    closed_exception_bytes = (
        b"# Bootstrap exception: req-0042-r1-iteration-qc-001\n\n"
        b"- Status: `closed`\n"
        b"- Transition: `iteration_qc`\n"
        b"- Target artifact: `.specbound/requirements/req-0042/req-0042-r1.md`\n"
        b"- Authority identity: `repository-maintainer`\n"
        + f"- Successful outcome: `{outcome_path}` at `{outcome_commit}`\n".encode()
        + b"- Maximum review/attempt budget: `1`\n"
    )
    (root / exception_relative).write_bytes(closed_exception_bytes)
    ledger_relative = Path("docs/governance/bootstrap-exceptions/README.md")
    ledger_bytes = (
        b"# Bootstrap exception ledger\n\n"
        b"**Active exceptions: 0**\n\n"
        b"## Inventory\n\n"
        b"| Exception | Transition | Target | Status | Expiry |\n"
        b"| --- | --- | --- | --- | --- |\n"
        b"| [`req-0042-r1-iteration-qc-001.md`](req-0042-r1-iteration-qc-001.md) "
        b"| `iteration_qc` "
        b"| `.specbound/requirements/req-0042/req-0042-r1.md` "
        b"| `closed` | consumed |\n"
    )
    ledger_path = root / ledger_relative
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.write_bytes(ledger_bytes)
    _git(root, "add", "--", exception_relative.as_posix(), ledger_relative.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "close IQC canary exception",
        env=_git_env("2026-07-05T00:00:00+00:00"),
    )
    closeout_commit = _git(root, "rev-parse", "HEAD")

    if separate_prospective_baseline:
        baseline_relative = Path("docs/evidence/req-0042-iqc-baseline.txt")
        (root / baseline_relative).write_bytes(b"prospective IQC baseline\n")
        _git(root, "add", "--", baseline_relative.as_posix())
        _git(
            root,
            "commit",
            "--quiet",
            "-m",
            "establish prospective IQC baseline",
            env=_git_env("2026-07-06T00:00:00+00:00"),
        )
        baseline_commit = _git(root, "rev-parse", "HEAD")
        baseline_at = "2026-07-06T00:00:00+00:00"
    else:
        baseline_commit = closeout_commit
        baseline_at = "2026-07-05T00:00:00+00:00"

    activation_relative = Path(
        ".specbound/activations/req-0042/act-0042-r1-iteration_qc.json"
    )
    activation = json.loads(
        (ROOT / "templates/activation-decision.json").read_text(encoding="utf-8")
    )
    adoption_path = outcome["adoption"]["path"]
    activation["adoption"]["path"] = adoption_path
    activation["adoption"]["sha256"] = hashlib.sha256(
        (root / adoption_path).read_bytes()
    ).hexdigest()
    activation["canary_outcome"]["path"] = outcome_path
    activation["canary_outcome"]["sha256"] = hashlib.sha256(
        (root / outcome_path).read_bytes()
    ).hexdigest()
    activation["passed_outcome_commit"] = outcome_commit
    activation["bootstrap_exception"] = {
        "path": exception_relative.as_posix(),
        "pre_close_commit": outcome["bootstrap_exception"]["pre_close_commit"],
        "pre_close_sha256": outcome["bootstrap_exception"]["pre_close_sha256"],
        "closeout_commit": closeout_commit,
        "closed_sha256": hashlib.sha256(closed_exception_bytes).hexdigest(),
    }
    activation["bootstrap_exception_ledger"]["sha256"] = hashlib.sha256(
        ledger_bytes
    ).hexdigest()
    activation["authority_policy"]["sha256"] = hashlib.sha256(
        (root / "specbound.yaml").read_bytes()
    ).hexdigest()
    activation["prospective_baseline_commit"] = baseline_commit
    activation["prospective_baseline_at"] = baseline_at
    activation["decided_at"] = "2026-07-07T00:00:00+00:00"
    _write_canonical_json(root, activation_relative, activation)
    _git(root, "add", "--", activation_relative.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "activate prospective IQC control plane",
        env=_git_env("2026-07-07T00:00:00+00:00"),
    )
    return root, activation_relative.as_posix()


def _commit_successful_dqc_activation(
    tmp_path: Path,
    *,
    iqc_present_in_adoption_source: bool = True,
) -> tuple[Path, str]:
    root, iqc_activation_path = _commit_successful_iqc_activation(tmp_path)
    iqc_activation_bytes = (root / iqc_activation_path).read_bytes()
    iqc_activation = json.loads(
        (root / iqc_activation_path).read_text(encoding="utf-8")
    )
    dqc_baseline_commit = iqc_activation["prospective_baseline_commit"]

    if not iqc_present_in_adoption_source:
        (root / iqc_activation_path).unlink()
        _git(root, "add", "--", iqc_activation_path)

    approval_relative = Path(".specbound/approvals/req-0042-r1.approval.json")
    approval = json.loads((root / approval_relative).read_text(encoding="utf-8"))
    approval["approved_at"] = "2026-07-08T00:00:00+00:00"
    _write_canonical_json(root, approval_relative, approval)
    _git(root, "add", "--", approval_relative.as_posix())
    _git(root, "commit", "--quiet", "-m", "approve exact DQC canary", env=_git_env("2026-07-08T00:00:00+00:00"))
    adoption_source_commit = _git(root, "rev-parse", "HEAD")

    if not iqc_present_in_adoption_source:
        (root / iqc_activation_path).write_bytes(iqc_activation_bytes)
        _git(root, "add", "--", iqc_activation_path)
        _git(root, "commit", "--quiet", "-m", "restore IQC after frozen DQC source", env=_git_env("2026-07-08T12:00:00+00:00"))

    iqc_adoption = json.loads(
        (root / iqc_activation["adoption"]["path"]).read_text(encoding="utf-8")
    )
    adoption_relative = Path(
        ".specbound/adoptions/req-0042/adp-0042-r1-delivery_qc.json"
    )
    adoption = deepcopy(iqc_adoption)
    adoption.update(
        adoption_id="adp-0042-r1-delivery_qc",
        transition="delivery_qc",
        adoption_source_commit=adoption_source_commit,
        canary_capability_baseline_commit=dqc_baseline_commit,
        canary_capability_baseline_at="2026-07-06T00:00:00+00:00",
        decided_at="2026-07-09T00:00:00+00:00",
        canary_work_attested_at="2026-07-09T00:00:00+00:00",
        authority_action_id="act-ref-adoption-dqc-0042-r1",
        context_id="ctx-adoption-dqc-0042-r1",
    )
    _write_canonical_json(root, adoption_relative, adoption)
    _git(root, "add", "--", adoption_relative.as_posix())
    _git(root, "commit", "--quiet", "-m", "record exact DQC adoption", env=_git_env("2026-07-09T00:00:00+00:00"))

    exception_relative = Path(
        "docs/governance/bootstrap-exceptions/req-0042-r1-delivery-qc-001.md"
    )
    exception_bytes = (
        b"# Bootstrap exception: req-0042-r1-delivery-qc-001\n\n"
        b"- Status: `active`\n- Transition: `delivery_qc`\n"
        b"- Target artifact: `.specbound/requirements/req-0042/req-0042-r1.md`\n"
        b"- Authority identity: `repository-maintainer`\n"
        b"- Maximum review/attempt budget: `1`\n"
    )
    (root / exception_relative).write_bytes(exception_bytes)
    _git(root, "add", "--", exception_relative.as_posix())
    _git(root, "commit", "--quiet", "-m", "open exact DQC canary exception", env=_git_env("2026-07-10T00:00:00+00:00"))
    pre_close_commit = _git(root, "rev-parse", "HEAD")

    outcome_relative = Path(
        ".specbound/canary-outcomes/req-0042/cny-0042-r1-delivery_qc-a1.json"
    )
    outcome = json.loads((ROOT / "templates/canary-outcome.json").read_text(encoding="utf-8"))
    outcome.update(
        canary_outcome_id="cny-0042-r1-delivery_qc-a1",
        transition="delivery_qc",
        recorded_at="2026-07-11T00:00:00+00:00",
        authority_action_id="act-ref-outcome-dqc-0042-r1-a1",
        context_id="ctx-outcome-dqc-0042-r1-a1",
    )
    outcome["adoption"] = {
        "path": adoption_relative.as_posix(),
        "sha256": hashlib.sha256((root / adoption_relative).read_bytes()).hexdigest(),
    }
    outcome["bootstrap_exception"] = {
        "path": exception_relative.as_posix(),
        "pre_close_commit": pre_close_commit,
        "pre_close_sha256": hashlib.sha256(exception_bytes).hexdigest(),
    }
    _write_canonical_json(root, outcome_relative, outcome)
    _git(root, "add", "--", outcome_relative.as_posix())
    _git(root, "commit", "--quiet", "-m", "record passed DQC canary outcome", env=_git_env("2026-07-11T00:00:00+00:00"))
    outcome_commit = _git(root, "rev-parse", "HEAD")

    closed_exception_bytes = exception_bytes.replace(b"- Status: `active`", b"- Status: `closed`").replace(
        b"- Maximum review/attempt budget: `1`\n",
        f"- Successful outcome: `{outcome_relative.as_posix()}` at `{outcome_commit}`\n".encode()
        + b"- Maximum review/attempt budget: `1`\n",
    )
    (root / exception_relative).write_bytes(closed_exception_bytes)
    ledger_relative = Path("docs/governance/bootstrap-exceptions/README.md")
    ledger_bytes = (
        b"# Bootstrap exception ledger\n\n**Active exceptions: 0**\n\n## Inventory\n\n"
        b"| Exception | Transition | Target | Status | Expiry |\n"
        b"| --- | --- | --- | --- | --- |\n"
        b"| [`req-0042-r1-delivery-qc-001.md`](req-0042-r1-delivery-qc-001.md) | `delivery_qc` "
        b"| `.specbound/requirements/req-0042/req-0042-r1.md` | `closed` | consumed |\n"
    )
    (root / ledger_relative).write_bytes(ledger_bytes)
    _git(root, "add", "--", exception_relative.as_posix(), ledger_relative.as_posix())
    _git(root, "commit", "--quiet", "-m", "close DQC canary exception", env=_git_env("2026-07-12T00:00:00+00:00"))
    closeout_commit = _git(root, "rev-parse", "HEAD")
    (root / "docs/evidence/req-0042-dqc-baseline.txt").write_bytes(b"prospective DQC baseline\n")
    _git(root, "add", "--", "docs/evidence/req-0042-dqc-baseline.txt")
    _git(root, "commit", "--quiet", "-m", "establish prospective DQC baseline", env=_git_env("2026-07-13T00:00:00+00:00"))
    baseline_commit = _git(root, "rev-parse", "HEAD")

    activation_relative = Path(
        ".specbound/activations/req-0042/act-0042-r1-delivery_qc.json"
    )
    activation = json.loads((ROOT / "templates/activation-decision.json").read_text(encoding="utf-8"))
    activation.update(
        activation_id="act-0042-r1-delivery_qc",
        transition="delivery_qc",
        passed_outcome_commit=outcome_commit,
        prospective_baseline_commit=baseline_commit,
        prospective_baseline_at="2026-07-13T00:00:00+00:00",
        decided_at="2026-07-14T00:00:00+00:00",
        authority_action_id="act-ref-activation-dqc-0042-r1",
        context_id="ctx-activation-dqc-0042-r1",
    )
    activation["adoption"] = {"path": adoption_relative.as_posix(), "sha256": hashlib.sha256((root / adoption_relative).read_bytes()).hexdigest()}
    activation["canary_outcome"] = {"path": outcome_relative.as_posix(), "sha256": hashlib.sha256((root / outcome_relative).read_bytes()).hexdigest()}
    activation["bootstrap_exception"] = {
        "path": exception_relative.as_posix(), "pre_close_commit": pre_close_commit,
        "pre_close_sha256": hashlib.sha256(exception_bytes).hexdigest(),
        "closeout_commit": closeout_commit, "closed_sha256": hashlib.sha256(closed_exception_bytes).hexdigest(),
    }
    activation["bootstrap_exception_ledger"]["sha256"] = hashlib.sha256(ledger_bytes).hexdigest()
    activation["authority_policy"]["sha256"] = hashlib.sha256((root / "specbound.yaml").read_bytes()).hexdigest()
    _write_canonical_json(root, activation_relative, activation)
    _git(root, "add", "--", activation_relative.as_posix())
    _git(root, "commit", "--quiet", "-m", "activate prospective DQC control plane", env=_git_env("2026-07-14T00:00:00+00:00"))
    return root, activation_relative.as_posix()


def test_resolve_successful_iqc_activation_accepts_exact_chain(tmp_path: Path) -> None:
    root, activation_path = _commit_successful_iqc_activation(tmp_path)
    module = importlib.import_module("specbound.control_plane_adoption")

    state, blockers = module.resolve_successful_iqc_activation(root, activation_path)

    assert blockers == ()
    assert state is not None
    assert state.path == activation_path
    assert state.requirement_id == "req-0042"
    assert state.revision == 1
    assert state.transition == "iteration_qc"
    assert state.prospective_baseline_commit == _git(root, "rev-parse", "HEAD^")


def test_resolve_successful_iqc_activation_requires_post_closeout_baseline(
    tmp_path: Path,
) -> None:
    root, activation_path = _commit_successful_iqc_activation(
        tmp_path,
        separate_prospective_baseline=False,
    )
    module = importlib.import_module("specbound.control_plane_adoption")

    state, blockers = module.resolve_successful_iqc_activation(root, activation_path)

    assert state is None
    assert [blocker.code for blocker in blockers] == [
        "prospective_baseline_not_after_closeout"
    ]


def test_delivery_qc_prerequisite_accepts_exact_successful_iqc_activation(
    tmp_path: Path,
) -> None:
    root, activation_path = _commit_successful_iqc_activation(tmp_path)
    activation = json.loads((root / activation_path).read_text(encoding="utf-8"))
    adoption = json.loads(
        (root / activation["adoption"]["path"]).read_text(encoding="utf-8")
    )
    module = importlib.import_module("specbound.control_plane_adoption")
    evidence = module.freeze_git_evidence(
        root,
        requirement_path=adoption["requirement"]["path"],
        approval_path=".specbound/approvals/req-0042-r1.approval.json",
        baseline_commit=adoption["canary_capability_baseline_commit"],
        baseline_at=adoption["canary_capability_baseline_at"],
    )
    assert evidence.valid

    result = module.resolve_adoption_eligibility(
        root,
        evidence=evidence,
        approved_at="2026-07-01T00:00:00+00:00",
        transition="delivery_qc",
    )

    assert "missing_successful_iteration_qc_activation" not in {
        blocker.code for blocker in result.blockers
    }
    assert "invalid_iteration_qc_activation" not in {
        blocker.code for blocker in result.blockers
    }


def test_delivery_qc_prerequisite_rejects_duplicate_target_bound_activation(
    tmp_path: Path,
) -> None:
    root, activation_path = _commit_successful_iqc_activation(tmp_path)
    duplicate_path = Path(
        ".specbound/activations/req-0042/"
        "act-0042-r1-iteration_qc-copy.json"
    )
    (root / duplicate_path).write_bytes((root / activation_path).read_bytes())
    _git(root, "add", "--", duplicate_path.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "add conflicting target-bound activation evidence",
        env=_git_env("2026-07-08T00:00:00+00:00"),
    )
    activation = json.loads((root / activation_path).read_text(encoding="utf-8"))
    adoption = json.loads(
        (root / activation["adoption"]["path"]).read_text(encoding="utf-8")
    )
    module = importlib.import_module("specbound.control_plane_adoption")
    evidence = module.freeze_git_evidence(
        root,
        requirement_path=adoption["requirement"]["path"],
        approval_path=".specbound/approvals/req-0042-r1.approval.json",
        baseline_commit=adoption["canary_capability_baseline_commit"],
        baseline_at=adoption["canary_capability_baseline_at"],
    )
    assert evidence.valid

    result = module.resolve_adoption_eligibility(
        root,
        evidence=evidence,
        approved_at="2026-07-01T00:00:00+00:00",
        transition="delivery_qc",
    )

    assert "invalid_iteration_qc_activation" in {
        blocker.code for blocker in result.blockers
    }


def test_effective_activation_registry_contains_exact_valid_activation(
    tmp_path: Path,
) -> None:
    root, activation_path = _commit_successful_iqc_activation(tmp_path)
    module = importlib.import_module("specbound.control_plane_adoption")

    registry = module.resolve_effective_activation_registry(root)

    assert registry.blockers == ()
    assert registry.valid
    assert [state.path for state in registry.activations] == [activation_path]
    assert [
        (state.requirement_id, state.revision, state.transition)
        for state in registry.activations
    ] == [("req-0042", 1, "iteration_qc")]


def test_effective_activation_registry_contains_exact_valid_dqc_activation(
    tmp_path: Path,
) -> None:
    root, activation_path = _commit_successful_dqc_activation(tmp_path)
    module = importlib.import_module("specbound.control_plane_adoption")

    registry = module.resolve_effective_activation_registry(root)

    assert registry.blockers == ()
    assert [state.path for state in registry.activations] == [
        activation_path,
        ".specbound/activations/req-0042/act-0042-r1-iteration_qc.json",
    ]


def test_effective_activation_registry_rejects_dqc_without_exact_iqc_in_source(
    tmp_path: Path,
) -> None:
    root, activation_path = _commit_successful_dqc_activation(
        tmp_path, iqc_present_in_adoption_source=False
    )
    module = importlib.import_module("specbound.control_plane_adoption")

    registry = module.resolve_effective_activation_registry(root)

    assert not registry.valid
    assert registry.activations == ()
    assert [(blocker.code, blocker.path) for blocker in registry.blockers] == [
        ("invalid_effective_activation", activation_path)
    ]
    assert "invalid_iteration_qc_activation" in registry.blockers[0].detail


def test_effective_activation_registry_fails_closed_on_target_bound_duplicate(
    tmp_path: Path,
) -> None:
    root, activation_path = _commit_successful_iqc_activation(tmp_path)
    duplicate_path = Path(
        ".specbound/activations/req-0042/"
        "act-0042-r1-iteration_qc-duplicate.json"
    )
    (root / duplicate_path).write_bytes((root / activation_path).read_bytes())
    _git(root, "add", "--", duplicate_path.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "add ambiguous effective activation",
        env=_git_env("2026-07-08T00:00:00+00:00"),
    )
    module = importlib.import_module("specbound.control_plane_adoption")

    registry = module.resolve_effective_activation_registry(root)

    assert not registry.valid
    assert registry.activations == ()
    assert [blocker.code for blocker in registry.blockers] == [
        "ambiguous_effective_activation"
    ]
    assert registry.blockers[0].path == duplicate_path.as_posix()


def test_effective_activation_registry_aggregates_global_identity_collision(
    tmp_path: Path,
) -> None:
    root, activation_path = _commit_successful_iqc_activation(tmp_path)
    module = importlib.import_module("specbound.control_plane_adoption")
    state, blockers = module.resolve_successful_iqc_activation(root, activation_path)
    assert blockers == ()
    assert state is not None
    conflicting_state = replace(
        state,
        path=".specbound/activations/req-0043/act-0043-r1-iteration_qc.json",
        requirement_id="req-0043",
        requirement_path=".specbound/requirements/req-0043/req-0043-r1.md",
        adoption_path=".specbound/adoptions/req-0043/adp-0043-r1-iteration_qc.json",
        outcome_path=(
            ".specbound/canary-outcomes/req-0043/"
            "cny-0043-r1-iteration_qc-a1.json"
        ),
    )

    registry = module._aggregate_effective_activation_states(
        (conflicting_state, state),
        (),
    )

    assert not registry.valid
    assert registry.activations == ()
    assert [blocker.code for blocker in registry.blockers] == [
        "conflicting_effective_activation_identity"
    ]
    assert registry.blockers[0].path == activation_path


def test_effective_activation_registry_rejects_duplicate_effective_key(
    tmp_path: Path,
) -> None:
    root, activation_path = _commit_successful_iqc_activation(tmp_path)
    module = importlib.import_module("specbound.control_plane_adoption")
    state, blockers = module.resolve_successful_iqc_activation(root, activation_path)
    assert blockers == ()
    assert state is not None
    conflicting_state = replace(
        state,
        path=(
            ".specbound/activations/req-0042/"
            "act-0042-r1-iteration_qc-conflict.json"
        ),
        authority_action_id="different-effective-action-reference",
        context_id="different-effective-context-reference",
    )

    registry = module._aggregate_effective_activation_states(
        (conflicting_state, state),
        (),
    )

    assert not registry.valid
    assert registry.activations == ()
    assert [blocker.code for blocker in registry.blockers] == [
        "ambiguous_effective_activation"
    ]
    assert registry.blockers[0].path == min(activation_path, conflicting_state.path)


def test_repository_validation_reads_valid_effective_activation_registry(
    tmp_path: Path,
) -> None:
    root, _activation_path = _commit_successful_iqc_activation(tmp_path)

    result = validation.validate(root)

    assert result.checked_effective_activations == 1
    assert not {
        "invalid_effective_activation",
        "ambiguous_effective_activation",
        "conflicting_effective_activation_identity",
    }.intersection(blocker["code"] for blocker in result.blockers)


def test_iteration_claim_uses_exact_effective_activation(
    tmp_path: Path,
) -> None:
    root, _activation_path = _commit_successful_iqc_activation(tmp_path)

    result = validation.validate(
        root,
        claim="iteration",
        requirement="req-0042-r1",
    )

    blocker_codes = {blocker["code"] for blocker in result.blockers}
    assert "control_plane_not_adopted" not in blocker_codes
    assert "missing_adopted_iteration_evidence" in blocker_codes


def test_delivery_claim_uses_exact_delivery_effective_activation(
    tmp_path: Path,
) -> None:
    root, _activation_path = _commit_successful_dqc_activation(tmp_path)

    result = validation.validate(
        root,
        claim="delivery",
        requirement="req-0042-r1",
    )

    blocker_codes = {blocker["code"] for blocker in result.blockers}
    assert "control_plane_not_adopted" not in blocker_codes
    assert "missing_adopted_delivery_evidence" in blocker_codes


def test_delivery_claim_does_not_reuse_iteration_effective_activation(
    tmp_path: Path,
) -> None:
    root, _activation_path = _commit_successful_iqc_activation(tmp_path)

    result = validation.validate(
        root,
        claim="delivery",
        requirement="req-0042-r1",
    )

    assert "control_plane_not_adopted" in {
        blocker["code"] for blocker in result.blockers
    }


def test_repository_validation_uses_git_head_when_activation_worktree_is_missing(
    tmp_path: Path,
) -> None:
    root, activation_path = _commit_successful_iqc_activation(tmp_path)
    (root / activation_path).unlink()

    result = validation.validate(root)

    assert result.checked_effective_activations == 0
    assert "invalid_effective_activation" in {
        blocker["code"] for blocker in result.blockers
    }


def test_repository_validation_rejects_fixture_authority_policy_replacement(
    tmp_path: Path,
) -> None:
    root, _activation_path = _commit_successful_iqc_activation(tmp_path)
    config_path = root / "specbound.yaml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    config["policy"]["discovery_confirmation_authorities_by_risk"]["medium"] = [
        "fixture-authority"
    ]
    config_path.write_text(
        yaml.safe_dump(config, sort_keys=False),
        encoding="utf-8",
        newline="\n",
    )

    result = validation.validate(root)

    assert result.checked_effective_activations == 0
    assert "invalid_effective_activation" in {
        blocker["code"] for blocker in result.blockers
    }


def test_bootstrap_ledger_parser_preserves_exact_row_semantics() -> None:
    module = importlib.import_module("specbound.control_plane_adoption")
    ledger = (
        "# Bootstrap exception ledger\n\n"
        "**Active exceptions: 1**\n\n"
        "## Inventory\n\n"
        "| Exception | Transition | Target | Status | Expiry |\n"
        "| --- | --- | --- | --- | --- |\n"
        "| [`req-0042-r1-iteration-qc-001.md`](req-0042-r1-iteration-qc-001.md) "
        "| `iteration_qc` "
        "| `.specbound/requirements/req-0042/req-0042-r1.md` "
        "| `active` | 2026-08-01T00:00:00Z |\n"
    ).encode("utf-8")

    parsed = module._parse_bootstrap_ledger(
        ledger,
        requirement_path=".specbound/requirements/req-0042/req-0042-r1.md",
        exception_prefix="req-0042-r1-",
    )

    assert parsed.active_count == 1
    assert [
        (row.exception_path, row.transition, row.target, row.status, row.expiry)
        for row in parsed.rows
    ] == [
        (
            "req-0042-r1-iteration-qc-001.md",
            "iteration_qc",
            ".specbound/requirements/req-0042/req-0042-r1.md",
            "active",
            "2026-08-01T00:00:00Z",
        )
    ]


def test_bootstrap_ledger_parser_accepts_repository_ledger_bytes() -> None:
    module = importlib.import_module("specbound.control_plane_adoption")

    parsed = module._parse_bootstrap_ledger(
        (ROOT / "docs/governance/bootstrap-exceptions/README.md").read_bytes(),
        requirement_path=".specbound/requirements/req-0005/req-0005-r1.md",
        exception_prefix="req-0005-r1-",
    )

    assert parsed.active_count == 0
    assert [row.exception_path for row in parsed.rows] == [
        "req-0005-r1-review-return-001.md"
    ]
    assert parsed.rows[0].status == "closed"


def test_bootstrap_ledger_parser_rejects_active_count_mismatch() -> None:
    module = importlib.import_module("specbound.control_plane_adoption")
    ledger = (
        "# Bootstrap exception ledger\n\n"
        "**Active exceptions: 0**\n\n"
        "## Inventory\n\n"
        "| Exception | Transition | Target | Status | Expiry |\n"
        "| --- | --- | --- | --- | --- |\n"
        "| [`req-0042-r1-iteration-qc-001.md`](req-0042-r1-iteration-qc-001.md) "
        "| `iteration_qc` "
        "| `.specbound/requirements/req-0042/req-0042-r1.md` "
        "| `active` | 2026-08-01T00:00:00Z |\n"
    ).encode("utf-8")

    with pytest.raises(ValueError, match="active exception count"):
        module._parse_bootstrap_ledger(
            ledger,
            requirement_path=".specbound/requirements/req-0042/req-0042-r1.md",
            exception_prefix="req-0042-r1-",
        )


def test_bootstrap_ledger_parser_rejects_duplicate_exception_rows() -> None:
    module = importlib.import_module("specbound.control_plane_adoption")
    row = (
        "| [`req-0042-r1-iteration-qc-001.md`](req-0042-r1-iteration-qc-001.md) "
        "| `iteration_qc` "
        "| `.specbound/requirements/req-0042/req-0042-r1.md` "
        "| `active` | 2026-08-01T00:00:00Z |\n"
    )
    ledger = (
        "# Bootstrap exception ledger\n\n"
        "**Active exceptions: 2**\n\n"
        "## Inventory\n\n"
        "| Exception | Transition | Target | Status | Expiry |\n"
        "| --- | --- | --- | --- | --- |\n"
        + row * 2
    ).encode("utf-8")

    with pytest.raises(ValueError, match="duplicate exception"):
        module._parse_bootstrap_ledger(
            ledger,
            requirement_path=".specbound/requirements/req-0042/req-0042-r1.md",
            exception_prefix="req-0042-r1-",
        )



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
        transition="iteration_qc",
    )

    assert result.eligible
    assert result.blockers == ()


def test_delivery_qc_adoption_requires_successful_iteration_qc_activation(
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
        approved_at="2026-07-01T00:00:01+00:00",
        transition="delivery_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        (
            "missing_successful_iteration_qc_activation",
            ".specbound/activations/req-0042",
        )
    ]


def test_adoption_eligibility_rejects_unsupported_transition(tmp_path: Path) -> None:
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
        approved_at="2026-07-01T00:00:01+00:00",
        transition="release",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("unsupported_adoption_transition", "transition")
    ]


def test_adoption_eligibility_requires_explicit_transition() -> None:
    module = importlib.import_module("specbound.control_plane_adoption")

    assert (
        inspect.signature(module.resolve_adoption_eligibility)
        .parameters["transition"]
        .default
        is inspect.Parameter.empty
    )



def test_resolve_adoption_eligibility_rejects_exact_candidate_micro_spec_prior_work(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    micro_spec = Path(".specbound/micro-specs/req-0042/ms-0042-001.md")
    micro_spec_path = root / micro_spec
    micro_spec_path.parent.mkdir(parents=True, exist_ok=True)
    micro_spec_path.write_bytes(
        b"---\n"
        b"schema_version: 1\n"
        b"id: ms-0042-001\n"
        b"kind: micro-spec\n"
        b"requirement:\n"
        b"  path: .specbound/requirements/req-0042/req-0042-r1.md\n"
        b"  id: req-0042\n"
        b"  revision: 1\n"
        b"  sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        b"---\n"
    )
    _git(root, "add", "--", micro_spec.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record prior micro spec work",
        env=_git_env("2026-07-02T00:00:00+00:00"),
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("prior_work_detected", micro_spec.as_posix())
    ]


def test_iteration_qc_adoption_fails_closed_on_ambiguous_malformed_micro_spec(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    micro_spec = Path(".specbound/micro-specs/req-0042/ms-0042-001.md")
    path = root / micro_spec
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\xffnot-yaml\n")
    _git(root, "add", "--", micro_spec.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record malformed planning evidence",
        env=_git_env("2026-07-02T00:00:00+00:00"),
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("malformed_prior_work_evidence", micro_spec.as_posix())
    ]


def _resolve_iteration_qc_with_prior_blob(
    tmp_path: Path,
    *,
    relative: str,
    payload: bytes,
):
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    evidence_path = Path(relative)
    path = root / evidence_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    _git(root, "add", "--", evidence_path.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record prior evidence",
        env=_git_env("2026-07-02T00:00:00+00:00"),
    )

    module = importlib.import_module("specbound.control_plane_adoption")
    evidence = module.freeze_git_evidence(
        root,
        requirement_path=requirement.as_posix(),
        approval_path=approval.as_posix(),
        baseline_commit=baseline,
        baseline_at=baseline_at,
    )
    return module.resolve_adoption_eligibility(
        root,
        evidence=evidence,
        approved_at="2026-07-01T00:00:01+00:00",
        transition="iteration_qc",
    )


@pytest.mark.parametrize(
    ("relative", "payload"),
    (
        (
            ".specbound/micro-specs/req-0042/ms-0042-999.md",
            b"---\nrequirement:\n"
            b"  path: .specbound/requirements/req-0042/req-0042-r2.md\n"
            b"  id: req-0042\n  revision: 2\n  revision: 2\n---\n",
        ),
        (
            ".specbound/micro-spec-reviews/req-0042/ms-0042-999.review.json",
            b'{"requirement_path":".specbound/requirements/req-0042/req-0042-r2.md",'
            b'"requirement_id":"req-0042","revision":2,"revision":2}\n',
        ),
    ),
)
def test_iteration_qc_adoption_ignores_unambiguous_malformed_other_revision(
    tmp_path: Path,
    relative: str,
    payload: bytes,
) -> None:
    result = _resolve_iteration_qc_with_prior_blob(
        tmp_path,
        relative=relative,
        payload=payload,
    )

    assert result.eligible
    assert result.blockers == ()


def test_iteration_qc_adoption_ignores_valid_prior_work_for_another_revision(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    micro_spec = Path(".specbound/micro-specs/req-0042/ms-0042-002.md")
    path = root / micro_spec
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        b"---\n"
        b"id: ms-0042-002\n"
        b"kind: micro-spec\n"
        b"requirement:\n"
        b"  path: .specbound/requirements/req-0042/req-0042-r2.md\n"
        b"  id: req-0042\n"
        b"  revision: 2\n"
        b"  sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        b"---\n\n# Other revision planning evidence\n"
    )
    _git(root, "add", "--", micro_spec.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record another revision",
        env=_git_env("2026-07-02T00:00:00+00:00"),
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
        transition="iteration_qc",
    )

    assert result.eligible
    assert result.blockers == ()


def test_iteration_qc_adoption_ignores_malformed_iqc_for_another_revision(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    other_revision = Path(
        ".specbound/iteration-qc/req-0042/iqc-0042-001-r2.json"
    )
    path = root / other_revision
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\xff")
    _git(root, "add", "--", other_revision.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record malformed r2 IQC",
        env=_git_env("2026-07-02T00:00:00+00:00"),
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
        transition="iteration_qc",
    )

    assert result.eligible
    assert result.blockers == ()


def test_resolve_adoption_eligibility_rejects_exact_candidate_micro_spec_review_prior_work(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    review = Path(
        ".specbound/micro-spec-reviews/req-0042/ms-0042-001.review.json"
    )
    review_path = root / review
    review_path.parent.mkdir(parents=True, exist_ok=True)
    review_path.write_bytes(
        b'{"micro_spec_id":"ms-0042-001",'
        b'"micro_spec_path":".specbound/micro-specs/req-0042/ms-0042-001.md",'
        b'"requirement_id":"req-0042",'
        b'"requirement_path":".specbound/requirements/req-0042/req-0042-r1.md",'
        b'"revision":1}\n'
    )
    _git(root, "add", "--", review.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record prior micro spec review",
        env=_git_env("2026-07-02T00:00:00+00:00"),
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("prior_work_detected", review.as_posix())
    ]


def test_resolve_adoption_eligibility_rejects_deleted_exact_candidate_prior_work(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    micro_spec = Path(".specbound/micro-specs/req-0042/ms-0042-001.md")
    micro_spec_path = root / micro_spec
    micro_spec_path.parent.mkdir(parents=True, exist_ok=True)
    micro_spec_path.write_bytes(
        b"---\n"
        b"requirement:\n"
        b"  path: .specbound/requirements/req-0042/req-0042-r1.md\n"
        b"  id: req-0042\n"
        b"  revision: 1\n"
        b"  sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        b"---\n"
    )
    _git(root, "add", "--", micro_spec.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record prior work",
        env=_git_env("2026-07-02T00:00:00+00:00"),
    )
    micro_spec_path.unlink()
    _git(root, "add", "--all")
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "delete prior work",
        env=_git_env("2026-07-03T00:00:00+00:00"),
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("prior_work_detected", micro_spec.as_posix())
    ]


def test_prior_work_scan_includes_deleted_evidence_from_merged_side_branch(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "common root",
        env=_git_env("2026-05-01T00:00:00+00:00"),
    )
    main_branch = _git(root, "branch", "--show-current")
    _git(root, "checkout", "--quiet", "-b", "historical-work")
    micro_spec = Path(".specbound/micro-specs/req-0042/ms-0042-001.md")
    path = root / micro_spec
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        b"---\nrequirement:\n"
        b"  path: .specbound/requirements/req-0042/req-0042-r1.md\n"
        b"  id: req-0042\n"
        b"  revision: 1\n"
        b"  sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        b"---\n"
    )
    _git(root, "add", "--", micro_spec.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "side branch prior work",
        env=_git_env("2026-06-02T00:00:00+00:00"),
    )
    path.unlink()
    _git(root, "add", "--all")
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "delete side branch prior work",
        env=_git_env("2026-06-03T00:00:00+00:00"),
    )

    _git(root, "checkout", "--quiet", main_branch)
    (root / "baseline.txt").write_bytes(b"capability\n")
    _git(root, "add", "--", "baseline.txt")
    baseline_at = "2026-06-01T00:00:00+00:00"
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    _git(
        root,
        "merge",
        "--quiet",
        "--no-ff",
        "historical-work",
        "-m",
        "merge historical work",
        env=_git_env("2026-07-02T00:00:00+00:00"),
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("prior_work_detected", micro_spec.as_posix())
    ]


def test_iteration_qc_adoption_rejects_exact_candidate_iteration_qc_prior_work(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    micro_spec = Path(".specbound/micro-specs/req-0042/ms-0042-001.md")
    micro_spec_path = root / micro_spec
    micro_spec_path.parent.mkdir(parents=True, exist_ok=True)
    micro_spec_path.write_bytes(
        b"---\n"
        b"requirement:\n"
        b"  path: .specbound/requirements/req-0042/req-0042-r1.md\n"
        b"  id: req-0042\n"
        b"  revision: 1\n"
        b"  sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        b"---\n"
    )
    iteration_qc = Path(
        ".specbound/iteration-qc/req-0042/iqc-0042-001-r1.json"
    )
    iteration_qc_path = root / iteration_qc
    iteration_qc_path.parent.mkdir(parents=True, exist_ok=True)
    iteration_qc_path.write_bytes(
        b'{"micro_spec":{"id":"ms-0042-001",'
        b'"path":".specbound/micro-specs/req-0042/ms-0042-001.md",'
        b'"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}\n'
    )
    _git(root, "add", "--", micro_spec.as_posix(), iteration_qc.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record prior iteration QC",
        env=_git_env("2026-07-02T00:00:00+00:00"),
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("prior_work_detected", iteration_qc.as_posix()),
        ("prior_work_detected", micro_spec.as_posix()),
    ]


def test_iteration_qc_adoption_rejects_exact_candidate_delivery_qc_prior_work(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    delivery_qc = Path(".specbound/delivery-qc/dqc-0042-r1.json")
    delivery_qc_path = root / delivery_qc
    delivery_qc_path.parent.mkdir(parents=True, exist_ok=True)
    delivery_qc_path.write_bytes(
        b'{"requirement":{"id":"req-0042",'
        b'"path":".specbound/requirements/req-0042/req-0042-r1.md",'
        b'"revision":1,'
        b'"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}\n'
    )
    _git(root, "add", "--", delivery_qc.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record prior delivery QC",
        env=_git_env("2026-07-02T00:00:00+00:00"),
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("prior_work_detected", delivery_qc.as_posix())
    ]


def test_iteration_qc_adoption_rejects_prior_adoption_identity(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    adoption = Path(
        ".specbound/adoptions/req-0042/adp-0042-r1-iteration_qc.json"
    )
    adoption_path = root / adoption
    adoption_path.parent.mkdir(parents=True, exist_ok=True)
    adoption_path.write_bytes(
        b'{"adoption_id":"adp-0042-r1-iteration_qc",'
        b'"requirement":{"id":"req-0042",'
        b'"path":".specbound/requirements/req-0042/req-0042-r1.md",'
        b'"revision":1,'
        b'"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},'
        b'"transition":"iteration_qc"}\n'
    )
    _git(root, "add", "--", adoption.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record prior adoption",
        env=_git_env("2026-07-02T00:00:00+00:00"),
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("prior_work_detected", adoption.as_posix())
    ]


@pytest.mark.parametrize(
    "payload",
    (
        b'{"adoption_id":"adp-0042-r1-iteration_qc",'
        b'"transition":"delivery_qc","requirement":'
        b'{"path":".specbound/requirements/req-0042/req-0042-r1.md",'
        b'"id":"req-0042","revision":1}}\n',
        b'{"adoption_id":"adp-0042-r1-delivery_qc",'
        b'"transition":"iteration_qc","requirement":'
        b'{"path":".specbound/requirements/req-0042/req-0042-r1.md",'
        b'"id":"req-0042","revision":1}}\n',
    ),
)
def test_iteration_qc_adoption_rejects_conflicting_adoption_path_identity(
    tmp_path: Path,
    payload: bytes,
) -> None:
    relative = ".specbound/adoptions/req-0042/adp-0042-r1-iteration_qc.json"
    result = _resolve_iteration_qc_with_prior_blob(
        tmp_path,
        relative=relative,
        payload=payload,
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("malformed_prior_work_evidence", relative)
    ]


@pytest.mark.parametrize(
    ("relative", "content"),
    (
        (
            ".specbound/canary-outcomes/req-0042/"
            "cny-0042-r1-iteration_qc-a1.json",
            b'{"attempt_sequence":1,'
            b'"canary_outcome_id":"cny-0042-r1-iteration_qc-a1",'
            b'"transition":"iteration_qc"}\n',
        ),
        (
            ".specbound/activations/req-0042/act-0042-r1-iteration_qc.json",
            b'{"activation_id":"act-0042-r1-iteration_qc",'
            b'"transition":"iteration_qc"}\n',
        ),
    ),
)
def test_iteration_qc_adoption_rejects_prior_canary_or_activation_identity(
    tmp_path: Path,
    relative: str,
    content: bytes,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    evidence_path = Path(relative)
    path = root / evidence_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    _git(root, "add", "--", evidence_path.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record prior canary lineage",
        env=_git_env("2026-07-02T00:00:00+00:00"),
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("prior_work_detected", evidence_path.as_posix())
    ]


def test_iteration_qc_adoption_rejects_mismatched_canary_attempt_sequence(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    outcome = Path(
        ".specbound/canary-outcomes/req-0042/"
        "cny-0042-r1-iteration_qc-a2.json"
    )
    outcome_path = root / outcome
    outcome_path.parent.mkdir(parents=True, exist_ok=True)
    outcome_path.write_bytes(
        b'{"attempt_sequence":1,'
        b'"canary_outcome_id":"cny-0042-r1-iteration_qc-a2",'
        b'"transition":"iteration_qc"}\n'
    )
    _git(root, "add", "--", outcome.as_posix())
    _git(root, "commit", "--quiet", "-m", "record mismatched canary attempt", env=_git_env("2026-07-02T00:00:00+00:00"))
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("malformed_prior_work_evidence", outcome.as_posix())
    ]


def test_iteration_qc_adoption_fails_closed_on_malformed_target_bound_prior_work(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    malformed = Path(
        ".specbound/canary-outcomes/req-0042/"
        "cny-0042-r1-iteration_qc-a1.json"
    )
    malformed_path = root / malformed
    malformed_path.parent.mkdir(parents=True, exist_ok=True)
    malformed_path.write_bytes(b"\xffnot-json\n")
    _git(root, "add", "--", malformed.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record malformed prior work",
        env=_git_env("2026-07-02T00:00:00+00:00"),
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("malformed_prior_work_evidence", malformed.as_posix())
    ]


@pytest.mark.parametrize(
    "relative",
    (
        ".specbound/micro-spec-reviews/req-0042/ms-0042-001.review.json",
        ".specbound/iteration-qc/req-0042/iqc-0042-001-r1.json",
        ".specbound/delivery-qc/dqc-0042-r1.json",
        ".specbound/adoptions/req-0042/adp-0042-r1-iteration_qc.json",
        "docs/governance/bootstrap-exceptions/req-0042-r1-iteration-qc-001.md",
    ),
)
def test_iteration_qc_adoption_fails_closed_on_malformed_family_evidence(
    tmp_path: Path,
    relative: str,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    malformed = Path(relative)
    malformed_path = root / malformed
    malformed_path.parent.mkdir(parents=True, exist_ok=True)
    malformed_path.write_bytes(b"\xffnot-valid-evidence\n")
    _git(root, "add", "--", malformed.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record malformed family evidence",
        env=_git_env("2026-07-02T00:00:00+00:00"),
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("malformed_prior_work_evidence", malformed.as_posix())
    ]


@pytest.mark.parametrize(
    "relative",
    (
        ".specbound/delivery-qc/dqc-0042-r1.json",
        ".specbound/adoptions/req-0042/adp-0042-r1-iteration_qc.json",
    ),
)
def test_adoption_fails_closed_on_target_path_with_conflicting_binding(
    tmp_path: Path,
    relative: str,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    evidence_path = Path(relative)
    path = root / evidence_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "requirement": {
                    "id": "req-0042",
                    "path": ".specbound/requirements/req-0042/req-0042-r2.md",
                    "revision": 2,
                }
            }
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    _git(root, "add", "--", evidence_path.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record conflicting canonical evidence",
        env=_git_env("2026-07-02T00:00:00+00:00"),
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("malformed_prior_work_evidence", evidence_path.as_posix())
    ]


@pytest.mark.parametrize(
    ("exception_transition", "expected_code"),
    (
        ("iteration_qc", "prior_work_detected"),
        ("delivery_qc", "malformed_prior_work_evidence"),
    ),
)
def test_iteration_qc_adoption_rejects_bootstrap_exception_prior_work(
    tmp_path: Path,
    exception_transition: str,
    expected_code: str,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    exception = Path(
        "docs/governance/bootstrap-exceptions/req-0042-r1-iteration-qc-001.md"
    )
    exception_path = root / exception
    exception_path.parent.mkdir(parents=True, exist_ok=True)
    exception_path.write_text(
        "# Bootstrap exception: req-0042-r1-iteration-qc-001\n\n"
        "- Exception ID: `req-0042-r1-iteration-qc-001`\n"
        "- Status: `closed`\n"
        f"- Transition: `{exception_transition}`\n"
        "- Target artifact: `.specbound/requirements/req-0042/req-0042-r1.md`\n"
        "- Target ID/revision: `req-0042-r1`\n"
        "- Action evidence: `commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`\n",
        encoding="utf-8",
        newline="\n",
    )
    _git(root, "add", "--", exception.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record bootstrap prior work",
        env=_git_env("2026-07-02T00:00:00+00:00"),
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        (expected_code, exception.as_posix())
    ]


@pytest.mark.parametrize(
    ("ledger_transition", "row_count", "expected_code"),
    (
        ("iteration_qc", 1, "prior_work_detected"),
        ("delivery_qc", 1, "malformed_prior_work_evidence"),
        ("iteration_qc", 2, "malformed_prior_work_evidence"),
    ),
)
def test_iteration_qc_adoption_rejects_closed_bootstrap_ledger_row(
    tmp_path: Path,
    ledger_transition: str,
    row_count: int,
    expected_code: str,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    ledger = Path("docs/governance/bootstrap-exceptions/README.md")
    ledger_path = root / ledger
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    row = (
        "| [`req-0042-r1-iteration-qc-001.md`](req-0042-r1-iteration-qc-001.md) "
        f"| `{ledger_transition}` "
        "| `.specbound/requirements/req-0042/req-0042-r1.md` "
        "| `closed` | n/a |\n"
    )
    ledger_path.write_text(
        "# Bootstrap exception ledger\n\n"
        "**Active exceptions: 0**\n\n"
        "## Inventory\n\n"
        "| Exception | Transition | Target | Status | Expiry |\n"
        "| --- | --- | --- | --- | --- |\n"
        + row * row_count,
        encoding="utf-8",
        newline="\n",
    )
    _git(root, "add", "--", ledger.as_posix())
    _git(
        root,
        "commit",
        "--quiet",
        "-m",
        "record closed exception ledger row",
        env=_git_env("2026-07-02T00:00:00+00:00"),
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        (expected_code, ledger.as_posix())
    ]


def test_iteration_qc_adoption_rejects_ledger_active_count_mismatch(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    ledger = Path("docs/governance/bootstrap-exceptions/README.md")
    ledger_path = root / ledger
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.write_text(
        "# Bootstrap exception ledger\n\n"
        "**Active exceptions: 0**\n\n"
        "## Inventory\n\n"
        "| Exception | Transition | Target | Status | Expiry |\n"
        "| --- | --- | --- | --- | --- |\n"
        "| [`req-0042-r1-iteration-qc-001.md`](req-0042-r1-iteration-qc-001.md) "
        "| `iteration_qc` | `.specbound/requirements/req-0042/req-0042-r1.md` "
        "| `active` | 2026-08-01T00:00:00Z |\n",
        encoding="utf-8",
        newline="\n",
    )
    _git(root, "add", "--", ledger.as_posix())
    _git(root, "commit", "--quiet", "-m", "record inconsistent ledger", env=_git_env("2026-07-02T00:00:00+00:00"))
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("malformed_prior_work_evidence", ledger.as_posix())
    ]


def test_iteration_qc_adoption_ignores_malformed_ledger_row_for_other_revision(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    ledger = Path("docs/governance/bootstrap-exceptions/README.md")
    ledger_path = root / ledger
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.write_text(
        "# Bootstrap exception ledger\n\n"
        "**Active exceptions: 0**\n\n"
        "## Inventory\n\n"
        "| Exception | Transition | Target | Status | Expiry |\n"
        "| --- | --- | --- | --- | --- |\n"
        "| [req-0042-r2-iteration-qc-001](req-0042-r2-iteration-qc-001.md) "
        "| `iteration_qc` | `.specbound/requirements/req-0042/req-0042-r2.md` "
        "| `closed` |\n",
        encoding="utf-8",
        newline="\n",
    )
    _git(root, "add", "--", ledger.as_posix())
    _git(root, "commit", "--quiet", "-m", "record unrelated malformed ledger row", env=_git_env("2026-07-02T00:00:00+00:00"))
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
        transition="iteration_qc",
    )

    assert result.eligible


def test_iteration_qc_adoption_rejects_duplicate_key_candidate_binding(
    tmp_path: Path,
) -> None:
    root = _init_git_repo(tmp_path)
    baseline_at = "2026-06-01T00:00:00+00:00"
    (root / ".gitkeep").write_bytes(b"")
    _git(root, "add", "--", ".gitkeep")
    _git(root, "commit", "--quiet", "-m", "capability baseline", env=_git_env(baseline_at))
    baseline = _git(root, "rev-parse", "HEAD")
    requirement, approval, _, _ = _commit_minimal_adoption_inputs(root)
    adoption = Path(
        ".specbound/adoptions/req-0042/adp-0042-r2-iteration_qc.json"
    )
    adoption_path = root / adoption
    adoption_path.parent.mkdir(parents=True, exist_ok=True)
    adoption_path.write_text(
        '{"requirement":{"path":".specbound/requirements/req-0042/req-0042-r1.md",'
        '"id":"req-0042","revision":1},'
        '"requirement":{"path":".specbound/requirements/req-0042/req-0042-r2.md",'
        '"id":"req-0042","revision":2}}\n',
        encoding="utf-8",
        newline="\n",
    )
    _git(root, "add", "--", adoption.as_posix())
    _git(root, "commit", "--quiet", "-m", "record duplicate-key adoption", env=_git_env("2026-07-02T00:00:00+00:00"))
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
        transition="iteration_qc",
    )

    assert [(blocker.code, blocker.path) for blocker in result.blockers] == [
        ("malformed_prior_work_evidence", adoption.as_posix())
    ]


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
        transition="iteration_qc",
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
        transition="iteration_qc",
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
        transition="iteration_qc",
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
        transition="iteration_qc",
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
        transition="iteration_qc",
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
        transition="iteration_qc",
    )

    assert {blocker.code for blocker in result.blockers} == {
        "requirement_introduction_not_after_baseline",
        "approval_introduction_not_after_baseline",
    }
