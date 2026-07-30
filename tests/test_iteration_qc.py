from __future__ import annotations

import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
from typing import Any

from jsonschema import Draft202012Validator
import pytest
import yaml

from specbound import control_plane_adoption, iteration_qc, validation
from specbound.iteration_qc import decide_iteration_qc
from specbound.validation import preflight

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/valid-minimal"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value))


def git(root: Path, *args: str) -> str:
    completed = subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True)
    return completed.stdout.strip()


def make_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    requirement_revision: int = 1,
    risk: str = "low",
) -> tuple[Path, Path, Path, str]:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    requirement_path = (
        f".specbound/requirements/req-0001/req-0001-r{requirement_revision}.md"
    )
    if requirement_revision != 1:
        requirement_bytes = (
            root / ".specbound/requirements/req-0001/req-0001-r1.md"
        ).read_bytes().replace(b"revision: 1", f"revision: {requirement_revision}".encode())
        (root / requirement_path).write_bytes(requirement_bytes)
    if risk != "low":
        (root / requirement_path).write_bytes(
            (root / requirement_path).read_bytes().replace(
                b"risk: low", f"risk: {risk}".encode()
            )
        )
    requirement_digest = sha256((root / requirement_path).read_bytes()).hexdigest()
    write_json(
        root
        / f".specbound/approvals/req-0001-r{requirement_revision}.approval.json",
        {
            "schema_version": 1,
            "requirement_path": requirement_path,
            "requirement_id": "req-0001",
            "revision": requirement_revision,
            "sha256": requirement_digest,
            "risk": risk,
            "authority": "fixture-maintainer",
            "approved_at": "2026-07-01T00:00:00+00:00",
        },
    )
    micro_path = root / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    micro_path.parent.mkdir(parents=True)
    micro_path.write_text(
        "---\n"
        "schema_version: 1\nid: ms-0001-003\nkind: micro-spec\n"
        "requirement:\n"
        f"  path: {requirement_path}\n  id: req-0001\n  revision: {requirement_revision}\n  sha256: {requirement_digest}\n"
        "selected_acceptance_criteria: [AC-001]\n---\n\n"
        "# IQC fixture\n\n## Objective\nBound IQC.\n\n## Scope\nAC-001.\n\n"
        "## Non-goals\nNo delivery.\n\n## Baseline\nApproved REQ.\n\n"
        "## Verification plan\nRun focused tests.\n\n## QC exit rule\nPassing evidence.\n",
        encoding="utf-8",
    )
    micro_digest = sha256(micro_path.read_bytes()).hexdigest()
    review_path = root / ".specbound/micro-spec-reviews/req-0001/ms-0001-003.review.json"
    write_json(review_path, {
        "authority": "fixture-maintainer", "decided_at": "2026-07-30T00:00:00Z",
        "decision": "approved_for_implementation", "micro_spec_id": "ms-0001-003",
        "micro_spec_path": ".specbound/micro-specs/req-0001/ms-0001-003.md",
        "micro_spec_sha256": micro_digest, "permitted_next_action": "implement_bound_micro_spec_only",
        "reason": "Independent exact fixture review accepted this bounded implementation.",
        "requirement_id": "req-0001", "requirement_path": requirement_path,
        "requirement_sha256": requirement_digest, "revision": requirement_revision, "risk": risk, "schema_version": 1,
    })
    adoption_path = root / (
        f".specbound/adoptions/req-0001/adp-0001-r{requirement_revision}-iteration_qc.json"
    )
    write_json(adoption_path, {"fixture": "exact adopted bytes"})
    (root / ".specbound/iteration-qc/req-0001").mkdir(parents=True)
    (root / ".specbound/iteration-qc/req-0001/.gitkeep").write_text("")
    config = yaml.safe_load((root / "specbound.yaml").read_text(encoding="utf-8"))
    config["policy"]["iteration_qc_authorities_by_risk"] = {
        "low": ["repository-maintainer"], "medium": ["repository-maintainer"],
        "high": ["independent-advanced-llm-reviewer"],
    }
    if risk != "low":
        config["policy"]["micro_spec_review_authorities_by_risk"][risk] = [
            "fixture-maintainer"
        ]
        config["policy"]["requirement_approval_authorities_by_risk"][risk] = [
            "fixture-maintainer"
        ]
    (root / "specbound.yaml").write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    git(root, "init", "--object-format=sha1")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "config", "user.name", "Fixture")
    git(root, "add", ".")
    git(root, "commit", "-m", "fixture")
    head = git(root, "rev-parse", "HEAD")
    adoption_digest = sha256(adoption_path.read_bytes()).hexdigest()
    state = SimpleNamespace(
        path=adoption_path.relative_to(root).as_posix(), sha256=adoption_digest,
        requirement_path=requirement_path, requirement_sha256=requirement_digest,
        requirement_id="req-0001", revision=requirement_revision,
        transition="iteration_qc", risk=risk,
        source_commit=head,
    )
    monkeypatch.setattr(iteration_qc, "check_effective_adoption", lambda *_: SimpleNamespace(valid=True, blockers=(), adoptions=(state,)))
    monkeypatch.setattr(iteration_qc, "_post_write_validation", lambda *_: ())

    implementation = tmp_path / "implementation.json"
    implementation_record = {
        "schema_version": 1, "result_id": "implementation-result-0001",
        "micro_spec": {"path": micro_path.relative_to(root).as_posix(), "id": "ms-0001-003", "sha256": micro_digest},
        "source_commit": head, "actor": "implementation-worker", "action_id": "implementation-action-0001",
        "context_id": "implementation-context-0001", "selected_acceptance_criteria": ["AC-001"],
        "verification": [{"acceptance_criterion": "AC-001", "command": "pytest -q tests/test_iteration_qc.py", "result": "passed", "exit_code": 0}],
        "verdict": "pass",
    }
    write_json(implementation, implementation_record)
    evaluation = tmp_path / "evaluation.json"
    write_json(evaluation, {
        "schema_version": 1, "result_id": "evaluation-result-0001",
        "micro_spec": implementation_record["micro_spec"],
        "implementation_result": {"result_id": implementation_record["result_id"], "sha256": sha256(implementation.read_bytes()).hexdigest()},
        "evaluator": "independent-evaluator", "action_id": "evaluation-action-0001", "context_id": "evaluation-context-0001",
        "selected_acceptance_criteria": ["AC-001"],
        "verification_sha256": sha256(canonical(implementation_record["verification"])).hexdigest(),
        "verdict": "pass", "findings": [],
    })
    return root, implementation, evaluation, head


def decide(root: Path, implementation: Path, evaluation: Path, **changes: str):
    arguments = {
        "root": root, "target_identity": "iqc-0001-003-r1",
        "implementation_result_path": implementation, "evaluation_result_path": evaluation,
        "authority_identity": "repository-maintainer", "authority_action_id": "authority-action-0001",
        "authority_context_id": "authority-context-0001",
    }
    arguments.update(changes)
    return decide_iteration_qc(**arguments)


def test_iteration_qc_schema_mirrors_and_templates_are_canonical() -> None:
    names = (
        "iteration-qc.schema.json", "iteration-qc-implementation-result.schema.json",
        "iteration-qc-evaluation-result.schema.json",
    )
    for name in names:
        root_bytes = (ROOT / "schemas" / name).read_bytes()
        assert root_bytes == (ROOT / "src/specbound/schemas" / name).read_bytes()
        parsed = json.loads(root_bytes)
        assert root_bytes == canonical(parsed)
        if name == "iteration-qc.schema.json":
            assert all(profile["additionalProperties"] is False for profile in parsed["oneOf"])
        else:
            assert parsed["additionalProperties"] is False
    template_bytes = (ROOT / "templates/iteration-qc.json").read_bytes()
    template = json.loads(template_bytes)
    assert template_bytes == canonical(template)
    Draft202012Validator(json.loads((ROOT / "schemas/iteration-qc.schema.json").read_text())).validate(template)


def test_preflight_requires_exact_closed_iteration_qc_authority_policy(tmp_path: Path) -> None:
    expected = {"low": ["repository-maintainer"], "medium": ["repository-maintainer"], "high": ["independent-advanced-llm-reviewer"]}
    for mutation in (
        {"low": ["repository-maintainer"], "medium": ["repository-maintainer"]},
        {**expected, "critical": ["repository-maintainer"]},
        {**expected, "high": ["repository-maintainer", "independent-advanced-llm-reviewer"]},
        {**expected, "low": ["repository-maintainer", "repository-maintainer"]},
        {
            "high": ["independent-advanced-llm-reviewer"],
            "low": ["repository-maintainer"],
            "medium": ["repository-maintainer"],
        },
        {"inherit": "delivery_qc_authorities_by_risk"},
    ):
        root = tmp_path / str(len(list(tmp_path.iterdir())))
        shutil.copytree(FIXTURE, root)
        config = yaml.safe_load((root / "specbound.yaml").read_text())
        config["policy"]["iteration_qc_authorities_by_risk"] = mutation
        (root / "specbound.yaml").write_text(yaml.safe_dump(config, sort_keys=False))
        assert "malformed_config" in {item["code"] for item in preflight(root).blockers}


def test_writer_publishes_exact_authority_bound_r1_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, implementation, evaluation, head = make_repository(tmp_path, monkeypatch)
    result = decide(root, implementation, evaluation)
    target = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"

    assert result.valid, result.payload()
    assert result.payload() == {"valid": True, "canonical_target": target.relative_to(root).as_posix(), "published_sha256": sha256(target.read_bytes()).hexdigest()}
    record = json.loads(target.read_bytes())
    assert target.read_bytes() == canonical(record)
    assert record["implementation_result"]["sha256"] == sha256(implementation.read_bytes()).hexdigest()
    assert record["implementation_result"]["source_commit"] == head
    assert record["evaluation_result"]["sha256"] == sha256(evaluation.read_bytes()).hexdigest()
    assert record["evaluation_result"]["implementation_result_sha256"] == record["implementation_result"]["sha256"]
    assert record["authority"] == {"identity": "repository-maintainer", "authority_action_id": "authority-action-0001", "context_id": "authority-context-0001"}
    assert record["verdict"] == "verified"
    assert record["remaining_acceptance_criteria"] == []


def test_successful_writer_preserves_every_non_target_canonical_root_byte_for_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    non_target_roots = [
        ".specbound/requirements",
        ".specbound/approvals",
        ".specbound/micro-specs",
        ".specbound/micro-spec-reviews",
        ".specbound/adoptions",
        ".specbound/canary-outcomes",
        ".specbound/activations",
        ".specbound/delivery-qc",
    ]

    def snapshot() -> dict[str, bytes]:
        return {
            path.relative_to(root).as_posix(): path.read_bytes()
            for relative in non_target_roots
            for path in (root / relative).rglob("*")
            if path.is_file()
        }

    before = snapshot()

    result = decide(root, implementation, evaluation)

    assert result.valid, result.payload()
    assert snapshot() == before


def test_writer_end_to_end_uses_real_adoption_resolver_and_full_post_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    adoption_path = root / (
        ".specbound/adoptions/req-0001/"
        "adp-0001-r1-iteration_qc.json"
    )
    adoption_path.unlink()
    (root / "specbound.yaml").write_bytes((ROOT / "specbound.yaml").read_bytes())
    source_relatives = (
        ".specbound/approvals/req-0001-r1.approval.json",
        ".specbound/requirements/req-0001/req-0001-r1.md",
    )
    post_adoption_relatives = (
        ".specbound/micro-specs/req-0001/ms-0001-003.md",
        ".specbound/micro-spec-reviews/req-0001/ms-0001-003.review.json",
    )
    for relative in (
        source_relatives[0],
        ".specbound/confirmations/dcy-0001-r1.confirmation.json",
        post_adoption_relatives[1],
    ):
        record_path = root / relative
        record = json.loads(record_path.read_bytes())
        record["authority"] = "repository-maintainer"
        if relative == source_relatives[0]:
            record["approved_at"] = "2026-07-01T00:00:00+00:00"
        write_json(record_path, record)
    staged_relatives = source_relatives + post_adoption_relatives
    target_bytes = {
        relative: (root / relative).read_bytes() for relative in staged_relatives
    }
    (root / ".specbound/iteration-qc/req-0001/.gitkeep").unlink()
    shutil.rmtree(root / ".git")
    for relative in staged_relatives:
        (root / relative).unlink()
    git(root, "init", "--quiet")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "config", "user.name", "Fixture")

    def commit_at(message: str, timestamp: str) -> None:
        environment = dict(os.environ)
        environment.update(
            GIT_AUTHOR_DATE=timestamp,
            GIT_COMMITTER_DATE=timestamp,
        )
        subprocess.run(
            ["git", "commit", "--quiet", "-m", message],
            cwd=root,
            check=True,
            env=environment,
        )

    git(root, "add", "-A")
    commit_at("establish capability baseline", "2026-06-30T00:00:00+00:00")
    baseline_commit = git(root, "rev-parse", "HEAD")
    for relative in source_relatives:
        payload = target_bytes[relative]
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    git(root, "add", "-A")
    commit_at("establish exact adoption source", "2026-07-02T00:00:00+00:00")
    source_commit = git(root, "rev-parse", "HEAD")
    baseline_at = git(root, "show", "-s", "--format=%cI", baseline_commit)
    decided_at = git(root, "show", "-s", "--format=%cI", source_commit)
    requirement_path = root / ".specbound/requirements/req-0001/req-0001-r1.md"
    adoption = json.loads(
        (ROOT / "templates/adoption-decision.json").read_bytes()
    )
    adoption.update(
        adoption_id="adp-0001-r1-iteration_qc",
        adoption_source_commit=source_commit,
        authority="repository-maintainer",
        authority_action_id="adoption-authority-action-0001",
        canary_capability_baseline_at=baseline_at,
        canary_capability_baseline_commit=baseline_commit,
        canary_work_attested_at=decided_at,
        canary_work_attested_by="repository-maintainer",
        context_id="adoption-context-0001",
        decided_at=decided_at,
        risk="low",
    )
    adoption["authority_policy"]["sha256"] = sha256(
        (root / "specbound.yaml").read_bytes()
    ).hexdigest()
    adoption["requirement"] = {
        "path": requirement_path.relative_to(root).as_posix(),
        "id": "req-0001",
        "revision": 1,
        "sha256": sha256(requirement_path.read_bytes()).hexdigest(),
    }
    write_json(adoption_path, adoption)
    git(root, "add", adoption_path.relative_to(root).as_posix())
    commit_at("record real exact adoption", "2026-07-03T00:00:00+00:00")
    for relative in post_adoption_relatives:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(target_bytes[relative])
    git(root, "add", "-A")
    commit_at("approve exact micro spec", "2026-07-04T00:00:00+00:00")
    implementation_record = json.loads(implementation.read_bytes())
    implementation_record["source_commit"] = git(root, "rev-parse", "HEAD")
    write_json(implementation, implementation_record)
    evaluation_record = json.loads(evaluation.read_bytes())
    evaluation_record["implementation_result"]["sha256"] = sha256(
        implementation.read_bytes()
    ).hexdigest()
    write_json(evaluation, evaluation_record)
    monkeypatch.undo()

    adoption_state, adoption_blockers = (
        control_plane_adoption.resolve_adoption_read_state(
            root, adoption_path.relative_to(root).as_posix()
        )
    )
    registry = iteration_qc.check_effective_adoption(
        root, "req-0001-r1", "iteration_qc"
    )
    result = decide(root, implementation, evaluation)

    assert adoption_state is not None, [
        (blocker.code, blocker.path, blocker.detail) for blocker in adoption_blockers
    ]
    assert registry.valid, registry.payload()
    assert result.valid, result.payload()
    assert validation.validate(root).valid

    approval_path = root / source_relatives[0]
    approval_record = json.loads(target_bytes[source_relatives[0]])
    approval_record["authority"] = "untrusted-but-nonempty"
    write_json(approval_path, approval_record)
    authority_tamper = validation.validate(root)
    assert "iteration_qc_requirement_binding_mismatch" in {
        blocker["code"] for blocker in authority_tamper.blockers
    }

    approval_record = json.loads(target_bytes[source_relatives[0]])
    approval_record["reason"] = "canonical bytes that were not adopted"
    write_json(approval_path, approval_record)
    source_drift = validation.validate(root)
    assert "invalid_iteration_qc_adoption" in {
        blocker["code"] for blocker in source_drift.blockers
    }

    approval_path.write_bytes(
        target_bytes[source_relatives[0]].replace(
            b"{\n",
            b'{\n  "authority": "repository-maintainer",\n',
            1,
        )
    )
    duplicate_key = validation.validate(root)
    assert "invalid_iteration_qc_binding" in {
        blocker["code"] for blocker in duplicate_key.blockers
    }


def test_high_risk_writer_requires_independent_advanced_llm_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, implementation, evaluation, _ = make_repository(
        tmp_path, monkeypatch, risk="high"
    )

    rejected = decide(root, implementation, evaluation)
    accepted = decide(
        root,
        implementation,
        evaluation,
        authority_identity="independent-advanced-llm-reviewer",
    )

    assert {blocker.code for blocker in rejected.blockers} == {
        "unauthorized_iteration_qc_authority"
    }
    assert accepted.valid, accepted.payload()


def test_writer_derives_noninitial_parent_requirement_revision_from_micro_spec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, implementation, evaluation, _ = make_repository(
        tmp_path, monkeypatch, requirement_revision=2
    )

    result = decide(root, implementation, evaluation)

    assert result.valid, result.payload()
    record = json.loads(
        (root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json").read_bytes()
    )
    assert record["requirement"]["revision"] == 2
    assert record["requirement"]["path"].endswith("req-0001-r2.md")
    assert record["adoption"]["path"].endswith("adp-0001-r2-iteration_qc.json")


def test_validator_accepts_authority_bound_record_for_noninitial_parent_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, implementation, evaluation, _ = make_repository(
        tmp_path, monkeypatch, requirement_revision=2
    )
    assert decide(root, implementation, evaluation).valid
    target = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"
    adoption_state = iteration_qc.check_effective_adoption(
        root, "req-0001-r2", "iteration_qc"
    ).adoptions[0]
    monkeypatch.setattr(
        validation,
        "check_effective_adoption",
        lambda *_: SimpleNamespace(
            valid=True, blockers=(), adoptions=(adoption_state,)
        ),
    )
    result = validation.Result(root=root)

    validation._validate_qc_record(root, target, result, "iteration_qc")

    assert result.valid, result.blockers


@pytest.mark.parametrize(("changes", "code"), [
    ({"authority_identity": "implementation-worker"}, "iteration_qc_self_qc"),
    ({"authority_action_id": "evaluation-action-0001"}, "iteration_qc_action_collision"),
    ({"authority_context_id": "implementation-context-0001"}, "iteration_qc_context_collision"),
    ({"authority_identity": "untrusted"}, "unauthorized_iteration_qc_authority"),
    ({"target_identity": "iqc-0001-003-r2"}, "invalid_iteration_qc_target"),
    ({"target_identity": "../iqc-0001-003-r1"}, "invalid_iteration_qc_target"),
])
def test_writer_rejects_authority_overlap_and_noncanonical_targets_without_mutation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changes: dict[str, str], code: str) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    result = decide(root, implementation, evaluation, **changes)
    assert not result.valid
    assert code in {item.code for item in result.blockers}
    assert not any((root / ".specbound/iteration-qc").rglob("*.json"))


def test_writer_rejects_dirty_or_stale_evidence_before_publication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    (root / "untracked").write_text("dirty")
    result = decide(root, implementation, evaluation)
    assert {item.code for item in result.blockers} == {"dirty_worktree"}
    assert not any((root / ".specbound/iteration-qc").rglob("*.json"))


def test_writer_rechecks_clean_snapshot_immediately_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    original_git_contract = iteration_qc._git_contract
    injected = False

    def inject_after_initial_check(candidate_root: Path, target: str) -> tuple[
        str | None, iteration_qc.IQCBlocker | None
    ]:
        nonlocal injected
        contract = original_git_contract(candidate_root, target)
        if not injected and contract[1] is None:
            (candidate_root / "dirty-after-initial-check.txt").write_text(
                "dirty", encoding="utf-8"
            )
            injected = True
        return contract

    monkeypatch.setattr(iteration_qc, "_git_contract", inject_after_initial_check)

    result = decide(root, implementation, evaluation)

    assert injected
    assert {blocker.code for blocker in result.blockers} == {"dirty_worktree"}
    assert not any((root / ".specbound/iteration-qc").rglob("*.json"))


def test_writer_rechecks_repository_snapshot_after_post_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    target = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"

    def dirty_after_validation(
        *_: Any,
    ) -> tuple[iteration_qc.IQCBlocker, ...]:
        (root / "late-race.txt").write_text("raced\n", encoding="utf-8")
        return ()

    monkeypatch.setattr(iteration_qc, "_post_write_validation", dirty_after_validation)

    result = decide(root, implementation, evaluation)

    assert {blocker.code for blocker in result.blockers} == {"dirty_worktree"}
    assert not target.exists()


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("stale-source", "stale_iteration_qc_source_commit"),
        ("implementation-edge", "iteration_qc_evaluation_binding_mismatch"),
        ("ac-set", "iteration_qc_implementation_binding_mismatch"),
        ("failed-evidence", "malformed_iteration_qc_input"),
        ("failed-evaluator", "malformed_iteration_qc_input"),
        ("duplicate-key", "malformed_iteration_qc_input"),
    ],
)
def test_writer_rejects_stale_mismatched_or_failed_result_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    code: str,
) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    implementation_record = json.loads(implementation.read_bytes())
    evaluation_record = json.loads(evaluation.read_bytes())
    if case == "stale-source":
        implementation_record["source_commit"] = "0" * 40
    elif case == "implementation-edge":
        evaluation_record["implementation_result"]["sha256"] = "0" * 64
    elif case == "ac-set":
        implementation_record["selected_acceptance_criteria"] = ["AC-999"]
    elif case == "failed-evidence":
        implementation_record["verification"][0].update(
            result="failed", exit_code=1
        )
    elif case == "failed-evaluator":
        evaluation_record.update(verdict="rework", findings=["failed"])
    else:
        implementation.write_bytes(
            b'{"schema_version": 1, "schema_version": 1}\n'
        )

    if case != "duplicate-key":
        write_json(implementation, implementation_record)
        if case != "implementation-edge":
            evaluation_record["implementation_result"]["sha256"] = sha256(
                implementation.read_bytes()
            ).hexdigest()
        write_json(evaluation, evaluation_record)

    result = decide(root, implementation, evaluation)

    assert not result.valid
    assert code in {blocker.code for blocker in result.blockers}
    assert not any((root / ".specbound/iteration-qc").rglob("*.json"))


@pytest.mark.parametrize("existing_revision", [1, 2])
def test_writer_preserves_existing_target_but_ignores_legacy_history_for_live_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing_revision: int,
) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    existing = root / (
        ".specbound/iteration-qc/req-0001/"
        f"iqc-0001-003-r{existing_revision}.json"
    )
    if existing_revision == 1:
        existing_bytes = b'{"preexisting": true}\n'
        existing.write_bytes(existing_bytes)
    else:
        micro_path = root / ".specbound/micro-specs/req-0001/ms-0001-003.md"
        write_json(
            existing,
            {
                "schema_version": 1,
                "micro_spec": {
                    "path": micro_path.relative_to(root).as_posix(),
                    "id": "ms-0001-003",
                    "sha256": sha256(micro_path.read_bytes()).hexdigest(),
                },
                "selected_acceptance_criteria": ["AC-001"],
                "verification": [
                    {"command": "true", "result": "passed", "exit_code": 0}
                ],
                "verdict": "verified",
                "remaining_acceptance_criteria": [],
            },
        )
        existing_bytes = existing.read_bytes()
    git(root, "add", existing.relative_to(root).as_posix())
    git(root, "commit", "-m", "pre-existing IQC")
    implementation_record = json.loads(implementation.read_bytes())
    implementation_record["source_commit"] = git(root, "rev-parse", "HEAD")
    write_json(implementation, implementation_record)
    evaluation_record = json.loads(evaluation.read_bytes())
    evaluation_record["implementation_result"]["sha256"] = sha256(
        implementation.read_bytes()
    ).hexdigest()
    write_json(evaluation, evaluation_record)

    result = decide(root, implementation, evaluation)

    if existing_revision == 1:
        assert not result.valid
        assert {blocker.code for blocker in result.blockers} == {
            "iteration_qc_already_exists"
        }
    else:
        assert result.valid, result.payload()
    assert existing.read_bytes() == existing_bytes


def test_failure_atomic_cleanup_preserves_replacement_winner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    target = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"

    def replace_and_fail(*_: object) -> tuple[iteration_qc.IQCBlocker, ...]:
        target.unlink()
        target.write_bytes(b"winner")
        return (iteration_qc.IQCBlocker("iteration_qc_post_validation_failed", target.relative_to(root).as_posix(), "injected"),)

    monkeypatch.setattr(iteration_qc, "_post_write_validation", replace_and_fail)
    result = decide(root, implementation, evaluation)
    assert not result.valid
    assert target.read_bytes() == b"winner"


def test_owned_leaf_cleanup_does_not_unlink_winner_swapped_during_ownership_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    target = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"owned")
    held_owned_leaf = target.open("rb")
    initial = target.stat()
    owned = (initial.st_dev, initial.st_ino)
    original_rename = iteration_qc.os.rename
    swapped = False

    def swap_before_rename(
        source: Any, destination: Any, *args: Any, **kwargs: Any
    ) -> None:
        nonlocal swapped
        if Path(source).name == target.name and not swapped:
            target.unlink()
            target.write_bytes(b"winner")
            swapped = True
        original_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(iteration_qc.os, "rename", swap_before_rename)

    iteration_qc._remove_if_owned(
        root,
        target.relative_to(root).as_posix(),
        owned,
    )

    assert swapped
    assert target.read_bytes() == b"winner"
    held_owned_leaf.close()


def test_owned_leaf_cleanup_restores_directory_replacement_winner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    target = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"owned")
    held_owned_leaf = target.open("rb")
    initial = target.stat()
    owned = (initial.st_dev, initial.st_ino)
    original_rename = iteration_qc.os.rename
    swapped = False

    def swap_directory_before_rename(
        source: Any, destination: Any, *args: Any, **kwargs: Any
    ) -> None:
        nonlocal swapped
        if Path(source).name == target.name and not swapped:
            target.unlink()
            target.mkdir()
            (target / "winner.txt").write_bytes(b"directory-winner")
            swapped = True
        original_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(iteration_qc.os, "rename", swap_directory_before_rename)

    iteration_qc._remove_if_owned(
        root,
        target.relative_to(root).as_posix(),
        owned,
    )

    assert swapped
    assert (target / "winner.txt").read_bytes() == b"directory-winner"
    assert not tuple(target.parent.glob(f".{target.name}.rollback-*"))
    held_owned_leaf.close()


def test_owned_leaf_cleanup_preserves_two_concurrent_replacement_winners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    target = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"owned")
    held_owned_leaf = target.open("rb")
    initial = target.stat()
    owned = (initial.st_dev, initial.st_ino)
    original_rename = iteration_qc.os.rename
    original_noreplace = iteration_qc._rename_noreplace
    first_swapped = False
    second_swapped = False

    def swap_first_before_rename(
        source: Any, destination: Any, *args: Any, **kwargs: Any
    ) -> None:
        nonlocal first_swapped
        if Path(source).name == target.name and not first_swapped:
            target.unlink()
            target.write_bytes(b"replacement-one")
            first_swapped = True
        original_rename(source, destination, *args, **kwargs)

    def swap_second_before_restore(parent_fd: int, source: str, destination: str) -> None:
        nonlocal second_swapped
        target.write_bytes(b"replacement-two")
        second_swapped = True
        original_noreplace(parent_fd, source, destination)

    monkeypatch.setattr(iteration_qc.os, "rename", swap_first_before_rename)
    monkeypatch.setattr(iteration_qc, "_rename_noreplace", swap_second_before_restore)

    iteration_qc._remove_if_owned(
        root,
        target.relative_to(root).as_posix(),
        owned,
    )

    quarantined = tuple(target.parent.glob(f".{target.name}.rollback-*"))
    assert first_swapped and second_swapped
    assert target.read_bytes() == b"replacement-two"
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == b"replacement-one"
    held_owned_leaf.close()


@pytest.mark.parametrize(
    "stage",
    [
        "unsupported_open", "write", "file_fsync", "directory_fsync",
        "final_read", "post_validation",
    ],
)
def test_failure_atomic_publication_removes_only_owned_partial_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    target = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"

    if stage == "unsupported_open":
        original_open = iteration_qc.os.open

        def fail_target_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            if Path(path).name == target.name and flags & iteration_qc.os.O_EXCL:
                raise OSError(errno.ENOSYS, "injected unavailable O_EXCL primitive")
            return original_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(iteration_qc.os, "open", fail_target_open)
    elif stage == "write":
        def fail_write(fd: int, _: bytes) -> None:
            assert iteration_qc.os.write(fd, b"partial") == 7
            raise OSError("injected write failure")

        monkeypatch.setattr(iteration_qc, "_write_published_bytes", fail_write)
    elif stage in {"file_fsync", "directory_fsync"}:
        original_fsync = iteration_qc._fsync_descriptor
        calls = 0

        def fail_fsync(fd: int) -> None:
            nonlocal calls
            calls += 1
            if (stage == "file_fsync" and calls == 1) or (
                stage == "directory_fsync" and calls == 2
            ):
                raise OSError(f"injected {stage} failure")
            original_fsync(fd)

        monkeypatch.setattr(iteration_qc, "_fsync_descriptor", fail_fsync)
    elif stage == "final_read":
        monkeypatch.setattr(
            iteration_qc,
            "_final_published_bytes",
            lambda _: (_ for _ in ()).throw(OSError("injected final-read failure")),
        )
    else:
        monkeypatch.setattr(
            iteration_qc,
            "_post_write_validation",
            lambda *_: (_ for _ in ()).throw(RuntimeError("injected post-validation failure")),
        )

    result = decide(root, implementation, evaluation)

    assert not result.valid
    assert not target.exists()


@pytest.mark.parametrize("failure", ["missing", "runtime-rejected"])
def test_writer_rejects_unavailable_atomic_noreplace_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    target = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"
    calls = 0
    if failure == "missing":
        monkeypatch.setattr(iteration_qc, "_RENAMEAT2", None)
    else:
        def rejected(*_: object) -> int:
            nonlocal calls
            calls += 1
            iteration_qc.ctypes.set_errno(errno.ENOSYS)
            return -1

        monkeypatch.setattr(iteration_qc, "_RENAMEAT2", rejected)

    result = decide(root, implementation, evaluation)

    assert {blocker.code for blocker in result.blockers} == {"unsupported_platform"}
    assert calls == (1 if failure == "runtime-rejected" else 0)
    assert not target.exists()


def test_same_evaluator_and_authority_identity_is_allowed_with_distinct_action_and_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    evaluation_record = json.loads(evaluation.read_bytes())
    evaluation_record["evaluator"] = "repository-maintainer"
    write_json(evaluation, evaluation_record)
    # Rebind the evaluation input's own implementation edge is unchanged by this edit.
    result = decide(root, implementation, evaluation)
    assert result.valid, result.payload()


def test_writer_rejects_implementation_actor_as_evaluator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    evaluation_record = json.loads(evaluation.read_bytes())
    evaluation_record["evaluator"] = "implementation-worker"
    write_json(evaluation, evaluation_record)

    result = decide(root, implementation, evaluation)

    assert not result.valid
    assert {blocker.code for blocker in result.blockers} == {
        "iteration_qc_self_qc"
    }
    assert not any((root / ".specbound/iteration-qc").rglob("*.json"))


def test_writer_rejects_blank_or_non_nfc_result_strings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for index, actor in enumerate(("   ", "e\u0301valuator")):
        case_root = tmp_path / str(index)
        case_root.mkdir()
        root, implementation, evaluation, _ = make_repository(
            case_root, monkeypatch
        )
        implementation_record = json.loads(implementation.read_bytes())
        implementation_record["actor"] = actor
        write_json(implementation, implementation_record)
        evaluation_record = json.loads(evaluation.read_bytes())
        evaluation_record["implementation_result"]["sha256"] = sha256(
            implementation.read_bytes()
        ).hexdigest()
        write_json(evaluation, evaluation_record)

        result = decide(root, implementation, evaluation)

        assert {blocker.code for blocker in result.blockers} == {
            "malformed_iteration_qc_input"
        }
        assert not any((root / ".specbound/iteration-qc").rglob("*.json"))


@pytest.mark.parametrize(
    "case",
    [
        "approval-authority",
        "approval-duplicate-key",
        "approval-noncanonical",
        "approval-source-drift",
        "review-extra-field",
    ],
)
def test_writer_rejects_invalid_approval_or_review_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    if case.startswith("approval"):
        artifact = root / ".specbound/approvals/req-0001-r1.approval.json"
        record = json.loads(artifact.read_bytes())
        if case == "approval-authority":
            record["authority"] = "untrusted"
            write_json(artifact, record)
        elif case == "approval-duplicate-key":
            artifact.write_bytes(
                artifact.read_bytes().replace(
                    b"{\n",
                    b'{\n  "authority": "fixture-maintainer",\n',
                    1,
                )
            )
        elif case == "approval-source-drift":
            record["unexpected"] = "canonical but not adopted"
            write_json(artifact, record)
        else:
            artifact.write_bytes(
                json.dumps(record, ensure_ascii=False).encode("utf-8") + b"\n"
            )
    else:
        artifact = root / ".specbound/micro-spec-reviews/req-0001/ms-0001-003.review.json"
        record = json.loads(artifact.read_bytes())
        record["unexpected"] = True
        write_json(artifact, record)
    git(root, "add", artifact.relative_to(root).as_posix())
    git(root, "commit", "-m", "invalid binding fixture")
    implementation_record = json.loads(implementation.read_bytes())
    implementation_record["source_commit"] = git(root, "rev-parse", "HEAD")
    write_json(implementation, implementation_record)
    evaluation_record = json.loads(evaluation.read_bytes())
    evaluation_record["implementation_result"]["sha256"] = sha256(
        implementation.read_bytes()
    ).hexdigest()
    write_json(evaluation, evaluation_record)
    published = False

    def unexpected_publish(*_: object) -> object:
        nonlocal published
        published = True
        raise AssertionError("publication must not be attempted")

    monkeypatch.setattr(iteration_qc, "_publish", unexpected_publish)
    result = decide(root, implementation, evaluation)

    expected = (
        "invalid_iteration_qc_requirement_binding"
        if case == "approval-authority"
        else (
            "malformed_iteration_qc_bindings"
            if case in {"approval-duplicate-key", "approval-noncanonical"}
            else (
                "invalid_iteration_qc_adoption"
                if case == "approval-source-drift"
                else "invalid_iteration_qc_micro_spec_review_binding"
            )
        )
    )
    assert {blocker.code for blocker in result.blockers} == {expected}
    assert not published
    assert not any((root / ".specbound/iteration-qc").rglob("*.json"))


@pytest.mark.parametrize("case", ["invalid-time", "non-nfc", "mixed-profile"])
def test_validator_rejects_invalid_authority_profile_text_and_shape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    assert decide(root, implementation, evaluation).valid
    target = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"
    record = json.loads(target.read_bytes())
    if case == "invalid-time":
        record["decided_at"] = "not-rfc3339Z"
    elif case == "non-nfc":
        record["implementation_result"]["actor"] = "e\u0301valuator"
    else:
        record.pop("authority")
        record["legacy_extra"] = True
    write_json(target, record)
    adoption_state = iteration_qc.check_effective_adoption(
        root, "req-0001-r1", "iteration_qc"
    ).adoptions[0]
    monkeypatch.setattr(
        validation,
        "check_effective_adoption",
        lambda *_: SimpleNamespace(
            valid=True, blockers=(), adoptions=(adoption_state,)
        ),
    )
    result = validation.Result(root=root)

    validation._validate_qc_record(root, target, result, "iteration_qc")

    assert "malformed_iteration_qc" in {
        blocker["code"] for blocker in result.blockers
    }


def test_validator_rejects_authority_bound_conflicting_r2_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    assert decide(root, implementation, evaluation).valid
    source = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"
    target = source.with_name("iqc-0001-003-r2.json")
    source.rename(target)
    adoption_state = iteration_qc.check_effective_adoption(
        root, "req-0001-r1", "iteration_qc"
    ).adoptions[0]
    monkeypatch.setattr(
        validation,
        "check_effective_adoption",
        lambda *_: SimpleNamespace(
            valid=True, blockers=(), adoptions=(adoption_state,)
        ),
    )
    result = validation.Result(root=root)

    validation._validate_qc_record(root, target, result, "iteration_qc")

    assert "iteration_qc_revision_conflict" in {
        blocker["code"] for blocker in result.blockers
    }


def test_publication_handoff_detects_same_bytes_replacement_and_preserves_winner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    target = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"
    original_read_bytes = Path.read_bytes
    replaced = False

    def replace_on_handoff(path: Path) -> bytes:
        nonlocal replaced
        if path == target and not replaced:
            content = original_read_bytes(path)
            path.unlink()
            path.write_bytes(content)
            replaced = True
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", replace_on_handoff)

    result = decide(root, implementation, evaluation)

    assert not result.valid
    assert {blocker.code for blocker in result.blockers} == {
        "iteration_qc_publication_handoff_failed"
    }
    assert replaced
    assert target.exists()


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("sha256", "unsupported_git_object_format"),
        ("missing-head", "git_query_failed"),
        ("shallow", "shallow_repository"),
    ],
)
def test_writer_rejects_unsupported_or_incomplete_git_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    code: str,
) -> None:
    root, implementation, evaluation, head = make_repository(tmp_path, monkeypatch)
    target_root = root
    if case == "sha256":
        shutil.rmtree(root / ".git")
        git(root, "init", "--object-format=sha256")
        git(root, "config", "user.email", "fixture@example.invalid")
        git(root, "config", "user.name", "Fixture")
        git(root, "add", ".")
        git(root, "commit", "-m", "sha256 fixture")
    elif case == "missing-head":
        (root / ".git/objects" / head[:2] / head[2:]).unlink()
    else:
        target_root = tmp_path / "shallow"
        subprocess.run(
            [
                "git", "clone", "--quiet", "--depth=1",
                root.resolve().as_uri(), str(target_root),
            ],
            check=True,
        )

    result = decide(target_root, implementation, evaluation)

    assert {blocker.code for blocker in result.blockers} == {code}
    assert not any(
        (target_root / ".specbound/iteration-qc").rglob("iqc-*.json")
    )


def test_writer_rejects_symlinked_canonical_parent_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    family = root / ".specbound/iteration-qc/req-0001"
    shutil.rmtree(family)
    outside = tmp_path / "outside"
    outside.mkdir()
    family.symlink_to(outside, target_is_directory=True)
    git(root, "add", "-A")
    git(root, "commit", "-m", "symlink fixture")

    result = decide(root, implementation, evaluation)

    assert {blocker.code for blocker in result.blockers} == {
        "unsafe_iteration_qc_target"
    }
    assert not any(outside.iterdir())


@pytest.mark.parametrize("case", ["missing", "wrong-transition", "conflicting"])
def test_writer_rejects_invalid_effective_adoption_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    root, implementation, evaluation, _ = make_repository(tmp_path, monkeypatch)
    base = iteration_qc.check_effective_adoption(
        root, "req-0001-r1", "iteration_qc"
    ).adoptions[0]
    if case == "missing":
        registry = SimpleNamespace(
            valid=False,
            blockers=(SimpleNamespace(code="control_plane_not_adopted"),),
            adoptions=(),
        )
    elif case == "wrong-transition":
        wrong = SimpleNamespace(
            path=base.path,
            sha256=base.sha256,
            transition="delivery_qc",
            requirement_path=base.requirement_path,
            requirement_id=base.requirement_id,
            revision=base.revision,
            requirement_sha256=base.requirement_sha256,
            risk=base.risk,
            source_commit=base.source_commit,
        )
        registry = SimpleNamespace(valid=True, blockers=(), adoptions=(wrong,))
    else:
        registry = SimpleNamespace(
            valid=True, blockers=(), adoptions=(base, base)
        )
    monkeypatch.setattr(
        iteration_qc,
        "check_effective_adoption",
        lambda *_: registry,
    )

    result = decide(root, implementation, evaluation)

    assert {blocker.code for blocker in result.blockers} == {
        "invalid_iteration_qc_adoption"
    }
    assert not any((root / ".specbound/iteration-qc").rglob("*.json"))
