from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from specbound import issuance_request

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
FIXTURE_REQUIREMENT = FIXTURES / "valid-minimal/docs/requirements/req-0001/req-0001-r1.md"


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "specbound.cli", *args],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        check=False,
        capture_output=True,
        text=True,
    )


def payload(result: subprocess.CompletedProcess[str]) -> dict:
    return json.loads(result.stdout)


def copied_fixture(tmp_path: Path) -> Path:
    fixture = tmp_path / "issuance-request"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    return fixture


def write_candidate(fixture: Path, text: str) -> Path:
    candidate = fixture / "candidate.md"
    candidate.write_text(text, encoding="utf-8")
    return candidate


def valid_micro_spec_candidate() -> str:
    digest = sha256(FIXTURE_REQUIREMENT.read_bytes()).hexdigest()
    return f'''---
schema_version: 1
id: ms-0001-003
kind: micro-spec
requirement:
  path: docs/requirements/req-0001/req-0001-r1.md
  id: req-0001
  revision: 1
  sha256: "{digest}"
selected_acceptance_criteria: [AC-001]
---

# Fixture Micro-SPEC

## Objective

Validate the fixture request without publication.

## Scope

- Read-only validation only.

## Non-goals

- Publication.

## Baseline

The parent REQ is approved.

## Verification plan

- Run fixture tests.

## QC exit rule

- This is not QC authority.
'''


def valid_iteration_qc_candidate(micro_spec: Path, selected: list[str] | None = None) -> str:
    selected = selected or ["AC-001"]
    return json.dumps(
        {
            "schema_version": 1,
            "micro_spec": {
                "path": ".specbound/micro-specs/req-0001/ms-0001-003.md",
                "id": "ms-0001-003",
                "sha256": sha256(micro_spec.read_bytes()).hexdigest(),
            },
            "selected_acceptance_criteria": selected,
            "verification": [{"command": ".venv/bin/python -m pytest", "result": "passed", "exit_code": 0}],
            "verdict": "verified",
            "remaining_acceptance_criteria": [],
        }
    )


def test_cg1_micro_spec_reviews_bind_exact_req0003_ac_coverage() -> None:
    requirement = ROOT / "docs/requirements/req-0003/req-0003-r2.md"
    requirement_digest = sha256(requirement.read_bytes()).hexdigest()
    expected = {
        "002": "[AC-001, AC-002]",
        "003": "[AC-003]",
        "004": "[AC-004]",
        "005": "[AC-005]",
        "006": "[AC-006]",
        "007": "[AC-007]",
        "008": "[AC-008]",
        "009": "[AC-001, AC-002, AC-003, AC-004, AC-005, AC-006, AC-007, AC-008]",
    }

    for slice_id, selected in expected.items():
        micro = ROOT / f".specbound/micro-specs/req-0003/ms-0003-{slice_id}.md"
        review = json.loads((ROOT / f".specbound/micro-spec-reviews/req-0003/ms-0003-{slice_id}.review.json").read_text(encoding="utf-8"))

        assert f"selected_acceptance_criteria: {selected}" in micro.read_text(encoding="utf-8")
        assert review["decision"] == "approved_for_implementation"
        assert review["requirement_sha256"] == requirement_digest
        assert review["micro_spec_sha256"] == sha256(micro.read_bytes()).hexdigest()


def test_issuance_request_prevalidates_a_complete_micro_spec_without_creating_target(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    candidate = write_candidate(fixture, valid_micro_spec_candidate())
    target = fixture / ".specbound/micro-specs/req-0001/ms-0001-003.md"

    result = run_cli(
        "--root", str(fixture), "issuance-request", "micro-spec", "ms-0001-003", "--candidate-file", str(candidate)
    )

    assert result.returncode == 0, result.stdout
    assert payload(result) == {
        "artifact_kind": "micro-spec",
        "canonical_target": ".specbound/micro-specs/req-0001/ms-0001-003.md",
        "operation": "prevalidation_only",
        "valid": True,
    }
    assert not target.exists()


@pytest.mark.parametrize(
    ("kind", "target", "candidate_text", "expected_code"),
    (
        ("unknown", "ms-0001-003", "content", "unknown_artifact_kind"),
        ("micro-spec", "../ms-0001-003", "content", "invalid_canonical_target"),
        ("micro-spec", "/tmp/ms-0001-003", "content", "invalid_canonical_target"),
        ("micro-spec", "ms-0001-003/alias", "content", "invalid_canonical_target"),
        ("micro-spec", "ms-0001-003", "", "incomplete_candidate_content"),
        ("micro-spec", "ms-0001-003", "---\nid: ms-0001-003\n---\n", "invalid_candidate_schema"),
    ),
)
def test_issuance_request_rejects_invalid_requests_without_target_mutation(
    tmp_path: Path, kind: str, target: str, candidate_text: str, expected_code: str
) -> None:
    fixture = copied_fixture(tmp_path)
    candidate = write_candidate(fixture, candidate_text)
    requested_target = fixture / ".specbound/micro-specs/req-0001/ms-0001-003.md"

    result = run_cli(
        "--root", str(fixture), "issuance-request", kind, target, "--candidate-file", str(candidate)
    )

    assert result.returncode == 2, result.stdout
    body = payload(result)
    assert body["valid"] is False
    assert expected_code in {blocker["code"] for blocker in body["blockers"]}
    assert not requested_target.exists()


def test_issuance_request_requires_complete_candidate_content_without_target_mutation(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    result = run_cli("--root", str(fixture), "issuance-request", "micro-spec", "ms-0001-003")

    assert result.returncode == 2, result.stdout
    assert "incomplete_candidate_content" in {blocker["code"] for blocker in payload(result)["blockers"]}
    assert not (fixture / ".specbound/micro-specs/req-0001/ms-0001-003.md").exists()


def test_issuance_request_rejects_malformed_configured_canonical_roots(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    candidate = write_candidate(fixture, valid_micro_spec_candidate())
    config = fixture / "specbound.yaml"
    config.write_text(config.read_text(encoding="utf-8").replace("micro_specs_root: .specbound/micro-specs", "micro_specs_root: unsafe-root"), encoding="utf-8")

    result = run_cli(
        "--root", str(fixture), "issuance-request", "micro-spec", "ms-0001-003", "--candidate-file", str(candidate)
    )

    assert result.returncode == 2, result.stdout
    assert "malformed_config" in {blocker["code"] for blocker in payload(result)["blockers"]}
    assert not (fixture / ".specbound/micro-specs/req-0001/ms-0001-003.md").exists()


def test_issuance_request_rejects_stale_micro_spec_parent_without_target_mutation(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    candidate = write_candidate(
        fixture,
        valid_micro_spec_candidate().replace(
            sha256(FIXTURE_REQUIREMENT.read_bytes()).hexdigest(),
            "0" * 64,
        ),
    )

    result = run_cli(
        "--root", str(fixture), "issuance-request", "micro-spec", "ms-0001-003", "--candidate-file", str(candidate)
    )

    assert result.returncode == 2, result.stdout
    assert "stale_parent_digest" in {blocker["code"] for blocker in payload(result)["blockers"]}
    assert not (fixture / ".specbound/micro-specs/req-0001/ms-0001-003.md").exists()


@pytest.mark.parametrize(
    ("kind", "target", "candidate"),
    (
        (
            "iteration-qc",
            "iqc-0003-003-r1",
            '{"schema_version":1,"micro_spec":{"path":".specbound/micro-specs/req-0001/ms-0001-003.md","id":"ms-0001-003","sha256":"' + "0" * 64 + '"},"selected_acceptance_criteria":["AC-001"],"verification":[{"command":"true","result":"passed","exit_code":0}],"verdict":"verified","remaining_acceptance_criteria":[]}',
        ),
        (
            "delivery-qc",
            "dqc-0003-r1",
            '{"schema_version":1,"requirement":{"path":"docs/requirements/req-0003/req-0003-r2.md","id":"req-0003","revision":2,"sha256":"' + "0" * 64 + '"},"coverage":[{"acceptance_criterion":"AC-001","iteration_qc":{"path":".specbound/iteration-qc/req-0003/iqc-0003-003-r1.json","sha256":"' + "0" * 64 + '"}}],"regression_evidence":[{"command":"true","result":"passed","exit_code":0}],"authority":"repository-maintainer","residual_risk":{"unresolved_exceptions":[],"disposition":"none"},"verdict":"verified"}',
        ),
    ),
)
def test_issuance_request_rejects_invalid_qc_parent_graph_before_publication(
    tmp_path: Path, kind: str, target: str, candidate: str
) -> None:
    fixture = copied_fixture(tmp_path)
    candidate_path = write_candidate(fixture, candidate)

    result = run_cli(
        "--root", str(fixture), "issuance-request", kind, target, "--candidate-file", str(candidate_path)
    )

    assert result.returncode == 2, result.stdout
    assert payload(result)["valid"] is False
    assert payload(result)["blockers"]
    assert not any((fixture / ".specbound").rglob(target))


def test_micro_spec_publish_creates_only_a_non_claiming_target_after_exact_parent_approval_validation(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    candidate_text = valid_micro_spec_candidate()
    candidate = write_candidate(fixture, candidate_text)
    target = fixture / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    target.parent.mkdir()
    before = {
        path.relative_to(fixture): sha256(path.read_bytes()).hexdigest()
        for path in fixture.rglob("*")
        if path.is_file()
    }

    result = run_cli(
        "--root", str(fixture), "issuance-request", "micro-spec", "ms-0001-003", "--candidate-file", str(candidate), "--publish"
    )

    assert result.returncode == 0, result.stdout
    assert payload(result) == {
        "artifact_kind": "micro-spec",
        "canonical_identity": "ms-0001-003",
        "canonical_target": ".specbound/micro-specs/req-0001/ms-0001-003.md",
        "operation": "published_pre_adoption_micro_spec",
        "published_sha256": sha256(candidate_text.encode()).hexdigest(),
        "valid": True,
    }
    assert target.read_text(encoding="utf-8") == candidate_text
    after = {
        path.relative_to(fixture): sha256(path.read_bytes()).hexdigest()
        for path in fixture.rglob("*")
        if path.is_file() and path != target
    }
    assert after == before
    assert "adopt" not in target.read_text(encoding="utf-8").lower()


def test_micro_spec_publish_requires_explicit_copied_fixture_marker(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    candidate = write_candidate(fixture, valid_micro_spec_candidate())
    target = fixture / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    target.parent.mkdir()
    (fixture / ".specbound/pre-adoption-fixture").unlink()

    result = run_cli(
        "--root", str(fixture), "issuance-request", "micro-spec", "ms-0001-003", "--candidate-file", str(candidate), "--publish"
    )

    assert result.returncode == 2, result.stdout
    assert "fixture_publication_required" in {blocker["code"] for blocker in payload(result)["blockers"]}
    assert not target.exists()


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    (
        (lambda fixture: (fixture / ".specbound/approvals/req-0001-r1.approval.json").unlink(), "missing_parent_approval"),
        (lambda fixture: (fixture / ".specbound/approvals/req-0001-r1.approval.json").write_text("not json", encoding="utf-8"), "malformed_parent_approval"),
        (lambda fixture: (fixture / ".specbound/approvals/req-0001-r1.approval.json").write_text((fixture / ".specbound/approvals/req-0001-r1.approval.json").read_text(encoding="utf-8").replace('"sha256": "0927', '"sha256": "0000'), encoding="utf-8"), "invalid_parent_approval_binding"),
        (lambda fixture: (fixture / "docs/requirements/req-0001/req-0001-r1.md").write_text((fixture / "docs/requirements/req-0001/req-0001-r1.md").read_text(encoding="utf-8").replace("status: approved", "status: draft"), encoding="utf-8"), "invalid_parent_requirement"),
    ),
)
def test_micro_spec_publish_rejects_invalid_parent_or_approval_without_target_mutation(tmp_path: Path, mutate: object, expected_code: str) -> None:
    fixture = copied_fixture(tmp_path)
    candidate = write_candidate(fixture, valid_micro_spec_candidate())
    target = fixture / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    target.parent.mkdir()
    mutate(fixture)  # type: ignore[operator]

    result = run_cli(
        "--root", str(fixture), "issuance-request", "micro-spec", "ms-0001-003", "--candidate-file", str(candidate), "--publish"
    )

    assert result.returncode == 2, result.stdout
    assert expected_code in {blocker["code"] for blocker in payload(result)["blockers"]}
    assert not target.exists()


def test_micro_spec_publish_rejects_a_superseded_parent_requirement_without_target_mutation(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    candidate = write_candidate(fixture, valid_micro_spec_candidate())
    target = fixture / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    target.parent.mkdir()
    parent = fixture / "docs/requirements/req-0001/req-0001-r1.md"
    (parent.parent / "req-0001-r2.md").write_text(
        parent.read_text(encoding="utf-8").replace("revision: 1", "revision: 2"),
        encoding="utf-8",
    )

    result = run_cli(
        "--root", str(fixture), "issuance-request", "micro-spec", "ms-0001-003", "--candidate-file", str(candidate), "--publish"
    )

    assert result.returncode == 2, result.stdout
    assert "superseded_parent_requirement" in {blocker["code"] for blocker in payload(result)["blockers"]}
    assert not target.exists()


def test_qc_publish_requires_explicit_fixture_adoption(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    micro = fixture / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    micro.parent.mkdir()
    micro.write_text(valid_micro_spec_candidate(), encoding="utf-8")
    candidate = write_candidate(fixture, valid_iteration_qc_candidate(micro))
    target = fixture / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"
    target.parent.mkdir()
    result = run_cli("--root", str(fixture), "issuance-request", "iteration-qc", "iqc-0001-003-r1", "--candidate-file", str(candidate), "--publish")
    assert result.returncode == 2, result.stdout
    assert "unadopted_parent" in {blocker["code"] for blocker in payload(result)["blockers"]}
    assert not target.exists()


def test_iteration_qc_publish_requires_exact_micro_spec_ac_set_before_fixture_mutation(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    micro = fixture / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    micro.parent.mkdir()
    micro.write_text(valid_micro_spec_candidate(), encoding="utf-8")
    digest = sha256(FIXTURE_REQUIREMENT.read_bytes()).hexdigest()
    config = fixture / "specbound.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "requirements: []",
            f"requirements:\n      - path: docs/requirements/req-0001/req-0001-r1.md\n        id: req-0001\n        revision: 1\n        sha256: {digest}",
        ),
        encoding="utf-8",
    )
    candidate = write_candidate(fixture, valid_iteration_qc_candidate(micro, ["AC-001", "AC-002"]))
    target = fixture / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"
    target.parent.mkdir()
    live_registry = ROOT / "specbound.yaml"
    before = sha256(live_registry.read_bytes()).hexdigest()

    result = run_cli(
        "--root", str(fixture), "issuance-request", "iteration-qc", "iqc-0001-003-r1", "--candidate-file", str(candidate), "--publish"
    )

    assert result.returncode == 2, result.stdout
    assert "iteration_qc_ac_set_mismatch" in {blocker["code"] for blocker in payload(result)["blockers"]}
    assert not target.exists()
    assert sha256(live_registry.read_bytes()).hexdigest() == before


def test_atomic_fixture_publish_rejects_symlinked_target_and_preserves_external_bytes(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    candidate = write_candidate(fixture, valid_micro_spec_candidate())
    target = fixture / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    target.parent.mkdir()
    external = tmp_path / "external.md"
    external.write_text("winner", encoding="utf-8")
    target.symlink_to(external)

    result = run_cli("--root", str(fixture), "issuance-request", "micro-spec", "ms-0001-003", "--candidate-file", str(candidate), "--publish")

    assert result.returncode == 2, result.stdout
    assert "duplicate_canonical_target" in {item["code"] for item in payload(result)["blockers"]}
    assert external.read_text(encoding="utf-8") == "winner"


def test_atomic_fixture_publish_rejects_intermediate_symlink(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    candidate = write_candidate(fixture, valid_micro_spec_candidate())
    root = fixture / ".specbound/micro-specs"
    root.mkdir(exist_ok=True)
    external = tmp_path / "external"
    external.mkdir()
    (root / "req-0001").symlink_to(external, target_is_directory=True)

    result = run_cli("--root", str(fixture), "issuance-request", "micro-spec", "ms-0001-003", "--candidate-file", str(candidate), "--publish")

    assert result.returncode == 2, result.stdout
    assert "unsafe_canonical_target_path" in {item["code"] for item in payload(result)["blockers"]}
    assert not (external / "ms-0001-003.md").exists()


def test_atomic_fixture_publish_allows_exactly_one_competing_writer(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    candidate = write_candidate(fixture, valid_micro_spec_candidate())
    target = fixture / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    target.parent.mkdir()
    command = [sys.executable, "-m", "specbound.cli", "--root", str(fixture), "issuance-request", "micro-spec", "ms-0001-003", "--candidate-file", str(candidate), "--publish"]
    environment = {"PYTHONPATH": str(ROOT / "src")}
    first = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=subprocess.PIPE, text=True)
    second = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=subprocess.PIPE, text=True)
    first_stdout, _ = first.communicate()
    second_stdout, _ = second.communicate()

    results = [(first.returncode, json.loads(first_stdout)), (second.returncode, json.loads(second_stdout))]
    assert sorted(code for code, _ in results) == [0, 2]
    assert target.read_text(encoding="utf-8") == valid_micro_spec_candidate()
    loser = next(body for code, body in results if code == 2)
    assert "duplicate_canonical_target" in {item["code"] for item in loser["blockers"]}


@pytest.mark.parametrize("hook", ["_write_published_bytes", "_flush_published_output", "_final_published_digest"])
def test_failure_atomic_publish_removes_owned_leaf_after_controlled_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hook: str) -> None:
    fixture = copied_fixture(tmp_path)
    target = fixture / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    target.parent.mkdir()

    def fail(*_: object, **__: object) -> None:
        raise OSError("injected failure")

    monkeypatch.setattr(issuance_request, hook, fail)
    blocker = issuance_request._exclusive_fixture_publish(fixture, ".specbound/micro-specs/req-0001/ms-0001-003.md", b"candidate")

    assert blocker is not None
    assert blocker.code == "publication_failed"
    assert not target.exists()


@pytest.mark.parametrize("failure_call", [1, 2])
def test_failure_atomic_publish_removes_owned_leaf_after_file_or_directory_fsync_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_call: int) -> None:
    fixture = copied_fixture(tmp_path)
    target = fixture / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    target.parent.mkdir()
    calls = 0

    def fail_on_selected_fsync(_: int) -> None:
        nonlocal calls
        calls += 1
        if calls == failure_call:
            raise OSError("injected fsync failure")

    monkeypatch.setattr(issuance_request, "_fsync_descriptor", fail_on_selected_fsync)
    blocker = issuance_request._exclusive_fixture_publish(fixture, ".specbound/micro-specs/req-0001/ms-0001-003.md", b"candidate")

    assert blocker is not None
    assert blocker.code == "publication_failed"
    assert not target.exists()


def test_failure_atomic_cleanup_does_not_remove_replaced_winner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = copied_fixture(tmp_path)
    target = fixture / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    target.parent.mkdir()

    def replace_then_fail(*_: object, **__: object) -> None:
        target.unlink()
        target.write_bytes(b"winner")
        raise OSError("injected post-write failure")

    monkeypatch.setattr(issuance_request, "_final_published_digest", replace_then_fail)
    blocker = issuance_request._exclusive_fixture_publish(fixture, ".specbound/micro-specs/req-0001/ms-0001-003.md", b"loser")

    assert blocker is not None
    assert target.read_bytes() == b"winner"


def test_issuance_request_help_and_guidance_state_non_authorizing_boundary() -> None:
    help_result = run_cli("issuance-request", "--help")
    guidance = (ROOT / "templates" / "issuance-request.md").read_text(encoding="utf-8")

    assert help_result.returncode == 0
    assert "marked copied fixture" in help_result.stdout
    assert "final published" in help_result.stdout and "SHA-256" in help_result.stdout
    assert "QC families additionally require the exact copied-fixture adoption binding" in guidance
    assert "refuses duplicate/competing targets" in guidance
    assert "never mutates the live adoption registry" in guidance
    assert "Publication is not approval, adoption, implementation completion, merge, delivery, or release" in guidance


def test_fixture_publication_never_mutates_live_adoption_registry(tmp_path: Path) -> None:
    fixture = copied_fixture(tmp_path)
    candidate = write_candidate(fixture, valid_micro_spec_candidate())
    (fixture / ".specbound/micro-specs/req-0001").mkdir()
    live_registry = ROOT / "specbound.yaml"
    before = sha256(live_registry.read_bytes()).hexdigest()

    result = run_cli(
        "--root", str(fixture), "issuance-request", "micro-spec", "ms-0001-003", "--candidate-file", str(candidate), "--publish"
    )

    assert result.returncode == 0, result.stdout
    assert sha256(live_registry.read_bytes()).hexdigest() == before
