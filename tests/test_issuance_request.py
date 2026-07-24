from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

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
def test_issuance_request_rejects_deferred_qc_families_before_publication(
    tmp_path: Path, kind: str, target: str, candidate: str
) -> None:
    fixture = copied_fixture(tmp_path)
    candidate_path = write_candidate(fixture, candidate)

    result = run_cli(
        "--root", str(fixture), "issuance-request", kind, target, "--candidate-file", str(candidate_path)
    )

    assert result.returncode == 2, result.stdout
    assert "family_prerequisite_unmet" in {blocker["code"] for blocker in payload(result)["blockers"]}
    assert not any((fixture / ".specbound").rglob(target))


def test_issuance_request_help_and_guidance_state_non_authorizing_boundary() -> None:
    help_result = run_cli("issuance-request", "--help")
    guidance = (ROOT / "templates" / "issuance-request.md").read_text(encoding="utf-8")

    assert help_result.returncode == 0
    assert "pre-publication" in help_result.stdout
    assert "does not publish, approve, adopt, merge, deliver, or release" in guidance
