from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys

import yaml
import pytest

from specbound.agent_contract import validate_agent_result, validate_agent_roles_policy, validate_role_request


ROLE_IDS = {
    "discovery-author",
    "requirement-author",
    "micro-spec-author",
    "independent-reviewer",
    "implementation",
    "iteration-qc",
    "delivery-qc",
}
ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/valid-minimal"
AGENT_FIXTURE = ROOT / "fixtures/agent-contract"


def run_cli(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "specbound.cli", "--root", str(root), *args],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        check=False,
        capture_output=True,
        text=True,
    )


def role(role_id: str) -> dict:
    read_only = role_id == "independent-reviewer"
    return {
        "role_id": role_id,
        "task_kind": role_id,
        "required_inputs": ["exact_target"],
        "allowed_path_patterns": [] if read_only else [f"candidates/{role_id}/**"],
        "allowed_tool_categories": ["repository-read"] if read_only else ["repository-read", "candidate-write"],
        "mutation_classes": ["none"] if read_only else ["candidate_write"],
        "output_kinds": ["agent-result"],
        "lifecycle_eligibility": ["approved"],
        "result_references": {
            "producer_result_ref": "required" if read_only else "optional",
            "reviewer_run_ref": "forbidden",
        },
        "evidence_slots": [
            {
                "slot": "target-binding",
                "requirement": "required",
                "not_applicable_allowed": False,
            }
        ],
        "permitted_next_actions": ["none"],
        "forbidden_actions": ["authority-transition", "merge", "release", "external-mutation"],
        "forbidden_claims": ["confirmation", "approval", "review-decision", "verified", "delivery"],
    }


def valid_policy() -> dict:
    return {"schema_version": 1, "roles": [role(role_id) for role_id in sorted(ROLE_IDS)]}


def write_policy(root: Path, policy: dict | None = None) -> Path:
    path = root / ".specbound/policies/agent-roles.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(policy or valid_policy(), sort_keys=False), encoding="utf-8")
    return path


def role_request_payload(root: Path, role_id: str) -> dict:
    target = root / "candidate.md"
    if not target.exists():
        target.write_text("exact candidate\n", encoding="utf-8")
    selected = role(role_id)
    return {
        "schema_version": 1,
        "role_id": role_id,
        "task_kind": role_id,
        "target": {
            "path": "candidate.md",
            "sha256": __import__("hashlib").sha256(target.read_bytes()).hexdigest(),
        },
        "current_state": "approved",
        "inputs": {name: name for name in selected["required_inputs"]},
        "requested_capabilities": {
            "path_patterns": selected["allowed_path_patterns"],
            "tool_categories": selected["allowed_tool_categories"],
            "mutation_classes": selected["mutation_classes"],
        },
        "producer_result_ref": "producer-result.json" if selected["result_references"]["producer_result_ref"] == "required" else None,
        "reviewer_run_ref": None,
    }


def valid_result_payload(root: Path) -> tuple[dict, Path]:
    target = root / "candidate.md"
    target.write_text("exact candidate\n", encoding="utf-8")
    artifact = root / "candidates/micro-spec-author/output.md"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("bounded output\n", encoding="utf-8")
    digest = __import__("hashlib").sha256
    payload = {
        "schema_version": 1,
        "role_id": "micro-spec-author",
        "task_kind": "micro-spec-author",
        "target": {"path": "candidate.md", "sha256": digest(target.read_bytes()).hexdigest()},
        "producer_result_ref": None,
        "reviewer_run_ref": None,
        "artifacts": [{"path": "candidates/micro-spec-author/output.md", "sha256": digest(artifact.read_bytes()).hexdigest(), "kind": "candidate"}],
        "evidence": [{"slot": "target-binding", "status": "provided", "artifact_ref": "candidates/micro-spec-author/output.md", "detail": "Exact target inspected."}],
        "provenance": {"execution_id": "run-001", "request_sha256": "0" * 64, "tool_categories": ["repository-read", "candidate-write"], "mutation_classes": ["candidate_write"]},
        "verification": {"commands": [{"command": "pytest -q", "result": "passed", "exit_code": 0}], "summary": "Focused checks passed."},
        "verdict": "completed",
        "permitted_next_action": "none",
        "claims": [],
    }
    return payload, artifact


def test_policy_accepts_exact_seven_role_inventory(tmp_path: Path) -> None:
    write_policy(tmp_path)

    result = validate_agent_roles_policy(tmp_path, ".specbound/policies/agent-roles.yaml")

    assert result.valid is True
    assert result.checked_roles == 7
    assert result.blockers == []


def test_packaged_schemas_and_fixture_policy_match_repository_contract() -> None:
    for name in ("agent-roles.schema.json", "agent-result.schema.json"):
        assert (ROOT / "schemas" / name).read_bytes() == (ROOT / "src/specbound/schemas" / name).read_bytes()
    assert (ROOT / ".specbound/policies/agent-roles.yaml").read_bytes() == (
        FIXTURE / ".specbound/policies/agent-roles.yaml"
    ).read_bytes()
    assert (ROOT / ".specbound/policies/agent-roles.yaml").read_bytes() == (
        AGENT_FIXTURE / ".specbound/policies/agent-roles.yaml"
    ).read_bytes()


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unknown"])
def test_policy_rejects_non_exact_role_inventory(tmp_path: Path, mutation: str) -> None:
    policy = valid_policy()
    if mutation == "missing":
        policy["roles"].pop()
    elif mutation == "duplicate":
        policy["roles"][-1] = dict(policy["roles"][0])
    else:
        policy["roles"][-1]["role_id"] = "runtime-operator"
    write_policy(tmp_path, policy)

    result = validate_agent_roles_policy(tmp_path, ".specbound/policies/agent-roles.yaml")

    assert result.valid is False
    assert {item["code"] for item in result.blockers} & {
        "malformed_agent_roles_policy",
        "invalid_agent_role_inventory",
    }


def test_policy_rejects_runtime_specific_or_unknown_field(tmp_path: Path) -> None:
    policy = valid_policy()
    policy["runtime"] = "hermes"
    write_policy(tmp_path, policy)

    result = validate_agent_roles_policy(tmp_path, ".specbound/policies/agent-roles.yaml")

    assert result.valid is False
    assert {item["code"] for item in result.blockers} == {"malformed_agent_roles_policy"}


def test_policy_rejects_reviewer_write_scope(tmp_path: Path) -> None:
    policy = valid_policy()
    reviewer = next(item for item in policy["roles"] if item["role_id"] == "independent-reviewer")
    reviewer["allowed_path_patterns"] = ["src/**"]
    write_policy(tmp_path, policy)

    result = validate_agent_roles_policy(tmp_path, ".specbound/policies/agent-roles.yaml")

    assert result.valid is False
    assert {item["code"] for item in result.blockers} == {"overpermissive_agent_role"}


def test_root_validate_checks_enabled_agent_policy(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    config_path = root / "specbound.yaml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    config["policy"]["agent_contract"] = {
        "enabled": True,
        "roles_path": ".specbound/policies/agent-roles.yaml",
    }
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    write_policy(root)

    result = run_cli(root, "validate")

    assert result.returncode == 0, result.stdout
    assert json.loads(result.stdout)["checked_agent_roles"] == 7


def test_role_request_accepts_exact_current_target_and_bounded_capabilities(tmp_path: Path) -> None:
    target = tmp_path / "candidate.md"
    target.write_text("exact candidate\n", encoding="utf-8")
    policy_path = write_policy(tmp_path)
    request = {
        "schema_version": 1,
        "role_id": "micro-spec-author",
        "task_kind": "micro-spec-author",
        "target": {
            "path": "candidate.md",
            "sha256": __import__("hashlib").sha256(target.read_bytes()).hexdigest(),
        },
        "current_state": "approved",
        "inputs": {"exact_target": "candidate.md"},
        "requested_capabilities": {
            "path_patterns": ["candidates/micro-spec-author/**"],
            "tool_categories": ["repository-read", "candidate-write"],
            "mutation_classes": ["candidate_write"],
        },
        "producer_result_ref": None,
        "reviewer_run_ref": None,
    }
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")

    result = validate_role_request(tmp_path, request_path, policy_path.relative_to(tmp_path).as_posix())

    assert result.valid is True
    assert result.blockers == []


@pytest.mark.parametrize("role_id", sorted(ROLE_IDS))
def test_role_request_accepts_each_stable_role(tmp_path: Path, role_id: str) -> None:
    policy_path = write_policy(tmp_path)
    request_path = tmp_path / f"{role_id}.request.json"
    request_path.write_text(json.dumps(role_request_payload(tmp_path, role_id)), encoding="utf-8")

    result = validate_role_request(tmp_path, request_path, policy_path.relative_to(tmp_path).as_posix())

    assert result.valid is True, result.blockers


@pytest.mark.parametrize("role_id", sorted(ROLE_IDS))
def test_role_request_rejects_ineligible_state_for_each_role(tmp_path: Path, role_id: str) -> None:
    policy_path = write_policy(tmp_path)
    payload = role_request_payload(tmp_path, role_id)
    payload["current_state"] = "blocked"
    request_path = tmp_path / f"{role_id}.request.json"
    request_path.write_text(json.dumps(payload), encoding="utf-8")

    result = validate_role_request(tmp_path, request_path, policy_path.relative_to(tmp_path).as_posix())

    assert "ineligible_agent_role" in {item["code"] for item in result.blockers}


def test_role_request_rejects_stale_target_and_capability_escalation(tmp_path: Path) -> None:
    policy_path = write_policy(tmp_path)
    payload = role_request_payload(tmp_path, "micro-spec-author")
    payload["target"]["sha256"] = "0" * 64
    payload["requested_capabilities"]["tool_categories"].append("test-execute")
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(payload), encoding="utf-8")

    result = validate_role_request(tmp_path, request_path, policy_path.relative_to(tmp_path).as_posix())

    codes = {item["code"] for item in result.blockers}
    assert {"target_digest_mismatch", "capability_escalation"}.issubset(codes)


def test_check_role_request_cli_is_read_only_and_uses_active_policy(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    target = root / ".specbound/requirements/req-0001/req-0001-r1.md"
    request = {
        "schema_version": 1,
        "role_id": "micro-spec-author",
        "task_kind": "micro-spec-author",
        "target": {
            "path": ".specbound/requirements/req-0001/req-0001-r1.md",
            "sha256": __import__("hashlib").sha256(target.read_bytes()).hexdigest(),
        },
        "current_state": "approved",
        "inputs": {
            "approved-requirement": "req-0001-r1",
            "selected-acceptance-criteria": "AC-001",
            "exact-target": ".specbound/requirements/req-0001/req-0001-r1.md",
        },
        "requested_capabilities": {
            "path_patterns": [".specbound/micro-specs/req-*/ms-*-*.md"],
            "tool_categories": ["repository-read", "candidate-write"],
            "mutation_classes": ["candidate_write"],
        },
        "producer_result_ref": None,
        "reviewer_run_ref": None,
    }
    request_path = root / "request.json"
    request_path.write_text(json.dumps(request), encoding="utf-8")
    before = {path.relative_to(root).as_posix(): __import__("hashlib").sha256(path.read_bytes()).hexdigest() for path in root.rglob("*") if path.is_file()}

    result = run_cli(root, "agent", "check-role-request", "--request-file", str(request_path))

    after = {path.relative_to(root).as_posix(): __import__("hashlib").sha256(path.read_bytes()).hexdigest() for path in root.rglob("*") if path.is_file()}
    assert result.returncode == 0, result.stdout
    assert json.loads(result.stdout)["checked_requests"] == 1
    assert after == before


def test_agent_result_accepts_closed_bound_evidence(tmp_path: Path) -> None:
    target = tmp_path / "candidate.md"
    target.write_text("exact candidate\n", encoding="utf-8")
    artifact = tmp_path / "candidates/micro-spec-author/output.md"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("bounded output\n", encoding="utf-8")
    policy_path = write_policy(tmp_path)
    digest = __import__("hashlib").sha256
    payload = {
        "schema_version": 1,
        "role_id": "micro-spec-author",
        "task_kind": "micro-spec-author",
        "target": {"path": "candidate.md", "sha256": digest(target.read_bytes()).hexdigest()},
        "producer_result_ref": None,
        "reviewer_run_ref": None,
        "artifacts": [
            {
                "path": "candidates/micro-spec-author/output.md",
                "sha256": digest(artifact.read_bytes()).hexdigest(),
                "kind": "candidate",
            }
        ],
        "evidence": [
            {
                "slot": "target-binding",
                "status": "provided",
                "artifact_ref": "candidates/micro-spec-author/output.md",
                "detail": "Exact target inspected.",
            }
        ],
        "provenance": {
            "execution_id": "run-001",
            "request_sha256": "0" * 64,
            "tool_categories": ["repository-read", "candidate-write"],
            "mutation_classes": ["candidate_write"],
        },
        "verification": {
            "commands": [{"command": "pytest -q", "result": "passed", "exit_code": 0}],
            "summary": "Focused checks passed.",
        },
        "verdict": "completed",
        "permitted_next_action": "none",
        "claims": [],
    }
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(payload), encoding="utf-8")

    result = validate_agent_result(tmp_path, result_path, policy_path.relative_to(tmp_path).as_posix())

    assert result.valid is True
    assert result.checked_results == 1


@pytest.mark.parametrize(
    ("scenario", "expected_code"),
    [
        ("unknown-field", "malformed_agent_result"),
        ("stale-target", "target_digest_mismatch"),
        ("outside-path", "artifact_outside_role_scope"),
        ("missing-evidence", "missing_evidence_slot"),
        ("invalid-not-applicable", "invalid_not_applicable_evidence"),
        ("widened-tool", "capability_escalation"),
        ("forbidden-claim", "forbidden_lifecycle_claim"),
        ("bad-next-action", "invalid_permitted_next_action"),
        ("false-completed", "invalid_completed_verdict"),
    ],
)
def test_agent_result_rejects_closed_contract_violations(tmp_path: Path, scenario: str, expected_code: str) -> None:
    policy_path = write_policy(tmp_path)
    payload, _ = valid_result_payload(tmp_path)
    if scenario == "unknown-field":
        payload["runtime"] = "hermes"
    elif scenario == "stale-target":
        payload["target"]["sha256"] = "0" * 64
    elif scenario == "outside-path":
        payload["artifacts"][0] = {
            "path": "candidate.md",
            "sha256": __import__("hashlib").sha256((tmp_path / "candidate.md").read_bytes()).hexdigest(),
            "kind": "candidate",
        }
        payload["evidence"][0]["artifact_ref"] = "candidate.md"
    elif scenario == "missing-evidence":
        payload["evidence"] = []
    elif scenario == "invalid-not-applicable":
        payload["evidence"][0].update(status="not_applicable", artifact_ref=None)
    elif scenario == "widened-tool":
        payload["provenance"]["tool_categories"].append("test-execute")
    elif scenario == "forbidden-claim":
        payload["claims"] = ["approval"]
    elif scenario == "bad-next-action":
        payload["permitted_next_action"] = "merge"
    else:
        payload["verification"]["commands"][0].update(result="failed", exit_code=1)
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(payload), encoding="utf-8")

    result = validate_agent_result(tmp_path, result_path, policy_path.relative_to(tmp_path).as_posix())

    assert expected_code in {item["code"] for item in result.blockers}, result.blockers


def test_implementation_result_uses_reviewed_micro_spec_code_paths(tmp_path: Path) -> None:
    policy = valid_policy()
    implementation = next(item for item in policy["roles"] if item["role_id"] == "implementation")
    implementation["allowed_path_patterns"] = ["@reviewed-micro-spec-scope"]
    policy_path = write_policy(tmp_path, policy)
    target = tmp_path / "micro-spec.md"
    target.write_text(
        "# Slice\n\n## Scope\n\n### Code paths\n\n- `src/example.py`\n- `tests/agent-contract/`\n\n### Impact radius\n\nBounded.\n",
        encoding="utf-8",
    )
    artifact = tmp_path / "src/example.py"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("VALUE = 1\n", encoding="utf-8")
    payload, _ = valid_result_payload(tmp_path)
    digest = __import__("hashlib").sha256
    payload.update(
        role_id="implementation",
        task_kind="implementation",
        target={"path": "micro-spec.md", "sha256": digest(target.read_bytes()).hexdigest()},
        artifacts=[{"path": "src/example.py", "sha256": digest(artifact.read_bytes()).hexdigest(), "kind": "implementation"}],
    )
    payload["evidence"][0]["artifact_ref"] = "src/example.py"
    result_path = tmp_path / "implementation-result.json"
    result_path.write_text(json.dumps(payload), encoding="utf-8")

    result = validate_agent_result(tmp_path, result_path, policy_path.relative_to(tmp_path).as_posix())

    assert result.valid is True, result.blockers


def test_read_only_reviewer_evidence_can_reference_exact_target(tmp_path: Path) -> None:
    policy_path = write_policy(tmp_path)
    payload, _ = valid_result_payload(tmp_path)
    payload.update(
        role_id="independent-reviewer",
        task_kind="independent-reviewer",
        producer_result_ref="producer-result.json",
        artifacts=[],
    )
    payload["evidence"][0]["artifact_ref"] = "candidate.md"
    payload["provenance"]["tool_categories"] = ["repository-read"]
    payload["provenance"]["mutation_classes"] = ["none"]
    result_path = tmp_path / "review-result.json"
    result_path.write_text(json.dumps(payload), encoding="utf-8")

    result = validate_agent_result(tmp_path, result_path, policy_path.relative_to(tmp_path).as_posix())

    assert result.valid is True, result.blockers


def test_validate_result_cli_is_read_only_and_uses_active_policy(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    target = root / ".specbound/requirements/req-0001/req-0001-r1.md"
    artifact = root / ".specbound/micro-specs/req-0001/ms-0001-099.md"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("candidate micro spec\n", encoding="utf-8")
    digest = __import__("hashlib").sha256
    payload = {
        "schema_version": 1,
        "role_id": "micro-spec-author",
        "task_kind": "micro-spec-author",
        "target": {
            "path": ".specbound/requirements/req-0001/req-0001-r1.md",
            "sha256": digest(target.read_bytes()).hexdigest(),
        },
        "producer_result_ref": None,
        "reviewer_run_ref": None,
        "artifacts": [
            {
                "path": ".specbound/micro-specs/req-0001/ms-0001-099.md",
                "sha256": digest(artifact.read_bytes()).hexdigest(),
                "kind": "candidate",
            }
        ],
        "evidence": [
            {"slot": "target-binding", "status": "provided", "artifact_ref": ".specbound/micro-specs/req-0001/ms-0001-099.md", "detail": "Bound."},
            {"slot": "selected-ac-coverage", "status": "provided", "artifact_ref": ".specbound/micro-specs/req-0001/ms-0001-099.md", "detail": "Covered."},
        ],
        "provenance": {
            "execution_id": "run-cli-001",
            "request_sha256": "0" * 64,
            "tool_categories": ["repository-read", "candidate-write"],
            "mutation_classes": ["candidate_write"],
        },
        "verification": {
            "commands": [{"command": "pytest -q", "result": "passed", "exit_code": 0}],
            "summary": "Passed.",
        },
        "verdict": "completed",
        "permitted_next_action": "submit-candidate-for-review",
        "claims": [],
    }
    result_path = root / "result.json"
    result_path.write_text(json.dumps(payload), encoding="utf-8")
    before = {path.relative_to(root).as_posix(): digest(path.read_bytes()).hexdigest() for path in root.rglob("*") if path.is_file()}

    result = run_cli(root, "agent", "validate-result", "--result-file", str(result_path))

    after = {path.relative_to(root).as_posix(): digest(path.read_bytes()).hexdigest() for path in root.rglob("*") if path.is_file()}
    assert result.returncode == 0, result.stdout
    assert json.loads(result.stdout)["checked_results"] == 1
    assert after == before


@pytest.mark.parametrize("role_id", sorted(ROLE_IDS))
def test_static_positive_and_negative_fixtures_cover_each_role(role_id: str) -> None:
    policy_path = ".specbound/policies/agent-roles.yaml"

    positive_request = validate_role_request(
        AGENT_FIXTURE,
        AGENT_FIXTURE / f"positive/{role_id}.request.json",
        policy_path,
    )
    negative_request = validate_role_request(
        AGENT_FIXTURE,
        AGENT_FIXTURE / f"negative/{role_id}.request.json",
        policy_path,
    )
    positive_result = validate_agent_result(
        AGENT_FIXTURE,
        AGENT_FIXTURE / f"positive/{role_id}.result.json",
        policy_path,
    )
    negative_result = validate_agent_result(
        AGENT_FIXTURE,
        AGENT_FIXTURE / f"negative/{role_id}.result.json",
        policy_path,
    )

    assert positive_request.valid is True, positive_request.blockers
    assert "ineligible_agent_role" in {item["code"] for item in negative_request.blockers}
    assert positive_result.valid is True, positive_result.blockers
    assert "forbidden_lifecycle_claim" in {item["code"] for item in negative_result.blockers}
