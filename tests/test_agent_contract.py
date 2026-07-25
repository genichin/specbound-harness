from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys

import pytest
import yaml

from specbound.agent_contract import (
    ROLE_IDS,
    _changed_path_allowed,
    _reviewed_micro_spec_paths,
    validate_agent_result,
    validate_agent_roles_policy,
    validate_role_request,
)


ROOT = Path(__file__).resolve().parents[1]
VALID_FIXTURE = ROOT / "fixtures/valid-minimal"
AGENT_FIXTURE = ROOT / "fixtures/agent-contract"
POLICY_REL = ".specbound/policies/agent-roles.yaml"
CANDIDATE_DEFINITIONS = {
    "discovery-author": (".specbound/discoveries/dcy-9100-r1.md", "dcy-9100", 1),
    "requirement-author": (".specbound/requirements/req-9100/req-9100-r1.md", "req-9100", 1),
    "micro-spec-author": (".specbound/micro-specs/req-9100/ms-9100-001.md", "ms-9100-001", None),
    "implementation": ("src/fixture_impl.py", "fixture_impl", None),
    "iteration-qc": (".specbound/iteration-qc/req-9100/iqc-9100-001-r1.json", "iqc-9100-001", 1),
    "delivery-qc": (".specbound/delivery-qc/dqc-9100-r1.json", "dqc-9100", 1),
}


def run_cli(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    return subprocess.run(
        [sys.executable, "-m", "specbound.cli", "--root", str(root), *args],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def repository_snapshot(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }


def actual_policy() -> dict:
    return yaml.safe_load((ROOT / POLICY_REL).read_text(encoding="utf-8"))


def setup_root(tmp_path: Path, policy: dict | None = None) -> tuple[Path, Path]:
    root = tmp_path / "repo"
    policy_path = root / POLICY_REL
    policy_path.parent.mkdir(parents=True)
    policy_path.write_text(yaml.safe_dump(policy or actual_policy(), sort_keys=False), encoding="utf-8", newline="\n")
    (root / "specbound.yaml").write_text(
        "version: 1\npolicy:\n  agent_contract:\n    enabled: true\n    roles_path: .specbound/policies/agent-roles.yaml\n"
        "  micro_spec_review_authorities_by_risk:\n    high: [fixture-maintainer]\n"
        "  discovery_confirmation_authorities_by_risk:\n    high: [fixture-maintainer]\n",
        encoding="utf-8",
        newline="\n",
    )
    return root, policy_path


def role_contract(role_id: str, policy: dict | None = None) -> dict:
    source = policy or actual_policy()
    return next(role for role in source["roles"] if role["role_id"] == role_id)


def result_reference(root: Path, role_id: str = "implementation") -> dict:
    artifact = {
        "schema_version": 1,
        "result_id": f"result-{role_id}",
        "role_id": role_id,
        "execution_id": f"execution-{role_id}",
        "context_id": f"context-{role_id}",
    }
    serialized = json.dumps(artifact, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    return {
        **{key: artifact[key] for key in ("result_id", "role_id", "execution_id", "context_id")},
        "sha256": sha256(serialized).hexdigest(),
    }


def exact_ref(root: Path, relative: str, artifact_id: str, revision: int | None) -> dict:
    return {
        "path": relative,
        "id": artifact_id,
        "revision": revision,
        "sha256": sha256((root / relative).read_bytes()).hexdigest(),
    }


def write_state_target(root: Path, role_id: str, state: str) -> dict:
    if role_id in {"discovery-author", "requirement-author"}:
        number = "9001" if role_id == "discovery-author" else "9002"
        artifact_id = f"dcy-{number}"
        relative = f".specbound/discoveries/{artifact_id}-r1.md"
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        discovery_body = "\n".join(
            f"{heading}\n\nSubstantive fixture evidence for {artifact_id}.\n"
            for heading in (
                "## 1. User intent",
                "## 2. Problem and target users",
                "## 3. Desired outcome and success signals",
                "## 6. Scope",
                "## 7. Non-goals",
                "## 9. Risks, constraints, and dependencies",
                "## 11. Open questions",
                "## 12. Recommendation",
                "## 12a. REQ drafting readiness",
                "## 13. Proposed next authorized action",
            )
        )
        target.write_text(
            f"---\nid: {artifact_id}\nrevision: 1\nstatus: {state}\nrisk_class: high\n---\n\n# Discovery\n\n{discovery_body}",
            encoding="utf-8",
            newline="\n",
        )
        ref = exact_ref(root, relative, artifact_id, 1)
        if state == "confirmed":
            record = root / f".specbound/confirmations/{artifact_id}-r1.confirmation.json"
            record.parent.mkdir(parents=True, exist_ok=True)
            in_review = target.read_text(encoding="utf-8").replace("status: confirmed", "status: in_review")
            record.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "discovery_path": relative,
                        "discovery_id": artifact_id,
                        "revision": 1,
                        "reviewed_sha256": sha256(in_review.encode("utf-8")).hexdigest(),
                        "sha256": ref["sha256"],
                        "risk_class": "high",
                        "authority": "fixture-maintainer",
                        "confirmed_at": "2026-01-01T00:00:00Z",
                        "decision": "confirmed",
                        "permitted_next_action": "draft_req_only",
                    },
                    indent=2,
                ) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        return ref

    if role_id in {"micro-spec-author", "independent-reviewer"}:
        number = "9003" if role_id == "micro-spec-author" else "9004"
        artifact_id = f"req-{number}"
        relative = f".specbound/requirements/{artifact_id}/{artifact_id}-r1.md"
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            f"---\nid: {artifact_id}\nrevision: 1\nstatus: {state}\nrisk: high\nowner: fixture-owner\n---\n\n# Requirement\n",
            encoding="utf-8",
            newline="\n",
        )
        ref = exact_ref(root, relative, artifact_id, 1)
        if state == "approved":
            record = root / f".specbound/approvals/{artifact_id}-r1.approval.json"
            record.parent.mkdir(parents=True, exist_ok=True)
            record.write_text(
                json.dumps(
                    {
                        "requirement_path": relative,
                        "requirement_id": artifact_id,
                        "revision": 1,
                        "sha256": ref["sha256"],
                        "risk": "high",
                        "authority": "fixture-maintainer",
                    },
                    indent=2,
                ) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        else:
            record = root / f".specbound/review-submissions/{artifact_id}-r1.review-submission.json"
            record.parent.mkdir(parents=True, exist_ok=True)
            draft = target.read_text(encoding="utf-8").replace("status: in_review", "status: draft")
            record.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "requirement_path": relative,
                        "requirement_id": artifact_id,
                        "revision": 1,
                        "draft_sha256": sha256(draft.encode("utf-8")).hexdigest(),
                        "reviewed_sha256": ref["sha256"],
                        "risk": "high",
                        "owner": "fixture-owner",
                        "submitted_at": "2026-01-01T00:00:00Z",
                        "decision": "submitted_for_review",
                        "permitted_next_action": "review_decision_only",
                    },
                    indent=2,
                ) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        return ref

    if role_id in {"implementation", "iteration-qc"}:
        number = "9005" if role_id == "implementation" else "9006"
        requirement_id = f"req-{number}"
        micro_id = f"ms-{number}-001"
        requirement_relative = f".specbound/requirements/{requirement_id}/{requirement_id}-r1.md"
        requirement = root / requirement_relative
        requirement.parent.mkdir(parents=True, exist_ok=True)
        requirement.write_text(
            f"---\nid: {requirement_id}\nrevision: 1\nstatus: approved\nrisk: high\nowner: fixture-owner\n---\n\n# Requirement\n",
            encoding="utf-8",
            newline="\n",
        )
        requirement_sha = sha256(requirement.read_bytes()).hexdigest()
        approval = root / f".specbound/approvals/{requirement_id}-r1.approval.json"
        approval.parent.mkdir(parents=True, exist_ok=True)
        approval.write_text(
            json.dumps(
                {
                    "requirement_path": requirement_relative,
                    "requirement_id": requirement_id,
                    "revision": 1,
                    "sha256": requirement_sha,
                    "risk": "high",
                    "authority": "fixture-maintainer",
                },
                indent=2,
            ) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        relative = f".specbound/micro-specs/{requirement_id}/{micro_id}.md"
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            f"---\nschema_version: 1\nid: {micro_id}\nkind: micro-spec\n"
            f"state: {state}\nrisk: high\nrequirement:\n  path: {requirement_relative}\n  id: {requirement_id}\n  revision: 1\n  sha256: {requirement_sha}\n---\n\n"
            "# Reviewed fixture Micro-SPEC\n\n## Scope\n\n### Code paths\n\n- `src/fixture_impl.py`\n\n### Impact radius\n\nFixture only.\n",
            encoding="utf-8",
            newline="\n",
        )
        ref = exact_ref(root, relative, micro_id, None)
        if role_id in {"implementation", "iteration-qc"}:
            review = root / f".specbound/micro-spec-reviews/{requirement_id}/{micro_id}.review.json"
            review.parent.mkdir(parents=True, exist_ok=True)
            review.write_text(
                json.dumps(
                    {
                        "schema_version": 1, "micro_spec_id": micro_id, "micro_spec_path": relative,
                        "micro_spec_sha256": ref["sha256"], "requirement_path": requirement_relative,
                        "requirement_id": requirement_id, "revision": 1, "requirement_sha256": requirement_sha,
                        "risk": "high", "authority": "fixture-maintainer", "decided_at": "2026-01-01T00:00:00Z",
                        "decision": "approved_for_implementation", "reason": "Exact fixture review permits only this bound implementation.",
                        "permitted_next_action": "implement_bound_micro_spec_only",
                    },
                    indent=2,
                    sort_keys=True,
                ) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        return ref

    requirement_id = "req-9007"
    requirement_relative = ".specbound/requirements/req-9007/req-9007-r1.md"
    requirement = root / requirement_relative
    requirement.parent.mkdir(parents=True, exist_ok=True)
    requirement.write_text(
        "---\nid: req-9007\nrevision: 1\nstatus: approved\nrisk: high\nowner: fixture-owner\n---\n\n"
        "# Requirement\n\n## Acceptance criteria\n\n### AC-001 — Implement slice\n\nEvidence.\n\n"
        "### AC-002 — Remaining delivery work\n\nEvidence.\n",
        encoding="utf-8",
        newline="\n",
    )
    requirement_sha = sha256(requirement.read_bytes()).hexdigest()
    approval = root / ".specbound/approvals/req-9007-r1.approval.json"
    approval.parent.mkdir(parents=True, exist_ok=True)
    approval.write_text(
        json.dumps(
            {
                "requirement_path": requirement_relative,
                "requirement_id": requirement_id,
                "revision": 1,
                "sha256": requirement_sha,
                "risk": "high",
                "authority": "fixture-maintainer",
            },
            indent=2,
        ) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    micro_id = "ms-9007-001"
    micro_relative = ".specbound/micro-specs/req-9007/ms-9007-001.md"
    micro = root / micro_relative
    micro.parent.mkdir(parents=True, exist_ok=True)
    micro.write_text(
        "---\nschema_version: 1\nid: ms-9007-001\nkind: micro-spec\nrisk: high\n"
        f"requirement:\n  path: {requirement_relative}\n  id: {requirement_id}\n  revision: 1\n  sha256: {requirement_sha}\n"
        "selected_acceptance_criteria: [AC-001]\n---\n\n# Verified fixture Micro-SPEC\n",
        encoding="utf-8",
        newline="\n",
    )
    micro_sha = sha256(micro.read_bytes()).hexdigest()
    review = root / ".specbound/micro-spec-reviews/req-9007/ms-9007-001.review.json"
    review.parent.mkdir(parents=True, exist_ok=True)
    review.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "micro_spec_id": micro_id,
                "micro_spec_path": micro_relative,
                "micro_spec_sha256": micro_sha,
                "requirement_path": requirement_relative,
                "requirement_id": requirement_id,
                "revision": 1,
                "requirement_sha256": requirement_sha,
                "risk": "high",
                "authority": "fixture-maintainer",
                "decided_at": "2026-01-01T00:00:00Z",
                "decision": "approved_for_implementation",
                "reason": "Exact fixture review permits only this bound implementation.",
                "permitted_next_action": "implement_bound_micro_spec_only",
            },
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    artifact_id = "iqc-9007-001"
    relative = ".specbound/iteration-qc/req-9007/iqc-9007-001-r1.json"
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "micro_spec": {"path": micro_relative, "id": micro_id, "sha256": micro_sha},
                "selected_acceptance_criteria": ["AC-001"],
                "remaining_acceptance_criteria": ["AC-002"],
                "verification": [{"command": "pytest -q", "result": "passed", "exit_code": 0}],
                "verdict": state,
            },
            indent=2,
        ) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return exact_ref(root, requirement_relative, requirement_id, 1)


def valid_request(root: Path, role_id: str) -> dict:
    role = role_contract(role_id)
    target = write_state_target(root, role_id, role["lifecycle_eligibility"][0])
    producer_requirement = role["result_references"]["producer_result_ref"]
    reviewer_requirement = role["result_references"]["reviewer_run_ref"]
    return {
        "schema_version": 1,
        "role_id": role_id,
        "task_kind": role["task_kind"],
        "target": target,
        "current_state": role["lifecycle_eligibility"][0],
        "inputs": {name: f"input:{name}" for name in role["required_inputs"]},
        "requested_capabilities": {
            "paths": [CANDIDATE_DEFINITIONS[role_id][0]] if role_id in CANDIDATE_DEFINITIONS else [],
            "tool_categories": list(role["allowed_tool_categories"]),
            "mutation_classes": list(role["mutation_classes"]),
            "output_kinds": list(role["output_kinds"]),
            "actions": list(role["permitted_next_actions"][:1]),
        },
        "producer_result_ref": result_reference(root, "iteration-qc" if role_id == "delivery-qc" else "implementation") if producer_requirement == "required" else None,
        "reviewer_run_ref": result_reference(root, "independent-reviewer") if reviewer_requirement == "required" else None,
    }


def write_changed_artifact(root: Path, role_id: str) -> dict | None:
    definition = CANDIDATE_DEFINITIONS.get(role_id)
    if definition is None:
        return None
    relative, artifact_id, revision = definition
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".json":
        path.write_text(json.dumps({"id": artifact_id, "revision": revision}, indent=2) + "\n", encoding="utf-8", newline="\n")
    elif path.suffix == ".md":
        revision_line = f"revision: {revision}\n" if revision is not None else ""
        path.write_text(f"---\nid: {artifact_id}\n{revision_line}---\n\n# Candidate\n", encoding="utf-8", newline="\n")
    else:
        path.write_text("fixture = True\n", encoding="utf-8", newline="\n")
    return exact_ref(root, relative, artifact_id, revision)


def valid_result(root: Path, role_id: str) -> dict:
    role = role_contract(role_id)
    target = write_state_target(root, role_id, role["lifecycle_eligibility"][0])
    changed_artifact = write_changed_artifact(root, role_id)
    artifacts = [target] + ([changed_artifact] if changed_artifact else [])
    slots = []
    for index, slot_policy in enumerate(role["evidence_slots"]):
        slot_artifacts = artifacts if index == 0 else [target]
        slots.append(
            {
                "slot": slot_policy["slot"],
                "status": "provided",
                "artifacts": slot_artifacts,
                "commands": [{"command": "fixture-check", "result": "passed", "exit_code": 0}] if slot_policy["slot"] in {"test-results", "focused-verification", "regression-evidence"} else [],
                "reason": None,
            }
        )
    producer_requirement = role["result_references"]["producer_result_ref"]
    reviewer_requirement = role["result_references"]["reviewer_run_ref"]
    return {
        "schema_version": 1,
        "result_id": f"result-{role_id}",
        "role_id": role_id,
        "task_kind": role["task_kind"],
        "execution_id": f"execution-{role_id}",
        "context_id": f"context-{role_id}",
        "model_alias": "advanced-review-model" if role_id == "independent-reviewer" else "worker-model",
        "target": target,
        "producer_result_ref": result_reference(root, "iteration-qc" if role_id == "delivery-qc" else "implementation") if producer_requirement == "required" else None,
        "reviewer_run_ref": result_reference(root, "independent-reviewer") if reviewer_requirement == "required" else None,
        "authority_type": "none",
        "authority_action_id": None,
        "context_provenance": {
            "fresh_context": True,
            "producer_transcript_inherited": False,
            "session_memory_inherited": False,
            "input_artifacts": [target],
        },
        "target_risk": "high",
        "effective_task_risk": "high",
        "tool_categories": list(role["allowed_tool_categories"]),
        "mutation_class": role["mutation_classes"][0],
        "changed_paths": [changed_artifact["path"]] if changed_artifact else [],
        "output_kind": "agent-result",
        "evidence": slots,
        "verdict": "pass",
        "findings": [],
        "permitted_next_action": role["permitted_next_actions"][0],
        "claims": [],
    }


def write_json(root: Path, relative: str, payload: dict) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path


def test_policy_accepts_exact_provider_neutral_inventory(tmp_path: Path) -> None:
    root, _ = setup_root(tmp_path)
    result = validate_agent_roles_policy(root, POLICY_REL)
    assert result.valid is True, result.blockers
    assert result.checked_roles == 7


@pytest.mark.parametrize(
    "mutation",
    [
        "missing", "duplicate", "unknown", "runtime", "path", "tool", "mutation", "output",
        "reference", "reference-edge", "evidence", "evidence-applicability", "risk-order",
        "crosswalk", "forbidden",
    ],
)
def test_policy_fails_closed_for_inventory_and_widening(tmp_path: Path, mutation: str) -> None:
    policy = actual_policy()
    if mutation == "missing":
        policy["roles"].pop()
    elif mutation == "duplicate":
        policy["roles"][-1] = deepcopy(policy["roles"][0])
    elif mutation == "unknown":
        policy["roles"][-1]["role_id"] = "runtime-operator"
    elif mutation == "runtime":
        policy["roles"][0]["provider"] = "vendor-runtime"
    elif mutation == "path":
        policy["roles"][0]["allowed_path_patterns"].append("src/**")
    elif mutation == "tool":
        policy["roles"][0]["allowed_tool_categories"].append("test-execute")
    elif mutation == "mutation":
        policy["roles"][0]["mutation_classes"] = ["repository_mutation"]
    elif mutation == "output":
        policy["roles"][0]["output_kinds"] = []
    elif mutation == "reference":
        policy["roles"][3]["result_references"]["producer_result_ref"] = "optional"
    elif mutation == "reference-edge":
        policy["roles"][4]["reference_edges"]["reviewer_run_ref"]["allowed_roles"] = ["implementation"]
    elif mutation == "evidence":
        policy["roles"][0]["evidence_slots"][0]["not_applicable_allowed"] = True
    elif mutation == "evidence-applicability":
        policy["evidence_applicability"]["authority_transition"]["supported"] = True
    elif mutation == "risk-order":
        policy["risk_order"] = ["low", "medium", "high", "critical"]
    elif mutation == "crosswalk":
        policy["transition_crosswalk"]["requirement-approval"]["writer"] = "attacker_writer"
    else:
        policy["roles"][0]["forbidden_actions"].append("extra-denial")
    root, _ = setup_root(tmp_path, policy)
    result = validate_agent_roles_policy(root, POLICY_REL)
    assert result.valid is False


@pytest.mark.parametrize("role_id", sorted(ROLE_IDS))
def test_role_request_accepts_each_role_from_repository_state(tmp_path: Path, role_id: str) -> None:
    root, _ = setup_root(tmp_path)
    request_path = write_json(root, "request.json", valid_request(root, role_id))
    result = validate_role_request(root, request_path, POLICY_REL)
    assert result.valid is True, result.blockers


def test_role_request_derives_confirmed_state_from_exact_canonical_record(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    shutil.copytree(VALID_FIXTURE, root)
    role = role_contract("requirement-author")
    target = exact_ref(root, ".specbound/discoveries/dcy-0001-r1.md", "dcy-0001", 1)
    payload = {
        "schema_version": 1,
        "role_id": "requirement-author",
        "task_kind": "requirement-author",
        "target": target,
        "current_state": "confirmed",
        "inputs": {name: f"input:{name}" for name in role["required_inputs"]},
        "requested_capabilities": {
            "paths": [CANDIDATE_DEFINITIONS["requirement-author"][0]],
            "tool_categories": role["allowed_tool_categories"],
            "mutation_classes": role["mutation_classes"],
            "output_kinds": role["output_kinds"],
            "actions": [role["permitted_next_actions"][0]],
        },
        "producer_result_ref": None,
        "reviewer_run_ref": None,
    }
    request_path = write_json(root, "request.json", payload)
    accepted = validate_role_request(root, request_path, POLICY_REL)
    assert accepted.valid is True, accepted.blockers

    confirmation_path = root / ".specbound/confirmations/dcy-0001-r1.confirmation.json"
    confirmation = json.loads(confirmation_path.read_text(encoding="utf-8"))
    confirmation["sha256"] = "0" * 64
    confirmation_path.write_text(json.dumps(confirmation, indent=2) + "\n", encoding="utf-8", newline="\n")
    rejected = validate_role_request(root, request_path, POLICY_REL)
    assert "undetermined_current_state" in {item["code"] for item in rejected.blockers}


def test_implementation_requires_a_fully_valid_canonical_micro_spec_review(tmp_path: Path) -> None:
    root, _ = setup_root(tmp_path)
    payload = valid_request(root, "implementation")
    parts = PurePosixPath(payload["target"]["path"]).parts
    review_path = root / f".specbound/micro-spec-reviews/{parts[2]}/{Path(parts[3]).stem}.review.json"
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review.pop("authority")
    review_path.write_text(json.dumps(review, indent=2) + "\n", encoding="utf-8", newline="\n")

    result = validate_role_request(root, write_json(root, "request.json", payload), POLICY_REL)

    assert "undetermined_current_state" in {item["code"] for item in result.blockers}


@pytest.mark.parametrize(
    ("role_id", "record_relative", "required_field"),
    [
        ("requirement-author", ".specbound/confirmations/dcy-9002-r1.confirmation.json", "authority"),
        ("micro-spec-author", ".specbound/approvals/req-9003-r1.approval.json", "risk"),
        ("independent-reviewer", ".specbound/review-submissions/req-9004-r1.review-submission.json", "submitted_at"),
    ],
)
def test_role_request_rejects_incomplete_canonical_state_record(
    tmp_path: Path,
    role_id: str,
    record_relative: str,
    required_field: str,
) -> None:
    root, _ = setup_root(tmp_path)
    payload = valid_request(root, role_id)
    record_path = root / record_relative
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record.pop(required_field)
    record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")

    result = validate_role_request(root, write_json(root, "request.json", payload), POLICY_REL)

    assert "undetermined_current_state" in {item["code"] for item in result.blockers}, result.blockers


def test_role_request_rejects_review_when_parent_requirement_bytes_are_stale(tmp_path: Path) -> None:
    root, _ = setup_root(tmp_path)
    payload = valid_request(root, "implementation")
    target_text = (root / payload["target"]["path"]).read_text(encoding="utf-8")
    target_metadata = yaml.safe_load(target_text.split("---\n", 2)[1])
    parent = root / target_metadata["requirement"]["path"]
    parent.write_text(
        parent.read_text(encoding="utf-8").replace("status: approved", "status: draft"),
        encoding="utf-8",
        newline="\n",
    )

    result = validate_role_request(root, write_json(root, "request.json", payload), POLICY_REL)

    assert "undetermined_current_state" in {item["code"] for item in result.blockers}, result.blockers


def test_iteration_qc_rejects_self_declared_implemented_state_without_canonical_review(tmp_path: Path) -> None:
    root, _ = setup_root(tmp_path)
    payload = valid_request(root, "iteration-qc")
    parts = PurePosixPath(payload["target"]["path"]).parts
    review = root / f".specbound/micro-spec-reviews/{parts[2]}/{Path(parts[3]).stem}.review.json"
    review.unlink()

    result = validate_role_request(root, write_json(root, "request.json", payload), POLICY_REL)

    assert "undetermined_current_state" in {item["code"] for item in result.blockers}, result.blockers


def test_delivery_qc_targets_exact_approved_requirement_without_result_references(tmp_path: Path) -> None:
    root, _ = setup_root(tmp_path)
    payload = valid_request(root, "delivery-qc")

    result = validate_role_request(root, write_json(root, "request.json", payload), POLICY_REL)

    assert payload["target"]["path"] == ".specbound/requirements/req-9007/req-9007-r1.md"
    assert payload["current_state"] == "approved"
    assert payload["producer_result_ref"] is None
    assert payload["reviewer_run_ref"] is None
    assert result.valid is True, result.blockers


def test_implementation_cannot_write_review_submission_authority_paths(tmp_path: Path) -> None:
    root, _ = setup_root(tmp_path)
    request = valid_request(root, "implementation")
    request["requested_capabilities"]["paths"].append(".specbound/review-submissions/forged.json")
    request_result = validate_role_request(root, write_json(root, "request.json", request), POLICY_REL)

    result_payload = valid_result(root, "implementation")
    forged = root / ".specbound/review-submissions/forged.json"
    forged.parent.mkdir(parents=True, exist_ok=True)
    forged.write_text("{}\n", encoding="utf-8", newline="\n")
    forged_ref = exact_ref(root, ".specbound/review-submissions/forged.json", "forged", None)
    result_payload["changed_paths"].append(forged_ref["path"])
    result_payload["evidence"][0]["artifacts"].append(forged_ref)
    agent_result = validate_agent_result(root, write_json(root, "result.json", result_payload), POLICY_REL)

    assert "capability_escalation" in {item["code"] for item in request_result.blockers}
    assert "forbidden_changed_path" in {item["code"] for item in agent_result.blockers}


@pytest.mark.parametrize(
    ("scenario", "expected_code"),
    [
        ("state-spoof", "current_state_spoofing"),
        ("stale-digest", "target_digest_mismatch"),
        ("identity", "target_identity_mismatch"),
        ("missing-input", "missing_role_input"),
        ("undeclared-input", "undeclared_role_input"),
        ("path", "capability_escalation"),
        ("tool", "capability_escalation"),
        ("mutation", "capability_escalation"),
        ("output", "capability_escalation"),
        ("action", "capability_escalation"),
        ("required-reference", "invalid_result_reference"),
        ("extra-reference-field", "malformed_role_request"),
        ("extra-field", "malformed_role_request"),
        ("absolute-path", "malformed_role_request"),
        ("traversal", "malformed_role_request"),
        ("double-separator", "malformed_role_request"),
        ("dot-segment", "malformed_role_request"),
        ("noncanonical-target", "undetermined_current_state"),
        ("reviewer-role", "invalid_result_reference"),
    ],
)
def test_role_request_rejects_spoofing_and_escalation(tmp_path: Path, scenario: str, expected_code: str) -> None:
    root, _ = setup_root(tmp_path)
    payload = valid_request(root, "implementation")
    if scenario == "state-spoof":
        payload["current_state"] = "implemented"
    elif scenario == "stale-digest":
        payload["target"]["sha256"] = "0" * 64
    elif scenario == "identity":
        payload["target"]["id"] = "ms-wrong"
    elif scenario == "missing-input":
        payload["inputs"].pop("review-record")
    elif scenario == "undeclared-input":
        payload["inputs"]["caller-extension"] = "not-declared-by-the-role"
    elif scenario in {"path", "tool", "mutation", "output", "action"}:
        field = {"path": "paths", "tool": "tool_categories", "mutation": "mutation_classes", "output": "output_kinds", "action": "actions"}[scenario]
        payload["requested_capabilities"][field].append("forbidden-capability")
    elif scenario == "required-reference":
        payload["reviewer_run_ref"] = None
    elif scenario == "extra-reference-field":
        payload["reviewer_run_ref"]["path"] = ".specbound/agent-results/independent-reviewer/result-independent-reviewer.json"
    elif scenario == "extra-field":
        payload["runtime"] = "forbidden"
    elif scenario == "absolute-path":
        payload["target"]["path"] = "/tmp/escape"
    elif scenario == "traversal":
        payload["target"]["path"] = "../escape"
    elif scenario == "double-separator":
        payload["target"]["path"] = payload["target"]["path"].replace("micro-specs/", "micro-specs//")
    elif scenario == "dot-segment":
        payload["target"]["path"] = payload["target"]["path"].replace("micro-specs/", "micro-specs/./")
    elif scenario == "noncanonical-target":
        source = root / payload["target"]["path"]
        target = root / "arbitrary.md"
        target.write_bytes(source.read_bytes())
        payload["target"] = exact_ref(root, "arbitrary.md", "ms-9000-001", None)
    else:
        payload["reviewer_run_ref"]["role_id"] = "delivery-qc"
    request_path = write_json(root, "request.json", payload)
    before = repository_snapshot(root)
    result = validate_role_request(root, request_path, POLICY_REL)
    after = repository_snapshot(root)
    assert expected_code in {item["code"] for item in result.blockers}, result.blockers
    assert after == before


@pytest.mark.parametrize("role_id", sorted(ROLE_IDS))
@pytest.mark.parametrize(
    ("field", "forbidden"),
    [
        ("paths", ".specbound/approvals/unauthorized.json"),
        ("tool_categories", "external-write"),
        ("mutation_classes", "authority_mutation"),
        ("output_kinds", "authority-record"),
        ("actions", "merge"),
    ],
)
def test_each_role_request_rejects_forbidden_capability_without_mutation(
    tmp_path: Path, role_id: str, field: str, forbidden: str
) -> None:
    root, _ = setup_root(tmp_path)
    payload = valid_request(root, role_id)
    payload["requested_capabilities"][field].append(forbidden)
    request_path = write_json(root, "request.json", payload)
    before = repository_snapshot(root)

    result = validate_role_request(root, request_path, POLICY_REL)

    assert result.valid is False
    assert repository_snapshot(root) == before


def test_role_request_rejects_nested_suffix_pattern_and_runtime_specific_input(tmp_path: Path) -> None:
    root, _ = setup_root(tmp_path)
    nested = valid_request(root, "discovery-author")
    nested["requested_capabilities"]["paths"] = [".specbound/discoveries/dcy-9100/nested-r1.md"]
    runtime_specific = valid_request(root, "requirement-author")
    runtime_specific["inputs"]["confirmed-discovery"] = "openai-runtime-reference"

    nested_path = write_json(root, "nested-request.json", nested)
    runtime_path = write_json(root, "runtime-request.json", runtime_specific)
    nested_result = validate_role_request(root, nested_path, POLICY_REL)
    runtime_result = validate_role_request(root, runtime_path, POLICY_REL)

    assert nested_result.valid is False
    assert "capability_escalation" in {item["code"] for item in nested_result.blockers}
    assert runtime_result.valid is False
    assert "runtime_specific_request" in {item["code"] for item in runtime_result.blockers}


@pytest.mark.parametrize(
    ("role_id", "candidate"),
    [
        ("discovery-author", ".specbound/discoveries/dcy--r.md"),
        ("requirement-author", ".specbound/requirements/req-123/req-999-r1.md"),
        ("micro-spec-author", ".specbound/micro-specs/req-123/ms-999-001.md"),
        ("iteration-qc", ".specbound/iteration-qc/req-123/iqc-999-001-r1.json"),
        ("delivery-qc", ".specbound/delivery-qc/dqc--r1.json"),
    ],
)
def test_role_request_rejects_noncanonical_family_topology(
    tmp_path: Path,
    role_id: str,
    candidate: str,
) -> None:
    root, _ = setup_root(tmp_path)
    payload = valid_request(root, role_id)
    payload["requested_capabilities"]["paths"] = [candidate]

    result = validate_role_request(root, write_json(root, "request.json", payload), POLICY_REL)

    assert "capability_escalation" in {item["code"] for item in result.blockers}, result.blockers


@pytest.mark.parametrize("role_id", sorted(ROLE_IDS))
def test_agent_result_accepts_exact_contract_for_each_role(tmp_path: Path, role_id: str) -> None:
    root, _ = setup_root(tmp_path)
    result_path = write_json(root, "result.json", valid_result(root, role_id))
    result = validate_agent_result(root, result_path, POLICY_REL)
    assert result.valid is True, result.blockers


@pytest.mark.parametrize(
    ("scenario", "expected_code"),
    [
        ("extra-field", "malformed_agent_result"),
        ("stale-target", "target_digest_mismatch"),
        ("target-identity", "target_identity_mismatch"),
        ("required-reference", "invalid_result_reference"),
        ("extra-reference-field", "malformed_agent_result"),
        ("provenance", "invalid_context_provenance"),
        ("missing-target-provenance", "missing_target_provenance"),
        ("tool", "capability_escalation"),
        ("mutation", "capability_escalation"),
        ("outside-path", "changed_path_outside_role_scope"),
        ("missing-evidence", "missing_evidence_slot"),
        ("not-applicable", "invalid_not_applicable_evidence"),
        ("missing-command", "missing_command_evidence"),
        ("inconsistent-command", "invalid_evidence_command"),
        ("failed-pass", "invalid_pass_verdict"),
        ("next-action", "invalid_permitted_next_action"),
        ("forbidden-claim", "forbidden_lifecycle_claim"),
        ("unknown-claim", "malformed_agent_result"),
        ("runtime-model", "runtime_specific_result"),
        ("target-risk", "target_risk_mismatch"),
        ("reviewer-role", "invalid_result_reference"),
        ("normalized-changed-path", "malformed_agent_result"),
        ("authority", "malformed_agent_result"),
        ("unknown-verdict", "malformed_agent_result"),
    ],
)
def test_agent_result_fails_closed_without_mutation(tmp_path: Path, scenario: str, expected_code: str) -> None:
    root, _ = setup_root(tmp_path)
    payload = valid_result(root, "implementation")
    if scenario == "extra-field":
        payload["provider"] = "forbidden"
    elif scenario == "stale-target":
        payload["target"]["sha256"] = "0" * 64
    elif scenario == "target-identity":
        payload["target"]["revision"] = 1
    elif scenario == "required-reference":
        payload["reviewer_run_ref"] = None
    elif scenario == "extra-reference-field":
        payload["reviewer_run_ref"]["path"] = ".specbound/agent-results/independent-reviewer/result-independent-reviewer.json"
    elif scenario == "provenance":
        payload["context_provenance"]["producer_transcript_inherited"] = True
    elif scenario == "missing-target-provenance":
        payload["context_provenance"]["input_artifacts"] = []
    elif scenario == "tool":
        payload["tool_categories"].append("network-write")
    elif scenario == "mutation":
        payload["mutation_class"] = "evidence_write"
    elif scenario == "outside-path":
        outside = root / "outside.py"
        outside.write_text("outside = True\n", encoding="utf-8", newline="\n")
        outside_ref = exact_ref(root, "outside.py", "outside", None)
        payload["changed_paths"] = ["outside.py"]
        payload["evidence"][0]["artifacts"].append(outside_ref)
    elif scenario == "missing-evidence":
        payload["evidence"] = [item for item in payload["evidence"] if item["slot"] != "test-results"]
    elif scenario == "not-applicable":
        item = next(item for item in payload["evidence"] if item["slot"] == "test-results")
        item.update({"status": "not_applicable", "artifacts": [], "commands": [], "reason": "No applicable test evidence exists."})
    elif scenario == "missing-command":
        item = next(item for item in payload["evidence"] if item["slot"] == "test-results")
        item["commands"] = []
    elif scenario == "inconsistent-command":
        item = next(item for item in payload["evidence"] if item["slot"] == "test-results")
        item["commands"] = [{"command": "pytest", "result": "passed", "exit_code": 1}]
    elif scenario == "failed-pass":
        item = next(item for item in payload["evidence"] if item["slot"] == "test-results")
        item["commands"] = [{"command": "pytest", "result": "failed", "exit_code": 1}]
    elif scenario == "next-action":
        payload["permitted_next_action"] = "merge"
    elif scenario == "forbidden-claim":
        payload["claims"] = ["approval"]
    elif scenario == "unknown-claim":
        payload["claims"] = ["merge-authorized"]
    elif scenario == "runtime-model":
        payload["model_alias"] = "openai-reviewer"
    elif scenario == "target-risk":
        target_path = root / payload["target"]["path"]
        target_path.write_text(target_path.read_text(encoding="utf-8").replace("risk: high", "risk: low"), encoding="utf-8", newline="\n")
        updated_target = exact_ref(root, payload["target"]["path"], payload["target"]["id"], None)
        payload["target"] = updated_target
        payload["context_provenance"]["input_artifacts"] = [updated_target]
        for evidence in payload["evidence"]:
            evidence["artifacts"] = [updated_target if item["path"] == updated_target["path"] else item for item in evidence["artifacts"]]
        parts = PurePosixPath(updated_target["path"]).parts
        review_path = root / f".specbound/micro-spec-reviews/{parts[2]}/{Path(parts[3]).stem}.review.json"
        review = json.loads(review_path.read_text(encoding="utf-8"))
        review["micro_spec_sha256"] = updated_target["sha256"]
        review_path.write_text(json.dumps(review, indent=2) + "\n", encoding="utf-8", newline="\n")
    elif scenario == "reviewer-role":
        payload["reviewer_run_ref"]["role_id"] = "delivery-qc"
    elif scenario == "normalized-changed-path":
        payload["changed_paths"] = ["src//fixture_impl.py"]
    elif scenario == "authority":
        payload["authority_type"] = "review-authority"
        payload["authority_action_id"] = "action-1"
    else:
        payload["verdict"] = "completed"
    result_path = write_json(root, "result.json", payload)
    before = repository_snapshot(root)
    result = validate_agent_result(root, result_path, POLICY_REL)
    after = repository_snapshot(root)
    assert expected_code in {item["code"] for item in result.blockers}, result.blockers
    assert after == before


@pytest.mark.parametrize("role_id", sorted(ROLE_IDS))
@pytest.mark.parametrize("scenario", ["path", "tool", "mutation", "output", "claim"])
def test_each_role_result_rejects_forbidden_boundary_without_mutation(
    tmp_path: Path, role_id: str, scenario: str
) -> None:
    root, _ = setup_root(tmp_path)
    payload = valid_result(root, role_id)
    if scenario == "path":
        authority = root / ".specbound/approvals/unauthorized.json"
        authority.parent.mkdir(parents=True, exist_ok=True)
        authority.write_text("{}\n", encoding="utf-8", newline="\n")
        authority_ref = exact_ref(root, ".specbound/approvals/unauthorized.json", "unauthorized", None)
        payload["changed_paths"] = [authority_ref["path"]]
        payload["evidence"][0]["artifacts"].append(authority_ref)
    elif scenario == "tool":
        payload["tool_categories"].append("external-write")
    elif scenario == "mutation":
        payload["mutation_class"] = "authority_mutation"
    elif scenario == "output":
        payload["output_kind"] = "authority-record"
    else:
        payload["claims"] = ["approval"]
    result_path = write_json(root, "result.json", payload)
    before = repository_snapshot(root)

    result = validate_agent_result(root, result_path, POLICY_REL)

    assert result.valid is False
    assert repository_snapshot(root) == before


def test_independent_reviewer_must_report_no_changed_paths(tmp_path: Path) -> None:
    root, _ = setup_root(tmp_path)
    payload = valid_result(root, "independent-reviewer")
    changed = root / "review.txt"
    changed.write_text("forbidden\n", encoding="utf-8", newline="\n")
    payload["changed_paths"] = ["review.txt"]
    payload["evidence"][0]["artifacts"].append(exact_ref(root, "review.txt", "review", None))
    result = validate_agent_result(root, write_json(root, "result.json", payload), POLICY_REL)
    assert "reviewer_mutation" in {item["code"] for item in result.blockers}


@pytest.mark.parametrize("role_id", sorted(ROLE_IDS))
def test_each_role_enforces_required_or_forbidden_reviewer_reference(tmp_path: Path, role_id: str) -> None:
    root, _ = setup_root(tmp_path)
    role = role_contract(role_id)
    request = valid_request(root, role_id)
    result_payload = valid_result(root, role_id)
    invalid_value = None if role["result_references"]["reviewer_run_ref"] == "required" else result_reference(root)
    request["reviewer_run_ref"] = invalid_value
    result_payload["reviewer_run_ref"] = invalid_value

    request_result = validate_role_request(root, write_json(root, "request.json", request), POLICY_REL)
    agent_result = validate_agent_result(root, write_json(root, "result.json", result_payload), POLICY_REL)

    assert "invalid_result_reference" in {item["code"] for item in request_result.blockers}
    assert "invalid_result_reference" in {item["code"] for item in agent_result.blockers}


def test_symlink_target_and_changed_path_fail_closed_when_supported(tmp_path: Path) -> None:
    root, _ = setup_root(tmp_path)
    payload = valid_request(root, "discovery-author")
    external = tmp_path / "external.md"
    external.write_text("external\n", encoding="utf-8", newline="\n")
    link = root / "targets/link.md"
    try:
        link.symlink_to(external)
    except OSError:
        pytest.skip("symlink creation is unavailable on this Windows host")
    payload["target"] = {"path": "targets/link.md", "id": "link", "revision": None, "sha256": sha256(external.read_bytes()).hexdigest()}
    result = validate_role_request(root, write_json(root, "request.json", payload), POLICY_REL)
    assert "invalid_target_path" in {item["code"] for item in result.blockers}


def test_role_request_rejects_mutation_path_through_external_link_or_junction(tmp_path: Path) -> None:
    root, _ = setup_root(tmp_path)
    payload = valid_request(root, "requirement-author")
    external = tmp_path / "external"
    external.mkdir()
    linked_parent = root / ".specbound/requirements/req-9100"
    linked_parent.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(linked_parent), str(external)],
            capture_output=True,
            text=True,
            encoding="mbcs",
            errors="replace",
            check=False,
        )
        if created.returncode != 0:
            pytest.skip(f"junction creation is unavailable: {created.stderr or created.stdout}")
    else:
        linked_parent.symlink_to(external, target_is_directory=True)
    payload["requested_capabilities"]["paths"] = [
        ".specbound/requirements/req-9100/req-9100-r1.md"
    ]

    result = validate_role_request(root, write_json(root, "request.json", payload), POLICY_REL)

    assert "unsafe_capability_path" in {item["code"] for item in result.blockers}, result.blockers


def test_symlinked_changed_path_fails_closed_when_supported(tmp_path: Path) -> None:
    root, _ = setup_root(tmp_path)
    payload = valid_result(root, "implementation")
    changed = root / "src/fixture_impl.py"
    real = root / "src/real_impl.py"
    real.write_text(changed.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    changed.unlink()
    try:
        changed.symlink_to(real)
    except OSError:
        pytest.skip("symlink creation is unavailable on this Windows host")
    linked_ref = exact_ref(root, "src/fixture_impl.py", "fixture_impl", None)
    for evidence in payload["evidence"]:
        evidence["artifacts"] = [linked_ref if item["path"] == "src/fixture_impl.py" else item for item in evidence["artifacts"]]
    result = validate_agent_result(root, write_json(root, "result.json", payload), POLICY_REL)
    assert "invalid_changed_path" in {item["code"] for item in result.blockers}


def test_agent_cli_commands_are_read_only(tmp_path: Path) -> None:
    root, _ = setup_root(tmp_path)
    request_path = write_json(root, "request.json", valid_request(root, "implementation"))
    result_path = write_json(root, "result.json", valid_result(root, "implementation"))
    before = repository_snapshot(root)
    request_run = run_cli(root, "agent", "check-role-request", "--request-file", str(request_path))
    result_run = run_cli(root, "agent", "validate-result", "--result-file", str(result_path))
    after = repository_snapshot(root)
    assert request_run.returncode == 0, request_run.stdout
    assert result_run.returncode == 0, result_run.stdout
    assert after == before


def test_root_validate_checks_enabled_policy_and_disabled_adopter_stays_compatible(tmp_path: Path) -> None:
    enabled = tmp_path / "enabled"
    shutil.copytree(VALID_FIXTURE, enabled)
    enabled_run = run_cli(enabled, "validate")
    assert enabled_run.returncode == 0, enabled_run.stdout
    assert json.loads(enabled_run.stdout)["checked_agent_roles"] == 7

    disabled = tmp_path / "disabled"
    shutil.copytree(VALID_FIXTURE, disabled)
    config = yaml.safe_load((disabled / "specbound.yaml").read_text(encoding="utf-8"))
    config["policy"].pop("agent_contract")
    shutil.rmtree(disabled / ".specbound/policies")
    (disabled / "specbound.yaml").write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8", newline="\n")
    disabled_run = run_cli(disabled, "validate")
    assert disabled_run.returncode == 0, disabled_run.stdout
    assert json.loads(disabled_run.stdout)["checked_agent_roles"] == 0


def test_packaged_schemas_and_fixture_policies_match_repository_contract() -> None:
    for name in ("agent-roles.schema.json", "agent-result.schema.json"):
        assert (ROOT / "schemas" / name).read_bytes() == (ROOT / "src/specbound/schemas" / name).read_bytes()
    assert (ROOT / POLICY_REL).read_bytes() == (VALID_FIXTURE / POLICY_REL).read_bytes()
    assert (ROOT / POLICY_REL).read_bytes() == (AGENT_FIXTURE / POLICY_REL).read_bytes()
    assert (ROOT / POLICY_REL).read_bytes() == (ROOT / "fixtures/invalid-unsafe-path" / POLICY_REL).read_bytes()


def test_repository_schema_cannot_override_packaged_core_contract(tmp_path: Path) -> None:
    root, _ = setup_root(tmp_path)
    payload = valid_result(root, "implementation")
    schemas = root / "schemas"
    schemas.mkdir()
    local_schema = json.loads((ROOT / "schemas/agent-result.schema.json").read_text(encoding="utf-8"))
    local_schema["additionalProperties"] = True
    (schemas / "agent-result.schema.json").write_text(json.dumps(local_schema), encoding="utf-8", newline="\n")

    result = validate_agent_result(root, write_json(root, "result.json", payload), POLICY_REL)

    assert "malformed_agent_result" in {item["code"] for item in result.blockers}


def test_implementation_scope_comes_from_exact_reviewed_micro_spec_scope() -> None:
    target = ".specbound/micro-specs/req-0004/ms-0004-001.md"
    scoped = _reviewed_micro_spec_paths(ROOT, target)
    role = role_contract("implementation")

    assert ("src/specbound/agent_contract.py", False) in scoped
    assert ("fixtures/agent-contract", True) in scoped
    assert ("src/specbound/schemas/agent-result.schema.json", False) in scoped
    assert ("fixtures/valid-minimal/specbound.yaml", False) in scoped
    assert ("fixtures/valid-minimal/.specbound/policies/agent-roles.yaml", False) in scoped
    assert ("fixtures/invalid-unsafe-path/specbound.yaml", False) in scoped
    assert ("fixtures/invalid-unsafe-path/.specbound/policies/agent-roles.yaml", False) in scoped
    assert _changed_path_allowed(ROOT, "src/specbound/agent_contract.py", role, target)
    assert _changed_path_allowed(ROOT, "fixtures/agent-contract/positive/implementation.result.json", role, target)
    assert not _changed_path_allowed(ROOT, "src/specbound/agent_contract.py/escape", role, target)
    assert not _changed_path_allowed(ROOT, "README.md", role, target)


@pytest.mark.parametrize("role_id", sorted(ROLE_IDS))
def test_static_fixtures_cover_positive_and_negative_contracts(role_id: str) -> None:
    positive_request = validate_role_request(
        AGENT_FIXTURE,
        AGENT_FIXTURE / f"positive/{role_id}.request.json",
        POLICY_REL,
    )
    negative_request = validate_role_request(
        AGENT_FIXTURE,
        AGENT_FIXTURE / f"negative/{role_id}.request.json",
        POLICY_REL,
    )
    positive_result = validate_agent_result(
        AGENT_FIXTURE,
        AGENT_FIXTURE / f"positive/{role_id}.result.json",
        POLICY_REL,
    )
    negative_result = validate_agent_result(
        AGENT_FIXTURE,
        AGENT_FIXTURE / f"negative/{role_id}.result.json",
        POLICY_REL,
    )

    assert positive_request.valid is True, positive_request.blockers
    assert "current_state_spoofing" in {item["code"] for item in negative_request.blockers}
    assert positive_result.valid is True, positive_result.blockers
    assert "forbidden_lifecycle_claim" in {item["code"] for item in negative_result.blockers}


def test_adoption_template_remains_preflight_valid(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    shutil.copytree(VALID_FIXTURE, root)
    shutil.copyfile(ROOT / "templates/specbound.yaml", root / "specbound.yaml")

    completed = run_cli(root, "preflight")

    assert completed.returncode == 0, completed.stdout


def test_agent_contract_fixture_bytes_are_cross_platform_stable_lf() -> None:
    text_suffixes = {".json", ".md", ".py", ".yaml", ".yml"}
    crlf_paths = [
        path.relative_to(AGENT_FIXTURE).as_posix()
        for path in AGENT_FIXTURE.rglob("*")
        if path.is_file() and path.suffix in text_suffixes and b"\r\n" in path.read_bytes()
    ]

    assert crlf_paths == []


def test_policy_declares_closed_risk_order_and_exact_task_floors() -> None:
    policy = actual_policy()

    assert policy["risk_order"] == ["low", "medium", "high"]
    assert {role["role_id"]: role["task_risk_floor"] for role in policy["roles"]} == {
        "discovery-author": "low",
        "requirement-author": "low",
        "micro-spec-author": "low",
        "independent-reviewer": "medium",
        "implementation": "medium",
        "iteration-qc": "medium",
        "delivery-qc": "medium",
    }
    validation = validate_agent_roles_policy(ROOT, POLICY_REL)
    assert validation.valid is True, validation.blockers


def test_policy_declares_closed_evidence_applicability_and_high_risk_requirements() -> None:
    policy = actual_policy()

    assert policy["evidence_applicability"] == {
        "none": {"supported": True},
        "candidate_write": {"supported": True},
        "repository_mutation": {"supported": True},
        "evidence_write": {"supported": True},
        "authority_transition": {"supported": False},
        "external_mutation": {"supported": False},
    }
    implementation = role_contract("implementation", policy)
    assert implementation["evidence_requirements_by_risk"]["high"] == {
        "required": [
            "target-binding",
            "test-results",
            "negative-tests",
            "regression-evidence",
            "rollback-inventory",
            "supported-ci",
        ],
        "conditional": [],
    }


def test_policy_declares_exact_existing_lifecycle_transition_crosswalk() -> None:
    assert actual_policy()["transition_crosswalk"] == {
        "discovery-confirmation": {
            "selector": "discovery_confirmation_authorities_by_risk",
            "writer": "create_discovery_confirmation",
            "risk_input": "canonical_artifact_risk",
        },
        "requirement-review-decision": {
            "selector": "requirement_review_decision_authorities_by_risk",
            "writer": "record_review_decision",
            "risk_input": "canonical_artifact_risk",
        },
        "requirement-rejection": {
            "selector": "requirement_review_authorities_by_risk",
            "writer": "reject_requirement",
            "risk_input": "canonical_artifact_risk",
        },
        "requirement-reconsideration": {
            "selector": "requirement_reconsideration_authorities_by_risk",
            "writer": "reconsider_requirement",
            "risk_input": "canonical_artifact_risk",
        },
        "requirement-approval": {
            "selector": "requirement_approval_authorities_by_risk",
            "writer": "approve_requirement",
            "risk_input": "canonical_artifact_risk",
        },
        "micro-spec-review": {
            "selector": "micro_spec_review_authorities_by_risk",
            "writer": "record_micro_spec_review",
            "risk_input": "canonical_artifact_risk",
        },
        "delivery-qc-verification": {
            "selector": "delivery_qc_authorities_by_risk",
            "writer": "publish_issuance",
            "risk_input": "canonical_artifact_risk",
        },
    }


def test_policy_declares_closed_consumer_reference_edges() -> None:
    policy = actual_policy()
    reviewer = role_contract("independent-reviewer", policy)
    implementation = role_contract("implementation", policy)
    iteration_qc = role_contract("iteration-qc", policy)
    delivery_qc = role_contract("delivery-qc", policy)

    assert reviewer["reference_edges"]["producer_result_ref"] == {
        "allowed_roles": ["discovery-author", "requirement-author", "micro-spec-author"],
        "target_binding": "exact-target",
        "required_verdict": "pass",
    }
    assert implementation["reference_edges"]["reviewer_run_ref"] == {
        "allowed_roles": ["independent-reviewer"],
        "target_binding": "exact-target",
        "required_verdict": "pass",
    }
    assert iteration_qc["reference_edges"] == {
        "producer_result_ref": {
            "allowed_roles": ["implementation"],
            "target_binding": "exact-target",
            "required_verdict": "pass",
        },
        "reviewer_run_ref": {
            "allowed_roles": ["independent-reviewer"],
            "target_binding": "exact-target",
            "required_verdict": "pass",
        },
    }
    assert delivery_qc["result_references"] == {
        "producer_result_ref": "forbidden",
        "reviewer_run_ref": "forbidden",
    }
    assert delivery_qc["reference_edges"] == {
        "producer_result_ref": None,
        "reviewer_run_ref": None,
    }
