from __future__ import annotations

import asyncio
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

import specbound.hermes_adapter as hermes_adapter
from specbound.hermes_adapter import execute_hermes_invocation


ROOT = Path(__file__).resolve().parents[1]
AGENT_FIXTURE = ROOT / "fixtures" / "agent-contract"
HERMES_FIXTURE = ROOT / "fixtures" / "hermes-adapter"
VALID_FIXTURE = ROOT / "fixtures" / "valid-minimal"
REPOSITORY_SKILLS = ROOT / "skills"
ROLE_IDS = (
    "discovery-author",
    "requirement-author",
    "micro-spec-author",
    "independent-reviewer",
    "implementation",
    "iteration-qc",
    "delivery-qc",
)
REFERENCE_FILES = {
    "independent-reviewer": (
        "reference-results/independent-reviewer-producer_result_ref.json",
    ),
    "implementation": (
        "reference-results/implementation-reviewer_run_ref.json",
        "reference-results/implementation-reviewer-producer_result_ref.json",
    ),
    "iteration-qc": (
        "reference-results/iteration-qc-producer_result_ref.json",
        "reference-results/iteration-qc-reviewer_run_ref.json",
        "reference-results/iteration-qc-reviewer-producer_result_ref.json",
    ),
}
REQUIRED_CAPABILITIES = (
    "fresh_leaf_context",
    "single_model_alias",
    "exact_workdir",
    "exact_skill_binding",
    "tool_allowlist",
    "path_boundary",
    "no_context_reuse",
    "structured_completion",
)


def _run_cli(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    return subprocess.run(
        [sys.executable, "-m", "specbound.cli", "--root", str(root), *args],
        cwd=ROOT,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def _json_output(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
    assert result.stdout.strip(), result
    return json.loads(result.stdout)


def _snapshot(root: Path, *, excluded_roots: tuple[str, ...] = (".git", ".venv")) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] in excluded_roots:
            continue
        if any(part in {"__pycache__", ".pytest_cache"} for part in relative.parts):
            continue
        snapshot[relative.as_posix()] = sha256(path.read_bytes()).hexdigest()
    return snapshot


def _reference_args(role_id: str) -> list[str]:
    arguments: list[str] = []
    for relative in REFERENCE_FILES.get(role_id, ()):
        arguments.extend(("--reference-result-file", relative))
    return arguments


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _adapter_root(tmp_path: Path, role_id: str) -> tuple[Path, Path]:
    root = tmp_path / "adapter-repository"
    shutil.copytree(AGENT_FIXTURE, root)
    shutil.copytree(REPOSITORY_SKILLS, root / "skills")
    adapter_root = root / "hermes-adapter"
    adapter_root.mkdir()
    shutil.copyfile(HERMES_FIXTURE / "valid/config.json", adapter_root / "config.json")
    invocation_path = adapter_root / "invocation.json"
    _write_json(
        invocation_path,
        {
            "schema_version": 1,
            "config_file": "hermes-adapter/config.json",
            "request_file": f"positive/{role_id}.request.json",
            "reference_result_files": list(REFERENCE_FILES.get(role_id, ())),
        },
    )
    return root, invocation_path


class _IntegrationDispatcher:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.capabilities = {name: True for name in REQUIRED_CAPABILITIES}
        self.calls: list[dict[str, object]] = []

    def dispatch(self, specification: dict[str, object]) -> dict[str, object]:
        self.calls.append(specification)
        source = json.loads(
            (self.root / f"positive/{specification['role_id']}.result.json").read_text(
                encoding="utf-8"
            )
        )
        result_fields = {
            key: source[key]
            for key in (
                "result_id",
                "context_provenance",
                "mutation_class",
                "changed_paths",
                "evidence",
                "verdict",
                "findings",
                "permitted_next_action",
                "claims",
            )
        }
        return {
            "schema_version": 1,
            "execution_id": specification["planned_execution_id"],
            "context_id": specification["planned_context_id"],
            "model_alias": specification["model_alias"],
            "applied_skill_path": specification["skill_path"],
            "applied_skill_sha256": specification["skill_sha256"],
            "result": result_fields,
        }


def test_actual_repository_root_and_skill_inventory_is_exactly_seven_and_read_only() -> None:
    before = _snapshot(ROOT)

    validation = _run_cli(ROOT, "validate")
    skills = _run_cli(ROOT, "agent", "validate-skills")

    assert validation.returncode == 0, validation.stdout
    validation_payload = _json_output(validation)
    assert validation_payload["valid"] is True
    assert validation_payload["blockers"] == []
    assert validation_payload["checked_agent_roles"] == 7
    assert validation_payload["checked_agent_skills"] == 7

    assert skills.returncode == 0, skills.stdout
    skill_payload = _json_output(skills)
    assert skill_payload["valid"] is True
    assert skill_payload["blockers"] == []
    assert skill_payload["checked_roles"] == 7
    assert skill_payload["checked_agent_skills"] == 7
    policy = yaml.safe_load((ROOT / ".specbound/policies/agent-roles.yaml").read_text(encoding="utf-8"))
    assert tuple(role["role_id"] for role in policy["roles"]) == ROLE_IDS
    assert _snapshot(ROOT) == before


@pytest.mark.parametrize("role_id", ROLE_IDS)
def test_seven_role_request_cli_matrix_is_reason_specific_and_read_only(role_id: str) -> None:
    positive = AGENT_FIXTURE / f"positive/{role_id}.request.json"
    negative = AGENT_FIXTURE / f"negative/{role_id}.request.json"
    assert positive.read_bytes() != negative.read_bytes()
    before = _snapshot(AGENT_FIXTURE, excluded_roots=())

    accepted = _run_cli(
        AGENT_FIXTURE,
        "agent",
        "check-role-request",
        "--request-file",
        str(positive),
        *_reference_args(role_id),
    )
    rejected = _run_cli(
        AGENT_FIXTURE,
        "agent",
        "check-role-request",
        "--request-file",
        str(negative),
        *_reference_args(role_id),
    )

    assert accepted.returncode == 0, accepted.stdout
    accepted_payload = _json_output(accepted)
    assert accepted_payload["valid"] is True
    assert accepted_payload["role_id"] == role_id
    assert accepted_payload["blockers"] == []
    assert rejected.returncode == 2, rejected.stdout
    rejected_payload = _json_output(rejected)
    assert rejected_payload["valid"] is False
    assert {item["code"] for item in rejected_payload["blockers"]} == {
        "current_state_spoofing"
    }
    assert rejected_payload["permitted_next_action"] == "none"
    assert _snapshot(AGENT_FIXTURE, excluded_roots=()) == before


@pytest.mark.parametrize("role_id", ROLE_IDS)
def test_seven_role_result_cli_matrix_is_reason_specific_and_read_only(role_id: str) -> None:
    positive = AGENT_FIXTURE / f"positive/{role_id}.result.json"
    negative = AGENT_FIXTURE / f"negative/{role_id}.result.json"
    assert positive.read_bytes() != negative.read_bytes()
    before = _snapshot(AGENT_FIXTURE, excluded_roots=())

    accepted = _run_cli(
        AGENT_FIXTURE,
        "agent",
        "validate-result",
        "--result-file",
        str(positive),
        *_reference_args(role_id),
    )
    rejected = _run_cli(
        AGENT_FIXTURE,
        "agent",
        "validate-result",
        "--result-file",
        str(negative),
        *_reference_args(role_id),
    )

    assert accepted.returncode == 0, accepted.stdout
    accepted_payload = _json_output(accepted)
    assert accepted_payload["valid"] is True
    assert accepted_payload["role_id"] == role_id
    assert accepted_payload["blockers"] == []
    assert rejected.returncode == 2, rejected.stdout
    rejected_payload = _json_output(rejected)
    assert rejected_payload["valid"] is False
    expected_codes = {"forbidden_lifecycle_claim"}
    if role_id == "independent-reviewer":
        expected_codes.add("invalid_no_write_proof")
    assert {item["code"] for item in rejected_payload["blockers"]} == expected_codes
    assert rejected_payload["permitted_next_action"] == "none"
    assert _snapshot(AGENT_FIXTURE, excluded_roots=()) == before


@pytest.mark.parametrize("role_id", ROLE_IDS)
def test_seven_role_adapter_matrix_is_exactly_one_shot_and_read_only(
    tmp_path: Path, role_id: str
) -> None:
    root, invocation_path = _adapter_root(tmp_path, role_id)
    before = _snapshot(root, excluded_roots=())
    dispatcher = _IntegrationDispatcher(root)

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is True
    assert outcome.dispatched is True
    assert outcome.call_count == 1
    assert outcome.blockers == []
    assert outcome.result is not None
    assert outcome.result["role_id"] == role_id
    assert outcome.result["model_alias"] == "worker-model"
    assert len(dispatcher.calls) == 1
    specification = dispatcher.calls[0]
    assert specification["role_id"] == role_id
    assert specification["execution_mode"] == "leaf"
    assert specification["workdir"] == str(root.resolve())
    assert specification["model_alias"] == "worker-model"
    assert specification["skill_path"] == f"skills/{role_id}/SKILL.md"
    assert specification["skill_sha256"] == sha256(
        (root / f"skills/{role_id}/SKILL.md").read_bytes()
    ).hexdigest()
    assert specification["planned_execution_id"] == f"execution-{role_id}"
    assert specification["planned_context_id"] == f"context-{role_id}"
    assert _snapshot(root, excluded_roots=()) == before


@pytest.mark.parametrize(
    ("failure", "expected_calls", "expected_dispatched", "expected_code"),
    (
        ("missing-capability", 0, False, "unenforced_dispatcher_capability"),
        ("timeout", 1, False, "hermes_dispatch_failed"),
        ("cancelled", 1, False, "hermes_dispatch_cancelled"),
        ("malformed-completion", 1, True, "malformed_hermes_completion"),
        ("core-result-rejection", 1, True, "forbidden_lifecycle_claim"),
        ("destination-conflict", 0, False, "result_destination_exists"),
    ),
)
def test_adapter_failure_matrix_is_no_retry_and_no_partial_mutation(
    tmp_path: Path,
    failure: str,
    expected_calls: int,
    expected_dispatched: bool,
    expected_code: str,
) -> None:
    root, invocation_path = _adapter_root(tmp_path, "implementation")
    invocation = json.loads(invocation_path.read_text(encoding="utf-8"))
    destination = "candidates/agent-results/integration-failure.json"
    invocation["result_destination"] = destination
    _write_json(invocation_path, invocation)

    class FailureDispatcher(_IntegrationDispatcher):
        def dispatch(self, specification: dict[str, object]) -> dict[str, object]:
            if failure == "timeout":
                self.calls.append(specification)
                raise TimeoutError("bounded integration timeout")
            if failure == "cancelled":
                self.calls.append(specification)
                raise asyncio.CancelledError("bounded integration cancellation")
            completion = super().dispatch(specification)
            if failure == "malformed-completion":
                completion["result"]["provider"] = "forbidden-runtime-field"  # type: ignore[index]
            elif failure == "core-result-rejection":
                completion["result"]["claims"] = ["approval"]  # type: ignore[index]
            return completion

    dispatcher = FailureDispatcher(root)
    if failure == "missing-capability":
        dispatcher.capabilities.pop("structured_completion")
    if failure == "destination-conflict":
        (root / destination).parent.mkdir(parents=True)
        (root / destination).write_text("sentinel\n", encoding="utf-8")
    before = _snapshot(root, excluded_roots=())

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.dispatched is expected_dispatched
    assert outcome.call_count == expected_calls
    assert outcome.result is None
    assert outcome.permitted_next_action == "none"
    assert {item["code"] for item in outcome.blockers} == {expected_code}
    assert len(dispatcher.calls) == expected_calls
    if failure == "destination-conflict":
        assert (root / destination).read_text(encoding="utf-8") == "sentinel\n"
    else:
        assert not (root / destination).exists()
        assert not (root / "candidates").exists()
    assert _snapshot(root, excluded_roots=()) == before


def test_post_preflight_immutable_request_replacement_is_zero_call_and_no_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, invocation_path = _adapter_root(tmp_path, "discovery-author")
    destination = "candidates/agent-results/replaced-input.json"
    invocation = json.loads(invocation_path.read_text(encoding="utf-8"))
    invocation["result_destination"] = destination
    _write_json(invocation_path, invocation)
    request_path = root / "positive/discovery-author.request.json"
    replacement = (root / "positive/micro-spec-author.request.json").read_bytes()
    original = hermes_adapter.validate_configured_role_request

    def validate_then_replace(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)
        request_path.write_bytes(replacement)
        return result

    monkeypatch.setattr(
        hermes_adapter, "validate_configured_role_request", validate_then_replace
    )
    dispatcher = _IntegrationDispatcher(root)
    canonical_before = _snapshot(root / ".specbound", excluded_roots=())

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.dispatched is False
    assert outcome.call_count == 0
    assert outcome.result is None
    assert outcome.permitted_next_action == "none"
    assert {item["code"] for item in outcome.blockers} == {"input_binding_changed"}
    assert dispatcher.calls == []
    assert not (root / destination).exists()
    assert not (root / "candidates").exists()
    assert _snapshot(root / ".specbound", excluded_roots=()) == canonical_before


@pytest.mark.parametrize(
    ("scenario", "command", "role_id", "expected_code"),
    (
        ("risk", "check-role-request", "implementation", "effective_task_risk_spoofing"),
        ("lifecycle", "check-role-request", "implementation", "current_state_spoofing"),
        ("evidence", "validate-result", "implementation", "missing_evidence_slot"),
        ("independence", "validate-result", "independent-reviewer", "self_reference_result"),
    ),
)
def test_cross_slice_risk_independence_evidence_and_lifecycle_regressions(
    tmp_path: Path,
    scenario: str,
    command: str,
    role_id: str,
    expected_code: str,
) -> None:
    root = tmp_path / f"cross-slice-{scenario}"
    shutil.copytree(AGENT_FIXTURE, root)
    kind = "request" if command == "check-role-request" else "result"
    artifact_path = root / f"positive/{role_id}.{kind}.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    if scenario == "risk":
        artifact["effective_task_risk"] = "low"
    elif scenario == "lifecycle":
        artifact["current_state"] = "in_review"
    elif scenario == "evidence":
        artifact["evidence"] = [
            item for item in artifact["evidence"] if item["slot"] != "rollback-inventory"
        ]
    else:
        producer = json.loads((root / REFERENCE_FILES[role_id][0]).read_text(encoding="utf-8"))
        artifact["planned_execution_id"] = producer["execution_id"]
        artifact["execution_id"] = producer["execution_id"]
    _write_json(artifact_path, artifact)
    before = _snapshot(root, excluded_roots=())
    artifact_option = "--request-file" if kind == "request" else "--result-file"

    rejected = _run_cli(
        root,
        "agent",
        command,
        artifact_option,
        str(artifact_path),
        *_reference_args(role_id),
    )

    assert rejected.returncode == 2, rejected.stdout
    payload = _json_output(rejected)
    assert payload["valid"] is False
    assert {item["code"] for item in payload["blockers"]} == {expected_code}
    assert payload["permitted_next_action"] == "none"
    assert _snapshot(root, excluded_roots=()) == before


@pytest.mark.parametrize(
    "runtime_field",
    (
        "delegate_task",
        "provider",
        "vendor",
        "profile",
        "session_id",
        "hermes_tools",
        "workdir",
        "runtime_config",
    ),
)
def test_provider_neutral_request_rejects_runtime_field_leakage(
    tmp_path: Path, runtime_field: str
) -> None:
    root = tmp_path / "runtime-leakage"
    shutil.copytree(AGENT_FIXTURE, root)
    request_path = root / "positive/implementation.request.json"
    request = json.loads(request_path.read_text(encoding="utf-8"))
    request[runtime_field] = "forbidden-runtime-value"
    _write_json(request_path, request)
    assert request_path.read_bytes() != (
        AGENT_FIXTURE / "positive/implementation.request.json"
    ).read_bytes()
    before = _snapshot(root, excluded_roots=())

    rejected = _run_cli(
        root,
        "agent",
        "check-role-request",
        "--request-file",
        str(request_path),
        *_reference_args("implementation"),
    )

    assert rejected.returncode == 2, rejected.stdout
    payload = _json_output(rejected)
    assert payload["valid"] is False
    assert {item["code"] for item in payload["blockers"]} == {
        "malformed_role_request"
    }
    assert payload["permitted_next_action"] == "none"
    assert _snapshot(root, excluded_roots=()) == before


def test_disabled_adopter_preserves_manual_validation_and_docs_without_agent_artifacts(
    tmp_path: Path,
) -> None:
    root = tmp_path / "disabled-adopter"
    shutil.copytree(VALID_FIXTURE, root)
    config_path = root / "specbound.yaml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    config["policy"]["agent_contract"]["enabled"] = False
    config_path.write_text(
        yaml.safe_dump(config, sort_keys=False), encoding="utf-8", newline="\n"
    )
    shutil.rmtree(root / ".specbound/policies")
    shutil.rmtree(root / "skills")

    generated = _run_cli(root, "docs", "requirements")
    assert generated.returncode == 0, generated.stdout
    assert (root / "docs/requirements.md").is_file()
    before = _snapshot(root, excluded_roots=())

    validation = _run_cli(root, "validate")
    documentation = _run_cli(root, "docs", "requirements", "--check")
    explicit_agent_check = _run_cli(root, "agent", "validate-skills")

    assert validation.returncode == 0, validation.stdout
    validation_payload = _json_output(validation)
    assert validation_payload["valid"] is True
    assert validation_payload["checked_agent_roles"] == 0
    assert validation_payload["checked_agent_skills"] == 0
    assert documentation.returncode == 0, documentation.stdout
    assert explicit_agent_check.returncode == 2, explicit_agent_check.stdout
    agent_payload = _json_output(explicit_agent_check)
    assert {item["code"] for item in agent_payload["blockers"]} == {
        "agent_contract_disabled"
    }
    assert _snapshot(root, excluded_roots=()) == before


@pytest.mark.parametrize(
    ("scenario", "expected_code"),
    (
        ("missing-policy", "malformed_agent_roles_policy"),
        ("missing-skill", "missing_agent_skill"),
        ("unsafe-policy", "malformed_config"),
    ),
)
def test_enabled_adopter_fails_closed_for_missing_or_unsafe_contract_prerequisites(
    tmp_path: Path, scenario: str, expected_code: str
) -> None:
    root = tmp_path / "enabled-adopter"
    shutil.copytree(VALID_FIXTURE, root)
    if scenario == "missing-policy":
        (root / ".specbound/policies/agent-roles.yaml").unlink()
    elif scenario == "missing-skill":
        shutil.rmtree(root / "skills/implementation")
    else:
        config_path = root / "specbound.yaml"
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        config["policy"]["agent_contract"]["roles_path"] = "../outside.yaml"
        config_path.write_text(
            yaml.safe_dump(config, sort_keys=False), encoding="utf-8", newline="\n"
        )
    before = _snapshot(root, excluded_roots=())

    validation = _run_cli(root, "validate")

    assert validation.returncode == 2, validation.stdout
    payload = _json_output(validation)
    assert payload["valid"] is False
    assert {item["code"] for item in payload["blockers"]} == {expected_code}
    assert _snapshot(root, excluded_roots=()) == before


def test_template_is_default_disabled_while_repository_dogfood_is_not_live_adoption() -> None:
    template = yaml.safe_load((ROOT / "templates/specbound.yaml").read_text(encoding="utf-8"))
    repository = yaml.safe_load((ROOT / "specbound.yaml").read_text(encoding="utf-8"))

    assert template["policy"]["agent_contract"]["enabled"] is False
    assert repository["policy"]["agent_contract"]["enabled"] is True
    assert repository["policy"]["control_plane_adoption"]["requirements"] == []


def test_ci_installed_wheel_gate_is_isolated_and_complete() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    for required in (
        "unset PYTHONPATH",
        "site-packages",
        " -I ",
        "-c /dev/null",
        "tests/test_agent_integration.py",
        "tests/test_hermes_adapter.py",
        "agent-roles.schema.json",
        "agent-result.schema.json",
        "hermes-adapter-config.schema.json",
        "hermes-invocation.schema.json",
    ):
        assert required in workflow
    assert 'matrix:\n        python-version: ["3.11", "3.12"]' in workflow


@pytest.mark.parametrize(
    ("relative_path", "surface_requirements"),
    (
        (
            "README.md",
            ("specbound agent validate-skills", "specbound agent check-role-request", "specbound agent validate-result", "Fake/stub", "no role chain", "implicit retry"),
        ),
        (
            "AGENTS.md",
            ("src/specbound", "source.is_relative_to(expected)", "tests/test_agent_integration.py", "tests/test_hermes_adapter.py", "site-packages", "head_sha", "Python 3.11 and 3.12"),
        ),
        (
            "docs/governance/issue-sdlc.md",
            ("Producer", "Reviewer", "Implementation", "IQC", "DQC", "Delivery remains a distinct"),
        ),
        (
            "skills/specbound-harness/SKILL.md",
            (
                "provider-neutral",
                "fresh isolated one-shot context",
                "non-authorizing",
                "live Hermes rollout",
                ".specbound/policies/agent-roles.yaml",
                "skills/<role-id>/SKILL.md",
                ".specbound/micro-spec-reviews/",
                "policy.agent_contract",
                "agent_contract:",
                "discovery-author",
                "requirement-author",
                "micro-spec-author",
                "independent-reviewer",
                "implementation",
                "iteration-qc",
                "delivery-qc",
                "specbound agent validate-skills",
                "specbound agent check-role-request",
                "specbound agent validate-result",
                "site-packages",
            ),
        ),
        (
            "skills/specbound-harness/references/adopter-contract.md",
            (
                ".specbound/rejections/",
                ".specbound/review-submissions/",
                ".specbound/review-decisions/",
                ".specbound/reconsiderations/",
                ".specbound/micro-specs/",
                ".specbound/micro-spec-reviews/",
                ".specbound/iteration-qc/",
                ".specbound/delivery-qc/",
                "discovery-author",
                "requirement-author",
                "micro-spec-author",
                "independent-reviewer",
                "implementation",
                "iteration-qc",
                "delivery-qc",
                "enabled: false",
                "roles_path: .specbound/policies/agent-roles.yaml",
                "specbound agent validate-skills",
                "site-packages",
            ),
        ),
    ),
)
def test_guidance_uses_one_closed_agent_contract_boundary(
    relative_path: str, surface_requirements: tuple[str, ...]
) -> None:
    guidance = (ROOT / relative_path).read_text(encoding="utf-8")

    common_requirements = (
        "exactly seven roles",
        "one configured model alias",
        "fresh isolated one-shot context",
        "provider-neutral",
        "manual lifecycle workflow",
        "non-authorizing",
        "Delivery, Merge, or Release",
        "live Hermes rollout",
    )
    for required in (*common_requirements, *surface_requirements):
        assert required in guidance, f"{relative_path}: missing {required!r}"


def test_template_and_agent_cli_help_state_opt_in_read_only_boundary() -> None:
    template = (ROOT / "templates/specbound.yaml").read_text(encoding="utf-8")
    assert "# Agent contract is opt-in and default-disabled for adopters." in template
    assert (
        "# Enabling validates repository-local policy and skills; it does not roll out Hermes."
        in template
    )

    help_text = " ".join(_run_cli(ROOT, "agent", "--help").stdout.split())
    for required in (
        "provider-neutral",
        "read-only",
        "does not dispatch",
        "non-authorizing",
        "configured Hermes adapter",
    ):
        assert required in help_text
