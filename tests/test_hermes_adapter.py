from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
from pathlib import Path

import pytest

import specbound.hermes_adapter as hermes_adapter
from specbound.hermes_adapter import execute_hermes_invocation


FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "agent-contract"
HERMES_FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "hermes-adapter"
REPOSITORY_SKILLS = Path(__file__).parents[1] / "skills"
REQUIRED_CAPABILITIES = [
    "fresh_leaf_context",
    "single_model_alias",
    "exact_workdir",
    "exact_skill_binding",
    "tool_allowlist",
    "path_boundary",
    "no_context_reuse",
    "structured_completion",
]
ROLE_IDS = [
    "discovery-author",
    "requirement-author",
    "micro-spec-author",
    "independent-reviewer",
    "implementation",
    "iteration-qc",
    "delivery-qc",
]
REFERENCE_FILES = {
    "implementation": [
        "reference-results/implementation-reviewer_run_ref.json",
        "reference-results/implementation-reviewer-producer_result_ref.json",
    ],
    "independent-reviewer": [
        "reference-results/independent-reviewer-producer_result_ref.json"
    ],
    "iteration-qc": [
        "reference-results/iteration-qc-producer_result_ref.json",
        "reference-results/iteration-qc-reviewer_run_ref.json",
        "reference-results/iteration-qc-reviewer-producer_result_ref.json",
    ],
}


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _configured_root(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE_ROOT, root)
    shutil.copytree(REPOSITORY_SKILLS, root / "skills")
    adapter_root = root / "hermes-adapter"
    adapter_root.mkdir()
    shutil.copyfile(HERMES_FIXTURE_ROOT / "valid/config.json", adapter_root / "config.json")
    invocation_path = adapter_root / "invocation.json"
    shutil.copyfile(
        HERMES_FIXTURE_ROOT / "valid/implementation.invocation.json",
        invocation_path,
    )
    return root, invocation_path


def _set_invocation_role(
    root: Path,
    invocation_path: Path,
    role_id: str,
    *,
    request_kind: str = "positive",
    result_destination: str | None = None,
) -> None:
    invocation = {
        "schema_version": 1,
        "config_file": "hermes-adapter/config.json",
        "request_file": f"{request_kind}/{role_id}.request.json",
        "reference_result_files": REFERENCE_FILES.get(role_id, []),
    }
    if result_destination is not None:
        invocation["result_destination"] = result_destination
    _write_json(invocation_path, invocation)


class EnforcingDispatcher:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls: list[dict[str, object]] = []
        self.capabilities = {name: True for name in REQUIRED_CAPABILITIES}

    def dispatch(self, spec: dict[str, object]) -> dict[str, object]:
        self.calls.append(spec)
        source = json.loads(
            (self.root / f"positive/{spec['role_id']}.result.json").read_text(
                encoding="utf-8"
            )
        )
        mutable_fields = {
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
            "execution_id": spec["planned_execution_id"],
            "context_id": spec["planned_context_id"],
            "model_alias": spec["model_alias"],
            "applied_skill_path": spec["skill_path"],
            "applied_skill_sha256": spec["skill_sha256"],
            "result": mutable_fields,
        }


def test_one_shot_adapter_dispatches_once_and_returns_validated_result(tmp_path: Path) -> None:
    root, invocation_path = _configured_root(tmp_path)
    dispatcher = EnforcingDispatcher(root)

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is True
    assert outcome.dispatched is True
    assert outcome.call_count == 1
    assert outcome.blockers == []
    assert outcome.result is not None
    assert outcome.result["role_id"] == "implementation"
    assert outcome.result["model_alias"] == "worker-model"
    assert outcome.result["planned_execution_id"] == "execution-implementation"
    assert outcome.result["context_id"] == "context-implementation"
    assert outcome.permitted_next_action == "request-iteration-qc"
    assert len(dispatcher.calls) == 1
    spec = dispatcher.calls[0]
    assert spec["role_id"] == "implementation"
    assert spec["execution_mode"] == "leaf"
    assert spec["workdir"] == str(root.resolve())
    assert spec["skill_path"] == "skills/implementation/SKILL.md"
    assert spec["skill_sha256"] == hashlib.sha256(
        (root / "skills/implementation/SKILL.md").read_bytes()
    ).hexdigest()
    assert spec["model_alias"] == "worker-model"
    assert spec["request_sha256"] == hashlib.sha256(
        (root / "positive/implementation.request.json").read_bytes()
    ).hexdigest()
    assert spec["reference_result_sha256"] == {
        path: hashlib.sha256((root / path).read_bytes()).hexdigest()
        for path in REFERENCE_FILES["implementation"]
    }


@pytest.mark.parametrize("capability_name", REQUIRED_CAPABILITIES)
@pytest.mark.parametrize("capability_state", ["missing", "false"])
def test_unprovable_dispatcher_capability_is_zero_call(
    tmp_path: Path, capability_state: str, capability_name: str
) -> None:
    root, invocation_path = _configured_root(tmp_path)
    dispatcher = EnforcingDispatcher(root)
    if capability_state == "missing":
        dispatcher.capabilities.pop(capability_name)
    else:
        dispatcher.capabilities[capability_name] = False

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.dispatched is False
    assert outcome.call_count == 0
    assert outcome.result is None
    assert outcome.permitted_next_action == "none"
    assert {item["code"] for item in outcome.blockers} == {
        "unenforced_dispatcher_capability"
    }
    assert dispatcher.calls == []


@pytest.mark.parametrize(
    "category,tool",
    [
        ("repository-read", "shell"),
        ("repository-read", "web_search"),
        ("repository-read", "read_secret"),
        ("repository-read", "approve_release"),
        ("repository-read", "*"),
        ("repository-read", "unknown_tool"),
        ("repository-read", "write_file"),
    ],
)
def test_forbidden_unknown_or_misclassified_tool_is_zero_call(
    tmp_path: Path, category: str, tool: str
) -> None:
    root, invocation_path = _configured_root(tmp_path)
    config_path = root / "hermes-adapter/config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["tool_category_map"][category] = [tool]
    _write_json(config_path, config)
    dispatcher = EnforcingDispatcher(root)

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 0
    assert outcome.result is None
    assert outcome.permitted_next_action == "none"
    assert dispatcher.calls == []


@pytest.mark.parametrize("field", ["applied_skill_path", "applied_skill_sha256"])
def test_wrong_or_stale_skill_binding_blocks_after_one_call(
    tmp_path: Path, field: str
) -> None:
    root, invocation_path = _configured_root(tmp_path)

    class WrongSkillDispatcher(EnforcingDispatcher):
        def dispatch(self, spec: dict[str, object]) -> dict[str, object]:
            completion = super().dispatch(spec)
            completion[field] = "0" * 64 if field.endswith("sha256") else "skills/other/SKILL.md"
            return completion

    dispatcher = WrongSkillDispatcher(root)
    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.dispatched is True
    assert outcome.call_count == 1
    assert outcome.result is None
    assert outcome.permitted_next_action == "none"
    assert {item["code"] for item in outcome.blockers} == {"skill_binding_mismatch"}
    assert len(dispatcher.calls) == 1


def test_dispatcher_exception_is_not_retried(tmp_path: Path) -> None:
    root, invocation_path = _configured_root(tmp_path)

    class FailingDispatcher(EnforcingDispatcher):
        def dispatch(self, spec: dict[str, object]) -> dict[str, object]:
            self.calls.append(spec)
            raise TimeoutError("bounded runtime timeout")

    dispatcher = FailingDispatcher(root)
    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.dispatched is False
    assert outcome.call_count == 1
    assert outcome.result is None
    assert outcome.permitted_next_action == "none"
    assert {item["code"] for item in outcome.blockers} == {"hermes_dispatch_failed"}
    assert len(dispatcher.calls) == 1


def test_dispatch_cancellation_is_structured_and_leaves_no_partial_result(
    tmp_path: Path,
) -> None:
    root, invocation_path = _configured_root(tmp_path)
    destination = "candidates/agent-results/cancelled.json"
    _set_invocation_role(
        root, invocation_path, "implementation", result_destination=destination
    )

    class CancelledDispatcher(EnforcingDispatcher):
        def dispatch(self, spec: dict[str, object]) -> dict[str, object]:
            self.calls.append(spec)
            raise asyncio.CancelledError("bounded invocation cancelled")

    dispatcher = CancelledDispatcher(root)
    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.dispatched is False
    assert outcome.call_count == 1
    assert outcome.result is None
    assert outcome.permitted_next_action == "none"
    assert {item["code"] for item in outcome.blockers} == {
        "hermes_dispatch_cancelled"
    }
    assert len(dispatcher.calls) == 1
    assert not (root / destination).exists()
    assert not (root / "candidates").exists()


def test_runtime_model_alias_must_match_planned_alias(tmp_path: Path) -> None:
    root, invocation_path = _configured_root(tmp_path)

    class WrongModelDispatcher(EnforcingDispatcher):
        def dispatch(self, spec: dict[str, object]) -> dict[str, object]:
            completion = super().dispatch(spec)
            completion["model_alias"] = "unreviewed-model"
            return completion

    outcome = execute_hermes_invocation(root, invocation_path, WrongModelDispatcher(root))

    assert outcome.valid is False
    assert outcome.dispatched is True
    assert outcome.call_count == 1
    assert outcome.result is None
    assert outcome.permitted_next_action == "none"
    assert {item["code"] for item in outcome.blockers} == {"model_alias_mismatch"}


@pytest.mark.parametrize("role_id", ROLE_IDS)
def test_all_seven_roles_dispatch_exactly_once_with_reviewed_mapping(
    tmp_path: Path, role_id: str
) -> None:
    root, invocation_path = _configured_root(tmp_path)
    _set_invocation_role(root, invocation_path, role_id)
    dispatcher = EnforcingDispatcher(root)

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is True, outcome.blockers
    assert outcome.call_count == 1
    assert outcome.result is not None
    assert outcome.result["role_id"] == role_id
    assert len(dispatcher.calls) == 1
    spec = dispatcher.calls[0]
    assert spec["skill_path"] == f"skills/{role_id}/SKILL.md"
    assert spec["model_alias"] == "worker-model"
    assert spec["execution_mode"] == "leaf"


@pytest.mark.parametrize("role_id", ROLE_IDS)
def test_core_ineligible_request_blocks_before_dispatch(
    tmp_path: Path, role_id: str
) -> None:
    root, invocation_path = _configured_root(tmp_path)
    _set_invocation_role(root, invocation_path, role_id, request_kind="negative")
    dispatcher = EnforcingDispatcher(root)

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.dispatched is False
    assert outcome.call_count == 0
    assert outcome.result is None
    assert outcome.permitted_next_action == "none"
    assert dispatcher.calls == []


def test_post_preflight_request_swap_is_zero_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, invocation_path = _configured_root(tmp_path)
    _set_invocation_role(root, invocation_path, "discovery-author")
    request_path = root / "positive/discovery-author.request.json"
    replacement = (root / "positive/micro-spec-author.request.json").read_bytes()
    original = hermes_adapter.validate_configured_role_request

    def validate_then_swap(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)
        request_path.write_bytes(replacement)
        return result

    monkeypatch.setattr(
        hermes_adapter, "validate_configured_role_request", validate_then_swap
    )
    dispatcher = EnforcingDispatcher(root)

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 0
    assert outcome.result is None
    assert outcome.permitted_next_action == "none"
    assert dispatcher.calls == []
    assert {item["code"] for item in outcome.blockers} == {"input_binding_changed"}


def test_post_preflight_reference_swap_is_zero_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, invocation_path = _configured_root(tmp_path)
    reference_path = root / REFERENCE_FILES["implementation"][0]
    original = hermes_adapter.validate_configured_role_request

    def validate_then_swap(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)
        reference_path.write_bytes(reference_path.read_bytes() + b"\n")
        return result

    monkeypatch.setattr(
        hermes_adapter, "validate_configured_role_request", validate_then_swap
    )
    dispatcher = EnforcingDispatcher(root)

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 0
    assert outcome.result is None
    assert outcome.permitted_next_action == "none"
    assert dispatcher.calls == []
    assert {item["code"] for item in outcome.blockers} == {"input_binding_changed"}


def test_reference_swap_during_dispatch_blocks_result_and_publication(tmp_path: Path) -> None:
    root, invocation_path = _configured_root(tmp_path)
    destination = "candidates/agent-results/swapped-reference.json"
    _set_invocation_role(
        root, invocation_path, "implementation", result_destination=destination
    )
    reference_path = root / REFERENCE_FILES["implementation"][0]

    class ReferenceSwappingDispatcher(EnforcingDispatcher):
        def dispatch(self, spec: dict[str, object]) -> dict[str, object]:
            completion = super().dispatch(spec)
            reference_path.write_bytes(reference_path.read_bytes() + b"\n")
            return completion

    dispatcher = ReferenceSwappingDispatcher(root)
    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 1
    assert outcome.result is None
    assert outcome.permitted_next_action == "none"
    assert len(dispatcher.calls) == 1
    assert {item["code"] for item in outcome.blockers} == {"input_binding_changed"}
    assert not (root / destination).exists()
    assert not (root / "candidates").exists()


def test_reference_swap_during_core_result_validation_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, invocation_path = _configured_root(tmp_path)
    reference_path = root / REFERENCE_FILES["implementation"][0]
    original = hermes_adapter.validate_configured_agent_result

    def validate_then_swap(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)
        reference_path.write_bytes(reference_path.read_bytes() + b"\n")
        return result

    monkeypatch.setattr(
        hermes_adapter, "validate_configured_agent_result", validate_then_swap
    )
    dispatcher = EnforcingDispatcher(root)
    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 1
    assert outcome.result is None
    assert outcome.permitted_next_action == "none"
    assert len(dispatcher.calls) == 1
    assert {item["code"] for item in outcome.blockers} == {"input_binding_changed"}


@pytest.mark.parametrize(
    "unsupported_field",
    [
        "roles",
        "chain",
        "retry",
        "scheduler",
        "concurrency",
        "provider",
        "model",
        "authority",
        "delivery",
        "merge",
        "release",
        "external_mutation",
    ],
)
def test_unsupported_lifecycle_or_runtime_controls_are_zero_call(
    tmp_path: Path, unsupported_field: str
) -> None:
    root, invocation_path = _configured_root(tmp_path)
    invocation = json.loads(invocation_path.read_text(encoding="utf-8"))
    invocation[unsupported_field] = True
    _write_json(invocation_path, invocation)
    dispatcher = EnforcingDispatcher(root)

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.dispatched is False
    assert outcome.call_count == 0
    assert outcome.result is None
    assert outcome.permitted_next_action == "none"
    assert dispatcher.calls == []


@pytest.mark.parametrize("identity_field", ["execution_id", "context_id"])
def test_runtime_identity_mismatch_blocks_without_retry(
    tmp_path: Path, identity_field: str
) -> None:
    root, invocation_path = _configured_root(tmp_path)

    class WrongIdentityDispatcher(EnforcingDispatcher):
        def dispatch(self, spec: dict[str, object]) -> dict[str, object]:
            completion = super().dispatch(spec)
            completion[identity_field] = f"wrong-{identity_field}"
            return completion

    dispatcher = WrongIdentityDispatcher(root)
    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 1
    assert outcome.result is None
    assert len(dispatcher.calls) == 1
    assert {
        "planned_execution_mismatch",
        "planned_context_mismatch",
    } & {item["code"] for item in outcome.blockers}


def test_runtime_field_leakage_in_result_is_blocked(tmp_path: Path) -> None:
    root, invocation_path = _configured_root(tmp_path)

    class LeakingDispatcher(EnforcingDispatcher):
        def dispatch(self, spec: dict[str, object]) -> dict[str, object]:
            completion = super().dispatch(spec)
            completion["result"]["provider"] = "runtime-specific"  # type: ignore[index]
            return completion

    dispatcher = LeakingDispatcher(root)
    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 1
    assert outcome.result is None
    assert {item["code"] for item in outcome.blockers} == {
        "malformed_hermes_completion"
    }
    assert len(dispatcher.calls) == 1


def test_valid_result_destination_is_atomic_noncanonical_output(tmp_path: Path) -> None:
    root, invocation_path = _configured_root(tmp_path)
    destination = "candidates/agent-results/implementation.json"
    _set_invocation_role(
        root, invocation_path, "implementation", result_destination=destination
    )
    dispatcher = EnforcingDispatcher(root)

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is True, outcome.blockers
    assert outcome.call_count == 1
    assert outcome.result is not None
    assert json.loads((root / destination).read_text(encoding="utf-8")) == outcome.result
    assert not list((root / destination).parent.glob("*.tmp"))


@pytest.mark.parametrize(
    "destination",
    [
        ".specbound/iteration-qc/forbidden.json",
        ".specbound/micro-spec-reviews/forbidden.json",
        "results/outside-allowlist.json",
    ],
)
def test_noncanonical_destination_allowlist_blocks_before_dispatch(
    tmp_path: Path, destination: str
) -> None:
    root, invocation_path = _configured_root(tmp_path)
    _set_invocation_role(
        root, invocation_path, "implementation", result_destination=destination
    )
    dispatcher = EnforcingDispatcher(root)

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 0
    assert dispatcher.calls == []
    assert not (root / destination).exists()


def test_existing_result_destination_blocks_before_dispatch(tmp_path: Path) -> None:
    root, invocation_path = _configured_root(tmp_path)
    destination = "candidates/agent-results/existing.json"
    (root / destination).parent.mkdir(parents=True)
    (root / destination).write_text("sentinel\n", encoding="utf-8")
    _set_invocation_role(
        root, invocation_path, "implementation", result_destination=destination
    )
    dispatcher = EnforcingDispatcher(root)

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 0
    assert dispatcher.calls == []
    assert (root / destination).read_text(encoding="utf-8") == "sentinel\n"


@pytest.mark.parametrize(
    "fixture_name,expected_code",
    [
        ("missing-exact-skill-capability.config.json", "malformed_hermes_invocation"),
        ("runtime-model.config.json", "runtime_specific_model_alias"),
    ],
)
def test_invalid_static_config_is_zero_call(
    tmp_path: Path, fixture_name: str, expected_code: str
) -> None:
    root, invocation_path = _configured_root(tmp_path)
    shutil.copyfile(
        HERMES_FIXTURE_ROOT / f"invalid/{fixture_name}",
        root / "hermes-adapter/config.json",
    )
    dispatcher = EnforcingDispatcher(root)

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 0
    assert dispatcher.calls == []
    assert expected_code in {item["code"] for item in outcome.blockers}


def test_static_multi_role_invocation_is_zero_call(tmp_path: Path) -> None:
    root, invocation_path = _configured_root(tmp_path)
    shutil.copyfile(
        HERMES_FIXTURE_ROOT / "invalid/multi-role.invocation.json", invocation_path
    )
    dispatcher = EnforcingDispatcher(root)

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 0
    assert dispatcher.calls == []
    assert {item["code"] for item in outcome.blockers} == {
        "malformed_hermes_invocation"
    }


def test_empty_output_kind_request_blocks_before_dispatch(tmp_path: Path) -> None:
    root, invocation_path = _configured_root(tmp_path)
    request_path = root / "positive/implementation.request.json"
    request = json.loads(request_path.read_text(encoding="utf-8"))
    request["requested_capabilities"]["output_kinds"] = []
    _write_json(request_path, request)
    dispatcher = EnforcingDispatcher(root)

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 0
    assert outcome.result is None
    assert dispatcher.calls == []
    assert {item["code"] for item in outcome.blockers} == {
        "invalid_hermes_request_mapping"
    }


def test_empty_mutation_class_request_blocks_before_dispatch(tmp_path: Path) -> None:
    root, invocation_path = _configured_root(tmp_path)
    request_path = root / "positive/implementation.request.json"
    request = json.loads(request_path.read_text(encoding="utf-8"))
    request["requested_capabilities"]["mutation_classes"] = []
    _write_json(request_path, request)
    dispatcher = EnforcingDispatcher(root)

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 0
    assert outcome.result is None
    assert dispatcher.calls == []
    assert {item["code"] for item in outcome.blockers} == {
        "invalid_hermes_request_mapping"
    }


def test_completion_mutation_class_must_match_requested_class(tmp_path: Path) -> None:
    root, invocation_path = _configured_root(tmp_path)

    class WrongMutationDispatcher(EnforcingDispatcher):
        def dispatch(self, spec: dict[str, object]) -> dict[str, object]:
            completion = super().dispatch(spec)
            completion["result"]["mutation_class"] = "none"  # type: ignore[index]
            return completion

    dispatcher = WrongMutationDispatcher(root)
    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 1
    assert outcome.result is None
    assert len(dispatcher.calls) == 1
    assert {item["code"] for item in outcome.blockers} == {
        "mutation_class_mismatch"
    }


@pytest.mark.parametrize("extra_field", ["additional_skill_path", "skill_chain"])
def test_additional_or_chained_skill_metadata_is_blocked(
    tmp_path: Path, extra_field: str
) -> None:
    root, invocation_path = _configured_root(tmp_path)

    class AdditionalSkillDispatcher(EnforcingDispatcher):
        def dispatch(self, spec: dict[str, object]) -> dict[str, object]:
            completion = super().dispatch(spec)
            completion[extra_field] = "skills/other/SKILL.md"
            return completion

    dispatcher = AdditionalSkillDispatcher(root)
    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 1
    assert outcome.result is None
    assert {item["code"] for item in outcome.blockers} == {
        "malformed_hermes_completion"
    }
    assert len(dispatcher.calls) == 1


def test_invalid_completion_leaves_no_partial_destination(tmp_path: Path) -> None:
    root, invocation_path = _configured_root(tmp_path)
    destination = "candidates/agent-results/no-partial.json"
    _set_invocation_role(
        root, invocation_path, "implementation", result_destination=destination
    )

    class InvalidCompletionDispatcher(EnforcingDispatcher):
        def dispatch(self, spec: dict[str, object]) -> dict[str, object]:
            completion = super().dispatch(spec)
            completion["result"]["unexpected"] = True  # type: ignore[index]
            return completion

    dispatcher = InvalidCompletionDispatcher(root)
    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 1
    assert outcome.result is None
    assert not (root / destination).exists()
    parent = (root / destination).parent
    assert not parent.exists() or not list(parent.iterdir())


def test_publication_failure_rolls_back_temp_and_created_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, invocation_path = _configured_root(tmp_path)
    destination = "candidates/agent-results/link-failure.json"
    _set_invocation_role(
        root, invocation_path, "implementation", result_destination=destination
    )

    def fail_link(source: object, target: object) -> None:
        raise OSError("simulated atomic link failure")

    monkeypatch.setattr("specbound.hermes_adapter.os.link", fail_link)
    outcome = execute_hermes_invocation(
        root, invocation_path, EnforcingDispatcher(root)
    )

    assert outcome.valid is False
    assert outcome.call_count == 1
    assert outcome.result is None
    assert {item["code"] for item in outcome.blockers} == {
        "result_publication_failed"
    }
    assert not (root / destination).exists()
    assert not (root / "candidates").exists()


def test_repository_adapter_schema_drift_blocks_before_dispatch(tmp_path: Path) -> None:
    root, invocation_path = _configured_root(tmp_path)
    schemas = root / "schemas"
    schemas.mkdir()
    for name in (
        "hermes-adapter-config.schema.json",
        "hermes-invocation.schema.json",
    ):
        shutil.copyfile(Path(__file__).parents[1] / "schemas" / name, schemas / name)
    schema_path = schemas / "hermes-invocation.schema.json"
    schema_path.write_text(
        schema_path.read_text(encoding="utf-8").replace(
            '"title": "SpecBound one-shot Hermes invocation v1"',
            '"title": "drifted schema"',
        ),
        encoding="utf-8",
    )
    dispatcher = EnforcingDispatcher(root)

    outcome = execute_hermes_invocation(root, invocation_path, dispatcher)

    assert outcome.valid is False
    assert outcome.call_count == 0
    assert dispatcher.calls == []
    assert {item["code"] for item in outcome.blockers} == {
        "malformed_hermes_invocation"
    }
