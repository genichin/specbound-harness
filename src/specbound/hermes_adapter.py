"""Fail-closed one-shot adapter between SpecBound contracts and Hermes dispatchers."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from jsonschema import Draft202012Validator

from .agent_contract import (
    RUNTIME_TERMS,
    configured_agent_policy_path,
    load_agent_roles_policy,
    validate_configured_agent_result,
    validate_configured_agent_role_skills,
    validate_configured_role_request,
)


REQUIRED_DISPATCHER_CAPABILITIES = frozenset(
    {
        "fresh_leaf_context",
        "single_model_alias",
        "exact_workdir",
        "exact_skill_binding",
        "tool_allowlist",
        "path_boundary",
        "no_context_reuse",
        "structured_completion",
    }
)
TOOL_CATEGORIES = frozenset(
    {"repository-read", "candidate-write", "test-execute", "filesystem-metadata"}
)
COMPLETION_RESULT_FIELDS = frozenset(
    {
        "result_id",
        "context_provenance",
        "mutation_class",
        "changed_paths",
        "evidence",
        "verdict",
        "findings",
        "permitted_next_action",
        "claims",
    }
)
COMPLETION_FIELDS = frozenset(
    {
        "schema_version",
        "execution_id",
        "context_id",
        "model_alias",
        "applied_skill_path",
        "applied_skill_sha256",
        "result",
    }
)


class HermesDispatcher(Protocol):
    capabilities: dict[str, bool]

    def dispatch(self, spec: dict[str, object]) -> dict[str, object]: ...


@dataclass
class HermesAdapterOutcome:
    valid: bool = True
    dispatched: bool = False
    call_count: int = 0
    result: dict[str, Any] | None = None
    permitted_next_action: str = "none"
    blockers: list[dict[str, str]] = field(default_factory=list)

    def block(self, code: str, path: str, detail: str) -> None:
        self.valid = False
        self.permitted_next_action = "none"
        self.blockers.append({"code": code, "path": path, "detail": detail})

    def payload(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "dispatched": self.dispatched,
            "call_count": self.call_count,
            "result": self.result,
            "permitted_next_action": self.permitted_next_action,
            "blockers": self.blockers,
        }


def _safe_repository_path(root: Path, relative: object, *, must_exist: bool = True) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("path must be a safe repository-relative POSIX path")
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("path must be a safe repository-relative POSIX path")
    resolved_root = root.resolve(strict=True)
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("symlink components are forbidden")
    resolved = current.resolve(strict=must_exist)
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ValueError("path escapes repository root")
    if must_exist and not current.is_file():
        raise ValueError("path must identify a regular file")
    return current


def _relative_invocation_path(root: Path, invocation_path: Path) -> str:
    try:
        relative = invocation_path.resolve(strict=True).relative_to(root.resolve(strict=True)).as_posix()
    except (OSError, ValueError) as exc:
        raise ValueError("invocation path must be an existing repository file") from exc
    _safe_repository_path(root, relative)
    return relative


def _read_object(path: Path, label: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def _schema(root: Path, name: str) -> dict[str, Any]:
    text = files("specbound.schemas").joinpath(name).read_text(encoding="utf-8")
    repository_schema = root / "schemas" / name
    if repository_schema.exists():
        safe_schema = _safe_repository_path(root, f"schemas/{name}")
        if safe_schema.read_text(encoding="utf-8") != text:
            raise ValueError(f"repository {name} differs from the packaged adapter contract")
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return value


def _schema_errors(root: Path, name: str, value: dict[str, Any]) -> list[str]:
    return [
        error.message
        for error in sorted(
            Draft202012Validator(_schema(root, name)).iter_errors(value),
            key=lambda item: list(item.path),
        )
    ]


def _role(policy: dict[str, Any], role_id: str) -> dict[str, Any] | None:
    return next((item for item in policy["roles"] if item["role_id"] == role_id), None)


def _extend_core_blockers(outcome: HermesAdapterOutcome, payload: dict[str, Any]) -> None:
    outcome.valid = False
    outcome.permitted_next_action = "none"
    outcome.blockers.extend(payload["blockers"])


def _atomic_publish_json(destination: Path, value: dict[str, Any]) -> None:
    created_directories: list[Path] = []
    current = destination.parent
    while not current.exists():
        created_directories.append(current)
        current = current.parent
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        for directory in created_directories:
            try:
                directory.rmdir()
            except OSError:
                pass
        raise FileExistsError("result destination already exists")
    temporary_path: Path | None = None
    published = False
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary_path, destination)
        published = True
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        if not published:
            for directory in created_directories:
                try:
                    directory.rmdir()
                except OSError:
                    pass


def execute_hermes_invocation(
    root: Path,
    invocation_path: Path,
    dispatcher: HermesDispatcher,
) -> HermesAdapterOutcome:
    """Validate, dispatch exactly once, normalize, and revalidate one role execution."""

    outcome = HermesAdapterOutcome()
    try:
        root = root.resolve(strict=True)
        invocation_relative = _relative_invocation_path(root, invocation_path)
        invocation = _read_object(root / invocation_relative, "Hermes invocation")
        errors = _schema_errors(root, "hermes-invocation.schema.json", invocation)
        if errors:
            raise ValueError("; ".join(errors))
        config_path = _safe_repository_path(root, invocation["config_file"])
        request_path = _safe_repository_path(root, invocation["request_file"])
        reference_files = [
            _safe_repository_path(root, value).relative_to(root).as_posix()
            for value in invocation["reference_result_files"]
        ]
        config = _read_object(config_path, "Hermes adapter config")
        errors = _schema_errors(root, "hermes-adapter-config.schema.json", config)
        if errors:
            raise ValueError("; ".join(errors))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        outcome.block("malformed_hermes_invocation", str(invocation_path), str(exc))
        return outcome

    if set(config["required_dispatcher_capabilities"]) != REQUIRED_DISPATCHER_CAPABILITIES:
        outcome.block("invalid_dispatcher_capability_registry", invocation["config_file"], "required capability registry must be exact")
        return outcome
    destination: Path | None = None
    destination_relative = invocation.get("result_destination")
    if destination_relative is not None:
        if not destination_relative.startswith("candidates/agent-results/") or not destination_relative.endswith(".json"):
            outcome.block(
                "invalid_result_destination",
                destination_relative,
                "result destination must be a JSON file under candidates/agent-results/",
            )
            return outcome
        try:
            destination = _safe_repository_path(root, destination_relative, must_exist=False)
        except (OSError, ValueError) as exc:
            outcome.block("invalid_result_destination", destination_relative, str(exc))
            return outcome
        if destination.exists():
            outcome.block("result_destination_exists", destination_relative, "result destination is no-overwrite")
            return outcome
    if set(config["tool_category_map"]) != TOOL_CATEGORIES:
        outcome.block("invalid_tool_category_map", invocation["config_file"], "tool category map must be exact")
        return outcome
    if any(term in config["model_alias"].casefold() for term in RUNTIME_TERMS):
        outcome.block("runtime_specific_model_alias", invocation["config_file"], "model_alias must remain provider-neutral")
        return outcome

    skill_result = validate_configured_agent_role_skills(root)
    if not skill_result.valid:
        _extend_core_blockers(outcome, skill_result.payload())
        return outcome
    request_result = validate_configured_role_request(root, request_path, reference_files)
    if not request_result.valid:
        _extend_core_blockers(outcome, request_result.payload())
        return outcome

    try:
        request = _read_object(request_path, "role request")
        _, policy = load_agent_roles_policy(root, configured_agent_policy_path(root))
        role = _role(policy, request["role_id"])
        if role is None:
            raise ValueError("selected role is absent from policy")
        skill_path = _safe_repository_path(root, role["skill_path"])
        skill_sha256 = hashlib.sha256(skill_path.read_bytes()).hexdigest()
        runtime_tools = sorted(
            {
                tool
                for category in role["allowed_tool_categories"]
                for tool in config["tool_category_map"][category]
            }
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        outcome.block("invalid_hermes_role_mapping", invocation["request_file"], str(exc))
        return outcome

    output_kinds = request["requested_capabilities"]["output_kinds"]
    if output_kinds != ["agent-result"]:
        outcome.block(
            "invalid_hermes_request_mapping",
            invocation["request_file"],
            "one-shot Hermes execution requires exactly one agent-result output kind",
        )
        return outcome

    mutation_classes = request["requested_capabilities"]["mutation_classes"]
    if len(mutation_classes) != 1:
        outcome.block(
            "invalid_hermes_request_mapping",
            invocation["request_file"],
            "one-shot Hermes execution requires exactly one requested mutation class",
        )
        return outcome

    capabilities = getattr(dispatcher, "capabilities", None)
    if not isinstance(capabilities, dict) or any(capabilities.get(name) is not True for name in REQUIRED_DISPATCHER_CAPABILITIES):
        outcome.block("unenforced_dispatcher_capability", invocation["config_file"], "dispatcher cannot attest every required enforcement capability")
        return outcome

    spec: dict[str, object] = {
        "schema_version": 1,
        "role_id": role["role_id"],
        "execution_mode": "leaf",
        "model_alias": config["model_alias"],
        "workdir": str(root),
        "skill_path": role["skill_path"],
        "skill_sha256": skill_sha256,
        "planned_execution_id": request["planned_execution_id"],
        "planned_context_id": request["planned_context_id"],
        "target": request["target"],
        "reference_result_files": reference_files,
        "allowed_tools": runtime_tools,
        "allowed_paths": request["requested_capabilities"]["paths"],
        "mutation_classes": request["requested_capabilities"]["mutation_classes"],
        "output_kinds": request["requested_capabilities"]["output_kinds"],
        "forbidden_actions": role["forbidden_actions"],
        "forbidden_claims": role["forbidden_claims"],
    }
    try:
        outcome.call_count = 1
        completion = dispatcher.dispatch(spec)
        outcome.dispatched = True
    except Exception as exc:  # dispatcher failures are untrusted runtime outcomes
        outcome.block("hermes_dispatch_failed", invocation["request_file"], str(exc))
        return outcome

    if not isinstance(completion, dict) or set(completion) != COMPLETION_FIELDS or completion.get("schema_version") != 1:
        outcome.block("malformed_hermes_completion", invocation["request_file"], "completion must match the closed runtime envelope")
        return outcome
    result_fields = completion.get("result")
    if not isinstance(result_fields, dict) or set(result_fields) != COMPLETION_RESULT_FIELDS:
        outcome.block("malformed_hermes_completion", invocation["request_file"], "completion result fields must be exact")
        return outcome
    if completion["model_alias"] != config["model_alias"]:
        outcome.block("model_alias_mismatch", invocation["config_file"], "dispatcher used a model alias different from the exact planned alias")
        return outcome
    if (
        completion["applied_skill_path"] != role["skill_path"]
        or completion["applied_skill_sha256"] != skill_sha256
    ):
        outcome.block("skill_binding_mismatch", role["skill_path"], "dispatcher did not apply the exact bound role skill")
        return outcome
    if result_fields["mutation_class"] != mutation_classes[0]:
        outcome.block(
            "mutation_class_mismatch",
            invocation["request_file"],
            "completion mutation class differs from the exact requested class",
        )
        return outcome

    normalized = {
        "schema_version": 1,
        "result_id": result_fields["result_id"],
        "role_id": role["role_id"],
        "task_kind": role["task_kind"],
        "planned_execution_id": request["planned_execution_id"],
        "planned_context_id": request["planned_context_id"],
        "execution_id": completion["execution_id"],
        "context_id": completion["context_id"],
        "model_alias": config["model_alias"],
        "target": request["target"],
        "producer_result_ref": request["producer_result_ref"],
        "reviewer_run_ref": request["reviewer_run_ref"],
        "authority_type": "none",
        "authority_action_id": None,
        "context_provenance": result_fields["context_provenance"],
        "target_risk": request["target_risk"],
        "effective_task_risk": request["effective_task_risk"],
        "tool_categories": request["requested_capabilities"]["tool_categories"],
        "mutation_class": result_fields["mutation_class"],
        "changed_paths": result_fields["changed_paths"],
        "output_kind": request["requested_capabilities"]["output_kinds"][0],
        "evidence": result_fields["evidence"],
        "verdict": result_fields["verdict"],
        "findings": result_fields["findings"],
        "permitted_next_action": result_fields["permitted_next_action"],
        "claims": result_fields["claims"],
    }
    try:
        with tempfile.TemporaryDirectory(prefix="specbound-hermes-result-") as temporary:
            candidate = Path(temporary) / "agent-result.json"
            candidate.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            validation = validate_configured_agent_result(root, candidate, reference_files)
    except (OSError, UnicodeError, ValueError) as exc:
        outcome.block("hermes_result_validation_failed", invocation["request_file"], str(exc))
        return outcome
    if not validation.valid:
        _extend_core_blockers(outcome, validation.payload())
        return outcome
    if destination is not None:
        try:
            _atomic_publish_json(destination, normalized)
        except OSError as exc:
            outcome.block(
                "result_publication_failed",
                destination_relative or str(destination),
                str(exc),
            )
            return outcome

    outcome.result = normalized
    outcome.permitted_next_action = normalized["permitted_next_action"]
    return outcome
