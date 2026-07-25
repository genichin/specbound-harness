"""Provider-neutral validation for lifecycle agent policy, requests, and results."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from hashlib import sha256
from importlib.resources import files
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

import yaml
from jsonschema import Draft202012Validator


ROLE_IDS = frozenset(
    {
        "discovery-author",
        "requirement-author",
        "micro-spec-author",
        "independent-reviewer",
        "implementation",
        "iteration-qc",
        "delivery-qc",
    }
)
REQUIRED_FORBIDDEN_ACTIONS = frozenset({"authority-transition", "merge", "release", "external-mutation"})
REQUIRED_FORBIDDEN_CLAIMS = frozenset({"confirmation", "approval", "review-decision", "verified", "delivery"})
AUTHORITY_PATH_PREFIXES = (
    ".specbound/approvals/",
    ".specbound/confirmations/",
    ".specbound/review-decisions/",
    ".specbound/micro-spec-reviews/",
)


@dataclass
class AgentContractResult:
    valid: bool = True
    checked_roles: int = 0
    checked_requests: int = 0
    checked_results: int = 0
    role_id: str | None = None
    blockers: list[dict[str, str]] = field(default_factory=list)

    def block(self, code: str, path: str, detail: str) -> None:
        self.valid = False
        self.blockers.append({"code": code, "path": path, "detail": detail})

    def payload(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "checked_roles": self.checked_roles,
            "checked_requests": self.checked_requests,
            "checked_results": self.checked_results,
            "role_id": self.role_id,
            "blockers": self.blockers,
        }


def _safe_relative(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def load_agent_roles_policy(root: Path, policy_path: str) -> tuple[Path, dict[str, Any]]:
    if not _safe_relative(policy_path):
        raise ValueError("policy path must be a safe repository-relative POSIX path")
    path = root / policy_path
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("agent roles policy must be a mapping")
    return path, data


def _load_schema(root: Path, name: str) -> dict[str, Any]:
    repository_schema = root / "schemas" / name
    if repository_schema.is_file():
        text = repository_schema.read_text(encoding="utf-8")
    else:
        text = files("specbound.schemas").joinpath(name).read_text(encoding="utf-8")
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return value


def validate_agent_roles_policy(root: Path, policy_path: str) -> AgentContractResult:
    result = AgentContractResult()
    try:
        path, policy = load_agent_roles_policy(root, policy_path)
    except (OSError, UnicodeError, yaml.YAMLError, ValueError) as exc:
        result.block("malformed_agent_roles_policy", policy_path, str(exc))
        return result

    try:
        schema = _load_schema(root, "agent-roles.schema.json")
        errors = sorted(Draft202012Validator(schema).iter_errors(policy), key=lambda item: list(item.path))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        result.block("malformed_agent_roles_schema", "schemas/agent-roles.schema.json", str(exc))
        return result
    if errors:
        detail = "; ".join(error.message for error in errors)
        result.block("malformed_agent_roles_policy", path.relative_to(root).as_posix(), detail)
        return result

    roles = policy["roles"]

    role_ids = [entry.get("role_id") for entry in roles if isinstance(entry, dict)]
    result.checked_roles = len(role_ids)
    if len(role_ids) != len(roles) or len(role_ids) != len(set(role_ids)) or set(role_ids) != ROLE_IDS:
        result.block(
            "invalid_agent_role_inventory",
            path.relative_to(root).as_posix(),
            "roles must contain each of the seven stable role IDs exactly once",
        )
        return result

    relative = path.relative_to(root).as_posix()
    for role in roles:
        role_id = role["role_id"]
        if role["task_kind"] != role_id:
            result.block(
                "invalid_agent_role_contract",
                relative,
                f"{role_id} task_kind must equal its stable role_id",
            )
        if not REQUIRED_FORBIDDEN_ACTIONS.issubset(role["forbidden_actions"]) or not REQUIRED_FORBIDDEN_CLAIMS.issubset(
            role["forbidden_claims"]
        ):
            result.block(
                "overpermissive_agent_role",
                relative,
                f"{role_id} must retain the fail-closed action and lifecycle-claim prohibitions",
            )
        if any(pattern.startswith(AUTHORITY_PATH_PREFIXES) for pattern in role["allowed_path_patterns"]):
            result.block(
                "overpermissive_agent_role",
                relative,
                f"{role_id} cannot write authority-owned artifact families",
            )
        if "none" in role["mutation_classes"] and role["mutation_classes"] != ["none"]:
            result.block(
                "overpermissive_agent_role",
                relative,
                f"{role_id} cannot combine mutation class none with a mutating class",
            )
        if role_id == "independent-reviewer" and (
            role["allowed_path_patterns"]
            or role["allowed_tool_categories"] != ["repository-read"]
            or role["mutation_classes"] != ["none"]
        ):
            result.block(
                "overpermissive_agent_role",
                relative,
                "independent-reviewer must remain repository-read-only with no writable path scope",
            )
    return result


ROLE_REQUEST_FIELDS = {
    "schema_version",
    "role_id",
    "task_kind",
    "target",
    "current_state",
    "inputs",
    "requested_capabilities",
    "producer_result_ref",
    "reviewer_run_ref",
}


def _read_json_object(path: Path, kind: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot parse {kind}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{kind} must be a JSON object")
    return value


def _role_by_id(policy: dict[str, Any], role_id: object) -> dict[str, Any] | None:
    return next((role for role in policy["roles"] if role["role_id"] == role_id), None)


def _reference_valid(requirement: str, value: object) -> bool:
    if requirement == "required":
        return isinstance(value, str) and bool(value.strip())
    if requirement == "optional":
        return value is None or (isinstance(value, str) and bool(value.strip()))
    return value is None


def validate_role_request(root: Path, request_path: Path, policy_path: str) -> AgentContractResult:
    """Fail closed before execution when a role request exceeds its declared contract."""

    result = AgentContractResult()
    policy_result = validate_agent_roles_policy(root, policy_path)
    if not policy_result.valid:
        result.valid = False
        result.blockers.extend(policy_result.blockers)
        return result
    try:
        _, policy = load_agent_roles_policy(root, policy_path)
        request = _read_json_object(request_path, "role request")
    except (OSError, UnicodeError, yaml.YAMLError, ValueError) as exc:
        result.block("malformed_role_request", str(request_path), str(exc))
        return result

    if set(request) != ROLE_REQUEST_FIELDS or request.get("schema_version") != 1:
        result.block("malformed_role_request", str(request_path), "role request must use the closed version-one field set")
        return result
    role = _role_by_id(policy, request.get("role_id"))
    if role is None:
        result.block("unknown_agent_role", str(request_path), "role_id is not present in the active policy")
        return result
    result.role_id = role["role_id"]
    result.checked_requests = 1
    if request["task_kind"] != role["task_kind"]:
        result.block("role_task_mismatch", str(request_path), "task_kind does not match the selected role")
    if request["current_state"] not in role["lifecycle_eligibility"]:
        result.block("ineligible_agent_role", str(request_path), "role is not eligible in the requested current state")

    inputs = request["inputs"]
    if not isinstance(inputs, dict) or not all(
        isinstance(key, str) and isinstance(value, str) and value.strip() for key, value in inputs.items()
    ):
        result.block("malformed_role_request", str(request_path), "inputs must map input names to non-empty string references")
    else:
        missing = sorted(set(role["required_inputs"]) - set(inputs))
        if missing:
            result.block("missing_role_input", str(request_path), f"missing required inputs: {', '.join(missing)}")

    target = request["target"]
    if not isinstance(target, dict) or set(target) != {"path", "sha256"} or not _safe_relative(target.get("path")):
        result.block("malformed_role_request", str(request_path), "target must contain a safe path and sha256")
    else:
        target_path = root / target["path"]
        try:
            resolved_root = root.resolve(strict=True)
            resolved_target = target_path.resolve(strict=True)
            if resolved_root not in resolved_target.parents and resolved_target != resolved_root:
                raise ValueError("target escapes repository root")
            current_digest = sha256(target_path.read_bytes()).hexdigest()
            if target.get("sha256") != current_digest:
                result.block("target_digest_mismatch", target["path"], "target sha256 does not match current bytes")
        except (OSError, ValueError) as exc:
            result.block("invalid_role_target", str(target.get("path")), str(exc))

    capabilities = request["requested_capabilities"]
    expected_capability_fields = {"path_patterns", "tool_categories", "mutation_classes"}
    if not isinstance(capabilities, dict) or set(capabilities) != expected_capability_fields:
        result.block("malformed_role_request", str(request_path), "requested_capabilities has an invalid shape")
    else:
        for requested_name, policy_name in (
            ("path_patterns", "allowed_path_patterns"),
            ("tool_categories", "allowed_tool_categories"),
            ("mutation_classes", "mutation_classes"),
        ):
            requested = capabilities[requested_name]
            if not isinstance(requested, list) or not set(requested).issubset(role[policy_name]):
                result.block(
                    "capability_escalation",
                    str(request_path),
                    f"requested {requested_name} exceed the {role['role_id']} policy",
                )

    for field_name in ("producer_result_ref", "reviewer_run_ref"):
        requirement = role["result_references"][field_name]
        if not _reference_valid(requirement, request[field_name]):
            result.block(
                "invalid_result_reference",
                str(request_path),
                f"{field_name} violates the role's {requirement} rule",
            )
    return result


def _verify_bound_path(root: Path, binding: dict[str, Any], result: AgentContractResult, code_prefix: str) -> None:
    path_value = binding.get("path")
    if not _safe_relative(path_value):
        result.block(f"invalid_{code_prefix}_path", str(path_value), "path must be safe and repository-relative")
        return
    path = root / path_value
    try:
        resolved_root = root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        if resolved_root not in resolved_path.parents and resolved_path != resolved_root:
            raise ValueError("path escapes repository root")
        digest = sha256(path.read_bytes()).hexdigest()
    except (OSError, ValueError) as exc:
        result.block(f"invalid_{code_prefix}_path", path_value, str(exc))
        return
    if binding.get("sha256") != digest:
        result.block(f"{code_prefix}_digest_mismatch", path_value, "sha256 does not match current bytes")


def _reviewed_micro_spec_paths(root: Path, target_path: str) -> list[str]:
    try:
        text = (root / target_path).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return []
    match = re.search(r"(?ms)^### Code paths\s*\n(.*?)(?=^### |^## |\Z)", text)
    if match is None:
        return []
    return [value.rstrip("/") for value in re.findall(r"`([^`]+)`", match.group(1)) if _safe_relative(value.rstrip("/"))]


def _artifact_allowed(root: Path, path: str, patterns: list[str], target_path: str) -> bool:
    if any(pattern != "@reviewed-micro-spec-scope" and fnmatchcase(path, pattern) for pattern in patterns):
        return True
    if "@reviewed-micro-spec-scope" not in patterns:
        return False
    return any(path == scoped or path.startswith(scoped + "/") for scoped in _reviewed_micro_spec_paths(root, target_path))


def validate_agent_result(root: Path, result_path: Path, policy_path: str) -> AgentContractResult:
    """Validate one closed, digest-bound agent result without mutating the repository."""

    outcome = AgentContractResult()
    policy_result = validate_agent_roles_policy(root, policy_path)
    if not policy_result.valid:
        outcome.valid = False
        outcome.blockers.extend(policy_result.blockers)
        return outcome
    try:
        _, policy = load_agent_roles_policy(root, policy_path)
        payload = _read_json_object(result_path, "agent result")
        schema = _load_schema(root, "agent-result.schema.json")
        schema_errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=lambda item: list(item.path))
    except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError, ValueError) as exc:
        outcome.block("malformed_agent_result", str(result_path), str(exc))
        return outcome
    if schema_errors:
        outcome.block(
            "malformed_agent_result",
            str(result_path),
            "; ".join(error.message for error in schema_errors),
        )
        return outcome

    role = _role_by_id(policy, payload["role_id"])
    if role is None:
        outcome.block("unknown_agent_role", str(result_path), "role_id is not present in the active policy")
        return outcome
    outcome.checked_results = 1
    outcome.role_id = role["role_id"]
    if payload["task_kind"] != role["task_kind"]:
        outcome.block("role_task_mismatch", str(result_path), "task_kind does not match the selected role")

    for field_name in ("producer_result_ref", "reviewer_run_ref"):
        requirement = role["result_references"][field_name]
        if not _reference_valid(requirement, payload[field_name]):
            outcome.block(
                "invalid_result_reference",
                str(result_path),
                f"{field_name} violates the role's {requirement} rule",
            )

    _verify_bound_path(root, payload["target"], outcome, "target")
    artifact_paths: set[str] = set()
    for artifact in payload["artifacts"]:
        artifact_path = artifact["path"]
        if artifact_path in artifact_paths:
            outcome.block("duplicate_result_artifact", artifact_path, "artifact path appears more than once")
        artifact_paths.add(artifact_path)
        _verify_bound_path(root, artifact, outcome, "artifact")
        if not _artifact_allowed(root, artifact_path, role["allowed_path_patterns"], payload["target"]["path"]):
            outcome.block("artifact_outside_role_scope", artifact_path, "artifact is outside the role's allowed path patterns")
        if artifact_path.startswith(AUTHORITY_PATH_PREFIXES):
            outcome.block("artifact_outside_role_scope", artifact_path, "authority-owned artifacts cannot be emitted by agent roles")

    evidence_by_slot: dict[str, dict[str, Any]] = {}
    for evidence in payload["evidence"]:
        slot = evidence["slot"]
        if slot in evidence_by_slot:
            outcome.block("duplicate_evidence_slot", str(result_path), f"evidence slot {slot} appears more than once")
        evidence_by_slot[slot] = evidence
    configured_slots = {slot["slot"]: slot for slot in role["evidence_slots"]}
    unknown_slots = sorted(set(evidence_by_slot) - set(configured_slots))
    if unknown_slots:
        outcome.block("unknown_evidence_slot", str(result_path), f"unknown evidence slots: {', '.join(unknown_slots)}")
    for slot_name, slot_policy in configured_slots.items():
        evidence = evidence_by_slot.get(slot_name)
        if evidence is None:
            if slot_policy["requirement"] == "required":
                outcome.block("missing_evidence_slot", str(result_path), f"required evidence slot {slot_name} is missing")
            continue
        if evidence["status"] == "not_applicable":
            if slot_policy["requirement"] == "required" or not slot_policy["not_applicable_allowed"]:
                outcome.block("invalid_not_applicable_evidence", str(result_path), f"slot {slot_name} cannot be not_applicable")
            if evidence["artifact_ref"] is not None:
                outcome.block("invalid_not_applicable_evidence", str(result_path), f"slot {slot_name} must use a null artifact_ref")
        elif evidence["artifact_ref"] not in artifact_paths and evidence["artifact_ref"] != payload["target"]["path"]:
            outcome.block(
                "invalid_evidence_reference",
                str(result_path),
                f"slot {slot_name} must reference a declared artifact or the exact target",
            )

    provenance = payload["provenance"]
    if not set(provenance["tool_categories"]).issubset(role["allowed_tool_categories"]):
        outcome.block("capability_escalation", str(result_path), "provenance tool categories exceed role policy")
    if not set(provenance["mutation_classes"]).issubset(role["mutation_classes"]):
        outcome.block("capability_escalation", str(result_path), "provenance mutation classes exceed role policy")
    if payload["permitted_next_action"] not in role["permitted_next_actions"]:
        outcome.block("invalid_permitted_next_action", str(result_path), "permitted_next_action is not allowed for the role")
    forbidden_claims = set(payload["claims"]) & set(role["forbidden_claims"])
    if forbidden_claims:
        outcome.block("forbidden_lifecycle_claim", str(result_path), f"forbidden claims: {', '.join(sorted(forbidden_claims))}")
    if payload["verdict"] == "completed" and any(
        command["result"] != "passed" or command["exit_code"] != 0 for command in payload["verification"]["commands"]
    ):
        outcome.block("invalid_completed_verdict", str(result_path), "completed verdict requires passed commands with exit code zero")
    return outcome


def configured_agent_policy_path(root: Path) -> str:
    try:
        config = yaml.safe_load((root / "specbound.yaml").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"cannot parse specbound.yaml: {exc}") from exc
    agent_contract = config.get("policy", {}).get("agent_contract") if isinstance(config, dict) else None
    if not isinstance(agent_contract, dict) or agent_contract.get("enabled") is not True:
        raise ValueError("policy.agent_contract.enabled must be true")
    policy_path = agent_contract.get("roles_path")
    if not _safe_relative(policy_path):
        raise ValueError("policy.agent_contract.roles_path must be a safe repository-relative POSIX path")
    return policy_path


def validate_configured_role_request(root: Path, request_path: Path) -> AgentContractResult:
    try:
        policy_path = configured_agent_policy_path(root)
    except ValueError as exc:
        result = AgentContractResult()
        result.block("agent_contract_disabled", "specbound.yaml", str(exc))
        return result
    return validate_role_request(root, request_path, policy_path)


def validate_configured_agent_result(root: Path, result_path: Path) -> AgentContractResult:
    try:
        policy_path = configured_agent_policy_path(root)
    except ValueError as exc:
        result = AgentContractResult()
        result.block("agent_contract_disabled", "specbound.yaml", str(exc))
        return result
    return validate_agent_result(root, result_path, policy_path)
