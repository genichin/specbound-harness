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

from jsonschema import Draft202012Validator
import yaml


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
REQUIRED_FORBIDDEN_ACTIONS = frozenset(
    {"authority-transition", "canonical-publication", "merge", "release", "external-mutation", "next-role-selection"}
)
REQUIRED_FORBIDDEN_CLAIMS = frozenset({"confirmation", "approval", "review-decision", "verified", "delivery"})
AUTHORITY_PATH_PREFIXES = (
    ".specbound/approvals/",
    ".specbound/confirmations/",
    ".specbound/rejections/",
    ".specbound/reconsiderations/",
    ".specbound/review-submissions/",
    ".specbound/review-decisions/",
    ".specbound/micro-spec-reviews/",
)
RUNTIME_TERMS = ("openai", "anthropic", "claude", "gemini", "hermes", "provider", "vendor", "runtime", "profile", "delegate_task")
COMMAND_EVIDENCE_SLOTS = frozenset({"test-results", "focused-verification", "regression-evidence"})

_AGENT_REQUEST_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version", "role_id", "task_kind", "target", "current_state", "inputs",
        "requested_capabilities", "producer_result_ref", "reviewer_run_ref",
    ],
    "properties": {
        "schema_version": {"const": 1},
        "role_id": {"$ref": "#/$defs/roleId"},
        "task_kind": {"$ref": "#/$defs/roleId"},
        "target": {"$ref": "#/$defs/artifactRef"},
        "current_state": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$"},
        "inputs": {
            "type": "object",
            "propertyNames": {"pattern": "^[a-z][a-z0-9-]*$"},
            "additionalProperties": {"type": "string", "minLength": 1},
        },
        "requested_capabilities": {
            "type": "object",
            "additionalProperties": False,
            "required": ["paths", "tool_categories", "mutation_classes", "output_kinds", "actions"],
            "properties": {
                "paths": {"type": "array", "uniqueItems": True, "items": {"$ref": "#/$defs/safePath"}},
                "tool_categories": {"type": "array", "uniqueItems": True, "items": {"type": "string", "minLength": 1}},
                "mutation_classes": {"type": "array", "uniqueItems": True, "items": {"type": "string", "minLength": 1}},
                "output_kinds": {"type": "array", "uniqueItems": True, "items": {"type": "string", "minLength": 1}},
                "actions": {"type": "array", "uniqueItems": True, "items": {"type": "string", "minLength": 1}},
            },
        },
        "producer_result_ref": {"$ref": "#/$defs/nullableResultRef"},
        "reviewer_run_ref": {"$ref": "#/$defs/nullableResultRef"},
    },
    "$defs": {
        "roleId": {"enum": sorted(ROLE_IDS)},
        "safePath": {
            "type": "string",
            "minLength": 1,
            "pattern": r"^(?!/)(?![A-Za-z]:)(?!.*\\)(?!.*//)(?!.*(?:^|/)\.(?:/|$))(?!.*(?:^|/)\.\.(?:/|$)).+$",
        },

        "digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "artifactRef": {
            "type": "object",
            "additionalProperties": False,
            "required": ["path", "id", "revision", "sha256"],
            "properties": {
                "path": {"$ref": "#/$defs/safePath"},
                "id": {"type": "string", "minLength": 1},
                "revision": {"type": ["integer", "null"], "minimum": 1},
                "sha256": {"$ref": "#/$defs/digest"},
            },
        },
        "resultRef": {
            "type": "object",
            "additionalProperties": False,
            "required": ["result_id", "role_id", "execution_id", "context_id", "sha256"],
            "properties": {
                "result_id": {"type": "string", "minLength": 1},
                "role_id": {"$ref": "#/$defs/roleId"},
                "execution_id": {"type": "string", "minLength": 1},
                "context_id": {"type": "string", "minLength": 1},
                "sha256": {"$ref": "#/$defs/digest"},
            },
        },
        "nullableResultRef": {"anyOf": [{"type": "null"}, {"$ref": "#/$defs/resultRef"}]},
    },
}

_EXPECTED_ROLE_CONTRACTS: dict[str, dict[str, Any]] = {
    "discovery-author": {
        "task_kind": "discovery-author",
        "task_risk_floor": "low",
        "evidence_requirements_by_risk": {
            risk: {"required": ["target-binding", "discovery-readiness"], "conditional": []}
            for risk in ("low", "medium", "high")
        },
        "required_inputs": ["user-intent", "repository-context", "exact-target"],
        "allowed_path_patterns": [".specbound/discoveries/dcy-*-r*.md"],
        "allowed_tool_categories": ["repository-read", "candidate-write"],
        "mutation_classes": ["candidate_write"],
        "output_kinds": ["agent-result"],
        "lifecycle_eligibility": ["draft"],
        "result_references": {"producer_result_ref": "forbidden", "reviewer_run_ref": "forbidden"},
        "reference_edges": {"producer_result_ref": None, "reviewer_run_ref": None},
        "evidence_slots": [("target-binding", "required", False), ("discovery-readiness", "required", False)],
        "permitted_next_actions": ["submit-candidate-for-review"],
    },
    "requirement-author": {
        "task_kind": "requirement-author",
        "task_risk_floor": "low",
        "evidence_requirements_by_risk": {
            risk: {"required": ["target-binding", "acceptance-criteria"], "conditional": []}
            for risk in ("low", "medium", "high")
        },
        "required_inputs": ["confirmed-discovery", "exact-target"],
        "allowed_path_patterns": [".specbound/requirements/req-*/req-*-r*.md"],
        "allowed_tool_categories": ["repository-read", "candidate-write"],
        "mutation_classes": ["candidate_write"],
        "output_kinds": ["agent-result"],
        "lifecycle_eligibility": ["confirmed"],
        "result_references": {"producer_result_ref": "optional", "reviewer_run_ref": "forbidden"},
        "reference_edges": {
            "producer_result_ref": {"allowed_roles": ["discovery-author"], "target_binding": "exact-parent", "required_verdict": "pass"},
            "reviewer_run_ref": None,
        },
        "evidence_slots": [("target-binding", "required", False), ("acceptance-criteria", "required", False)],
        "permitted_next_actions": ["submit-candidate-for-review"],
    },
    "micro-spec-author": {
        "task_kind": "micro-spec-author",
        "task_risk_floor": "low",
        "evidence_requirements_by_risk": {
            risk: {"required": ["target-binding", "selected-ac-coverage"], "conditional": []}
            for risk in ("low", "medium", "high")
        },
        "required_inputs": ["approved-requirement", "selected-acceptance-criteria", "exact-target"],
        "allowed_path_patterns": [".specbound/micro-specs/req-*/ms-*-*.md"],
        "allowed_tool_categories": ["repository-read", "candidate-write"],
        "mutation_classes": ["candidate_write"],
        "output_kinds": ["agent-result"],
        "lifecycle_eligibility": ["approved"],
        "result_references": {"producer_result_ref": "optional", "reviewer_run_ref": "forbidden"},
        "reference_edges": {
            "producer_result_ref": {"allowed_roles": ["requirement-author"], "target_binding": "exact-parent", "required_verdict": "pass"},
            "reviewer_run_ref": None,
        },
        "evidence_slots": [("target-binding", "required", False), ("selected-ac-coverage", "required", False)],
        "permitted_next_actions": ["submit-candidate-for-review"],
    },
    "independent-reviewer": {
        "task_kind": "independent-reviewer",
        "task_risk_floor": "medium",
        "evidence_requirements_by_risk": {
            risk: {"required": ["target-binding", "review-findings", "no-write"], "conditional": []}
            for risk in ("low", "medium", "high")
        },
        "required_inputs": ["producer-result", "exact-target", "current-state"],
        "allowed_path_patterns": [],
        "allowed_tool_categories": ["repository-read"],
        "mutation_classes": ["none"],
        "output_kinds": ["agent-result"],
        "lifecycle_eligibility": ["in_review"],
        "result_references": {"producer_result_ref": "required", "reviewer_run_ref": "forbidden"},
        "reference_edges": {
            "producer_result_ref": {
                "allowed_roles": ["discovery-author", "requirement-author", "micro-spec-author"],
                "target_binding": "exact-target",
                "required_verdict": "pass",
            },
            "reviewer_run_ref": None,
        },
        "evidence_slots": [
            ("target-binding", "required", False),
            ("review-findings", "required", False),
            ("no-write", "required", False),
        ],
        "permitted_next_actions": ["request-authority-action", "request-candidate-rework"],
    },
    "implementation": {
        "task_kind": "implementation",
        "task_risk_floor": "medium",
        "evidence_requirements_by_risk": {
            "low": {
                "required": ["target-binding", "test-results", "rollback-inventory"],
                "conditional": ["negative-tests", "regression-evidence", "supported-ci"],
            },
            "medium": {
                "required": ["target-binding", "test-results", "negative-tests", "regression-evidence", "rollback-inventory"],
                "conditional": ["supported-ci"],
            },
            "high": {
                "required": ["target-binding", "test-results", "negative-tests", "regression-evidence", "rollback-inventory", "supported-ci"],
                "conditional": [],
            },
        },
        "required_inputs": ["reviewed-micro-spec", "review-record", "exact-target", "current-state"],
        "allowed_path_patterns": ["@reviewed-micro-spec-scope"],
        "allowed_tool_categories": ["repository-read", "candidate-write", "test-execute", "filesystem-metadata"],
        "mutation_classes": ["repository_mutation"],
        "output_kinds": ["agent-result"],
        "lifecycle_eligibility": ["approved_for_implementation"],
        "result_references": {"producer_result_ref": "optional", "reviewer_run_ref": "required"},
        "reference_edges": {
            "producer_result_ref": {"allowed_roles": ["micro-spec-author"], "target_binding": "exact-target", "required_verdict": "pass"},
            "reviewer_run_ref": {"allowed_roles": ["independent-reviewer"], "target_binding": "exact-target", "required_verdict": "pass"},
        },
        "evidence_slots": [
            ("target-binding", "required", False),
            ("test-results", "required", False),
            ("rollback-inventory", "required", False),
            ("negative-tests", "optional", True),
            ("regression-evidence", "optional", True),
            ("supported-ci", "optional", True),
        ],
        "permitted_next_actions": ["request-iteration-qc"],
    },
    "iteration-qc": {
        "task_kind": "iteration-qc",
        "task_risk_floor": "medium",
        "evidence_requirements_by_risk": {
            "low": {"required": ["target-binding", "focused-verification"], "conditional": ["regression-evidence"]},
            "medium": {"required": ["target-binding", "focused-verification"], "conditional": ["regression-evidence"]},
            "high": {"required": ["target-binding", "focused-verification", "regression-evidence"], "conditional": []},
        },
        "required_inputs": ["implementation-result", "reviewed-micro-spec", "exact-target", "current-state"],
        "allowed_path_patterns": [".specbound/iteration-qc/req-*/iqc-*-*-r*.json"],
        "allowed_tool_categories": ["repository-read", "candidate-write", "test-execute", "filesystem-metadata"],
        "mutation_classes": ["evidence_write"],
        "output_kinds": ["agent-result"],
        "lifecycle_eligibility": ["implemented"],
        "result_references": {"producer_result_ref": "required", "reviewer_run_ref": "required"},
        "reference_edges": {
            "producer_result_ref": {"allowed_roles": ["implementation"], "target_binding": "exact-target", "required_verdict": "pass"},
            "reviewer_run_ref": {"allowed_roles": ["independent-reviewer"], "target_binding": "exact-target", "required_verdict": "pass"},
        },
        "evidence_slots": [
            ("target-binding", "required", False),
            ("focused-verification", "required", False),
            ("regression-evidence", "optional", True),
        ],
        "permitted_next_actions": ["request-delivery-qc", "request-rework"],
    },
    "delivery-qc": {
        "task_kind": "delivery-qc",
        "task_risk_floor": "medium",
        "evidence_requirements_by_risk": {
            risk: {
                "required": ["target-binding", "complete-ac-coverage", "regression-evidence"],
                "conditional": [],
            }
            for risk in ("low", "medium", "high")
        },
        "required_inputs": ["verified-iteration-qc-set", "approved-requirement", "exact-target", "current-state"],
        "allowed_path_patterns": [".specbound/delivery-qc/dqc-*-r*.json"],
        "allowed_tool_categories": ["repository-read", "candidate-write", "test-execute", "filesystem-metadata"],
        "mutation_classes": ["evidence_write"],
        "output_kinds": ["agent-result"],
        "lifecycle_eligibility": ["approved"],
        "result_references": {"producer_result_ref": "forbidden", "reviewer_run_ref": "forbidden"},
        "reference_edges": {"producer_result_ref": None, "reviewer_run_ref": None},
        "evidence_slots": [
            ("target-binding", "required", False),
            ("complete-ac-coverage", "required", False),
            ("regression-evidence", "required", False),
        ],
        "permitted_next_actions": ["request-delivery-decision", "request-rework"],
    },
}


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
    if not isinstance(value, str) or not value or "\\" in value or re.match(r"^[A-Za-z]:", value):
        return False
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        return False
    path = PurePosixPath(value)
    return not path.is_absolute()


def _safe_repository_path(root: Path, relative: str, *, must_exist: bool = True) -> Path:
    if not _safe_relative(relative):
        raise ValueError("path must be a safe repository-relative POSIX path")
    resolved_root = root.resolve(strict=True)
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"symlink component is forbidden: {current.relative_to(root).as_posix()}")
    if must_exist and not current.exists():
        raise FileNotFoundError(relative)
    resolved = current.resolve(strict=must_exist)
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ValueError("path escapes repository root")
    return current


def load_agent_roles_policy(root: Path, policy_path: str) -> tuple[Path, dict[str, Any]]:
    path = _safe_repository_path(root, policy_path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("agent roles policy must be a mapping")
    return path, data


def _load_schema(root: Path, name: str) -> dict[str, Any]:
    text = files("specbound.schemas").joinpath(name).read_text(encoding="utf-8")
    repository_schema = root / "schemas" / name
    if repository_schema.exists():
        safe_schema = _safe_repository_path(root, f"schemas/{name}")
        if safe_schema.read_text(encoding="utf-8") != text:
            raise ValueError(f"repository {name} differs from the packaged core contract")
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return value


def _schema_errors(root: Path, name: str, value: dict[str, Any]) -> list[str]:
    schema = _load_schema(root, name)
    return [error.message for error in sorted(Draft202012Validator(schema).iter_errors(value), key=lambda item: list(item.path))]


def _evidence_signature(role: dict[str, Any]) -> list[tuple[str, str, bool]]:
    return [(item["slot"], item["requirement"], item["not_applicable_allowed"]) for item in role["evidence_slots"]]


def validate_agent_roles_policy(root: Path, policy_path: str) -> AgentContractResult:
    result = AgentContractResult()
    try:
        path, policy = load_agent_roles_policy(root, policy_path)
        errors = _schema_errors(root, "agent-roles.schema.json", policy)
    except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError, ValueError) as exc:
        result.block("malformed_agent_roles_policy", policy_path, str(exc))
        return result
    if errors:
        result.block("malformed_agent_roles_policy", path.relative_to(root).as_posix(), "; ".join(errors))
        return result

    roles = policy["roles"]
    role_ids = [entry.get("role_id") for entry in roles]
    result.checked_roles = len(role_ids)
    if len(role_ids) != len(set(role_ids)) or set(role_ids) != ROLE_IDS:
        result.block("invalid_agent_role_inventory", path.relative_to(root).as_posix(), "roles must contain each stable role ID exactly once")
        return result

    relative = path.relative_to(root).as_posix()
    if any(term in json.dumps(policy, sort_keys=True).lower() for term in RUNTIME_TERMS):
        result.block("runtime_specific_agent_policy", relative, "core policy must not name providers, runtimes, profiles, or delegation APIs")
    for role in roles:
        role_id = role["role_id"]
        expected = _EXPECTED_ROLE_CONTRACTS[role_id]
        actual = {key: role[key] for key in expected if key != "evidence_slots"}
        expected_without_evidence = {key: value for key, value in expected.items() if key != "evidence_slots"}
        if actual != expected_without_evidence or _evidence_signature(role) != expected["evidence_slots"]:
            result.block("overpermissive_agent_role", relative, f"{role_id} must match the closed version-one minimum-authority contract")
        if len(role["forbidden_actions"]) != len(REQUIRED_FORBIDDEN_ACTIONS) or set(role["forbidden_actions"]) != REQUIRED_FORBIDDEN_ACTIONS:
            result.block("overpermissive_agent_role", relative, f"{role_id} must use the exact closed forbidden action registry")
        if len(role["forbidden_claims"]) != len(REQUIRED_FORBIDDEN_CLAIMS) or set(role["forbidden_claims"]) != REQUIRED_FORBIDDEN_CLAIMS:
            result.block("overpermissive_agent_role", relative, f"{role_id} must use the exact closed forbidden claim registry")
    return result


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
        return isinstance(value, dict)
    if requirement == "optional":
        return value is None or isinstance(value, dict)
    return value is None


def _verify_result_reference(root: Path, reference: dict[str, Any] | None, result: AgentContractResult, field_name: str) -> bool:
    """Accept the exact closed reference envelope; cross-result resolution is deferred by ms-0004-001."""

    if reference is None:
        return False
    return True


def _frontmatter(path: Path) -> dict[str, Any]:
    if path.suffix.lower() not in {".md", ".markdown"}:
        return {}
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        return {}
    _, body, _ = text.split("---\n", 2)
    value = yaml.safe_load(body)
    return value if isinstance(value, dict) else {}


def _artifact_metadata(path: Path) -> dict[str, Any]:
    if path.suffix.lower() == ".json":
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, UnicodeError, json.JSONDecodeError):
            return {}
    return _frontmatter(path)


def _fallback_identity(path: Path) -> tuple[str, int | None]:
    stem = path.stem
    match = re.fullmatch(r"(.+)-r([1-9][0-9]*)", stem)
    return (match.group(1), int(match.group(2))) if match else (stem, None)


def _verify_artifact_ref(
    root: Path,
    binding: dict[str, Any],
    result: AgentContractResult,
    code_prefix: str,
) -> Path | None:
    relative = binding["path"]
    try:
        path = _safe_repository_path(root, relative)
        digest = sha256(path.read_bytes()).hexdigest()
    except (OSError, ValueError) as exc:
        result.block(f"invalid_{code_prefix}_path", relative, str(exc))
        return None
    if binding["sha256"] != digest:
        result.block(f"{code_prefix}_digest_mismatch", relative, "sha256 does not match current bytes")
    metadata = _artifact_metadata(path)
    fallback_id, fallback_revision = _fallback_identity(path)
    actual_id = metadata.get("id", fallback_id)
    actual_revision = metadata.get("revision", fallback_revision)
    if binding["id"] != actual_id or binding["revision"] != actual_revision:
        result.block(
            f"{code_prefix}_identity_mismatch",
            relative,
            f"expected id/revision {actual_id!r}/{actual_revision!r}",
        )
    return path


def _micro_spec_review_state(root: Path, target: dict[str, Any]) -> str | None:
    parts = PurePosixPath(target["path"]).parts
    if len(parts) != 4 or parts[:2] != (".specbound", "micro-specs"):
        return None
    review_relative = f".specbound/micro-spec-reviews/{parts[2]}/{Path(parts[3]).stem}.review.json"
    try:
        review_path = _safe_repository_path(root, review_relative)
        review = _read_json_object(review_path, "Micro-SPEC review")
        from .validation import Result as RepositoryResult, _load_config, _validate_micro_spec_review, _validate_requirement

        config = _load_config(root)
        raw_allowed = config["policy"]["micro_spec_review_authorities_by_risk"]
        allowed = {risk: set(authorities) for risk, authorities in raw_allowed.items()}
        validation = RepositoryResult(root)
        _validate_micro_spec_review(root, review_path, validation, allowed)
        parent_path = _safe_repository_path(root, review["requirement_path"])
        parent_metadata = _artifact_metadata(parent_path)
        if (
            parent_metadata.get("id") != review["requirement_id"]
            or parent_metadata.get("revision") != review["revision"]
            or parent_metadata.get("status") != "approved"
            or sha256(parent_path.read_bytes()).hexdigest() != review["requirement_sha256"]
        ):
            return None
        _validate_requirement(
            root,
            parent_path,
            validation,
            {review["requirement_id"]: review["revision"]},
        )
    except (KeyError, OSError, ValueError):
        return None
    if validation.valid and review.get("decision") == "approved_for_implementation":
        return "approved_for_implementation"
    return None


def _canonical_state_record_matches(root: Path, target: dict[str, Any], state: str) -> bool:
    relative = target["path"]
    expected_roots = {
        "draft": ".specbound/discoveries/",
        "confirmed": ".specbound/discoveries/",
        "approved": ".specbound/requirements/",
        "in_review": ".specbound/requirements/",
        "implemented": ".specbound/micro-specs/",
        "verified": ".specbound/iteration-qc/",
    }
    expected_root = expected_roots.get(state)
    if expected_root is None or not relative.startswith(expected_root):
        return False
    stem = Path(relative).stem
    candidates: dict[str, tuple[str, str, str]] = {
        "confirmed": (
            f".specbound/confirmations/{stem}.confirmation.json",
            "discovery_path",
            "sha256",
        ),
        "approved": (
            f".specbound/approvals/{stem}.approval.json",
            "requirement_path",
            "sha256",
        ),
        "in_review": (
            f".specbound/review-submissions/{stem}.review-submission.json",
            "requirement_path",
            "reviewed_sha256",
        ),
    }
    topology_patterns = {
        "draft": ".specbound/discoveries/dcy-*-r*.md",
        "confirmed": ".specbound/discoveries/dcy-*-r*.md",
        "approved": ".specbound/requirements/req-*/req-*-r*.md",
        "in_review": ".specbound/requirements/req-*/req-*-r*.md",
        "implemented": ".specbound/micro-specs/req-*/ms-*-*.md",
        "verified": ".specbound/iteration-qc/req-*/iqc-*-*-r*.json",
    }
    if not _path_matches(relative, topology_patterns[state]):
        return False
    candidate = candidates.get(state)
    if candidate is None:
        if state == "draft":
            return True
        if state != "verified":
            return False
        try:
            from .validation import Result as RepositoryResult, _validate_qc_record

            validation = RepositoryResult(root)
            _validate_qc_record(
                root,
                _safe_repository_path(root, relative),
                validation,
                "iteration_qc",
            )
        except (OSError, TypeError, ValueError):
            return False
        return validation.valid
    record_relative, path_field, digest_field = candidate
    try:
        record_path = _safe_repository_path(root, record_relative)
        record = _read_json_object(record_path, f"{state} state record")
    except (OSError, ValueError):
        return False
    expected_decision = {"confirmed": "confirmed", "in_review": "submitted_for_review"}.get(state)
    shallow_binding_matches = (
        record.get(path_field) == relative
        and record.get(digest_field) == target["sha256"]
        and record.get("revision") == target["revision"]
        and (
            record.get("discovery_id") == target["id"]
            if state == "confirmed"
            else record.get("requirement_id") == target["id"]
        )
        and (expected_decision is None or record.get("decision") == expected_decision)
    )
    if not shallow_binding_matches:
        return False
    try:
        from .validation import (
            Result as RepositoryResult,
            _load_config,
            _validate_discovery_confirmation,
            _validate_requirement,
            _validate_requirement_review_submission,
        )

        validation = RepositoryResult(root)
        if state == "confirmed":
            config = _load_config(root)
            raw_allowed = config["policy"]["discovery_confirmation_authorities_by_risk"]
            allowed = {risk: set(authorities) for risk, authorities in raw_allowed.items()}
            _validate_discovery_confirmation(root, record_path, validation, allowed)
        elif state == "approved":
            _validate_requirement(root, _safe_repository_path(root, relative), validation, {target["id"]: target["revision"]})
        else:
            target_path = _safe_repository_path(root, relative)
            _validate_requirement(root, target_path, validation, {})
            _validate_requirement_review_submission(root, record_path, validation)
    except (KeyError, OSError, TypeError, ValueError):
        return False
    return validation.valid


def _derive_current_state(
    root: Path,
    target: dict[str, Any],
    path: Path,
    role_id: str,
    producer_reference_valid: bool,
    producer_reference: dict[str, Any] | None,
) -> str | None:
    if not target["path"].startswith(".specbound/"):
        return None
    review_state = _micro_spec_review_state(root, target)
    if (
        review_state == "approved_for_implementation"
        and role_id == "iteration-qc"
        and producer_reference_valid
        and producer_reference is not None
        and producer_reference["role_id"] == "implementation"
    ):
        return "implemented"
    if review_state:
        return review_state
    metadata = _artifact_metadata(path)
    for field_name in ("status", "state", "decision", "verdict"):
        value = metadata.get(field_name)
        if isinstance(value, str) and value:
            if not _canonical_state_record_matches(root, target, value):
                return None
            if value == "implemented" and (
                role_id != "iteration-qc"
                or not producer_reference_valid
                or producer_reference is None
                or producer_reference["role_id"] != "implementation"
            ):
                return None
            if value == "verified" and (
                role_id != "delivery-qc"
                or not producer_reference_valid
                or producer_reference is None
                or producer_reference["role_id"] != "iteration-qc"
            ):
                return None
            return value
    return None


def validate_role_request(root: Path, request_path: Path, policy_path: str) -> AgentContractResult:
    """Fail closed before execution when a request exceeds repository-derived eligibility."""

    result = AgentContractResult()
    policy_result = validate_agent_roles_policy(root, policy_path)
    if not policy_result.valid:
        result.valid = False
        result.blockers.extend(policy_result.blockers)
        return result
    try:
        _, policy = load_agent_roles_policy(root, policy_path)
        request = _read_json_object(request_path, "role request")
        errors = [
            error.message
            for error in sorted(
                Draft202012Validator(_AGENT_REQUEST_SCHEMA).iter_errors(request),
                key=lambda item: list(item.path),
            )
        ]
    except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError, ValueError) as exc:
        result.block("malformed_role_request", str(request_path), str(exc))
        return result
    if errors:
        result.block("malformed_role_request", str(request_path), "; ".join(errors))
        return result
    lowered_inputs = json.dumps(request["inputs"], sort_keys=True).lower()
    if any(term in lowered_inputs for term in RUNTIME_TERMS):
        result.block("runtime_specific_request", str(request_path), "request inputs embed a provider/runtime-specific identifier")

    role = _role_by_id(policy, request["role_id"])
    if role is None:
        result.block("unknown_agent_role", str(request_path), "role_id is not present in the active policy")
        return result
    result.role_id = role["role_id"]
    result.checked_requests = 1
    if request["task_kind"] != role["task_kind"]:
        result.block("role_task_mismatch", str(request_path), "task_kind does not match the selected role")

    reference_validity: dict[str, bool] = {}
    for field_name in ("producer_result_ref", "reviewer_run_ref"):
        requirement = role["result_references"][field_name]
        reference = request[field_name]
        if not _reference_valid(requirement, reference):
            result.block("invalid_result_reference", str(request_path), f"{field_name} violates the role's {requirement} rule")
            reference_validity[field_name] = False
        else:
            reference_validity[field_name] = reference is not None and _verify_result_reference(root, reference, result, field_name)
    if request["reviewer_run_ref"] is not None and request["reviewer_run_ref"]["role_id"] != "independent-reviewer":
        result.block("invalid_result_reference", str(request_path), "reviewer_run_ref role_id must be independent-reviewer")

    target_path = _verify_artifact_ref(root, request["target"], result, "target")
    if target_path is not None:
        derived_state = _derive_current_state(
            root,
            request["target"],
            target_path,
            role["role_id"],
            reference_validity["producer_result_ref"],
            request["producer_result_ref"],
        )
        if derived_state is None:
            result.block("undetermined_current_state", request["target"]["path"], "repository target has no deterministic lifecycle state")
        else:
            if request["current_state"] != derived_state:
                result.block("current_state_spoofing", request["target"]["path"], f"caller claimed {request['current_state']!r}; repository state is {derived_state!r}")
            if derived_state not in role["lifecycle_eligibility"]:
                result.block("ineligible_agent_role", request["target"]["path"], f"role is not eligible in repository state {derived_state!r}")

    required_inputs = set(role["required_inputs"])
    supplied_inputs = set(request["inputs"])
    missing = sorted(required_inputs - supplied_inputs)
    undeclared = sorted(supplied_inputs - required_inputs)
    if missing:
        result.block("missing_role_input", str(request_path), f"missing required inputs: {', '.join(missing)}")
    if undeclared:
        result.block("undeclared_role_input", str(request_path), f"undeclared inputs: {', '.join(undeclared)}")

    capabilities = request["requested_capabilities"]
    for requested_name, policy_name in (
        ("tool_categories", "allowed_tool_categories"),
        ("mutation_classes", "mutation_classes"),
        ("output_kinds", "output_kinds"),
        ("actions", "permitted_next_actions"),
    ):
        if not set(capabilities[requested_name]).issubset(role[policy_name]):
            result.block("capability_escalation", str(request_path), f"requested {requested_name} exceed the {role['role_id']} policy")
    for requested_path in capabilities["paths"]:
        try:
            _safe_repository_path(root, requested_path, must_exist=False)
        except (OSError, ValueError) as exc:
            result.block("unsafe_capability_path", requested_path, str(exc))
            continue
        if requested_path.startswith(AUTHORITY_PATH_PREFIXES) or not _changed_path_allowed(
            root, requested_path, role, request["target"]["path"]
        ):
            result.block("capability_escalation", requested_path, f"requested path exceeds the {role['role_id']} policy")
    forbidden_actions = set(capabilities["actions"]) & set(role["forbidden_actions"])
    if forbidden_actions:
        result.block("forbidden_agent_action", str(request_path), f"forbidden actions: {', '.join(sorted(forbidden_actions))}")

    return result


def _reviewed_micro_spec_paths(root: Path, target_path: str) -> list[tuple[str, bool]]:
    try:
        text = _safe_repository_path(root, target_path).read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return []
    match = re.search(r"(?ms)^## Scope\s*\n(.*?)(?=^## |\Z)", text)
    if match is None:
        return []
    roots = (".specbound/", ".github/", "fixtures/", "schemas/", "src/", "templates/", "tests/")
    exact_files = {"pyproject.toml", "specbound.yaml"}
    scoped: list[tuple[str, bool]] = []
    for raw_value in re.findall(r"`([^`]+)`", match.group(1)):
        is_directory = raw_value.endswith("/")
        value = raw_value.rstrip("/")
        if not _safe_relative(value) or not (value.startswith(roots) or value in exact_files):
            continue
        scoped.append((value, is_directory))
        if value.startswith("schemas/"):
            scoped.append((f"src/specbound/{value}", is_directory))
            scoped.append(("src/specbound/schemas/__init__.py", False))
    if "valid/invalid fixture config" in match.group(1):
        scoped.extend(
            (path, False)
            for path in (
                "fixtures/valid-minimal/specbound.yaml",
                "fixtures/valid-minimal/.specbound/policies/agent-roles.yaml",
                "fixtures/invalid-unsafe-path/specbound.yaml",
                "fixtures/invalid-unsafe-path/.specbound/policies/agent-roles.yaml",
            )
        )
    return scoped


def _path_matches(path: str, pattern: str) -> bool:
    canonical_patterns: dict[str, str] = {
        ".specbound/discoveries/dcy-*-r*.md": r"\.specbound/discoveries/dcy-([0-9]+)-r([1-9][0-9]*)\.md",
        ".specbound/requirements/req-*/req-*-r*.md": r"\.specbound/requirements/req-([0-9]+)/req-([0-9]+)-r([1-9][0-9]*)\.md",
        ".specbound/micro-specs/req-*/ms-*-*.md": r"\.specbound/micro-specs/req-([0-9]+)/ms-([0-9]+)-(0*[1-9][0-9]*)\.md",
        ".specbound/iteration-qc/req-*/iqc-*-*-r*.json": r"\.specbound/iteration-qc/req-([0-9]+)/iqc-([0-9]+)-(0*[1-9][0-9]*)-r([1-9][0-9]*)\.json",
        ".specbound/delivery-qc/dqc-*-r*.json": r"\.specbound/delivery-qc/dqc-([0-9]+)-r([1-9][0-9]*)\.json",
    }
    canonical = canonical_patterns.get(pattern)
    if canonical is not None:
        match = re.fullmatch(canonical, path)
        if match is None:
            return False
        if pattern in {
            ".specbound/requirements/req-*/req-*-r*.md",
            ".specbound/micro-specs/req-*/ms-*-*.md",
            ".specbound/iteration-qc/req-*/iqc-*-*-r*.json",
        }:
            return match.group(1) == match.group(2)
        return True
    path_parts = PurePosixPath(path).parts
    pattern_parts = PurePosixPath(pattern).parts
    return len(path_parts) == len(pattern_parts) and all(
        fnmatchcase(path_part, pattern_part)
        for path_part, pattern_part in zip(path_parts, pattern_parts, strict=True)
    )


def _changed_path_allowed(root: Path, path: str, role: dict[str, Any], target_path: str) -> bool:
    patterns = role["allowed_path_patterns"]
    if any(pattern != "@reviewed-micro-spec-scope" and _path_matches(path, pattern) for pattern in patterns):
        return True
    if "@reviewed-micro-spec-scope" not in patterns:
        return False
    if path.startswith(".specbound/") and not path.startswith(".specbound/policies/"):
        return False
    return any(path == scoped or (is_directory and path.startswith(scoped + "/")) for scoped, is_directory in _reviewed_micro_spec_paths(root, target_path))


def validate_agent_result(root: Path, result_path: Path, policy_path: str) -> AgentContractResult:
    """Validate one closed, exact-bound, non-authorizing result without mutation."""

    outcome = AgentContractResult()
    policy_result = validate_agent_roles_policy(root, policy_path)
    if not policy_result.valid:
        outcome.valid = False
        outcome.blockers.extend(policy_result.blockers)
        return outcome
    try:
        _, policy = load_agent_roles_policy(root, policy_path)
        payload = _read_json_object(result_path, "agent result")
        errors = _schema_errors(root, "agent-result.schema.json", payload)
    except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError, ValueError) as exc:
        outcome.block("malformed_agent_result", str(result_path), str(exc))
        return outcome
    if errors:
        outcome.block("malformed_agent_result", str(result_path), "; ".join(errors))
        return outcome

    role = _role_by_id(policy, payload["role_id"])
    if role is None:
        outcome.block("unknown_agent_role", str(result_path), "role_id is not present in the active policy")
        return outcome
    outcome.checked_results = 1
    outcome.role_id = role["role_id"]
    if payload["task_kind"] != role["task_kind"]:
        outcome.block("role_task_mismatch", str(result_path), "task_kind does not match the selected role")
    if any(term in payload["model_alias"].lower() for term in RUNTIME_TERMS):
        outcome.block("runtime_specific_result", str(result_path), "model_alias must remain a provider-neutral alias")
    if payload["output_kind"] not in role["output_kinds"]:
        outcome.block("invalid_output_kind", str(result_path), "output_kind is outside the role policy")

    reference_validity: dict[str, bool] = {}
    for field_name in ("producer_result_ref", "reviewer_run_ref"):
        requirement = role["result_references"][field_name]
        reference = payload[field_name]
        if not _reference_valid(requirement, reference):
            outcome.block("invalid_result_reference", str(result_path), f"{field_name} violates the role's {requirement} rule")
            reference_validity[field_name] = False
        else:
            reference_validity[field_name] = reference is not None and _verify_result_reference(root, reference, outcome, field_name)
    if payload["reviewer_run_ref"] is not None and payload["reviewer_run_ref"]["role_id"] != "independent-reviewer":
        outcome.block("invalid_result_reference", str(result_path), "reviewer_run_ref role_id must be independent-reviewer")

    target_path = _verify_artifact_ref(root, payload["target"], outcome, "target")
    if target_path is not None:
        state = _derive_current_state(
            root,
            payload["target"],
            target_path,
            role["role_id"],
            reference_validity["producer_result_ref"],
            payload["producer_result_ref"],
        )
        if state is None or state not in role["lifecycle_eligibility"]:
            outcome.block("result_state_mismatch", payload["target"]["path"], f"repository state {state!r} is not eligible for {role['role_id']}")
        metadata = _artifact_metadata(target_path)
        recorded_risk = metadata.get("risk", metadata.get("risk_class"))
        if recorded_risk is not None and payload["target_risk"] != recorded_risk:
            outcome.block("target_risk_mismatch", payload["target"]["path"], "target_risk does not match repository metadata")

    provenance = payload["context_provenance"]
    if not provenance["fresh_context"] or provenance["producer_transcript_inherited"] or provenance["session_memory_inherited"]:
        outcome.block("invalid_context_provenance", str(result_path), "result context must be fresh and inherit neither producer transcript nor session memory")
    input_keys: set[tuple[str, str, int | None, str]] = set()
    for artifact in provenance["input_artifacts"]:
        _verify_artifact_ref(root, artifact, outcome, "input_artifact")
        input_keys.add((artifact["path"], artifact["id"], artifact["revision"], artifact["sha256"]))
    target_key = (payload["target"]["path"], payload["target"]["id"], payload["target"]["revision"], payload["target"]["sha256"])
    if target_key not in input_keys:
        outcome.block("missing_target_provenance", str(result_path), "context_provenance.input_artifacts must include the exact target")

    if not set(payload["tool_categories"]).issubset(role["allowed_tool_categories"]):
        outcome.block("capability_escalation", str(result_path), "tool categories exceed role policy")
    if payload["mutation_class"] not in role["mutation_classes"]:
        outcome.block("capability_escalation", str(result_path), "mutation class exceeds role policy")

    changed_paths = payload["changed_paths"]
    if role["role_id"] == "independent-reviewer" and changed_paths:
        outcome.block("reviewer_mutation", str(result_path), "independent-reviewer changed_paths must be empty")
    if payload["mutation_class"] == "none" and changed_paths:
        outcome.block("mutation_class_conflict", str(result_path), "mutation_class none requires empty changed_paths")
    if payload["verdict"] == "pass" and payload["mutation_class"] != "none" and not changed_paths:
        outcome.block("missing_changed_path", str(result_path), "a passing mutating role must report at least one changed path")
    for changed_path in changed_paths:
        try:
            _safe_repository_path(root, changed_path)
        except (OSError, ValueError) as exc:
            outcome.block("invalid_changed_path", changed_path, str(exc))
            continue
        if changed_path.startswith(AUTHORITY_PATH_PREFIXES):
            outcome.block("forbidden_changed_path", changed_path, "authority-owned paths cannot be changed by an agent role")
        if not _changed_path_allowed(root, changed_path, role, payload["target"]["path"]):
            outcome.block("changed_path_outside_role_scope", changed_path, "changed path is outside the role policy")

    evidence_by_slot: dict[str, dict[str, Any]] = {}
    evidence_artifact_paths: set[str] = set()
    all_commands: list[dict[str, Any]] = []
    for evidence in payload["evidence"]:
        slot = evidence["slot"]
        if slot in evidence_by_slot:
            outcome.block("duplicate_evidence_slot", str(result_path), f"evidence slot {slot} appears more than once")
        evidence_by_slot[slot] = evidence
        for artifact in evidence["artifacts"]:
            _verify_artifact_ref(root, artifact, outcome, "evidence_artifact")
            evidence_artifact_paths.add(artifact["path"])
        for command in evidence["commands"]:
            if command["result"] == "passed" and command["exit_code"] != 0:
                outcome.block("invalid_evidence_command", str(result_path), "a passed command must have exit_code 0")
            if command["result"] == "failed" and command["exit_code"] == 0:
                outcome.block("invalid_evidence_command", str(result_path), "a failed command must have non-zero exit_code")
        all_commands.extend(evidence["commands"])

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
        if evidence["status"] == "not_applicable" and (
            slot_policy["requirement"] == "required" or not slot_policy["not_applicable_allowed"]
        ):
            outcome.block("invalid_not_applicable_evidence", str(result_path), f"slot {slot_name} cannot be not_applicable")
        if evidence["status"] == "provided" and slot_name in COMMAND_EVIDENCE_SLOTS and not evidence["commands"]:
            outcome.block("missing_command_evidence", str(result_path), f"evidence slot {slot_name} requires a recorded command")
    missing_changed_evidence = sorted(set(changed_paths) - evidence_artifact_paths)
    if missing_changed_evidence:
        outcome.block("missing_changed_path_evidence", str(result_path), f"changed paths lack exact artifact evidence: {', '.join(missing_changed_evidence)}")

    action = payload["permitted_next_action"]
    if payload["verdict"] == "pass":
        if action not in role["permitted_next_actions"]:
            outcome.block("invalid_permitted_next_action", str(result_path), "passing result requires a role-permitted next action")
        if any(command["result"] != "passed" or command["exit_code"] != 0 for command in all_commands):
            outcome.block("invalid_pass_verdict", str(result_path), "pass requires every reported command to pass with exit code zero")
        if any(finding["severity"] in {"high", "critical"} for finding in payload["findings"]):
            outcome.block("invalid_pass_verdict", str(result_path), "pass cannot retain high or critical findings")
    else:
        if action is not None and (action not in role["permitted_next_actions"] or "rework" not in action):
            outcome.block("invalid_permitted_next_action", str(result_path), "rework/blocked cannot advance to the next lifecycle stage")

    forbidden_claims = set(payload["claims"]) & set(role["forbidden_claims"])
    if forbidden_claims:
        outcome.block("forbidden_lifecycle_claim", str(result_path), f"forbidden claims: {', '.join(sorted(forbidden_claims))}")
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
