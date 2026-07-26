"""Provider-neutral validation for lifecycle agent policy, requests, and results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from fnmatch import fnmatchcase
from hashlib import sha256
from importlib.resources import files
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
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
RISK_ORDER = ("low", "medium", "high")
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
COMMAND_EVIDENCE_SLOTS = frozenset({"test-results", "focused-verification", "negative-tests", "regression-evidence", "supported-ci"})
SKILL_CONTRACT_FIELDS = frozenset(
    {
        "schema_version", "role_id", "policy_path", "skill_path", "task_kind", "required_inputs",
        "allowed_path_patterns", "allowed_tool_categories", "mutation_classes", "output_kinds",
        "lifecycle_eligibility", "result_references", "permitted_next_actions", "forbidden_actions",
        "forbidden_claims", "authority_type", "self_review", "self_approval",
    }
)
SKILL_POLICY_FIELDS = (
    "task_kind", "required_inputs", "allowed_path_patterns", "allowed_tool_categories", "mutation_classes",
    "output_kinds", "lifecycle_eligibility", "result_references", "permitted_next_actions",
    "forbidden_actions", "forbidden_claims",
)
REQUIRED_SKILL_HEADINGS = (
    "## Overview", "## When to Use", "## Required Inputs", "## Allowed Operations",
    "## Forbidden Actions and Claims", "## Procedure", "## Verification",
    "## Rework and Blocked", "## Completion Checklist",
)
REQUIRED_SKILL_BOUNDARIES = (
    "The machine-readable role policy is authoritative; this skill is procedural guidance only.",
    "This role must not perform self-review or self-approval.",
    "This role never issues or claims confirmation, approval, review-decision, verified, delivery, canonical publication, Merge, Release, or external mutation authority.",
)
OVERBROAD_SKILL_CLAIM_RE = re.compile(
    r"\b(?:may|can|is authorized to)\s+(?:"
    r"self-review|self-approve|approve|confirm|publish\s+canonical|merge|release|deliver|"
    r"(?:issue|grant|claim)\s+(?:an?\s+)?(?:confirmation|approval|review[ -]decision|verified|delivery|canonical\s+publication)|"
    r"(?:write|modify|change)\s+(?:to\s+)?(?:any|all)\s+(?:repository\s+)?(?:path|paths|file|files)|"
    r"(?:use|invoke)\s+(?:any|all)\s+(?:tool|tools)"
    r")\b",
    re.IGNORECASE,
)
_NOT_APPLICABLE_BOILERPLATE = frozenset(
    {
        "a", "an", "applicable", "are", "because", "does", "evidence", "exist", "exists", "for", "here", "is", "it",
        "missing", "no", "not", "simply", "slot", "task", "the", "this", "to", "unavailable", "was", "were",
    }
)


def _authority_owned_path(relative: str) -> bool:
    normalized = relative.casefold()
    return normalized.startswith(tuple(prefix.casefold() for prefix in AUTHORITY_PATH_PREFIXES))


def _canonical_repository_spelling(root: Path, relative: str) -> bool:
    current = root.resolve()
    for part in PurePosixPath(relative).parts:
        try:
            matches = [name for name in os.listdir(current) if name.casefold() == part.casefold()]
        except OSError:
            return False
        if len(matches) != 1 or matches[0] != part:
            return False
        current /= matches[0]
    return True


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _rollback_verification_command(command: dict[str, Any]) -> bool:
    text = command.get("command", "").strip().casefold()
    if command.get("result") != "passed" or command.get("exit_code") != 0:
        return False
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        return False
    if not tokens:
        return False
    executable = PurePosixPath(tokens[0].replace("\\", "/")).name
    arguments = " ".join(tokens[1:])
    if executable == "git":
        return ("diff" in tokens[1:] and "--exit-code" in tokens[1:]) or ("status" in tokens[1:] and "--porcelain" in tokens[1:])
    if executable in {"sha256sum", "shasum", "checksum"}:
        return True
    verification_target = f"{executable} {arguments}"
    has_subject = any(marker in verification_target for marker in ("rollback", "partial-mutation", "partial_mutation", "atomicity"))
    has_verification = any(marker in verification_target for marker in ("check", "test", "verify"))
    return executable not in {"echo", "printf"} and has_subject and has_verification


def _blanket_not_applicable_reason(reason: str, slot: str | None = None) -> bool:
    normalized = reason.strip().casefold().rstrip(".")
    slot_tokens = set(re.findall(r"[a-z0-9][a-z0-9-]*", (slot or "").casefold().replace("-", " ")))
    substantive_tokens = [
        token
        for token in re.findall(r"[a-z0-9][a-z0-9-]*", normalized)
        if token not in _NOT_APPLICABLE_BOILERPLATE and token not in slot_tokens
    ]
    return (
        len(normalized) < 20
        or normalized in {"not applicable", "not applicable here", "simply not applicable", "this evidence is not applicable here"}
        or "simply not applicable" in normalized
        or normalized.startswith("n/a")
        or normalized.count("not applicable") > 1
        or len(substantive_tokens) < 3
    )

_AGENT_REQUEST_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version", "role_id", "task_kind", "planned_execution_id", "planned_context_id",
        "target", "current_state", "target_risk", "effective_task_risk", "inputs",
        "verified_iteration_qc_set", "requested_capabilities", "producer_result_ref", "reviewer_run_ref",
    ],
    "properties": {
        "schema_version": {"const": 1},
        "role_id": {"$ref": "#/$defs/roleId"},
        "task_kind": {"$ref": "#/$defs/roleId"},
        "planned_execution_id": {"type": "string", "minLength": 1},
        "planned_context_id": {"type": "string", "minLength": 1},
        "target": {"$ref": "#/$defs/artifactRef"},
        "current_state": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$"},
        "target_risk": {"enum": list(RISK_ORDER)},
        "effective_task_risk": {"enum": list(RISK_ORDER)},
        "inputs": {
            "type": "object",
            "propertyNames": {"pattern": "^[a-z][a-z0-9-]*$"},
            "additionalProperties": {"type": "string", "minLength": 1},
        },
        "verified_iteration_qc_set": {
            "type": "array",
            "uniqueItems": True,
            "items": {"$ref": "#/$defs/artifactRef"},
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
        "skill_path": "skills/discovery-author/SKILL.md",
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
        "skill_path": "skills/requirement-author/SKILL.md",
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
        "skill_path": "skills/micro-spec-author/SKILL.md",
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
        "skill_path": "skills/independent-reviewer/SKILL.md",
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
        "skill_path": "skills/implementation/SKILL.md",
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
        "skill_path": "skills/iteration-qc/SKILL.md",
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
        "skill_path": "skills/delivery-qc/SKILL.md",
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
    checked_skills: int = 0
    checked_requests: int = 0
    checked_results: int = 0
    role_id: str | None = None
    derived_current_state: str | None = None
    derived_target_risk: str | None = None
    derived_effective_task_risk: str | None = None
    advisory_next_action: str | None = None
    blockers: list[dict[str, str]] = field(default_factory=list)

    def block(self, code: str, path: str, detail: str) -> None:
        self.valid = False
        self.blockers.append({"code": code, "path": path, "detail": detail})

    def payload(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "checked_roles": self.checked_roles,
            "checked_agent_skills": self.checked_skills,
            "checked_requests": self.checked_requests,
            "checked_results": self.checked_results,
            "role_id": self.role_id,
            "derived_current_state": self.derived_current_state,
            "derived_target_risk": self.derived_target_risk,
            "derived_effective_task_risk": self.derived_effective_task_risk,
            "advisory_state": "eligible" if self.valid else "blocked",
            "permitted_next_action": self.advisory_next_action if self.valid and self.advisory_next_action else "none",
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


def _stable_skill_bytes(root: Path, relative: str) -> tuple[bytes, tuple[int, int] | str]:
    path = _safe_repository_path(root, relative)
    if not _canonical_repository_spelling(root, relative):
        raise ValueError("skill path spelling is not canonical for the repository")
    if not path.is_file():
        raise ValueError("skill path must identify a regular file")
    before = path.stat(follow_symlinks=False)
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        raw = handle.read()
        after_read = os.fstat(handle.fileno())
    after = path.stat(follow_symlinks=False)
    stable = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    opened_state = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    if stable != opened_state or opened_state != (
        after_read.st_dev,
        after_read.st_ino,
        after_read.st_size,
        after_read.st_mtime_ns,
    ) or stable != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError("skill changed while being read")
    physical: tuple[int, int] | str = (opened.st_dev, opened.st_ino) if opened.st_ino else str(path.resolve()).casefold()
    return raw, physical


def _parse_role_skill(raw: bytes) -> tuple[dict[str, Any], str]:
    text = raw.decode("utf-8")
    if not text.startswith("---\n"):
        raise ValueError("skill must start with YAML frontmatter at byte zero")
    parts = text.split("---\n", 2)
    if len(parts) != 3 or parts[0] != "":
        raise ValueError("skill frontmatter closing delimiter is missing")
    metadata = yaml.safe_load(parts[1])
    if not isinstance(metadata, dict) or not parts[2].strip():
        raise ValueError("skill requires mapping frontmatter and a non-empty Markdown body")
    return metadata, parts[2]


def validate_agent_role_skills(root: Path, policy_path: str) -> AgentContractResult:
    """Validate one exact repository-backed SKILL.md for every stable role without mutation."""

    result = AgentContractResult()
    try:
        policy_file, policy = load_agent_roles_policy(root, policy_path)
    except (OSError, UnicodeError, yaml.YAMLError, ValueError) as exc:
        result.block("invalid_agent_roles_policy", policy_path, str(exc))
        return result
    roles = policy.get("roles")
    if not isinstance(roles, list):
        result.block("invalid_agent_roles_policy", policy_path, "roles must be a list")
        return result
    skill_paths = [role.get("skill_path") for role in roles if isinstance(role, dict)]
    if len(skill_paths) != len(set(value for value in skill_paths if isinstance(value, str))):
        result.block("duplicate_agent_skill_path", policy_path, "each stable role must map to one unique skill path")

    policy_result = validate_agent_roles_policy(root, policy_path)
    result.checked_roles = policy_result.checked_roles
    if not policy_result.valid:
        result.block("invalid_agent_roles_policy", policy_file.relative_to(root).as_posix(), "skill validation requires the exact closed role policy")
        result.blockers.extend(policy_result.blockers)
        return result

    expected_paths = {role["skill_path"] for role in roles}
    physical_files: set[tuple[int, int] | str] = set()
    for role in roles:
        role_id = role["role_id"]
        relative = role["skill_path"]
        try:
            raw, physical = _stable_skill_bytes(root, relative)
        except FileNotFoundError:
            result.block("missing_agent_skill", relative, f"{role_id} requires its exact repository-backed SKILL.md")
            continue
        except (OSError, UnicodeError, ValueError) as exc:
            code = "noncanonical_agent_skill_path" if "spelling" in str(exc) else "unsafe_agent_skill_path"
            result.block(code, relative, str(exc))
            continue
        result.checked_skills += 1
        if physical in physical_files:
            result.block("duplicate_agent_skill_path", relative, "multiple role mappings resolve to one physical skill file")
            continue
        physical_files.add(physical)
        try:
            frontmatter, body = _parse_role_skill(raw)
        except (UnicodeError, yaml.YAMLError, ValueError) as exc:
            result.block("malformed_agent_skill_frontmatter", relative, str(exc))
            continue

        if set(frontmatter) != {"name", "description", "version", "author", "license", "metadata"}:
            result.block("malformed_agent_skill_frontmatter", relative, "skill frontmatter must use the exact closed top-level fields")
            continue
        description = frontmatter.get("description")
        metadata = frontmatter.get("metadata")
        if (
            not isinstance(description, str)
            or not description.startswith("Use when ")
            or not 40 <= len(description.strip()) <= 1024
            or frontmatter.get("version") != "1.0.0"
            or frontmatter.get("author") != "SpecBound Maintainers"
            or frontmatter.get("license") != "Apache-2.0"
            or not isinstance(metadata, dict)
        ):
            result.block("malformed_agent_skill_frontmatter", relative, "skill description, version, author, license, and metadata must match the closed role-skill contract")
            continue
        hermes_metadata = metadata.get("hermes") if isinstance(metadata, dict) else None
        if (
            not isinstance(metadata, dict)
            or set(metadata) != {"hermes", "specbound"}
            or not isinstance(hermes_metadata, dict)
            or set(hermes_metadata) != {"tags", "related_skills"}
            or hermes_metadata.get("related_skills") != ["specbound-harness"]
        ):
            result.block("malformed_agent_skill_frontmatter", relative, "metadata must contain closed hermes tags/related_skills and specbound mappings")
            continue
        contract = metadata.get("specbound")
        if not isinstance(contract, dict) or set(contract) != SKILL_CONTRACT_FIELDS:
            result.block("malformed_agent_skill_frontmatter", relative, "metadata.specbound must use the exact closed contract fields")
            continue
        if (
            frontmatter.get("name") != role_id
            or contract.get("schema_version") != 1
            or contract.get("role_id") != role_id
            or contract.get("policy_path") != policy_path
            or contract.get("skill_path") != relative
        ):
            result.block("misaligned_agent_skill_identity", relative, f"skill identity must bind exact policy role {role_id}")
        if contract.get("authority_type") != "none" or contract.get("self_review") is not False or contract.get("self_approval") is not False:
            result.block("invalid_agent_skill_authority", relative, "role skills are non-authorizing and forbid self-review and self-approval")
        if any(contract.get(field_name) != role[field_name] for field_name in SKILL_POLICY_FIELDS):
            result.block("misaligned_agent_skill_contract", relative, f"{role_id} skill capabilities must exactly match the machine policy")
        missing_headings = [heading for heading in REQUIRED_SKILL_HEADINGS if f"\n{heading}\n" not in f"\n{body}"]
        missing_boundaries = [boundary for boundary in REQUIRED_SKILL_BOUNDARIES if boundary not in body]
        if missing_headings or missing_boundaries:
            result.block(
                "invalid_agent_skill_body",
                relative,
                f"missing headings={missing_headings}, missing non-authority boundaries={len(missing_boundaries)}",
            )
        if OVERBROAD_SKILL_CLAIM_RE.search(body):
            result.block("overbroad_agent_skill_claim", relative, "skill body contains an explicit over-authorizing normative claim")

    skills_root = root / "skills"
    if skills_root.is_dir():
        for candidate in sorted(skills_root.glob("*/SKILL.md")):
            relative = candidate.relative_to(root).as_posix()
            if relative in expected_paths:
                continue
            try:
                raw, _ = _stable_skill_bytes(root, relative)
                frontmatter, _ = _parse_role_skill(raw)
            except (OSError, UnicodeError, yaml.YAMLError, ValueError):
                continue
            metadata = frontmatter.get("metadata")
            if isinstance(metadata, dict) and isinstance(metadata.get("specbound"), dict):
                result.block("orphan_agent_skill", relative, "SpecBound role skill is not mapped by the exact stable role policy")
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


def _validate_reference_result_intrinsics(
    payload: dict[str, Any],
    role_contract: dict[str, Any],
    effective_risk: str,
) -> None:
    for field_name, requirement in role_contract["result_references"].items():
        reference = payload[field_name]
        if requirement == "required" and reference is None:
            raise ValueError(f"reference result is missing required {field_name}")
        if requirement == "forbidden" and reference is not None:
            raise ValueError(f"reference result carries forbidden {field_name}")
        if reference is not None:
            allowed_roles = role_contract["reference_edges"][field_name]["allowed_roles"]
            if reference["role_id"] not in allowed_roles:
                raise ValueError(f"reference result {field_name} role is outside the declared handoff edge")

    configured_slots = {
        slot_name: {"requirement": requirement, "not_applicable_allowed": not_applicable_allowed}
        for slot_name, requirement, not_applicable_allowed in role_contract["evidence_slots"]
    }
    evidence_by_slot: dict[str, dict[str, Any]] = {}
    all_commands: list[dict[str, Any]] = []
    for evidence in payload["evidence"]:
        slot_name = evidence["slot"]
        if slot_name in evidence_by_slot:
            raise ValueError(f"reference result repeats evidence slot {slot_name}")
        if slot_name not in configured_slots:
            raise ValueError(f"reference result uses unknown evidence slot {slot_name}")
        evidence_by_slot[slot_name] = evidence
        for command in evidence["commands"]:
            if (command["result"] == "passed") != (command["exit_code"] == 0):
                raise ValueError("reference result evidence command and exit code conflict")
        all_commands.extend(evidence["commands"])

    applicability = role_contract["evidence_requirements_by_risk"][effective_risk]
    required_slots = set(applicability["required"])
    conditional_slots = set(applicability["conditional"])
    for slot_name in required_slots | conditional_slots:
        evidence = evidence_by_slot.get(slot_name)
        if evidence is None:
            raise ValueError(f"reference result evidence slot {slot_name} is not explicitly resolved")
        slot_policy = configured_slots[slot_name]
        if evidence["status"] == "not_applicable":
            reason = (evidence.get("reason") or "").strip()
            if (
                _blanket_not_applicable_reason(reason, evidence["slot"])
                or slot_name in required_slots
                or not slot_policy["not_applicable_allowed"]
            ):
                raise ValueError(f"reference result has invalid not_applicable evidence for {slot_name}")
        if evidence["status"] == "provided" and slot_name in COMMAND_EVIDENCE_SLOTS and not evidence["commands"]:
            raise ValueError(f"reference result evidence slot {slot_name} lacks a command")
        if slot_name == "no-write" and (
            evidence["commands"] or payload["changed_paths"] or payload["mutation_class"] != "none"
        ):
            raise ValueError("reference result no-write proof permits mutation")
        if slot_name == "rollback-inventory" and effective_risk == "high":
            rollback_paths = {artifact["path"] for artifact in evidence["artifacts"]}
            if not any(_rollback_verification_command(command) for command in evidence["commands"]) or not set(payload["changed_paths"]).issubset(rollback_paths):
                raise ValueError("reference result high-risk rollback inventory is incomplete")

    action = payload["permitted_next_action"]
    if payload["verdict"] == "pass":
        if action not in role_contract["permitted_next_actions"] or (isinstance(action, str) and "rework" in action):
            raise ValueError("passing reference result has an invalid next action")
        if any(command["result"] != "passed" or command["exit_code"] != 0 for command in all_commands):
            raise ValueError("passing reference result contains failed command evidence")
        if any(finding["severity"] in {"high", "critical"} for finding in payload["findings"]):
            raise ValueError("passing reference result retains a high-severity finding")
    elif action is not None and (action not in role_contract["permitted_next_actions"] or "rework" not in action):
        raise ValueError("non-passing reference result advances the lifecycle")


def _load_reference_result_index(
    root: Path,
    relative_files: list[str],
    result: AgentContractResult,
) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    physical_files: set[tuple[int, int] | str] = set()
    for relative in relative_files:
        try:
            if _authority_owned_path(relative):
                raise ValueError("authority-owned paths cannot be reference result inputs")
            path = _safe_repository_path(root, relative)
            if not _canonical_repository_spelling(root, relative):
                raise ValueError("reference result path spelling is not canonical for the repository")
            if not path.is_file():
                raise ValueError("reference result must be a regular file")
            before = path.stat(follow_symlinks=False)
            with path.open("rb") as handle:
                opened = os.fstat(handle.fileno())
                raw = handle.read()
                after_read = os.fstat(handle.fileno())
            after = path.stat(follow_symlinks=False)
            identity = (opened.st_dev, opened.st_ino)
            stable = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            if stable != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
                raise ValueError("reference result changed between path validation and open")
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                after_read.st_dev,
                after_read.st_ino,
                after_read.st_size,
                after_read.st_mtime_ns,
            ) or stable != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise ValueError("reference result changed while being read")
            _safe_repository_path(root, relative)
            physical_key: tuple[int, int] | str = identity if opened.st_ino else str(path.resolve()).casefold()
            if physical_key in physical_files:
                raise ValueError("duplicate physical reference result file")
            physical_files.add(physical_key)
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("reference result must be a JSON object")
            schema_errors = _schema_errors(root, "agent-result.schema.json", payload)
            if schema_errors:
                raise ValueError("; ".join(schema_errors))
            if any(term in payload["model_alias"].casefold() for term in RUNTIME_TERMS):
                raise ValueError("reference result model_alias must remain provider-neutral")
            if payload["role_id"] != payload["task_kind"]:
                raise ValueError("reference result role_id and task_kind must match")
            if payload["planned_execution_id"] != payload["execution_id"]:
                raise ValueError("reference result execution identity differs from its plan")
            if payload["planned_context_id"] != payload["context_id"]:
                raise ValueError("reference result context identity differs from its plan")
            provenance = payload["context_provenance"]
            if (
                provenance["fresh_context"] is not True
                or provenance["producer_transcript_inherited"] is not False
                or provenance["session_memory_inherited"] is not False
            ):
                raise ValueError("reference result must prove a fresh isolated context")
            if payload["target"] not in provenance["input_artifacts"]:
                raise ValueError("reference result provenance must include its exact target")
            role_contract = _EXPECTED_ROLE_CONTRACTS.get(payload["role_id"])
            if role_contract is None:
                raise ValueError("reference result role is outside the closed role inventory")
            target_path = _safe_repository_path(root, payload["target"]["path"])
            risk_outcome = AgentContractResult()
            canonical_target_risk = _canonical_artifact_risk(root, target_path, risk_outcome)
            effective_risk = _effective_task_risk(canonical_target_risk, role_contract["task_risk_floor"])
            if not risk_outcome.valid:
                raise ValueError("reference result target risk lineage is invalid")
            if payload["target_risk"] != canonical_target_risk or payload["effective_task_risk"] != effective_risk:
                raise ValueError("reference result risk declaration differs from canonical risk")
            _validate_reference_result_intrinsics(payload, role_contract, effective_risk)
            evidence_outcome = AgentContractResult()
            evidence_artifact_paths: set[str] = set()
            target_binding_proven = False
            for evidence in payload["evidence"]:
                for artifact in evidence["artifacts"]:
                    _verify_artifact_ref(root, artifact, evidence_outcome, "reference_evidence_artifact")
                    evidence_artifact_paths.add(artifact["path"])
                    if evidence["slot"] == "target-binding" and artifact == payload["target"]:
                        target_binding_proven = True
            if not evidence_outcome.valid:
                raise ValueError("reference result contains invalid exact evidence artifacts")
            if not target_binding_proven:
                raise ValueError("reference result target-binding evidence omits the exact target")
            if not set(payload["changed_paths"]).issubset(evidence_artifact_paths):
                raise ValueError("reference result changed paths lack exact artifact evidence")
            if payload["authority_type"] != "none" or payload["authority_action_id"] is not None:
                raise ValueError("reference result must remain non-authorizing")
            if set(payload["claims"]).intersection(REQUIRED_FORBIDDEN_CLAIMS):
                raise ValueError("reference result carries a forbidden authority claim")
            if not set(payload["tool_categories"]).issubset(set(role_contract["allowed_tool_categories"])):
                raise ValueError("reference result uses tools outside its role contract")
            if payload["mutation_class"] not in role_contract["mutation_classes"]:
                raise ValueError("reference result mutation is outside its role contract")
            if payload["output_kind"] not in role_contract["output_kinds"]:
                raise ValueError("reference result output is outside its role contract")
            if payload["mutation_class"] == "none" and payload["changed_paths"]:
                raise ValueError("read-only reference result cannot declare changed paths")
            if payload["verdict"] == "pass" and payload["mutation_class"] != "none" and not payload["changed_paths"]:
                raise ValueError("passing mutating reference result must declare changed paths")
            for changed_path in payload["changed_paths"]:
                if _authority_owned_path(changed_path):
                    raise ValueError("reference result declares an authority-owned changed path")
                _safe_repository_path(root, changed_path)
                if not _changed_path_allowed(root, changed_path, role_contract, payload["target"]["path"]):
                    raise ValueError("reference result changed path is outside its role contract")
            result_id = payload["result_id"]
            if result_id in index:
                raise ValueError(f"duplicate reference result ID: {result_id}")
            index[result_id] = {
                "payload": payload,
                "path": relative,
                "sha256": sha256(raw).hexdigest(),
            }
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            result.block("invalid_reference_result_file", relative, str(exc))
    for indexed in index.values():
        payload = indexed["payload"]
        role_contract = _EXPECTED_ROLE_CONTRACTS[payload["role_id"]]
        provenance_artifacts = payload["context_provenance"]["input_artifacts"]
        reference_provenance: list[dict[str, Any]] = []
        for field_name, requirement in role_contract["result_references"].items():
            reference = payload[field_name]
            if reference is None:
                continue
            nested = index.get(reference["result_id"])
            if nested is None:
                result.block(
                    "invalid_reference_result_file",
                    indexed["path"],
                    f"referenced result requires explicit transitive bytes for {field_name}",
                )
                continue
            nested_payload = nested["payload"]
            expected = {
                "result_id": nested_payload["result_id"],
                "role_id": nested_payload["role_id"],
                "execution_id": nested_payload["execution_id"],
                "context_id": nested_payload["context_id"],
                "sha256": nested["sha256"],
            }
            edge = role_contract["reference_edges"][field_name]
            if (
                reference != expected
                or nested_payload["role_id"] not in edge["allowed_roles"]
                or nested_payload["target"] != payload["target"]
                or nested_payload["verdict"] != edge["required_verdict"]
            ):
                result.block(
                    "invalid_reference_result_file",
                    indexed["path"],
                    f"transitive {field_name} does not satisfy its exact handoff edge",
                )
                continue
            overlap = []
            if nested_payload["execution_id"] == payload["execution_id"]:
                overlap.append("execution_id")
            if nested_payload["context_id"] == payload["context_id"]:
                overlap.append("context_id")
            if overlap:
                result.block(
                    "reference_identity_overlap",
                    indexed["path"],
                    f"transitive {field_name} reuses {', '.join(overlap)} from its consumer result",
                )
                continue
            expected_provenance = {
                "path": nested["path"],
                "id": nested_payload["result_id"],
                "revision": None,
                "sha256": nested["sha256"],
            }
            reference_provenance.append(expected_provenance)
            if expected_provenance not in provenance_artifacts:
                result.block(
                    "invalid_reference_result_file",
                    indexed["path"],
                    f"transitive {field_name} is absent from exact context provenance",
                )
        producer_reference = payload["producer_result_ref"]
        producer_valid = producer_reference is None and role_contract["result_references"]["producer_result_ref"] != "required"
        if producer_reference is not None and producer_reference["result_id"] in index:
            producer_indexed = index[producer_reference["result_id"]]
            producer_payload = producer_indexed["payload"]
            producer_edge = role_contract["reference_edges"]["producer_result_ref"]
            producer_valid = (
                producer_reference
                == {
                    "result_id": producer_payload["result_id"],
                    "role_id": producer_payload["role_id"],
                    "execution_id": producer_payload["execution_id"],
                    "context_id": producer_payload["context_id"],
                    "sha256": producer_indexed["sha256"],
                }
                and producer_payload["role_id"] in producer_edge["allowed_roles"]
                and producer_payload["target"] == payload["target"]
                and producer_payload["verdict"] == producer_edge["required_verdict"]
            )
        lifecycle_outcome = AgentContractResult()
        target_path = _verify_artifact_ref(root, payload["target"], lifecycle_outcome, "reference_target")
        lifecycle_state = None
        if target_path is not None and lifecycle_outcome.valid:
            lifecycle_state = _derive_current_state(
                root,
                payload["target"],
                target_path,
                payload["role_id"],
                producer_valid,
                producer_reference,
                lifecycle_outcome,
                for_result=True,
            )
        if not lifecycle_outcome.valid or lifecycle_state not in role_contract["lifecycle_eligibility"]:
            result.block(
                "invalid_reference_result_lifecycle",
                indexed["path"],
                f"referenced result role {payload['role_id']} is not eligible for its exact assignment state",
            )
        provenance_outcome = AgentContractResult()
        for artifact in provenance_artifacts:
            if artifact == payload["target"] or artifact in reference_provenance:
                continue
            _verify_artifact_ref(root, artifact, provenance_outcome, "reference_input_artifact")
        if not provenance_outcome.valid:
            result.block(
                "invalid_reference_result_file",
                indexed["path"],
                "reference result contains invalid extra context provenance",
            )
    return index


def _verify_result_reference(
    root: Path,
    reference: dict[str, Any] | None,
    result: AgentContractResult,
    field_name: str,
    reference_index: dict[str, dict[str, Any]] | None = None,
    used_reference_ids: set[str] | None = None,
) -> bool:
    """Verify a closed reference envelope against explicitly supplied noncanonical result bytes."""

    if reference is None:
        return False
    if reference_index is None:
        return True
    indexed = reference_index.get(reference["result_id"])
    if indexed is None:
        result.block("missing_reference_result_file", field_name, f"no explicit result file declares {reference['result_id']}")
        return False
    payload = indexed["payload"]
    expected = {
        "result_id": payload["result_id"],
        "role_id": payload["role_id"],
        "execution_id": payload["execution_id"],
        "context_id": payload["context_id"],
        "sha256": indexed["sha256"],
    }
    if reference != expected:
        result.block("reference_result_mismatch", field_name, "reference envelope differs from the explicit result bytes")
        return False
    if used_reference_ids is not None:
        pending = [payload]
        while pending:
            current = pending.pop()
            current_id = current["result_id"]
            if current_id in used_reference_ids:
                continue
            used_reference_ids.add(current_id)
            for nested_field in ("producer_result_ref", "reviewer_run_ref"):
                nested_reference = current[nested_field]
                if nested_reference is not None and nested_reference["result_id"] in reference_index:
                    pending.append(reference_index[nested_reference["result_id"]]["payload"])
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


def _canonical_artifact_risk(
    root: Path,
    target_path: Path,
    outcome: AgentContractResult | None = None,
    seen: set[Path] | None = None,
) -> str:
    """Derive Artifact Risk from exact canonical ancestry and block unresolved or downgraded lineage."""

    def fail(code: str, detail: str) -> str:
        if outcome is not None:
            try:
                relative = target_path.relative_to(root).as_posix()
            except ValueError:
                relative = str(target_path)
            outcome.block(code, relative, detail)
        return "high"

    try:
        resolved = target_path.resolve(strict=True)
    except OSError:
        return fail("invalid_artifact_lineage", "canonical risk target cannot be resolved")
    visited = set() if seen is None else set(seen)
    if resolved in visited:
        return fail("cyclic_artifact_lineage", "canonical risk ancestry contains a cycle")
    visited.add(resolved)
    try:
        metadata = _artifact_metadata(target_path)
    except (OSError, UnicodeError, yaml.YAMLError, ValueError):
        return fail("malformed_artifact_lineage", "canonical risk metadata cannot be parsed")
    try:
        relative = target_path.relative_to(root).as_posix()
    except ValueError:
        return fail("invalid_artifact_lineage", "canonical risk target is outside the repository")
    recorded = metadata.get("risk", metadata.get("risk_class"))
    inherits_risk = relative.startswith(".specbound/micro-specs/")
    if recorded is not None and recorded not in RISK_ORDER:
        return fail("invalid_artifact_risk", f"canonical artifact risk must be one of {RISK_ORDER}")
    if recorded is None and not inherits_risk:
        return fail("invalid_artifact_risk", f"canonical artifact risk must be one of {RISK_ORDER}")
    required_parent = None
    if relative.startswith(".specbound/requirements/"):
        required_parent = "parent_discovery"
    elif relative.startswith(".specbound/micro-specs/"):
        required_parent = "requirement"

    parent_names = ("parent_discovery", "requirement", "micro_spec")
    declared = [name for name in parent_names if name in metadata]
    if required_parent is not None and required_parent not in declared:
        return fail("missing_artifact_lineage", f"canonical {required_parent} binding is required")

    risks = [recorded] if recorded is not None else []
    for name in declared:
        binding = metadata.get(name)
        if not isinstance(binding, dict):
            return fail("invalid_artifact_lineage", f"{name} binding must be an object")
        relative_parent = binding.get("path")
        digest = binding.get("sha256")
        if not isinstance(relative_parent, str) or not isinstance(digest, str):
            return fail("invalid_artifact_lineage", f"{name} binding requires path and sha256")
        try:
            parent_path = _safe_repository_path(root, relative_parent)
            if parent_path.resolve() in visited:
                return fail("cyclic_artifact_lineage", "canonical risk ancestry contains a cycle")
            if sha256(parent_path.read_bytes()).hexdigest() != digest:
                return fail("stale_artifact_lineage", f"{name} digest differs from canonical parent bytes")
        except (OSError, ValueError):
            return fail("invalid_artifact_lineage", f"{name} path cannot be resolved safely")
        try:
            parent_metadata = _artifact_metadata(parent_path)
        except (OSError, UnicodeError, yaml.YAMLError, ValueError):
            return fail("malformed_artifact_lineage", f"{name} parent metadata cannot be parsed")
        required_binding_keys = {"id", "revision"} if name in {"parent_discovery", "requirement"} else {"id"}
        if any(key not in binding for key in required_binding_keys):
            return fail("invalid_artifact_lineage", f"{name} binding is missing exact identity fields")
        if binding.get("id") != parent_metadata.get("id") or (
            "revision" in required_binding_keys and binding.get("revision") != parent_metadata.get("revision")
        ):
            return fail("artifact_lineage_identity_mismatch", f"{name} identity differs from canonical parent bytes")
        confirmed_parent_risk: str | None = None
        if name == "parent_discovery":
            expected_confirmation = f".specbound/confirmations/{Path(relative_parent).stem}.confirmation.json"
            if binding.get("confirmation_path") != expected_confirmation:
                return fail(
                    "artifact_lineage_identity_mismatch",
                    "parent Discovery binding must name its exact canonical confirmation record",
                )
            state_outcome = outcome if outcome is not None else AgentContractResult()
            state_target = {
                "path": relative_parent,
                "id": parent_metadata.get("id"),
                "revision": parent_metadata.get("revision"),
                "sha256": digest,
            }
            if not _canonical_state_record_matches(root, state_target, "confirmed", state_outcome):
                return "high"
            try:
                confirmation = _read_json_object(
                    _safe_repository_path(root, expected_confirmation),
                    "Discovery confirmation",
                )
            except (OSError, UnicodeError, ValueError):
                return fail("missing_confirmed_record", "canonical Discovery confirmation is missing or unreadable")
            confirmed_parent_risk = confirmation.get("risk_class")
            if confirmed_parent_risk not in RISK_ORDER:
                return fail("invalid_artifact_risk", "confirmed Discovery risk must use the closed risk order")
        parent_risk = _canonical_artifact_risk(root, parent_path, outcome, visited)
        if confirmed_parent_risk is not None:
            if parent_risk != confirmed_parent_risk:
                return fail(
                    "conflicting_artifact_risk",
                    "confirmed Discovery snapshot risk differs from its exact confirmation-bound risk",
                )
            parent_risk = confirmed_parent_risk
        risks.append(parent_risk)
        if recorded is not None and RISK_ORDER.index(recorded) < RISK_ORDER.index(parent_risk):
            fail("artifact_risk_downgrade", f"child risk {recorded!r} is below parent risk {parent_risk!r}")
    return RISK_ORDER[max(RISK_ORDER.index(risk) for risk in risks)]


def _effective_task_risk(target_risk: str, task_floor: str) -> str:
    return RISK_ORDER[max(RISK_ORDER.index(target_risk), RISK_ORDER.index(task_floor))]


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


def _micro_spec_review_state(
    root: Path,
    target: dict[str, Any],
    outcome: AgentContractResult | None = None,
) -> str | None:
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
            if outcome is not None:
                outcome.block("stale_micro_spec_review_parent", review_relative, "Micro-SPEC review parent requirement binding is stale or mismatched")
            return None
        _validate_requirement(
            root,
            parent_path,
            validation,
            {review["requirement_id"]: review["revision"]},
        )
    except (KeyError, OSError, ValueError) as exc:
        if outcome is not None:
            outcome.block("missing_or_malformed_micro_spec_review", review_relative, f"Micro-SPEC review cannot be resolved: {exc}")
        return None
    if not validation.valid:
        if outcome is not None:
            for blocker in validation.blockers:
                outcome.block(f"lifecycle_{blocker['code']}", blocker["path"], blocker["detail"])
        return None
    if review.get("decision") == "approved_for_implementation":
        return "approved_for_implementation"
    if outcome is not None:
        outcome.block("conflicting_micro_spec_review", review_relative, "Micro-SPEC review decision is not approved_for_implementation")
    return None


def _retained_requirement_lifecycle_is_valid(
    root: Path,
    target: dict[str, Any],
    outcome: AgentContractResult | None,
) -> bool:
    stem = Path(target["path"]).stem
    records = {
        "rejection": (
            f".specbound/rejections/{stem}.rejection.json",
            {"schema_version", "requirement_path", "requirement_id", "revision", "reviewed_sha256", "sha256", "risk", "authority", "rejected_at", "decision", "reason"},
            "requirement_rejection_authorities_by_risk",
            "rejected",
        ),
        "reconsideration": (
            f".specbound/reconsiderations/{stem}.reconsideration.json",
            {"schema_version", "requirement_path", "requirement_id", "revision", "reviewed_sha256", "rejected_sha256", "reopened_sha256", "risk", "authority", "reconsidered_at", "decision", "reason"},
            "requirement_reconsideration_authorities_by_risk",
            "reopened_for_review",
        ),
        "review-decision": (
            f".specbound/review-decisions/{stem}.review-decision.json",
            {"schema_version", "requirement_path", "requirement_id", "revision", "reviewed_sha256", "risk", "authority", "decided_at", "decision", "reason"},
            "requirement_review_decision_authorities_by_risk",
            None,
        ),
    }
    present: dict[str, tuple[str, dict[str, Any]]] = {}
    try:
        from .validation import PLACEHOLDER_RE

        target_path = _safe_repository_path(root, target["path"])
        metadata = _artifact_metadata(target_path)
        config_path = _safe_repository_path(root, "specbound.yaml")
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        policy = config["policy"]
        for name, (relative, required_fields, selector, expected_decision) in records.items():
            path = _safe_repository_path(root, relative, must_exist=False)
            if not path.exists():
                continue
            record = _read_json_object(_safe_repository_path(root, relative), f"retained {name}")
            present[name] = (relative, record)
            risk = metadata.get("risk")
            allowed = policy.get(selector, {}).get(risk, []) if isinstance(policy, dict) else []
            digest_fields = [field for field in required_fields if field.endswith("sha256") or field == "sha256"]
            timestamp_field = {"rejection": "rejected_at", "reconsideration": "reconsidered_at", "review-decision": "decided_at"}[name]
            if (
                not required_fields.issubset(record)
                or record.get("schema_version") != 1
                or record.get("requirement_path") != target["path"]
                or record.get("requirement_id") != target["id"]
                or record.get("revision") != target["revision"]
                or record.get("risk") != risk
                or record.get("authority") not in allowed
                or not isinstance(record.get("reason"), str)
                or not record["reason"].strip()
                or PLACEHOLDER_RE.search(record["reason"])
                or not _valid_timestamp(record.get(timestamp_field))
                or any(not isinstance(record.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", record[field]) for field in digest_fields)
                or (expected_decision is not None and record.get("decision") != expected_decision)
                or (name == "review-decision" and record.get("decision") not in {"approval_ready", "rejected"})
            ):
                raise ValueError(f"retained {name} record is malformed, unbound, or unauthorized")
        if ("rejection" in present) != ("reconsideration" in present):
            raise ValueError("retained rejection and reconsideration evidence must form an exact pair")
        if "rejection" in present:
            rejection = present["rejection"][1]
            reconsideration = present["reconsideration"][1]
            if (
                rejection["reviewed_sha256"] != target["sha256"]
                or reconsideration["reviewed_sha256"] != target["sha256"]
                or reconsideration["reopened_sha256"] != target["sha256"]
                or reconsideration["rejected_sha256"] != rejection["sha256"]
            ):
                raise ValueError("retained rejection/reconsideration digests do not bind the exact in-review snapshot")
        if "review-decision" in present and present["review-decision"][1]["reviewed_sha256"] != target["sha256"]:
            raise ValueError("retained review decision does not bind the exact in-review snapshot")
    except (KeyError, OSError, TypeError, ValueError, yaml.YAMLError) as exc:
        if outcome is not None:
            outcome.block("conflicting_lifecycle_evidence", target["path"], str(exc))
        return False
    return True


def _canonical_state_record_matches(
    root: Path,
    target: dict[str, Any],
    state: str,
    outcome: AgentContractResult | None = None,
) -> bool:
    relative = target["path"]

    def fail(code: str, detail: str) -> bool:
        if outcome is not None:
            outcome.block(code, relative, detail)
        return False
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
        return fail("invalid_lifecycle_target_family", f"state {state!r} is incompatible with the target family")
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
        return fail("invalid_lifecycle_target_topology", f"target path is not canonical for state {state!r}")
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
        return fail(f"missing_{state}_record", f"canonical {state} record is missing or unreadable")
    expected_decision = {"confirmed": "confirmed", "in_review": "submitted_for_review"}.get(state)
    if record.get(path_field) != relative:
        return fail(f"{state}_record_path_mismatch", f"canonical {state} record targets different artifact bytes")
    if record.get(digest_field) != target["sha256"]:
        return fail(f"stale_{state}_record", f"canonical {state} record digest differs from the exact target")
    expected_identity = record.get("discovery_id") if state == "confirmed" else record.get("requirement_id")
    if expected_identity != target["id"] or record.get("revision") != target["revision"]:
        return fail(f"{state}_record_identity_mismatch", f"canonical {state} record identity differs from the target")
    if expected_decision is not None and record.get("decision") != expected_decision:
        return fail(f"conflicting_{state}_record", f"canonical {state} record carries a conflicting decision")
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
            requirement_path = _safe_repository_path(root, relative)
            _validate_requirement(root, requirement_path, validation, {target["id"]: target["revision"]})
            config = _load_config(root)
            allowed_by_risk = config["policy"]["requirement_approval_authorities_by_risk"]
            approval_risk = record.get("risk")
            allowed_authorities = allowed_by_risk.get(approval_risk, []) if isinstance(allowed_by_risk, dict) else []
            if record.get("authority") not in allowed_authorities:
                validation.block(
                    "unauthorized_approval_authority",
                    record_relative,
                    "approval authority is not allowed for the canonical Artifact Risk",
                )
        else:
            target_path = _safe_repository_path(root, relative)
            _validate_requirement(root, target_path, validation, {})
            _validate_requirement_review_submission(root, record_path, validation)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        return fail(f"invalid_{state}_record", f"canonical {state} record validation failed: {exc}")
    if not validation.valid and outcome is not None:
        for blocker in validation.blockers:
            outcome.block(
                f"lifecycle_{blocker['code']}",
                blocker.get("path", relative),
                blocker.get("detail", f"canonical {state} record failed validation"),
            )
    if state == "in_review" and validation.valid and not _retained_requirement_lifecycle_is_valid(root, target, outcome):
        return False
    return validation.valid


def _derive_current_state(
    root: Path,
    target: dict[str, Any],
    path: Path,
    role_id: str,
    producer_reference_valid: bool,
    producer_reference: dict[str, Any] | None,
    outcome: AgentContractResult | None = None,
    *,
    for_result: bool = False,
) -> str | None:
    if not target["path"].startswith(".specbound/"):
        return None
    if for_result and role_id == "discovery-author" and target["path"].startswith(".specbound/discoveries/"):
        metadata = _artifact_metadata(path)
        if metadata.get("status") == "in_review":
            return "draft"
    if for_result and role_id == "requirement-author" and target["path"].startswith(".specbound/requirements/"):
        metadata = _artifact_metadata(path)
        parent = metadata.get("parent_discovery")
        if not isinstance(parent, dict):
            return None
        check = outcome if outcome is not None else AgentContractResult()
        blockers_before = len(check.blockers)
        parent_path = _verify_artifact_ref(root, parent, check, "parent_discovery")
        if parent_path is None or len(check.blockers) != blockers_before:
            return None
        if not _canonical_state_record_matches(root, parent, "confirmed", check):
            return None
        return "confirmed"
    if (
        for_result
        and role_id == "independent-reviewer"
        and producer_reference_valid
        and target["path"].startswith(".specbound/requirements/")
    ):
        metadata = _artifact_metadata(path)
        state = metadata.get("status")
        if not isinstance(state, str) or not state:
            if outcome is not None:
                outcome.block("missing_canonical_state", target["path"], "reviewed requirement lacks a canonical status")
            return None
        if not _canonical_state_record_matches(root, target, state, outcome):
            return None
        return state
    if (
        for_result
        and role_id == "independent-reviewer"
        and producer_reference_valid
        and target["path"].startswith(".specbound/discoveries/")
    ):
        metadata = _artifact_metadata(path)
        state = metadata.get("status")
        if state == "in_review":
            return "in_review"
        if isinstance(state, str) and _canonical_state_record_matches(root, target, state, outcome):
            return state
        return None
    if (
        for_result
        and role_id == "independent-reviewer"
        and producer_reference_valid
        and target["path"].startswith(".specbound/micro-specs/")
    ):
        return "in_review"
    if for_result and role_id == "micro-spec-author" and target["path"].startswith(".specbound/micro-specs/"):
        metadata = _artifact_metadata(path)
        requirement = metadata.get("requirement")
        if not isinstance(requirement, dict):
            return None
        check = outcome if outcome is not None else AgentContractResult()
        blockers_before = len(check.blockers)
        requirement_path = _verify_artifact_ref(root, requirement, check, "parent_requirement")
        if requirement_path is None or len(check.blockers) != blockers_before:
            return None
        if not _canonical_state_record_matches(root, requirement, "approved", check):
            return None
        return "approved"
    if (
        target["path"].startswith(".specbound/micro-specs/")
        and role_id == "independent-reviewer"
        and producer_reference_valid
        and producer_reference is not None
        and producer_reference["role_id"] == "micro-spec-author"
    ):
        parts = PurePosixPath(target["path"]).parts
        review_relative = f".specbound/micro-spec-reviews/{parts[2]}/{Path(parts[3]).stem}.review.json"
        try:
            review_path = _safe_repository_path(root, review_relative, must_exist=False)
        except ValueError as exc:
            if outcome is not None:
                outcome.block("unsafe_artifact_path", review_relative, str(exc))
            return None
        if not review_path.exists():
            return "in_review"
    review_state = _micro_spec_review_state(root, target, outcome)
    if target["path"].startswith(".specbound/micro-specs/") and review_state is None:
        return None
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
            if not _canonical_state_record_matches(root, target, value, outcome):
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


def _expected_author_role_for_target(target: dict[str, Any]) -> str | None:
    path = target["path"]
    if path.startswith(".specbound/discoveries/"):
        return "discovery-author"
    if path.startswith(".specbound/requirements/"):
        return "requirement-author"
    if path.startswith(".specbound/micro-specs/"):
        return "micro-spec-author"
    return None


def validate_role_request(
    root: Path,
    request_path: Path,
    policy_path: str,
    *,
    reference_result_files: list[str] | None = None,
) -> AgentContractResult:
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
    result.advisory_next_action = role["permitted_next_actions"][0]
    if request["task_kind"] != role["task_kind"]:
        result.block("role_task_mismatch", str(request_path), "task_kind does not match the selected role")

    reference_index = _load_reference_result_index(root, reference_result_files or [], result)
    used_reference_ids: set[str] = set()
    reference_validity: dict[str, bool] = {}
    for field_name in ("producer_result_ref", "reviewer_run_ref"):
        requirement = role["result_references"][field_name]
        reference = request[field_name]
        if not _reference_valid(requirement, reference):
            result.block("invalid_result_reference", str(request_path), f"{field_name} violates the role's {requirement} rule")
            reference_validity[field_name] = False
        else:
            reference_validity[field_name] = reference is not None and _verify_result_reference(
                root,
                reference,
                result,
                field_name,
                reference_index,
                used_reference_ids,
            )
        if reference_validity[field_name]:
            referenced_payload = reference_index[reference["result_id"]]["payload"]
            if (
                referenced_payload["execution_id"] == request["planned_execution_id"]
                or referenced_payload["context_id"] == request["planned_context_id"]
            ):
                result.block("self_reference_result", field_name, "request identity overlaps its referenced result")
                reference_validity[field_name] = False
            reference_edge = role["reference_edges"][field_name]
            if reference_validity[field_name] and (
                reference_edge is None or referenced_payload["role_id"] not in reference_edge["allowed_roles"]
            ):
                result.block("invalid_reference_edge", field_name, "referenced producer role differs from the closed consumer edge")
                reference_validity[field_name] = False
            elif (
                reference_validity[field_name]
                and role["role_id"] == "independent-reviewer"
                and field_name == "producer_result_ref"
                and referenced_payload["role_id"] != _expected_author_role_for_target(request["target"])
            ):
                result.block("invalid_reference_edge", field_name, "review producer role must match the reviewed artifact family")
                reference_validity[field_name] = False
            elif (
                reference_validity[field_name]
                and reference_edge["target_binding"] in {"exact-target", "exact-parent"}
                and referenced_payload["target"] != request["target"]
            ):
                result.block("reference_target_mismatch", field_name, "referenced result is not bound to the exact consumer target or authoring parent")
                reference_validity[field_name] = False
            elif reference_validity[field_name] and referenced_payload["verdict"] != reference_edge["required_verdict"]:
                result.block("invalid_reference_verdict", field_name, "referenced result does not have the required verdict")
                reference_validity[field_name] = False
    if all(reference_validity.get(name) for name in ("producer_result_ref", "reviewer_run_ref")):
        producer_payload = reference_index[request["producer_result_ref"]["result_id"]]["payload"]
        reviewer_payload = reference_index[request["reviewer_run_ref"]["result_id"]]["payload"]
        if any(
            producer_payload[name] == reviewer_payload[name]
            for name in ("result_id", "execution_id", "context_id")
        ):
            result.block("reference_identity_overlap", str(request_path), "producer and reviewer references must use distinct result, execution, and context identities")
            reference_validity["producer_result_ref"] = False
            reference_validity["reviewer_run_ref"] = False
    if request["reviewer_run_ref"] is not None and request["reviewer_run_ref"]["role_id"] != "independent-reviewer":
        result.block("invalid_result_reference", str(request_path), "reviewer_run_ref role_id must be independent-reviewer")

    target_path = _verify_artifact_ref(root, request["target"], result, "target")
    if target_path is not None:
        target_risk = _canonical_artifact_risk(root, target_path, result)
        effective_task_risk = _effective_task_risk(target_risk, role["task_risk_floor"])
        result.derived_target_risk = target_risk
        result.derived_effective_task_risk = effective_task_risk
        if request["target_risk"] != target_risk:
            result.block("target_risk_spoofing", request["target"]["path"], f"caller claimed {request['target_risk']!r}; repository risk is {target_risk!r}")
        if request["effective_task_risk"] != effective_task_risk:
            result.block("effective_task_risk_spoofing", request["target"]["path"], f"caller claimed {request['effective_task_risk']!r}; derived task risk is {effective_task_risk!r}")
        state_blocker_count = len(result.blockers)
        derived_state = _derive_current_state(
            root,
            request["target"],
            target_path,
            role["role_id"],
            reference_validity["producer_result_ref"],
            request["producer_result_ref"],
            result,
        )
        if derived_state is None:
            if len(result.blockers) == state_blocker_count:
                result.block("undetermined_current_state", request["target"]["path"], "repository target has no deterministic lifecycle state")
        else:
            result.derived_current_state = derived_state
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

    verified_iqc_set = request["verified_iteration_qc_set"]
    if role["role_id"] == "delivery-qc":
        for artifact in verified_iqc_set:
            _verify_artifact_ref(root, artifact, result, "verified_iteration_qc")
        _delivery_qc_iqc_provenance(root, request["target"], verified_iqc_set, result)
    elif verified_iqc_set:
        result.block("unexpected_verified_iqc_set", str(request_path), "only delivery-qc may declare a verified Iteration-QC set")

    capabilities = request["requested_capabilities"]
    supported_mutations = {mutation for configured_role in policy["roles"] for mutation in configured_role["mutation_classes"]}
    for mutation in capabilities["mutation_classes"]:
        if mutation in {"authority_transition", "external_mutation"}:
            result.block(
                f"unsupported_{mutation}",
                str(request_path),
                "agent-role requests never authorize canonical authority or external mutations",
            )
        elif mutation not in supported_mutations:
            result.block("unknown_mutation_class", str(request_path), f"unknown mutation class: {mutation}")
        elif mutation not in role["mutation_classes"]:
            result.block("capability_escalation", str(request_path), f"requested mutation class exceeds the {role['role_id']} policy")
    for requested_name, policy_name in (
        ("tool_categories", "allowed_tool_categories"),
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
        if _authority_owned_path(requested_path) or not _changed_path_allowed(
            root, requested_path, role, request["target"]["path"]
        ):
            result.block("capability_escalation", requested_path, f"requested path exceeds the {role['role_id']} policy")
    forbidden_actions = set(capabilities["actions"]) & set(role["forbidden_actions"])
    if forbidden_actions:
        result.block("forbidden_agent_action", str(request_path), f"forbidden actions: {', '.join(sorted(forbidden_actions))}")
    if reference_index is not None:
        for result_id in sorted(set(reference_index) - used_reference_ids):
            result.block("extra_reference_result_file", reference_index[result_id]["path"], f"explicit result {result_id} is not declared by the request")

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
    scope_text = match.group(1)
    if "valid/invalid fixture config" in scope_text:
        scoped.extend(
            (path, False)
            for path in (
                "fixtures/valid-minimal/specbound.yaml",
                "fixtures/valid-minimal/.specbound/policies/agent-roles.yaml",
                "fixtures/invalid-unsafe-path/specbound.yaml",
                "fixtures/invalid-unsafe-path/.specbound/policies/agent-roles.yaml",
            )
        )
    if "three repository policy copies" in scope_text:
        scoped.extend(
            (path, False)
            for path in (
                "fixtures/valid-minimal/.specbound/policies/agent-roles.yaml",
                "fixtures/invalid-unsafe-path/.specbound/policies/agent-roles.yaml",
            )
        )
    if "installed wheel" in scope_text:
        scoped.append((".github/workflows/ci.yml", False))
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


def _delivery_qc_iqc_provenance(
    root: Path,
    target: dict[str, Any],
    input_artifacts: list[dict[str, Any]],
    outcome: AgentContractResult,
) -> None:
    iqc_refs = [
        artifact
        for artifact in input_artifacts
        if isinstance(artifact, dict)
        and isinstance(artifact.get("path"), str)
        and artifact["path"].startswith(".specbound/iteration-qc/")
    ]
    if not iqc_refs:
        outcome.block("missing_verified_iqc_set", target["path"], "delivery-qc requires at least one exact canonical IQC provenance artifact")
        return
    required_criteria: set[str] = set()
    try:
        requirement_path = _safe_repository_path(root, target["path"])
        required_criteria = set(re.findall(r"^###\s+(AC-[0-9]+)\b", requirement_path.read_text(encoding="utf-8"), re.MULTILINE))
    except (OSError, ValueError):
        outcome.block("invalid_delivery_requirement", target["path"], "approved requirement bytes could not be read for AC coverage")
        return
    covered: set[str] = set()
    seen_micro_specs: set[tuple[str, str, str]] = set()
    for artifact in iqc_refs:
        try:
            iqc_path = _verify_artifact_ref(root, artifact, outcome, "delivery-qc-iqc")
            if iqc_path is None:
                continue
            from .validation import Result as RepositoryResult, _validate_qc_record

            validation = RepositoryResult(root)
            _validate_qc_record(root, iqc_path, validation, "iteration_qc")
            if not validation.valid:
                for blocker in validation.blockers:
                    outcome.block(blocker["code"], blocker["path"], blocker["detail"])
                continue
            iqc = _read_json_object(iqc_path, "iteration-QC evidence")
            expected_iqc_keys = {
                "schema_version", "micro_spec", "selected_acceptance_criteria",
                "remaining_acceptance_criteria", "verification", "verdict",
            }
            if set(iqc) != expected_iqc_keys:
                outcome.block("invalid_iqc_provenance", artifact["path"], "IQC record must use the exact closed canonical field set")
                continue
            if iqc.get("verdict") != "verified":
                outcome.block("unverified_iqc", artifact["path"], "delivery-qc provenance contains a non-verified IQC")
                continue
            micro_ref = iqc.get("micro_spec")
            if not isinstance(micro_ref, dict) or set(micro_ref) != {"path", "id", "sha256"}:
                outcome.block("invalid_iqc_ancestry", artifact["path"], "IQC micro_spec ancestry is malformed")
                continue
            micro_path = _safe_repository_path(root, micro_ref["path"])
            if sha256(micro_path.read_bytes()).hexdigest() != micro_ref["sha256"]:
                outcome.block("stale_iqc_ancestry", artifact["path"], "IQC Micro-SPEC digest is stale")
                continue
            micro_metadata = _artifact_metadata(micro_path)
            _canonical_artifact_risk(root, micro_path, outcome)
            if micro_metadata.get("id") != micro_ref["id"]:
                outcome.block("iqc_identity_mismatch", artifact["path"], "IQC Micro-SPEC identity does not match exact bytes")
                continue
            micro_key = (micro_ref["path"], micro_ref["id"], micro_ref["sha256"])
            if micro_key in seen_micro_specs:
                outcome.block("duplicate_iqc", artifact["path"], "verified IQC set contains duplicate Micro-SPEC coverage")
                continue
            seen_micro_specs.add(micro_key)
            parent = micro_metadata.get("requirement")
            if not isinstance(parent, dict) or any(parent.get(key) != target[key] for key in ("path", "id", "revision", "sha256")):
                outcome.block("cross_requirement_iqc", artifact["path"], "IQC ancestry does not bind to the exact Delivery-QC requirement")
                continue
            micro_target = {"path": micro_ref["path"], "id": micro_ref["id"], "revision": None, "sha256": micro_ref["sha256"]}
            if _micro_spec_review_state(root, micro_target) != "approved_for_implementation":
                outcome.block("unreviewed_iqc_ancestry", artifact["path"], "IQC ancestry lacks an exact approved Micro-SPEC review")
                continue
            selected = iqc.get("selected_acceptance_criteria")
            if not isinstance(selected, list) or not selected or any(not isinstance(item, str) for item in selected):
                outcome.block("invalid_iqc_coverage", artifact["path"], "IQC selected acceptance criteria are empty or malformed")
                continue
            overlap = covered.intersection(selected)
            if overlap:
                outcome.block("duplicate_iqc_coverage", artifact["path"], f"acceptance criteria covered more than once: {', '.join(sorted(overlap))}")
            covered.update(selected)
        except (KeyError, OSError, TypeError, ValueError):
            outcome.block("invalid_iqc_ancestry", artifact["path"], "IQC provenance could not be resolved safely")
    if covered != required_criteria:
        missing = sorted(required_criteria - covered)
        extra = sorted(covered - required_criteria)
        detail = f"IQC set does not exactly cover requirement ACs; missing={missing}, extra={extra}"
        outcome.block("incomplete_iqc_coverage", target["path"], detail)


def validate_agent_result(
    root: Path,
    result_path: Path,
    policy_path: str,
    *,
    reference_result_files: list[str] | None = None,
) -> AgentContractResult:
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
    if payload.get("mutation_class") in {"authority_transition", "external_mutation"}:
        outcome.block(
            f"unsupported_{payload['mutation_class']}",
            str(result_path),
            "agent-result contracts never authorize canonical authority or external mutations",
        )
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
    outcome.advisory_next_action = payload["permitted_next_action"]
    if payload["task_kind"] != role["task_kind"]:
        outcome.block("role_task_mismatch", str(result_path), "task_kind does not match the selected role")
    if payload["planned_execution_id"] != payload["execution_id"]:
        outcome.block("planned_execution_mismatch", str(result_path), "execution_id differs from the pre-execution planned_execution_id")
    if payload["planned_context_id"] != payload["context_id"]:
        outcome.block("planned_context_mismatch", str(result_path), "context_id differs from the pre-execution planned_context_id")
    if any(term in payload["model_alias"].lower() for term in RUNTIME_TERMS):
        outcome.block("runtime_specific_result", str(result_path), "model_alias must remain a provider-neutral alias")
    if payload["output_kind"] not in role["output_kinds"]:
        outcome.block("invalid_output_kind", str(result_path), "output_kind is outside the role policy")

    reference_index = _load_reference_result_index(root, reference_result_files or [], outcome)
    used_reference_ids: set[str] = set()
    reference_validity: dict[str, bool] = {}
    for field_name in ("producer_result_ref", "reviewer_run_ref"):
        requirement = role["result_references"][field_name]
        reference = payload[field_name]
        if not _reference_valid(requirement, reference):
            outcome.block("invalid_result_reference", str(result_path), f"{field_name} violates the role's {requirement} rule")
            reference_validity[field_name] = False
        else:
            reference_validity[field_name] = reference is not None and _verify_result_reference(
                root,
                reference,
                outcome,
                field_name,
                reference_index,
                used_reference_ids,
            )
        if reference_validity[field_name]:
            referenced_payload = reference_index[reference["result_id"]]["payload"]
            referenced_parent_ids = {
                item["result_id"]
                for item in (referenced_payload["producer_result_ref"], referenced_payload["reviewer_run_ref"])
                if item is not None
            }
            if (
                referenced_payload["result_id"] == payload["result_id"]
                or referenced_payload["execution_id"] == payload["execution_id"]
                or referenced_payload["context_id"] == payload["context_id"]
                or payload["result_id"] in referenced_parent_ids
            ):
                outcome.block("self_reference_result", field_name, "result identity overlaps or is referenced by its own parent result")
                reference_validity[field_name] = False
            reference_edge = role["reference_edges"][field_name]
            if reference_validity[field_name] and (
                reference_edge is None or referenced_payload["role_id"] not in reference_edge["allowed_roles"]
            ):
                outcome.block("invalid_reference_edge", field_name, "referenced producer role differs from the closed consumer edge")
                reference_validity[field_name] = False
            elif (
                reference_validity[field_name]
                and role["role_id"] == "independent-reviewer"
                and field_name == "producer_result_ref"
                and referenced_payload["role_id"] != _expected_author_role_for_target(payload["target"])
            ):
                outcome.block("invalid_reference_edge", field_name, "review producer role must match the reviewed artifact family")
                reference_validity[field_name] = False
            elif (
                reference_validity[field_name]
                and reference_edge["target_binding"] in {"exact-target", "exact-parent"}
                and referenced_payload["target"] != payload["target"]
            ):
                outcome.block("reference_target_mismatch", field_name, "referenced result is not bound to the exact consumer target or authoring parent")
                reference_validity[field_name] = False
            elif reference_validity[field_name] and referenced_payload["verdict"] != reference_edge["required_verdict"]:
                outcome.block("invalid_reference_verdict", field_name, "referenced result does not have the required verdict")
                reference_validity[field_name] = False
    if all(reference_validity.get(name) for name in ("producer_result_ref", "reviewer_run_ref")):
        producer_payload = reference_index[payload["producer_result_ref"]["result_id"]]["payload"]
        reviewer_payload = reference_index[payload["reviewer_run_ref"]["result_id"]]["payload"]
        if any(
            producer_payload[name] == reviewer_payload[name]
            for name in ("result_id", "execution_id", "context_id")
        ):
            outcome.block("reference_identity_overlap", str(result_path), "producer and reviewer references must use distinct result, execution, and context identities")
            reference_validity["producer_result_ref"] = False
            reference_validity["reviewer_run_ref"] = False
    if payload["reviewer_run_ref"] is not None and payload["reviewer_run_ref"]["role_id"] != "independent-reviewer":
        outcome.block("invalid_result_reference", str(result_path), "reviewer_run_ref role_id must be independent-reviewer")

    derived_effective_task_risk = "high"
    target_path = _verify_artifact_ref(root, payload["target"], outcome, "target")
    if target_path is not None:
        state_blocker_count = len(outcome.blockers)
        state = _derive_current_state(
            root,
            payload["target"],
            target_path,
            role["role_id"],
            reference_validity["producer_result_ref"],
            payload["producer_result_ref"],
            outcome,
            for_result=True,
        )
        outcome.derived_current_state = state
        if state is None:
            if len(outcome.blockers) == state_blocker_count:
                outcome.block("result_state_mismatch", payload["target"]["path"], f"repository state {state!r} is not eligible for {role['role_id']}")
        elif state not in role["lifecycle_eligibility"]:
            outcome.block("result_state_mismatch", payload["target"]["path"], f"repository state {state!r} is not eligible for {role['role_id']}")
        target_risk = _canonical_artifact_risk(root, target_path, outcome)
        derived_effective_task_risk = _effective_task_risk(target_risk, role["task_risk_floor"])
        outcome.derived_target_risk = target_risk
        outcome.derived_effective_task_risk = derived_effective_task_risk
        if payload["target_risk"] != target_risk:
            outcome.block("target_risk_mismatch", payload["target"]["path"], "target_risk does not match canonical repository risk")
        if payload["effective_task_risk"] != derived_effective_task_risk:
            outcome.block("effective_task_risk_mismatch", payload["target"]["path"], "effective_task_risk is not max(target risk, task floor)")

    provenance = payload["context_provenance"]
    if not provenance["fresh_context"] or provenance["producer_transcript_inherited"] or provenance["session_memory_inherited"]:
        outcome.block("invalid_context_provenance", str(result_path), "result context must be fresh and inherit neither producer transcript nor session memory")
    expected_reference_provenance: dict[str, dict[str, Any]] = {}
    for field_name in ("producer_result_ref", "reviewer_run_ref"):
        reference = payload[field_name]
        if reference is None or reference["result_id"] not in reference_index:
            continue
        indexed = reference_index[reference["result_id"]]
        expected_reference_provenance[indexed["path"]] = {
            "path": indexed["path"],
            "id": reference["result_id"],
            "revision": None,
            "sha256": reference["sha256"],
        }
    input_keys: set[tuple[str, str, int | None, str]] = set()
    for artifact in provenance["input_artifacts"]:
        expected_reference = expected_reference_provenance.get(artifact["path"])
        if expected_reference is not None:
            if artifact != expected_reference:
                outcome.block("invalid_reference_result_provenance", artifact["path"], "reference-result provenance must exactly bind path, result_id, null revision, and file digest")
        else:
            _verify_artifact_ref(root, artifact, outcome, "input_artifact")
        input_keys.add((artifact["path"], artifact["id"], artifact["revision"], artifact["sha256"]))
    for expected in expected_reference_provenance.values():
        expected_key = (expected["path"], expected["id"], expected["revision"], expected["sha256"])
        if expected_key not in input_keys:
            outcome.block("missing_reference_result_provenance", expected["path"], "context_provenance.input_artifacts must include the exact explicit reference-result file")
    target_key = (payload["target"]["path"], payload["target"]["id"], payload["target"]["revision"], payload["target"]["sha256"])
    if target_key not in input_keys:
        outcome.block("missing_target_provenance", str(result_path), "context_provenance.input_artifacts must include the exact target")
    if role["role_id"] == "delivery-qc":
        _delivery_qc_iqc_provenance(root, payload["target"], provenance["input_artifacts"], outcome)

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
        if _authority_owned_path(changed_path):
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
    risk_evidence = role["evidence_requirements_by_risk"][derived_effective_task_risk]
    required_slots = set(risk_evidence["required"])
    conditional_slots = set(risk_evidence["conditional"])
    for slot_name, slot_policy in configured_slots.items():
        evidence = evidence_by_slot.get(slot_name)
        if evidence is None:
            if slot_name in required_slots or slot_name in conditional_slots:
                applicability = "required" if slot_name in required_slots else "conditional"
                outcome.block(
                    "missing_evidence_slot",
                    str(result_path),
                    f"{applicability} evidence slot {slot_name} must be explicitly resolved",
                )
            continue
        if evidence["status"] == "not_applicable":
            reason = (evidence.get("reason") or "").strip()
            if _blanket_not_applicable_reason(reason, evidence["slot"]):
                outcome.block("blanket_not_applicable_evidence", str(result_path), f"slot {slot_name} requires a concrete task-specific reason")
            if slot_name in required_slots or slot_name not in conditional_slots or not slot_policy["not_applicable_allowed"]:
                outcome.block("invalid_not_applicable_evidence", str(result_path), f"slot {slot_name} cannot be not_applicable")
        if evidence["status"] == "provided" and slot_name in COMMAND_EVIDENCE_SLOTS and not evidence["commands"]:
            outcome.block("missing_command_evidence", str(result_path), f"evidence slot {slot_name} requires a recorded command")
        if slot_name == "no-write" and (
            evidence["commands"] or changed_paths or payload["mutation_class"] != "none"
        ):
            outcome.block("invalid_no_write_proof", str(result_path), "no-write-proof requires empty commands, empty changed_paths, and mutation_class none")
        if slot_name == "rollback-inventory" and derived_effective_task_risk == "high":
            rollback_paths = {artifact["path"] for artifact in evidence["artifacts"]}
            if not any(_rollback_verification_command(command) for command in evidence["commands"]) or not set(changed_paths).issubset(rollback_paths):
                outcome.block(
                    "invalid_rollback_evidence",
                    str(result_path),
                    "high-risk rollback inventory requires rollback/no-partial-mutation verification and exact evidence for every changed path",
                )
    missing_changed_evidence = sorted(set(changed_paths) - evidence_artifact_paths)
    if missing_changed_evidence:
        outcome.block("missing_changed_path_evidence", str(result_path), f"changed paths lack exact artifact evidence: {', '.join(missing_changed_evidence)}")

    action = payload["permitted_next_action"]
    if payload["verdict"] == "pass":
        if action not in role["permitted_next_actions"] or (isinstance(action, str) and "rework" in action):
            outcome.block("invalid_permitted_next_action", str(result_path), "passing result requires a non-rework role-permitted next action")
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
    for result_id in sorted(set(reference_index) - used_reference_ids):
        outcome.block("extra_reference_result_file", reference_index[result_id]["path"], f"explicit result {result_id} is not declared by the result")
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


def validate_configured_agent_role_skills(root: Path) -> AgentContractResult:
    try:
        policy_path = configured_agent_policy_path(root)
    except ValueError as exc:
        result = AgentContractResult()
        result.block("agent_contract_disabled", "specbound.yaml", str(exc))
        return result
    return validate_agent_role_skills(root, policy_path)


def validate_configured_role_request(
    root: Path,
    request_path: Path,
    reference_result_files: list[str] | None = None,
) -> AgentContractResult:
    try:
        policy_path = configured_agent_policy_path(root)
    except ValueError as exc:
        result = AgentContractResult()
        result.block("agent_contract_disabled", "specbound.yaml", str(exc))
        return result
    return validate_role_request(
        root,
        request_path,
        policy_path,
        reference_result_files=reference_result_files,
    )


def validate_configured_agent_result(
    root: Path,
    result_path: Path,
    reference_result_files: list[str] | None = None,
) -> AgentContractResult:
    try:
        policy_path = configured_agent_policy_path(root)
    except ValueError as exc:
        result = AgentContractResult()
        result.block("agent_contract_disabled", "specbound.yaml", str(exc))
        return result
    return validate_agent_result(
        root,
        result_path,
        policy_path,
        reference_result_files=reference_result_files,
    )
