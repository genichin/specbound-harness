from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
import pytest
import yaml

from specbound import validation


ROOT = Path(__file__).resolve().parents[1]
TOPOLOGY_CONFIGS = (
    ROOT / "specbound.yaml",
    ROOT / "templates/specbound.yaml",
    ROOT / "fixtures/valid-minimal/specbound.yaml",
    ROOT / "fixtures/invalid-unsafe-path/specbound.yaml",
)
ALIAS_CONFIGS = TOPOLOGY_CONFIGS + (ROOT / "fixtures/agent-contract/specbound.yaml",)

EXPECTED_CONTROL_PLANE_TOPOLOGY = {
    "adoptions_root": ".specbound/adoptions",
    "canary_outcomes_root": ".specbound/canary-outcomes",
    "activations_root": ".specbound/activations",
}
EXPECTED_CONTROL_PLANE_PATTERNS = {
    "adoption_pattern": "req-<id>/adp-<id>-r<revision>-<transition>.json",
    "canary_outcome_pattern": "req-<id>/cny-<id>-r<revision>-<transition>-a<sequence>.json",
    "activation_pattern": "req-<id>/act-<id>-r<revision>-<transition>.json",
}
EXPECTED_ALIAS = {"inherit": "discovery_confirmation_authorities_by_risk"}


def _schema(name: str) -> dict:
    root_path = ROOT / "schemas" / name
    packaged_path = ROOT / "src/specbound/schemas" / name
    assert root_path.read_bytes() == packaged_path.read_bytes()
    schema = json.loads(root_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return schema


def _config(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_control_plane_topology_and_aliases_are_declared_without_manual_registry() -> None:
    for key, value in EXPECTED_CONTROL_PLANE_TOPOLOGY.items():
        assert validation.REQUIRED_ROOTS[key] == value

    for name, value in EXPECTED_CONTROL_PLANE_PATTERNS.items():
        assert getattr(validation, name.upper()) == value

    for path in TOPOLOGY_CONFIGS:
        config = _config(path)
        canonical = config["canonical"]
        for key, value in EXPECTED_CONTROL_PLANE_TOPOLOGY.items():
            assert canonical[key] == value, path
        for key, value in EXPECTED_CONTROL_PLANE_PATTERNS.items():
            assert canonical[key] == value, path

    for path in ALIAS_CONFIGS:
        policy = _config(path)["policy"]
        assert policy["control_plane_adoption_authorities_by_risk"] == EXPECTED_ALIAS, path
        assert policy["control_plane_activation_authorities_by_risk"] == EXPECTED_ALIAS, path
        assert "control_plane_adoption" not in policy, path


def test_preflight_accepts_only_exact_inherit_aliases_and_empty_legacy_shape(tmp_path: Path) -> None:
    base = _config(ROOT / "templates/specbound.yaml")

    def run(config: dict) -> validation.Result:
        root = tmp_path / str(len(list(tmp_path.iterdir())))
        root.mkdir()
        (root / "specbound.yaml").write_text(
            yaml.safe_dump(config, sort_keys=False), encoding="utf-8", newline="\n"
        )
        return validation.preflight(root)

    assert run(base).valid

    legacy = deepcopy(base)
    legacy["policy"]["control_plane_adoption"] = {"schema_version": 1, "requirements": []}
    assert run(legacy).valid

    for key in (
        "control_plane_adoption_authorities_by_risk",
        "control_plane_activation_authorities_by_risk",
    ):
        missing = deepcopy(base)
        del missing["policy"][key]
        assert {item["code"] for item in run(missing).blockers} == {"malformed_config"}

        widened = deepcopy(base)
        widened["policy"][key] = {
            "inherit": "discovery_confirmation_authorities_by_risk",
            "fallback": ["fixture-maintainer"],
        }
        assert {item["code"] for item in run(widened).blockers} == {"malformed_config"}

        explicit = deepcopy(base)
        explicit["policy"][key] = {"low": ["repository-maintainer"]}
        assert {item["code"] for item in run(explicit).blockers} == {"malformed_config"}

    nonempty = deepcopy(base)
    nonempty["policy"]["control_plane_adoption"] = {
        "schema_version": 1,
        "requirements": [
            {
                "path": ".specbound/requirements/req-1/req-1-r1.md",
                "id": "req-1",
                "revision": 1,
                "sha256": "0" * 64,
            }
        ],
    }
    assert {item["code"] for item in run(nonempty).blockers} == {"malformed_config"}

    extra = deepcopy(base)
    extra["policy"]["control_plane_adoption"] = {
        "schema_version": 1,
        "requirements": [],
        "generated": True,
    }
    assert {item["code"] for item in run(extra).blockers} == {"malformed_config"}


def test_adoption_schema_is_closed_and_binds_exact_canary_authority() -> None:
    schema = _schema("adoption-decision.schema.json")
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        "schema_version",
        "adoption_id",
        "requirement",
        "scope_mode",
        "transition",
        "risk",
        "authority",
        "authority_action_id",
        "context_id",
        "decision",
        "reason",
        "decided_at",
        "permitted_next_action",
        "adoption_source_commit",
        "canary_capability_baseline_commit",
        "canary_capability_baseline_at",
        "canary_work_state",
        "canary_work_attested_by",
        "canary_work_attested_at",
        "canary_work_source_refs",
        "authority_policy",
    }
    properties = schema["properties"]
    assert properties["scope_mode"] == {"const": "exact_canary"}
    assert properties["transition"]["enum"] == ["iteration_qc", "delivery_qc"]
    assert properties["decision"] == {"const": "adopted_for_exact_canary"}
    assert properties["permitted_next_action"] == {
        "const": "approve_bootstrap_exception_for_exact_canary"
    }
    assert properties["canary_work_state"] == {"const": "not_started"}
    assert properties["reason"]["minLength"] >= 1


def test_canary_outcome_schema_is_closed_and_non_authorizing() -> None:
    schema = _schema("canary-outcome.schema.json")
    assert schema["additionalProperties"] is False
    properties = schema["properties"]
    required = set(schema["required"])
    assert properties["scope_mode"] == {"const": "exact_canary"}
    assert properties["transition"]["enum"] == ["iteration_qc", "delivery_qc"]
    assert properties["outcome"]["enum"] == ["passed", "failed"]
    assert properties["attempt_sequence"]["minimum"] == 1
    assert {"authority", "authority_action_id", "context_id", "bootstrap_exception"} <= required
    assert "pre_close_commit" in properties["bootstrap_exception"]["required"]
    assert {"reason", "decision", "permitted_next_action", "passed_outcome_commit"}.isdisjoint(
        properties
    )


def test_activation_schema_is_closed_and_prospective_only() -> None:
    schema = _schema("activation-decision.schema.json")
    assert schema["additionalProperties"] is False
    properties = schema["properties"]
    required = set(schema["required"])
    assert properties["scope_mode"] == {"const": "prospective_after_baseline"}
    assert properties["transition"]["enum"] == ["iteration_qc", "delivery_qc"]
    assert properties["decision"] == {"const": "activated_for_prospective_scope"}
    assert {
        "adoption",
        "canary_outcome",
        "passed_outcome_commit",
        "prospective_baseline_commit",
        "prospective_baseline_at",
        "authority",
        "authority_action_id",
        "context_id",
        "authority_policy",
    } <= required
    assert {"reason", "permitted_next_action"}.isdisjoint(properties)


def test_control_plane_canonical_roots_have_tracked_placeholders() -> None:
    roots = (
        ROOT,
        ROOT / "fixtures/valid-minimal",
        ROOT / "fixtures/agent-contract",
        ROOT / "fixtures/invalid-unsafe-path",
    )
    for root in roots:
        for relative in (
            ".specbound/adoptions/.gitkeep",
            ".specbound/canary-outcomes/.gitkeep",
            ".specbound/activations/.gitkeep",
        ):
            marker = root / relative
            assert marker.is_file(), marker
            assert marker.read_bytes() == b""


@pytest.mark.parametrize(
    ("schema_name", "template_name"),
    (
        ("adoption-decision.schema.json", "adoption-decision.json"),
        ("canary-outcome.schema.json", "canary-outcome.json"),
        ("activation-decision.schema.json", "activation-decision.json"),
    ),
)
def test_record_templates_are_canonical_closed_schema_instances(
    schema_name: str, template_name: str
) -> None:
    schema = _schema(schema_name)
    path = ROOT / "templates" / template_name
    record = json.loads(path.read_text(encoding="utf-8"))
    canonical = (
        json.dumps(record, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    assert path.read_bytes() == canonical
    Draft202012Validator(schema).validate(record)

    widened = deepcopy(record)
    widened["unexpected"] = True
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(widened)


def test_root_validate_does_not_require_the_removed_manual_registry() -> None:
    result = validation.validate(ROOT)
    assert result.valid, result.blockers
