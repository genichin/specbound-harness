from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "valid-minimal"


def run_cli(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "specbound.cli", "--root", str(root), *args],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        check=False,
        capture_output=True,
        text=True,
    )


def body(result: subprocess.CompletedProcess[str]) -> dict:
    return json.loads(result.stdout)


def copied_fixture(tmp_path: Path) -> Path:
    destination = tmp_path / "repo"
    shutil.copytree(FIXTURE, destination)
    return destination


def test_ci_installed_wheel_gate_covers_control_plane_adoption_contract() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "fetch-depth: 0" in workflow
    for schema_name in (
        "adoption-decision.schema.json",
        "canary-outcome.schema.json",
        "activation-decision.schema.json",
    ):
        assert schema_name in workflow
    assert "import specbound.control_plane_adoption as control_plane_adoption" in workflow
    assert '\"$WHEEL_CLI\" --root \"$GITHUB_WORKSPACE\" adoption list' in workflow
    assert '\"$WHEEL_CLI\" --root \"$GITHUB_WORKSPACE\" adoption check' in workflow
    assert '\"$GITHUB_WORKSPACE/tests/test_control_plane_adoption.py\"' in workflow
    assert "Draft202012Validator" in workflow
    assert 'repository / "templates"' in workflow
    for schema_name in (
        "iteration-qc.schema.json",
        "iteration-qc-implementation-result.schema.json",
        "iteration-qc-evaluation-result.schema.json",
    ):
        assert schema_name in workflow
    assert "import specbound.iteration_qc as iteration_qc" in workflow
    assert 'iteration-qc --help' in workflow
    assert 'tests/test_iteration_qc.py' in workflow
    assert workflow.index('cd "$RUNNER_TEMP"') < workflow.index(
        '\"$WHEEL_CLI\" --root \"$GITHUB_WORKSPACE\" adoption list'
    )


def valid_micro_spec(root: Path, target: str = "ms-0001-003") -> str:
    digest = sha256((root / ".specbound/requirements/req-0001/req-0001-r1.md").read_bytes()).hexdigest()
    return f"""---
schema_version: 1
id: {target}
kind: micro-spec
requirement:
  path: .specbound/requirements/req-0001/req-0001-r1.md
  id: req-0001
  revision: 1
  sha256: {digest}
selected_acceptance_criteria: [AC-001]
---

# {target}

## Objective

Bind one approved parent REQ.

## Scope

Validate this bounded planning record.

## Non-goals

Do not issue approval or QC evidence.

## Baseline

AC-001 validates the parent approval binding.

## Verification plan

Run the focused validator tests.

## QC exit rule

All focused checks must pass.
"""


def valid_iteration_qc(root: Path) -> str:
    micro = root / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    digest = sha256(micro.read_bytes()).hexdigest()
    return json.dumps(
        {
            "schema_version": 1,
            "micro_spec": {
                "path": ".specbound/micro-specs/req-0001/ms-0001-003.md",
                "id": "ms-0001-003",
                "sha256": digest,
            },
            "selected_acceptance_criteria": ["AC-001"],
            "verification": [
                {
                    "command": ".venv/bin/python -m pytest -q tests/test_artifact_topology.py",
                    "result": "passed",
                    "exit_code": 0,
                }
            ],
            "verdict": "verified",
            "remaining_acceptance_criteria": [],
        },
        indent=2,
    ) + "\n"


def valid_delivery_qc(root: Path) -> str:
    requirement = root / ".specbound/requirements/req-0001/req-0001-r1.md"
    iteration = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"
    return json.dumps(
        {
            "schema_version": 1,
            "requirement": {
                "path": ".specbound/requirements/req-0001/req-0001-r1.md",
                "id": "req-0001",
                "revision": 1,
                "sha256": sha256(requirement.read_bytes()).hexdigest(),
            },
            "coverage": [
                {
                    "acceptance_criterion": "AC-001",
                    "iteration_qc": {
                        "path": ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json",
                        "sha256": sha256(iteration.read_bytes()).hexdigest(),
                    },
                }
            ],
            "regression_evidence": [
                {
                    "command": ".venv/bin/python -m pytest -q",
                    "result": "passed",
                    "exit_code": 0,
                }
            ],
            "authority": "fixture-maintainer",
            "residual_risk": {
                "unresolved_exceptions": [],
                "disposition": "No unresolved exceptions; evidence awaits a separately authorized delivery decision.",
            },
            "verdict": "verified",
        },
        indent=2,
    ) + "\n"


def write_valid_family_set(root: Path) -> None:
    micro = root / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    iteration = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"
    delivery = root / ".specbound/delivery-qc/dqc-0001-r1.json"
    micro.parent.mkdir(parents=True)
    iteration.parent.mkdir(parents=True)
    micro.write_text(valid_micro_spec(root), encoding="utf-8")
    iteration.write_text(valid_iteration_qc(root), encoding="utf-8")
    delivery.write_text(valid_delivery_qc(root), encoding="utf-8")


def write_legacy_adoption_registry(root: Path, digest: str | None = None) -> None:
    requirement = root / ".specbound/requirements/req-0001/req-0001-r1.md"
    exact_digest = digest or sha256(requirement.read_bytes()).hexdigest()
    config = root / "specbound.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "policy:\n",
            "policy:\n"
            "  control_plane_adoption:\n"
            "    schema_version: 1\n"
            "    requirements:\n"
            "      - path: .specbound/requirements/req-0001/req-0001-r1.md\n"
            "        id: req-0001\n"
            "        revision: 1\n"
            f"        sha256: {exact_digest}",
        ),
        encoding="utf-8",
    )


def test_validate_accepts_version_one_artifact_families(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    write_valid_family_set(root)

    result = run_cli(root, "validate")

    assert result.returncode == 0, result.stdout
    payload = body(result)
    assert payload["checked_micro_specs"] == 1
    assert payload["checked_iteration_qc"] == 1
    assert payload["checked_delivery_qc"] == 1


def test_real_cli_accepts_unscoped_evidence_but_rejects_unactivated_claims(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    write_valid_family_set(root)

    # The minimal copied REQ deliberately has one AC. Delivery-QC must cover
    # every AC in that isolated parent, while separate tests cover invalid
    # multi-record and claim-boundary variants.
    for path in (
        root / ".specbound/micro-specs/req-0001/ms-0001-003.md",
        root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json",
        root / ".specbound/delivery-qc/dqc-0001-r1.json",
    ):
        assert path.is_file()

    preflight = run_cli(root, "preflight")
    root_validation = run_cli(root, "validate")
    iteration_claim = run_cli(root, "validate", "--claim", "iteration", "--requirement", "req-0001-r1")
    delivery_claim = run_cli(root, "validate", "--claim", "delivery", "--requirement", "req-0001-r1")

    for result in (preflight, root_validation):
        assert result.returncode == 0, result.stdout
        assert body(result)["valid"] is True
    for result in (iteration_claim, delivery_claim):
        assert result.returncode == 2, result.stdout
        assert "control_plane_not_adopted" in {
            blocker["code"] for blocker in body(result)["blockers"]
        }

    payload = body(root_validation)
    assert payload["checked_micro_specs"] == 1
    assert payload["checked_iteration_qc"] == 1
    assert payload["checked_delivery_qc"] == 1


@pytest.mark.parametrize(
    ("relative", "content", "code"),
    [
        (".specbound/micro-specs/req-0007/ms-0008-003.md", "---\nschema_version: 1\n---\n", "micro_spec_binding_mismatch"),
        (".specbound/micro-specs/req-0007/ms-0007-0.md", "---\nschema_version: 1\n---\n", "invalid_micro_spec_path"),
        (".specbound/iteration-qc/req-0007/iqc-0008-003-r2.json", '{"schema_version": 1}', "iteration_qc_binding_mismatch"),
        (".specbound/iteration-qc/req-0007/iqc-0007-003-r0.json", '{"schema_version": 1}', "invalid_iteration_qc_path"),
        (".specbound/delivery-qc/nested/dqc-0007-r2.json", '{"schema_version": 1}', "invalid_delivery_qc_path"),
        (".specbound/delivery-qc/dqc-0007-r2.json", '{"schema_version": 2}', "malformed_delivery_qc"),
        (".specbound/iteration-qc/req-0007/iqc-0007-003-r2.json", "{broken", "malformed_iteration_qc"),
        (".specbound/micro-specs/req-0007/ms-0007-003.md", "---\nschema_version: 2\n---\n", "malformed_micro_spec"),
    ],
)
def test_validate_rejects_noncanonical_or_malformed_version_one_artifacts(
    tmp_path: Path, relative: str, content: str, code: str
) -> None:
    root = copied_fixture(tmp_path)
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

    result = run_cli(root, "validate")

    assert result.returncode == 2, result.stdout
    assert code in {blocker["code"] for blocker in body(result)["blockers"]}


@pytest.mark.parametrize(
    ("replacement", "code"),
    [
        ("id: ms-0001-003", "micro_spec_binding_mismatch"),
        ("path: .specbound/requirements/req-0001/req-0001-r1.md", "micro_spec_binding_mismatch"),
        ("sha256: ", "micro_spec_digest_mismatch"),
        ("selected_acceptance_criteria: [AC-999]", "invalid_selected_acceptance_criteria"),
        ("selected_acceptance_criteria: [AC-001, AC-001]", "invalid_selected_acceptance_criteria"),
        ("## QC exit rule\n\nAll focused checks must pass.", "incomplete_micro_spec_plan"),
    ],
)
def test_validate_rejects_invalid_micro_spec_parent_ac_or_plan(
    tmp_path: Path, replacement: str, code: str
) -> None:
    root = copied_fixture(tmp_path)
    path = root / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    path.parent.mkdir(parents=True)
    content = valid_micro_spec(root)
    if code == "micro_spec_binding_mismatch":
        if replacement.startswith("id:"):
            content = content.replace(replacement, "id: ms-0001-004")
        else:
            content = content.replace(replacement, "path: .specbound/requirements/req-0001/req-0001-r2.md")
    elif code == "micro_spec_digest_mismatch":
        digest = sha256((root / ".specbound/requirements/req-0001/req-0001-r1.md").read_bytes()).hexdigest()
        content = content.replace(f"sha256: {digest}", "sha256: '" + "0" * 64 + "'")
    elif code == "incomplete_micro_spec_plan":
        content = content.replace(replacement, "")
    else:
        content = content.replace("selected_acceptance_criteria: [AC-001]", replacement)
    path.write_text(content, encoding="utf-8")

    result = run_cli(root, "validate")

    assert result.returncode == 2, result.stdout
    assert code in {blocker["code"] for blocker in body(result)["blockers"]}


def test_validate_rejects_unapproved_micro_spec_parent(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    path = root / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    path.parent.mkdir(parents=True)
    path.write_text(valid_micro_spec(root), encoding="utf-8")
    requirement = root / ".specbound/requirements/req-0001/req-0001-r1.md"
    requirement.write_text(requirement.read_text(encoding="utf-8").replace("status: approved", "status: in_review"), encoding="utf-8")

    result = run_cli(root, "validate")

    assert result.returncode == 2, result.stdout
    assert "unapproved_micro_spec_parent" in {blocker["code"] for blocker in body(result)["blockers"]}


def test_validate_requires_rollback_for_high_risk_micro_spec_parent(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    path = root / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    path.parent.mkdir(parents=True)
    path.write_text(valid_micro_spec(root), encoding="utf-8")
    requirement = root / ".specbound/requirements/req-0001/req-0001-r1.md"
    requirement.write_text(requirement.read_text(encoding="utf-8").replace("risk: low", "risk: high"), encoding="utf-8")

    result = run_cli(root, "validate")

    assert result.returncode == 2, result.stdout
    assert "incomplete_micro_spec_plan" in {blocker["code"] for blocker in body(result)["blockers"]}


def test_validate_rejects_duplicate_micro_spec_target(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    first = root / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    second = root / ".specbound/micro-specs/req-0001/ms-0001-004.md"
    first.parent.mkdir(parents=True)
    first.write_text(valid_micro_spec(root), encoding="utf-8")
    second.write_text(valid_micro_spec(root), encoding="utf-8")

    result = run_cli(root, "validate")

    assert result.returncode == 2, result.stdout
    assert "duplicate_micro_spec_target" in {blocker["code"] for blocker in body(result)["blockers"]}


def test_preflight_rejects_wrong_iteration_qc_contract(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    config = root / "specbound.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace("iteration_qc_root: .specbound/iteration-qc", "iteration_qc_root: /tmp/qc"),
        encoding="utf-8",
    )

    result = run_cli(root, "preflight")

    assert result.returncode == 2
    assert "malformed_config" in {blocker["code"] for blocker in body(result)["blockers"]}


def test_validate_rejects_symlinked_iteration_qc_path(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    external = tmp_path / "external"
    external.mkdir()
    (external / "iqc-0007-003-r2.json").write_text('{"schema_version": 1}\n', encoding="utf-8")
    link = root / ".specbound/iteration-qc/req-0007"
    link.symlink_to(external, target_is_directory=True)

    result = run_cli(root, "validate")

    assert result.returncode == 2, result.stdout
    assert "unsafe_artifact_path" in {blocker["code"] for blocker in body(result)["blockers"]}


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda record: record["micro_spec"].update(sha256="0" * 64), "iteration_qc_micro_spec_digest_mismatch"),
        (lambda record: record.update(selected_acceptance_criteria=["AC-999"]), "iteration_qc_ac_set_mismatch"),
        (lambda record: record.update(verification=[]), "malformed_iteration_qc_evidence"),
        (lambda record: record["verification"][0].update(result="failed"), "invalid_iteration_qc_verdict"),
        (lambda record: record.update(remaining_acceptance_criteria=["AC-001"]), "iteration_qc_remaining_ac_mismatch"),
    ],
)
def test_validate_rejects_invalid_iteration_qc_evidence(tmp_path: Path, mutate, code: str) -> None:
    root = copied_fixture(tmp_path)
    write_valid_family_set(root)
    path = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    mutate(record)
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

    result = run_cli(root, "validate")

    assert result.returncode == 2, result.stdout
    assert code in {blocker["code"] for blocker in body(result)["blockers"]}


def test_validate_rejects_iteration_qc_with_missing_or_mismatched_micro_spec(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    write_valid_family_set(root)
    path = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    record["micro_spec"]["path"] = ".specbound/micro-specs/req-0001/ms-0001-004.md"
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

    result = run_cli(root, "validate")

    assert result.returncode == 2, result.stdout
    assert "iteration_qc_micro_spec_mismatch" in {blocker["code"] for blocker in body(result)["blockers"]}



def test_validate_rejects_delivery_qc_authority_claim_field(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    write_valid_family_set(root)
    path = root / ".specbound/delivery-qc/dqc-0001-r1.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    record["authorized_next_action"] = "merge"
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

    result = run_cli(root, "validate")

    assert result.returncode == 2, result.stdout
    assert "malformed_delivery_qc" in {blocker["code"] for blocker in body(result)["blockers"]}


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda record: record["requirement"].update(sha256="0" * 64), "delivery_qc_requirement_digest_mismatch"),
        (lambda record: record.update(coverage=[]), "delivery_qc_ac_coverage_mismatch"),
        (lambda record: record["coverage"][0].update(acceptance_criterion="AC-999"), "delivery_qc_ac_coverage_mismatch"),
        (lambda record: record["coverage"][0]["iteration_qc"].update(path=".specbound/iteration-qc/req-0007/iqc-0007-003-r1.json"), "delivery_qc_ac_coverage_mismatch"),
        (lambda record: record.update(regression_evidence=[]), "malformed_delivery_qc_regression_evidence"),
        (lambda record: record.update(authority="untrusted-reviewer"), "invalid_delivery_qc_authority"),
        (lambda record: record["residual_risk"].update(unresolved_exceptions=["Open security exception"]), "invalid_delivery_qc_verdict"),
    ],
)
def test_validate_rejects_invalid_delivery_qc_aggregation(tmp_path: Path, mutate, code: str) -> None:
    root = copied_fixture(tmp_path)
    write_valid_family_set(root)
    path = root / ".specbound/delivery-qc/dqc-0001-r1.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    mutate(record)
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

    result = run_cli(root, "validate")

    assert result.returncode == 2, result.stdout
    assert code in {blocker["code"] for blocker in body(result)["blockers"]}


def test_validate_rejects_delivery_qc_nonverified_iteration(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    write_valid_family_set(root)
    iteration = root / ".specbound/iteration-qc/req-0001/iqc-0001-003-r1.json"
    iteration_record = json.loads(iteration.read_text(encoding="utf-8"))
    iteration_record["verdict"] = "rework"
    iteration.write_text(json.dumps(iteration_record, indent=2) + "\n", encoding="utf-8")

    result = run_cli(root, "validate")

    assert result.returncode == 2, result.stdout
    assert "delivery_qc_ac_coverage_mismatch" in {blocker["code"] for blocker in body(result)["blockers"]}


def test_manual_bootstrap_micro_spec_is_not_relabelled_as_canonical(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    path = root / ".specbound/micro-specs/req-0007/ms-0007-003.md"
    path.parent.mkdir(parents=True)
    path.write_text("---\nkind: manual-bootstrap-micro-spec\n---\n", encoding="utf-8")

    result = run_cli(root, "validate")

    assert result.returncode == 0, result.stdout
    assert body(result)["checked_micro_specs"] == 0


def test_pre_adoption_root_validation_does_not_require_canonical_qc(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)

    result = run_cli(root, "validate")

    assert result.returncode == 0, result.stdout


def test_claim_requires_explicit_adoption(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)

    result = run_cli(root, "validate", "--claim", "iteration", "--requirement", "req-0001-r1")

    assert result.returncode == 2, result.stdout
    assert "control_plane_not_adopted" in {blocker["code"] for blocker in body(result)["blockers"]}


def test_nonempty_legacy_adoption_registry_is_rejected(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    write_legacy_adoption_registry(root)

    result = run_cli(root, "validate")

    assert result.returncode == 2, result.stdout
    assert "malformed_config" in {blocker["code"] for blocker in body(result)["blockers"]}


def test_iteration_claim_remains_blocked_without_effective_activation(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)

    missing = run_cli(root, "validate", "--claim", "iteration", "--requirement", "req-0001-r1")
    assert missing.returncode == 2, missing.stdout
    assert "control_plane_not_adopted" in {blocker["code"] for blocker in body(missing)["blockers"]}

    write_valid_family_set(root)
    verified = run_cli(root, "validate", "--claim", "iteration", "--requirement", "req-0001-r1")
    assert verified.returncode == 2, verified.stdout
    assert "control_plane_not_adopted" in {blocker["code"] for blocker in body(verified)["blockers"]}


def test_delivery_claim_remains_blocked_without_effective_activation(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    write_valid_family_set(root)
    (root / ".specbound/delivery-qc/dqc-0001-r1.json").unlink()

    missing = run_cli(root, "validate", "--claim", "delivery", "--requirement", "req-0001-r1")
    assert missing.returncode == 2, missing.stdout
    assert "control_plane_not_adopted" in {blocker["code"] for blocker in body(missing)["blockers"]}

    delivery = root / ".specbound/delivery-qc/dqc-0001-r1.json"
    delivery.write_text(valid_delivery_qc(root), encoding="utf-8")
    verified = run_cli(root, "validate", "--claim", "delivery", "--requirement", "req-0001-r1")
    assert verified.returncode == 2, verified.stdout
    assert "control_plane_not_adopted" in {blocker["code"] for blocker in body(verified)["blockers"]}


def test_manual_bootstrap_micro_spec_does_not_activate_iteration_claim(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    path = root / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    path.parent.mkdir(parents=True)
    path.write_text("---\nkind: manual-bootstrap-micro-spec\n---\n", encoding="utf-8")

    result = run_cli(root, "validate", "--claim", "iteration", "--requirement", "req-0001-r1")

    assert result.returncode == 2, result.stdout
    assert "control_plane_not_adopted" in {blocker["code"] for blocker in body(result)["blockers"]}


def test_validate_rejects_nonempty_legacy_adoption_snapshot(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    write_legacy_adoption_registry(root, digest="a" * 64)

    result = run_cli(root, "validate")

    assert result.returncode == 2, result.stdout
    assert "malformed_config" in {blocker["code"] for blocker in body(result)["blockers"]}


def test_preflight_rejects_unknown_adoption_schema_version(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    config = root / "specbound.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "policy:\n",
            "policy:\n"
            "  control_plane_adoption:\n"
            "    schema_version: 2\n"
            "    requirements: []\n",
        ),
        encoding="utf-8",
    )

    result = run_cli(root, "preflight")

    assert result.returncode == 2, result.stdout
    assert "malformed_config" in {blocker["code"] for blocker in body(result)["blockers"]}


def test_requirements_root_migration_manifest_binds_current_artifacts() -> None:
    manifest = json.loads(
        (ROOT / ".specbound/migrations/requirements-root-v1.json").read_text(encoding="utf-8")
    )

    assert manifest["kind"] == "repository_format_migration"
    assert manifest["source_root"] == "docs/requirements"
    assert manifest["target_root"] == ".specbound/requirements"
    after_paths: set[str] = set()
    for transformation in manifest["transformations"]:
        assert transformation["after_path"] not in after_paths
        after_paths.add(transformation["after_path"])
        assert len(transformation["before_sha256"]) == 64
        path = ROOT / transformation["after_path"]
        assert path.is_file(), transformation["after_path"]
        assert sha256(path.read_bytes()).hexdigest() == transformation["after_sha256"]
