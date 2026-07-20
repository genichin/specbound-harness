from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "specbound.cli", *args],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        check=False,
        capture_output=True,
        text=True,
    )


def payload(result: subprocess.CompletedProcess[str]) -> dict:
    return json.loads(result.stdout)


def test_context_discovers_fixture_root() -> None:
    result = run_cli("--root", str(FIXTURES / "valid-minimal"), "context")

    assert result.returncode == 0, result.stderr
    body = payload(result)
    assert body["requirements_root"] == "docs/requirements"
    assert body["discoveries_root"] == "docs/discoveries"
    assert body["discovery_confirmations_root"] == ".specbound/discovery-confirmations"


def test_preflight_accepts_bootstrap_config() -> None:
    result = run_cli("--root", str(FIXTURES / "valid-minimal"), "preflight")

    assert result.returncode == 0, result.stdout
    assert payload(result)["valid"] is True


def test_validate_accepts_exact_approved_requirement_binding() -> None:
    result = run_cli("--root", str(FIXTURES / "valid-minimal"), "validate")

    assert result.returncode == 0, result.stdout
    body = payload(result)
    assert body["valid"] is True
    assert body["approved_requirements"] == 1


def test_validate_accepts_exact_discovery_confirmation_binding() -> None:
    result = run_cli("--root", str(FIXTURES / "valid-minimal"), "validate")

    assert result.returncode == 0, result.stdout
    body = payload(result)
    assert body["checked_discoveries"] == 1
    assert body["confirmed_discoveries"] == 1


def test_discovery_template_matches_confirmation_contract() -> None:
    template = (ROOT / "templates/discovery.md").read_text(encoding="utf-8")

    assert "risk_class: <repository-defined risk classification>" in template
    assert "docs/discoveries/dcy-<id>/disc-<id>-r<revision>.md" in template
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
    ):
        assert heading in template


def test_validate_rejects_unsafe_approval_path() -> None:
    result = run_cli("--root", str(FIXTURES / "invalid-unsafe-path"), "validate")

    assert result.returncode == 2
    assert "unsafe_artifact_path" in {item["code"] for item in payload(result)["blockers"]}


def test_preflight_rejects_non_string_approval_field_config(tmp_path: Path) -> None:
    fixture = tmp_path / "malformed-config"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    (fixture / "specbound.yaml").write_text(
        (fixture / "specbound.yaml").read_text(encoding="utf-8").replace("    - requirement_path", "    - {}"),
        encoding="utf-8",
    )

    result = run_cli("--root", str(fixture), "preflight")

    assert result.returncode == 2
    assert "malformed_config" in {item["code"] for item in payload(result)["blockers"]}


def test_preflight_rejects_uppercase_requirement_pattern(tmp_path: Path) -> None:
    fixture = tmp_path / "uppercase-pattern"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    config = fixture / "specbound.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "req-<id>/req-<id>-r<revision>.md", "REQ-<id>/REQ-<id>-r<revision>.md"
        ),
        encoding="utf-8",
    )

    result = run_cli("--root", str(fixture), "preflight")

    assert result.returncode == 2
    assert "malformed_config" in {item["code"] for item in payload(result)["blockers"]}


def test_preflight_rejects_wrong_discovery_pattern(tmp_path: Path) -> None:
    fixture = tmp_path / "wrong-discovery-pattern"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    config = fixture / "specbound.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "dcy-<id>/disc-<id>-r<revision>.md", "disc-<id>/disc-<id>-r<revision>.md"
        ),
        encoding="utf-8",
    )

    result = run_cli("--root", str(fixture), "preflight")

    assert result.returncode == 2
    assert "malformed_config" in {item["code"] for item in payload(result)["blockers"]}


def test_preflight_requires_discovery_confirmer_allowlist(tmp_path: Path) -> None:
    fixture = tmp_path / "missing-discovery-confirmer-allowlist"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    config = fixture / "specbound.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "  discovery_confirmation_authorities_by_risk:\n    low:\n      - fixture-maintainer\n", ""
        ),
        encoding="utf-8",
    )

    result = run_cli("--root", str(fixture), "preflight")

    assert result.returncode == 2
    assert "malformed_config" in {item["code"] for item in payload(result)["blockers"]}


def test_validate_rejects_symlinked_approval_record(tmp_path: Path) -> None:
    fixture = tmp_path / "symlinked-approval"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    approval = fixture / ".specbound/approvals/req-0001-r1.approval.json"
    outside = tmp_path / "outside-approval.json"
    outside.write_text(approval.read_text(encoding="utf-8"), encoding="utf-8")
    approval.unlink()
    try:
        approval.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink not available: {exc}")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    assert "unsafe_artifact_path" in {item["code"] for item in payload(result)["blockers"]}


def test_validate_rejects_digest_mismatch(tmp_path: Path) -> None:
    fixture = tmp_path / "digest-mismatch"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    requirement = fixture / "docs/requirements/req-0001/req-0001-r1.md"
    requirement.write_text(requirement.read_text(encoding="utf-8") + "\nChanged after approval.\n", encoding="utf-8")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    assert "requirement_digest_mismatch" in {item["code"] for item in payload(result)["blockers"]}


def test_validate_rejects_discovery_confirmation_digest_mismatch(tmp_path: Path) -> None:
    fixture = tmp_path / "discovery-digest-mismatch"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    discovery = fixture / "docs/discoveries/dcy-0001/disc-0001-r1.md"
    discovery.write_text(discovery.read_text(encoding="utf-8") + "\nChanged after confirmation.\n", encoding="utf-8")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    report = payload(result)
    assert "discovery_digest_mismatch" in {item["code"] for item in report["blockers"]}
    assert report["confirmed_discoveries"] == 0


def test_validate_rejects_excessive_discovery_authorization(tmp_path: Path) -> None:
    fixture = tmp_path / "excessive-discovery-authorization"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    confirmation_path = fixture / ".specbound/discovery-confirmations/disc-0001-r1.confirmation.json"
    confirmation = json.loads(confirmation_path.read_text(encoding="utf-8"))
    confirmation["permitted_next_action"] = "implementation"
    confirmation_path.write_text(json.dumps(confirmation), encoding="utf-8")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    assert "excessive_discovery_authorization" in {item["code"] for item in payload(result)["blockers"]}


def test_validate_rejects_unallowlisted_discovery_confirmer(tmp_path: Path) -> None:
    fixture = tmp_path / "unallowlisted-discovery-confirmer"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    confirmation_path = fixture / ".specbound/discovery-confirmations/disc-0001-r1.confirmation.json"
    confirmation = json.loads(confirmation_path.read_text(encoding="utf-8"))
    confirmation["authority"] = "untrusted-actor"
    confirmation_path.write_text(json.dumps(confirmation), encoding="utf-8")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    assert "invalid_discovery_confirmation_authority" in {item["code"] for item in payload(result)["blockers"]}


def test_validate_rejects_missing_discovery_schema_version(tmp_path: Path) -> None:
    fixture = tmp_path / "missing-discovery-schema-version"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    confirmation_path = fixture / ".specbound/discovery-confirmations/disc-0001-r1.confirmation.json"
    confirmation = json.loads(confirmation_path.read_text(encoding="utf-8"))
    del confirmation["schema_version"]
    confirmation_path.write_text(json.dumps(confirmation), encoding="utf-8")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    assert "malformed_discovery_confirmation" in {item["code"] for item in payload(result)["blockers"]}


def test_validate_rejects_symlinked_requirement_record(tmp_path: Path) -> None:
    fixture = tmp_path / "symlinked-requirement"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    requirement = fixture / "docs/requirements/req-0001/req-0001-r1.md"
    outside = tmp_path / "outside-requirement.md"
    requirement.rename(outside)
    try:
        requirement.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink not available: {exc}")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    assert "unsafe_artifact_path" in {item["code"] for item in payload(result)["blockers"]}


@pytest.mark.parametrize("link_path", ["docs", ".specbound/approvals"])
def test_validate_rejects_symlinked_intermediate_directory(tmp_path: Path, link_path: str) -> None:
    fixture = tmp_path / "intermediate-symlink"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    linked = fixture / link_path
    outside = tmp_path / f"outside-{link_path.replace('/', '-') }"
    linked.rename(outside)
    try:
        linked.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink not available: {exc}")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    assert "unsafe_artifact_path" in {item["code"] for item in payload(result)["blockers"]}


def test_validate_rejects_symlinked_discovery_directory(tmp_path: Path) -> None:
    fixture = tmp_path / "symlinked-discovery"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    directory = fixture / "docs/discoveries/dcy-0001"
    outside = tmp_path / "outside-discovery"
    directory.rename(outside)
    try:
        directory.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink not available: {exc}")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    assert "unsafe_artifact_path" in {item["code"] for item in payload(result)["blockers"]}
