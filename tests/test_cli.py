from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

import specbound.validation as validation
from specbound.validation import (
    RequirementDraftError,
    RequirementReviewSubmissionError,
    create_requirement_draft,
    submit_requirement_for_review,
)

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
    assert body["requirements_root"] == ".specbound/requirements"
    assert body["discoveries_root"] == ".specbound/discoveries"
    assert body["discovery_confirmations_root"] == ".specbound/confirmations"
    assert body["micro_specs_root"] == ".specbound/micro-specs"
    assert body["iteration_qc_root"] == ".specbound/iteration-qc"
    assert body["delivery_qc_root"] == ".specbound/delivery-qc"


def test_cli_exposes_read_only_adoption_check_and_list_commands() -> None:
    adoption_help = run_cli("adoption", "--help")
    check_help = run_cli("adoption", "check", "--help")
    list_help = run_cli("adoption", "list", "--help")

    assert adoption_help.returncode == 0
    assert "{decide,check,list}" in adoption_help.stdout
    assert "without mutation" in adoption_help.stdout
    assert check_help.returncode == 0
    assert "--transition {iteration_qc,delivery_qc}" in check_help.stdout
    assert list_help.returncode == 0


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
    assert ".specbound/discoveries/dcy-<id>-r<revision>.md" in template
    assert "This is a `draft` Discovery." not in template
    assert "lifecycle state is determined by its frontmatter" in template
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


def test_requirement_template_and_draft_skill_match_draft_contract() -> None:
    template = (ROOT / "templates/requirement.md").read_text(encoding="utf-8")
    skill = (ROOT / "skills/draft-req/SKILL.md").read_text(encoding="utf-8")

    for text in (
        "id: req-<numeric-id>",
        "revision: <positive-integer>",
        "status: draft",
        "risk: <parent-risk-class>",
        ".specbound/discoveries/dcy-<numeric-id>-r<revision>.md",
        ".specbound/confirmations/dcy-<numeric-id>-r<revision>.confirmation.json",
        "## Scope",
        "## Non-goals",
        "## Acceptance criteria",
        "AC completion contract",
        "`observable_success`",
        "`required_preconditions`",
        "`mutation_boundary`",
        "`negative_behavior`",
        "`direct_evidence`",
        "`dependencies`",
        "`completion_group`",
        "`candidate_micro_spec`",
        "`non_goals`",
        "specbound req check-readiness",
        "specbound req to-in-review",
        "review-submission record",
        "Draft issuance is not review, rejection, approval, or implementation authority.",
    ):
        assert text in template
    for text in (
        ".venv/bin/python -m specbound.cli req draft",
        "Do not self-approve",
        "approval record",
        "`observable_success`",
        "`completion_group`",
        "Only a passing CLI and validator result proves the repository contract.",
        "new numeric REQ revision",
    ):
        assert text in skill


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
            "dcy-<id>-r<revision>.md", "dcy-<id>/dcy-<id>-r<revision>.md"
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


def test_discovery_confirm_creates_exact_record_and_validates(tmp_path: Path) -> None:
    fixture = tmp_path / "confirm-discovery"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    confirmation_path = fixture / ".specbound/confirmations/dcy-0001-r1.confirmation.json"
    confirmation_path.unlink()
    discovery_path = fixture / ".specbound/discoveries/dcy-0001-r1.md"
    discovery_path.write_text(
        discovery_path.read_text(encoding="utf-8").replace("status: confirmed", "status: in_review", 1),
        encoding="utf-8",
        newline="\n",
    )
    reviewed_digest = hashlib.sha256(discovery_path.read_bytes()).hexdigest()
    reviewed_body = discovery_path.read_text(encoding="utf-8").split("\n---\n", 1)[1]

    result = run_cli(
        "--root",
        str(fixture),
        "discovery",
        "confirm",
        "dcy-0001-r1",
        "--authority",
        "fixture-maintainer",
    )

    assert result.returncode == 0, result.stdout
    record = json.loads(confirmation_path.read_text(encoding="utf-8"))
    assert record["discovery_path"] == ".specbound/discoveries/dcy-0001-r1.md"
    assert record["discovery_id"] == "dcy-0001"
    assert record["revision"] == 1
    assert record["reviewed_sha256"] == reviewed_digest
    confirmed_text = discovery_path.read_text(encoding="utf-8")
    assert "status: confirmed" in confirmed_text
    assert confirmed_text.split("\n---\n", 1)[1] == reviewed_body
    assert record["sha256"] == hashlib.sha256(
        discovery_path.read_bytes()
    ).hexdigest()
    assert record["authority"] == "fixture-maintainer"
    assert record["decision"] == "confirmed"
    assert record["permitted_next_action"] == "draft_req_only"
    assert run_cli("--root", str(fixture), "validate").returncode == 0


def test_validate_rejects_confirmed_discovery_without_record(tmp_path: Path) -> None:
    fixture = tmp_path / "confirmed-without-record"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    (fixture / ".specbound/confirmations/dcy-0001-r1.confirmation.json").unlink()

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    assert "missing_discovery_confirmation" in {item["code"] for item in payload(result)["blockers"]}


def test_discovery_confirm_rejects_existing_confirmation(tmp_path: Path) -> None:
    fixture = tmp_path / "duplicate-confirmation"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)

    result = run_cli(
        "--root",
        str(fixture),
        "discovery",
        "confirm",
        "dcy-0001-r1",
        "--authority",
        "fixture-maintainer",
    )

    assert result.returncode == 2
    assert "confirmation_already_exists" in {item["code"] for item in payload(result)["blockers"]}


def test_discovery_confirm_rejects_superseded_revision_without_exception(tmp_path: Path) -> None:
    fixture = tmp_path / "superseded-confirmation"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    (fixture / ".specbound/confirmations/dcy-0001-r1.confirmation.json").unlink()
    r1 = fixture / ".specbound/discoveries/dcy-0001-r1.md"
    r1.write_text(r1.read_text(encoding="utf-8").replace("status: confirmed", "status: in_review", 1), encoding="utf-8")
    r2 = fixture / ".specbound/discoveries/dcy-0001-r2.md"
    r2.write_text(
        r1.read_text(encoding="utf-8").replace("revision: 1", "revision: 2", 1), encoding="utf-8"
    )

    rejected = run_cli(
        "--root",
        str(fixture),
        "discovery",
        "confirm",
        "dcy-0001-r1",
        "--authority",
        "fixture-maintainer",
    )
    assert rejected.returncode == 2
    assert "superseded_discovery_revision" in {item["code"] for item in payload(rejected)["blockers"]}

    accepted = run_cli(
        "--root",
        str(fixture),
        "discovery",
        "confirm",
        "dcy-0001-r1",
        "--authority",
        "fixture-maintainer",
        "--supersession-exception",
        "Required historical baseline for migration audit.",
    )
    assert accepted.returncode == 0, accepted.stdout
    record = json.loads((fixture / ".specbound/confirmations/dcy-0001-r1.confirmation.json").read_text(encoding="utf-8"))
    assert record["supersession_exception"]["reason"] == "Required historical baseline for migration audit."


def test_discovery_confirm_rejects_unallowlisted_authority(tmp_path: Path) -> None:
    fixture = tmp_path / "unallowlisted-confirmation"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    confirmation_path = fixture / ".specbound/confirmations/dcy-0001-r1.confirmation.json"
    confirmation_path.unlink()
    discovery_path = fixture / ".specbound/discoveries/dcy-0001-r1.md"
    discovery_path.write_text(
        discovery_path.read_text(encoding="utf-8").replace("status: confirmed", "status: in_review", 1),
        encoding="utf-8",
    )

    result = run_cli(
        "--root",
        str(fixture),
        "discovery",
        "confirm",
        "dcy-0001-r1",
        "--authority",
        "untrusted-actor",
    )

    assert result.returncode == 2
    assert "invalid_discovery_confirmation_authority" in {item["code"] for item in payload(result)["blockers"]}
    assert not confirmation_path.exists()
    assert "status: in_review" in discovery_path.read_text(encoding="utf-8")


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
    requirement = fixture / ".specbound/requirements/req-0001/req-0001-r1.md"
    requirement.write_text(requirement.read_text(encoding="utf-8") + "\nChanged after approval.\n", encoding="utf-8")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    assert "requirement_digest_mismatch" in {item["code"] for item in payload(result)["blockers"]}


def test_validate_rejects_discovery_confirmation_digest_mismatch(tmp_path: Path) -> None:
    fixture = tmp_path / "discovery-digest-mismatch"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    discovery = fixture / ".specbound/discoveries/dcy-0001-r1.md"
    discovery.write_text(discovery.read_text(encoding="utf-8") + "\nChanged after confirmation.\n", encoding="utf-8")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    report = payload(result)
    assert "discovery_digest_mismatch" in {item["code"] for item in report["blockers"]}
    assert report["confirmed_discoveries"] == 0


def test_validate_rejects_excessive_discovery_authorization(tmp_path: Path) -> None:
    fixture = tmp_path / "excessive-discovery-authorization"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    confirmation_path = fixture / ".specbound/confirmations/dcy-0001-r1.confirmation.json"
    confirmation = json.loads(confirmation_path.read_text(encoding="utf-8"))
    confirmation["permitted_next_action"] = "implementation"
    confirmation_path.write_text(json.dumps(confirmation), encoding="utf-8")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    assert "excessive_discovery_authorization" in {item["code"] for item in payload(result)["blockers"]}


def test_validate_rejects_unallowlisted_discovery_confirmer(tmp_path: Path) -> None:
    fixture = tmp_path / "unallowlisted-discovery-confirmer"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    confirmation_path = fixture / ".specbound/confirmations/dcy-0001-r1.confirmation.json"
    confirmation = json.loads(confirmation_path.read_text(encoding="utf-8"))
    confirmation["authority"] = "untrusted-actor"
    confirmation_path.write_text(json.dumps(confirmation), encoding="utf-8")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    assert "invalid_discovery_confirmation_authority" in {item["code"] for item in payload(result)["blockers"]}


def test_validate_rejects_missing_discovery_schema_version(tmp_path: Path) -> None:
    fixture = tmp_path / "missing-discovery-schema-version"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    confirmation_path = fixture / ".specbound/confirmations/dcy-0001-r1.confirmation.json"
    confirmation = json.loads(confirmation_path.read_text(encoding="utf-8"))
    del confirmation["schema_version"]
    confirmation_path.write_text(json.dumps(confirmation), encoding="utf-8")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    assert "malformed_discovery_confirmation" in {item["code"] for item in payload(result)["blockers"]}


def test_validate_rejects_symlinked_requirement_record(tmp_path: Path) -> None:
    fixture = tmp_path / "symlinked-requirement"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    requirement = fixture / ".specbound/requirements/req-0001/req-0001-r1.md"
    outside = tmp_path / "outside-requirement.md"
    requirement.rename(outside)
    try:
        requirement.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink not available: {exc}")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    assert "unsafe_artifact_path" in {item["code"] for item in payload(result)["blockers"]}


@pytest.mark.parametrize(
    "link_path", [".specbound/requirements", ".specbound/approvals"]
)
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
    directory = fixture / ".specbound/discoveries"
    outside = tmp_path / "outside-discovery"
    directory.rename(outside)
    try:
        directory.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink not available: {exc}")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    assert "unsafe_artifact_path" in {item["code"] for item in payload(result)["blockers"]}


def test_req_draft_mints_exact_parent_bound_draft(tmp_path: Path) -> None:
    fixture = tmp_path / "req-draft"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)

    result = run_cli(
        "--root", str(fixture), "req", "draft", "dcy-0001-r1", "req-0002-r1"
    )

    assert result.returncode == 0, result.stdout
    draft = fixture / ".specbound/requirements/req-0002/req-0002-r1.md"
    assert payload(result)["requirement_path"] == ".specbound/requirements/req-0002/req-0002-r1.md"
    assert draft.is_file()
    text = draft.read_text(encoding="utf-8")
    assert "id: req-0002" in text
    assert "revision: 1" in text
    assert "status: draft" in text
    assert "path: .specbound/discoveries/dcy-0001-r1.md" in text
    assert "confirmation_path: .specbound/confirmations/dcy-0001-r1.confirmation.json" in text
    assert "This artifact's lifecycle state is determined only by frontmatter" in text
    assert "Draft issuance is not review, rejection, approval, or implementation authority." in text
    assert "Approval issuance, implementation, merge, delivery, and release are separate actions." in text
    assert "Review the exact snapshot separately; do not infer approval from issuance." in text
    assert "specbound req check-readiness" in text
    assert "specbound req to-in-review" in text
    for field in (
        "observable_success",
        "required_preconditions",
        "mutation_boundary",
        "negative_behavior",
        "direct_evidence",
        "dependencies",
        "completion_group",
        "candidate_micro_spec",
        "non_goals",
    ):
        assert f"`{field}`" in text
    assert "This draft is not" not in text
    assert "outside this draft command" not in text
    assert run_cli("--root", str(fixture), "validate").returncode == 0


def test_req_draft_allows_a_preexisting_canonical_requirement_directory(tmp_path: Path) -> None:
    fixture = tmp_path / "req-draft-existing-directory"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    (fixture / ".specbound/requirements/req-0002").mkdir()

    result = run_cli(
        "--root", str(fixture), "req", "draft", "dcy-0001-r1", "req-0002-r1"
    )

    assert result.returncode == 0, result.stdout
    assert (fixture / ".specbound/requirements/req-0002/req-0002-r1.md").is_file()


@pytest.mark.parametrize("target", ("../req-0002-r1", "/tmp/req-0002-r1", "req-0002-r1/extra"))
def test_req_draft_rejects_noncanonical_target_without_writing(tmp_path: Path, target: str) -> None:
    fixture = tmp_path / "req-draft-noncanonical-target"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)

    result = run_cli("--root", str(fixture), "req", "draft", "dcy-0001-r1", target)

    assert result.returncode == 2
    assert "invalid_requirement_target" in {item["code"] for item in payload(result)["blockers"]}
    assert not (fixture / ".specbound/requirements/req-0002").exists()


def test_req_draft_rejects_symlinked_target_directory_without_writing(tmp_path: Path) -> None:
    fixture = tmp_path / "req-draft-symlinked-target"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    target_directory = fixture / ".specbound/requirements/req-0002"
    outside = tmp_path / "outside-requirement-target"
    outside.mkdir()
    try:
        target_directory.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink not available: {exc}")

    result = run_cli("--root", str(fixture), "req", "draft", "dcy-0001-r1", "req-0002-r1")

    assert result.returncode == 2
    assert "unsafe_artifact_path" in {item["code"] for item in payload(result)["blockers"]}
    assert not (outside / "req-0002-r1.md").exists()


def test_req_draft_rejects_existing_target_without_overwrite(tmp_path: Path) -> None:
    fixture = tmp_path / "duplicate-req-draft"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)

    first = run_cli("--root", str(fixture), "req", "draft", "dcy-0001-r1", "req-0002-r1")
    original = (fixture / ".specbound/requirements/req-0002/req-0002-r1.md").read_bytes()
    second = run_cli("--root", str(fixture), "req", "draft", "dcy-0001-r1", "req-0002-r1")

    assert first.returncode == 0, first.stdout
    assert second.returncode == 2
    assert "requirement_already_exists" in {item["code"] for item in payload(second)["blockers"]}
    assert (fixture / ".specbound/requirements/req-0002/req-0002-r1.md").read_bytes() == original


def test_req_draft_preserves_target_created_during_publish_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "req-draft-create-race"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    target = fixture / ".specbound/requirements/req-0002/req-0002-r1.md"
    original_link = validation.os.link

    def create_competing_target(
        source: str | os.PathLike[str], destination: str | os.PathLike[str], *args: object, **kwargs: object
    ) -> None:
        if Path(destination).name == target.name and not target.exists():
            target.parent.mkdir(exist_ok=True)
            target.write_text("competing artifact", encoding="utf-8")
        original_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(validation.os, "link", create_competing_target)

    with pytest.raises(RequirementDraftError) as excinfo:
        create_requirement_draft(fixture, "dcy-0001-r1", "req-0002-r1")

    assert excinfo.value.code == "requirement_already_exists"
    assert target.read_text(encoding="utf-8") == "competing artifact"


def test_req_draft_leaves_no_target_when_temp_draft_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "req-draft-write-failure"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    target = fixture / ".specbound/requirements/req-0002/req-0002-r1.md"

    def fail_fsync(_fd: int) -> None:
        raise OSError("simulated fsync failure")

    monkeypatch.setattr(validation.os, "fsync", fail_fsync)

    with pytest.raises(RequirementDraftError) as excinfo:
        create_requirement_draft(fixture, "dcy-0001-r1", "req-0002-r1")

    assert excinfo.value.code == "requirement_write_failed"
    assert not target.exists()


def test_req_draft_removes_its_published_target_when_directory_sync_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "req-draft-directory-sync-failure"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    target = fixture / ".specbound/requirements/req-0002/req-0002-r1.md"
    original_fsync = validation.os.fsync
    calls = 0

    def fail_published_directory_sync(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated directory fsync failure")
        original_fsync(fd)

    monkeypatch.setattr(validation.os, "fsync", fail_published_directory_sync)

    with pytest.raises(RequirementDraftError) as excinfo:
        create_requirement_draft(fixture, "dcy-0001-r1", "req-0002-r1")

    assert excinfo.value.code == "requirement_write_failed"
    assert not target.exists()


def test_req_draft_removes_its_published_target_when_generated_validation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "req-draft-generated-validation-failure"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    target = fixture / ".specbound/requirements/req-0002/req-0002-r1.md"
    original_validate = validation.validate
    calls = 0

    def fail_after_publication(root: Path) -> validation.Result:
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_validate(root)
        result = validation.Result(root)
        result.block("simulated_generated_requirement_failure", ".specbound/requirements", "simulated")
        return result

    monkeypatch.setattr(validation, "validate", fail_after_publication)

    with pytest.raises(RequirementDraftError) as excinfo:
        create_requirement_draft(fixture, "dcy-0001-r1", "req-0002-r1")

    assert excinfo.value.code == "generated_requirement_invalid"
    assert not target.exists()


def test_req_draft_rejects_target_parent_replaced_by_symlink_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "req-draft-symlink-race"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    target_directory = fixture / ".specbound/requirements/req-0002"
    outside = tmp_path / "outside-requirement-target"
    outside.mkdir()
    original_open = validation.os.open

    def replace_parent_with_symlink(
        path: str | os.PathLike[str], flags: int, *args: object, **kwargs: object
    ) -> int:
        if Path(path) == target_directory and flags & os.O_DIRECTORY:
            target_directory.rmdir()
            target_directory.symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(validation.os, "open", replace_parent_with_symlink)

    with pytest.raises(RequirementDraftError) as excinfo:
        create_requirement_draft(fixture, "dcy-0001-r1", "req-0002-r1")

    assert excinfo.value.code == "unsafe_artifact_path"
    assert not (outside / "req-0002-r1.md").exists()


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("remove_confirmation", "missing_discovery_confirmation"),
        ("mutate_discovery", "discovery_reviewed_digest_mismatch"),
        ("overauthorize", "excessive_discovery_authorization"),
    ],
)
def test_req_draft_rejects_invalid_parent_evidence(
    tmp_path: Path, mutation: str, expected_code: str
) -> None:
    fixture = tmp_path / mutation
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    confirmation_path = fixture / ".specbound/confirmations/dcy-0001-r1.confirmation.json"
    if mutation == "remove_confirmation":
        confirmation_path.unlink()
    elif mutation == "mutate_discovery":
        discovery = fixture / ".specbound/discoveries/dcy-0001-r1.md"
        discovery.write_text(
            discovery.read_text(encoding="utf-8") + "\nMutated.\n", encoding="utf-8"
        )
    else:
        confirmation = json.loads(confirmation_path.read_text(encoding="utf-8"))
        confirmation["permitted_next_action"] = "implementation"
        confirmation_path.write_text(json.dumps(confirmation), encoding="utf-8")

    result = run_cli("--root", str(fixture), "req", "draft", "dcy-0001-r1", "req-0002-r1")

    assert result.returncode == 2
    assert expected_code in {item["code"] for item in payload(result)["blockers"]}
    assert not (fixture / ".specbound/requirements/req-0002/req-0002-r1.md").exists()


def test_req_draft_can_issue_draft_revision_without_mutating_historical_approval(tmp_path: Path) -> None:
    fixture = tmp_path / "req-draft-revision"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    historical_approval = fixture / ".specbound/approvals/req-0001-r1.approval.json"
    original_approval = historical_approval.read_bytes()

    requirement = create_requirement_draft(fixture, "dcy-0001-r1", "req-0001-r2")

    assert requirement == fixture / ".specbound/requirements/req-0001/req-0001-r2.md"
    assert "status: draft" in requirement.read_text(encoding="utf-8")
    assert historical_approval.read_bytes() == original_approval
    assert validation.validate(fixture).valid


def test_validate_requires_valid_exception_for_approved_historical_revision(tmp_path: Path) -> None:
    fixture = tmp_path / "requirement-revision-policy"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    r1 = fixture / ".specbound/requirements/req-0001/req-0001-r1.md"
    r2 = fixture / ".specbound/requirements/req-0001/req-0001-r2.md"
    r2.write_text(
        r1.read_text(encoding="utf-8")
        .replace("revision: 1", "revision: 2", 1),
        encoding="utf-8",
    )
    approval_path = fixture / ".specbound/approvals/req-0001-r1.approval.json"
    approval = json.loads(approval_path.read_text(encoding="utf-8"))
    r2_approval = dict(approval)
    r2_approval["requirement_path"] = ".specbound/requirements/req-0001/req-0001-r2.md"
    r2_approval["revision"] = 2
    r2_approval["sha256"] = validation._digest(r2)
    (fixture / ".specbound/approvals/req-0001-r2.approval.json").write_text(
        json.dumps(r2_approval), encoding="utf-8"
    )

    rejected = run_cli("--root", str(fixture), "validate")
    assert rejected.returncode == 2
    assert "superseded_requirement_revision" in {item["code"] for item in payload(rejected)["blockers"]}

    approval["supersession_exception"] = {
        "reason": "Retained as an approved historical audit baseline.",
        "authority": approval["authority"],
        "recorded_at": "2026-07-21T09:00:00+00:00",
    }
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    assert run_cli("--root", str(fixture), "validate").returncode == 0

    approval["supersession_exception"]["recorded_at"] = "not-a-timestamp"
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    malformed = run_cli("--root", str(fixture), "validate")
    assert malformed.returncode == 2
    assert "malformed_supersession_exception" in {item["code"] for item in payload(malformed)["blockers"]}


def _make_ready_draft(fixture: Path, target: str = "req-0002-r1") -> Path:
    requirement = create_requirement_draft(fixture, "dcy-0001-r1", target)
    frontmatter = requirement.read_text(encoding="utf-8").split("---\n", 2)[1]
    requirement.write_text(
        "---\n"
        + frontmatter
        + "---\n\n"
        + f"# REQ: {target}\n\n"
        + "## 목표 (Goal)\n\nSubmit one closed, evidence-backed completion contract for review.\n\n"
        + "## Scope (범위)\n\n- Validate and submit this exact draft only.\n\n"
        + "## Non-goals (비목표)\n\n- Approval, implementation, merge, delivery, and release remain separate actions.\n\n"
        + "## Acceptance criteria\n\n"
        + "### AC-001 — Submit exact review snapshot\n\n"
        + "- `observable_success`: The CLI emits one digest-bound review-submission record.\n"
        + "- `required_preconditions`: A confirmed parent Discovery and a canonical draft REQ exist.\n"
        + "- `mutation_boundary`: Only this REQ status and its new review-submission record may change.\n"
        + "- `negative_behavior`: Invalid readiness preserves the draft and creates no record.\n"
        + "- `direct_evidence`: .venv/bin/python -m pytest tests/test_cli.py -q\n"
        + "- `dependencies`: none\n"
        + "- `completion_group`: AC-001\n"
        + "- `candidate_micro_spec`: ms-0002-1\n"
        + "- `non_goals`: This does not approve or implement the REQ.\n\n"
        + "## Approval handoff\n\nReview this exact digest-bound draft. Submission is not approval.\n",
        encoding="utf-8",
    )
    return requirement


def test_req_check_readiness_rejects_unfilled_scaffold_without_mutation(tmp_path: Path) -> None:
    fixture = tmp_path / "readiness-scaffold"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    requirement = create_requirement_draft(fixture, "dcy-0001-r1", "req-0002-r1")
    original = requirement.read_bytes()

    result = run_cli("--root", str(fixture), "req", "check-readiness", "req-0002-r1")

    assert result.returncode == 2
    assert "incomplete_review_handoff" in {item["code"] for item in payload(result)["blockers"]}
    assert requirement.read_bytes() == original
    assert not (fixture / ".specbound/review-submissions/req-0002-r1.review-submission.json").exists()


def test_req_to_in_review_atomically_binds_draft_and_reviewed_snapshots(tmp_path: Path) -> None:
    fixture = tmp_path / "ready-review-submission"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    requirement = _make_ready_draft(fixture)
    draft_digest = hashlib.sha256(requirement.read_bytes()).hexdigest()

    readiness = run_cli("--root", str(fixture), "req", "check-readiness", "req-0002-r1")
    submitted = run_cli("--root", str(fixture), "req", "to-in-review", "req-0002-r1")

    assert readiness.returncode == 0, readiness.stdout
    assert submitted.returncode == 0, submitted.stdout
    record_path = fixture / ".specbound/review-submissions/req-0002-r1.review-submission.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert payload(submitted)["review_submission_path"] == ".specbound/review-submissions/req-0002-r1.review-submission.json"
    assert "status: in_review" in requirement.read_text(encoding="utf-8")
    assert record["draft_sha256"] == draft_digest
    assert record["reviewed_sha256"] == hashlib.sha256(requirement.read_bytes()).hexdigest()
    assert record["decision"] == "submitted_for_review"
    assert record["permitted_next_action"] == "review_decision_only"
    assert run_cli("--root", str(fixture), "validate").returncode == 0


def test_req_check_readiness_fails_closed_for_unknown_ac_dependency(tmp_path: Path) -> None:
    fixture = tmp_path / "unknown-ac-dependency"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    requirement = _make_ready_draft(fixture)
    requirement.write_text(
        requirement.read_text(encoding="utf-8").replace("- `dependencies`: none", "- `dependencies`: AC-999"),
        encoding="utf-8",
    )

    result = run_cli("--root", str(fixture), "req", "check-readiness", "req-0002-r1")

    assert result.returncode == 2
    assert "unknown_acceptance_criterion_dependency" in {item["code"] for item in payload(result)["blockers"]}


def test_req_to_in_review_rolls_back_on_status_publish_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = tmp_path / "review-submission-rollback"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    requirement = _make_ready_draft(fixture)
    original = requirement.read_bytes()

    def fail_status_publish(_path: Path, _text: str) -> None:
        raise OSError("simulated status publish failure")

    monkeypatch.setattr(validation, "_atomic_replace_text", fail_status_publish)
    with pytest.raises(RequirementReviewSubmissionError) as excinfo:
        submit_requirement_for_review(fixture, "req-0002-r1")

    assert excinfo.value.code == "review_submission_write_failed"
    assert requirement.read_bytes() == original
    assert not (fixture / ".specbound/review-submissions/req-0002-r1.review-submission.json").exists()


def test_req_to_in_review_rolls_back_after_generated_validation_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = tmp_path / "review-submission-validation-rollback"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    requirement = _make_ready_draft(fixture)
    original = requirement.read_bytes()
    original_validate = validation.validate
    calls = 0

    def fail_only_generated_result(
        root: Path, claim: str | None = None, requirement: str | None = None
    ) -> validation.Result:
        nonlocal calls
        calls += 1
        result = original_validate(root, claim=claim, requirement=requirement)
        if calls == 2:
            result.block("simulated_generated_validation_failure", "test", "force rollback after publication")
        return result

    monkeypatch.setattr(validation, "validate", fail_only_generated_result)
    with pytest.raises(RequirementReviewSubmissionError) as excinfo:
        submit_requirement_for_review(fixture, "req-0002-r1")

    assert excinfo.value.code == "generated_review_submission_invalid"
    assert requirement.read_bytes() == original
    assert not (fixture / ".specbound/review-submissions/req-0002-r1.review-submission.json").exists()


def test_req_to_in_review_leaves_no_record_when_record_fsync_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = tmp_path / "review-submission-record-write-failure"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    requirement = _make_ready_draft(fixture)
    original = requirement.read_bytes()

    def fail_fsync(_fd: int) -> None:
        raise OSError("simulated record fsync failure")

    monkeypatch.setattr(validation.os, "fsync", fail_fsync)
    with pytest.raises(RequirementReviewSubmissionError) as excinfo:
        submit_requirement_for_review(fixture, "req-0002-r1")

    assert excinfo.value.code == "review_submission_write_failed"
    assert requirement.read_bytes() == original
    assert not (fixture / ".specbound/review-submissions/req-0002-r1.review-submission.json").exists()


def test_req_to_in_review_rejects_mutation_after_readiness_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = tmp_path / "review-submission-concurrent-mutation"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    requirement = _make_ready_draft(fixture)
    original = requirement.read_bytes()
    original_readiness = validation.check_requirement_readiness

    def mutate_after_readiness(root: Path, target: str) -> validation.Result:
        result = original_readiness(root, target)
        requirement.write_text(requirement.read_text(encoding="utf-8") + "\nConcurrent mutation.\n", encoding="utf-8")
        return result

    monkeypatch.setattr(validation, "check_requirement_readiness", mutate_after_readiness)
    with pytest.raises(RequirementReviewSubmissionError) as excinfo:
        submit_requirement_for_review(fixture, "req-0002-r1")

    assert excinfo.value.code == "concurrent_requirement_mutation"
    assert requirement.read_bytes() != original
    assert not (fixture / ".specbound/review-submissions/req-0002-r1.review-submission.json").exists()


def test_req_to_in_review_preserves_a_complete_pair_when_rollback_cleanup_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = tmp_path / "review-submission-rollback-cleanup-failure"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    requirement = _make_ready_draft(fixture)
    original_validate = validation.validate
    calls = 0

    def fail_generated_validation(root: Path, claim: str | None = None, requirement: str | None = None) -> validation.Result:
        nonlocal calls
        calls += 1
        result = original_validate(root, claim=claim, requirement=requirement)
        if calls == 2:
            result.block("simulated_generated_validation_failure", "test", "force rollback")
        return result

    def fail_record_cleanup(_directory_fd: int, _name: str, _identity: tuple[int, int]) -> None:
        raise OSError("simulated record cleanup failure")

    monkeypatch.setattr(validation, "validate", fail_generated_validation)
    monkeypatch.setattr(validation, "_unlink_review_submission_if_owned", fail_record_cleanup)
    with pytest.raises(RequirementReviewSubmissionError) as excinfo:
        submit_requirement_for_review(fixture, "req-0002-r1")

    assert excinfo.value.code == "review_submission_rollback_failed"
    assert "status: in_review" in requirement.read_text(encoding="utf-8")
    assert (fixture / ".specbound/review-submissions/req-0002-r1.review-submission.json").exists()


def _make_in_review_requirement(fixture: Path) -> Path:
    requirement = fixture / ".specbound/requirements/req-0001/req-0001-r1.md"
    reviewed_text = requirement.read_text(encoding="utf-8").replace("status: approved", "status: in_review", 1)
    requirement.write_text(reviewed_text, encoding="utf-8", newline="\n")
    (fixture / ".specbound/approvals/req-0001-r1.approval.json").unlink()
    review_submission = {
        "schema_version": 1,
        "requirement_path": ".specbound/requirements/req-0001/req-0001-r1.md",
        "requirement_id": "req-0001",
        "revision": 1,
        "draft_sha256": hashlib.sha256(reviewed_text.replace("status: in_review", "status: draft", 1).encode()).hexdigest(),
        "reviewed_sha256": hashlib.sha256(reviewed_text.encode()).hexdigest(),
        "risk": "low",
        "owner": "fixture-owner",
        "submitted_at": "2026-07-23T09:00:00+00:00",
        "decision": "submitted_for_review",
        "permitted_next_action": "review_decision_only",
    }
    (fixture / ".specbound/review-submissions/req-0001-r1.review-submission.json").write_text(
        json.dumps(review_submission), encoding="utf-8"
    )
    review_decision = {
        "schema_version": 1,
        "requirement_path": ".specbound/requirements/req-0001/req-0001-r1.md",
        "requirement_id": "req-0001",
        "revision": 1,
        "reviewed_sha256": hashlib.sha256(reviewed_text.encode()).hexdigest(),
        "risk": "low",
        "authority": "fixture-maintainer",
        "decided_at": "2026-07-23T09:01:00+00:00",
        "decision": "rejected",
        "reason": "Fixture blocker with direct deterministic evidence.",
    }
    decision_path = fixture / ".specbound/review-decisions/req-0001-r1.review-decision.json"
    decision_path.parent.mkdir(parents=True, exist_ok=True)
    decision_path.write_text(json.dumps(review_decision), encoding="utf-8")
    assert run_cli("--root", str(fixture), "validate").returncode == 0
    return requirement


def test_req_reject_atomically_binds_reviewed_and_rejected_snapshots(tmp_path: Path) -> None:
    fixture = tmp_path / "req-reject"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    requirement = _make_in_review_requirement(fixture)
    reviewed_sha256 = hashlib.sha256(requirement.read_bytes()).hexdigest()

    result = run_cli(
        "--root", str(fixture), "req", "reject", "req-0001-r1",
        "--authority", "fixture-maintainer",
        "--reason", "The reviewed REQ contains contradictory lifecycle claims.",
    )

    assert result.returncode == 0, result.stdout
    rejection_path = fixture / ".specbound/rejections/req-0001-r1.rejection.json"
    rejection = json.loads(rejection_path.read_text(encoding="utf-8"))
    assert payload(result)["rejection_path"] == ".specbound/rejections/req-0001-r1.rejection.json"
    assert "status: rejected" in requirement.read_text(encoding="utf-8")
    assert rejection["decision"] == "rejected"
    assert rejection["reviewed_sha256"] == reviewed_sha256
    assert rejection["sha256"] == hashlib.sha256(requirement.read_bytes()).hexdigest()
    report = run_cli("--root", str(fixture), "validate")
    assert report.returncode == 0, report.stdout
    assert payload(report)["approved_requirements"] == 0


def test_req_reject_refuses_unallowlisted_authority_without_writing(tmp_path: Path) -> None:
    fixture = tmp_path / "req-reject-unallowlisted"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    requirement = _make_in_review_requirement(fixture)
    original = requirement.read_bytes()

    result = run_cli(
        "--root", str(fixture), "req", "reject", "req-0001-r1",
        "--authority", "untrusted-actor",
        "--reason", "The reviewed REQ must not proceed.",
    )

    assert result.returncode == 2
    assert "invalid_rejection_authority" in {item["code"] for item in payload(result)["blockers"]}
    assert requirement.read_bytes() == original
    assert not (fixture / ".specbound/rejections/req-0001-r1.rejection.json").exists()


def test_validate_fails_closed_for_tampered_requirement_rejection(tmp_path: Path) -> None:
    fixture = tmp_path / "tampered-req-rejection"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    _make_in_review_requirement(fixture)
    rejected = run_cli(
        "--root", str(fixture), "req", "reject", "req-0001-r1",
        "--authority", "fixture-maintainer",
        "--reason", "The reviewed REQ has unresolved lifecycle contradictions.",
    )
    assert rejected.returncode == 0, rejected.stdout
    rejection_path = fixture / ".specbound/rejections/req-0001-r1.rejection.json"
    rejection = json.loads(rejection_path.read_text(encoding="utf-8"))
    rejection["reviewed_sha256"] = "0" * 64
    rejection_path.write_text(json.dumps(rejection), encoding="utf-8")

    result = run_cli("--root", str(fixture), "validate")

    assert result.returncode == 2
    assert "rejection_digest_mismatch" in {item["code"] for item in payload(result)["blockers"]}


def test_req_reject_refuses_duplicate_decision_without_overwrite(tmp_path: Path) -> None:
    fixture = tmp_path / "duplicate-req-rejection"
    shutil.copytree(FIXTURES / "valid-minimal", fixture)
    requirement = _make_in_review_requirement(fixture)
    first = run_cli(
        "--root", str(fixture), "req", "reject", "req-0001-r1",
        "--authority", "fixture-maintainer",
        "--reason", "The reviewed REQ has unresolved lifecycle contradictions.",
    )
    record = fixture / ".specbound/rejections/req-0001-r1.rejection.json"
    original_requirement = requirement.read_bytes()
    original_record = record.read_bytes()
    second = run_cli(
        "--root", str(fixture), "req", "reject", "req-0001-r1",
        "--authority", "fixture-maintainer",
        "--reason", "A different outcome must not overwrite the prior decision.",
    )

    assert first.returncode == 0, first.stdout
    assert second.returncode == 2
    assert "rejection_already_exists" in {item["code"] for item in payload(second)["blockers"]}
    assert requirement.read_bytes() == original_requirement
    assert record.read_bytes() == original_record
