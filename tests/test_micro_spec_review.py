from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "valid-minimal"


def run_cli(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "specbound.cli", "--root", str(root), *args],
        cwd=ROOT, env={"PYTHONPATH": str(ROOT / "src")}, check=False, capture_output=True, text=True,
    )


def body(result: subprocess.CompletedProcess[str]) -> dict:
    return json.loads(result.stdout)


def copied_fixture(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    return root


def valid_micro_spec(root: Path) -> str:
    digest = sha256((root / "docs/requirements/req-0001/req-0001-r1.md").read_bytes()).hexdigest()
    return f"""---
schema_version: 1
id: ms-0001-003
kind: micro-spec
requirement:
  path: docs/requirements/req-0001/req-0001-r1.md
  id: req-0001
  revision: 1
  sha256: {digest}
selected_acceptance_criteria: [AC-001]
---

# ms-0001-003

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


def issue(root: Path) -> subprocess.CompletedProcess[str]:
    return run_cli(
        root, "micro-spec", "review-decision", "ms-0001-003", "--authority", "fixture-maintainer",
        "--decision", "approved_for_implementation", "--reason",
        "Independent fixture review found the selected AC bounded and the parent binding exact.",
    )


def test_micro_spec_review_decision_is_append_only_and_exact_bound(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    micro = root / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    micro.parent.mkdir(parents=True)
    micro.write_text(valid_micro_spec(root), encoding="utf-8")

    issued = issue(root)

    assert issued.returncode == 0, issued.stdout
    review = root / ".specbound/micro-spec-reviews/req-0001/ms-0001-003.review.json"
    assert review.is_file()
    assert body(run_cli(root, "validate"))["valid"] is True
    duplicate = run_cli(
        root, "micro-spec", "review-decision", "ms-0001-003", "--authority", "fixture-maintainer",
        "--decision", "blocked", "--reason", "A second decision must never overwrite the first.",
    )
    assert duplicate.returncode == 2
    assert {item["code"] for item in body(duplicate)["blockers"]} == {"micro_spec_review_already_exists"}


def test_validate_fails_closed_for_tampered_micro_spec_review_binding(tmp_path: Path) -> None:
    root = copied_fixture(tmp_path)
    micro = root / ".specbound/micro-specs/req-0001/ms-0001-003.md"
    micro.parent.mkdir(parents=True)
    micro.write_text(valid_micro_spec(root), encoding="utf-8")
    assert issue(root).returncode == 0
    review = root / ".specbound/micro-spec-reviews/req-0001/ms-0001-003.review.json"
    data = json.loads(review.read_text(encoding="utf-8"))
    data["micro_spec_sha256"] = "0" * 64
    review.write_text(json.dumps(data), encoding="utf-8")

    result = run_cli(root, "validate")

    assert result.returncode == 2
    assert "micro_spec_review_binding_mismatch" in {item["code"] for item in body(result)["blockers"]}
