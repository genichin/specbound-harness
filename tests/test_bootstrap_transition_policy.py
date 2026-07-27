from __future__ import annotations

from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "docs/governance/bootstrap-to-canonical-transition.md"
EXCEPTION_DIR = ROOT / "docs/governance/bootstrap-exceptions"
EXCEPTION_INDEX = EXCEPTION_DIR / "README.md"
EXCEPTION_TEMPLATE = ROOT / "templates/bootstrap-exception.md"
REPO_SKILL = ROOT / "skills/specbound-harness/SKILL.md"
ADOPTER_CONTRACT = ROOT / "skills/specbound-harness/references/adopter-contract.md"

EXPECTED_GOVERNANCE_SHA256 = {
    POLICY: "eb615188e8283e6884f01a5bdc4832134079a2baffa53e5a927cb871417d466e",
    EXCEPTION_INDEX: "c27fa756e539239b191d8a3ad4c7e55e70087002eac9bed92e277f04b8fab70d",
    EXCEPTION_TEMPLATE: "f793dc2d6f4009e6af64f708edb48369dd8843a92e424645d6b368ef3cc250ca",
    REPO_SKILL: "50dbeeff51a24a69c1e15d79f6fee73d4a584f83b1d5e69db69a9378885a2504",
    ADOPTER_CONTRACT: "5c99fa8bf576a2aa36719c11ace732a058fd395e7e86a83cdf7de952c29677b2",
}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_transition_policy_exact_artifacts_are_digest_guarded() -> None:
    for path, expected in EXPECTED_GOVERNANCE_SHA256.items():
        assert sha256(path.read_bytes()).hexdigest() == expected

    assert {path.name for path in EXCEPTION_DIR.iterdir() if path.is_file()} == {"README.md"}


def test_transition_policy_is_repo_local_and_canonical_first() -> None:
    policy = _text(POLICY)

    for required in (
        "# Bootstrap-to-Canonical Transition Policy",
        "2722bcd50938ed7a43011fe3d4793e521ef9f997",
        "discord:1531116736534020167",
        "Scope:** this repository only; it is not automatically part of the general adopter contract.",
        "An applicable canonical gate cannot be replaced by a manual status edit",
        "A canonical gate failure caused by invalid candidate bytes, missing evidence, stale bindings, or unauthorized authority requires rework or stop.",
        "No active exception is created by this matrix.",
        "Break-glass never authorizes self-approval, silent status mutation, direct authority-record issuance, adoption, Delivery, Merge, Release, credentials, or network/production mutation.",
        "No retrospective promotion",
        "Prospective cutover",
    ):
        assert required in policy

    for classification in (
        "CANONICAL_REQUIRED",
        "BOOTSTRAP_ADVISORY",
        "BOOTSTRAP_AUTHORITY_EXCEPTION",
        "UNSUPPORTED_BLOCKED",
    ):
        assert classification in policy

    source_boundary = _text(REPO_SKILL)
    assert "When operating inside the `specbound-harness` source repository" in source_boundary
    assert "When this reusable skill is used in an adopting repository" in source_boundary
    assert "the `specbound-harness` transition policy does not apply" in source_boundary
    assert "a nonexistent `docs/governance/bootstrap-to-canonical-transition.md` is not a blocker for adopters" in source_boundary

    adopter = _text(ADOPTER_CONTRACT)
    assert "bootstrap-to-canonical-transition.md" not in adopter
    assert "Bootstrap-to-Canonical Transition Policy" not in adopter

    linked_paths = (
        ROOT / "README.md",
        ROOT / "AGENTS.md",
        ROOT / "docs/governance/issue-sdlc.md",
        REPO_SKILL,
    )
    for linked_path in linked_paths:
        linked = _text(linked_path)
        assert "docs/governance/bootstrap-to-canonical-transition.md" in linked

    deprecated_scan_paths = (
        POLICY,
        EXCEPTION_INDEX,
        EXCEPTION_TEMPLATE,
        ADOPTER_CONTRACT,
        *linked_paths,
    )
    for path in deprecated_scan_paths:
        assert "Bootstrap Closure Mode" not in _text(path)


def test_break_glass_contract_forbids_implicit_or_evidence_bypass() -> None:
    policy = _text(POLICY)
    for eligible in (
        "reproducible CLI/writer defect",
        "validator false positive against exact valid bytes",
        "supported-platform control-plane unavailability",
        "writer failure after all input, evidence, binding, and authority preconditions pass",
    ):
        assert eligible in policy

    for forbidden in (
        "schema-invalid or semantically invalid candidate bytes",
        "missing test, review, IQC, DQC, rollback, or CI evidence",
        "unsafe/noncanonical path or stale/digest-mismatched binding",
        "unauthorized or non-allowlisted authority",
        "work outside the approved Discovery/REQ/Micro-SPEC",
        "a failed canary that shows the new capability is not operational",
    ):
        assert forbidden in policy

    index = _text(EXCEPTION_INDEX)
    assert "Active exceptions: 0" in index
    assert "No exception is implicit." in index
    assert "does not authorize" in index

    template = _text(EXCEPTION_TEMPLATE)
    for heading in (
        "## Exact canonical failure",
        "## Failure classification",
        "## Accountable authority",
        "## Permitted next action",
        "## Forbidden claims",
        "## Repair and expiry",
        "## Closeout",
    ):
        assert heading in template

    assert "control-plane defect" in template
    assert "candidate/evidence/authority failure" in template
    assert "Canonical state: not recorded" in template
    assert "Bootstrap provenance preserved; no retrospective promotion" in template
