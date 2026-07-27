from __future__ import annotations

from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "docs/governance/bootstrap-to-canonical-transition.md"
EXCEPTION_DIR = ROOT / "docs/governance/bootstrap-exceptions"
EXCEPTION_INDEX = EXCEPTION_DIR / "README.md"
EXCEPTION_RECORD = EXCEPTION_DIR / "req-0005-r1-review-return-001.md"
EXCEPTION_TEMPLATE = ROOT / "templates/bootstrap-exception.md"
REPO_SKILL = ROOT / "skills/specbound-harness/SKILL.md"
ADOPTER_CONTRACT = ROOT / "skills/specbound-harness/references/adopter-contract.md"

EXPECTED_GOVERNANCE_SHA256 = {
    POLICY: "45359f14618a84bbeb3e2a63af746b71130c3e3280a95d0a9258776f9e173110",
    EXCEPTION_INDEX: "ef80689ba42089b1afab55af3600ccc1fe1cf20fc7f3ca70483018bd888b0ee8",
    EXCEPTION_RECORD: "ba1987de730b2709a0cb0773d3091f33c825a088eb29ee63b01f4de41352b328",
    EXCEPTION_TEMPLATE: "f793dc2d6f4009e6af64f708edb48369dd8843a92e424645d6b368ef3cc250ca",
    REPO_SKILL: "50dbeeff51a24a69c1e15d79f6fee73d4a584f83b1d5e69db69a9378885a2504",
    ADOPTER_CONTRACT: "5c99fa8bf576a2aa36719c11ace732a058fd395e7e86a83cdf7de952c29677b2",
}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_transition_policy_exact_artifacts_are_digest_guarded() -> None:
    for path, expected in EXPECTED_GOVERNANCE_SHA256.items():
        assert sha256(path.read_bytes()).hexdigest() == expected

    assert {path.name for path in EXCEPTION_DIR.iterdir() if path.is_file()} == {
        "README.md",
        "req-0005-r1-review-return-001.md",
    }


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
    assert "Active exceptions: 1" in index
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


def test_temporary_changes_requested_bridge_is_bounded_and_self_expiring() -> None:
    policy = _text(POLICY)

    for required in (
        "Temporary REQ review-return decision source:** `discord:1531284648511012916`",
        "Non-terminal REQ review return and same-revision amendment/resubmission",
        "`BOOTSTRAP_AUTHORITY_EXCEPTION` until implemented",
        "draft -> in_review -> changes_requested -> in_review -> approved",
        "`changes_requested` is non-authorizing and has the same permitted authoring work as `draft`",
        "`rejected` remains reserved for an accountable terminal decision that ends the proposal.",
        "do not create a canonical `rejected` review decision, rejection record, or reconsideration record",
        "monotonically increasing `n`th return count",
        "This informational log is not canonical evidence, carries no SHA-256 or authority semantics",
        "use `status: draft` as the temporary frontmatter compatibility representation",
        "Canonical changes_requested state: not recorded",
        "delete §5.1 and the temporary matrix row in the same reviewed policy change",
        "Do not retain this Bootstrap path as a fallback.",
    ):
        assert required in policy

    assert "one exact per-artifact `BOOTSTRAP_AUTHORITY_EXCEPTION`" in policy
    assert "same REQ revision" in policy
    assert "an explicit adoption decision and a new non-historical REQ canary complete the real loop" in policy
