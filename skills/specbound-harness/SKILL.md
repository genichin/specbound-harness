---
name: specbound-harness
description: "Use when drafting or reviewing canonical Discovery/REQ artifacts, or validating SpecBound confirmation, approval, and rejection bindings before governed implementation or delivery claims."
version: 0.9.0
author: SpecBound Harness
license: MIT
metadata:
  hermes:
    tags: [governance, discovery, requirements, validation, ci, fail-closed]
    related_skills: [confirm-discovery, draft-req, review-req]
---

# SpecBound Harness

## Overview

SpecBound is a provider-neutral, repository-local control-plane harness. It treats lifecycle claims as separately stored, content-addressed bindings rather than Markdown status labels. The CLI and CI own deterministic enforcement; `confirm-discovery` governs the explicit human authorization boundary before the CLI creates a Discovery record. Repository protection, CI review, and optional signed or external records provide any immutability guarantee.

### Agent-contract boundary

The opt-in, provider-neutral agent contract defines exactly seven roles. A configured Hermes adapter maps each invocation to one configured model alias, the role's exact skill bytes, and a fresh isolated one-shot context; the portable request/result schemas contain no Hermes, provider, profile, session, or workdir fields. When the contract is disabled, the manual lifecycle workflow remains valid without agent policy or role-skill artifacts. Validation is read-only and non-authorizing: neither a valid envelope nor a successful dispatch may issue confirmation, approval, review-decision, verified, Delivery, Merge, or Release authority. Enabling repository validation is not a live Hermes rollout; runtime rollout and credentials remain a separate explicit operator action.

The executable contract is repository-backed. `policy.agent_contract` selects the
policy at `.specbound/policies/agent-roles.yaml`; every policy role binds one
exact `skills/<role-id>/SKILL.md` file and its SHA-256. Adopter templates remain
default-disabled, while this harness enables the same contract for dogfood
validation:

```yaml
policy:
  agent_contract:
    enabled: false  # true only after the repository owns the policy and all role skills
    roles_path: .specbound/policies/agent-roles.yaml
```

The closed version-one role inventory is exactly:

```text
discovery-author
requirement-author
micro-spec-author
independent-reviewer
implementation
iteration-qc
delivery-qc
```

These are logical roles, not seven persistent profiles. The existing manual
lifecycle skills remain separate guidance and are not members of this inventory.

## When to Use

Use this skill when:

- drafting or revising a repository-local Discovery;
- reviewing Discovery evidence, lineage, risk, and REQ-drafting readiness;
- validating a Discovery confirmation or REQ approval binding;
- diagnosing a SpecBound blocker in CI or locally; or
- preparing an adopting repository for the implemented control-plane slice.

Do not use it as a substitute for an explicit confirmation/approval record, authorized actor, or passing `specbound validate` result.

## Canonical topology

```text
specbound.yaml
.specbound/discoveries/dcy-<id>-r<revision>.md
.specbound/confirmations/dcy-<id>-r<revision>.confirmation.json
.specbound/requirements/req-<id>/req-<id>-r<revision>.md
.specbound/review-submissions/req-<id>-r<revision>.review-submission.json
.specbound/review-decisions/req-<id>-r<revision>.review-decision.json
.specbound/rejections/req-<id>-r<revision>.rejection.json
.specbound/reconsiderations/req-<id>-r<revision>.reconsideration.json
.specbound/approvals/req-<id>-r<revision>.approval.json
.specbound/policies/agent-roles.yaml
skills/<role-id>/SKILL.md
.specbound/micro-specs/req-<id>/ms-<id>-<slice>.md
.specbound/micro-spec-reviews/req-<id>/ms-<id>-<slice>.review.json
.specbound/iteration-qc/req-<id>/iqc-<id>-<slice>-r<revision>.json
.specbound/delivery-qc/dqc-<id>-r<revision>.json
docs/requirements.md  # generated user-facing projection; never canonical
```

Discovery IDs and filenames use the single lowercase `dcy-` prefix. Never place canonical lifecycle state in `temp/`.

## Draft Discovery workflow

1. Run `specbound context` and `specbound preflight` from the target repository before creating canonical artifacts.
2. Inspect the initiating issue/request, relevant repository state, related Discovery/REQ documents, and direct evidence. Separate verified facts, user intent, assumptions, and recommendations.
3. Determine whether the work is `new`, an update, follow-up, or superseding Discovery. Do not silently overwrite history. If the target or relationship is ambiguous, stop and ask the accountable user/owner.
4. Create or revise exactly `.specbound/discoveries/dcy-<id>-r<revision>.md` from `templates/discovery.md`. Populate real frontmatter, including `risk_class`, and use typed `DECIDE`, `CONFIRM`, or `DATA` questions for unresolved material items.
5. Keep candidate requirement concerns explicitly non-binding. A Discovery must not contain REQ acceptance criteria, an implementation plan, an approval assertion, or merge/delivery/release authorization.
6. Before asking for confirmation, review intent, evidence, scope/non-goals, impact, risks/dependencies, decision ownership, open-question disposition, and REQ-drafting readiness. Replace generic placeholders with sourced content or a typed open question.
7. Set a reviewed candidate to `status: in_review`. After an explicit accountable decision, use `confirm-discovery`; the CLI atomically changes only that frontmatter field to `status: confirmed` and writes the matching record.
8. Run `specbound validate`. A non-zero result blocks a confirmation or governed claim.

### Drafting authority boundary

A drafting agent may create or update a **draft** Discovery. It may not:

- self-confirm a Discovery;
- create or sign a Discovery confirmation record without an authorized decision;
- claim that REQ drafting is permitted without a matching, valid confirmation record;
- convert Discovery hypotheses into approved REQ scope; or
- authorize implementation, merge, delivery, or release.

A valid confirmation authorizes only `draft_req_only`. It is not a REQ approval.

## Confirmation and approval workflow

1. A confirmer reviews the exact `in_review` Discovery snapshot.
2. After explicit authorization, run `specbound discovery confirm dcy-<id>-r<revision> --authority <allowlisted-authority>`. The CLI atomically changes `status: in_review` to `status: confirmed`, then writes a record binding schema version (`1`), safe path, ID, revision, the pre-transition `reviewed_sha256`, final confirmed-byte `sha256`, matching risk class, authority, time, `decision: confirmed`, and `permitted_next_action: draft_req_only`.
3. The `latest_only_with_explicit_exception` policy rejects issuance for a lower revision while a newer revision exists unless a substantive `--supersession-exception` is recorded.
4. After confirmation, never edit the hash-bound Discovery in place. Mint a new revision and a matching new control-plane record for any later change.
5. Run `specbound validate` before claiming a Discovery is confirmed or a REQ is approved.
6. Treat a non-zero result as blocked. Repair the source artifact or record; never bypass with tracker state, copied Markdown, or an unvalidated temporary file.

## Commands

The three public, read-only agent-contract surfaces are `specbound agent validate-skills`,
`specbound agent check-role-request`, and `specbound agent validate-result`. They validate
repository-owned inputs and never dispatch an agent or issue authority.

Use the repository's reproducible interpreter:

```bash
.venv/bin/python -m specbound.cli context
.venv/bin/python -m specbound.cli preflight
.venv/bin/python -m specbound.cli validate
.venv/bin/python -m specbound.cli agent validate-skills
.venv/bin/python -m specbound.cli agent check-role-request --request-file <request.json> --reference-result-file <result.json>
.venv/bin/python -m specbound.cli agent validate-result --result-file <result.json>
.venv/bin/python -m specbound.cli docs requirements --check
.venv/bin/python -m specbound.cli discovery confirm dcy-0001-r1 --authority repository-maintainer
.venv/bin/python -m specbound.cli req reject req-0002-r1 --authority independent-advanced-llm-reviewer --reason "<substantive review finding>"
.venv/bin/python -m pytest
```

To test a repository explicitly, pass `--root` before the command:

```bash
.venv/bin/python -m specbound.cli --root /path/to/repository validate
```

### Installed-wheel verification

Source success does not prove the shipped package. Build and install the wheel
non-editably into a disposable environment, clear source overrides, and execute
outside the checkout. Both `specbound.agent_contract.__file__` and
`specbound.hermes_adapter.__file__` must resolve under that environment's
`site-packages`, never repository `src/`. Compare the installed package bytes
for `agent-roles`, `agent-result`, `hermes-adapter-config`, and
`hermes-invocation` schemas with the repository schemas before running the same
integration and adapter suites.

```bash
python -m pip wheel --wheel-dir dist ".[test]"
python -m venv /tmp/specbound-wheel
/tmp/specbound-wheel/bin/pip install --no-index --find-links dist specbound pytest
unset PYTHONPATH
cd /tmp
/tmp/specbound-wheel/bin/python -I -c "import specbound.agent_contract as a, specbound.hermes_adapter as h; print(a.__file__); print(h.__file__); assert 'site-packages' in a.__file__; assert 'site-packages' in h.__file__"
/tmp/specbound-wheel/bin/python -I -m pytest -c /dev/null -q /path/to/repository/tests/test_agent_integration.py /path/to/repository/tests/test_hermes_adapter.py
```

This procedure is verification evidence only. It does not dispatch an agent or
authorize a lifecycle transition.

## Current scope

When operating inside the `specbound-harness` source repository and `docs/governance/bootstrap-to-canonical-transition.md` exists, follow that repository-local **Bootstrap-to-Canonical Transition Policy** before starting or advancing lifecycle work. It makes implemented and applicable canonical gates mandatory, blocks unsupported transitions unless an exact accountable Bootstrap exception is active, and limits break-glass to a reproducible control-plane defect or supported-platform unavailability. It cannot bypass invalid candidate bytes, missing evidence, stale bindings, insufficient authority, or out-of-scope work. Preserve advisory and historical Bootstrap labels, and report `Canonical state: not recorded` whenever the canonical transition did not execute.

When this reusable skill is used in an adopting repository, the `specbound-harness` transition policy does not apply and must not be inferred, copied, or treated as authority. Follow only the adopter contract plus that repository's own explicit governance and adoption decisions; a nonexistent `docs/governance/bootstrap-to-canonical-transition.md` is not a blocker for adopters.

The implemented control-plane slice validates configuration, canonical non-symlink paths, Discovery frontmatter/evidence, content-addressed Discovery confirmation binding, canonical REQ paths/frontmatter, content-addressed approval and rejection bindings, and SHA-256 digests. Canonical Micro-SPECs at `.specbound/micro-specs/req-<id>/ms-<id>-<slice>.md` additionally require the exact approved parent REQ path/ID/revision/SHA-256 binding, a unique non-empty subset of the parent’s listed `AC-<id>` values, and substantive objective/scope/non-goals/baseline/verification/QC-exit planning sections (plus rollback/containment for high-risk parents):

```yaml
requirement:
  path: .specbound/requirements/req-<id>/req-<id>-r<revision>.md
  id: req-<id>
  revision: <revision>
  sha256: <exact-approved-req-sha256>
selected_acceptance_criteria: [AC-<id>]
```

Iteration-QC at `.specbound/iteration-qc/req-<id>/iqc-<id>-<slice>-r<revision>.json` must bind the filename-derived canonical Micro-SPEC path/ID and its exact SHA-256, exactly preserve the Micro-SPEC selected AC list, provide one or more focused `{command, result, exit_code}` evidence entries, use only `verified`, `rework`, or `blocked`, and enumerate exactly the parent REQ ACs not selected by that Micro-SPEC. `verified` requires all focused evidence to be `passed` with exit code 0. Delivery-QC at `.specbound/delivery-qc/dqc-<id>-r<revision>.json` must bind the exact approved REQ path/ID/revision/SHA-256 snapshot, map every REQ AC to an exact verified canonical iteration-QC snapshot, retain passing cross-iteration regression evidence, use a risk-policy allowlisted QC authority, and state unresolved exceptions plus residual-risk disposition. Strict fields make merge, delivery, release, and authorization claims invalid in a delivery-QC. These records prove evidence only; none issue approval or authorize delivery, merge, or release. Canonical QC absence remains compatible by default. To make an iteration or delivery claim, first record an exact approved REQ snapshot in version-one `policy.control_plane_adoption`, then run `specbound validate --claim iteration --requirement req-<id>-r<revision>` or `specbound validate --claim delivery --requirement req-<id>-r<revision>`. These claim checks fail closed for their selected claim if adoption or the corresponding canonical evidence is missing/invalid; adoption never reclassifies manual-bootstrap records.

## Common pitfalls

1. **Treating `status: confirmed` as sufficient proof.** The matching content-addressed confirmation record is also required.
2. **Editing a confirmed Discovery in place.** This creates a digest mismatch; create a new revision instead.
3. **Using an obsolete Discovery path or filename.** Canonical paths require `.specbound/discoveries/dcy-<id>-r<revision>.md`.
4. **Over-authorizing the next action.** Discovery confirmation permits drafting a REQ only—not implementation, merge, delivery, or release.
5. **Using guidance as enforcement.** Run the CLI and CI; the skill cannot prove compliance.
6. **Confirming a lower revision without disclosure.** The CLI rejects it by default; a substantive supersession exception is required.
7. **Allowing a full root filesystem to invalidate test evidence.** If pytest fails with `OSError: [Errno 28] No space left on device` while creating `tmp_path` fixtures, do not interpret it as a contract failure. Re-run with an isolated memory-backed base, for example `rm -rf /dev/shm/specbound-pytest && .venv/bin/python -m pytest -q --basetemp=/dev/shm/specbound-pytest`, preserve the actual exit status, then remove that temporary directory. This does not relax any SpecBound validation requirement.

## References

- `references/discovery-contract.md` — Discovery path, state, and confirmation binding contract.
- `references/adopter-contract.md` — complete bootstrap topology and blocker behavior.

## Verification checklist

- [ ] `specbound context` discovers the intended repository root.
- [ ] `specbound preflight` returns `valid: true`.
- [ ] Discovery path exactly uses `.specbound/discoveries/dcy-<id>-r<revision>.md`.
- [ ] Confirmed Discovery has a matching content-addressed confirmation record and unchanged digest.
- [ ] Confirmation authorizes only `draft_req_only`.
- [ ] `specbound validate` returns `valid: true` with no blockers.
- [ ] `specbound docs requirements --check` confirms the user-facing list matches canonical REQ metadata.
- [ ] Confirmed Discoveries and approved REQs have not been modified in place after digest binding.
