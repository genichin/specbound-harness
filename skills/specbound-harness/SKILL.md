---
name: specbound-harness
description: "Use when drafting or reviewing canonical Discovery/REQ artifacts, or validating SpecBound confirmation, approval, and rejection bindings before governed implementation or delivery claims."
version: 0.8.0
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

## When to Use

Use this skill when:

- drafting or revising a repository-local Discovery;
- reviewing Discovery evidence, lineage, risk, and REQ-drafting readiness;
- validating a Discovery confirmation or REQ approval binding;
- diagnosing a SpecBound blocker in CI or locally; or
- preparing an adopting repository for the implemented bootstrap slice.

Do not use it as a substitute for an explicit confirmation/approval record, authorized actor, or passing `specbound validate` result.

## Canonical topology

```text
specbound.yaml
.specbound/discoveries/dcy-<id>-r<revision>.md
.specbound/confirmations/dcy-<id>-r<revision>.confirmation.json
docs/requirements/req-<id>/req-<id>-r<revision>.md
.specbound/approvals/req-<id>-r<revision>.approval.json
.specbound/rejections/req-<id>-r<revision>.rejection.json
.specbound/micro-specs/req-<id>/ms-<id>-<slice>.md
.specbound/iteration-qc/req-<id>/iqc-<id>-<slice>-r<revision>.json
.specbound/delivery-qc/dqc-<id>-r<revision>.json
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

Use the repository's reproducible interpreter:

```bash
.venv/bin/python -m specbound.cli context
.venv/bin/python -m specbound.cli preflight
.venv/bin/python -m specbound.cli validate
.venv/bin/python -m specbound.cli discovery confirm dcy-0001-r1 --authority repository-maintainer
.venv/bin/python -m specbound.cli req reject req-0002-r1 --authority independent-advanced-llm-reviewer --reason "<substantive review finding>"
.venv/bin/python -m pytest
```

To test a repository explicitly, pass `--root` before the command:

```bash
.venv/bin/python -m specbound.cli --root /path/to/repository validate
```

## Current scope

The implemented bootstrap slice validates configuration, canonical non-symlink paths, Discovery frontmatter/evidence, content-addressed Discovery confirmation binding, canonical REQ paths/frontmatter, content-addressed approval and rejection bindings, and SHA-256 digests. Canonical Micro-SPECs at `.specbound/micro-specs/req-<id>/ms-<id>-<slice>.md` additionally require the exact approved parent REQ path/ID/revision/SHA-256 binding, a unique non-empty subset of the parent’s listed `AC-<id>` values, and substantive objective/scope/non-goals/baseline/verification/QC-exit planning sections (plus rollback/containment for high-risk parents):

```yaml
requirement:
  path: docs/requirements/req-<id>/req-<id>-r<revision>.md
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
- [ ] Confirmed Discoveries and approved REQs have not been modified in place after digest binding.
