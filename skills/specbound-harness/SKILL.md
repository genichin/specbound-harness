---
name: specbound-harness
description: "Use when drafting or reviewing canonical Discovery artifacts, or validating SpecBound Discovery confirmation and REQ approval bindings before governed implementation or delivery claims."
version: 0.2.0
author: SpecBound Harness
license: MIT
metadata:
  hermes:
    tags: [governance, discovery, requirements, validation, ci, fail-closed]
    related_skills: []
---

# SpecBound Harness

## Overview

SpecBound is a provider-neutral, repository-local control-plane harness. It treats lifecycle claims as separately stored, content-addressed bindings rather than Markdown status labels. The CLI and CI own deterministic enforcement; this skill supplies an agent workflow but cannot itself confirm a Discovery or approve a REQ. Repository protection, CI review, and optional signed or external records provide any immutability guarantee.

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
docs/discoveries/dcy-<id>/disc-<id>-r<revision>.md
.specbound/discovery-confirmations/disc-<id>-r<revision>.confirmation.json
docs/requirements/req-<id>/req-<id>-r<revision>.md
.specbound/approvals/req-<id>-r<revision>.approval.json
```

The Discovery directory prefix `dcy-` and document ID prefix `disc-` intentionally differ. Never normalize them or place canonical lifecycle state in `temp/`.

## Draft Discovery workflow

1. Run `specbound context` and `specbound preflight` from the target repository before creating canonical artifacts.
2. Inspect the initiating issue/request, relevant repository state, related Discovery/REQ documents, and direct evidence. Separate verified facts, user intent, assumptions, and recommendations.
3. Determine whether the work is `new`, an update, follow-up, or superseding Discovery. Do not silently overwrite history. If the target or relationship is ambiguous, stop and ask the accountable user/owner.
4. Create or revise exactly `docs/discoveries/dcy-<id>/disc-<id>-r<revision>.md` from `templates/discovery.md`. Populate real frontmatter, including `risk_class`, and use typed `DECIDE`, `CONFIRM`, or `DATA` questions for unresolved material items.
5. Keep candidate requirement concerns explicitly non-binding. A Discovery must not contain REQ acceptance criteria, an implementation plan, an approval assertion, or merge/delivery/release authorization.
6. Before asking for confirmation, review intent, evidence, scope/non-goals, impact, risks/dependencies, decision ownership, open-question disposition, and REQ-drafting readiness. Replace generic placeholders with sourced content or a typed open question.
7. Set a reviewed candidate to `status: in_review`; do not write `confirmed` in its frontmatter or body. A separate authorized control-plane process creates the confirmation record.
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
2. The confirmation record binds its schema version (`1`), safe path, ID, revision, SHA-256 bytes digest, matching risk class, an allowlisted authority, an ISO-8601 time with timezone, `decision: confirmed`, and `permitted_next_action: draft_req_only`.
3. Never edit a hash-bound Discovery or approved REQ in place. Mint a new revision and a matching new control-plane record.
4. Run `specbound validate` before claiming a Discovery is confirmed or a REQ is approved.
5. Treat a non-zero result as blocked. Repair the source artifact or record; never bypass with tracker state, copied Markdown, or an unvalidated temporary file.

## Commands

Use the repository's reproducible interpreter:

```bash
.venv/bin/python -m specbound.cli context
.venv/bin/python -m specbound.cli preflight
.venv/bin/python -m specbound.cli validate
.venv/bin/python -m pytest
```

To test a repository explicitly, pass `--root` before the command:

```bash
.venv/bin/python -m specbound.cli --root /path/to/repository validate
```

## Current scope

The implemented bootstrap slice validates configuration, canonical non-symlink paths, Discovery frontmatter/evidence, content-addressed Discovery confirmation binding, canonical REQ paths/frontmatter, content-addressed approval binding, and SHA-256 digests. It does **not** validate Micro-SPECs, iteration evidence/QC, delivery QC, merge, release records, or external immutability provenance.

## Common pitfalls

1. **Treating `status: in_review` as confirmation.** A matching content-addressed confirmation record is also required.
2. **Editing a confirmed Discovery in place.** This creates a digest mismatch; create a new revision instead.
3. **Using the wrong Discovery directory prefix.** Canonical paths require `dcy-<id>/disc-<id>-r<revision>.md`.
4. **Over-authorizing the next action.** Discovery confirmation permits drafting a REQ only—not implementation, merge, delivery, or release.
5. **Using guidance as enforcement.** Run the CLI and CI; the skill cannot prove compliance.

## References

- `references/discovery-contract.md` — Discovery path, state, and confirmation binding contract.
- `references/adopter-contract.md` — complete bootstrap topology and blocker behavior.

## Verification checklist

- [ ] `specbound context` discovers the intended repository root.
- [ ] `specbound preflight` returns `valid: true`.
- [ ] Discovery path exactly uses `dcy-<id>/disc-<id>-r<revision>.md`.
- [ ] Confirmed Discovery has a matching content-addressed confirmation record and unchanged digest.
- [ ] Confirmation authorizes only `draft_req_only`.
- [ ] `specbound validate` returns `valid: true` with no blockers.
- [ ] Confirmed Discoveries and approved REQs have not been modified in place after digest binding.
