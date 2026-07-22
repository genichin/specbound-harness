---
name: confirm-discovery
description: "Use when an accountable user or repository authority has explicitly decided to confirm one exact SpecBound Discovery revision."
version: 1.1.0
author: SpecBound Harness
license: MIT
metadata:
  hermes:
    tags: [governance, discovery, confirmation, specbound, fail-closed]
    related_skills: [specbound-harness]
---

# Confirm Discovery

## Overview

This workflow turns an explicit, accountable confirmation decision into a rollback-safe lifecycle transition: it changes one exact `in_review` SpecBound Discovery to `confirmed` and creates its non-overwritable, content-addressed confirmation record. It does not decide whether a Discovery should be confirmed, elevate an agent to an authority, or authorize implementation. A successful record permits only `draft_req_only`.

## When to Use

Use this skill only when all of these are true:

- the exact target is named as `dcy-<id>-r<revision>`;
- the Discovery is ready for review and has an accountable human/role decision; and
- the user has explicitly supplied the confirmation authority to record.

Do not use it to confirm a draft, infer approval from silence, record an agent's own recommendation, overwrite an existing record, or authorize REQ approval, implementation, merge, delivery, or release.

## Required authorization boundary

Before invoking the command, obtain an explicit statement that identifies all three:

```text
Confirm dcy-0001-r2 as <allowlisted-authority>.
```

If the target, authority, scope, risks, unresolved questions, or intended next action are ambiguous, stop. Ask the accountable user/owner; do not manufacture a confirmation record.

The CLI records the asserted authority and validates it against repository policy. It does not independently prove the actor's identity or provide an external immutability guarantee.

## Workflow

1. Discover the target repository and inspect the exact revision:

   ```bash
   .venv/bin/python -m specbound.cli context
   .venv/bin/python -m specbound.cli preflight
   .venv/bin/python -m specbound.cli validate
   ```

2. Verify the target is exactly `.specbound/discoveries/dcy-<id>-r<revision>.md`, has `status: in_review`, and is the snapshot the authority reviewed. Present its scope, non-goals, risks, open questions, readiness recommendation, and the fact that confirmation authorizes only REQ drafting.

3. Confirm the authority is allowlisted for the document's `risk_class` in `specbound.yaml`.

4. After explicit authorization, run the command. It verifies the reviewed source, changes only `status: in_review` to `status: confirmed`, calculates `reviewed_sha256` for the prior bytes and `sha256` for the final bytes, and creates the record. If record creation or final validation fails, it restores the original source.

   ```bash
   .venv/bin/python -m specbound.cli discovery confirm dcy-0001-r2 \
     --authority repository-maintainer
   ```

5. Re-run validation and report the generated path. A successful result is expected at:

   ```text
   .specbound/confirmations/dcy-0001-r2.confirmation.json
   ```

## Revision policy

The default policy is `latest_only_with_explicit_exception`.

- When `dcy-0001-r2.md` exists, the CLI refuses to newly confirm `dcy-0001-r1`.
- It does not overwrite, erase, or retroactively falsify an existing historical `r1` record.
- A lower revision requires an explicit, substantive exception reason:

  ```bash
  .venv/bin/python -m specbound.cli discovery confirm dcy-0001-r1 \
    --authority repository-maintainer \
    --supersession-exception "Required historical baseline for a migration audit."
  ```

The exception is stored with its reason, authority, and timestamp in the generated record. It is an auditable exception to issuance policy—not a claim that the lower revision is the current preferred scope.

## Common pitfalls

1. **Treating `status: confirmed` as sufficient proof.** The matching exact-byte record is required too.
2. **Confirming an unspecified revision.** Always use the complete `dcy-<id>-r<revision>` target.
3. **Editing after confirmation.** This breaks the SHA-256 binding. Mint a new revision instead.
4. **Bypassing a newer revision.** Use a substantive exception only for an accountable historical/audit need; never as a shortcut around review.
5. **Treating confirmation as approval.** `draft_req_only` does not authorize a REQ, implementation, merge, delivery, or release.

## Verification checklist

- [ ] The authorization names the exact Discovery revision and authority.
- [ ] `specbound preflight` and `specbound validate` pass before confirmation.
- [ ] The command transitioned the target from `in_review` to `confirmed`, and the selected authority is allowlisted for its risk class.
- [ ] The CLI reports the expected non-overwritable confirmation path.
- [ ] `specbound validate` passes after creation.
- [ ] Any lower-revision exception is substantive and recorded explicitly.
