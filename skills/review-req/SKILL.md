---
name: review-req
description: "Use when preparing, deciding, reconsidering, or approving a canonical SpecBound REQ through digest-bound repository CLI controls."
version: 1.1.0
author: SpecBound Harness
license: MIT
metadata:
  hermes:
    tags: [specbound, requirements, review, rejection, fail-closed]
    related_skills: [draft-req]
---

# Prepare or Reject a Canonical REQ

## Scope

Use this skill to prepare or decide the review of an exact canonical REQ. It is procedural guidance; `specbound` CLI output and `validate` are the enforcement evidence.

This workflow does **not** approve REQs, write approval records, implement work, merge, deliver, or release.

## Review preparation and submission

1. The handoff owner first runs the read-only readiness check:
   ```bash
   .venv/bin/python -m specbound.cli req check-readiness req-0002-r1
   ```
   Passing readiness proves only deterministic structural completeness: exact confirmed-parent binding, substantive AC completion contracts, dependency and candidate Micro-SPEC closure, bounded completion groups, and no unresolved high-risk `DECIDE`. It grants no decision or implementation authority.
2. Only then submit via the canonical transition:
   ```bash
   .venv/bin/python -m specbound.cli req to-in-review req-0002-r1
   ```
   The command rechecks readiness, performs the rollback-safe `draft → in_review` change, and issues one non-overwritable `.specbound/review-submissions/req-<id>-r<revision>.review-submission.json` record. The record binds exact `draft_sha256` and `reviewed_sha256`, is non-authorizing, and sets `permitted_next_action: review_decision_only`.
3. Never manually patch `status` or create the submission record. If any publication or post-write validation fails, no partial handoff may remain.

## Decision evidence and rejection preconditions

1. Work at the repository root using the local virtualenv.
2. Identify the exact target `req-<id>-r<revision>` and validate its canonical submission digest.
3. Lifecycle status is determined only by canonical frontmatter plus a matching digest-bound control-plane record. Narrative text about a future draft, a successor, or a later handoff is **not** a lifecycle-state blocker.
4. Before rejection, issue an append-only review-decision record that binds the exact reviewed SHA-256, an allowlisted authority, a structured blocker code, concrete evidence path/command, and a substantive reason. A prose interpretation without machine-checkable evidence must not be recorded as a rejection blocker.
5. Use an authority allowlisted for the REQ risk in `specbound.yaml`. Review/reconsideration/approval authority is distinct from implementation, remediation, merge, delivery, and release authority.
6. Confirm the repository passes validation before deciding:

```bash
.venv/bin/python -m specbound.cli preflight
.venv/bin/python -m specbound.cli validate
```

## Rejection

Use only the CLI. Do not manually edit `status`, and do not manually create a rejection JSON record.

```bash
.venv/bin/python -m specbound.cli req reject req-0002-r1 \
  --authority "independent-advanced-llm-reviewer" \
  --reason "<specific review finding>"
```

On success, the command atomically:

1. checks the exact REQ is `in_review`;
2. binds the pre-transition SHA-256;
3. changes the REQ to `status: rejected`;
4. writes `.specbound/rejections/req-<id>-r<revision>.rejection.json` with the reviewed and rejected SHA-256 values, authority, timestamp, decision, risk, and reason;
5. validates the generated result.

## Reconsideration and approval

Rejection, reconsideration, and approval evidence is append-only. Never delete or rewrite an original review-submission, review-decision, or rejection record to change an outcome.

1. A reconsideration must bind the original rejection SHA-256, the original reviewed SHA-256, the reopened `in_review` SHA-256, an allowlisted reconsideration authority, timestamp, and substantive reversal reason.
2. Reopening restores only the review lifecycle state. It does not resolve an implementation blocker or authorize remediation, merge, delivery, release, or adoption.
3. Approval requires a separate `approval_ready` review-decision for the exact reopened snapshot. It must bind both the reviewed SHA-256 and final approved SHA-256. Any post-write validation failure must restore the pre-approval `in_review` file and remove only the newly written approval record.
4. When a later revision is approved, preserve earlier approval records as immutable history. Express supersession only in the newer forward-binding record; never mutate historical approval evidence to make it pass a new rule.

## Fail-closed rules

The command must refuse and leave no partial decision if the target is noncanonical, missing, not `in_review`, already rejected, has an approval record, has an existing rejection record, has an unsafe/symlinked canonical path, uses an unallowlisted authority, has a placeholder reason, or the repository does not already validate.

## Verification

```bash
.venv/bin/python -m specbound.cli validate
.venv/bin/python -m pytest -q
```

A valid result has no blockers. A rejected REQ is not counted as an approved requirement.
