---
name: draft-req
description: "Use when issuing or preparing a canonical SpecBound REQ draft from a confirmed Discovery in this repository."
version: 1.0.0
author: SpecBound Harness
license: MIT
metadata:
  hermes:
    tags: [specbound, requirements, drafting, governance, fail-closed]
    related_skills: [specbound-harness, confirm-discovery, review-req]
---

# Draft Canonical REQs

## Overview

This repository issues REQ drafts only under `docs/requirements/` and binds each draft to an exact confirmed Discovery and its content-addressed confirmation record. The `specbound` CLI is enforcement authority; this skill is procedural guidance only.

## When to Use

Use this skill after a Discovery is confirmed and its confirmation permits `draft_req_only`, when a new canonical REQ draft is needed.

Do not use it to approve a REQ, create an approval record, change a REQ to `approved`, implement a REQ, merge, deliver, or release.

## Preconditions

1. Work from the repository root with its local virtualenv.
2. Confirm the parent exists at `.specbound/discoveries/dcy-<id>-r<revision>.md`.
3. Confirm its matching record exists at `.specbound/confirmations/dcy-<id>-r<revision>.confirmation.json`.
4. Run the executable checks; stop on any blocker:

```bash
.venv/bin/python -m specbound.cli preflight
.venv/bin/python -m specbound.cli validate
```

A Discovery confirmation authorizes only draft issuance. It does not authorize REQ approval or downstream work.

## Draft Workflow

1. Select exact targets: `dcy-<id>-r<revision>` and `req-<id>-r<revision>`.
2. Issue the draft only through the CLI:

```bash
.venv/bin/python -m specbound.cli req draft dcy-0001-r1 req-0002-r1
```

3. The command creates only:

```text
docs/requirements/req-0002/req-0002-r1.md
```

It refuses noncanonical identifiers, traversal, symlinked canonical paths, invalid parent evidence, missing confirmation records, stale parent digests, over-broad parent authorization, and existing targets.

4. Complete the generated document with an outcome, explicit scope, non-goals, risk/owner context, and any material open decisions. Preserve the generated parent binding exactly.
5. For **every** AC, replace all nine completion-contract placeholders before review:
   - `observable_success`
   - `required_preconditions`
   - `mutation_boundary`
   - `negative_behavior`
   - `direct_evidence`
   - `dependencies`
   - `completion_group`
   - `candidate_micro_spec`
   - `non_goals`

   Describe a directly observable success and the fail-closed behavior. Record every prerequisite or AC dependency explicitly. If multiple ACs cannot be completed and evidenced separately, give them the same `completion_group`, explain why, and do not imply that a partial group is implementation-ready.
6. Keep the draft as `status: draft`. Do not self-approve, write `.specbound/approvals/*.approval.json`, or mutate an approved revision. A separate accountable approval decision and matching approval record are required later.
7. Re-run:

```bash
.venv/bin/python -m specbound.cli validate
.venv/bin/python -m pytest
```

8. Submit only after deterministic readiness passes:

```bash
.venv/bin/python -m specbound.cli req check-readiness req-0002-r1
.venv/bin/python -m specbound.cli req to-in-review req-0002-r1
.venv/bin/python -m specbound.cli validate
```

`check-readiness` is read-only and grants no approval or implementation authority. `to-in-review` is the sole canonical, rollback-safe `draft → in_review` transition; it creates a non-authorizing record bound to exact draft and reviewed SHA-256 snapshots. `in_review` remains distinct from approval, implementation, merge, delivery, and release.

## Revision Rules

- A material scope, risk, acceptance-criteria, or lineage change requires a new numeric REQ revision.
- Never repair an approved REQ in place; mint a new revision.
- By default, only the latest numeric revision can be approved. Historical lower-revision approval needs a substantive authority-bound, timezone-bearing `supersession_exception`.
- A higher revision does not delete history or create approval authority by itself.

## Common Pitfalls

1. **Manual Markdown creation:** It can omit parent evidence. Use `specbound req draft` first.
2. **Treating a confirmed Discovery as implementation approval:** Confirmation permits only draft issuance.
3. **Overwriting a REQ:** Target paths are intentionally non-overwritable; create a new revision.
4. **Treating this skill as proof:** Only a passing CLI and validator result proves the repository contract.

## Verification Checklist

- [ ] `preflight` and `validate` passed before issuance.
- [ ] The CLI output names the expected canonical REQ path.
- [ ] Draft frontmatter is `status: draft` and has exact parent path, ID, revision, confirmation path, and SHA-256.
- [ ] The draft documents goal, scope, non-goals, risk, and deterministic acceptance criteria.
- [ ] Every AC completes `observable_success`, `required_preconditions`, `mutation_boundary`, `negative_behavior`, `direct_evidence`, `dependencies`, `completion_group`, `candidate_micro_spec`, and `non_goals`.
- [ ] An AC sharing a completion group does not claim that a partial group is independently implementation-ready.
- [ ] `check-readiness` passed before `to-in-review`; no manual status edit or hand-authored review-submission record was used.
- [ ] No approval record or `approved` status was created by the drafting workflow.
- [ ] Final `validate` and `pytest` passed.
