---
name: review-req
description: "Use when rejecting an in-review canonical SpecBound REQ through the repository CLI."
version: 1.0.0
author: SpecBound Harness
license: MIT
metadata:
  hermes:
    tags: [specbound, requirements, review, rejection, fail-closed]
    related_skills: [draft-req]
---

# Reject a Canonical REQ

## Scope

Use this skill only to reject an exact `status: in_review` canonical REQ. It is procedural guidance; `specbound` CLI output and `validate` are the enforcement evidence.

This workflow does **not** approve REQs, write approval records, implement work, merge, deliver, or release.

## Preconditions

1. Work at the repository root using the local virtualenv.
2. Identify the exact target `req-<id>-r<revision>`.
3. Provide a substantive, non-placeholder reason.
4. Use an authority allowlisted for the REQ risk in `specbound.yaml`.
5. Confirm the repository passes validation before deciding:

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

## Fail-closed rules

The command must refuse and leave no partial decision if the target is noncanonical, missing, not `in_review`, already rejected, has an approval record, has an existing rejection record, has an unsafe/symlinked canonical path, uses an unallowlisted authority, has a placeholder reason, or the repository does not already validate.

## Verification

```bash
.venv/bin/python -m specbound.cli validate
.venv/bin/python -m pytest -q
```

A valid result has no blockers. A rejected REQ is not counted as an approved requirement.
