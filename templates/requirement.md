---
id: req-<numeric-id>
revision: <positive-integer>
status: draft
risk: <parent-risk-class>
owner: <accountable-owner>
parent_discovery:
  id: dcy-<numeric-id>
  revision: <positive-integer>
  path: .specbound/discoveries/dcy-<numeric-id>-r<revision>.md
  sha256: <exact-confirmed-discovery-sha256>
  confirmation_path: .specbound/confirmations/dcy-<numeric-id>-r<revision>.confirmation.json
---

# REQ: <req-id> r<revision>

> **Lifecycle boundary:** This artifact's lifecycle state is determined only by frontmatter plus its matching content-addressed decision record. Draft issuance is not review, rejection, approval, or implementation authority.
>
> **Review decision:** An `in_review` REQ may be rejected only through `specbound req reject`; the CLI changes the REQ to `rejected` and atomically emits the matching canonical rejection record.

## Goal

<verifiable outcome>

## Scope

- <included behavior>

## Non-goals

- Approval issuance, implementation, merge, delivery, and release are separate actions.

## Acceptance criteria

- AC-001: <deterministic verification>

## Approval handoff

Review the exact draft separately; do not infer approval from issuance.
