---
schema_version: 1
id: ms-<id>-<slice>
kind: micro-spec
requirement:
  path: docs/requirements/req-<id>/req-<id>-r<revision>.md
  id: req-<id>
  revision: <revision>
  sha256: <exact-approved-req-sha256>
selected_acceptance_criteria: [AC-<id>]
---

# Micro-SPEC — REQ-<id> slice <slice>

> **Lifecycle boundary:** This human-readable planning artifact binds one exact approved REQ snapshot and a selected subset of its acceptance criteria. It is not an approval, iteration-QC, delivery-QC, merge decision, delivery decision, or release authority.

## Objective

State the bounded outcome.

## Scope

- State only the implementation/validation work for the selected ACs.

## Non-goals

- State explicitly excluded work and authority boundaries.

## Baseline

State the current verified behavior and relevant constraints.

## Verification plan

List focused, deterministic checks and expected results.

## QC exit rule

State the evidence required before this slice may claim verification.

## Rollback and containment

Required for a high-risk parent REQ; state the containment action if this slice fails.
