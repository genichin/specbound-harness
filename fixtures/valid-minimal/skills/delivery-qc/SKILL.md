---
name: delivery-qc
description: Use when performing the repository-bound SpecBound delivery-qc role under
  the active machine policy; enforces exact inputs, minimum authority, evidence, and
  handoff boundaries.
version: 1.0.0
author: SpecBound Maintainers
license: Apache-2.0
metadata:
  hermes:
    tags:
    - specbound
    - governance
    - role-contract
    related_skills:
    - specbound-harness
  specbound:
    schema_version: 1
    role_id: delivery-qc
    policy_path: .specbound/policies/agent-roles.yaml
    skill_path: skills/delivery-qc/SKILL.md
    task_kind: delivery-qc
    required_inputs:
    - verified-iteration-qc-set
    - approved-requirement
    - exact-target
    - current-state
    allowed_path_patterns:
    - .specbound/delivery-qc/dqc-*-r*.json
    allowed_tool_categories:
    - repository-read
    - candidate-write
    - test-execute
    - filesystem-metadata
    mutation_classes:
    - evidence_write
    output_kinds:
    - agent-result
    lifecycle_eligibility:
    - approved
    result_references:
      producer_result_ref: forbidden
      reviewer_run_ref: forbidden
    permitted_next_actions:
    - request-delivery-decision
    - request-rework
    forbidden_actions:
    - authority-transition
    - canonical-publication
    - merge
    - release
    - external-mutation
    - next-role-selection
    forbidden_claims:
    - confirmation
    - approval
    - review-decision
    - verified
    - delivery
    authority_type: none
    self_review: false
    self_approval: false
---

# delivery-qc

## Overview

The machine-readable role policy is authoritative; this skill is procedural guidance only.
This role must not perform self-review or self-approval.
This role never issues or claims confirmation, approval, review-decision, verified, delivery, canonical publication, Merge, Release, or external mutation authority.

## When to Use

Use this skill only for the `delivery-qc` task kind when repository-derived lifecycle state is one of: `approved`.

## Required Inputs

- `verified-iteration-qc-set`
- `approved-requirement`
- `exact-target`
- `current-state`

## Allowed Operations

- Paths: `.specbound/delivery-qc/dqc-*-r*.json`
- Tool categories: `repository-read`, `candidate-write`, `test-execute`, `filesystem-metadata`
- Mutation classes: `evidence_write`
- Output kinds: `agent-result`
- Permitted next actions: `request-delivery-decision`, `request-rework`

## Forbidden Actions and Claims

- Forbidden actions: `authority-transition`, `canonical-publication`, `merge`, `release`, `external-mutation`, `next-role-selection`
- Forbidden claims: `confirmation`, `approval`, `review-decision`, `verified`, `delivery`
- Stop when an assignment would exceed any path, tool, mutation, output, lifecycle, reference, or action boundary.

## Procedure

1. Verify the approved Requirement and complete exact verified Iteration-QC set.
2. Check complete acceptance-criterion coverage and regressions.
3. Write only the bound Delivery-QC candidate evidence path.
4. Return an agent-result that requests a separate Delivery decision or rework.

## Verification

- Resolve `target-binding` as `required`; not-applicable is forbidden.
- Resolve `complete-ac-coverage` as `required`; not-applicable is forbidden.
- Resolve `regression-evidence` as `required`; not-applicable is forbidden.
- Bind every artifact reference to its exact repository path, identity, revision, and SHA-256.
- Ensure the result uses only policy-permitted capabilities and contains no forbidden claims.

## Rework and Blocked

Return rework only through a policy-listed rework action. Return blocked with concrete missing input or policy conflict evidence; do not select the next role or mutate authority-owned records.

## Completion Checklist

- [ ] Exact target and required inputs are bound.
- [ ] Paths, tools, mutations, output, references, and lifecycle state remain within policy.
- [ ] Required evidence slots are resolved.
- [ ] Self-review, self-approval, authority actions, and forbidden claims are absent.
- [ ] The agent-result requests only a permitted next action.
