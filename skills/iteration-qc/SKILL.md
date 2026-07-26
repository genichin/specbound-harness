---
name: iteration-qc
description: Use when performing the repository-bound SpecBound iteration-qc role
  under the active machine policy; enforces exact inputs, minimum authority, evidence,
  and handoff boundaries.
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
    role_id: iteration-qc
    policy_path: .specbound/policies/agent-roles.yaml
    skill_path: skills/iteration-qc/SKILL.md
    task_kind: iteration-qc
    required_inputs:
    - implementation-result
    - reviewed-micro-spec
    - exact-target
    - current-state
    allowed_path_patterns:
    - .specbound/iteration-qc/req-*/iqc-*-*-r*.json
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
    - implemented
    result_references:
      producer_result_ref: required
      reviewer_run_ref: required
    permitted_next_actions:
    - request-delivery-qc
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

# iteration-qc

## Overview

The machine-readable role policy is authoritative; this skill is procedural guidance only.
This role must not perform self-review or self-approval.
This role never issues or claims confirmation, approval, review-decision, verified, delivery, canonical publication, Merge, Release, or external mutation authority.

## When to Use

Use this skill only for the `iteration-qc` task kind when repository-derived lifecycle state is one of: `implemented`.

## Required Inputs

- `implementation-result`
- `reviewed-micro-spec`
- `exact-target`
- `current-state`

## Allowed Operations

- Paths: `.specbound/iteration-qc/req-*/iqc-*-*-r*.json`
- Tool categories: `repository-read`, `candidate-write`, `test-execute`, `filesystem-metadata`
- Mutation classes: `evidence_write`
- Output kinds: `agent-result`
- Permitted next actions: `request-delivery-qc`, `request-rework`

## Forbidden Actions and Claims

- Forbidden actions: `authority-transition`, `canonical-publication`, `merge`, `release`, `external-mutation`, `next-role-selection`
- Forbidden claims: `confirmation`, `approval`, `review-decision`, `verified`, `delivery`
- Stop when an assignment would exceed any path, tool, mutation, output, lifecycle, reference, or action boundary.

## Procedure

1. Verify the exact implemented Micro-SPEC, producer result, and reviewer result.
2. Inspect and test without changing implementation paths.
3. Write only the bound Iteration-QC candidate evidence path.
4. Return an agent-result that requests delivery evidence or candidate rework.

## Verification

- Resolve `target-binding` as `required`; not-applicable is forbidden.
- Resolve `focused-verification` as `required`; not-applicable is forbidden.
- Resolve `regression-evidence` as `optional`; not-applicable is allowed with a substantive reason.
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
