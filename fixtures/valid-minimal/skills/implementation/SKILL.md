---
name: implementation
description: Use when performing the repository-bound SpecBound implementation role
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
    role_id: implementation
    policy_path: .specbound/policies/agent-roles.yaml
    skill_path: skills/implementation/SKILL.md
    task_kind: implementation
    required_inputs:
    - reviewed-micro-spec
    - review-record
    - exact-target
    - current-state
    allowed_path_patterns:
    - '@reviewed-micro-spec-scope'
    allowed_tool_categories:
    - repository-read
    - candidate-write
    - test-execute
    - filesystem-metadata
    mutation_classes:
    - repository_mutation
    output_kinds:
    - agent-result
    lifecycle_eligibility:
    - approved_for_implementation
    result_references:
      producer_result_ref: optional
      reviewer_run_ref: required
    permitted_next_actions:
    - request-iteration-qc
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

# implementation

## Overview

The machine-readable role policy is authoritative; this skill is procedural guidance only.
This role must not perform self-review or self-approval.
This role never issues or claims confirmation, approval, review-decision, verified, delivery, canonical publication, Merge, Release, or external mutation authority.

## When to Use

Use this skill only for the `implementation` task kind when repository-derived lifecycle state is one of: `approved_for_implementation`.

## Required Inputs

- `reviewed-micro-spec`
- `review-record`
- `exact-target`
- `current-state`

## Allowed Operations

- Paths: `@reviewed-micro-spec-scope`
- Tool categories: `repository-read`, `candidate-write`, `test-execute`, `filesystem-metadata`
- Mutation classes: `repository_mutation`
- Output kinds: `agent-result`
- Permitted next actions: `request-iteration-qc`

## Forbidden Actions and Claims

- Forbidden actions: `authority-transition`, `canonical-publication`, `merge`, `release`, `external-mutation`, `next-role-selection`
- Forbidden claims: `confirmation`, `approval`, `review-decision`, `verified`, `delivery`
- Stop when an assignment would exceed any path, tool, mutation, output, lifecycle, reference, or action boundary.

## Procedure

1. Verify the exact approved-for-implementation Micro-SPEC and reviewer result.
2. Change only paths allowed by the reviewed Micro-SPEC and role policy.
3. Run focused tests and record the complete changed-path rollback inventory.
4. Return an agent-result that requests Iteration-QC or implementation rework.

## Verification

- Resolve `target-binding` as `required`; not-applicable is forbidden.
- Resolve `test-results` as `required`; not-applicable is forbidden.
- Resolve `rollback-inventory` as `required`; not-applicable is forbidden.
- Resolve `negative-tests` as `optional`; not-applicable is allowed with a substantive reason.
- Resolve `regression-evidence` as `optional`; not-applicable is allowed with a substantive reason.
- Resolve `supported-ci` as `optional`; not-applicable is allowed with a substantive reason.
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
