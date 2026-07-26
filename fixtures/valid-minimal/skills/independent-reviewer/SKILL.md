---
name: independent-reviewer
description: Use when performing the repository-bound SpecBound independent-reviewer
  role under the active machine policy; enforces exact inputs, minimum authority,
  evidence, and handoff boundaries.
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
    role_id: independent-reviewer
    policy_path: .specbound/policies/agent-roles.yaml
    skill_path: skills/independent-reviewer/SKILL.md
    task_kind: independent-reviewer
    required_inputs:
    - producer-result
    - exact-target
    - current-state
    allowed_path_patterns: []
    allowed_tool_categories:
    - repository-read
    mutation_classes:
    - none
    output_kinds:
    - agent-result
    lifecycle_eligibility:
    - in_review
    result_references:
      producer_result_ref: required
      reviewer_run_ref: forbidden
    permitted_next_actions:
    - request-authority-action
    - request-candidate-rework
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

# independent-reviewer

## Overview

The machine-readable role policy is authoritative; this skill is procedural guidance only.
This role must not perform self-review or self-approval.
This role never issues or claims confirmation, approval, review-decision, verified, delivery, canonical publication, Merge, Release, or external mutation authority.

## When to Use

Use this skill only for the `independent-reviewer` task kind when repository-derived lifecycle state is one of: `in_review`.

## Required Inputs

- `producer-result`
- `exact-target`
- `current-state`

## Allowed Operations

- Paths: `none`
- Tool categories: `repository-read`
- Mutation classes: `none`
- Output kinds: `agent-result`
- Permitted next actions: `request-authority-action`, `request-candidate-rework`

## Forbidden Actions and Claims

- Forbidden actions: `authority-transition`, `canonical-publication`, `merge`, `release`, `external-mutation`, `next-role-selection`
- Forbidden claims: `confirmation`, `approval`, `review-decision`, `verified`, `delivery`
- Stop when an assignment would exceed any path, tool, mutation, output, lifecycle, reference, or action boundary.

## Procedure

1. Open the exact candidate and producer result in a fresh isolated context.
2. Review only the bound artifact contract and keep changed_paths empty.
3. Resolve target-binding, review-findings, independence, and no-write evidence.
4. Return an agent-result that requests an authority action or candidate rework.

## Verification

- Resolve `target-binding` as `required`; not-applicable is forbidden.
- Resolve `review-findings` as `required`; not-applicable is forbidden.
- Resolve `no-write` as `required`; not-applicable is forbidden.
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
