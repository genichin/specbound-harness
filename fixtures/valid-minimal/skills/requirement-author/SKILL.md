---
name: requirement-author
description: Use when performing the repository-bound SpecBound requirement-author
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
    role_id: requirement-author
    policy_path: .specbound/policies/agent-roles.yaml
    skill_path: skills/requirement-author/SKILL.md
    task_kind: requirement-author
    required_inputs:
    - confirmed-discovery
    - exact-target
    allowed_path_patterns:
    - .specbound/requirements/req-*/req-*-r*.md
    allowed_tool_categories:
    - repository-read
    - candidate-write
    mutation_classes:
    - candidate_write
    output_kinds:
    - agent-result
    lifecycle_eligibility:
    - confirmed
    result_references:
      producer_result_ref: optional
      reviewer_run_ref: forbidden
    permitted_next_actions:
    - submit-candidate-for-review
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

# requirement-author

## Overview

The machine-readable role policy is authoritative; this skill is procedural guidance only.
This role must not perform self-review or self-approval.
This role never issues or claims confirmation, approval, review-decision, verified, delivery, canonical publication, Merge, Release, or external mutation authority.

## When to Use

Use this skill only for the `requirement-author` task kind when repository-derived lifecycle state is one of: `confirmed`.

## Required Inputs

- `confirmed-discovery`
- `exact-target`

## Allowed Operations

- Paths: `.specbound/requirements/req-*/req-*-r*.md`
- Tool categories: `repository-read`, `candidate-write`
- Mutation classes: `candidate_write`
- Output kinds: `agent-result`
- Permitted next actions: `submit-candidate-for-review`

## Forbidden Actions and Claims

- Forbidden actions: `authority-transition`, `canonical-publication`, `merge`, `release`, `external-mutation`, `next-role-selection`
- Forbidden claims: `confirmation`, `approval`, `review-decision`, `verified`, `delivery`
- Stop when an assignment would exceed any path, tool, mutation, output, lifecycle, reference, or action boundary.

## Procedure

1. Verify the exact confirmed Discovery and optional producer result reference.
2. Draft acceptance criteria only at the bound requirement candidate path.
3. Resolve target-binding and acceptance-criteria evidence.
4. Return an agent-result that requests candidate review.

## Verification

- Resolve `target-binding` as `required`; not-applicable is forbidden.
- Resolve `acceptance-criteria` as `required`; not-applicable is forbidden.
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
