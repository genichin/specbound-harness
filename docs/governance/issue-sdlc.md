# Issue SDLC: SPEC-driven Micro-iterations

## Purpose and authority

This document defines the human operating model for an issue from intake through release. An issue is a **delivery container**, not a single implementation action. After a REQ is approved, delivery proceeds through small, SPEC-driven micro-iterations: each iteration selects a bounded slice of approved acceptance criteria, implements it, produces focused evidence, and either advances to the next slice or stops for re-planning.

This document is the single human-readable authority for lifecycle semantics in this repository. It does **not** change the current bootstrap validator. `specbound` CLI and CI remain the enforcement authority for the REQ and approval bindings they currently implement. A future schema or validator may implement a rule in this document only through an explicit, reviewed change.

## Ownership boundaries

| Concern | Canonical owner | SpecBound role |
| --- | --- | --- |
| Work intake, priority, assignment, issue status, and iteration scheduling | The team's issue tracker or Kanban system | Reference only; never duplicate its status as canonical state. |
| Problem framing and decision record | Discovery artifact | Defines whether REQ drafting may begin. |
| Human-reviewable requirement scope and acceptance criteria | Versioned REQ under `docs/requirements/` | Validates approved REQ path, identity, revision, and digest binding. |
| Approval authority and approved snapshot | Approval record under `.specbound/approvals/` | Validates the exact approval binding. |
| Bounded implementation intent for one delivery slice | Micro-SPEC and its implementation plan | Maps one iteration to approved acceptance criteria; it cannot expand the REQ. |
| Focused verification and iteration QC evidence | The iteration's evidence and QC result | Establishes whether that slice may advance. |
| Delivery, merge, and release evidence | Delivery systems and repository governance | Out of scope for the current bootstrap validator. |

An issue tracker state never substitutes for a SpecBound approval record. Conversely, an approved REQ does not mark an issue complete, authorize an unconstrained implementation, or authorize merge/release by itself.

## Core model

1. **One issue, many bounded iterations.** A single issue may require multiple Micro-SPECs. Each Micro-SPEC is independently reviewable and verifiable; it is not merely a task-list fragment.
2. **REQ first, SPEC slice second.** A Micro-SPEC derives from a valid approved REQ and cites the exact REQ revision plus the acceptance criteria it addresses.
3. **Vertical, observable slices.** An iteration should deliver the smallest coherent behavior that can be verified end-to-end. Avoid a slice that only creates internal scaffolding unless the REQ or a dependency makes that the only safely verifiable increment.
4. **Evidence before progress.** Implementation does not advance an iteration. A passing, focused verification result and required QC evidence do.
5. **Re-plan rather than stretch scope.** A discovery that changes acceptance criteria, risk, or requirement scope returns to Discovery/REQ revision. A change confined to implementation approach may produce a revised Micro-SPEC for the same approved REQ.
6. **The issue closes only when all in-scope acceptance criteria are evidenced or explicitly dispositioned by the authorized actor.**

## Lifecycle

| Phase | Issue/Kanban state | Required input | Required output | Authorized next transition | Blockers |
| --- | --- | --- | --- | --- | --- |
| 1. Intake | `new` / `triage` | Reported problem, request, or opportunity | Owner, priority, and problem statement | Start Discovery | Missing owner, unclear problem, duplicate issue, or no priority decision. |
| 2. Discovery | `discovery` | Intake context and stakeholders | Discovery with goal, users, scope, non-goals, risks, open questions, and recommendation | Confirm Discovery; draft REQ | Unresolved blocking question, unknown risk, or no decision owner. |
| 3. Discovery confirmed | `ready_for_requirement` | Reviewed Discovery snapshot | Explicit confirmation and permitted next action: draft a REQ | Create REQ draft only | Confirmation absent, stale snapshot, or confirmation authorizes more than REQ drafting. |
| 4. REQ draft/review | `requirement_review` | Confirmed Discovery | Versioned REQ draft with acceptance criteria, risk, and scope boundaries | Approve exact REQ revision | Missing acceptance criteria, unresolved scope/risk, or draft differs from reviewed snapshot. |
| 5. REQ approved | `ready_for_spec` | Exact REQ revision and authorized approval decision | `status: approved` REQ plus approval record bound to path, ID, revision, SHA-256, risk, and authority | Draft the first Micro-SPEC only | Invalid `specbound validate`, missing or mismatched approval binding, or insufficient approval authority. |
| 6. Micro-SPEC planned/reviewed | `iteration_planning` | Valid approved REQ, selected unfulfilled acceptance criteria, and current verified baseline | Bounded Micro-SPEC with focused verification plan | Implement that Micro-SPEC only | Slice has no REQ/acceptance mapping, is too broad to verify, lacks explicit non-goals or evidence plan, or expands approved scope. |
| 7. Micro-iteration implementation | `in_progress` | Reviewed Micro-SPEC | Small code/configuration change plus implementation evidence | Run focused verification and iteration QC | Work exceeds the Micro-SPEC, dependency is unresolved, or a reproducible verification path is absent. |
| 8. Focused verification and iteration QC | `iteration_review` | Changed slice, Micro-SPEC, and test/evidence plan | Pass/fail/blocked result mapped to the selected acceptance criteria | Plan next Micro-SPEC, aggregate delivery QC, or rework the same slice | Failing or missing verification, acceptance mapping gap, security/compliance concern, unresolved review finding, or evidence that scope changed. |
| 9. Delivery QC | `delivery_review` | All in-scope Micro-SPEC results and full acceptance-criterion coverage | Aggregate QC result, residual-risk decision, and delivery request | Delivery decision | Any required acceptance criterion lacks evidence, an iteration is blocked, regression coverage is inadequate, or residual risk lacks authority. |
| 10. Delivery decision | `ready_to_merge` / `blocked` | Passing delivery QC and delivery evidence | Explicit delivery/merge decision and any required approval | Merge or return to a named Micro-SPEC/REQ revision | Invalid delivery request, policy/authority gap, failed QC, changed scope, or unresolved blocker. |
| 11. Merge and release | `done` / `released` | Authorized delivery decision | Merge/release provenance and issue closure | Close issue | Merge/release not completed, provenance absent, or post-release blocker open. |

State labels are illustrative. An adopting team's tracker may use different labels, but it must preserve the transition semantics, required outputs, and blocker conditions above.

## Micro-SPEC contract

Before implementation begins, each Micro-SPEC must state:

| Field | Required content |
| --- | --- |
| Parent binding | Exact approved REQ path, ID, revision, and selected acceptance-criterion IDs. |
| Iteration objective | The smallest user-observable or system-observable outcome this slice will establish. |
| Scope | Included behavior, affected components, dependencies, and explicitly excluded behavior. |
| Baseline | What is already verified and what this iteration assumes from prior iterations. |
| Design decision | The relevant approach, interfaces, data/control flow, and risk-specific constraints. |
| Verification plan | Exact focused commands/checks, expected observable result, and evidence to retain. |
| QC/exit rule | Conditions for `verified`, `rework`, `blocked`, or escalation to a revised REQ. |
| Rollback/containment | Reversal or containment approach when the slice changes operational behavior or risk warrants it. |

A Micro-SPEC is invalid as an iteration plan when it says only “implement feature X,” lists unbounded files/tasks, maps to no acceptance criteria, or postpones all verification to the final delivery review.

## Iteration loop and re-planning rules

```text
valid approved REQ
  → select smallest unfulfilled acceptance slice
  → draft/review Micro-SPEC
  → implement only that slice
  → focused verification + iteration QC
  ├─ verified: record evidence; select the next slice or enter delivery QC
  ├─ rework: revise implementation within the same Micro-SPEC; repeat verification
  ├─ blocked: record blocker, owner, and removal condition; do not advance status
  └─ scope/risk/acceptance change: return to Discovery or mint a new REQ revision
```

1. **Verified iteration.** The selected acceptance criteria have direct, reproducible evidence. Mark only those criteria as covered; do not infer coverage for the remaining REQ.
2. **Same-slice rework.** A failing test, code-review defect, or implementation correction may stay within the Micro-SPEC only when the selected acceptance criteria, risk, and stated boundaries do not change.
3. **Micro-SPEC revision.** A change to the approach, decomposition, or verification plan may revise the Micro-SPEC when it remains inside the approved REQ's scope and risk boundary. Re-review the revised plan before further implementation.
4. **REQ revision required.** New/changed acceptance criteria, changed user outcome, material risk increase, or a changed non-goal requires a new REQ revision and fresh approval binding. Do not edit a hash-bound approved REQ in place.
5. **Discovery revisit required.** Return to Discovery when the problem, target users, fundamental trade-off, or decision premise is no longer valid—not merely because an implementation detail changed.
6. **Aggregate delivery QC.** Final delivery QC confirms complete coverage across all required REQ acceptance criteria and checks cross-iteration regressions; it does not replace iteration-level verification.

## Transition rules

1. **Narrow authorization.** Each approved transition authorizes only the next named action. Confirmation of a Discovery permits REQ drafting, not implementation. REQ approval permits the first Micro-SPEC, not unconstrained implementation, merge, or release.
2. **Reviewed snapshot provenance.** A reviewed or approved artifact is content-addressed by its binding. Do not edit it in place: material changes require a new revision and binding. Protected source history, CI review, and where required a signed or external record enforce immutability.
3. **Fail closed at enforcement boundaries.** A non-zero `specbound validate` result blocks any claim that an approved REQ is valid. Missing lifecycle evidence blocks the related transition even when no validator exists yet.
4. **One canonical owner per fact.** The tracker owns work lifecycle; the REQ owns requirement scope; the approval record owns approval facts; Micro-SPEC/QC/delivery systems own their evidence. Do not create synced duplicate state.
5. **Risk-based authority.** Required approver and merge authority are determined by the repository's risk policy. A lower-risk change may use delegated authority only when that policy explicitly allows it; a higher-risk change requires the policy's elevated authority.
6. **Blockers are explicit.** A blocker must state its source artifact or system, why the transition is unsafe, its owner, and the condition for removal. It is not resolved by changing a status label alone.

## Current artifact contract

The bootstrap implementation currently recognizes these lifecycle artifacts:

```text
specbound.yaml
docs/discoveries/dcy-<id>/disc-<id>-r<revision>.md
.specbound/discovery-confirmations/disc-<id>-r<revision>.confirmation.json
docs/requirements/req-<id>/req-<id>-r<revision>.md
.specbound/approvals/req-<id>-r<revision>.approval.json
```

`templates/discovery.md` is the reusable **draft Discovery template**, not an instance or confirmation record. A reviewed Discovery uses `status: in_review`; confirmation is valid only when its separately stored record binds `schema_version: 1`, exact path, ID, revision, SHA-256 digest, matching risk class, policy-allowlisted authority, timezone-bearing confirmation time, `decision: confirmed`, and `permitted_next_action: draft_req_only`. It never authorizes implementation, merge, delivery, or release.

Micro-SPEC, iteration QC, delivery QC, merge, and release records remain lifecycle requirements in this document, but their canonical schemas, paths, and CLI checks require a subsequent approved design and implementation slice.

## Minimum evidence before a transition claim

- **Discovery confirmed:** content-addressed reviewed Discovery reference, risk-allowlisted confirmer/authority, confirmation time, and narrowly authorized next action. Protected source history, CI, and an optional signed or external record provide immutability provenance.
- **REQ approved:** exact REQ path, ID, revision, SHA-256, risk, authority, and a passing `specbound validate` result.
- **Micro-SPEC reviewed:** parent REQ binding, selected acceptance criteria, bounded objective/scope, baseline, verification plan, and explicit exit rule.
- **Iteration verified:** focused command/result evidence, selected acceptance-criterion mapping, review/QC result, and remaining/unfulfilled criteria list.
- **Delivery QC passed:** all required acceptance criteria mapped to one or more verified iterations, cross-iteration regression evidence, reviewer identity or delegated authority, and unresolved-exception list.
- **Delivery authorized:** passing delivery QC reference, scope/revision reference, delivery decision authority, target, and rollback/containment note where applicable.
- **Released/closed:** merge or release provenance plus confirmation that all required blockers are resolved or explicitly accepted by the authorized actor.

## Non-goals

- This document does not prescribe a particular issue tracker, Kanban vendor, or Git hosting provider.
- It does not create an approval, validate future artifact types, or override repository-specific risk policy.
- It does not turn a planning document, draft, tracker label, or Micro-SPEC into a canonical approval record.
- It does not authorize changing an approved REQ in place or bypassing its validation gate.
