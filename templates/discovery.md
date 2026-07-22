---
id: dcy-<id>
revision: <revision>
status: draft
title: <concise discovery title>
issue_ref: <canonical tracker issue reference>
owner: <responsible role or person>
source_refs: []
risk_class: <repository-defined risk classification>
relationship: new # new | update | follow-up | superseding
related_discovery_refs: []
related_requirement_refs: []
---

# Discovery: <concise discovery title>

> **Lifecycle boundary:** This Discovery's lifecycle state is determined by its frontmatter and any matching content-addressed confirmation record. It is not an approved requirement and never authorizes implementation, merge, delivery, or release. REQ drafting is permitted only when a valid confirmation record at `.specbound/confirmations/dcy-<id>-r<revision>.confirmation.json` binds this exact `.specbound/discoveries/dcy-<id>-r<revision>.md` snapshot with `permitted_next_action: draft_req_only`. Repository protection, CI, and (where required) a signed or external record enforce immutability beyond this local validator.

## 0. Discovery context and lineage

- **Trigger / initiating change:**
- **Relationship:** `new` / `update` / `follow-up` / `superseding`
- **Related Discovery and REQ references:**
- **Why this is a new or revised Discovery rather than a minor update to prior work:**
- **Impact on prior approved scope, in-flight work, or released behavior:**

Write `None` for each assessed relationship that does not exist. Do not overwrite history; represent a material scope reset as a new revision or a linked follow-up/superseding Discovery.

## 1. User intent

- **Stated intent:**
- **Source context:**
- **Verbatim excerpt or faithful summary:**

## 2. Problem and target users

- **Problem:**
- **Target users / affected systems:**
- **Current state and evidence:**

## 3. Desired outcome and success signals

- **Desired outcome:**
- **Observable success signals:**
- **Measurement or observation method:**

> Keep these at the problem/outcome level. Do not write implementation acceptance criteria here; those belong to the REQ.

## 3a. Candidate requirement concerns (non-binding)

- **Capability concerns to refine into a REQ:**
- **Quality, safety, or operational concerns to refine into a REQ:**
- **Scope boundaries that a REQ must preserve:**

These are discovery hypotheses, not REQ acceptance criteria or approved scope. They exist to make the REQ handoff concrete without pre-approving implementation.

## 4. Confirmed facts

| Fact | Evidence / source | Confidence or limitation |
| --- | --- | --- |
| <fact> | <reference> | <limitation> |

Write `None confirmed yet` when no facts are confirmed.

## 5. Assumptions and hypotheses

| Assumption or hypothesis | Why it matters | Validation approach / owner |
| --- | --- | --- |
| <assumption> | <impact> | <approach> |

Write `None` when there are no material assumptions.

## 6. Scope

- **In scope:**
- **Affected boundaries/components:**
- **Dependencies:**

## 7. Non-goals

- **Explicitly excluded:**
- **Deferred to a later Discovery or REQ:**

Write `None` only after confirming that no meaningful exclusion is needed.

## 7a. Expected change and impact

- **Expected product/service behavior change:**
- **Likely affected boundaries, components, documents, or operational flows:**
- **Expected compatibility, migration, or rollout concern:**
- **Repository/context evidence inspected:**

This is an impact hypothesis for Discovery. A Micro-SPEC later determines the bounded implementation slice and its verification evidence.

## 8. Alternatives and trade-offs

| Alternative | Benefits | Costs / risks | Decision or reason not selected |
| --- | --- | --- | --- |
| <alternative> | <benefits> | <costs> | <decision> |

Write `No material alternative identified` when no substantive alternative exists.

## 9. Risks, constraints, and dependencies

| Item | Type | Impact | Owner | Mitigation, removal condition, or defer rationale |
| --- | --- | --- | --- | --- |
| <item> | risk / constraint / dependency | <impact> | <owner> | <response> |

Write `No material risks, constraints, or dependencies identified` only after assessment.

## 10. Decisions

| Decision | Decider / authority | Rationale | Date or source | Reversible? |
| --- | --- | --- | --- | --- |
| <decision> | <actor/role> | <reason> | <reference> | yes / no |

Write `No decision made` when decisions remain open. Do not represent an agent recommendation as a user decision.

## 11. Open questions

| Question | Type | Blocker? | Owner | Resolution or defer condition |
| --- | --- | --- | --- | --- |
| <question> | DECIDE / CONFIRM / DATA | yes / no | <owner> | <condition> |

- `DECIDE`: a product, policy, priority, or scope choice that requires an accountable decision-maker.
- `CONFIRM`: a fact, interpretation, or boundary that must be verified.
- `DATA`: evidence or measurement that may be collected later; state explicitly whether it blocks REQ drafting.

Write `None` only when no unresolved material question remains. Do not leave generic `TBD`; use one of the typed question classes and its resolution/defer condition.

## 12. Recommendation

- **Recommended direction:**
- **Why this direction:**
- **Trade-offs accepted or deferred:**

## 12a. REQ drafting readiness

- **Readiness assessment:** `not ready` / `ready for confirmation` / `confirmation pending`
- **Scope and non-goals are sufficiently bounded for a REQ draft:** yes / no — <reason>
- **Success signals can be converted into REQ acceptance criteria:** yes / no — <reason>
- **Open-question disposition:** all blocking questions resolved / explicitly deferred / <remaining blocker>
- **Risks and dependencies have an owner or explicit handling path:** yes / no — <reason>
- **Required confirmation boundary:** a separate content-addressed confirmation record; this template must not self-confirm.

## 13. Proposed next authorized action

- **Requested next action:** `draft REQ only` / `<other non-implementation action>`
- **Preconditions still required:**
- **What this Discovery does not authorize:** implementation, merge, delivery, and release unless separately authorized by the governing lifecycle.

## Review checklist

- [ ] User intent is distinguishable from agent assumptions and recommendations.
- [ ] Trigger, lineage, and impact on related Discovery/REQ/delivery work are explicit or assessed as absent.
- [ ] Problem, target users, desired outcome, scope, non-goals, and expected change impact are explicit.
- [ ] Candidate requirement concerns are non-binding and do not masquerade as approved acceptance criteria.
- [ ] Facts have evidence; assumptions are labelled and owned.
- [ ] Material alternatives, risks, constraints, dependencies, decisions, and open questions are explicit or marked as assessed/not applicable.
- [ ] Every open question is typed `DECIDE`, `CONFIRM`, or `DATA`, with an owner and a resolution/defer condition.
- [ ] REQ drafting readiness reflects the actual blocker and confirmation state; this document contains no self-confirmation claim.
- [ ] No implementation acceptance criteria, implementation authorization, or approval claim appears in this Discovery.
- [ ] The proposed next action is narrow and does not exceed Discovery authority.
