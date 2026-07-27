# Bootstrap-to-Canonical Transition Policy

## 1. Status and authority

This is the repository-local transition policy for `specbound-harness`. It governs how this repository moves from accountable Bootstrap operation to prospective canonical self-hosting.

- **Official name:** `Bootstrap-to-Canonical Transition Policy`
- **Transition baseline:** `2722bcd50938ed7a43011fe3d4793e521ef9f997`
- **Accountable decision source:** `discord:1531116736534020167`
- **Temporary REQ review-return decision source:** `discord:1531284648511012916`
- **Scope:** this repository only; it is not automatically part of the general adopter contract.
- **Authority classification:** repository-local Bootstrap governance decision. This document does not create a new canonical lifecycle artifact family or claim that a not-yet-implemented transition executed.

The effective policy snapshot is the first repository commit containing this exact document and its linked contract test. The baseline above identifies the last pre-policy `main` state; the policy does not embed a self-referential commit digest.

## 2. Purpose

Bootstrap is not removed from the repository. It is narrowed to a temporary transition and recovery path while implemented canonical controls become mandatory one transition at a time.

```text
implemented and applicable canonical transition
  -> canonical writer, record, validator, and configured authority are mandatory

unsupported transition required to close self-hosting
  -> exact accountable Bootstrap exception may permit one bounded next action

canonical control-plane defect blocks a valid transition
  -> Break-glass Bootstrap exception may permit repair or bounded continuation

capability + adoption + prospective canary succeed
  -> corresponding Bootstrap exception expires
```

This policy prevents both self-hosting deadlock and silent canonical bypass.

## 3. Terminology

| Term | Meaning |
| --- | --- |
| `CANONICAL_REQUIRED` | An applicable repository writer, record, validator, and authority path exist. The canonical gate must be used. |
| `BOOTSTRAP_ADVISORY` | Review, test, or QC evidence may be produced, but it cannot establish canonical authority state. |
| `BOOTSTRAP_AUTHORITY_EXCEPTION` | An accountable, exact, temporary exception permits one bounded action across an unsupported transition. |
| `UNSUPPORTED_BLOCKED` | Neither a canonical transition nor an approved Bootstrap exception exists. Work stops. |
| `Break-glass Bootstrap exception` | A special `BOOTSTRAP_AUTHORITY_EXCEPTION` used only for a reproducible canonical control-plane defect or unavailability. |
| `Prospective cutover` | A newly implemented and adopted transition becomes canonical for future exact artifacts after a new canary succeeds. |

Candidate authoring is not an authority transition. A role-constrained or manual candidate write may be allowed when no dedicated writer exists, but it cannot create confirmation, approval, review, verified, Delivery, Merge, or Release authority.

## 4. Canonical-first rules

1. An applicable canonical gate cannot be replaced by a manual status edit, tracker label, advisory verdict, direct authority-record write, or generic accountable instruction.
2. A canonical gate failure caused by invalid candidate bytes, missing evidence, stale bindings, or unauthorized authority requires rework or stop. It is not eligible for Bootstrap fallback.
3. A validator or copied-fixture publication test does not prove that a live applicable writer exists.
4. Reviewer recommendation, accountable authority, and writer execution remain separate.
5. A canonical record establishes only its exact transition. It does not infer downstream Delivery, Merge, or Release authority.
6. Historical Bootstrap evidence remains historical. New enforcement does not retroactively govern old work.

## 5. Current repository transition matrix

This matrix applies from the effective policy commit until a later reviewed policy revision changes an exact row.

| Lifecycle activity | Current classification | Required operation | Current limitation / expiry |
| --- | --- | --- | --- |
| Intake and problem framing | non-authorizing repository work | Preserve source, owner, problem, and risk questions | Tracker integration remains optional. |
| Discovery candidate authoring and move to `in_review` | non-authorizing candidate work | Use the canonical path/template and validate candidate bytes | No dedicated Discovery draft/review-submission writer exists. |
| Independent Discovery review | `BOOTSTRAP_ADVISORY` | Fresh context, exact candidate binding, no mutation, advisory label | Expires only after an operational reviewer execution/result path is adopted and can be proven live. |
| Discovery confirmation | `CANONICAL_REQUIRED` | Use `specbound discovery confirm` and the configured risk authority | Failure requires rework unless an eligible break-glass control-plane defect is proven. |
| REQ draft, readiness, review submission, approval-ready decision, terminal rejection/reconsideration, and approval | `CANONICAL_REQUIRED` | Use the implemented `specbound req` commands and exact records | Manual approval/status mutation is forbidden. |
| Non-terminal REQ review return and same-revision amendment/resubmission | `BOOTSTRAP_AUTHORITY_EXCEPTION` until implemented | Use the temporary §5.1 procedure only under an exact per-artifact exception; do not issue a terminal `rejected` decision for ordinary review feedback | Remove this row and §5.1 after the `changes_requested` writer/validator path is implemented, adopted, and proven by a new canary review loop. |
| Micro-SPEC candidate authoring | non-authorizing candidate work | Bind an exact approved REQ and use the canonical path/contract | Live publication remains narrower than candidate authoring. |
| Micro-SPEC review decision | `CANONICAL_REQUIRED` | Use `specbound micro-spec review-decision` and configured authority | Advisory review alone cannot authorize implementation. |
| Implementation authorization boundary | `CANONICAL_REQUIRED` | Implement only the exact reviewed Micro-SPEC authorized by its canonical review decision | No canonical implementation-completion record exists. |
| Implementation result evaluation | `BOOTSTRAP_ADVISORY` | Retain exact source/test/CI evidence without claiming canonical completion | Expires only after an applicable canonical implementation/QC result path is adopted and canary-proven. |
| Live iteration-QC publication/claim | `UNSUPPORTED_BLOCKED` by default | Require a separately approved exact `BOOTSTRAP_AUTHORITY_EXCEPTION` for closure work | Expires after live writer/adoption and a new canonical canary IQC succeed. |
| Live delivery-QC publication/claim | `UNSUPPORTED_BLOCKED` by default | Require a separately approved exact `BOOTSTRAP_AUTHORITY_EXCEPTION` for closure work | Expires after live writer/adoption and a new canonical canary DQC succeed. |
| Delivery decision | `UNSUPPORTED_BLOCKED` | No implicit transition | Requires a separate Discovery/REQ and prospective canary. |
| Merge/Release provenance | `UNSUPPORTED_BLOCKED` | No implicit transition | Requires a separate Discovery/REQ and prospective canary. |
| Live Hermes runtime rollout | optional external operation | Keep provider-neutral contract and repository validation separate from rollout | Fake/stub adapter evidence is not live execution. |

No active exception is created by this matrix. The default for every unsupported row is `UNSUPPORTED_BLOCKED` until an exact exception record is approved.

### 5.1 Temporary `changes_requested` review-return procedure

This subsection is a temporary Bootstrap bridge for the control-plane gap tracked by GitHub Issue `#11`. It governs only ordinary review feedback on a non-approved REQ that must be edited and resubmitted under the same numeric revision. The intended lifecycle is:

```text
draft -> in_review -> changes_requested -> in_review -> approved
```

`changes_requested` is non-authorizing and has the same permitted authoring work as `draft`: edit the same revision, run readiness/validation, and resubmit it for fresh review. It does not create approval, implementation, adoption, IQC/DQC, Delivery, Merge, or Release authority. `rejected` remains reserved for an accountable terminal decision that ends the proposal.

Until the dedicated status, writer, validator, and resubmission path exist, `changes_requested` is a Bootstrap operational state rather than a supported REQ frontmatter value. Do not write the unsupported value into the canonical artifact. For validator compatibility, one exact per-artifact `BOOTSTRAP_AUTHORITY_EXCEPTION` may permit this bounded procedure:

1. Stop after the review requests changes; do not create a canonical `rejected` review decision, rejection record, or reconsideration record.
2. Record only the repository-relative REQ identity and monotonically increasing `n`th return count in the linked issue/work log. This informational log is not canonical evidence, carries no SHA-256 or authority semantics, and cannot affect validation or approval eligibility.
3. Bind the exception to the exact non-approved REQ and permit only one return to editable same-revision work plus one resubmission. The exception must forbid approval, implementation, downstream lifecycle claims, unrelated artifact mutation, and revision expansion.
4. Preserve the previous valid `in_review` artifact and non-authorizing review-submission bytes in Git history, then use `status: draft` as the temporary frontmatter compatibility representation and remove only the active singleton review-submission record that prevents draft validation. This manual compatibility mutation is permitted only by the exact exception and must leave the repository valid; it is not a canonical `changes_requested` transition.
5. Edit the same REQ revision, run `req check-readiness` and repository validation, then use the implemented canonical `req to-in-review` writer to create the next active non-authorizing submission record for the new bytes.
6. After final fresh review, use the implemented approval-ready decision and approval writers normally. The review-return count and Bootstrap exception do not substitute for that exact approval path.

Every report for this bridge must say `Canonical changes_requested state: not recorded`. A review-return log, Git history, advisory result, deleted active singleton record, or Bootstrap exception must never be relabelled as canonical review evidence.

This subsection and its matrix row expire together only after all of the following are complete:

1. `changes_requested` is an implemented REQ status with a rollback-safe return writer and same-revision resubmission writer;
2. validation supports the complete `in_review -> changes_requested -> in_review` loop without deleting or overwriting authority-bearing history;
3. source, installed-wheel, and supported Ubuntu CI behavior pass for the exact implementation;
4. an explicit adoption decision and a new non-historical REQ canary complete the real loop;
5. every active exception using this subsection is closed and removed from the active ledger.

After those conditions pass, delete §5.1 and the temporary matrix row in the same reviewed policy change. Do not retain this Bootstrap path as a fallback.

## 6. Exception ledger

Bootstrap exception records live under:

```text
docs/governance/bootstrap-exceptions/<exception-id>.md
```

They are Git-preserved Bootstrap governance records, not canonical SpecBound lifecycle records. The inventory and active count are maintained in `docs/governance/bootstrap-exceptions/README.md`. Create a candidate from `templates/bootstrap-exception.md`.

Each exception must bind:

- exact target artifact and immutable commit or byte digest;
- failed or unsupported transition;
- exact command/blocker when one exists;
- failure classification;
- accountable authority and decision source;
- one permitted next action;
- forbidden claims and paths;
- required evidence;
- repair owner;
- expiry and closeout condition.

A generic instruction such as `continue in Bootstrap` is not an exception record.

## 7. Break-glass Bootstrap exception

### 7.1 Eligible failures

Break-glass may be considered only when direct evidence shows that a valid transition is blocked by the control plane itself, for example:

- reproducible CLI/writer defect;
- validator false positive against exact valid bytes;
- supported-platform control-plane unavailability;
- writer failure after all input, evidence, binding, and authority preconditions pass.

### 7.2 Ineligible failures

Break-glass is forbidden for:

- schema-invalid or semantically invalid candidate bytes;
- missing test, review, IQC, DQC, rollback, or CI evidence;
- unsafe/noncanonical path or stale/digest-mismatched binding;
- unauthorized or non-allowlisted authority;
- work outside the approved Discovery/REQ/Micro-SPEC;
- a requested adoption, migration, risk, authority, Delivery, Merge, or Release policy change;
- a failed canary that shows the new capability is not operational.

These failures require rework, stop, or a new Discovery as applicable.

### 7.3 Procedure

1. Stop at the canonical failure; do not continue automatically.
2. Freeze the exact candidate, commit, config, policy, command, stdout/stderr, and blocker.
3. Reproduce that the defect is in the control plane rather than the candidate, evidence, or authority.
4. Draft one exception record from the template.
5. Obtain an explicit accountable decision bound to that record.
6. Perform only the permitted next action with the smallest mutation boundary.
7. Report `Canonical state: not recorded` for the bypassed transition.
8. Repair the control plane and rerun the canonical transition before downstream work whenever possible.
9. If downstream work already occurred, preserve its break-glass provenance; do not backfill a retrospective canonical record.
10. Close the exception after repair and a prospective canonical retry or canary.

Break-glass never authorizes self-approval, silent status mutation, direct authority-record issuance, adoption, Delivery, Merge, Release, credentials, or network/production mutation. Each such transition remains governed solely by its own current policy and authority; a break-glass record cannot enlarge its own scope.

## 8. No retrospective promotion

The following are prohibited:

- relabelling a Bootstrap advisory review as a canonical Independent Reviewer result;
- creating retrospective IQC/DQC records from historical implementation evidence;
- claiming a newly implemented agent contract executed prior work;
- adopting a completed historical REQ to make its old evidence canonical;
- replacing an unsupported writer with a direct authority-record edit.

If a break-glass action advanced beyond a missing transition, its evidence remains Bootstrap-labelled. Normal canonical operation resumes prospectively after repair.

## 9. Prospective cutover

A transition changes from Bootstrap exception to `CANONICAL_REQUIRED` only when all are complete:

1. the capability is implemented and passes source, installed-artifact, and supported-platform verification as applicable;
2. an explicit exact adoption/cutover decision exists;
3. a new small canary artifact traverses the transition through the real live writer and validator;
4. the canonical record validates and binds the exact artifact/evidence/authority;
5. the corresponding exception is closed and removed from the active ledger.

Recommended staged cutovers:

```text
Control-plane cutover : Discovery -> REQ -> Micro-SPEC -> IQC -> DQC
Delivery cutover      : canonical Delivery decision
Integration cutover   : canonical Merge/Release provenance
Runtime rollout       : optional live agent execution; separate from lifecycle authority
```

## 10. Reporting

Every mixed-mode handoff reports:

```text
Target/baseline              : exact artifact and commit
Transition                   : exact lifecycle transition
Classification               : one current matrix value
Canonical command/result     : command and success/blocker
Bootstrap exception          : exact record or none
Evaluation label             : advisory/formal QC/canonical record
Canonical state              : recorded or not recorded
Permitted next action        : one action or none
Exception expiry             : repair/adoption/canary condition
Active exceptions            : exact count
```

Do not report a repository as globally canonical merely because `preflight` or `validate` is green. Report transition-by-transition authority state.

## 11. Policy revision and retirement

Material changes to adoption, migration, risk, authority, exception eligibility, or required lifecycle transitions require a new Discovery/REQ unless the missing mechanism makes that impossible and an exact accountable Bootstrap decision explicitly governs the policy repair.

This policy retires when every required lifecycle transition is either operationally canonical and canary-proven or explicitly removed from the intended lifecycle by an accountable governance decision. Historical exception records remain preserved after retirement.