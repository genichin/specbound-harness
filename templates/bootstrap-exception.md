# Bootstrap exception: {exception-id}

> This is a repository-local Bootstrap governance record, not a canonical SpecBound lifecycle record. It cannot establish confirmation, approval, verified, Delivery, Merge, or Release authority.

## Identity and exact target

- Exception ID: `{exception-id}`
- Status: `candidate | active | closed`
- Transition: `{exact-transition}`
- Target artifact: `{repository-relative-path}`
- Target ID/revision: `{id-and-revision}`
- Target SHA-256: `{64-lowercase-hex}`
- Repository commit: `{full-commit-id}`
- Policy/config references: `{exact-paths-and-digests}`

## Exact canonical failure

- Command: `{exact-command}`
- Exit code: `{integer}`
- Blocker code: `{exact-code-or-unsupported}`
- Captured evidence: `{path-or-immutable-reference}`
- Reproduction: `{minimal-deterministic-steps}`

## Failure classification

- Classification: `control-plane defect | control-plane unavailable | intentionally unsupported transition`
- Why this is not a candidate/evidence/authority failure: `{direct evidence}`
- Why normal rework cannot remove the blocker: `{reason}`

A candidate/evidence/authority failure is not eligible for a Break-glass Bootstrap exception.

## Accountable authority

- Authority identity: `{configured-accountable-identity}`
- Decision source: `{immutable-reference}`
- Decision: `approve | reject`
- Decision reason: `{substantive-reason}`

## Permitted next action

Exactly one bounded action is permitted:

`{one-action}`

- Allowed paths/systems: `{closed-list}`
- Required evidence: `{closed-list}`
- Rollback/containment: `{exact-procedure}`

## Forbidden claims

- Canonical state for the bypassed transition
- Self-approval or authority-record issuance
- Adoption, Delivery, Merge, or Release unless this exact transition is independently governed
- Network, credential, production, or external mutation outside the permitted next action
- Any action beyond the exact target and path boundary

Canonical state: not recorded

## Repair and expiry

- Repair owner: `{owner}`
- Repair target: `{control-plane-component}`
- Expiry condition: `{repair-plus-canonical-retry-or-prospective-canary}`
- Maximum review/attempt budget: `{bounded-number}`
- If expiry cannot be reached: `stop and request a new accountable disposition`

## Closeout

- Final status: `active | closed`
- Action evidence: `{exact-commit-command-result}`
- Canonical retry/canary evidence: `{exact-record-or-not-run}`
- Historical treatment: `Bootstrap provenance preserved; no retrospective promotion`
- Closed by/source: `{authority-and-reference}`
