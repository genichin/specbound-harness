# Bootstrap exception: req-0005-r1-review-return-001

> This is a repository-local Bootstrap governance record, not a canonical SpecBound lifecycle record. It cannot establish confirmation, approval, verified, Delivery, Merge, or Release authority.

## Identity and exact target

- Exception ID: `req-0005-r1-review-return-001`
- Status: `active`
- Transition: `in_review -> changes_requested -> same-revision in_review resubmission`
- Target artifact: `.specbound/requirements/req-0005/req-0005-r1.md`
- Target ID/revision: `req-0005-r1`
- Target SHA-256: `8014b96387d7819248c3fba61394943412f19790c4dda29832e10a18cc17faf9`
- Repository commit: `34bad066cbd736cdf1ecef07963e5c2bc8154fc3`
- Policy/config references: `docs/governance/bootstrap-to-canonical-transition.md` SHA-256 `45359f14618a84bbeb3e2a63af746b71130c3e3280a95d0a9258776f9e173110`; `specbound.yaml` SHA-256 `1b0ea9cc45108deb5dc9945ecb842796faa6fc363d2aea6edc83e1559b98ba43`

## Exact canonical failure

- Command: `PYTHONPATH=src .venv/Scripts/python.exe -m specbound.cli --root . req request-changes req-0005-r1`
- Exit code: `2`
- Blocker code: `unsupported_req_changes_requested_transition`
- Captured evidence: GitHub Issue `#11`, `https://github.com/genichin/specbound-harness/issues/11`; command output at accountable execution source `discord:1531288730709786724`
- Reproduction: from repository commit `34bad066cbd736cdf1ecef07963e5c2bc8154fc3`, run the command above and observe argparse reject `request-changes` because only `draft`, `reject`, `review-decision`, `reconsider`, `approve`, `check-readiness`, and `to-in-review` exist.

## Failure classification

- Classification: `intentionally unsupported transition`
- Why this is not a candidate/evidence/authority failure: the exact `in_review` REQ and its non-authorizing review-submission record validate; the missing operation is a CLI/status/validator path for ordinary non-terminal review return.
- Why normal rework cannot remove the blocker: current validation forbids editing an `in_review` snapshot or retaining its singleton review-submission with `status: draft`, and `changes_requested` is not a supported frontmatter state.

A candidate/evidence/authority failure is not eligible for a Break-glass Bootstrap exception.

## Accountable authority

- Authority identity: `repository-maintainer`
- Decision source: `discord:1531288730709786724`
- Decision: `approve`
- Decision reason: return the non-approved `req-0005-r1` to same-revision authoring under the explicitly adopted temporary Bootstrap procedure, close the three bounded review blockers, and resubmit without creating terminal rejection evidence or a new revision.

## Permitted next action

Exactly one bounded action is permitted:

`For req-0005-r1 only, execute one review-return/amendment/resubmission transaction: log return_count=1 on GitHub Issue #11; use status: draft as the temporary changes_requested compatibility representation; remove the active singleton review-submission; amend only the three enumerated review blockers in the same r1; pass readiness and repository validation; and resubmit through req to-in-review.`

- Allowed paths/systems: `.specbound/requirements/req-0005/req-0005-r1.md`; `.specbound/review-submissions/req-0005-r1.review-submission.json`; `docs/requirements.md` as the generated non-authorizing status projection only; `docs/governance/bootstrap-exceptions/req-0005-r1-review-return-001.md`; `docs/governance/bootstrap-exceptions/README.md`; GitHub Issue `#11` return-count log only.
- Required evidence: pre-action target/review-submission digests; Issue `#11` log with `req-0005-r1 return_count=1`; readiness, repository validation, regenerated requirement-index check, skill-validation, focused policy test and exact diff checks; new active review-submission binding after resubmission.
- Rollback/containment: before resubmission, restore the exact target, review-submission, and generated requirement-index bytes from commit `34bad066cbd736cdf1ecef07963e5c2bc8154fc3` if any required check fails; keep this exception active with failure evidence and stop. After successful resubmission, do not edit the new `in_review` bytes and close this exception as consumed.

## Forbidden claims

- Canonical `changes_requested` state for the bypassed transition
- Self-approval or authority-record issuance
- Adoption, Delivery, Merge, or Release unless this exact transition is independently governed
- Network, credential, production, or external mutation outside the permitted Issue `#11` return-count log
- Any action beyond the exact target and path boundary
- Terminal rejection evidence, retrospective canonical review evidence, or a new numeric REQ revision

Canonical changes_requested state: not recorded

## Repair and expiry

- Repair owner: `repository-maintainer`
- Repair target: `specbound req changes_requested status/writer/validator and same-revision resubmission path tracked by GitHub Issue #11`
- Expiry condition: close this exact exception after its one successful same-revision canonical resubmission; remove the policy bridge only after implementation, adoption, supported Ubuntu CI, and a new non-historical canary review loop satisfy §5.1.
- Maximum review/attempt budget: `1`
- If expiry cannot be reached: `stop and request a new accountable disposition`

## Closeout

- Final status: `active`
- Action evidence: `not run`
- Canonical retry/canary evidence: `not run`
- Historical treatment: `Bootstrap provenance preserved; no retrospective promotion`
- Closed by/source: `not closed`
