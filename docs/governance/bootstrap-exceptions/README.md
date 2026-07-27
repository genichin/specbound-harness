# Bootstrap exception ledger

This directory contains repository-local Bootstrap exception records governed by [`Bootstrap-to-Canonical Transition Policy`](../bootstrap-to-canonical-transition.md).

**Active exceptions: 0**

No exception is implicit. This index does not authorize a lifecycle transition, implementation, canonical publication, adoption, Delivery, Merge, Release, or external mutation.

## Rules

1. Create a candidate record from `templates/bootstrap-exception.md`.
2. Bind one exact target, transition, failure/unsupported condition, authority decision, and permitted next action.
3. Add the approved record to the active inventory before executing the exception.
4. Keep `Canonical state: not recorded` when the canonical transition did not occur.
5. Close rather than delete the record after repair and a canonical retry or prospective canary.
6. Update the active count in the same change that activates or closes an exception.

## Inventory

| Exception | Transition | Target | Status | Expiry |
| --- | --- | --- | --- | --- |
| [`req-0005-r1-review-return-001.md`](req-0005-r1-review-return-001.md) | `in_review -> changes_requested -> same-revision in_review resubmission` | `.specbound/requirements/req-0005/req-0005-r1.md` | `closed` | Consumed by canonical resubmission commit `7ae473c15097a2288e310fc41b676480c6908581`; retire policy bridge after Issue #11 implementation/adoption/canary. |
