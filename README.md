# SpecBound Harness

SpecBound is a provider-neutral, repository-local control-plane harness for binding implementation claims to revisioned, approved requirements.

## Bootstrap slice

This initial slice supplies:

- `specbound context` — discover and print repository adoption context.
- `specbound preflight` — verify the adoption configuration and canonical roots.
- `specbound validate` — fail-closed validation of canonical Discovery/confirmation, REQ/approval, and REQ/rejection bindings.
- `specbound docs requirements` — regenerate the user-facing requirement list from canonical REQ metadata; `--check` fails when the projection is stale.
- `specbound req reject` — atomic rejection of an exact in-review REQ with immutable decision evidence.
- `specbound discovery confirm` — non-overwritable, exact-byte confirmation record creation after an explicit authority decision.
- isolated valid/invalid fixtures and CI.
- a repository-backed Hermes skill source under `skills/`.

The CLI and CI are enforcement surfaces. The Hermes skill explains the workflow but does not replace deterministic validation.

## Agent-contract boundary

The opt-in, provider-neutral agent contract defines exactly seven roles. A configured Hermes adapter maps each invocation to one configured model alias, the role's exact skill bytes, and a fresh isolated one-shot context; the portable request/result schemas contain no Hermes, provider, profile, session, or workdir fields. When the contract is disabled, the manual lifecycle workflow remains valid without agent policy or role-skill artifacts. Validation is read-only and non-authorizing: neither a valid envelope nor a successful dispatch may issue confirmation, approval, review-decision, verified, Delivery, Merge, or Release authority. Enabling repository validation is not a live Hermes rollout; runtime rollout and credentials remain a separate explicit operator action.

The portable public validation surface is `specbound agent validate-skills`, `specbound agent check-role-request`, and `specbound agent validate-result`. These commands validate repository bytes and never dispatch. The separately configured Hermes adapter is deliberately one-shot: no role chain, scheduler, implicit retry, or next-role selection is supported. Fake/stub dispatchers are test evidence only and are not a live Hermes rollout or production execution claim.

## Lifecycle governance

The repository's human operating model for issue intake through release is defined in [Issue SDLC](docs/governance/issue-sdlc.md). It uses SPEC-driven micro-iterations: each bounded Micro-SPEC maps to approved acceptance criteria, is focusedly verified, and advances only with iteration QC evidence.

The user-facing [Requirement list](docs/requirements.md) is generated from the latest revision of each canonical REQ under `.specbound/requirements/`. The generated list is a readable projection, not a second source of truth; edit REQ `title` and `summary` metadata, then regenerate it instead of editing the list directly. The one-time exact-path and digest rebinding is documented in [Canonical requirements root migration](docs/governance/requirements-root-migration.md).

The reusable [Discovery template](templates/discovery.md) is the source for a draft Discovery. It is not a lifecycle instance or a confirmation/approval record.

## Local use

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m specbound.cli context
.venv/bin/python -m specbound.cli preflight
.venv/bin/python -m specbound.cli validate
.venv/bin/python -m specbound.cli docs requirements --check
.venv/bin/python -m pytest
```

For a target repository, copy/adapt `specbound.yaml`, retain canonical Discoveries under `.specbound/discoveries/dcy-<id>-r<revision>.md` with confirmation records under `.specbound/confirmations/`, canonical requirements under `.specbound/requirements/`, approval records under `.specbound/approvals/`, and rejection records under `.specbound/rejections/`. The version-one artifact families are deliberately distinct: human-readable Micro-SPEC planning at `.specbound/micro-specs/req-<id>/ms-<id>-<slice>.md`, machine iteration-QC at `.specbound/iteration-qc/req-<id>/iqc-<id>-<slice>-r<revision>.json`, and machine delivery-QC at `.specbound/delivery-qc/dqc-<id>-r<revision>.json`. The current validator enforces canonical Micro-SPEC safe paths plus `schema_version: 1`, exact canonical approved-REQ path/ID/revision/SHA-256 binding, a unique selected subset of the parent REQ's current `AC-<id>` entries, and substantive planning sections. A canonical Micro-SPEC has this binding shape:

```yaml
requirement:
  path: .specbound/requirements/req-<id>/req-<id>-r<revision>.md
  id: req-<id>
  revision: <revision>
  sha256: <exact-approved-req-sha256>
selected_acceptance_criteria: [AC-<id>]
```

Canonical iteration-QC records bind the exact canonical Micro-SPEC path/ID/SHA-256 snapshot, preserve that Micro-SPEC's selected AC list, retain one or more reproducible focused `command`/`result`/`exit_code` entries, use only `verified`, `rework`, or `blocked` verdicts, and enumerate exactly the parent REQ ACs remaining outside the slice. `verified` requires complete passing focused evidence. Canonical delivery-QC records bind one exact approved REQ snapshot and its risk-policy-allowlisted QC authority, map every parent AC to one or more exact, verified canonical iteration-QC snapshots, retain passing cross-iteration regression evidence, and explicitly preserve unresolved exceptions plus residual-risk disposition. A delivery-QC cannot contain merge, delivery, release, or authorization claims; it proves readiness evidence only and never authorizes a transition. Control-plane evidence remains opt-in: `policy.control_plane_adoption` is a strict versioned registry of exact approved REQ `{path, id, revision, sha256}` snapshots. Normal `specbound validate` preserves compatibility when canonical Micro-SPEC/QC evidence is absent. An explicit `specbound validate --claim iteration|delivery --requirement req-<id>-r<revision>` requires that exact REQ to be adopted and then fails closed only for the requested claim when the required canonical evidence is absent or invalid. Adoption never retroactively relabels manual-bootstrap artifacts or authorizes merge, delivery, or release. Discovery confirmation permits only REQ drafting. An explicit allowlisted authority may reject an exact `in_review` revision only through `specbound req reject req-<id>-r<revision> --authority <allowlisted-authority> --reason <substantive-reason>`; it atomically transitions the REQ to `rejected` and records both reviewed and final byte digests.

## Runtime boundary

`skills/specbound-harness/` is the editable source of truth for Hermes guidance. It is not automatically installed into a live Hermes profile. Adding it to `skills.external_dirs` or exporting it is a separate, explicit runtime rollout step.
