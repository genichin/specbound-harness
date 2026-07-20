# SpecBound Harness

SpecBound is a provider-neutral, repository-local control-plane harness for binding implementation claims to revisioned, approved requirements.

## Bootstrap slice

This initial slice supplies:

- `specbound context` — discover and print repository adoption context.
- `specbound preflight` — verify the adoption configuration and canonical roots.
- `specbound validate` — fail-closed validation of canonical Discovery/confirmation and REQ/approval bindings.
- isolated valid/invalid fixtures and CI.
- a repository-backed Hermes skill source under `skills/`.

The CLI and CI are enforcement surfaces. The Hermes skill explains the workflow but does not replace deterministic validation.

## Lifecycle governance

The repository's human operating model for issue intake through release is defined in [Issue SDLC](docs/governance/issue-sdlc.md). It uses SPEC-driven micro-iterations: each bounded Micro-SPEC maps to approved acceptance criteria, is focusedly verified, and advances only with iteration QC evidence.

The reusable [Discovery template](templates/discovery.md) is the source for a draft Discovery. It is not a lifecycle instance or a confirmation/approval record.

## Local use

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m specbound.cli context
.venv/bin/python -m specbound.cli preflight
.venv/bin/python -m specbound.cli validate
.venv/bin/python -m pytest
```

For a target repository, copy/adapt `specbound.yaml`, retain canonical Discoveries under `docs/discoveries/dcy-<id>/disc-<id>-r<revision>.md` with confirmation records under `.specbound/discovery-confirmations/`, retain canonical requirements under `docs/requirements/`, and retain approval records under `.specbound/approvals/`.

## Runtime boundary

`skills/specbound-harness/` is the editable source of truth for Hermes guidance. It is not automatically installed into a live Hermes profile. Adding it to `skills.external_dirs` or exporting it is a separate, explicit runtime rollout step.
