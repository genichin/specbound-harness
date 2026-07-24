# SpecBound Harness instructions

## Scope and authority

- This repository owns the portable SpecBound CLI, schemas, templates, fixtures, CI, and repository-backed skill source.
- `temp/` is ignored planning/reference material, never validator input or canonical lifecycle state.
- The canonical REQ root for the implemented bootstrap slice is `.specbound/requirements/`; `docs/requirements.md` is a generated user-facing projection, not lifecycle state.
- A skill provides workflow guidance only. `specbound` CLI exit status and CI are enforcement authority.

## Safety invariants

- Treat all artifact paths as safe repository-relative paths. Reject absolute paths, `..` traversal, and paths outside allowlisted roots.
- An approved REQ requires an approval record that binds exact path, ID, revision, SHA-256 digest, risk, and authority.
- Never mutate an approved REQ in place to repair a digest mismatch; mint a new revision and approval record.
- Never hand-edit `docs/requirements.md`; update canonical REQ display metadata and regenerate it with `specbound docs requirements`.
- Do not modify live Hermes profile configuration or `~/.hermes` from this repository unless the user explicitly requests rollout.

## Verification

Run before claiming a change is complete. Use the repository-local virtualenv; do not rely on whichever `python3` happens to be on `PATH`:

```bash
test -x .venv/bin/python || { echo "Create the project virtualenv (.venv) before verification."; exit 1; }
.venv/bin/python -m pytest
.venv/bin/python -m specbound.cli preflight
.venv/bin/python -m specbound.cli validate
.venv/bin/python -m specbound.cli docs requirements --check
```
