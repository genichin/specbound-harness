# SpecBound Harness instructions

## Scope and authority

- This repository owns the portable SpecBound CLI, schemas, templates, fixtures, CI, and repository-backed skill source.
- `temp/` is ignored planning/reference material, never validator input or canonical lifecycle state.
- The canonical REQ root for the implemented bootstrap slice is `.specbound/requirements/`; `docs/requirements.md` is a generated user-facing projection, not lifecycle state.
- A skill provides workflow guidance only. `specbound` CLI exit status and CI are enforcement authority.

## Agent-contract boundary

The opt-in, provider-neutral agent contract defines exactly seven roles. A configured Hermes adapter maps each invocation to one configured model alias, the role's exact skill bytes, and a fresh isolated one-shot context; the portable request/result schemas contain no Hermes, provider, profile, session, or workdir fields. When the contract is disabled, the manual lifecycle workflow remains valid without agent policy or role-skill artifacts. Validation is read-only and non-authorizing: neither a valid envelope nor a successful dispatch may issue confirmation, approval, review-decision, verified, Delivery, Merge, or Release authority. Enabling repository validation is not a live Hermes rollout; runtime rollout and credentials remain a separate explicit operator action.

For agent-contract changes, first prove source provenance from the checkout: `python -c "from pathlib import Path; import specbound.agent_contract as m; source=Path(m.__file__).resolve(); expected=Path('src/specbound').resolve(); print(source); assert source.is_relative_to(expected)"`. Then run `tests/test_agent_integration.py` and `tests/test_hermes_adapter.py` in the focused source gate. The installed-wheel gate must clear `PYTHONPATH`, execute outside the checkout, print `module.__file__`, require `site-packages` provenance, compare all four packaged schemas byte-for-byte, and run the same integration/adapter tests. Push only after these local gates pass; then require GitHub Actions success for the exact `head_sha` on both Python 3.11 and 3.12 before Bootstrap formal QC. Green tests remain evidence, not authority.

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
