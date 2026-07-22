# Discovery confirmation contract

## Canonical topology

```text
.specbound/discoveries/dcy-<numeric-id>-r<revision>.md
.specbound/confirmations/dcy-<numeric-id>-r<revision>.confirmation.json
```

Discovery identity and filename use the same lowercase `dcy-` prefix.

## Drafting boundary

A Discovery starts with `status: draft`. A reviewed candidate has `status: in_review`. The accountable confirmation command is the sole transition to `status: confirmed`; a drafting agent may populate or revise a Discovery, but may not self-confirm it, create a confirmation record, or authorize REQ implementation, merge, delivery, or release.

Before a confirmation can transition an `in_review` Discovery, the validator requires non-placeholder frontmatter (`id`, `revision`, `status`, `title`, `issue_ref`, `owner`, `source_refs`, and `risk_class`) plus substantive evidence under the required Discovery template headings.

## Content-addressed confirmation record

The confirmation record must bind all of the following exactly:

- `schema_version: 1`;
- safe repository-relative Discovery path;
- `dcy-<id>` identity and integer revision;
- SHA-256 of the exact reviewed `in_review` file bytes as `reviewed_sha256`;
- SHA-256 of the exact final `confirmed` file bytes as `sha256`;
- risk class matching Discovery frontmatter;
- non-empty confirmation authority allowlisted for the Discovery's risk class by `policy.discovery_confirmation_authorities_by_risk`;
- ISO-8601 confirmation timestamp;
- `decision: confirmed`;
- `permitted_next_action: draft_req_only`.

Create this record only through the deterministic command after an explicit accountable decision:

```bash
.venv/bin/python -m specbound.cli discovery confirm dcy-0001-r1 --authority repository-maintainer
```

The configured revision policy is `latest_only_with_explicit_exception`. If a higher revision of the same `dcy-<id>` exists, the command refuses to newly confirm a lower revision unless `--supersession-exception` supplies a substantive reason. An exception is stored as `supersession_exception` with the reason, matching authority, and timestamp. It does not make that lower revision the preferred current scope.

The command performs one rollback-safe lifecycle transaction: it verifies the `in_review` source, changes only its frontmatter status to `confirmed`, then writes the non-overwritable record. The validator reconstructs the reviewed form from the confirmed file and requires `reviewed_sha256` to match, so no content beyond that status transition may differ. Once confirmed and hash-bound, modify the Discovery only by minting a new revision and, if it is later confirmed, a new confirmation record. A valid confirmation permits only drafting a REQ; it is not a REQ approval or implementation authorization.

The local validator proves exact-byte consistency of the current checkout; it does not prove historical immutability. Require protected source history, CI review, and a signed or external append-only record when immutability is a security boundary.

## Required commands

Use the repository's reproducible interpreter:

```bash
.venv/bin/python -m specbound.cli preflight
.venv/bin/python -m specbound.cli validate
```

Treat a non-zero result as a blocker. Do not relocate lifecycle state into `temp/`, an issue tracker label, or a copy of the Markdown document.
