# Discovery confirmation contract

## Canonical topology

```text
docs/discoveries/dcy-<numeric-id>/disc-<numeric-id>-r<revision>.md
.specbound/discovery-confirmations/disc-<numeric-id>-r<revision>.confirmation.json
```

The directory prefix `dcy-` and the file/identity prefix `disc-` are intentionally different. Do not normalize one to the other.

## Drafting boundary

A Discovery starts with `status: draft`. A reviewed candidate has `status: in_review`. Neither status self-confirms the document. A draft authoring agent may populate or revise a Discovery, but may not create a confirmation record, state that it is confirmed, or authorize REQ implementation, merge, delivery, or release.

Before a confirmation can bind an `in_review` Discovery, the validator requires non-placeholder frontmatter (`id`, `revision`, `status`, `title`, `issue_ref`, `owner`, `source_refs`, and `risk_class`) plus substantive evidence under the required Discovery template headings.

## Content-addressed confirmation record

The confirmation record must bind all of the following exactly:

- `schema_version: 1`;
- safe repository-relative Discovery path;
- `disc-<id>` identity and integer revision;
- SHA-256 of the exact Discovery file bytes;
- risk class matching Discovery frontmatter;
- non-empty confirmation authority allowlisted for the Discovery's risk class by `policy.discovery_confirmation_authorities_by_risk`;
- ISO-8601 confirmation timestamp;
- `decision: confirmed`;
- `permitted_next_action: draft_req_only`.

The confirmation is a control-plane record, not a document metadata field. Once hash-bound, modify the Discovery only by minting a new revision and, if it is later confirmed, a new confirmation record. A valid confirmation permits only drafting a REQ; it is not a REQ approval or implementation authorization.

The local validator proves exact-byte consistency of the current checkout; it does not prove historical immutability. Require protected source history, CI review, and a signed or external append-only record when immutability is a security boundary.

## Required commands

Use the repository's reproducible interpreter:

```bash
.venv/bin/python -m specbound.cli preflight
.venv/bin/python -m specbound.cli validate
```

Treat a non-zero result as a blocker. Do not relocate lifecycle state into `temp/`, an issue tracker label, or a copy of the Markdown document.
