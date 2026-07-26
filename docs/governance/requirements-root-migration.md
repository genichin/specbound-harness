# Canonical requirements root migration

## Decision

The bootstrap repository moved canonical REQ artifacts from `docs/requirements/` to `.specbound/requirements/`.

`docs/requirements.md` is now a generated, user-facing projection. It is not lifecycle state and must not be used as approval or implementation evidence.

## Migration scope

Because SpecBound binds exact repository paths and SHA-256 snapshots, this was treated as a repository-format migration rather than a file-only rename. The machine-readable [migration manifest](../../.specbound/migrations/requirements-root-v1.json) records each affected canonical artifact's before/after path and digest together with the migration authority. The migration updated the complete in-repository binding chain:

- canonical REQ paths and display metadata;
- approval, review-submission, review-decision, rejection, and reconsideration bindings;
- canonical Micro-SPEC parent bindings;
- Micro-SPEC review digests;
- Discovery references and affected confirmation digests;
- schemas, templates, fixtures, tests, CLI behavior, CI, and operating guidance.

The repository contained no live canonical iteration-QC or delivery-QC records at migration time, so no downstream QC digest records required rebinding.

## Integrity boundary

This one-time bootstrap format migration does not relax the normal rule that an approved REQ must not be edited in place. Future material requirement changes still require a new numeric revision and a new approval binding.

After migration, the required verification surfaces are:

```bash
specbound preflight
specbound validate
specbound docs requirements --check
pytest
```

Text artifacts that participate in digest bindings are pinned to LF through `.gitattributes` so Windows and POSIX checkouts use identical canonical bytes.
