# Issuance-request prevalidation and bounded Micro-SPEC publication

`specbound issuance-request <artifact-kind> <canonical-target-identity> --candidate-file <path>` validates one complete candidate against its derived canonical target. Without `--publish`, it is read-only: it does not create the requested target.

`--publish` is currently limited to an explicitly marked copied fixture (`.specbound/pre-adoption-fixture`) and the `micro-spec` family. It first verifies the exact current canonical approved parent REQ path, ID, revision, SHA-256, status, and canonical approval-record binding. On success it creates only the requested pre-adoption Micro-SPEC planning artifact. It does **not** approve, adopt, merge, deliver, or release, and grants no lifecycle authority.

Supported kinds are `micro-spec`, `iteration-qc`, and `delivery-qc`. The target input is an exact family identity, not a filesystem path; the CLI derives the configured canonical safe-relative target itself. Validation rejects unknown kinds, malformed identities, incomplete candidates, invalid candidate schema or semantics, stale/mismatched parents, invalid approval bindings, and unmet family prerequisites with machine-readable blockers.

Iteration-QC and delivery-QC publication, adoption-graph handling, atomic exclusive-create safety, failure cleanup, duplicate policy, and result digests are separate later-slice responsibilities.
