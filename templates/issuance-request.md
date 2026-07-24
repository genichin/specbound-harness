# Issuance-request prevalidation

`specbound issuance-request <artifact-kind> <canonical-target-identity> --candidate-file <path>` validates one complete candidate against its derived canonical target **without publishing anything**.

It does not publish, approve, adopt, merge, deliver, or release. It grants no lifecycle authority and does not create the requested target, including when validation succeeds.

Supported kinds are `micro-spec`, `iteration-qc`, and `delivery-qc`. The target input is an exact family identity, not a filesystem path; the CLI derives the configured canonical safe-relative target itself. Validation rejects unknown kinds, malformed identities, incomplete candidates, invalid candidate schema or semantics, stale/mismatched parents, and unmet family prerequisites with machine-readable blockers.

Publication, exclusive-create safety, adoption-graph handling, and result digests are separate later-slice responsibilities.
