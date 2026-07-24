# Issuance-request prevalidation and bounded Micro-SPEC publication

`specbound issuance-request <artifact-kind> <canonical-target-identity> --candidate-file <path>` validates one complete candidate against a derived canonical safe-relative target. The identity is exact family data, never a filesystem path. Without `--publish`, the command is read-only and never creates that target.

Supported validation families are `micro-spec`, `iteration-qc`, and `delivery-qc`. Each receives its own schema/semantic checks and parent/adoption prerequisites: Micro-SPEC requires the exact approved canonical REQ and approval binding; QC families additionally require the exact copied-fixture adoption binding. Validation rejects unknown families, unsafe identities, malformed candidates, stale parents, invalid approvals/adoptions, and missing prerequisites with machine-readable blockers.

`--publish` is intentionally narrower than validation: it is limited to a marked copied fixture (`.specbound/pre-adoption-fixture`) and the `micro-spec` family. It derives the target rather than accepting a path; safely creates one new pre-adoption planning artifact without following unsafe path components; refuses duplicate/competing targets; removes only an owned leaf after write/flush/fsync/digest failure; and returns the artifact kind, canonical identity, safe-relative target, and SHA-256 recomputed from the final published bytes.

Publication is not approval, adoption, implementation completion, merge, delivery, or release. It grants no lifecycle authority, never mutates the live adoption registry, and cannot publish iteration-QC or delivery-QC artifacts.
