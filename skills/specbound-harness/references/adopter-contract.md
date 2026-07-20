# SpecBound adopter contract — bootstrap slice

An adopting repository must place `specbound.yaml` at its root. The bootstrap validator accepts only this canonical topology:

```text
docs/discoveries/dcy-<numeric-id>/disc-<numeric-id>-r<revision>.md
.specbound/discovery-confirmations/disc-<numeric-id>-r<revision>.confirmation.json
docs/requirements/req-<numeric-id>/req-<numeric-id>-r<revision>.md
.specbound/approvals/req-<numeric-id>-r<revision>.approval.json
```

A Discovery confirmation binds `schema_version`, `discovery_path`, `discovery_id`, `revision`, `sha256`, `risk_class`, `authority`, `confirmed_at`, `decision`, and `permitted_next_action`. The confirmer must be allowlisted for that Discovery's risk class by `policy.discovery_confirmation_authorities_by_risk`; its only permitted action is `draft_req_only`.

For a REQ whose frontmatter has `status: approved`, create the matching approval record. The approval JSON must bind `requirement_path`, `requirement_id`, `revision`, `sha256`, `risk`, and `authority`.

The CLI fails closed on missing config, malformed frontmatter or control-plane records, unsafe paths (including symlinked canonical path components), path/identity/risk mismatch, missing approval/Discovery, invalid confirmation authority or timestamp, over-broad Discovery authorization, insufficient confirmed-Discovery evidence, and digest mismatch.

This slice does not yet validate Micro-SPEC, iteration evidence/QC, delivery request/QC, merge, or release records.
