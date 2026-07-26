# SpecBound adopter contract — bootstrap slice

An adopting repository must place `specbound.yaml` at its root. The bootstrap validator accepts only this canonical topology:

```text
.specbound/discoveries/dcy-<numeric-id>-r<revision>.md
.specbound/confirmations/dcy-<numeric-id>-r<revision>.confirmation.json
.specbound/requirements/req-<numeric-id>/req-<numeric-id>-r<revision>.md
.specbound/approvals/req-<numeric-id>-r<revision>.approval.json
```

`docs/requirements.md` is a generated, user-facing projection of the latest canonical REQ revisions. It is not lifecycle state. Run `specbound docs requirements` after changing canonical REQ display metadata and enforce freshness with `specbound docs requirements --check` in CI.

A Discovery confirmation binds `schema_version`, `discovery_path`, `discovery_id`, `revision`, `sha256`, `risk_class`, `authority`, `confirmed_at`, `decision`, and `permitted_next_action`. After an explicit accountable decision, create it with `specbound discovery confirm dcy-<id>-r<revision> --authority <allowlisted-authority>`. The confirmer must be allowlisted for that Discovery's risk class by `policy.discovery_confirmation_authorities_by_risk`; its only permitted action is `draft_req_only`. `policy.discovery_confirmation_revision_policy: latest_only_with_explicit_exception` rejects a new confirmation of a lower revision while a higher revision exists unless an auditable supersession exception is recorded.

For a REQ whose frontmatter has `status: approved`, create the matching approval record. The approval JSON must bind `requirement_path`, `requirement_id`, `revision`, `sha256`, `risk`, and `authority`. `policy.requirement_revision_policy: latest_only_with_explicit_exception` rejects an approved lower revision when a newer numeric revision exists unless that older approval contains a substantive authority-bound `supersession_exception` with an ISO-8601 timestamp.

Issue a greenfield draft only through `specbound req draft dcy-<id>-r<revision> req-<id>-r<revision>`. The command is non-overwritable and fails closed unless the exact canonical parent Discovery is confirmed, its matching confirmation has the exact final digest, and its authorization is exactly `draft_req_only`.

The CLI fails closed on missing config, malformed frontmatter or control-plane records, unsafe paths (including symlinked canonical path components), path/identity/risk mismatch, missing approval/Discovery, invalid confirmation authority or timestamp, over-broad Discovery authorization, insufficient confirmed-Discovery evidence, and digest mismatch.

This slice does not yet validate Micro-SPEC, iteration evidence/QC, delivery request/QC, merge, or release records.
