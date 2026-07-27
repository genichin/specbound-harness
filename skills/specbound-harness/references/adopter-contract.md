# SpecBound adopter contract — implemented control-plane slice

An adopting repository must place `specbound.yaml` at its root. The current validator accepts only this canonical topology:

## Agent-contract boundary

The opt-in, provider-neutral agent contract defines exactly seven roles. A configured Hermes adapter maps each invocation to one configured model alias, the role's exact skill bytes, and a fresh isolated one-shot context; the portable request/result schemas contain no Hermes, provider, profile, session, or workdir fields. When the contract is disabled, the manual lifecycle workflow remains valid without agent policy or role-skill artifacts. Validation is read-only and non-authorizing: neither a valid envelope nor a successful dispatch may issue confirmation, approval, review-decision, verified, Delivery, Merge, or Release authority. Enabling repository validation is not a live Hermes rollout; runtime rollout and credentials remain a separate explicit operator action.

```text
.specbound/discoveries/dcy-<numeric-id>-r<revision>.md
.specbound/confirmations/dcy-<numeric-id>-r<revision>.confirmation.json
.specbound/requirements/req-<numeric-id>/req-<numeric-id>-r<revision>.md
.specbound/approvals/req-<numeric-id>-r<revision>.approval.json
.specbound/rejections/req-<numeric-id>-r<revision>.rejection.json
.specbound/review-submissions/req-<numeric-id>-r<revision>.review.json
.specbound/review-decisions/req-<numeric-id>-r<revision>.decision.json
.specbound/reconsiderations/req-<numeric-id>-r<revision>.reconsideration.json
.specbound/micro-specs/req-<numeric-id>/ms-<numeric-id>-<slice>.md
.specbound/micro-spec-reviews/req-<numeric-id>/ms-<numeric-id>-<slice>.review.json
.specbound/iteration-qc/req-<numeric-id>/iqc-<numeric-id>-<slice>-r<revision>.json
.specbound/delivery-qc/dqc-<numeric-id>-r<revision>.json
.specbound/policies/agent-roles.yaml
skills/<role-id>/SKILL.md
```

The exact seven role IDs are `discovery-author`, `requirement-author`, `micro-spec-author`, `independent-reviewer`, `implementation`, `iteration-qc`, and `delivery-qc`; do not add implicit aliases or role chains. Adoption is default-disabled and requires an explicit repository-local opt-in:

```yaml
policy:
  agent_contract:
    enabled: false
    roles_path: .specbound/policies/agent-roles.yaml
```

Changing `enabled` to `true` activates repository validation only after the exact policy and all seven exact skill paths exist. It does not dispatch Hermes or authorize a live rollout.

`docs/requirements.md` is a generated, user-facing projection of the latest canonical REQ revisions. It is not lifecycle state. Run `specbound docs requirements` after changing canonical REQ display metadata and enforce freshness with `specbound docs requirements --check` in CI.

A Discovery confirmation binds `schema_version`, `discovery_path`, `discovery_id`, `revision`, `sha256`, `risk_class`, `authority`, `confirmed_at`, `decision`, and `permitted_next_action`. After an explicit accountable decision, create it with `specbound discovery confirm dcy-<id>-r<revision> --authority <allowlisted-authority>`. The confirmer must be allowlisted for that Discovery's risk class by `policy.discovery_confirmation_authorities_by_risk`; its only permitted action is `draft_req_only`. `policy.discovery_confirmation_revision_policy: latest_only_with_explicit_exception` rejects a new confirmation of a lower revision while a higher revision exists unless an auditable supersession exception is recorded.

For a REQ whose frontmatter has `status: approved`, create the matching approval record. The approval JSON must bind `requirement_path`, `requirement_id`, `revision`, `sha256`, `risk`, and `authority`. `policy.requirement_revision_policy: latest_only_with_explicit_exception` rejects an approved lower revision when a newer numeric revision exists unless that older approval contains a substantive authority-bound `supersession_exception` with an ISO-8601 timestamp.

Issue a greenfield draft only through `specbound req draft dcy-<id>-r<revision> req-<id>-r<revision>`. The command is non-overwritable and fails closed unless the exact canonical parent Discovery is confirmed, its matching confirmation has the exact final digest, and its authorization is exactly `draft_req_only`.

The CLI fails closed on missing config, malformed frontmatter or control-plane records, unsafe paths (including symlinked canonical path components), path/identity/risk mismatch, missing approval/Discovery, invalid confirmation authority or timestamp, over-broad Discovery authorization, insufficient confirmed-Discovery evidence, digest mismatch, malformed Micro-SPECs, invalid iteration-QC, invalid delivery-QC, and—when the opt-in agent contract is enabled—missing or stale role policy/skill bytes.

The public agent commands are `specbound agent validate-skills`, `specbound agent check-role-request`, and `specbound agent validate-result`; all are read-only and do not dispatch. Installed-wheel verification must prove imports originate in `site-packages`, compare the packaged role/result/adapter/invocation schemas byte-for-byte with repository schemas, and execute the full integration/adapter matrix outside the checkout with `PYTHONPATH` cleared. Micro-SPEC, iteration-QC, and delivery-QC validation are implemented, but their evidence remains non-authorizing: Delivery, Merge, and Release decisions are separate and remain outside this agent contract.
