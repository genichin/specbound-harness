---
id: req-<numeric-id>
revision: <positive-integer>
status: draft
risk: <parent-risk-class>
owner: <accountable-owner>
parent_discovery:
  id: dcy-<numeric-id>
  revision: <positive-integer>
  path: .specbound/discoveries/dcy-<numeric-id>-r<revision>.md
  sha256: <exact-confirmed-discovery-sha256>
  confirmation_path: .specbound/confirmations/dcy-<numeric-id>-r<revision>.confirmation.json
---

# REQ: <req-id> r<revision>

> **Lifecycle boundary:** 이 artifact의 lifecycle state는 frontmatter와 이에 대응하는 content-addressed decision record로만 결정된다. This artifact's lifecycle state is determined only by frontmatter plus its matching content-addressed decision record. `draft` 발급은 review, rejection, approval 또는 implementation 권한이 아니다. Draft issuance is not review, rejection, approval, or implementation authority.
>
> **Review handoff:** `draft` REQ는 먼저 `specbound req check-readiness <req-id>-r<revision>`를 통과한 뒤에만 `specbound req to-in-review <req-id>-r<revision>`로 제출한다. canonical CLI는 exact draft/reviewed digest를 가진 non-authorizing review-submission record와 `in_review` 상태를 rollback-safe하게 함께 발급한다. Lifecycle state는 canonical frontmatter와 matching digest-bound decision record로만 판정한다. 본문의 future-state, successor, draft-handoff prose는 단독 rejection blocker가 아니다. `in_review` REQ의 rejection에는 exact reviewed digest, structured blocker code, 재현 가능한 evidence, allowlisted authority를 가진 review-decision record가 선행되어야 한다. Approval, implementation, merge, delivery, and release remain separate actions.

## 목표 (Goal)

<검증 가능한 결과>

## Scope (범위)

- <포함되는 동작>

## Non-goals (비목표)

- approval 발급, implementation, merge, delivery, release는 각각 별도의 action이다.

## Acceptance criteria

> **AC completion contract:** 각 AC는 독립적으로 검토 가능한 observable behavior를 기술해야 한다. 모든 field의 placeholder를 review 전에 실제 내용으로 교체한다. 이 template은 approval 또는 implementation 권한을 부여하지 않는다.

### AC-001 — <짧고 구체적인 결과 이름>

- `observable_success`: <사용자·CLI·fixture가 관찰할 성공 결과>
- `required_preconditions`: <필요한 parent, authority, input, state, fixture>
- `mutation_boundary`: <허용되는 mutation 및 절대 변경하면 안 되는 대상>
- `negative_behavior`: <invalid/failure request의 reject 결과와 no-mutation 보장>
- `direct_evidence`: <이 AC의 성공·실패를 직접 증명할 command, fixture, assertion>
- `dependencies`: <none 또는 선행 AC ID / shared contract>
- `completion_group`: <이 AC만으로 완료 가능한 경우 자체 group; 함께 완료해야 하면 group ID와 이유>
- `candidate_micro_spec`: <예상 Micro-SPEC slice ID 또는 아직 미정인 이유>
- `non_goals`: <이 AC를 완료해도 주장하지 않는 behavior>

### AC-002 — <필요한 만큼 같은 completion contract를 복제>

- `observable_success`: <...>
- `required_preconditions`: <...>
- `mutation_boundary`: <...>
- `negative_behavior`: <...>
- `direct_evidence`: <...>
- `dependencies`: <none 또는 AC ID>
- `completion_group`: <group ID와 이유>
- `candidate_micro_spec`: <예상 slice ID 또는 이유>
- `non_goals`: <...>

`draft` REQ must pass `specbound req check-readiness` before review submission. Use `specbound req to-in-review` for the canonical rollback-safe handoff; never patch `status` manually.

## Approval handoff

이 정확한 draft를 별도로 review한다. artifact 발급 사실만으로 approval을 추론하지 않는다.
