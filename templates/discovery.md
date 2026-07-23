---
id: dcy-<id>
revision: <revision>
status: draft
title: <간결한 Discovery 제목>
issue_ref: <canonical tracker issue reference>
owner: <책임 역할 또는 담당자>
source_refs: []
risk_class: <repository-defined risk classification>
relationship: new # new | update | follow-up | superseding
related_discovery_refs: []
related_requirement_refs: []
---

# Discovery: <간결한 Discovery 제목>

> **Lifecycle boundary:** 이 Discovery의 lifecycle state는 frontmatter와 이에 대응하는 content-addressed confirmation record로만 결정된다. Its lifecycle state is determined by its frontmatter and matching content-addressed confirmation record. 이 문서는 approved requirement가 아니며 implementation, merge, delivery 또는 release를 절대 authorize하지 않는다. REQ draft는 `.specbound/confirmations/dcy-<id>-r<revision>.confirmation.json`의 유효한 confirmation record가 이 정확한 `.specbound/discoveries/dcy-<id>-r<revision>.md` snapshot에 `permitted_next_action: draft_req_only`로 binding될 때만 허용된다. repository protection, CI, 그리고 필요한 경우 signed 또는 external record가 이 local validator를 넘어서는 immutability를 강제한다.

## 0. Discovery context 및 lineage

- **Trigger / initiating change:**
- **Relationship:** `new` / `update` / `follow-up` / `superseding`
- **관련 Discovery 및 REQ 참조:**
- **기존 작업의 경미한 갱신이 아니라 새 Discovery 또는 revision이 필요한 이유:**
- **기존 approved scope, 진행 중 작업 또는 released behavior에 미치는 영향:**

존재하지 않는 관계를 평가한 경우 각 항목에 `None`을 쓴다. history를 덮어쓰지 않는다. material scope reset은 새 revision 또는 연결된 `follow-up`/`superseding` Discovery로 표현한다.

## 1. User intent (사용자 의도)

- **명시된 의도:**
- **출처 context:**
- **원문 인용 또는 충실한 요약:**

## 2. Problem and target users (문제와 대상 사용자)

- **문제:**
- **대상 사용자 / 영향받는 시스템:**
- **현재 상태와 evidence:**

## 3. Desired outcome and success signals (기대 결과와 성공 신호)

- **기대 결과:**
- **관찰 가능한 성공 신호:**
- **측정 또는 관찰 방법:**

> 이 절은 문제/결과 수준으로 유지한다. implementation Acceptance criteria는 여기에 쓰지 않고 REQ에 작성한다.

## 3a. Candidate requirement concerns (non-binding)

- **REQ로 구체화할 capability concern:**
- **REQ로 구체화할 quality, safety 또는 operational concern:**
- **REQ가 보존해야 하는 scope boundary:**

이 항목들은 Discovery hypothesis이며 REQ Acceptance criteria나 approved scope가 아니다. implementation을 사전 approval하지 않으면서 REQ handoff를 구체화하기 위해 존재한다.

## 4. 확인된 사실 (Confirmed facts)

| 사실 (Fact) | Evidence / source | 신뢰도 또는 한계 |
| --- | --- | --- |
| <사실> | <참조> | <한계> |

확인된 사실이 없으면 `None confirmed yet`를 쓴다.

## 5. 가정 및 가설 (Assumptions and hypotheses)

| 가정 또는 가설 | 중요성 | 검증 접근법 / owner |
| --- | --- | --- |
| <가정> | <영향> | <접근법> |

material assumption이 없으면 `None`을 쓴다.

## 6. Scope (범위)

- **In scope:**
- **영향받는 boundary/component:**
- **Dependency:**

## 7. Non-goals (비목표)

- **명시적으로 제외:**
- **후속 Discovery 또는 REQ로 defer:**

의미 있는 제외 사항이 없음을 확인한 뒤에만 `None`을 쓴다.

## 7a. 예상 변경 및 영향 (Expected change and impact)

- **예상 product/service behavior 변경:**
- **영향 가능성이 있는 boundary, component, document 또는 operational flow:**
- **예상 compatibility, migration 또는 rollout concern:**
- **검토한 repository/context evidence:**

이는 Discovery의 impact hypothesis다. 후속 Micro-SPEC가 bounded implementation slice와 그 verification evidence를 결정한다.

## 8. 대안 및 trade-off (Alternatives and trade-offs)

| 대안 | 장점 | 비용 / risk | 결정 또는 미선택 이유 |
| --- | --- | --- | --- |
| <대안> | <장점> | <비용> | <결정> |

substantive alternative가 없으면 `No material alternative identified`를 쓴다.

## 9. Risks, constraints, and dependencies (Risk, constraint 및 dependency)

| 항목 | Type | 영향 | Owner | 완화, 해소 조건 또는 defer 근거 |
| --- | --- | --- | --- | --- |
| <항목> | risk / constraint / dependency | <영향> | <owner> | <대응> |

평가 후 material risk, constraint 또는 dependency가 없을 때만 `No material risks, constraints, or dependencies identified`를 쓴다.

## 10. 결정 (Decisions)

| 결정 | Decider / authority | 근거 | 날짜 또는 source | 되돌릴 수 있는가? |
| --- | --- | --- | --- | --- |
| <결정> | <담당자/역할> | <근거> | <참조> | yes / no |

결정이 열려 있으면 `No decision made`를 쓴다. agent recommendation을 user decision으로 표현하지 않는다.

## 11. Open questions (미해결 질문)

| ID | 질문 | Type | Blocker? | Owner | 해소 또는 defer 조건 |
| --- | --- | --- | --- | --- | --- |
| OQ-1 | <질문> | DECIDE / CONFIRM / DATA | yes / no | <owner> | <조건> |

- `DECIDE`: accountable decision-maker의 product, policy, priority 또는 scope 선택이 필요하다.
- `CONFIRM`: fact, interpretation 또는 boundary를 검증해야 한다.
- `DATA`: 후속 수집 가능한 evidence 또는 measurement이며 REQ drafting blocker 여부를 명시한다.

stable한 Discovery-local ID(`OQ-1`, `OQ-2`, …)를 사용한다. 질문이 해결된 뒤에도 ID를 renumber하거나 reuse하지 말고, resolution을 함께 보존하여 review, confirmation, REQ handoff가 같은 decision을 인용하도록 한다.

미해결 material question이 없을 때만 `None`을 쓴다. 일반적인 `TBD`를 남기지 말고 typed question class와 resolution/defer condition을 쓴다.

## 12. Recommendation (권고)

- **권장 방향:**
- **이 방향을 권장하는 이유:**
- **수용하거나 defer한 trade-off:**

## 12a. REQ drafting readiness (REQ 초안 준비 상태)

- **Readiness assessment:** `not ready` / `ready for confirmation` / `confirmation pending`
- **scope와 Non-goals가 REQ draft에 충분히 bounded되었는가:** yes / no — <근거>
- **성공 신호를 REQ Acceptance criteria로 변환할 수 있는가:** yes / no — <근거>
- **Open question disposition:** 모든 blocking question 해소 / 명시적으로 defer / <잔여 blocker>
- **Risk와 dependency에 owner 또는 명시적 handling path가 있는가:** yes / no — <근거>
- **필요한 confirmation boundary:** 별도의 content-addressed confirmation record이며, 이 template은 self-confirm하지 않는다.

## 13. Proposed next authorized action (제안하는 다음 authorized action)

- **요청하는 다음 action:** `draft REQ only` / `<기타 non-implementation action>`
- **여전히 필요한 precondition:**
- **이 Discovery가 authorize하지 않는 것:** governing lifecycle가 별도로 authorize하지 않는 implementation, merge, delivery, release.

## Review checklist

- [ ] User intent와 agent assumption/recommendation이 구분된다.
- [ ] Trigger, lineage 및 관련 Discovery/REQ/delivery 작업 영향이 명시되었거나 부재를 평가했다.
- [ ] Problem, target user, desired outcome, scope, Non-goals, 예상 변경 영향이 명시적이다.
- [ ] Candidate requirement concern은 non-binding이며 approved Acceptance criteria처럼 보이지 않는다.
- [ ] Fact에는 evidence가 있고 assumption은 label 및 owner가 있다.
- [ ] Material alternative, risk, constraint, dependency, decision, Open question을 명시하거나 assessed/not applicable로 표시했다.
- [ ] 모든 Open question은 stable `OQ-<n>` ID, `DECIDE`/`CONFIRM`/`DATA` type, owner 및 resolution/defer condition을 가진다.
- [ ] REQ drafting readiness는 실제 blocker 및 confirmation state를 반영하며, 이 문서는 self-confirmation claim을 포함하지 않는다.
- [ ] 이 Discovery에 implementation Acceptance criteria, implementation authorization 또는 approval claim이 없다.
- [ ] 제안된 다음 action은 narrow하며 Discovery authority를 초과하지 않는다.
