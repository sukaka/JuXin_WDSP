# NG-AZ-04 管理向导 / 影响评估 / 全链验收 冻结设计（S3 阶段 4 设计稿，2026-10-05）

> 依据：`docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md` §8.4（授权页面六要素：来源/有效期/冲突/最后同步时间/节点 ACK/当前能否实断；分权；切 PROTECT 四要素前置；集成四断言；跨租户/撤销回滚/快照过期/旧节点/断网/时钟偏差/重新授权用例）+ §15.2 NG-AZ-04 行（完成证据：页面 E2E、审计、业务确认单）。
> 本设计是 S3 授权实断线的收尾：把 AZ-01（权威接入）/AZ-02（水位/租约/ACK）/AZ-03（VERIFIED_VIOLATION 与 PROTECT 开关）已落地能力接到管理界面，并完成全链验收。
> 前置事实（inventory 复核 2026-10-05）：
> - server 既有 API 面（均已上线）：`GET /api-security/authz/node-acks`（apiauthzacks，STALE_WITHIN_LEASE/STALE_EXPIRED/NEVER_ACKED/CLOCK_SKEW/FRESH 派生在服务端）；`GET /api-security/authz/authorities{,/{id},/{id}/status}`（status 内嵌 watermark/gap_status/conflicts(OPEN≤50)/batches(≤20)）；`GET/POST .../authz/relations{,/{id}/revoke,/{id}/reauthorize}`；`GET .../authz/decisions{,/{id}}`（decision 过滤含 VERIFIED_VIOLATION，evidence 内嵌 authz_enforcement 按 evidence_read 裁剪）；`GET .../authz/coverage`；`PATCH /api-security/object-models/{id}`（publishable/OWNER/排他/on_lease_expired + enforcement 四要素强制前置，NG-AZ-03）；`applications.authz_lease_seconds` 写入路径。**conflicts 无独立查询端点**（仅嵌在 authorities status）；**readiness/影响评估/确认单 API 均不存在**。
> - 前端现状（`web/src/`）：授权主页 `pages/api-authz/ApiAuthzPage.tsx`（Tabs：对象授权/角色基线/对象权属/字段权限 + BOLA 评估工具；`ObjectAuthorizationTab` 已有候选确认/关系/决策三列表与 coverage 统计）；对象模型表格在 `pages/api-access-profiles/ApiAccessProfilesPage.tsx` 对象维度 Tab（详情抽屉，**无 PATCH 入口、无 enforcement 字段**）；`api/apiAuthz.ts`（decisions/relations/candidates/coverage client）与 `api/apiSecurity.ts`（apiObjectModelsApi 仅 list）；decisionStatus 三值映射（ALLOW/OBSERVE_VIOLATION/UNKNOWN）；权限惯例 `useAuthStore`+`hasPermission`；TanStack Query + AntD 5（SmartTable/StatusTag/Drawer/Modal/Steps/Statistic 既有封装）。**前端无 authorities 管理页面**（NG-AZ-01 管理面仅 server API）。
> - E2E 现状（`web/e2e/`）：Playwright + `helpers.ts`（Valkey 读验证码真实登录）、场景 spec 惯例（scenario/stage 系列）、`global-setup/teardown`；构建 `tsc -b && vite build`，`typecheck`/`lint`/`vitest run`。
> - 运行事实（AZ-03 联调）：PATCH enforcement 与网关发布是两阶段——PATCH 落库成功后发布仍可能因能力门（az/3 需求）fail-closed，「配置与生效不一致」是真实可达状态，向导必须如实呈现。

## 1. 冻结契约

### 1.1 信息架构（六要素落位）

不新建独立「授权态势」页。六要素聚合落在既有授权主页 **`ApiAuthzPage` 新增第五个 Tab「态势与实断资格」**（每应用维度），明细数据仍归原 Tab/原页面编辑：

| 要素 | 落位 | 数据来源（既有/新增） |
|---|---|---|
| 来源（MANUAL/AUTHORITY_SYNC） | 态势 Tab 关系摘要行 + 关系明细列（对象授权 Tab 既有表格加 source 列） | 既有 relations API（source/source_id 列已在响应） |
| 有效期（valid_from/valid_until） | 态势 Tab 关系摘要行 + 关系明细列（既有） | 既有 relations API |
| 冲突（OPEN 冲突对象） | 态势 Tab 冲突区块（对象类型/对象引用/涉及主体数/首次冲突时间） | **新增** `GET .../authz/conflicts`（独立查询，见 D1 注；不再只嵌 authorities status） |
| 最后同步时间 | 态势 Tab 来源区块（AUTHORITY_SYNC：最近批次 applied_at + gap_status；MANUAL：关系 updated_at 最大值） | 既有 `authorities/{id}/status` + relations API |
| 节点 ACK | 态势 Tab 节点区块（ack_state 徽章/陈旧秒数/快照版本/水位） | 既有 `GET .../authz/node-acks` |
| 当前能否实断 | 态势 Tab 端点表格 readiness 徽章列 + 对象模型表格（访问画像页）同徽章列 | **新增** `GET .../authz/enforcement-readiness`（D2） |

D1 注：conflicts 独立查询端点的理由——authorities status 的冲突列表按来源聚合且上限 50，态势视图需要按应用过滤的全量 OPEN 冲突分页列表；新端点只读、沿用 `api_authorization.read`，列同 ConflictRecord。

### 1.2 「能否实断」readiness 服务端派生（D2 结论：服务端派生 API，非前端拼装）

`GET /api/v1/api-security/authz/enforcement-readiness?application_id=<uuid>&endpoint_id=<uuid, 可省>`，返回端点级徽章列表（按端点对象模型行逐行派生）：

```
READY                 可实断：publishable+OWNER+排他+端点 CONFIRMED + 存在有效 OWNER 关系
                      + 无 OPEN 冲突 + 快照未过期/租约正常 + 全部网关节点 ACK=FRESH 且自报 az/3
PROTECT_ACTIVE        当前 enforcement=PROTECT（展示态；阻塞因子仍随附供排障）
NOT_PUBLISHABLE       资格字段不齐（publishable=false / required_relation≠OWNER / 排他=false / 端点非 CONFIRMED）
BLOCKED_BY_NO_RELATION 无有效 OWNER 关系（OTHER_OWNER 不成立，VERIFIED_VIOLATION 永不产生）
BLOCKED_BY_CONFLICT   该端点对象类型存在 OPEN 冲突（D7 UNKNOWN，不阻断）
BLOCKED_BY_STALE      快照过期/租约过期 strict/时钟偏差（D7 UNKNOWN，不阻断）
BLOCKED_BY_NODE       任一在线节点 ACK≠FRESH 或自报能力 < az/3（实断配置将被能力门 fail-closed）
```

逐行响应字段：`endpoint_id/endpoint_key/object_segment/enforcement/readiness/reasons[]（全部不真因子原文，而非仅首个）/checked_at`。派生规则为**唯一事实源**（与网关消费侧同语义的服务端翻译）；readiness 是切换预评估而非决策承诺（徽章 tooltip 固定注明「UNKNOWN 永不阻断」）。

服务端派生而非前端拼装的理由：①判定口径（八因子+时效+水位+ACK）与网关同语义，前端拼装等于把判定逻辑复制到 JS，双写漂移必然；②分权——`api_authorization.read` 可见徽章与 reasons 摘要，样本/证据明细按 `evidence_read` 裁剪，裁剪点在服务端一处实现；③影响评估（D3）与向导（D5）复用同一派生，不三处实现。

### 1.3 影响评估（切换前预览）

`POST /api/v1/api-security/authz/enforcement-impact`（只读评估动作用 POST 承载复杂参数；**不产生任何写副作用**）：

```json
请求：{"endpoint_id":"<uuid>","window_days":7}
响应：{
  "endpoint_id":"…","endpoint_key":"GET /api/v1/tenants/{id}/projects/p002/items","object_segment":"path:3",
  "window_days":7,"evaluated_at":"…",
  "observe_violation_count":12,          // 切换后将被 403 的请求量近似（decision='OBSERVE_VIOLATION'）
  "unknown_total":34,
  "unknown_by_reason":[{"reason_code":"AUTHZ-IDENTITY-001","count":20},…],   // UNKNOWN 分桶
  "distinct_principal_count":5,          // 涉及主体数（VERIFIED 主体指纹 distinct）
  "verified_violation_count":0,          // 已实断数（PROTECT 复评时非零）
  "recent_samples":[                     // ≤5 条脱敏样本（evidence_read 权限才返回，否则省略）
    {"occurred_at":"…","decision":"OBSERVE_VIOLATION","reason_code":"AUTHZ-BOLA-001"}],
  "readiness":"READY","readiness_reasons":[],   // 复用 D2 派生
  "confirm_token":"<uuid>","confirm_token_expires_at":"…"   // 一次性签署令牌（仅 api_authorization.manage 调用才签发）
}
```

边界（冻结）：window_days ∈ 1~30（词表外 400）；数据源 `api_authorization_decisions`（decision/checks 列，按 endpoint_key+occurred_at 索引有界扫描）+ `api_runtime_events`（主体计数）；单接口一次聚合 + LIMIT 5 样本；评估结果**不入库**（确认单才入库）；`api_authorization.read` 可评估（无 token 签发），`api_authorization.manage` 评估同时签发 confirm_token。

### 1.4 业务确认单（迁移 000175）

表 `api_authz_enforcement_confirmations`：

```sql
id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
confirm_token   UUID NOT NULL UNIQUE,              -- 一次性签署令牌（影响评估响应签发）
application_id  UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
endpoint_id     UUID NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
object_segment  TEXT NOT NULL DEFAULT '',          -- 确认粒度 = 对象模型行（端点×对象段）
window_days     INTEGER NOT NULL,
impact_snapshot JSONB NOT NULL,                    -- 签署时刻影响评估摘要全量（§1.3 响应无 token 键）
confirm_text    TEXT NOT NULL,                     -- 冻结确认语义文案（含文案版本号，见下）
enforcement_owner TEXT NOT NULL,                   -- 四要素先签后切换
evidence_source TEXT NOT NULL CHECK (evidence_source IN ('AUTHORITY_SYNC','MANUAL_CONFIRMED')),
on_unknown      TEXT NOT NULL DEFAULT 'ALLOW_UNKNOWN' CHECK (on_unknown='ALLOW_UNKNOWN'),
confirmed_by    UUID NOT NULL, confirmed_by_name TEXT NOT NULL,
created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
token_expires_at TIMESTAMPTZ NOT NULL,             -- 签发后 15 分钟
signed_at       TIMESTAMPTZ,                       -- 向导第 4 步签署时刻（签署动作落库）
consumed_at     TIMESTAMPTZ,                       -- PATCH 消费时刻（NULL=未消费）
consumed_audit_id TEXT NOT NULL DEFAULT ''         -- 消费它的切换审计 ID（溯源闭环）
```

切换强制引用（冻结）：`PATCH /api-security/object-models/{id}` 当 `enforcement=PROTECT` 时**必须携带 `confirm_token`**——服务端在同一事务内：①校验 token 存在、未消费（consumed_at IS NULL）、未过期、endpoint_id/object_segment 绑定一致、已签署（signed_at 非空）；②执行 enforcement 切换（四要素既有校验不变）；③置 `consumed_at`+`consumed_audit_id`。任一不满足 400（精确消息区分：token 不存在/已消费/已过期/端点绑定不符/未签署）。**切回 OBSERVE 不要求 token**（延续 AZ-03「切回无前置」）。确认单留存不删（历史事实，与「回滚不回退事实」同纪律）。

确认语义文案（冻结 v1，随 confirm_text 落库）：「我已知悉：本端点切换 PROTECT 后，经显式资格判定成立的违规请求将被实断（403 AUTHZ_VIOLATION_DENIED）；UNKNOWN 永不阻断。近 {window_days} 天观测违规 {observe_violation_count} 次、涉及主体 {distinct_principal_count} 个；我（{confirmed_by_name}）作为业务负责人确认承担实断影响。（确认文案 v1）」

### 1.5 PROTECT 切换向导 UX（D5）

入口：态势 Tab 端点表格行操作「切换 PROTECT」+ 访问画像页对象模型详情抽屉同入口。AntD Steps 五步：

1. **选端点**：仅列出 publishable 候选对象模型行（readiness 徽章随行展示；NOT_PUBLISHABLE 行禁用并注明缺项）。
2. **影响评估**：进入即请求 §1.3 API；展示命中数（切换后将 403 的近似量，红色 Statistic）、UNKNOWN 分桶（注明永不阻断）、主体数、readiness 徽章与 reasons；命中数 >0 时固定警示条「这些请求切换后将被实断」。
3. **四要素填写**：enforcement_owner（≤128 计数）/evidence_source（二选一词表说明）/on_unknown（固定 ALLOW_UNKNOWN 只读 + 「UNKNOWN 永不阻断」说明）；readiness 非 READY 时允许继续但黄条列出阻塞因子（如实预期管理：切换后也可能不实断）。
4. **确认单签署**：影响摘要回显 + 冻结确认文案（占位符已替换）+ 勾选「我已阅读并确认」→ 提交签署（signed_at 落库）。
5. **提交与结果**：PATCH（携带 confirm_token + 四要素）→ 触发发布 → 轮询发布任务：SUCCESS 展示「已生效」+ decisions 链接；**FAILED 如实展示「配置与生效不一致」**——enforcement 已落库 PROTECT 但节点未应用，完整展示 failure_code/failure_message（含 `CAP_MISSING:detectors.authzdecide(required=az/3,actual=az/2)` 缺口明细）与修复指引（升级节点/回退 OBSERVE），并提供「立即切回 OBSERVE」快捷操作。

失败路径（冻结）：PATCH 400（要素/token）回对应步骤并保留表单；token 过期（15 分钟）回第 2 步重新评估签发；发布 LOCK_BUSY 自动重试（沿用 s5_publish 退避惯例）；能力门拒绝不自动回退（如实呈现，由人决策——不替操作者做静默决定）。

## 2. 冻结决策点（D1~D10）

### D1 六要素信息架构：聚合 Tab，不新建页面

- **结论**：六要素聚合于 `ApiAuthzPage` 新 Tab「态势与实断资格」（每应用维度），明细编辑仍归原 Tab/页面；conflicts 新增独立只读查询端点（`GET .../authz/conflicts?application_id=&status=OPEN`，分页，沿用 `api_authorization.read`）。
- **理由**：§8.4「授权页面展示」指同一页面语境——六要素共同回答「这个端点现在切 PROTECT 会发生什么」，分散到四个既有 Tab 会割裂判断语境；新建独立页面则与 ApiAuthzPage 功能重叠。聚合 Tab + 明细原位是信息架构最小增量。

### D2 readiness 服务端派生 API（结论见 §1.2，枚举六态+PROTECT_ACTIVE 展示态）

- **结论**：新增 `GET .../authz/enforcement-readiness`，服务端唯一事实源派生；前端只渲染徽章与 reasons。
- **理由**：判定口径单点维护（防 JS/Go 双写漂移）、分权裁剪单点实现、影响评估与向导复用。前端拼装被否的三条理由同此。

### D3 影响评估 API 形状与边界（结论见 §1.3）

- **结论**：`POST .../authz/enforcement-impact`（只读，POST 承载参数）；窗口 1~30 天；`api_authorization.read` 可评估、manage 评估同时签发一次性 confirm_token；评估结果不入库。
- **理由**：「切换后将 403 多少请求」必须用量化的近因证据回答（decisions 表 decision 列直接可聚合，无需回扫 events 全文）；样本按 evidence_read 裁剪保持分权纪律；token 与评估绑定使「确认的是这份影响面」可验证（端点绑定+15 分钟 TTL，不做内容哈希强一致——数据漂移以 evaluated_at 如实呈现，不过度工程）。

### D4 业务确认单：强制引用、同事务消费（结论见 §1.4）

- **结论**：迁移 000175 单表；PATCH enforcement=PROTECT 强制 `confirm_token`（校验+切换+消费同一事务）；切回 OBSERVE 免 token。
- **理由**：§15.2 完成证据点名「业务确认单」——确认单把「谁、何时、基于哪份影响面、确认了什么语义」落成不可篡改记录；强制引用使「先评估后切换」成为系统约束而非流程倡议；同事务消费杜绝 token 复用与半切换状态；粒度=对象模型行（与 enforcement 列同粒度）。

### D5 向导五步流程与失败路径（结论见 §1.5）

- **结论**：Steps 五步（选端点→影响评估→四要素→签署→提交与结果）；能力门/发布失败如实展示「配置与生效不一致」并提供快捷切回，不自动回退。
- **理由**：五步与四要素前置+确认单的系统约束一一对应；「配置与生效不一致」是两阶段（PATCH/发布）的固有可达状态，隐瞒它比展示它危险得多（管理面误以为实断生效）。

### D6 双人复核：本批不做，页面如实标注单人模式

- **结论**：不做（延续 AZ-03 D8）。确认单区块固定标注：「当前为单人切换模式——签署人与操作人可为同一账户；生产环境建议经内部流程复核后操作。」
- **理由**：RD_PLAN §6 列为候选机制非首批强制；确认单（签署+影响面快照+HIGH 审计）已构成切换动作即审计证据的最低保障；双人复核的工作流（发起/审批/超时/代批/通知）是独立复杂域，并入向导批会使两批都做不好。标注义务履行「不隐瞒治理缺口」。

### D7 VERIFIED_VIOLATION 与证据的页面呈现（事件/决策层，不报表归并）

- **结论**：`decisionStatus` 加第四值（VERIFIED_VIOLATION → 红色「已验证违规（实断）」）；决策详情抽屉新增 authz_enforcement 区块（eligibility 逐项布尔对错图标、model_version/policy_version/revocation_watermark/lease_seconds/applied_at_age_seconds、enforcement_owner/evidence_source、recorded_at；BFLA 形态如实展示其实评键集与 object_ref 空）；OBSERVE 形态 `proposed_decision` 展示「拟实断（当前 OBSERVE 不实断）」；api-runtime-events 详情同带 final_decision.authz_enforcement 区块。
- **理由**：「为什么被实断」的可答性是 AZ-03 证据结构的设计目的，详情层直读原样；报表归并（派生视图 UI 化）属独立批次（§3 顺延）。

### D8 权限/审计映射

- **结论**（逐区块）：
  | 动作 | 权限点（全部既有，零新增） |
  |---|---|
  | 态势 Tab / readiness / conflicts / node-acks 查询 | `api_authorization.read` |
  | 影响评估 | `api_authorization.read`（样本明细另需 `api_authorization.evidence_read`，无则省略） |
  | 确认单签发（含 token） | `api_authorization.manage` |
  | 确认单查询 | `api_authorization.read` |
  | PATCH enforcement（携带 token） | `api_authorization.manage`（既有） |
- 审计：确认单签发（create，`object_type=api_authz_enforcement_confirmation`，risk=HIGH，after 摘要含端点/影响面计数/签署人）；PATCH 切换沿用既有 HIGH 审计并在 after 摘要追加 `confirm_token`（溯源闭环）；影响评估/查询不审计（只读）。
- 越权对照：jiuzhang_admin（SYSTEM_ADMIN，无 api_authorization.*）对全部新端点 403（E2E 断言）。

### D9 测试计划

- **页面 E2E（Playwright，`web/e2e/authz-protect-wizard.spec.ts`）**：①态势 Tab 六要素展示（含 readiness 徽章与 node-acks 区块）；②向导五步全流（选端点→评估数字非空→四要素校验→签署→提交→发布 SUCCESS→decisions 过滤 VERIFIED_VIOLATION 可见）；③能力门阻塞提示（az/2 自报形态下发布 FAILED→「配置与生效不一致」区块+缺口明细+快捷切回）；④jiuzhang_admin 越权 403（新端点+确认单签发）；⑤VERIFIED_VIOLATION 决策详情证据区块。
- **server 单测**：readiness 派生矩阵（六态+PROTECT_ACTIVE+reasons 全列）；影响评估聚合（窗口夹紧 1/30/31 词表、分桶、主体计数、样本权限裁剪、token 仅 manage 签发）；确认单生命周期（签发→签署→消费/过期拒绝/复用拒绝/绑定不符拒绝/未签署拒绝）；PATCH+token 同事务（失败回滚不留半切换）。
- **全链验收矩阵（§8.4 用例群）**：
  | 用例 | 覆盖状态 |
  |---|---|
  | 跨租户同名对象 | AZ-03 联调已覆盖（N9 TENANT-001 OBSERVE_VIOLATION 放行）——本批页面层复验展示 |
  | 撤销后回滚 | AZ-02 已覆盖（水位回退拒载）+ AZ-03 N4（撤销 UNKNOWN 放行） |
  | 快照过期 | AZ-02 已覆盖（PreviousValid 资格过滤/拒载） |
  | 旧节点 | AZ-03 已覆盖（C08 三态）——本批向导阻塞提示 E2E 复验 |
  | 断网（节点失联） | **本批补**：节点心跳停止 → node-acks NEVER_ACKED/STALE_EXPIRED 展示 + readiness=BLOCKED_BY_NODE（页面 E2E 或 stage5 停容器法） |
  | 时钟偏差 | AZ-02 已覆盖（skew 判定与 ACK CLOCK_SKEW 列）；stage5 注入限制同 AZ-03 注明 |
  | 重新授权 | AZ-02 已覆盖（reauthorize CONFIRMED 恢复）——本批关系 Tab 操作路径页面 E2E 补 |
  | 集成四断言（客户端/源站/决策/事件） | AZ-03 联调已系统覆盖——本批不重复网关侧，页面 E2E 复用其数据链 |

### D10 兼容/增量/本批不做

- **OpenAPI 增量**：新端点 4（enforcement-readiness / enforcement-impact / confirmations 签发+查询）+ conflicts 独立查询 1 = **+5，预估 691**（基线 686；逐一对账双向零差集）。PATCH object-models 请求 schema 加 `confirm_token` 可选字段（仅 PROTECT 必填的语义在 description 注明）。
- **迁移预估**：000175 单表（§1.4 DDL）；无既有表变更。
- **前端约束**：零新增重依赖（AntD Steps/Statistic/Descriptions 既有；分布展示用表格+Statistic 不引入新图表库）；typecheck/lint/vitest 全绿为合入门槛；api client 复用 `request`/`PageResult` 惯例。
- **本批不做（如实标注）**：VERIFIED_VIOLATION 报表归并与风险中心展示（派生视图 UI 化）；TENANT-001 阻断资格评审；角色基线 enforcement 行级管理写通道（「显式行级 OBSERVE 覆盖端点」语义随该通道评审）；双人复核工作流（D6）；权威来源管理页面与删除端点（NG-AZ-01 移交顺延，本批只做态势只读区块）；确认单列表页（查询 API 先行，页面从审计与决策详情可达）；ha-lab 双节点分区演练（顺延）。

## 3. 本批不做（范围外，如实标注）

见 D10 末节清单。特别强调：任何「页面有了即治理完成」的表述禁止——双人复核、报表归并、TENANT-001 均为明示顺延项。

## 4. 实现拆分建议（文件级边界；三轨可并行）

**共享契约先冻结（本文件 §1.2/§1.3/§1.4 即契约）**：readiness 枚举与 reasons 语义、影响评估响应形状、confirm_token 生命周期、PATCH `confirm_token` 字段——三轨按此并行，互不等待。

**A. server 轨**（`server/` 独占）
- `migrations/000175_authz_enforcement_confirmations.{up,down}.sql`；
- `apiauthz/` 或新包 `apiauthzwizard`：readiness 派生（`enforcement_readiness.go`：六态规则+reasons 全列，ACK/能力数据读 `apiauthzacks` 与节点清单）、影响评估聚合（`enforcement_impact.go`：decisions 聚合+窗口夹紧+样本权限裁剪+token 签发）、确认单 store（`confirmations.go`：签发/签署/消费事务）；
- `apisecurity/object_models_update.go`：PATCH 增 confirm_token 校验+同事务消费（仅 PROTECT 分支）；
- OpenAPI 片段登记 + reconcile。
- 产出物：四个新端点 + PATCH 扩展 + 迁移。

**B. web 轨**（`web/` 独占）
- `api/apiAuthz.ts`：四个新端点 client + 类型（与 §1.2/1.3/1.4 逐键一致）；`api/apiSecurity.ts`：apiObjectModelsApi 增 patch + enforcement 四字段类型；
- `pages/api-authz/`：`PostureTab.tsx`（态势 Tab：六要素区块+端点 readiness 表格+切换入口）、`ProtectWizard.tsx`（Steps 五步向导，§1.5 状态机）、`ObjectAuthorizationTab.tsx`（decisionStatus 第四值+authz_enforcement 详情区块+source 列）；
- `pages/api-access-profiles/ApiAccessProfilesPage.tsx`：对象模型表格 readiness 徽章列 + 详情抽屉 enforcement 区块与向导入口；
- vitest 组件测试（readiness 徽章渲染/向导步骤状态机/权限裁剪）。
- 产出物：页面与向导。

**C. E2E/验收轨**（`web/e2e/` + stage5）
- `web/e2e/authz-protect-wizard.spec.ts`（D9 五场景）；
- stage5 全链验收矩阵复验（D9 表格：断网用例补齐 + 已覆盖项页面层复验）；
- 验收对账：OpenAPI reconcile、typecheck/lint/vitest、Playwright 全绿、stage5 回归 40/40+13/13 不回退。

**边界**：A 不动页面；B 不动 server；C 只消费冻结契约。B 轨可先用 §1 形状 mock 起步，A 轨上线后切换真端点零改动（client 形状即契约）。

## 5. 移交项（后续批次）

- VERIFIED_VIOLATION 报表归并（reason_code+enforced 派生视图）与风险中心展示。
- 双人复核工作流（发起/审批/超时/通知）与确认单审批化演进。
- 角色基线 enforcement 行级管理通道（含「显式行级 OBSERVE 覆盖端点」语义定稿）。
- TENANT-001 阻断资格评审（租户语义数据齐备后）。
- 权威来源管理页面（NG-AZ-01 移交）与确认单列表页。

## 6. 实现状态（2026-10-05 集成验收批补记；本节为实施记录，不改上文契约）

**状态：已落地并经 stage5 联调 + Playwright E2E 验收。** A（server）/B（web）/C（集成验收）三轨按 §4 边界实施，出口判定见 `docs/nextgen/s3/S3-AZ04-EXIT-NOTE.md`。

### 6.1 决策点映射（D1~D10 → 实现位置）

| 决策 | 实现 |
|---|---|
| D1 六要素信息架构 | `web/src/pages/api-authz/PostureTab.tsx`（态势与实断资格 Tab：统计卡五枚 + 关系来源与最后同步 + 冲突表 + 节点 ACK 表 + 端点 readiness 表格）；`server/internal/apiauthzwizard/handler.go ListConflicts`（OPEN 冲突独立分页查询） |
| D2 readiness 服务端派生 | `apiauthzwizard/readiness.go DeriveReadiness`（六态纯函数唯一事实源）+ `handler.go collectNodeFacts`（ACK 复用 apiauthzacks.BuildView + 快照过期直查 + sidecar 能力检查 `capability.go`）+ 前端 `components/AuthzEnforcement.tsx ReadinessBadge` 只渲染 |
| D3 影响评估 | `apiauthzwizard/impact.go`（窗口词表/decisions 键族聚合/主体计数/样本裁剪）+ `EvaluateImpact`（read 评估 / manage 评估同时签发 token） |
| D4 业务确认单 | 迁移 `000175_authz_enforcement_confirmations`（签发→签署→消费全列）+ `store.go IssueConfirmation/SignConfirmation/ConsumeConfirmToken` + `apisecurity/object_models_update.go` PATCH 同事务（五类 400 精确区分，失败整体回滚） |
| D5 向导五步 | `web/src/pages/api-authz/ProtectWizard.tsx`（Drawer+Steps；preset 入口直进第 2 步；能力门 FAILED 展示「配置与生效不一致」+缺口明细+Popconfirm 快捷切回不自动回退） |
| D6 双人复核不做 | 确认单签署区固定文案（SINGLE_OPERATOR_NOTE：单人切换模式如实标注） |
| D7 VERIFIED_VIOLATION 呈现 | `ObjectAuthorizationTab`（decisionStatus 第四值「已验证违规（实断）」+ 详情抽屉 AuthzEnforcementBlock）；`ApiRuntimeEventsPage` 详情抽屉「授权实断证据」区块（final_decision.authz_enforcement，空态不渲染） |
| D8 权限/审计 | 零新增权限点（read/evidence_read/manage 既有映射）；确认单签署 HIGH 审计 + PATCH after 摘要追加 confirm_token；consumed_audit_id=request_id 溯源闭环；jiuzhang_admin 全 403（单测+E2E 双证） |
| D9 测试 | server：readiness 六态矩阵/impact 聚合/确认单生命周期/consume 五类/PATCH 事务回滚/迁移 up-down；web：vitest（PostureTab/ProtectWizard 状态机/ApiRuntimeEventsPage 证据区块）；Playwright 五场景全绿；stage5 联调六组（向导全流/五拒/断网/越权/readiness 三态/多行拒猜义） |
| D10 兼容/增量 | OpenAPI +5 → 691（reconcile 双向零差集）；迁移 000175 单表零既有表变更；前端零新重依赖（AntD 既有组件） |

### 6.2 A 轨偏差登记（7 条，承接 A 轨回报）

1. 确认单四要素列可空（§1.4 DDL NOT NULL → DEFAULT ''；签发先于填写，sign 端点强制非空+词表兜底）。
2. `consumed_audit_id` 落 request_id（审计 ID 异步生成于事务后；request_id 贯穿审计与确认单双向可溯源）。
3. impact 请求增 `object_segment` 可选字段（token 绑定粒度=对象模型行；端点多行缺省 400 列候选不猜义，恰一行自动选定）。
4. readiness 节点状态细分映射：STALE_EXPIRED/CLOCK_SKEW → BLOCKED_BY_STALE，NEVER_ACKED/STALE_WITHIN_LEASE → BLOCKED_BY_NODE（贴 §1.2 语义注记；原始 ack_state 在 reasons 原文带出）。
5. 快照过期直查 `api_node_authz_acks.authz_snapshot_expires_at`（不动 apiauthzacks 冻结视图，本包只读直查）。
6. 174 迁移契约测试 down 两步适配（新增 175 后先 down 175 再 down 174）。
7. UNKNOWN 分桶按 checks 展开计数（一行可含 BOLA+BFLA 双 check，分桶总和可超 unknown_total，schema 注明）。

### 6.3 B 轨偏差登记（7 条，承接 B 轨回报与代码佐证）

1. readiness 徽章与证据区块做成复用件（`components/AuthzEnforcement.tsx`：ReadinessBadge tooltip 全因子+「UNKNOWN 永不阻断」注记；AuthzEnforcementBlock 决策详情/事件详情两处复用）。
2. 向导 preset 入口初始即第 2 步（态势表行携带 endpoint+segment，「选端点」步在 preset 入口跳过；非 preset 入口从第 1 步起）。
3. evidence_source 用 Radio.Group 二选一（词表两值，比下拉更直白）；on_unknown 固定 ALLOW_UNKNOWN 只读展示。
4. 影响评估失败态 Alert（初版 onError 仅 toast 后 Spin 死转，集成批修正为 Alert 如实呈现+指引）。
5. 快捷切回走 Popconfirm 二次确认（「切回 OBSERVE 不要求签署令牌」文案如实说明）。
6. 决策状态第四值中文 label「已验证违规（实断）」+ OBSERVE 形态 proposed_decision 拟实断留痕标签。
7. 向导第 3 步 readiness 非 READY 黄条预期管理（允许继续但如实列全部阻塞因子）。

### 6.4 集成新发现与修正（集成验收批，2026-10-05）

1. **签署端点 id→confirm_token（契约缺口修正）**：SignConfirmation 初版按行 id 查找，但 §1.3 影响评估响应只签发 confirm_token（前端/向导不持有行 id）——handler/store/OpenAPI 路径参数全链改为 confirm_token 语义，补按 token 签署成功与不存在 404 用例，reconcile 691 保持零差集。
2. **影响评估 endpoint_key 键族修正（A 轨实现与现实数据形状冲突）**：decisions/runtime_events 落库键是请求路径归一化键——纯数字对象值归一 {id}（恰等模板键），不可归一值（t001）保留字面（每值一键）。初版按模板键精确匹配 → 字面键全部漏计（评估计数恒 0）。修正为模板派生 LIKE 键族（占位段→%，LIKE 特殊字符转义），PG 契约补字面键锚定。
3. **ProtectWizard 评估请求补 object_segment**（B 轨按 §1.3 原型实现未带扩展字段，多行端点 400 卡「评估中…」）；B 轨 vitest 断言同步对齐（参数含 object_segment）。
4. **D7 后半补齐**：api-runtime-events 详情页接 AuthzEnforcementBlock（server 列表已带 final_decision 列零改动；页面本地类型扩展 RuntimeEventRecord.final_decision）；vitest 补证据区块+空态两用例。
5. E2E 交互细节（AntD Select placeholder 为 div 非 input、Radio.Group 词表、同端点多行消歧需 endpoint_key+object_segment 双键、Popconfirm 二次确认）——Playwright 惯例沉淀进 spec helper。
6. **断网用例实证路径**：停网关容器 → sidecar 能力清单停刷 180s+ 陈旧 → readiness 各行 reasons 出「节点能力自报不足 az/3 或清单不可用」（PROTECT_ACTIVE 展示态覆盖徽章、因子随附）→ 恢复后清单刷新+心跳 ACK 回 FRESH、因子消失。节点 status（api_gateway_nodes）为自报持久值不随停机自动老化，如实呈现。

### 6.5 E2E 证据摘要（stage5 + Playwright，2026-10-05；逐项原文见出口记录）

- stage5 向导全流：影响评估（observe_violation_count=4/principals=3/READY/token 签发）→ 签署（confirm_token 路径，冻结文案含影响面计数）→ PATCH 携带 token → 发布 SUCCESS → other 403 AUTHZ_VIOLATION_DENIED 精确体+源站零到达（mark 缺席）/owner 200 到达 → decisions VERIFIED_VIOLATION 证据在册 → 确认单 signed_at/consumed_at/consumed_audit_id(request_id) 落库。
- 确认单五类拒绝逐条 400 精确消息（不存在/已消费/已过期/绑定不符/未签署）。
- readiness 三态实证（READY/NOT_PUBLISHABLE 三因子全列/BLOCKED_BY_CONFLICT 双因子）。
- 断网（停网关容器）→ 清单陈旧阻塞因子出现 → 恢复 FRESH 因子消失。
- Playwright 五场景全绿（态势六要素/向导全流含 403 实证/能力门「配置与生效不一致」+CAP_MISSING(az/3,az/2)+快捷切回/越权全 403/决策详情证据区块）。
- 回归：stage5-gateway-tests 40/40、custom-pack 13/13、server 7 包绿、web typecheck/lint/vitest 1019/build 全绿、reconcile 691 零差集。
