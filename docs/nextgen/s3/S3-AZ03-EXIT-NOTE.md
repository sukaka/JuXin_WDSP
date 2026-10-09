# S3-AZ03 出口记录（NG-AZ-03 显式阻断资格 / VERIFIED_VIOLATION）

日期：2026-10-05 ｜ 范围：冻结设计 §1~§2 全量（A server 快照与资格判定 + B 网关决策与阻断执行 + 联调验收）
设计：`docs/nextgen/NG-AZ-03-verified-violation.md`（契约节冻结；实现状态节 §6 本批追加）

## 出口判定：PASS（全部验收项完成，回归零回退）

| 验收项 | 结果 | 证据位置 |
|---|---|---|
| D1 决策词表第四值（动作词表/历史行不变） | PASS | decisions 表 VERIFIED_VIOLATION 行在册；final_action 恒 ALLOW/OBSERVE/BLOCK 既有词表 |
| D2 八因子真值表 | PASS | 证据 eligibility 八因子全真（实断）/ 任一不真落 UNKNOWN 或 OBSERVE_VIOLATION（负向样本逐条） |
| D3 PROTECT 开关+四要素强制前置 | PASS | 逐缺项/空白/超长/词表外 8×400 精确消息；切回 OBSERVE 列值保留 |
| D4 阻断执行（统一 JSON、源站零到达） | PASS | 403 `AUTHZ_VIOLATION_DENIED` 精确体 ×3；origin-mark 0/3 |
| D5 证据内嵌零新表 | PASS | `final_decision.authz_enforcement` §1.4 全键；decisions 查询行 evidence 原样带出 |
| D6 能力门 az/3（NG-T-C08） | PASS | 三态：fail-closed / az/3 正常 / az/2 全 OBSERVE 正常（见下） |
| D7 时效交互（lease 过期 strict 抽查） | PASS | 窗口内 403 / 过期 200 放行 + AUTHZ-LEASE-001+dependency_unavailable |
| D8 权限/审计/回滚 | PASS | `api_authorization.manage` 不新增权限点；审计 after 含四要素全值；切回后拟动作记录恢复 |
| D9 测试计划 | PASS | 单测 + 六组 E2E（见下逐组结果） |
| D10 兼容/缺省/OpenAPI | PASS | 新列全默认 OBSERVE/空值（NG-T-C01 实证）；OpenAPI 686 持平双向零差集 |

## 完成证据一：UNKNOWN 不误断（负向样本清单逐条结果，全部 PROTECT 下断言放行）

| # | 负向样本 | 客户端 | decision | reason_code | 源站到达 |
|---|---|---|---|---|---|
| 1 | 未验证主体（无 JWT） | 200 放行 | UNKNOWN | AUTHZ-IDENTITY-001 | mark 出席 |
| 2 | 伪造 JWT（坏签名） | 200 放行 | UNKNOWN | AUTHZ-IDENTITY-001 | mark 出席 |
| 3 | 无有效关系 NONE（other→t999） | 404 放行 | UNKNOWN | AUTHZ-RELATION-001 | mark 出席 |
| 4 | 关系已撤销（other→t001 无有效 OWNER） | 200 放行 | UNKNOWN | AUTHZ-RELATION-001 | mark 出席 |
| 5 | OPEN 冲突对象（other→t777） | 404 放行 | UNKNOWN | AUTHZ-CONFLICT-001 | mark 出席 |
| 6 | lease 过期 strict（PROTECT 下 other→t001） | 200 放行 | UNKNOWN（BOLA+BFLA 双检查） | AUTHZ-LEASE-001 + dependency_unavailable=true | mark 出席 |
| 7 | owner_exclusive=false（模型退出快照） | 404 放行 | UNKNOWN | AUTHZ-POLICY-001（端点无模型） | mark 出席 |
| 8 | publishable=false（模型下线） | 404 放行 | UNKNOWN | AUTHZ-POLICY-001（端点无模型） | mark 出席 |
| 9 | 租户不一致（tenant-a token → t001） | 200 放行 | OBSERVE_VIOLATION（非 VERIFIED） | TENANT-001（不实断） | mark 出席 |
| 10 | CLOCK_SKEW 负向漂移 | —（stage5 未造：需回拨共享网关节点时钟，破坏面大） | — | — | B 轨单测承接（authzdecide_az3_test.go CLOCK_SKEW 用例 + NG-AZ-02 负向漂移用例） |
| 11 | 关系未生效（valid_from 未来） | —（编译侧经 NG-AZ-02 测试承接：未来关系保留在快照由网关窗口过滤） | — | — | guardconfig 单测 `TestLoadAPIAuthzSnapshotRetainsFutureRelationsForGatewayFiltering` |
| 12 | 快照 stale / 水位回退 | —（NG-AZ-02 已实证：PreviousValid 资格过滤 / 节点拒载，与 enforcement 无关，D7 矩阵「同左」） | — | — | NG-AZ-02 出口记录 D3/D4-1 |

红线实证：**12 条负向样本无一被实断**（可造的 9 条全部到达源站；3 条由既有测试/前批实证承接并注明原因）。

## 完成证据二：可信违规不达源站（NG-T-A01 主链四段）

1. **OBSERVE 基准**：other（非本人）→ t001 ×2：`200 + X-Wdsp-Origin-Mark: jiuzhang-test-origin`（到达源站），decisions `OBSERVE_VIOLATION` 记录不实断；owner（真本人）×2：200 + `ALLOW`。
2. **切 PROTECT（四要素齐全）→ other ×3**：逐条 `403` + 精确体 `{"code":"AUTHZ_VIOLATION_DENIED","message":"无权访问该对象","request_id":"a22655ee-…/11650b1b-…/21dd802f-…"}`；**源站零到达：X-Wdsp-Origin-Mark 出席 0/3**（计数差分：OBSERVE 基准 3/3 → PROTECT 0/3；testorigin 每到达请求恰回写一次该头，契约 `deployment/stage1/testorigin/main.go:40`）。
3. **决策与证据**：api_runtime_events `final_action=BLOCK` ×3 + `final_decision.authz_enforcement` = decision VERIFIED_VIOLATION / reason AUTHZ-BOLA-001 / enforced=true / **eligibility 八因子全真** / principal_source=JWT_VERIFIED / object_ref=`objref:74a55c5a…`（与管理面自算 HMAC 一致）/ model_version、policy_version、revocation_watermark、lease_seconds、applied_at_age_seconds、enforcement_owner=`zhang.lei@example.com`、evidence_source=`MANUAL_CONFIRMED`、recorded_at 全键在册；`GET /api-security/authz/decisions?decision=VERIFIED_VIOLATION` total=3 + 行内嵌证据原样带出（evidence_read 权限门控实证：只读主体不带出）。
4. **真本人与切回**：owner PROTECT 下 `200 + mark 出席`（有效本人仍 ALLOW 到达）；切回 OBSERVE 后 other 恢复 `200 + mark 出席`，决策降回 `OBSERVE_VIOLATION` 拟动作（final_action=OBSERVE），列值（enforcement_owner/evidence_source/on_unknown）保留供审计。

## BFLA 三态（E2E-4）

| 场景 | 结果 | 证据 |
|---|---|---|
| 行级未配置继承端点 PROTECT（viewer denied→1001） | 403 精确体 + mark 缺席 | AUTHZ-BFLA-001；eligibility BFLA 实评四键全真；**enforcement_owner/evidence_source/model_version 继承自端点模型**（行级无伴随列的铁证） |
| 行级显式 PROTECT（端点 OBSERVE，viewer→1001） | 403 精确体 + mark 缺席 | AUTHZ-BFLA-001；enforcement_owner/evidence_source/model_version 置空（行级形态） |
| 全 OBSERVE（viewer→1001） | 404 放行 + mark 出席 | analyst allowed 行同路径 404 放行对照 |

## NG-T-C08 能力门三态（E2E-5）

```
态1 az/2 自报 + 含 PROTECT 快照 → FAILED  CAPABILITY_MISSING
    节点 "gateway-stage5-01" 缺少本次发布所需能力，发布已拒绝（不发送 /load）:
    CAP_MISSING:detectors.authzdecide(required=az/3,actual=az/2)
态2 az/3 自报 + 含 PROTECT 快照 → PUBLISH_OK（BFLA-3 发布即实证；capability.json authzdecide=az/3）
态3 az/2 自报 + 全 OBSERVE 快照 → PUBLISH_OK（滚动升级路径）
```

## PATCH 四要素校验（E2E-2，逐条 400）

```
缺 enforcement_owner → 切换 PROTECT 必须同请求提供 enforcement_owner（业务负责人标识）
owner 空白           → 同上
缺 evidence_source   → 切换 PROTECT 必须同请求提供 evidence_source（…AUTHORITY_SYNC|MANUAL_CONFIRMED）
缺 on_unknown        → 切换 PROTECT 必须同请求提供 on_unknown（…首批仅 ALLOW_UNKNOWN）
enforcement=BLOCK    → enforcement 非法（OBSERVE|PROTECT；缺省 OBSERVE）
evidence_source=GUESSED → evidence_source 非法（AUTHORITY_SYNC|MANUAL_CONFIRMED）
on_unknown=DENY_UNKNOWN → on_unknown 非法（首批仅 ALLOW_UNKNOWN——UNKNOWN 永不阻断）
owner 超 128         → enforcement_owner 超过 128 字符
```

## 回归输出（原样关键行）

```
阶段5真实网关测试汇总：总用例数 40，通过 40，失败 0
CUSTOM_PACK 二次阻断评估验证：13/13 通过，0 失败
server 6 包：apisecurity / guardconfig / gatewayconfig / apiauthz / apiruntime / app 全 ok（-count=1）
gateway：dynamic_security detectors/events/pipeline/capability 全 ok；modules/jiuzhang_guard 全模块 ok
python3 tools/check-api-reconcile.py：代码注册路由 686  OpenAPI 片段收录 686  对账通过：双向零差集
gofmt -l <改动包>：干净
迁移契约（一次性 PG 16.4 digest 锁定容器，用毕已删）：
  applied migration 000174 / rolled back 000174 / applied 000174
  TestAuthzEnforcementMigration174PostgresContract PASS / TestObjectModelEnforcementPatchPostgresContract PASS
```

## 联调新发现（已写入设计文档 §6.4）

1. **A/B 契约缺口已修正**：角色基线 DB 缺省 OBSERVE 经 A 轨归一为空串下发（网关空值继承端点模型）；修正前继承链断裂（viewer denied 行端点 PROTECT 下不放行），修正后三态实证通过。涉及文件 `server/internal/guardconfig/authz_decision.go`（guardconfig 包测试复跑绿）。
2. BOLA/BFLA 端点匹配口径差异登记（BFLA 归一键字符串相等，BOLA 另有 path_template 通配兜底；不可归一对象值字面请求不匹配 BFLA 基线）。
3. 新应用发布验证需 Bot `route_reservation=RESERVED_TOMBSTONE`（首次 OFF 无墓碑探针 404 fail-closed）。
4. object_hmac_key 删除须「带 key 发布（新快照无模型）→ 删 key → 再发布」顺序（PreviousValid 重注入 fail-hard）。

## 本批交付物清单

- 迁移：`server/migrations/000174_authz_enforcement.{up,down}.sql`（object_models 四列 + role_baselines.enforcement + decisions CHECK 放宽）
- server（A 轨）：`apisecurity/object_models{,_update}.go`、`gatewayconfig/{guard.go,capability_gate.go}`、`guardconfig/authz_decision.go`、`apiauthz/handler.go`、`apiruntime/events.go` + 对应测试（含 `object_models_update_integration_test.go`、迁移 174 契约）
- gateway（B 轨）：`dynamic_security/{detectors/authzdecide.go,events/authz.go,pipeline/pipeline.go}`、`modules/jiuzhang_guard/{module.go,apiprotect.go,capability_report.go}` + az3 测试套件
- OpenAPI：object-models PATCH 四字段 + decisions 枚举第四值 + `ApiSecAuthzEnforcementEvidence`（686 零差集）
- 文档：设计文档 §6 实现状态节、CHANGELOG Unreleased 条目、本记录
- 临时资产（已清理）：`server/tmpaz2sign`（ES256 mint/principal/objref/encrypt E2E 工具）、stage5 az3app 全量 fixture

## 遗留与后续（移交）

1. CLOCK_SKEW 负向漂移的 stage5 实证（需节点时钟注入设施；当前单测承接）。
2. 前端向导与影响评估（NG-AZ-04：切换前影响面/确认单/双人复核/页面 E2E）。
3. VERIFIED_VIOLATION 报表归并与风险中心展示（查询侧派生视图 UI 化）。
4. TENANT-001 阻断资格评审（需租户语义数据后再评，本批 OBSERVE_VIOLATION 不实断）。
5. ha-lab 双节点 PROTECT 分区演练（时钟偏差+分区下 strict/degraded 矩阵，NG-AZ-02 移交顺延）。
6. 角色基线 enforcement 管理面写通道（当前仅列级能力，行级 PROTECT 经 DB 验证；「显式行级 OBSERVE 覆盖端点」语义待该通道评审时一并定稿）。

## 现场状态

stage5 已还原：az3app（含域名/源站/策略）软删、关系/冲突/基线/对象模型/端点/设置行（identity_salt、object_hmac_key）全部清理、两次发布还原（autosave 零 az3/PROTECT/hmac_key/api_authz_models 残留键，能力需求回到空集免门禁）；迁移 000174、OpenAPI、代码与文档保留在线；E2E 决策与事件行保留（历史事实，回滚不回退事实同纪律）。
