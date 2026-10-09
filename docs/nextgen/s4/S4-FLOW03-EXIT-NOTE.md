# S4-FLOW03 出口记录（NG-FLOW-03 成功判定确认 / 未知恢复与管理对账 全链验收）

日期：2026-10-05 ｜ 范围：FLOW-03 双轨（gateway 响应回程 commit/202/INDETERMINATE + server 详情/resolve/000178）联调验收
设计：`docs/nextgen/NG-FLOW-strong-flow.md`（契约节冻结；实现状态 §8 本批追加）

## 出口判定：PASS（FLOW-03 承诺项全部验收，回归零回退；1 项设计-实现不一致移交设计裁决）

| 验收项（设计 §4/§15.2 映射） | 结果 | 证据位置 |
|---|---|---|
| F01 正常流程与合法并行（步骤按序 CONFIRMED；判定式命中才确认；同 parallel_group 并行不违规） | PASS | stage5 order-f3-1 两步 COMMIT OK→INSTANCE_CONFIRMED；组合判定读数在册；v11 并行组 seq3 先行不违规 |
| F04 超时但源站已成功（INDETERMINATE 不自动回滚；源站记录型证据；对账后 CONFIRMED） | PASS | 慢端点 12s>10s → 504 + INDETERMINATE；Valkey 槽 PENDING 保持；SLOW_PAY_EXECUTED 日志；resolve 收口 CONFIRMED |
| F05 迟到响应与旧 fencing（旧 token 提交拒绝不覆盖；事件链两 fencing 值） | PASS | pay#2 接管 fence=2→3 COMMIT OK；pay#1 迟到 COMMIT REJECTED FENCE-001（PG 侧 REJECTED 行碰撞缺席登记，网关日志在册） |
| F06 取消后新实例、定义升级 | **部分成立（登记裁决）** | 终态后新实例 PASS；「旧实例按旧版本走完」**不成立**——仅 ACTIVE 下发实证（见偏差 1，移交设计裁决） |
| F07 复验（Valkey 故障 UNKNOWN 不切本地；恢复后热状态读回；对账收口） | PASS | 停机 UNKNOWN 放行+dependency_unavailable+no local fallback 日志；重启后 PROTECT 正常流恢复；resolve CONFIRM_NOT_EXECUTED 收口 FAILED |
| F08 管理恢复边界（越权/乐观锁/终态/KEEP_UNKNOWN/详情语义/裁剪双档） | PASS | jiuzhang_admin 全 403；409 两态精确消息；语义逐字；双档七键 vs 四键 |
| allows_202（已受理待完成不自动完成） | PASS | 202 → FLOW-ACCEPTED-202 + 实例 ACTIVE 保持；人工 resolve 收口 |
| 迁移 000178 / OpenAPI 700 | PASS | 000178 up/down 契约（server PG 测试）；reconcile 700 双向零差集 |

## stage5 联调关键证据行（原样）

**F01 完整确认流（order-f3-1，定义 v6 OBSERVE 两步，pay=[200]+$.status=="ok" 组合与）**

```
register → 200+源站到达：sf [INSTANCE_NEW OK f=1, RESERVE OK f=1, COMMIT OK f=1]
  match flowguard.step_confirmed INFO {status:200, step_key:register}
pay → 200+源站到达：sf [RESERVE OK f=2, COMMIT OK f=2, INSTANCE_CONFIRMED OK f=2]
  evidence: rule_forms=status_codes,body_jsonpath_equals / status=200 / jsonpath_path=$.status expect=ok actual=ok
PG: 实例 CONFIRMED version=2 terminated_at 落；事件链 6 行（INSTANCE_NEW→RESERVE→COMMIT→RESERVE→COMMIT→INSTANCE_CONFIRMED）
并行组（v11 三步 g1：register seq1 + pay seq2 + settle seq3）：order-pg-1 register→settle(先)→pay(后)
  全链 CONFIRMED version=2，事件全 OK 无 REJECTED——同组互不为前置，乱序合法不误判
```

**F04 超时但源站已成功（order-f4-1，v8 pay=POST /slow-pay）**

```
pay delay 12s > upstream 超时 10s → curl_total=10.04s HTTP 504 Gateway Timeout
网关事件：pay RESERVE OK f=2 / pay INSTANCE_INDETERMINATE UNKNOWN UNKNOWN-001 f=2
  flowguard.step_unknown OBSERVE {detail:downstream_error, indeterminate_marked:true}
Valkey：sflow:v1:{...}:step:pay → state PENDING token 2（不自动 release 实证）；state status INDETERMINATE
源站记录型证据：testorigin 日志 SLOW_PAY_EXECUTED order_id=order-f4-1 delay_ms=12000 at=2026-10-05T15:27:22Z
同键重试：200 放行但 sf pay RESERVE UNKNOWN UNKNOWN-001（instance_indeterminate——不重放成功语义）
resolve CONFIRM_SUCCEEDED（reason 含源站日志证据）→ status=CONFIRMED semantics=SUCCEEDED version=3
  事件 +INSTANCE_CONFIRMED OK FLOW-RESOLVE-001；审计 HIGH after JSON 全值（action/reason/status_before→after/version 2→3）
```

**F05 迟到 fencing（order-f5-1，v9 pay lease=15s；upstream 超时临时 20s 用完已还原）**

```
register COMMIT OK f=1 → pay#1 delay 16s（reserve f=2，lease 15s）→ 15.5s 后 pay#2 delay 0：
  sf pay [EXPIRE OK f=2, RESERVE OK f=3, COMMIT OK f=3, INSTANCE_CONFIRMED OK f=3]
pay#1 16s 迟到返回（200 判定命中）：
  sf pay [RESERVE OK f=2, COMMIT REJECTED FENCE-001 f=3]（旧 token 提交拒绝，不覆盖新状态）
  match flowguard.commit_rejected OBSERVE FENCE-001 not_pending
PG 事件链 fence=2（RESERVE/EXPIRE）与 fence=3（RESERVE/COMMIT/INSTANCE_CONFIRMED）两值在册；
  COMMIT REJECTED 行因事件唯一键碰撞缺席（网关日志在册——见偏差 2）
```

**F06 版本切换与终态后新实例（v6→v7，同 endpoint 重叠形态）**

```
实例行冻结：order-f6-old 行 definition_version=6 ACTIVE 保持（不换图成立）
「按旧版本走完」不成立（仅 ACTIVE 下发实证）：
  order-f6-old pay（v6 RETIRED 后）→ 命中 v7 绑定 → version=7 实例键另起新实例 848b6c15
  → 7|pay|RESERVE|0|REJECTED|FLOW-RESERVE-001（predecessor_unconfirmed，OBSERVE 放行 200）
  → v6 旧实例停留「register CONFIRMED」中途态，无法经原 ref 走完（移交设计裁决——偏差 1）
新实例用新版本：order-f6-new v7 完整 [INSTANCE_NEW..COMMIT..INSTANCE_CONFIRMED] CONFIRMED
终态后同主体新实例：order-f3-1 CONFIRMED 终态后 order-f6-new 正常开始并完成
```

**allows_202（order-f3-202，v10 pay=/accept-pay allows_202=true）**

```
pay → HTTP 202 Accepted：sf pay [RESERVE OK f=2, RESERVE OK FLOW-ACCEPTED-202 f=2]
  flowguard.step_accepted_202 INFO {status:202, reason_code:FLOW-ACCEPTED-202}
PG 实例保持 ACTIVE version=1（不自动记完成）
人工 resolve CONFIRM_SUCCEEDED → CONFIRMED version=2 + INSTANCE_CONFIRMED FLOW-RESOLVE-001
（PG 侧受理 reason_code 因唯一键碰撞缺席，网关日志在册——同偏差 2）
```

**F08 管理恢复边界**

```
越权：jiuzhang_admin GET detail → 403；POST resolve → 403
乐观锁：expected_version=99 → HTTP 409 {"code":"RESOURCE_CONFLICT","message":"strong flow instance version conflict（乐观锁不匹配：实例已被变更，请刷新后重试）"}
终态重复：CONFIRMED 实例再 resolve → HTTP 409 {"code":"RESOURCE_CONFLICT","message":"instance already terminal（CONFIRMED/CANCELLED/FAILED 终态拒绝重复恢复）"}
KEEP_UNKNOWN：200，status=INDETERMINATE version=2 不推进；PG +RESOLVE UNKNOWN FLOW-RESOLVE-001；
  审计 HIGH after={"action":"KEEP_UNKNOWN","reason":"源站超时但无法确认业务是否入账，保持未知待继续对账",...}
详情语义逐字：status_semantics=UNKNOWN_NOT_CONFIRMED / status_message=未知，不显示安全通过
证据双档（SECURITY_ADMIN 临时摘除/恢复 evidence_read 映射实证）：
  无 evidence_read → step keys=[action,occurred_at,result,step_key]（明细三键缺席）
  有 evidence_read → step keys=[action,fencing_token,occurred_at,reason_code,request_id,result,step_key]（七键全出席）
```

**F07 复验（v12 PROTECT）**

```
基线：register order-f7a 200（reserve+commit 正常）
docker stop valkey：register order-f7b → 200+源站到达；直 pay order-f7c → 200+源站到达
  sf [RESERVE UNKNOWN UNKNOWN-001] ×2；flowguard.unknown OBSERVE valkey_error dependency_unavailable=true
  caddy.log：strong flow valkey op failed, UNKNOWN fail-open (D8: no local fallback) op=reserve error=EOF
docker start valkey + docker restart gateway（healthy）：
  order-f7d register/pay 200（热状态读回正常流恢复）
  order-f8-2（INDETERMINATE）resolve CONFIRM_NOT_EXECUTED → FAILED semantics=FAILED version=3
  事件链：.. settle INSTANCE_INDETERMINATE UNKNOWN-001 → RESOLVE UNKNOWN FLOW-RESOLVE-001 → INSTANCE_FAILED OK FLOW-RESOLVE-001
（commit 路径 Valkey 故障同 UNKNOWN 纪律由 gateway finalize_test 单测覆盖——「commit 依赖不可用 → F04 同一语义披露」在册）
```

## 偏差与联调发现清单

**（2026-10-06 追记：偏差 1/2 两条已裁决并修复闭环——见文末「裁决闭环追记」；设计文档 §8.6 同载）**

1. **F06「旧实例按旧版本走完」不成立（移交设计裁决）**：§1.1 该句与发布面「仅 ACTIVE 定义下发」不一致，stage5 实证旧实例停留中途态且同 ref 请求按新版本另起实例 REJECTED。裁决建议：①下发面含存量实例引用旧版本（育龄窗）或②修订 §1.1 为「RETIRED 即停止服务，存量实例经管理对账收口」。详见设计 §8.4-1。
2. **PG 事件唯一键碰撞（两实例）**：F05 COMMIT REJECTED FENCE-001（fencing_token 携当前 fence 读数）与 COMMIT OK 同键去重；202 受理第二 RESERVE（FLOW-ACCEPTED-202）与首 RESERVE 同键去重——REJECTED/受理 reason_code PG 缺席（网关日志均在册）。详见设计 §8.4-2。
3. **超时语义承载层**：§1.4「超时」由 upstream response_header_timeout（10s）承载；步骤 timeout_seconds 当前不下发不消费。F05 实证临时上调 20s 用完已还原 10s。详见设计 §8.4-3。
4. **evidence_read 双档实证口径**：自建角色被用户创建 API 拒收（角色目录缓存口径），改 SECURITY_ADMIN 临时摘除/恢复映射完成（权限每请求实时查库），已恢复。详见设计 §8.4-4。
5. **回归脚本并发登录竞态**：custom-pack 与 stage5 回归并发跑首跑 sysadmin login failed（验证码/CSRF 轮换冲突），串行重跑 13/13——非产品问题。
6. server 轨 6 条实现偏差（RESOLVE 词表/FAILED 映射/审计 JSON 形态/evidence_read 复用/KEEP_UNKNOWN 去重/哨兵文案）与 gateway 轨 7 条实现选择（体采样门/采样挂点/错误不细分/Hijack 同支/FENCE 不入 INDETERMINATE/防御分支/实断解耦）——逐条见设计 §8.2/§8.3。

## C01 零变化声明（NG-T-C01，FLOW-03 增量面）

- 无成功预留（reserve 违规/未知/未命中绑定）的请求：响应记录器零包装零行为（`wrapStrongFlowResponse` 无 Reservation 直通）。
- 无定义应用（waf-s5.local 等存量 Host）：stage5 回归 40/40、custom-pack 13/13 不回退。
- 事件面：`strong_flow` 数组仅新增 FLOW-03 动作词（COMMIT/INSTANCE_CONFIRMED/INSTANCE_INDETERMINATE/RESOLVE），无强流程活动请求事件形状零变化；server 采集对新词校验词表同步（RESOLVE 管理面专属不入采集校验）。

## 回归输出（原样关键行）

```
阶段5真实网关测试汇总：总用例数 40，通过 40，失败 0
CUSTOM_PACK 二次阻断评估验证：13/13 通过，0 失败（串行重跑；并发首跑登录竞态非产品问题）
server：ok strongflow 1.243s / apiruntime 1.791s / guardconfig 1.968s / gatewayconfig 3.032s / app 2.306s
gateway：dynamic_security 17 包 ok / jiuzhang_guard 17 包 ok，无 FAIL（-count=1）
python3 tools/check-api-reconcile.py：代码注册路由 700  OpenAPI 片段收录 700  对账通过：双向零差集
gofmt：本批文件干净
PG 契约（FLOW-03 server 批已跑）：迁移 178 up/up/down/up、resolve 三 action 全链、乐观锁/终态/KEEP_UNKNOWN/裁剪/审计全 PASS
```

## 现场还原终态

- 测试定义 v6~v12 全部 RETIRED；本批实例/步骤事件按应用维度清理（PG DELETE）；Valkey `sflow:v1:*` 键清理。
- 发布还原：retire 触发最终发布（快照无 api_strong_flows 段）；upstream response_header_timeout_ms 已还原 10000 并发布。
- testorigin 临时改动（/slow-pay、/accept-pay、echo Status 字段）已恢复原文件并重建镜像；api_endpoints 两个临时 CONFIRMED 端点已删除。
- stage5 全栈 healthy（api/gateway/postgres/valkey/testorigin）。

## 裁决闭环追记（2026-10-06，偏差 1/2 两条已裁决+修复+stage5 复验闭环）

**裁决 1（偏差 1，F06）采「育龄窗下发」案已闭环**：发布面 `ACTIVE ∪ 存在非终态实例（ACTIVE/INDETERMINATE）的 RETIRED 版本`。
- 修复位置：server `guardconfig/strongflow.go`（`ListPublishableStrongFlows` 查询 EXISTS 子句 + `GuardStrongFlowDefinition.status` 透传；PG 契约 `strongflow_pg_test.go` 五态在册）；gateway `flowguard/{definition,validate,reserve,evaluate}.go`（`StatusRetired` 词表、validate 放宽 ACTIVE|RETIRED、`Reserve(allowNewInstance)` Lua 原子域 `definition_retired` 闸——RETIRED 仅存量实例续跑，新实例必须按 ACTIVE 版本键；Valkey IT `TestStrongFlowITRetiredPublishWindow`）。
- stage5 复验（v13→v14 同名升级）：autosave `api_strong_flows` 含 v13(status=RETIRED)+v14(ACTIVE) 双版本透传；
  order-w1（v13 下 register CONFIRMED）pay 按 v13 续跑走完 `sf v13 pay [RESERVE OK f=2, COMMIT OK f=2, INSTANCE_CONFIRMED f=2]`（实例行 v13 CONFIRMED）；
  新 ref order-w3 `sf v13 register RESERVE REJECTED FLOW-RESERVE-001`+`flowguard.violation OBSERVE v13 definition_retired`（RETIRED 拒新实例），同请求 `sf v14 register [INSTANCE_NEW, RESERVE OK, COMMIT OK]`（新实例只按 ACTIVE 版本键）；
  order-w2 v14 新实例全程 CONFIRMED。**F06 语义完整成立**（多版本并存下新版本视角的跳步 REJECTED 如实记录，OBSERVE 放行不阻断）。

**裁决 2（偏差 2，事件唯一键碰撞）采「fencing_token 恒为本事件自持有 token」案已闭环**：REJECTED 事件携被拒旧 token，当前 fence 读数移 evidence `fence_current`；202 受理即预留轮换（INCR fence 新 token）。
- 修复位置：gateway `flowguard/reserve.go`（commitLua/releaseLua FENCE-001 token 位改携被拒 token+auxToken 载当前 fence；markAcceptedLua INCR 轮换+`MarkAccepted(leaseSeconds)`；`OpResult.FenceCurrent`+parseOpReply REJECTED 映射）、`finalize.go`（commit REJECTED evidence 增 `fence_current`；Valkey IT `TestStrongFlowITFenceExpiry`/`TestStrongFlowITMarkAccepted` 重写）；server 采集不变 + PG 契约 `TestStrongFlowEventTokenSemanticsPostgresContract`（F05 双行/202 双行在册）。
- stage5 复验（v15 重跑 F05 时序：pay#1 hold 16s + pay#2 接管 + pay#1 迟到）：
  PG 事件链 9 行——`pay COMMIT f=3 OK` 与 `pay COMMIT f=2 REJECTED FENCE-001` **双行在册**（碰撞消解）；
  网关事件 `sf pay COMMIT REJECTED FENCE-001 fence=2` + `match flowguard.commit_rejected OBSERVE FENCE-001 fence_current=3`。

**回归（裁决修复后）**：stage5 40/40、custom-pack 13/13（登录限流键无 TTL 致 429（ratelimit.go 既有注释坑），删计数键后通过——测试环境治理非产品改动）；server strongflow/guardconfig ok、gateway dynamic_security 17 包+jiuzhang_guard 17 包 ok（含 Valkey IT -race）；reconcile 700 零差集；gofmt 干净。
