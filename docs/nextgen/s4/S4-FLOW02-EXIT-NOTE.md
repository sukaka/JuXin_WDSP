# S4-FLOW02 出口记录（NG-FLOW-01/02 强流程定义隔离 / 原子操作与实断 全链验收）

日期：2026-10-05 ｜ 范围：FLOW-01（定义与隔离）+ FLOW-02（原子操作与实断）双轨实现与联调验收
设计：`docs/nextgen/NG-FLOW-strong-flow.md`（契约节冻结；实现状态 §7 本批追加）

## 出口判定：PASS（FLOW-02 批承诺项全部验收，回归零回退；覆盖边界如实移交 FLOW-03/04）

| 验收项（设计 §4/§15.2 映射） | 结果 | 证据位置 |
|---|---|---|
| F01 正常流程（本批覆盖=按序放行+决策组+事件链；CONFIRMED 断言移交 FLOW-03，见偏差 1） | PASS | stage5 order-f1-1：两步 200+源站到达；strong_flow 数组与 PG 事件链一致 |
| F02 双节点同一步（恰一 reserve 成功） | PASS | 双网关 overlay 6 轮并发全部恰一 200 一 403；两侧事件链互证；Valkey 键族在册 |
| F03 幂等重试与同键异参（403 裁决，见偏差 2） | PASS | 同键同摘要 3 连幂等重放 OK；同键异摘要 PROTECT 403+IDEMPOTENT-CONFLICT-001 |
| F07 Valkey 故障/网关重启 | PASS | 停机恒 UNKNOWN 放行+dependency_unavailable+no local fallback 日志实证；恢复后同实例 fence 1→2 热状态读回 |
| C08 能力门 flow/1 | PASS | 篡改 flow/0 → CAPABILITY_MISSING fail-closed 不发送 /load；恢复后全 OBSERVE 快照发布成功 |
| 违规两态（OBSERVE 记录 / PROTECT 403 统一体） | PASS | 精确体+源站零到达+final_action=BLOCK；PROTECT 合法首步不误断；OBSERVE 还原 |
| 越权（jiuzhang_admin） | PASS | 已注册 7 端点全 403；instances/{id} 404=路由未注册（FLOW-03 范围，如实登记） |
| NG-T-C01 缺省零变化 | PASS | 无定义应用回归 40/40 不回退；Runtime nil 零行为；发布面零变化声明见下 |
| 迁移 000176/177 | PASS | stage5 迁移在册（177 已应用）；五态/词表 CHECK 与双唯一约束生效（事件去重实证） |
| OpenAPI 698 | PASS | `python3 tools/check-api-reconcile.py` 双向零差集（预估 699 差 1=实例详情随 FLOW-03） |

## stage5 联调关键证据行（原样）

**F1 按序两步（order-f1-1，定义 v1 OBSERVE；order-e2e-4 前批部分链复核一致）**

```
register POST /submit?order_id=order-f1-1  → HTTP 200, X-Wdsp-Origin-Mark: jiuzhang-test-origin
  sf: register INSTANCE_NEW OK fence=1 / register RESERVE OK fence=1   final_action=OBSERVE
pay      POST /api/json?order_id=order-f1-1 → HTTP 200, X-Wdsp-Origin-Mark 出席（OBSERVE 放行）
  sf: pay RESERVE REJECTED FLOW-RESERVE-001 fence=0                     final_action=OBSERVE
  match: flowguard.violation OBSERVE FLOW-RESERVE-001 predecessor_unconfirmed mode=OBSERVE
PG: register|INSTANCE_NEW|1|OK ; register|RESERVE|1|OK ; pay|RESERVE|0|REJECTED|FLOW-RESERVE-001
（注：pay REJECTED 为 FLOW-02 预期语义——commit 未接线（FLOW-03），前置 register 恒未 CONFIRMED，如实呈现不误称通过）
```

**违规两态**

```
OBSERVE（v1）：直 pay order-vio-1（跳过 register）→ HTTP 200 + 源站到达；pay RESERVE REJECTED FLOW-RESERVE-001 落库
切 PROTECT：Create 同名 v2 草稿（mode=PROTECT）→ activate（v1 RETIRED，version 单调）→ 自动发布 SUCCESS
PROTECT（v2）：直 pay order-vio-2 → HTTP 403
  精确体：{"code":"FLOW_VIOLATION_DENIED","message":"流程状态不允许该操作","request_id":"fd136982-83e3-4c5c-ad88-8683ef856de8"}
  X-Wdsp-Origin-Mark 计数 0（源站零到达）
  sf: pay RESERVE REJECTED FLOW-RESERVE-001 fence=0 ; match: flowguard.violation BLOCK ... mode=PROTECT ; final_action=BLOCK
PROTECT 合法首步：register order-f1-2 → HTTP 200 + 源站到达（不误断）
还原：Create v3（OBSERVE）→ activate → 发布 SUCCESS；直 pay order-vio-3 → 200 放行+记录
```

**F03 幂等**

```
同键同摘要（Idempotency-Key: idem-f03-1，同 body，OBSERVE v3）3 连发全 200+源站到达：
  #1 [INSTANCE_NEW OK fence=1, RESERVE OK fence=1]
  #2 [RESERVE OK fence=1]（幂等重放：无 INSTANCE_NEW、同 token、无冲突）
  #3 [RESERVE OK fence=1]
同键异摘要（Idempotency-Key: idem-f03-2，body amount 11→22，PROTECT v4）：
  #1 200 → #2 HTTP 403 精确体（源站零到达）
  sf: register RESERVE CONFLICT IDEMPOTENT-CONFLICT-001 fence=1
  match: flowguard.violation BLOCK IDEMPOTENT-CONFLICT-001 digest_mismatch ; final_action=BLOCK
```

**F02 双节点并发（overlay：gateway-stage5-01 :18080 / gateway-stage5-02 :18082，共享 Valkey）**

```
6 轮（5 正序+1 反序）同实例键同步骤（异参数摘要）并发：全部恰一 200 一 403
  A 侧事件：register RESERVE CONFLICT FLOW-RESERVE-001 fence=1 final=BLOCK（×5+1）
  B 侧事件：register INSTANCE_NEW OK fence=1 / RESERVE OK fence=1 final=OBSERVE
Valkey：sflow:v1:{sfref:…}:fence / :state / :step:register 键族在册（共享原子域实证）
方向偏置登记：6 轮均 B 先占槽（容器时延差异，非原子性缺陷）；断言「恰一成功」与方向无关
（首轮同 body 并发全 200 系幂等重放语义——同摘要重放合法去重，改异摘要后冲突语义显现）
```

**F07 故障与恢复（PROTECT v4）**

```
基线：register order-f07-1 → 200（RESERVE OK fence=1）
docker stop jiuzhang-stage5-valkey：
  register order-f07-2 → HTTP 200 + 源站到达；pay order-f07-3（违规形态）→ HTTP 200 + 源站到达
  sf: register RESERVE UNKNOWN UNKNOWN-001 fence=0 final=OBSERVE
  match: flowguard.unknown OBSERVE UNKNOWN-001 valkey_error dependency_unavailable=true（两条同形）
  caddy.log：{"level":"warn",…,"msg":"strong flow valkey op failed, UNKNOWN fail-open (D8: no local fallback)","op":"reserve","error":"EOF"}
docker start valkey + docker restart gateway（healthy）：
  同实例 register order-f07-1 异摘要 → 200：sf: register EXPIRE OK fence=1 / register RESERVE OK fence=2
  （lease 过期接管，事件链含两次 fencing 值；fence 单调 1→2 证明热状态从 Valkey 读回，非重建 fence=1）
  新实例 order-f07-4 → INSTANCE_NEW OK fence=1 / RESERVE OK fence=1（正常）
```

**C08 能力门**

```
capability.json flowguard 篡改 flow/0（flow/1 为真实自报值）：
  发布任务 FAILED | CAPABILITY_MISSING | 节点 "gateway-stage5-01" 缺少本次发布所需能力，发布已拒绝（不发送 /load）:
    CAP_MISSING:detectors.flowguard(required=flow/1,actual=flow/0)
恢复 flow/1 → Create v5（OBSERVE）→ activate → 发布 SUCCESS（全 OBSERVE 定义快照正常发布）
```

**越权（jiuzhang_admin，SYSTEM_ADMIN）**

```
GET definitions / GET definitions/{id} / GET instances            → 403 / 403 / 403
POST definitions / POST {id}/activate / POST {id}/retire          → 403 / 403 / 403
GET instances/{id}                                                → 404（路由未注册，FLOW-03 范围——非权限语义，如实登记）
```

**审计（PG operation_audits 原样）**

```
activate | api_strong_flow_definition | HIGH | SUCCESS | sec_admin_s5 | 2026-10-05 14:19:51（v5）
create   | api_strong_flow_definition | HIGH | SUCCESS | sec_admin_s5 | 2026-10-05 14:19:51
（v2/v3/v4 create+activate 同形在册，request_id 可溯源）
```

## 偏差与联调修正清单（全部落码或落文档）

1. **F01 覆盖边界（移交非缺陷）**：commit/release 已实现并有单测但运行时不接线（FLOW-03 响应回程成功判定）；本批带前置步骤恒 predecessor_unconfirmed 如实呈现，§4 F01「步骤按序 CONFIRMED」断言移交 FLOW-03。F04（超时 INDETERMINATE 对账）同理由移交。
2. **F03 响应码裁决**：设计 §4 矩阵「同键异摘要 409」与 §1.6「PROTECT 违规 403 统一体」内部不一致——采 **403**（响应码不泄露槽占用语义，AZ-03 防探测同纪律；冲突类型只落事件）。设计稿 §7.2-3 已登记，FLOW-03 批修订时回写 §4。
3. **strong_flow 事件数组化（联调修正①）**：一请求多动作（INSTANCE_NEW+RESERVE 同拍等）单对象无法承载，线契约定为数组；server `collector.go` 消费侧已适配，旧版网关缺键容忍。
4. **strong-flow-only 应用 HMAC 密钥下发（联调修正②）**：`guardconfig/provider.go` needsKey 增 `len(cfg.APIStrongFlows)>0`（无授权模型仅有强流程定义的应用也须下发对象 HMAC key），应下发而缺失 fail-hard。
5. **OpenAPI 实收 698（预估 699 差 1）**：实例详情端点随 FLOW-03 登记，本批 definitions 5 + instances 列表 1 + 事件查询并入既有面，reconcile 双向零差集。
6. **方向偏置（F02）**：6 轮并发均同侧先占槽（容器时延差异），与 Lua 原子域正确性无关；断言「恰一成功」成立。

## C01 零变化声明（NG-T-C01）

- 无 `api_strong_flows` 下发段时 `buildStrongFlowRuntime` 返回 nil，pipeline 零行为（单测 `TestEvaluate*` 零值路径 + 装配注释契约）。
- 无定义应用（waf-s5.local 等存量 Host）：stage5 回归 40/40、custom-pack 13/13 不回退——行为面零变化。
- 发布面：含定义应用首次发布产生 `api_strong_flows` 段与版本戳漂移一次（定义即配置的正常发布语义）；无定义应用发布快照零新段。
- 事件面：无强流程活动的请求 `strong_flow` 键缺省（omitempty），api_runtime_events 零形状变化，采集侧容忍缺失。

## 回归输出（原样关键行）

```
阶段5真实网关测试汇总：总用例数 40，通过 40，失败 0
CUSTOM_PACK 二次阻断评估验证：13/13 通过，0 失败
server：ok strongflow 1.814s / ok apiruntime 1.552s / ok guardconfig 1.879s / ok gatewayconfig 2.757s（-count=1）
gateway：go build ./... exit=0；dynamic_security 17 包 ok / modules/jiuzhang_guard 17 包 ok，无 FAIL（-count=1）
python3 tools/check-api-reconcile.py：代码注册路由 698  OpenAPI 片段收录 698  对账通过：双向零差集
gofmt：本批改动文件（flowguard/strongflow/apiruntime/guardconfig/gatewayconfig/jiuzhang_guard）干净
  （工作区既有 6 个非本批文件 gofmt 列出：corazasemantics/selfcheck_debug_test.go、capability/types.go、
    exceptions/{fromevent,handler}.go、securityevents/normalize.go、tests/stage_exceptions_p0_test.go——不属本批不动）
```

## 现场还原终态

- 测试定义：v1~v5 全部 RETIRED（RETIRED 单向终态，激活链 v5→retire）；实例/步骤事件按应用维度清理（PG DELETE，级联完整）。
- Valkey `sflow:v1:*` 测试键已清理；autosave 无残留（最终发布快照无 api_strong_flows 段，应用版本与发布状态还原）。
- 临时编排 `deployment/docker-compose.stage5-f02.yml` 已删除（gateway-b 容器/卷验收后即清）。
- `server/tmpaz2sign/`（JWT 签名 E2E 工具）已删除；stage5 全栈 healthy（api/gateway/postgres/valkey/testorigin）。
