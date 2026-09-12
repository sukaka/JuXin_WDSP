# 统一动态安全架构设计（阶段8 / WDSP）

## 一、目的与范围

本文描述阶段8（WDSP）的统一动态安全架构：**一套产品、一条流量处理链、一次协议解析、
统一风险决策**。Web 与 API 流量不经分类分流、不进两套系统，而是在同一条 Caddy 请求链上
由同一个引擎处理：解析一次、各检测器读写同一份 `RequestContext`、由唯一决策引擎定案。

覆盖范围：

- 网关侧统一引擎 `gateway/dynamic_security/`（context / parser / normalizer / classifier /
  detectors / decision / events / pipeline / learning）；
- 引擎在 `jiuzhang_guard` 请求链上的唯一挂点 `serveNext`
  （`gateway/modules/jiuzhang_guard/apiprotect.go:47`）；
- 事件上行：guard `apievents` JSONL → 管理平台 `apiruntime.Collector` →
  `api_runtime_events` 与 `api_endpoints`；
- 配置下行：发布通道 `guardconfig.Provider` → Caddy JSON → guard 运行时；
- 产品形态开关 `PRODUCT_EDITION` / `API_DYNAMIC_PROTECTION_ENABLED`
  （`server/internal/product/edition.go:36`）。

相关专项文档：统一请求上下文见 `docs/REQUEST_CONTEXT_DESIGN.md`，API 发现见
`docs/API_DISCOVERY_DESIGN.md`，Schema 防护见 `docs/API_SCHEMA_PROTECTION.md`，
产品分离见 `docs/API_PRODUCT_SEPARATION.md`。

## 二、架构与数据流

### 2.1 请求处理链（网关）

`jiuzhang_guard` 是 Caddy HTTP 中间件（`http.handlers.jiuzhang_guard`），阶段8 在其既有
处理链尾部追加唯一挂点。处理顺序（`gateway/modules/jiuzhang_guard/module.go:517`）：

```text
客户端请求
  ↓
1. 真实客户端 IP 识别（可信代理判定；伪造代理头产生事件）
2. 保护地址命中 → serveNext（旁路 ACL/CC，不旁路 WAF 与 API 动态防护）
3. 人工临时封禁查询（命中即 403）
4. IP 白名单 / 黑名单（白名单命中 → serveNext）
5. 自动临时封禁（未被白名单绕过则 403）
6. CC 频率限制（REJECT / TEMP_BLOCK）
7. serveNext ──────────────┐
  ↓                        │  api_dynamic_protection=false：直接放行（零开销）
  API 动态防护管线 ◄────────┘  api_dynamic_protection=true：先跑统一管线
  ↓（决策为 BLOCK/RATE_LIMIT/TEMP_BLOCK 时在此拦截，403/429）
下一处理器（Coraza WAF → 反向代理 → 源站）
```

所有放行出口（保护地址旁路、白名单、常规链路）统一收敛到 `serveNext`
（`apiprotect.go:47-56`），保证引擎**有且仅有一个挂点**；关闭时第一行即
`return next.ServeHTTP(w, r)`，零行为变化。

### 2.2 统一管线（一次解析 → 检测 → 统一决策）

`pipeline.Process`（`gateway/dynamic_security/pipeline/pipeline.go:43`）是引擎入口：

```text
*http.Request
  ↓ parser.ParseRequest        一次解析（Query/头/JSON/表单/XML/Multipart/GraphQL）
RequestContext + Parsed        限界解析（ParseLimits），敏感头脱敏，体哈希
  ↓ classifier.Classify        API 流量识别（多信号打分，置信度 0..1）
  ↓ normalizer.EndpointKey     API键 = METHOD + 归一化路径
  ↓ detectors.*                各检测器只 AddMatch（结论+证据+分值），不得定案：
                               api_schema 偏离 / identity 存在性 / authentication 有效性 /
                               sensitive_data 敏感字段 / resource_access 对象级辅助 /
                               lifecycle 生命周期 / api_ratelimit 写限速 / behavior 基线
  ↓ decision.Decide            唯一 finalize 路径：Mode（OFF/OBSERVE/PROTECT）×
                               Matches 类别 → FinalAction 写回上下文
Result{Context, Parsed, API, EndpointKey, FinalAction}
```

外部检测结论（如 WAF 命中）可通过 `externalMatches` 参数注入同一上下文
（`pipeline.go:63-66`），同样只记录、不定案。**检测器不能直接返回阻断响应**，
最终动作只有 `decision.Decide`（`gateway/dynamic_security/decision/engine.go:25`）能写入。

决策动作优先级（`engine.go:76-89`）：
`TEMP_BLOCK > RATE_LIMIT > BLOCK（仅 PROTECT 实阻断；OBSERVE 降级为 OBSERVE）>
OBSERVE > ALLOW`；`INFO` 类明细（如凭据存在性）不参与动作判定（`engine.go:53-56`）。
guard 侧把 `BLOCK` 映射 403、`RATE_LIMIT` 映射 429、`TEMP_BLOCK` 映射 403
（`apiprotect.go:94-103`）。

### 2.3 事件上行（运行时 → 管理面）

```text
jiuzhang_guard.emitAPIEvent（apiprotect.go:123）
  │  仅当：API 流量 或 存在检测明细（apiprotect.go:90）
  │  apievents.Record（主事件 + API发现信息；字段截断、控制字符剥离）
  ▼
/var/log/caddy/api-runtime-events.log（JSONL，共享日志卷）
  ▼
apiruntime.Collector（server/internal/apiruntime/collector.go:62；2s 轮询，断点续传）
  ├─ 全部记录 → apiassets.UpsertDiscovery（API发现，按 endpoint_key 幂等）
  └─ notable 记录（有检测明细或动作非 ALLOW）→ api_runtime_events
       （SavePrimary 按 request_id 幂等，同一 Request ID 一个主事件）
```

与阶段5 访问控制事件同一套采集纪律：offset+inode+前缀指纹断点、轮转检测、
原子保存断点、坏行进 `.errors` 文件不静默丢弃（`collector.go:216-265`）。
checkpoint 落在可写数据目录（`server/cmd/api/main.go:119-120`）。

### 2.4 配置下行（管理面 → 网关）

```text
guardconfig.Provider.BuildGuardConfig（server/internal/guardconfig/provider.go:126）
  │  读取：可信代理/保护地址/黑白名单/CC 策略（阶段5 既有）
  │  阶段8 追加（仅 apiEnabled 时，provider.go:289-320）：
  │    api_dynamic_protection / api_protection_mode（settings 表覆盖 > env > 默认）
  │    api_formal_schemas   ← apimodels.ListFormalSchemas（冻结正式模型）
  │    api_known_endpoints  ← apiassets.ListKeyStatus（已知API基线）
  ▼
gatewayconfig.buildGuardHandler → Caddy JSON（server/internal/gatewayconfig/guard.go:85）
  ▼ 发布通道（Caddy Admin API over Unix Socket）
guard Provision：解析配置、校验模式白名单、开启 apievents 记录器
  （module.go:287-403）
```

关闭时 `buildGuardHandler` 不注入任何 `api_*` 键（`guard.go:128-143`），
下发 JSON 与纯 WAF 完全一致；链路顺序由回归测试锁定为
headers → jiuzhang_guard → waf（`gatewayconfig/guard_test.go:58-67`）。

### 2.5 产品形态

`product.Load()`（`server/internal/product/edition.go:36`）从环境变量解析：

- `PRODUCT_EDITION=waf|wdsp`（缺省 waf）；
- `API_DYNAMIC_PROTECTION_ENABLED`：显式值优先，缺省 wdsp 开 / waf 关；
- `APIDynamicProtectionEnabled()` = 同时满足 wdsp 形态与开关（`edition.go:80`）——
  即使实验环境在 waf 形态下强开检测开关，管理面路由与发布通道也不暴露 API 能力；
- 能力关闭时下发模式恒为 `OFF`（`edition.go:85-90`）。

## 三、关键设计决策

1. **单挂点 serveNext，而非链路改造**。阶段5 的处理链（真实IP/ACL/CC）保持稳定，
   所有放行出口收敛到一个函数，引擎只在该函数内插入。收益：关闭时零开销可证明
   （首行早退）、挂点唯一可审计、阶段5 回归测试不受影响。

2. **一次解析、上下文共享**。parser 读取并消费请求体，因此 `preserveRequestBody`
   先完整读出、管线结束后再还原给下游（Coraza/反向代理）（`apiprotect.go:106-120`）；
   读取失败即跳过管线（fail-open）。解析产物写入 `RequestContext` 并随
   `http.Request.Context()` 传递（`apiprotect.go:87`），下游可经
   `RequestContextFrom` 复用（`apiprotect.go:31`），杜绝重复解析。

3. **检测器与决策分离**。检测器只 `AddMatch`（类别/严重度/脱敏证据/分值），
   只有 `decision.Decide` 能 `SetFinalAction`。这把「发现了什么」与「怎么处置」解耦：
   同一命中在 OBSERVE 与 PROTECT 下行为不同，策略切换不需要改检测器。

4. **fail-open 与既有 guard 故障策略一致**。管线错误、事件输出失败只告警不阻断
   （`apiprotect.go:79-81`、`apiprotect.go:145-147`）；模式配置缺失时按 OBSERVE
   （fail-safe，`apiprotect.go:36-44`）；模式白名单在 guard `Validate` 与
   管理面双侧校验（`module.go:395-401`、`provider.go:109-120`），非法覆盖值回退，
   脏数据不能改变网关行为。

5. **事件走文件而非直连数据库**。网关不持有数据库凭据，JSONL 追加写是网关侧
   最小可信面；管理平台以只读挂载采集，断点续传 + 幂等入库容忍重放与轮转。
   与阶段5 事件体系同一范式，运维心智一致。

6. **模型与基线经发布通道下发，网关不轮询管理库**。冻结模型（`api_formal_schemas`）
   与已知API基线（`api_known_endpoints`）随配置发布进入 Caddy JSON，
   网关重启/重载后仍持有最后有效配置；配置发布失败不影响当前运行配置
   （与 `docs/SECURITY_DESIGN.md` 网关安全一节一致）。

7. **运行时一体化、能力域可拆分**。引擎代码集中在 `gateway/dynamic_security/`，
   不写入 Coraza 适配器内部；管理面 API 集中在 `/api/v1/api-security` 命名空间、
   独立权限点（迁移 000019）、独立事件表，满足未来「九章 API 安全系统」独立打包的边界
   （任务书 §49；产品分离见 `docs/API_PRODUCT_SEPARATION.md`）。

## 四、当前实现范围与限制

如实说明当前实现的边界（与任务书全量范围的差距）：

1. **WAF 命中尚未经 externalMatches 进入统一上下文**。生产路径上
   `pipeline.Process(r, cfg, nil)`（`apiprotect.go:77`）第三个参数为 nil——
   Coraza 在 guard 下游独立执行，其命中仍走阶段4 既有 WAF 事件链；
   统一上下文预留了注入点（`pipeline.go:63-66`），WAF 作为「统一检测器之一」
   写回同一上下文的合流尚未接线和未做全链路回归。统一事件中心当前为：
   WAF 事件（`security_events`）、访问控制事件（`access_control_events`）、
   API 运行时主事件（`api_runtime_events`）三表并存，靠同一 Request ID 关联；
   同一 Request ID 一个主事件的约束在 API 事件流内由 `SavePrimary` 幂等保证
   （`server/internal/apiruntime/events.go:25-44`）。

2. **响应侧检测未实现**。当前管线只解析请求；`RequestContext` 的响应字段
   （状态/头/体哈希）与 `MASK_RESPONSE` 动作已定义但无生产者；
   `CHALLENGE_RESERVED` 未定义（动作枚举见 `context.go:16-24`）。

3. **进程内状态为单节点语义**。behavior/api_ratelimit/resource 检测器的滑窗与游标
   在网关进程内存（LRU 定容），多网关节点各自计数、不共享基线，进程重启清零
   （`gateway/dynamic_security/detectors/window.go:9-12`）。

4. **自动学习未接通**。`gateway/dynamic_security/learning` 的 `Observe` 是占位
   实现（只计数，`learning/version.go:61-67`）；候选模型当前由管理员手工创建
   （详见 `docs/API_LEARNING_SECURITY.md`）。

5. **部分库表已建、写入方未接**。`api_runtime_findings`、`api_schema_violations`、
   `api_sensitive_fields`、`api_learning_samples`、`api_identity_profiles`、
   `api_call_edges`、`api_behavior_profiles` 等表由迁移 000018 建立且有查询接口，
   但当前无生产写入方；运行时发现以主事件 `details_json` 中的检测明细为准。

6. **事件覆盖范围**。guard 只对「API 流量或存在检测明细」的请求输出主事件
   （`apiprotect.go:90`），纯通行非 API 请求仍由访问日志/WAF 事件覆盖，
   不产生 API 运行时事件（但所有被输出的事件都会喂API发现）。

## 五、与任务书章节对应

| 本文章节 | 任务书 |
|----------|--------|
| 2.1 请求处理链 | §六 总体架构、§2.1 同一请求只解析一次 |
| 2.2 统一管线 | §2.2 统一上下文、§2.4 统一决策、§四十五 统一风险决策 |
| 2.3 事件上行 | §2.5 统一事件、§四十六 统一事件中心、§54 可观测性 |
| 2.4 配置下行 | §四十七 统一策略模型、§51.6 策略发布 |
| 2.5 产品形态 | §2.8 运行时一体化能力域可拆分、§四十九 独立API产品 |
| 四、限制 | §65 退出条件中未满足项的如实披露 |

---

Copyright © 聚信得仁
All Rights Reserved.
