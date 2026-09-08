# API 学习安全设计（阶段8 / WDSP）

## 一、目的与范围

动态学习是把运行时流量转化为防护模型的过程，其安全目标是：**学习可以持续，
放宽必须人工；样本不成为新的敏感数据孤岛；攻击者不能通过喂流量污染模型**。
本文覆盖：

- 样本的数据最小化（哈希/指纹，不落敏感明文）；
- 样本过滤与排除模型（`accepted` / `exclude_reason`）；
- 学习任务状态机（`api_learning_jobs`）与API学习状态；
- 防学习污染的设计原则与当前已落实的硬保证；
- 当前学习触发方式与未接通的环节（如实披露）。

模型确认与冻结见 `docs/API_MODEL_VERSIONING.md`；样本原料（统一主事件）见
`docs/UNIFIED_DYNAMIC_SECURITY_ARCHITECTURE.md` §2.3。

## 二、样本数据最小化

学习样本表 `api_learning_samples`（迁移 000018）：

```text
id / api_endpoint_id / request_id / sample_hash / source_fingerprint /
identity_fingerprint / response_status / accepted / exclude_reason / collected_at
```

设计约束（任务书 §50.4「不保存完整敏感值」）：

- **`sample_hash` 是样本唯一身份**：内容哈希，不存请求体明文；
- **来源与身份只存指纹**：`source_fingerprint`（客户端来源）、
  `identity_fingerprint`（凭据身份）与网关侧同族——运行期身份维度一律
  FNV-1a 64 不可逆指纹（`detectors/authentication.go:184`），不存 IP 明文之外的
  任何凭据值；
- 网关解析期已完成前置脱敏：authorization/cookie/x-api-key 头只留
  `[redacted]` 标记（`parser/parse.go:89-98`），检测证据只记 scheme 与长度分档
  （`detectors/authentication.go:143-159`），请求体只留 FNV 哈希
  （`parser/parse.go:267-275`）——**进入样本链路的数据在源头就不含敏感明文**；
- 列表查询接口 `GET .../learning/samples` 只暴露上述脱敏列
  （`apiassets/store.go:743-781`）。

## 三、样本过滤与排除模型

样本带 `accepted` 布尔与 `exclude_reason` 文本：**被排除的样本也留存记录**
（带排除原因），而不是删除——过滤决策本身可审计、可复查、可反查误杀。
统计接口按 `accepted` 聚合（`SampleStats{total, accepted, excluded}`，
`store.go:687-707`）。

任务书 §25 的过滤规则（WAF 高风险命中、API 偏离命中、黑名单、CC 超限、
401/403/429、5xx、解析失败、扫描器、高频随机参数、已确认攻击/异常、
超出正式模型、单一来源重复、超解析限制、响应不完整）是本系统的**设计目标全集**；
统一主事件的 `details_json`（各检测器明细 + final_action + 响应侧信号）为执行
这些过滤提供了原料。

**采集端已执行的过滤规则**（`apiruntime/samples.go:sampleVerdict`，按优先级命中即排除）：

| 优先级 | 规则 | `exclude_reason` | 原料状态 |
|--------|------|------------------|----------|
| 1 | `final_action` ∈ {BLOCK, RATE_LIMIT, TEMP_BLOCK} | `blocked_by_decision` | 生产可用（含 API 限速/临时封禁维度；先于状态码规则：此时 403/429 是本系统决策产生而非上游响应） |
| 2 | `response_status` ∈ {401,403,429} 或 ≥500 | `response_status_<N>` | 规则已实现；放行请求状态码采集待后续（事件置 0 时跳过本规则，见 §七） |
| 3 | details 含 `detector=waf` 命中 | `waf_hit` | 规则已实现；Coraza 明细尚未同步进统一上下文（§七），同步后自动生效 |
| 4 | details 含 `detector=api_schema` 命中 | `schema_deviation` | 生产可用 |

**落库侧附加规则**（`apiassets/learning_automation.go:RecordLearningSample`）：

- **来源占比上限**（任务书 §26 最小子集）：同一 `source_fingerprint` 的
  accepted 样本达 `max(10, sample_target/2)` 后，该来源后续样本改判
  `exclude_reason=source_ratio_cap`；
- **幂等去重**：`(api_endpoint_id, request_id)` 部分唯一索引（迁移 000027，
  `request_id<>''`）+ `ON CONFLICT DO NOTHING`，采集器重读不重复落样、
  不重复计数；空 `request_id` 的样本无法幂等去重，不落库。

设计目标全集中**尚未执行**的规则（解析失败、扫描器、高频随机参数、
已确认攻击/异常、超出正式模型、超解析限制、响应不完整）待相应原料
（响应解析、发现/情报联动）落地后补充。

## 四、学习任务状态机

学习任务（`api_learning_jobs`，`store.go:92-105`）：

```text
            learning/start                    learning/stop
NOT_STARTED ──────────► RUNNING（任务行） ──────────► STOPPED
（API learning_status） LEARNING                     PAUSED
                              │
                              └─ 样本达阈值（learningjobs.Worker）─► COMPLETED
                                API learning_status=LEARNED
                        状态列取值：RUNNING / STOPPED / COMPLETED / FAILED（预留）
```

- `StartLearning`（`store.go:730`）：锁API行（`FOR UPDATE`）防并发双开，
  已有 RUNNING 任务返回 `ErrLearningRunning`（HTTP 409）；建任务同事务置API
  `learning_status=LEARNING`；可选请求体 `{"sample_target": N}`
  （N∈[10, 100000]，缺省 100；0 或越界 400）设定样本目标；
- `StopLearning`（`store.go:779`）：无 RUNNING 返回 `ErrLearningNotRunning`
  （409）；置 STOPPED + `stopped_at`，API回 `PAUSED`，写生命周期事件；
- **达标自动完成**（`learning_automation.go:CompleteLearning`）：`learningjobs.Worker`
  周期扫描（默认 30s，可经 `system_settings` 组 `api_learning` 的
  `sweep_interval_seconds` 覆盖），`valid_count >= sample_target` 的任务在事务内
  置 COMPLETED（`stopped_at=now`）+ API `LEARNED` + 生命周期事件
  （LEARNING→LEARNED，actor=system），随后自动生成模型候选并写操作审计；
  单任务失败不阻断其他任务，失败原因记 `last_error`；
- 查询：`GET .../learning/status` 返回最近一次任务 + 样本统计；
- 任务计数列（`sample_target/collected_count/valid_count/excluded_count`）
  由样本落库同事务回填（只对实际插入的行计数）。

API学习状态白名单 `NOT_STARTED/LEARNING/PAUSED/LEARNED`（`store.go:39-44`），
与模型版本状态（CANDIDATE/FORMAL…）分离：学习是过程，模型是产物（任务书 §12）。

## 五、防学习污染：原则与已落实的硬保证

任务书 §26 要求的机制分两类如实说明。

**当前已落实（代码级不变量）**：

1. **正式模型冻结**：FORMAL 无任何内容更新接口，偏离请求只产生检测明细，
   永不反向扩大正式模型（`detectors/schema.go:11`；`apimodels/store.go:35-36`）。
   攻击者持续发送异常请求对防护基准零影响——这是防污染的根本保证。
2. **候选生成受控**：自动路径仅一条——样本达阈值由 `learningjobs.Worker`
   生成**空 Schema 候选**（`created_reason=learning_threshold`，变更说明要求
   人工完善 Schema 后提交审核）；手工路径为
   `POST .../endpoints/{id}/models`（`apimodels/handler.go:70-106`），
   带权限点（`api_model.edit`）、CSRF、操作审计。自动路径不携带任何
   从流量学出的字段结构，流量不会直接变成模型。
3. **确认是独立人工动作**：候选→FORMAL 需 `api_model.confirm` 权限，
   记录确认人/时间并审计（`apimodels/store.go:158-199`）。
4. **截断不学习**：超大请求体只嗅探不遍历字段（`parser/parse.go:133-137`），
   半个 Schema 不会进入任何比对与学习产物。
5. **样本表只存哈希**：即使未来自动样本采集接通，表结构本身不定义明文字段。
6. **来源占比上限**：同一来源指纹的 accepted 样本达
   `max(10, sample_target/2)` 即改判排除（`source_ratio_cap`，见 §三），
   单一来源无法灌满样本池；样本按 `(endpoint, request_id)` 幂等去重，
   重放流量不重复计数。

**设计方向（尚未实现，随自动学习继续落地）**：

- 单身份 / 单 Token / 单 UA 样本占比上限（身份指纹已随样本落库，规则未执行）；
- 新结构最小独立来源数、新范围最小有效样本数；
- 离群值排除、时间衰减、人工可信来源标记；
- 学习审计（样本级 accepted/exclude_reason 已为此留位）。

## 六、与运行时事件的衔接（样本原料链）

```text
运行时请求 → 统一管线（一次解析 + 检测明细 + 决策）
  → guard 输出 apievents.Record（脱敏后的事件与API信息，
    含 response_status/source_fingerprint/identity_fingerprint）
  → api-runtime-events.log（JSONL）
  → apiruntime.Collector 入库 api_runtime_events（主事件）
      + UpsertDiscovery（API发现）
      + recordSample：按 endpoint_key 匹配 RUNNING 学习任务，
        依 §三过滤规则写 api_learning_samples（accepted/exclude_reason），
        (endpoint, request_id) 幂等、计数同事务回填、来源占比上限
  → learningjobs.Worker（默认 30s 周期）：valid_count 达 sample_target
      → 任务 COMPLETED + API LEARNED + 生命周期事件
      → 自动生成候选版本（created_reason=learning_threshold，空 Schema
        待人工完善）+ 操作审计；确认与冻结仍为人工动作
```

当前状态：全链路（事件 → 样本 → 阈值判定 → 候选）已生产接通；
样本 Schema 画像（从样本统计字段类型）仍遗留，候选 Schema 需人工完善。

## 七、当前实现范围与限制

1. **样本采集已自动接通**：学习任务 start 后，采集器按 §三过滤规则落样并回填
   计数；启动时可指定样本目标（`sample_target`，缺省 100）。网关旧版本事件
   不含 `response_status`/指纹字段时按零值处理（状态码规则跳过、占比上限
   不判定），不产生错误。
2. **阈值触发自动候选已接通**：达阈值任务自动 COMPLETED + API LEARNED +
   生成空 Schema 候选（`created_reason=learning_threshold`）；候选创建失败
   不回滚任务完成（失败记 `last_error`，可手工补建候选，避免重试产生重复版本）。
   候选 Schema 需人工完善（参数统计画像仍遗留，见下）。网关侧
   `learning.Store.Observe` 仍是占位实现，不参与本闭环。
3. **响应状态码部分缺失**：放行请求在上游响应前即输出事件，`response_status`
   置 0（状态码过滤规则对 0 跳过；阻断类动作按决策映射 403/429 填充）。
   状态码规则的完整生效待响应侧挂点。
4. **Coraza 命中未进统一上下文**：`waf_hit` 规则已实现，但 Coraza/WAF 明细
   尚未同步进 `RequestContext`（经 request_id 在管理面关联；coraza-caddy 为
   第三方模块，不 fork），同步后该规则自动生效。
5. **防污染配额部分实现**：`source_ratio_cap`（来源指纹维度）已执行；
   单身份/Token/UA 上限、最小独立来源数、离群排除、时间衰减、可信来源
   仍待落地；候选人工完善 + 确认人工冻结仍是最终闸门。
6. **样本画像未实现**：自动候选为空 Schema——从 accepted 样本统计字段类型/
   约束的参数画像（任务书 §50.3 观察列）仅有表结构，是下一步核心遗留。

## 八、与任务书章节对应

| 本文章节 | 任务书 |
|----------|--------|
| 二、数据最小化 | §7.1、§50.4（样本不落敏感值）、§三十五（凭据只存指纹） |
| 三、过滤模型 | §二十五 学习样本过滤（设计目标与原料对照） |
| 四、任务状态机 | §十二 API学习状态、§51.2 学习接口 |
| 五、防污染 | §二十六 防学习污染机制（已落实/未实现分列）、§2.6 |
| 七、限制 | §二十八 版本生成条件（自动触发未实现的如实披露） |

---

Copyright © 聚信得仁
All Rights Reserved.
