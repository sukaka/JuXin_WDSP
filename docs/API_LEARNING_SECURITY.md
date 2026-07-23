# API 学习安全设计（阶段8 / WDSP）

## 一、目的与范围

动态学习是把运行时流量转化为防护模型的过程，其安全目标是：**学习可以持续，
放宽必须人工；样本不成为新的敏感数据孤岛；攻击者不能通过喂流量污染模型**。
本文覆盖：

- 样本的数据最小化（哈希/指纹，不落敏感明文）；
- 样本过滤与排除模型（`accepted` / `exclude_reason`）；
- 学习任务状态机（`api_learning_jobs`）与端点学习状态；
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
这些过滤提供了原料。当前已具备的判定原料：

| 过滤依据 | 原料来源 |
|----------|----------|
| 偏离正式模型 | `api_schema` 明细（`detectors/schema.go`） |
| 认证缺失/弱凭据/格式错误 | `authentication` 明细（`detectors/authentication.go`） |
| 速率异常 | `api_ratelimit` / `behavior` 明细 |
| 请求被截断（解析不完整） | `BodyTruncated` 标记（`parser/parse.go:116-127`） |
| 被最终阻断/限速 | 主事件 `final_action` |

## 四、学习任务状态机

学习任务（`api_learning_jobs`，`store.go:92-105`）：

```text
            learning/start                    learning/stop
NOT_STARTED ──────────► RUNNING（任务行） ──────────► STOPPED
（端点 learning_status） LEARNING                     PAUSED
                        状态列预留：RUNNING / STOPPED / COMPLETED / FAILED
```

- `StartLearning`（`store.go:602-641`）：锁端点行（`FOR UPDATE`）防并发双开，
  已有 RUNNING 任务返回 `ErrLearningRunning`（HTTP 409）；建任务同事务置端点
  `learning_status=LEARNING`；
- `StopLearning`（`store.go:645-684`）：无 RUNNING 返回 `ErrLearningNotRunning`
  （409）；置 STOPPED + `stopped_at`，端点回 `PAUSED`，写生命周期事件；
- 查询：`GET .../learning/status` 返回最近一次任务 + 样本统计；
- 任务计数列（`sample_target/collected_count/valid_count/excluded_count`）
  与 `last_error` 已建，当前无自动采集器回填（见第七节）。

端点学习状态白名单 `NOT_STARTED/LEARNING/PAUSED/LEARNED`（`store.go:39-44`），
与模型版本状态（CANDIDATE/FORMAL…）分离：学习是过程，模型是产物（任务书 §12）。

## 五、防学习污染：原则与已落实的硬保证

任务书 §26 要求的机制分两类如实说明。

**当前已落实（代码级不变量）**：

1. **正式模型冻结**：FORMAL 无任何内容更新接口，偏离请求只产生检测明细，
   永不反向扩大正式模型（`detectors/schema.go:11`；`apimodels/store.go:35-36`）。
   攻击者持续发送异常请求对防护基准零影响——这是防污染的根本保证。
2. **候选生成是人工动作**：当前唯一产生候选的接口是
   `POST .../endpoints/{id}/models`（`apimodels/handler.go:70-106`），
   带权限点（`api_model.edit`）、CSRF、操作审计；没有任何自动路径把流量
   直接变成模型。
3. **确认是独立人工动作**：候选→FORMAL 需 `api_model.confirm` 权限，
   记录确认人/时间并审计（`apimodels/store.go:158-199`）。
4. **截断不学习**：超大请求体只嗅探不遍历字段（`parser/parse.go:133-137`），
   半个 Schema 不会进入任何比对与学习产物。
5. **样本表只存哈希**：即使未来自动样本采集接通，表结构本身不定义明文字段。

**设计方向（尚未实现，随自动学习接通落地）**：

- 单 IP / 单身份 / 单 Token / 单 UA 样本占比上限；
- 新结构最小独立来源数、新范围最小有效样本数；
- 离群值排除、样本去重、时间衰减、人工可信来源标记；
- 学习审计（样本级 accepted/exclude_reason 已为此留位）。

## 六、与运行时事件的衔接（样本原料链）

```text
运行时请求 → 统一管线（一次解析 + 检测明细 + 决策）
  → guard 输出 apievents.Record（脱敏后的事件与端点信息）
  → api-runtime-events.log（JSONL）
  → apiruntime.Collector 入库 api_runtime_events（主事件）
      + UpsertDiscovery（端点发现）
  → 【未接通】学习采集器：按学习任务订阅端点事件，
      依 §三的过滤规则写 api_learning_samples（accepted/exclude_reason），
      达到阈值后生成候选版本（created_reason=learning_threshold）
```

当前状态：箭头到 `api_runtime_events` 为止已生产可用；样本采集与候选生成
环节尚无生产实现（如实披露，见第七节）。

## 七、当前实现范围与限制

1. **学习触发为手工**：学习任务只有 start/stop/status 管理接口；启动后没有
   自动样本采集器消费运行时事件，`collected_count` 等计数列保持 0。
2. **样本表无生产写入方**：`api_learning_samples` 结构、查询、统计接口齐备，
   但没有任何代码路径 INSERT（全仓检索确认）；`accepted/exclude_reason`
   模型为先行落地的表结构设计。
3. **自动候选生成的阈值触发在演进中**：网关 `learning.Store.Observe` 是占位
   实现，只累计计数、不生成候选（`gateway/dynamic_security/learning/version.go:61-67`）；
   管理面 `created_reason` 当前仅 `manual`。
4. **防污染配额未实现**：§5 第二类的占比上限/最小来源数/离群排除等
   需随自动学习一并落地；当前阶段以「候选人工创建 + 确认人工冻结」
   作为等效防污染闸门。
5. **响应侧信号缺失**：样本过滤依据中的「响应不完整、5xx」等依赖响应解析，
   当前管线只处理请求，过滤规则实现时需先补响应挂点。

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
