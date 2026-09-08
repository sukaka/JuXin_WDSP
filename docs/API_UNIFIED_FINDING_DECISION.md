# API 统一 Finding 与统一决策设计

> 对应补全任务书 §227（P0-08/P0-09 口径）。本文以代码为准描述第一波交付后（G1 后）
> 的真实实现：统一 RequestContext、检测器只写明细、decision 唯一 finalize、
> DetectorMatch→Finding 物化、事件流幂等均已落地；**Coraza 合流（G2）已按
> 「下游哨兵归因」形态落地（第三波）**，现状与局限如实说明（见 §八）。

## 一、目的与范围

统一引擎的核心纪律：**检测器只写结论（`AddMatch`），不直接决定阻断；最终动作仅由
`decision.Decide` 定案**（`dynamic_security/decision/engine.go:1`）。本文覆盖：

- 检测器清单与相位（请求相位 / 响应相位）；
- `DetectorMatch` 明细结构与统一决策的优先级、硬阻断资格、异常分现状；
- `MASK_RESPONSE` 决策分支；
- 统一事件流（网关 JSONL → 采集器 → 入库）与幂等；
- 管理面 `DetectorMatch → Finding` 物化规则；
- Coraza 合流现状（G2 已落地：下游哨兵归因形态与局限）。

## 二、统一上下文与明细结构

同一 HTTP 请求只创建一份 `RequestContext`（`dynamic_security/context/context.go:145`）；
检测结论统一为 `DetectorMatch`（context.go:99-113）：

```text
detector     检测器名（api_schema / authentication / sensitive_data / ...）
rule_id      规则 ID（全局唯一、自带检测器前缀，如 schema.param_length）
category     BLOCK / OBSERVE / RATE_LIMIT / TEMP_BLOCK / INFO
severity     INFO / LOW / MEDIUM / HIGH / CRITICAL
message      人读摘要
evidence     已脱敏键值（字段名/粗类型/约束名；参数原始值与凭据明文永不入内）
score_delta  异常分增量（AddMatch 时累加进 RiskScore）
```

`AddMatch` 线程安全追加并把 `score_delta` 累加进 `RiskScore`，同步推导 `RiskLevel`
（context.go:228/338-351：≥80 CRITICAL、≥50 HIGH、≥25 MEDIUM、>0 LOW、否则 NONE）。

## 三、检测器清单与相位

### 3.1 请求相位（`pipeline.Process`，pipeline/pipeline.go:67）

执行序即代码序；全部只 AddMatch，统一由 `decision.Decide` 定案：

| 检测器（detector 名） | 规则（rule_id） | category / severity / 加分 | 触发条件 |
|---|---|---|---|
| api_schema（schema.go） | schema.undefined_field | OBSERVE/MEDIUM/+15 | BODY 字段不在 FORMAL schema |
| | schema.type_mismatch | **BLOCK**/HIGH/+40 | BODY 字段类型偏离 FORMAL schema |
| | schema.missing_field | OBSERVE/LOW/+5 | FORMAL schema 字段缺失 |
| | schema.param_required | OBSERVE/LOW/+5 | confirmed required 参数缺失 |
| | schema.param_type / param_range / param_length / param_enum | **BLOCK**/HIGH/+40 | confirmed 约束违例（type/minimum/maximum/min_length/max_length/enum） |
| identity（schema.go，CheckIdentitySignals） | identity.token_present / identity.cookie_present | INFO/INFO/0 | 凭据存在性（纯信息，不参与定案） |
| authentication（authentication.go） | auth.unauthenticated_api | OBSERVE/MEDIUM/+10 | API 流量无凭据 |
| | auth.weak_credential / auth.malformed_credential | OBSERVE/LOW|MEDIUM/+5~10 | 弱凭据 / 形态非法 |
| | auth.jwt_malformed_header / jwt_alg_none / jwt_kid_traversal / jwt_empty_signature / jwt_expired | OBSERVE/LOW~HIGH/+5~25 | JWT 结构异常族 |
| authentication（envanomaly.go，同凭据环境异常；匿名跳过） | auth.credential_ip_spread | OBSERVE/MEDIUM/+15 | 滑窗 distinct IP 超阈（默认 3） |
| | auth.credential_concurrency | OBSERVE/LOW/+10 | 同凭据并发 in-flight 超阈（默认 8） |
| | auth.credential_unusual_hour / auth.credential_ua_change | OBSERVE/LOW|MEDIUM/+10~15 | 时段偏离自身基线 / UA 族突变 |
| | auth.env_anomaly_stack | OBSERVE/HIGH/+20 | 多环境异常信号叠加 |
| sensitive_data（sensitive.go） | sensitive.in_query | **BLOCK**/HIGH/+40 | URL query 出现敏感字段名 |
| | sensitive.field | OBSERVE/MEDIUM/+10 | BODY 等位置敏感字段名（值级规则开启时扩展 HEADER 名/PATH 字面段名） |
| | sensitive.value_in_query | **BLOCK**/HIGH/+40 | URL query 值命中值级规则（发布下发才启用，第三波） |
| | sensitive.value | OBSERVE/MEDIUM/+15 | JSON/FORM 留存值、HEADER 非脱敏头值、PATH 原始段值命中值级规则（证据不落值） |
| resource_access（resource.go） | resource.unauthenticated_object_access | OBSERVE/MEDIUM/+15 | 匿名访问对象级资源（BOLA 前置信号） |
| lifecycle（lifecycle.go；仅 API 流量） | lifecycle.new_endpoint | OBSERVE/LOW/+5 | 未登记API（影子 API 信号） |
| | lifecycle.deprecated_api_call | OBSERVE/MEDIUM/+10 | 已下线API被调用 |
| api_ratelimit（ratelimit.go；写方法且 API） | ratelimit.api_write_rate | **RATE_LIMIT**/HIGH/+30 | 写方法每分钟超阈（默认 60） |
| api_authz（authzcheck.go，第四波；API有 confirmed 基线时才判定，不挂 api.IsAPI 门槛） | authz.bfla_anonymous | OBSERVE/HIGH/+30 | 匿名访问有角色基线的API |
| | authz.bfla_role_mismatch | OBSERVE/MEDIUM/+15 | 请求角色无 allowed 基线（角色取自未验签 JWT claims，仅观察信号） |
| | authz.forbidden_field | **BLOCK**/HIGH/+40 | 请求体写入 FORBIDDEN 字段（Mass Assignment） |
| | authz.server_generated_write / authz.readonly_write | OBSERVE/MEDIUM/+15 | 写入 SERVER_GENERATED / READ_ONLY / ADMIN_WRITABLE 指定角色外字段（仅 REQUEST 方向 json. 前缀行） |
| behavior（behavior.go） | behavior.rate_spike | OBSERVE/MEDIUM/+15 | 当前窗 > max(20, 3×历史均值)，样本 ≥5 窗 |

追踪键纪律：凭据指纹优先、无凭据回退 IP，只做滑窗/游标计数维度，**不充当身份**
（pipeline.go:132-133）；身份指纹仅凭据派生（`CredentialKey`），IP 属环境维度。

### 3.2 响应相位（`ProcessResponse`，仅 API 流量、下游响应完成后）

| 检测器 | 规则 | category / severity / 加分 |
|---|---|---|
| sensitive_data | sensitive.response_field | OBSERVE/MEDIUM/+10（单事件上限 20） |
| api_response | response.error_signature | OBSERVE/LOW（5xx 时 MEDIUM）/+5 |
| api_response | response.mask_plan | OBSERVE/LOW/0（计划生成事实） |
| api_response | response.mask_applied / mask_failed / fail_closed | INFO 或 OBSERVE/HIGH（执行结果入账） |

明细随主事件输出，语义与请求相位一致。

## 四、统一决策（decision.Decide）

### 4.1 优先级（engine.go:76-93，自上而下首中即定）

```text
TEMP_BLOCK  >  RATE_LIMIT  >  BLOCK（PROTECT）  >  MASK_RESPONSE（PROTECT 且计划非空）
            >  OBSERVE     >  ALLOW
```

- 任一明细 `category=TEMP_BLOCK`（或 detector=temp_block）→ TEMP_BLOCK；
- 任一 `category=RATE_LIMIT`（或 detector=rate_limit）→ RATE_LIMIT；
- 存在硬阻断资格明细（§4.2）：PROTECT → BLOCK；OBSERVE → OBSERVE（降级不定案）；
- `HasTransformPlan()`（响应脱敏计划非空）且 PROTECT → **MASK_RESPONSE**
  （放行但改写响应体；优先级低于一切阻断类——阻断请求无响应相位；OBSERVE 仅记录计划）；
- 存在 OBSERVE 类明细 → OBSERVE；否则 ALLOW；
- 模式语义：`OFF` 恒 ALLOW；未配置默认 PROTECT（引擎内），**挂点侧启用但未配置模式时
  默认 OBSERVE**（fail-safe，`apiprotect.go:47` `apiDecisionMode`）；
- `INFO` 类明细（category 或 severity 为 INFO）不参与动作决策（engine.go:53-55）。

决策被调用两次：请求相位一次（pipeline.go:178）、响应相位复跑一次
（response.go:164，此时请求相位明细仍在上下文内，加上响应侧明细统一复评；
被阻断请求到不了响应相位，优先级语义不变）。

### 4.2 硬阻断资格（engine.go:57-71）

满足下述任一条件的明细才把 `hasBlock` 置真：

1. `category=BLOCK`（任意检测器显式声明，如 schema.type_mismatch、
   schema.param_* 约束违例、sensitive.in_query）；
2. detector ∈ {`waf`, `api_schema`, `access_control`} 且 severity ∈ {HIGH, CRITICAL}；
3. 单条明细 `score_delta ≥ 50`。

**反向含义（现状要点）**：authentication/behavior/lifecycle/resource_access/
api_response 等检测器即使 severity=HIGH（如 auth.jwt_alg_none、auth.env_anomaly_stack）
也只贡献异常分与 Finding，**不单独触发阻断**——它们是 OBSERVE 级信号。

### 4.3 异常分现状（聚合分仅展示）

- `RiskScore` 为全部明细 `score_delta` 之和，`RiskLevel` 按 §二阈值推导；
- **决策不看聚合分**：定案只依据逐条明细的 category/severity/score_delta（≥50 门槛）
  与 TransformPlan；聚合分与等级仅随事件输出、写入 `api_runtime_events` 与
  `api_runtime_findings`（展示与排序用）；
- 即「积少成多不阻断」：多条 LOW/MEDIUM 叠加到高分也不会升级为 BLOCK，
  升级阻断必须出现 §4.2 资格明细。这是当前实现的有意保守（防误杀），
  聚合分参与定案是后续演进项。

## 五、动作执行（网关挂点，`apiprotect.go`）

| FinalAction | 执行 |
|---|---|
| BLOCK / TEMP_BLOCK | 403，事件在阻断时输出（response_status=403） |
| RATE_LIMIT | 429，事件在阻断时输出 |
| MASK_RESPONSE | 仅完整缓冲的 JSON 响应可执行：`response.ApplyJSON` 字段级改写 → Content-Length 修正、ETag/Content-MD5 失效删除（`docs/API_RESPONSE_SECURITY.md` §六）；改写失败按 `api_response_fail_policy` 放行原响应或 500 抑制 |
| OBSERVE / ALLOW | 放行；API 流量事件在响应完成后输出（真实 response_status/latency_ms） |

引擎/事件输出故障一律 fail-open（告警不阻断业务）；检测器自身无执行权。

## 六、统一事件流与幂等

```text
网关 jiuzhang_guard（apievents.Logger，JSON Lines，0600）
  │  每请求至多一条主事件：阻断时 / API 响应完成后 / 非 API 命中响应前（status=0）
  ▼
server apiruntime.Collector（2s 轮询 CollectOnce）
  │  断点续传：offset + inode + 前缀 sha256 指纹；轮转（inode 变/文件变小/前缀变）
  │  → 从头重读；解析失败行写 .errors 文件（不静默丢弃）
  ▼
api_runtime_events（notable 才入库：有检测明细或 final_action≠ALLOW）
  │  幂等：INSERT ... WHERE NOT EXISTS request_id（同一 Request ID 只一条主事件；
  │  断点不前移的重读不产生重复行）
  ▼
副作用（handleRecord，错误仅记日志不中断采集）：API发现 upsert / 流量桶计数 /
学习样本落样 / schema 违例落库 / **Findings 物化**（§七）/ 参数值观测聚合
```

事件新字段（迁移 000035，第一波已落地）：`client_ip / method / raw_path /
latency_ms / model_version / policy_version`，旧版网关缺字段落 NULL 全程容忍。

## 七、DetectorMatch → Finding（管理面物化）

采集器对每条含明细的事件按**物化规则 v1** 筛选（`apiruntime/findings.go:69`）：

- 明细 severity ≥ MEDIUM，**或**事件 final_action ≠ ALLOW（被拦截/限速/观察事件的
  全部明细都算风险信号，含 severity 缺失者——缺失保守落 INFO）；
- `finding_type`：语义覆盖表优先（`lifecycle.new_endpoint→SHADOW`、
  `lifecycle.deprecated_api_call→DEPRECATED`、
  `resource.unauthenticated_object_access→BOLA_UNAUTHENTICATED_OBJECT_ACCESS`），
  其余机械映射（rule_id 大写下划线化；数字开头加 detector 前缀兜底）；
- 主体：身份指纹 → `IDENTITY`；否则来源指纹 → `IP`；皆无 → 空
  （永不落明文 IP/凭据）；
- 证据脱敏：白名单键（field/param/name/type/want/got/constraint/location/
  object_type）带值（截断 128），其余只留键名；
- **幂等 upsert**：`dedup_fingerprint = sha256(endpoint_id ␟ finding_type ␟
  subject_id)`，`ON CONFLICT` 命中则 `count+1`、刷新 `last_seen_at/updated_at`，
  不覆盖首次证据与标题；API未解析时以 `"key:"+endpoint_key` 兜底保证指纹非空；
- 事件级 `risk_score/risk_level` 与 `model_version/policy_version` 随行落库（溯源
  「当时生效哪版模型与策略」）。

## 八、Coraza 合流现状（G2 已落地：下游哨兵归因）

- **落地形态（第三波，`jiuzhang_guard/apicoraza.go`）**：不 fork coraza-caddy 的折中——
  统一管线判定非阻断的 API 流量在响应捕获路径检查下游返回错误；错误链命中
  coraza-caddy v2.5.0 未导出哨兵错误（"interruption triggered"，包装为
  `caddyhttp.HandlerError{StatusCode: 中断码, ID: Coraza 事务 ID}`）即归因 Coraza 阻断：
  `attributeWAFIntercept` 补记 `detector="waf"` 的 BLOCK 类明细（rule_id
  `waf.downstream_intercept`，Confidence 0.9，证据 `attribution=downstream_intercept` /
  `coraza_tx_id` / `status_code` / `uncertainty=message_matched_no_rule_detail`），
  事件 `final_action` 按实记 BLOCK、`response_status` 取中断码——**阻断已在下游真实
  发生，此处是事实记录而非引擎决策**（OBSERVE 模式同样按实记录）。挂接点
  `apiprotect.go:136-142`（finishAPIResponse 下游错误路径）；管线已判阻断类
  （BLOCK/RATE_LIMIT/TEMP_BLOCK）不重复归因，非 Coraza 错误（如反代 502）不误归因。
- **管线注入仍未接线**：`pipeline.Process(r, cfg, externalMatches)` 第三参恒为 `nil`
  （apiprotect.go:329）——合流走下游错误归因而非请求相位注入；`decision` 对 `waf`
  detector 的硬阻断资格（§4.2 第 2 条）为管线注入形态预留，当前归因明细不参与
  决策（阻断已发生，无需再定案）。
- **局限（如实声明，apicoraza.go:19-23）**：①归因依赖未导出哨兵消息串，与
  coraza-caddy v2.5.0 耦合，升级 CORAZA_CADDY_VERSION 必须复核；②无法取得命中规则
  明细（规则 ID/分值仍在 Coraza 审计日志，经 request_id 事后关联不变——
  `securityevents/normalize.go:159` 提取 x-request-id 落 `security_events`）；
  ③phase 3（响应头相位）中断不归因：无错误返回，特征与源站自返 403 不可区分；
  ④非 API 流量事件维持响应前输出（G1 语义），事后 Coraza 阻断不回填该事件。
- Coraza 仍是**引擎外独立决策点**（guard 先于 Coraza 执行）；guard 传统检查
  （黑白名单/ACL/L7/CC 在 module.go 内直接 return）同样是引擎外决策点。统一决策
  因此仍不是请求路径上唯一的定案者；统一事件源枚举（任务书 §167）尚不存在。
- **测试**：`apicoraza_test.go`——哨兵识别矩阵（裸消息串/非 HandlerError/502 不误判）、
  归因矩阵（已判阻断不重复归因/非 Coraza 错误不归因/nil 上下文安全）、集成用例
  `TestServeNext_CorazaDownstreamIntercept`（ALLOW + 下游 403 中断 → 事件
  final_action=BLOCK、response_status=403、details 含 waf 归因明细）。

## 九、测试证据

- `dynamic_security/decision/engine_test.go`：优先级矩阵、模式降级、INFO 豁免、
  硬阻断资格（detector 白名单 / category BLOCK / score≥50）；
- `dynamic_security/pipeline/pipeline_test.go`、`pipeline_detectors_test.go`、
  `pipeline_constraints_test.go`：多检测器归并单上下文、约束违例 BLOCK；
- `dynamic_security/pipeline/response_test.go`：响应相位复评与 MASK_RESPONSE；
- `server/internal/apiruntime/findings_test.go`：物化规则、finding_type 映射、
  证据白名单、dedup upsert 幂等；
- `server/internal/apiruntime/collector_test.go`：断点续传、轮转、错误行、
  request_id 幂等；
- `gateway/modules/jiuzhang_guard/apicoraza_test.go`：Coraza 哨兵识别/归因矩阵与
  下游中断集成用例（§八）。
