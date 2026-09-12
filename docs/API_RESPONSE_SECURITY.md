# API 响应侧安全设计（ResponseContext / 响应相位 / Response Transformer）

> 对应补全任务书 §226（P0-05 ResponseContext、P0-07 MASK_RESPONSE）。本文以代码为准
> 描述第一波交付后的真实实现：响应捕获、响应相位、字段级脱敏改写与失败策略均已落地；
> 发布通道不下发的配置项与未实现的响应 Schema 校验如实标注。

## 一、目的与范围

API 流量的安全视野从「只看请求」扩展到「请求 + 响应」：响应捕获后统一解析，
做敏感字段检测、错误签名提取与字段级脱敏改写（MASK/HASH/REMOVE），并让事件在
响应完成后输出（真实 `response_status` 与 `latency_ms`）。本文覆盖：

- `ResponseContext` 响应侧上下文（`gateway/dynamic_security/context/context.go`）；
- 响应捕获挂点与直通/缓冲/抑制策略（`gateway/modules/jiuzhang_guard/apiresponse.go`）；
- 响应相位 `ProcessResponse`（`gateway/dynamic_security/pipeline/response.go`）；
- 敏感字段检测与错误签名（`dynamic_security/response/fields.go`、`signatures.go`）；
- Response Transformer（`dynamic_security/response/transform.go`）与 Content-Length 修正；
- 压缩/流式降级、FAIL_OPEN/FAIL_CLOSED 失败策略与性能保护。

请求侧管线与统一决策见 `docs/API_UNIFIED_FINDING_DECISION.md`；脱敏规则的
管理面（类型/规则/生效计划）见 `docs/API_SENSITIVE_DATA.md` 口径与
`server/internal/apidata`。

## 二、ResponseContext 响应侧上下文

`ResponseContext`（context.go:80-93）由响应相位在**下游响应完成后写入一次**
（`SetResponse`，仅 API 流量），挂在统一 `RequestContext.Response` 上：

```text
status             响应状态码
content_type       响应 Content-Type
headers            响应头快照（已脱敏：set-cookie/www-authenticate 等仅标记
                   "[redacted]"；值截断 256 字符；头数封顶 64）
body_size          捕获/传输字节数（脱敏改写时为改写前大小）
body_hash          捕获体 sha256 前 8 字节 hex（哈希，非明文）
truncated          体超捕获上限，未完整解析（禁止解析与改写）
streamed           流式/非可安全重编码直通（未缓冲）
is_json / parsed_body   JSON 字段路径 → 类型（string|number|bool|object|array|null）
sensitive_fields[]      敏感字段命中（证据只含字段路径与数据类型标签，绝不含值）
error_signatures[]      错误签名标签（http_5xx / stack.* / db.*）
transform_plan[]        字段级脱敏计划（FieldTransform：field_path/algorithm/
                        keep_head/keep_tail；决策引擎 MASK_RESPONSE 分支依据）
```

数据最小化纪律与请求侧一致（context.go:78-79 注释）：**不保存响应明文体**，
解析产物只含字段路径与类型；脱敏算法在内存中对解码后的 JSON 树执行，
事件/证据只含字段路径与数据类型标签。

## 三、响应捕获挂点（捕获/上限/直通策略）

仅 **API 流量**包装捕获（`api_dynamic_protection` 开启且判为 API；
`apiprotect.go:115`），非 API 流量零包装零开销。捕获 writer
`apiResponseCapture`（apiresponse.go:49）在首个 `WriteHeader` 时按响应头定模式：

| 条件 | 模式 | 行为 |
|---|---|---|
| 101 升级 / `Upgrade` 头（WebSocket） | 直通 | 不缓冲，立即透传状态行 |
| `Content-Encoding` 非 identity（gzip/br 等） | 直通或抑制 | FAIL_OPEN → 直通（有命中规则时 Warn 记录跳过脱敏）；FAIL_CLOSED 且API有规则 → 抑制 |
| `Content-Type` 缺失或 JSON 族（`application/json`、`+json` 后缀） | 缓冲 | 缓冲完整响应，响应相位后一次性写回 |
| 显式非 JSON（含 SSE `text/event-stream`） | 直通 | 不缓冲（避免长连接挂死与内存失控） |
| 缓冲超 `api_response_capture_max_bytes` | 溢出/抑制 | FAIL_OPEN → 转直通溢出（spill）：已缓冲前缀 + 后续完整外发，**原响应不截断**，Warn；FAIL_CLOSED 且API有规则 → 抑制 |
| 连接被 Hijack | 脱离捕获 | 有规则时只能 fail-open + Warn（无法向已劫持连接注入封闭响应） |

**抑制（captureDiscarded）**：字节全部丢弃、原响应**一字节不外发**，最终以
`500 + 空明细 JSON`（`{"error":"response_processing_failed","request_id":...}`）替代，
并剥除 `Content-Length/Content-Encoding/ETag/Content-MD5`
（`writeFailClosedResponse`，apiprotect.go:269）。

配置键（网关 `jiuzhang_guard` 模块级，module.go:159-166）：

- `api_response_capture_max_bytes`：捕获上限，默认 **1 MiB**，配置硬上限 **16 MiB**
  （apiresponse.go:30-32；超限配置 Validate 拒绝加载）；
- `api_response_fail_policy`：`FAIL_OPEN`（缺省）/ `FAIL_CLOSED`（词表外 Validate 拒绝）。

**发布通道现状（诚实标注）**：server 端 GuardConfig 当前**不下发**这两个键
（`gatewayconfig/guard.go` 无对应字段，`gateway_runtime` 设置白名单亦无），
网关上以默认值生效；发布下发的响应侧内容目前为 `api_mask_rules` +
`api_policy_version` + `api_formal_model_versions`。需要 FAIL_CLOSED/调整上限时
只能在网关配置层注入，管理面下发属后续分片。

## 四、响应相位 ProcessResponse

`ProcessResponse`（pipeline/response.go:49）在下游响应完成后调用一次，依次：

1. **JSON 解析**：仅完整捕获（非截断/非流式）且 JSON 族/嗅探判定为 JSON 的响应；
   `WalkJSONFields` 提取字段路径 → 类型（`UseNumber` 保留数字字面量；数组仅下钻
   首个元素，路径记 `[]`，字段数/深度受 `ParseLimits` 上限约束）；
2. **敏感字段检测**：复用 detectors 词表做**字段名**匹配（`cfg.SensitivePatterns`
   为 nil 用内置默认表），命中写 `sensitive_fields` 并 AddMatch
   （`sensitive_data` / `sensitive.response_field`，OBSERVE/MEDIUM/+10）；
   单事件命中上限 20（`maxResponseSensitiveFindings`，与请求侧对齐）；
3. **错误签名提取**：5xx 状态码 + 体内堆栈/数据库错误特征（§五）；
4. **transform plan 生成**：API脱敏规则 ∩ 解析产物，仅收录字段真实存在且算法
   可执行的项（§六）；
5. **统一决策**：`decision.Decide` 复跑——计划非空且 PROTECT → `MASK_RESPONSE`；
   OBSERVE 模式仅记录不执行（决策优先级语义见
   `docs/API_UNIFIED_FINDING_DECISION.md` §决策）。

请求侧阻断类请求不会到达本相位（挂点已拦截），优先级语义不变
（response.go:159 注释）。

## 五、敏感字段检测与错误签名

- **敏感字段**（响应侧）：字段名匹配，证据只含 `{field, data_type,
  location:"response_json"}`；数据类型标签为 phone/email/id_card/bank_card/
  credential 五类（与 `detectors/sensitive.go` 内置词表同源）。
- **错误签名**（`signatures.go`）：固定特征子串表，命中即收录签名标签一次，
  不提取原文——`http_5xx`（状态码 5xx）、`stack.python_traceback`、
  `stack.go_panic`、`stack.java_trace`、`db.sqlstate`、`db.oracle`；
  体扫描上限 **64 KiB**（`maxErrorSignatureScanBytes`）。命中 AddMatch
  （`api_response` / `response.error_signature`，OBSERVE；5xx 时 MEDIUM，否则 LOW；+5）。

## 六、Response Transformer（MASK/HASH/REMOVE）

### 6.1 规则与计划

- 规则来源：管理面 `api_masking_rules` 表 enabled 规则 → 发布通道
  `api_mask_rules` 下发（`guardconfig/apiruntime.go:141`；表缺失/查询失败 Warn 跳过，
  不阻断发布）→ 网关 `compileAPIMaskRules` 逐条校验并按 `endpoint_key` 归组
  （配置错误拒绝加载，不静默吞错）。
- 规则字段：`endpoint_key / field_path / data_type / algorithm / params`
  （`keep_head/keep_tail`，默认 3/4，上限 64）；规则总数上限 512、字段路径 ≤256 字符。
- `field_path` 点路径 DSL（response/rule.go:44-50）：`.` 分段；段名以 `[]` 结尾
  表示数组通配（`users[].phone` 命中每个元素的 phone；`users[]` 命中每个标量元素）；
  与解析产物路径同构精确匹配；**键名本身含 `.` 的字段无法寻址**（既定限制）。
- `BuildTransformPlan`（rule.go:147）：只收录字段在解析产物中**真实存在**且算法
  可执行的规则——object/array 目标仅 REMOVE 可执行，MASK/HASH 空转项在生成期剔除，
  保证「plan 非空」对决策引擎是有执行含义的信号。规则顺序即计划顺序；
  同路径多规则**首条生效**。
- 作用域说明：发布读取按 `endpoint_key` 原样下发、网关按当前API精确命中归组规则；
  GLOBAL/APPLICATION/ENDPOINT 三作用域的合并求值由管理面
  `apidata.MaskPlanForEndpoint` 提供（GLOBAL < APPLICATION < ENDPOINT 覆盖），
  发布下发链路当前不做 scope 展开。

### 6.2 执行（ApplyJSON，transform.go:25）

仅处理**可安全重编码的完整 JSON**（解析失败返回错误，调用方按失败策略处理）：

- **MASK**：保留前 `keep_head`、后 `keep_tail` 字符，中间按原字符数替换为 `*`；
  值长 ≤ keep_head+keep_tail 时整体替换为 `"****"`（不泄露精确长度与残留字符）；
- **HASH**：对标量字符串形式取 sha256 hex（不可逆，可跨响应关联同一值）；
- **REMOVE**：对象成员删键；数组元素从数组中移除；
- MASK/HASH 仅适用标量（string/number/bool）；非标量目标跳过并计 `skipped_fields`；
- 重编码 `UseNumber` 保留数字字面量、`SetEscapeHTML(false)`（JSON API 语义不变、
  减小字节漂移）。

### 6.3 写回与 Content-Length 修正

`writeBufferedResponse`（apiprotect.go:244）：

- 脱敏改写后：按新体长**重设 `Content-Length`**，同时**删除 `ETag` / `Content-MD5`**
  （体已变化，旧校验值失效）；
- 未改写且处理器未声明长度时：按缓冲长度补 `Content-Length`
  （1xx/204/304 不带体）；因此 chunked 响应经缓冲写回后转为显式长度
  （直通模式不受影响，保持原传输形态）。

## 七、压缩与流式降级（gzip/br/chunked/SSE/WebSocket）

- **gzip/br 等非 identity 编码**：无法安全重编码 → FAIL_OPEN 直通 + Warn
  （API有规则时）；FAIL_CLOSED 且API有规则 → 抑制（§三）。即压缩响应在默认策略下
  **不做脱敏**——源站对敏感API开压缩等于绕过脱敏，部署纪律上应由网关侧压缩或
  关闭源站压缩（当前实现不在捕获层解压）。
- **SSE / WebSocket / 显式非 JSON**：直通不缓冲；WebSocket  Hijack 后脱离捕获。
- **chunked**：无声明长度的 JSON 族响应正常缓冲，写回时补 `Content-Length`。
- **缓冲超限**：FAIL_OPEN 溢出直通（原响应完整外发，事件 `truncated=true`，
  已缓冲前缀仅留作错误签名扫描，不参与解析与改写）；FAIL_CLOSED 且有规则 → 抑制。

## 八、失败策略（FAIL_OPEN / FAIL_CLOSED）

| 场景 | FAIL_OPEN（默认） | FAIL_CLOSED |
|---|---|---|
| 缓冲超捕获上限 | 溢出直通，原响应完整外发 + Warn | API有规则 → 500 空明细抑制 |
| 非 identity 编码 | 直通 + Warn（有规则时） | API有规则 → 抑制 |
| Hijack | 直通 + Warn（有规则时） | 同左（已劫持连接无法注入封闭响应） |
| 响应相位故障（如敏感词表编译失败） | 放行原响应（不脱敏）+ Warn | 同左（相位故障一律 fail-open，apiprotect.go:179） |
| Transformer 执行失败 | 放行原响应 + Warn + 记 `response.mask_failed`（OBSERVE/HIGH） | 抑制 + 记 `response.mask_failed` |

要点：FAIL_CLOSED 仅在**API存在命中规则**（`hasMaskRules`）时进入抑制分支——
无规则API不承受抑制风险；抑制前必须**未外发任何字节**（缓冲/抑制模式扣留状态行）。
任何失败不 panic、不静默：Warn 必带 `endpoint_key` 与 `request_id`（每请求至多一条）。

## 九、事件输出时机与响应后字段

- **API 放行流量**：事件在**响应完成后输出**，携带真实 `response_status` 与
  `latency_ms`（入口到下游响应完成），以及响应相位新增的检测明细；
- **阻断类动作**（BLOCK/TEMP_BLOCK/RATE_LIMIT）：事件在阻断时输出，状态码按决策
  映射 403/429；
- **非 API 命中**：维持响应前输出，`response_status=0`（未采集语义）；
- 脱敏执行结果以明细入账：`response.mask_applied`（INFO，含
  applied_fields/skipped_fields）/ `response.mask_failed` / `response.fail_closed`。

## 十、性能保护

- 仅 API 流量包装捕获，非 API 零包装零开销；`api_dynamic_protection` 关闭时
  纯 WAF 路径零行为变化；
- 捕获上限默认 1 MiB、硬上限 16 MiB；超限即转直通/抑制，不整包驻留内存；
- 敏感字段命中单事件上限 20；错误签名体扫描上限 64 KiB；
- JSON 解析受 `ParseLimits`（深度 32 / 字段数 2048）约束；截断/流式响应不解析；
- 规则总数 512、字段路径 256 字符上限（防超大配置撑爆内存与日志）；
- 事件字段截断与脱敏（`apievents` sanitize：控制字符剥离 + 长度封顶）；
- `ResponseContext.BodyHash` 只存 sha256 前 8 字节 hex，明文体不进上下文、不进事件。

## 十一、限制与遗留（诚实清单）

1. `api_response_fail_policy` / `api_response_capture_max_bytes` 不经发布通道下发
   （§三），管理面无可配入口；
2. 压缩（gzip/br）响应默认不脱敏（§七），依赖部署纪律；
3. `CompiledEndpointPolicy.response_schema` 恒 null（P0-06 响应模型另一波补全），
   响应侧**无 Schema 偏离校验**；敏感检测仅字段名级，不做值级检测（值级 regex/
   validator 已在管理面 `api_sensitive_data_types` 落数据，待下发消费）；
4. 非 JSON 响应（XML/表单/二进制）不解析不脱敏；
5. 点路径 DSL 无法寻址键名含 `.` 的字段。

## 十二、测试证据

- `dynamic_security/pipeline/response_test.go`：响应相位（解析/敏感/签名/计划/决策）；
- `dynamic_security/response/transform_test.go`、`rule_test.go`、`signatures_test.go`：
  Transformer 三算法/数组通配/首条生效/短值整体遮蔽、规则校验、签名提取；
- `jiuzhang_guard/apiresponse_test.go`：捕获模式矩阵、溢出 spill、FAIL_CLOSED 抑制、
  Content-Length 修正、Hijack；
- `jiuzhang_guard/apiprotect_test.go`：端到端 MASK_RESPONSE、事件响应后输出
  （真实 response_status/latency_ms）。
