# API 身份安全设计（阶段8 / WDSP）

## 一、目的与范围

本文档描述阶段8 API 身份与凭据安全能力：网关侧凭据存在性识别与认证有效性检测、
身份/计数维度键（CredentialKey/TrackingKey）的生成与用途、管理面身份画像表结构。核心原则贯穿全文：

**凭据明文不出解析层**——Authorization、Cookie、X-API-Key 的值在请求解析阶段即被
替换为 `[redacted]` 标记，下游检测器、事件、证据与数据库只接触"存在性"与
"不可逆指纹"，永不落明文。

覆盖代码：`gateway/dynamic_security/parser/parse.go`（脱敏）、
`gateway/dynamic_security/detectors/schema.go`（存在性指纹）、
`gateway/dynamic_security/detectors/fingerprint.go`（统一加盐指纹）、
`gateway/dynamic_security/detectors/authentication.go`（认证有效性 + CredentialKey/TrackingKey）、
迁移 000018 `api_identity_profiles`、迁移 000029（运行时事件身份字段）。

## 二、架构与数据流

```text
HTTP 请求
  ▼
parser.ParseRequest（parse.go:63）
  │  头脱敏：authorization / cookie / x-api-key → "[redacted]"（parse.go:94-99）
  ▼
pipeline.Process（pipeline.go:47）
  ├─ detectors.CheckIdentitySignals（schema.go:63）
  │    凭据存在性 → ctx.AuthenticationType / TokenFingerprint / APIKeyFingerprint
  │    （"present" 标记，INFO 级 match，不参与决策）
  ├─ detectors.CredentialKey / TrackingKey（authentication.go:163 / 182）
  │    凭据原文计算 HMAC-SHA256 加盐指纹（明文凭据不出函数作用域）；
  │    身份键仅凭据派生，无凭据时计数键回退 ip:+客户端IP
  ├─ detectors.CheckAuthentication（authentication.go:25）
  │    scheme / 格式 / 弱凭据规则 → AddMatch（OBSERVE 类）
  └─ TrackingKey 供 behavior / api_ratelimit / resource_access 检测器做维度归并
  ▼
decision.Decide 统一决策 → 运行时主事件（Details 为已脱敏 DetectorMatch；
  identity_fingerprint / auth_type 随事件落库，见第七节）
  ▼
管理面：api_identity_profiles（画像表，当前无写入方，见第七节）
```

## 三、凭据存在性指纹与认证有效性检测

### 3.1 存在性指纹（CheckIdentitySignals）

`gateway/dynamic_security/detectors/schema.go:63-100`：

- `authorization` 头存在（解析层已脱敏为 `[redacted]`）→
  `ctx.AuthenticationType = "bearer_or_basic"`、`ctx.TokenFingerprint = "present"`，
  并追加一条 INFO 级 match（`identity.token_present`）；
- `x-api-key` 头存在 → `ctx.APIKeyFingerprint = "present"`、
  `ctx.AuthenticationType = "api_key"`；
- `cookie` 头存在 → `ctx.SessionFingerprint = "present"`，并追加一条 INFO 级
  match（`identity.cookie_present`）；仅在无 token/api_key 时
  `ctx.AuthenticationType = "cookie_session"`（cookie 优先级最低，不覆盖前两者）。

INFO 级 match 被决策引擎显式跳过（`decision/engine.go:54`），存在性记录只用于
上下文与事件明细，永远不抬高 FinalAction。

### 3.2 认证有效性规则（CheckAuthentication）

`gateway/dynamic_security/detectors/authentication.go:25-65`，只 AddMatch 不定案：

| 规则 ID | 触发条件 | 类别 / 严重度 | ScoreDelta |
|---------|----------|---------------|------------|
| `auth.unauthenticated_api` | 无 Authorization 且无 X-API-Key，且流量判定为 API | OBSERVE / MEDIUM | 10 |
| `auth.weak_credential` | X-API-Key 长度 < 8 | OBSERVE / LOW | 5 |
| `auth.malformed_credential` | Authorization 无法拆出 scheme/凭据两段，或 scheme 不受支持 | OBSERVE / MEDIUM | 10 |
| `auth.weak_credential` | 凭据为空、长度 < 8、字符集异常（详见 3.3） | OBSERVE / LOW | 5 |

匿名访问判定带 `isAPI` 门控：非 API 流量（静态资源等）无凭据属正常，不产生 match
（authentication.go:33）。所有命中均为 OBSERVE 类——认证有效性当前是观察信号，
不直接阻断。

### 3.3 Authorization 头校验顺序

`checkAuthorization`（authentication.go:68-130）按序判定，每头至多产出一条 match：

1. **结构**：按首个空格拆两段，失败 → `malformed_credential`
   （reason=`missing_scheme_or_credentials`）；
2. **scheme 白名单**：仅 `bearer` / `basic` / `digest`（大小写不敏感，
   正则 `reAuthScheme`，authentication.go:16），其余 → `malformed_credential`
   （reason=`unsupported_scheme`，scheme 截断 16 字符入证据，`clipScheme` 第 133 行）；
3. **空凭据**：`"Bearer "` 一类 → `weak_credential`（reason=`empty_token`）；
   实现特意传原始头值而非 TrimSpace 后的值，保证空 token 判弱凭据而非格式错误
   （authentication.go:46-48）；
4. **长度**：token < 8 字符 → `weak_credential`（reason=`too_short`）；
5. **字符集**：digest 凭据为 k=v 对列表，要求含 `=`（否则 `not_key_value_pairs`）；
   bearer/basic 要求 Base64 系字符集 `^[A-Za-z0-9._~+/=-]+$`（含 JWT 分段点与
   URL-safe 变体，`reTokenBase64ish` 第 18 行），不符 → `not_base64ish`。

### 3.4 证据去敏

Evidence 只含三类信息（authentication.go:12-13）：

- `header` 名（authorization / x-api-key）；
- `scheme`（截断 16 字符）；
- `length_bucket` 长度分档：`0` / `1-7` / `8-15` / `16-31` / `32-63` / `64+`
  （`lengthBucket`，authentication.go:142-156）——连精确长度都不记录，进一步去敏。

## 四、CredentialKey 与 TrackingKey：身份与计数维度键

旧 `IdentityKey`（凭据优先、回退 IP 的单一键）已拆分为两个职责分离的键
（authentication.go:163-197）：

- **`CredentialKey`**（身份维度）：仅由凭据派生，无凭据返回空串（匿名）。优先级：

```text
Authorization 头存在 → "auth:" + Fingerprint(原始头值)
X-API-Key 头存在    → "key:"  + Fingerprint(原始头值)
Cookie 头存在       → "sess:" + Fingerprint(原始头值)
否则                → ""（匿名）
```

- **`TrackingKey`**（计数维度）：CredentialKey 优先，无凭据回退
  "ip:" + RemoteAddr 主机部分（net.SplitHostPort），兜底 "unknown"。
  仅供 behavior / api_ratelimit / resource_access 检测器做滑窗 / 对象游标归并
  （避免匿名流量并入同一桶）；IP 属环境维度，不得冒充身份
  （docs/API_MICRO_MODELS.md §2.2），该键不输出到事件或画像。

统一指纹算法（`detectors.Fingerprint`，fingerprint.go:17-25）：

- HMAC-SHA256(key=salt, value) 截断前 16 字节、hex 输出（32 字符）；不可逆，
  明文凭据不出函数作用域。
- salt 来自 jiuzhang_guard 模块配置项 `identity_salt`（module.go:141，经
  `pipeline.Config.IdentitySalt` 透传）；未配置时以固定域分隔前缀代替
  （未加盐，跨部署可复现），Provision 打 Warn 一次（module.go:385）。
- `parser.BodyHash` 仍用 FNV-1a（样本哈希用途，无跨系统关联需求），不受影响。

身份指纹已进入运行时事件：apiprotect.go:188-194 将 CredentialKey 结果写入
`apievents.Record.IdentityFingerprint`（匿名为空串）、`ctx.AuthenticationType`
写入 `AuthType`（bearer_or_basic / api_key / cookie_session / 空），
`source_fingerprint` 同源升级为 HMAC 指纹（纯客户端 IP 的不可逆脱敏）；
服务端迁移 000029 为 `api_runtime_events` 落库 `identity_fingerprint` /
`auth_type` 两列（详见第七节）。管理面
`api_learning_samples.identity_fingerprint` 列（迁移 000018 第 111 行）为同一
口径的预留字段——样本表当前无写入方，仅有 `ListLearningSamples` 读接口
（`server/internal/apiassets/store.go:877`）。

## 五、api_identity_profiles 画像结构

迁移 000018 第 229-238 行：

| 列 | 说明 |
|----|------|
| `identity_fingerprint` | 身份指纹（VARCHAR(128)，非明文） |
| `endpoint_id` | API，FK 级联删除 |
| `auth_type` | 认证方式（bearer / api_key 等） |
| `request_count` | 累计请求数 |
| `first_seen_at` / `last_seen_at` | 首见 / 最近见时间 |

约束：`UNIQUE (identity_fingerprint, endpoint_id)`——画像按"身份 × API"聚合，
对应任务书第三十五章"保存指纹，不保存完整凭据"。

## 六、关键设计决策

1. **解析层一次性脱敏**。凭据替换为 `[redacted]` 发生在 `ParseRequest`
   （parse.go:94-99），之后所有检测器物理上接触不到明文；这是唯一脱敏点，
   不存在"下游再脱敏"的重复劳动与遗漏风险。
2. **存在性与有效性分离**。`CheckIdentitySignals` 只回答"有没有"（INFO），
   `CheckAuthentication` 回答"像不像样"（OBSERVE）；两者都不定案，
   动作统一由决策引擎输出（任务书 2.4）。
3. **证据最小化**。连凭据长度都只记分档不记精确值；scheme 截断；
   弱凭据判定只输出规则化 reason，不输出任何凭据片段。
4. **身份与计数维度分离，统一 HMAC-SHA256 加盐指纹**。身份只由凭据派生
   （CredentialKey），IP 回退仅限 TrackingKey 的进程内计数归并；指纹随运行时
   事件落库并支持管理面按身份过滤，故采用 HMAC-SHA256 截断 16 字节
   （`detectors.Fingerprint`），盐由 `identity_salt` 配置注入，缺盐降级为
   固定域分隔前缀并启动 Warn。样本哈希（`parser.BodyHash`）无跨系统关联
   需求，保持 FNV-1a 不变。
5. **匿名判定限 API 流量**。静态资源无凭据是常态，仅 API 流量产生
   `unauthenticated_api` 信号，避免噪音淹没事件中心。

## 七、当前实现范围与限制

- **画像表仅建表**。`api_identity_profiles` 无 Go 写入方与查询接口；
  画像聚合（request_count、首见/最近见）未实现；身份维度的运行时数据
  当前存在于运行时事件身份列与网关进程内存（滑窗键）中。
- **认证方式识别为粗粒度**。`AuthenticationType` 仅区分
  `bearer_or_basic` / `api_key` / `cookie_session`（cookie 仅识别存在性，
  不校验会话有效性）；任务书第三十五章的 JWT 结构识别、OAuth、
  HMAC 签名、mTLS 元数据未实现（scheme 白名单校验不等于 JWT 解析）。
- **无 Token 生命周期检测**。任务书三十五章的 Token 过期、跨应用、
  已吊销凭据继续访问等检测项仍未实现；其中「同凭据跨 IP 跳变」与「同凭据高并发」
  两项已落地（第二批，2026-08，网关 `envanomaly.go`）：`auth.credential_ip_spread`
  （同凭据滑窗 distinct IP≥3，OBSERVE/MEDIUM/+15，证据只含 distinct 数与窗口，
  IP 只以加盐指纹入集合）与 `auth.credential_concurrency`（同凭据并发 ≥8，
  OBSERVE/LOW/+10）；仅凭据维度（CredentialKey）聚合、匿名跳过，阈值经
  `credential_ip_spread_limit` / `credential_concurrency_limit` 配置，
  均为 OBSERVE 级信号只 AddMatch。CredentialKey / TrackingKey 的其余用途
  仍只服务身份标记与计数维度，不做其他异常判定。
- **认证命中全部 OBSERVE**。弱凭据/无凭据不产生阻断；`API Key 出现在 URL`
  的检测由敏感数据检测器以字段名规则覆盖（见 docs/API_SENSITIVE_DATA.md），
  而非身份检测器。
- **身份指纹已进运行时事件（身份微模型第一批，2026-08）**。迁移 000029 为
  `api_runtime_events` 增加 `identity_fingerprint`（仅凭据派生，匿名为空串，
  带 `WHERE identity_fingerprint <> ''` 部分索引）与 `auth_type` 两列；
  网关 `apievents.Record` 输出、apiruntime collector 解析落库，
  `GET /api/v1/api-security/runtime/events` 响应携带两字段并支持
  `identity_fingerprint` 查询参数精确过滤（空串/缺省不过滤）。

## 八、与任务书对应章节

- 第三十五章（API 身份与凭据模型）："保存指纹，不保存完整凭据"的落地；
  凭据缺失检测（`auth.unauthenticated_api`）；
- 2.4（统一决策）：检测器只 AddMatch；
- 7.1（数据最小化）：解析层脱敏与证据去敏；
- 第五十章：`api_identity_profiles` 表结构；`api_learning_samples.identity_fingerprint`。

Copyright © 聚信得仁
All Rights Reserved.
