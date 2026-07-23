# API 身份安全设计（阶段8 / WDSP）

## 一、目的与范围

本文档描述阶段8 API 身份与凭据安全能力：网关侧凭据存在性识别与认证有效性检测、
身份维度键（IdentityKey）的生成与用途、管理面身份画像表结构。核心原则贯穿全文：

**凭据明文不出解析层**——Authorization、Cookie、X-API-Key 的值在请求解析阶段即被
替换为 `[redacted]` 标记，下游检测器、事件、证据与数据库只接触"存在性"与
"不可逆指纹"，永不落明文。

覆盖代码：`gateway/dynamic_security/parser/parse.go`（脱敏）、
`gateway/dynamic_security/detectors/schema.go`（存在性指纹）、
`gateway/dynamic_security/detectors/authentication.go`（认证有效性 + IdentityKey）、
迁移 000018 `api_identity_profiles`。

## 二、架构与数据流

```text
HTTP 请求
  ▼
parser.ParseRequest（parse.go:58）
  │  头脱敏：authorization / cookie / x-api-key → "[redacted]"（parse.go:91-94）
  ▼
pipeline.Process（pipeline.go:43）
  ├─ detectors.CheckIdentitySignals（schema.go:59）
  │    凭据存在性 → ctx.AuthenticationType / TokenFingerprint / APIKeyFingerprint
  │    （"present" 标记，INFO 级 match，不参与决策）
  ├─ identity := detectors.IdentityKey(r)（authentication.go:163）
  │    原始请求头计算 FNV-1a 指纹（指纹不出网关进程）
  ├─ detectors.CheckAuthentication（authentication.go:27）
  │    scheme / 格式 / 弱凭据规则 → AddMatch（OBSERVE 类）
  └─ identity 供 behavior / api_ratelimit / resource_access 检测器做维度归并
  ▼
decision.Decide 统一决策 → 运行时主事件（Details 为已脱敏 DetectorMatch）
  ▼
管理面：api_identity_profiles（画像表，当前无写入方，见第七节）
```

## 三、凭据存在性指纹与认证有效性检测

### 3.1 存在性指纹（CheckIdentitySignals）

`gateway/dynamic_security/detectors/schema.go:59-80`：

- `authorization` 头存在（解析层已脱敏为 `[redacted]`）→
  `ctx.AuthenticationType = "bearer_or_basic"`、`ctx.TokenFingerprint = "present"`，
  并追加一条 INFO 级 match（`identity.token_present`）；
- `x-api-key` 头存在 → `ctx.APIKeyFingerprint = "present"`、
  `ctx.AuthenticationType = "api_key"`。

INFO 级 match 被决策引擎显式跳过（`decision/engine.go:54`），存在性记录只用于
上下文与事件明细，永远不抬高 FinalAction。

### 3.2 认证有效性规则（CheckAuthentication）

`gateway/dynamic_security/detectors/authentication.go:27-67`，只 AddMatch 不定案：

| 规则 ID | 触发条件 | 类别 / 严重度 | ScoreDelta |
|---------|----------|---------------|------------|
| `auth.unauthenticated_api` | 无 Authorization 且无 X-API-Key，且流量判定为 API | OBSERVE / MEDIUM | 10 |
| `auth.weak_credential` | X-API-Key 长度 < 8 | OBSERVE / LOW | 5 |
| `auth.malformed_credential` | Authorization 无法拆出 scheme/凭据两段，或 scheme 不受支持 | OBSERVE / MEDIUM | 10 |
| `auth.weak_credential` | 凭据为空、长度 < 8、字符集异常（详见 3.3） | OBSERVE / LOW | 5 |

匿名访问判定带 `isAPI` 门控：非 API 流量（静态资源等）无凭据属正常，不产生 match
（authentication.go:34-35）。所有命中均为 OBSERVE 类——认证有效性当前是观察信号，
不直接阻断。

### 3.3 Authorization 头校验顺序

`checkAuthorization`（authentication.go:70-132）按序判定，每头至多产出一条 match：

1. **结构**：按首个空格拆两段，失败 → `malformed_credential`
   （reason=`missing_scheme_or_credentials`）；
2. **scheme 白名单**：仅 `bearer` / `basic` / `digest`（大小写不敏感，
   正则 `reAuthScheme`，authentication.go:18），其余 → `malformed_credential`
   （reason=`unsupported_scheme`，scheme 截断 16 字符入证据，`clipScheme` 第 135 行）；
3. **空凭据**：`"Bearer "` 一类 → `weak_credential`（reason=`empty_token`）；
   实现特意传原始头值而非 TrimSpace 后的值，保证空 token 判弱凭据而非格式错误
   （authentication.go:49-50）；
4. **长度**：token < 8 字符 → `weak_credential`（reason=`too_short`）；
5. **字符集**：digest 凭据为 k=v 对列表，要求含 `=`（否则 `not_key_value_pairs`）；
   bearer/basic 要求 Base64 系字符集 `^[A-Za-z0-9._~+/=-]+$`（含 JWT 分段点与
   URL-safe 变体，`reTokenBase64ish` 第 20 行），不符 → `not_base64ish`。

### 3.4 证据去敏

Evidence 只含三类信息（authentication.go:15-16）：

- `header` 名（authorization / x-api-key）；
- `scheme`（截断 16 字符）；
- `length_bucket` 长度分档：`0` / `1-7` / `8-15` / `16-31` / `32-63` / `64+`
  （`lengthBucket`，authentication.go:144-159）——连精确长度都不记录，进一步去敏。

## 四、IdentityKey：身份维度键

`IdentityKey`（authentication.go:163-181）为 behavior / ratelimit / resource
检测器提供统一身份维度，优先级：

```text
Authorization 头存在 → "auth:" + FNV-1a(原始头值)
X-API-Key 头存在    → "key:"  + FNV-1a(原始头值)
否则                → "ip:"   + RemoteAddr 主机部分（net.SplitHostPort）
兜底                → "unknown"
```

- 指纹算法 FNV-1a 64 位、十六进制输出（authentication.go:184-188），轻量非加密用途，
  与 `parser.BodyHash` 同族；不可逆，明文凭据不出该函数作用域。
- 指纹优先于 IP：同一凭据跨 IP 调用仍归并到同一身份维度；无凭据时回退 IP 维度。
- 该键只在网关进程内存中作为计数维度使用（滑窗 / 对象游标）。管理面
  `api_learning_samples.identity_fingerprint` 列（迁移 000018 第 112 行）为同一
  口径的预留字段——样本表当前同样无写入方，仅有 `ListLearningSamples` 读接口
  （`server/internal/apiassets/store.go:743`）；运行时主事件
  （`apiruntime.Record`）当前不携带身份字段。

## 五、api_identity_profiles 画像结构

迁移 000018 第 230-239 行：

| 列 | 说明 |
|----|------|
| `identity_fingerprint` | 身份指纹（VARCHAR(128)，非明文） |
| `endpoint_id` | 端点，FK 级联删除 |
| `auth_type` | 认证方式（bearer / api_key 等） |
| `request_count` | 累计请求数 |
| `first_seen_at` / `last_seen_at` | 首见 / 最近见时间 |

约束：`UNIQUE (identity_fingerprint, endpoint_id)`——画像按"身份 × 端点"聚合，
对应任务书第三十五章"保存指纹，不保存完整凭据"。

## 六、关键设计决策

1. **解析层一次性脱敏**。凭据替换为 `[redacted]` 发生在 `ParseRequest`
   （parse.go:91-94），之后所有检测器物理上接触不到明文；这是唯一脱敏点，
   不存在"下游再脱敏"的重复劳动与遗漏风险。
2. **存在性与有效性分离**。`CheckIdentitySignals` 只回答"有没有"（INFO），
   `CheckAuthentication` 回答"像不像样"（OBSERVE）；两者都不定案，
   动作统一由决策引擎输出（任务书 2.4）。
3. **证据最小化**。连凭据长度都只记分档不记精确值；scheme 截断；
   弱凭据判定只输出规则化 reason，不输出任何凭据片段。
4. **FNV-1a 指纹而非加密哈希**。身份键用途是进程内计数归并，不需要抗碰撞
   安全强度；FNV-1a 零依赖、无密钥管理负担，且与解析层 BodyHash 保持同族
   一致性。不可逆性满足"不落明文"要求，但不应用于跨系统身份关联。
5. **匿名判定限 API 流量**。静态资源无凭据是常态，仅 API 流量产生
   `unauthenticated_api` 信号，避免噪音淹没事件中心。

## 七、当前实现范围与限制

- **画像表仅建表**。`api_identity_profiles` 无 Go 写入方与查询接口；
  身份维度的运行时数据当前只存在于网关进程内存（滑窗键）与事件明细中，
  画像聚合（request_count、首见/最近见）未实现。
- **认证方式识别为粗粒度**。`AuthenticationType` 仅区分
  `bearer_or_basic` / `api_key`；任务书第三十五章的 JWT 结构识别、OAuth、
  HMAC 签名、mTLS 元数据未实现（scheme 白名单校验不等于 JWT 解析）。
- **无 Token 生命周期检测**。任务书三十五章的 Token 过期、跨应用、跨 IP 异常、
  已吊销凭据继续访问、同凭据高并发/多设备等检测项均未实现；IdentityKey
  当前只服务计数维度，不做异常判定。
- **认证命中全部 OBSERVE**。弱凭据/无凭据不产生阻断；`API Key 出现在 URL`
  的检测由敏感数据检测器以字段名规则覆盖（见 docs/API_SENSITIVE_DATA.md），
  而非身份检测器。
- **身份指纹不进运行时事件**。`apiruntime.Record` 无身份字段，管理面无法
  按身份回溯事件；该字段目前仅在检测器维度键与学习样本预留列中存在。

## 八、与任务书对应章节

- 第三十五章（API 身份与凭据模型）："保存指纹，不保存完整凭据"的落地；
  凭据缺失检测（`auth.unauthenticated_api`）；
- 2.4（统一决策）：检测器只 AddMatch；
- 7.1（数据最小化）：解析层脱敏与证据去敏；
- 第五十章：`api_identity_profiles` 表结构；`api_learning_samples.identity_fingerprint`。

Copyright © 聚信得仁
All Rights Reserved.
