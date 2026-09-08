# API 身份与授权安全设计（阶段8 / WDSP，补全任务书 §228 口径）

## 一、目的与范围

本文档描述 API 安全域的身份与授权能力现状：统一身份指纹方案（HMAC/盐/降级）、
认证识别规则、Identity Profile 生产线、访问环境异常检测，以及授权侧（BOLA 辅助信号）
的真实落地边界。BFLA（功能级授权）与字段权限（Mass Assignment）**整体未实现**，
如实标注为后续迭代项（见第七节）。

贯穿全文的核心纪律（与 docs/API_IDENTITY_SECURITY.md 一致）：

**凭据明文不出解析层**——Authorization、Cookie、X-API-Key 的值在请求解析阶段即被
替换为 `[redacted]` 标记，下游检测器、事件、证据与数据库只接触"存在性"与
"不可逆指纹"，永不落明文；IP 属环境维度，不得冒充身份（docs/API_MICRO_MODELS.md §2.2）。

覆盖代码：`gateway/dynamic_security/detectors/fingerprint.go`（统一加盐指纹）、
`gateway/dynamic_security/detectors/authentication.go`（认证有效性 + CredentialKey/TrackingKey）、
`gateway/dynamic_security/detectors/envanomaly.go`（同凭据环境异常）、
`gateway/dynamic_security/detectors/resource.go`（BOLA 辅助信号）、
`server/internal/aggregations/identity.go`（画像聚合）、
`server/internal/apisecurity/identity.go`（画像只读 API + 质量分/风险评估）、
迁移 000018（`api_identity_profiles`/`api_object_models`）、000029（事件身份列）、
000035（事件审计列）、000038（学习身份多样性条件）。

## 二、身份指纹方案

### 2.1 统一指纹算法（Fingerprint）

`gateway/dynamic_security/detectors/fingerprint.go:17-25`：

- 算法：`HMAC-SHA256(key=salt, value)`，截断前 16 字节，hex 输出（32 字符）；
- 单向不可逆、跨请求/跨表可关联；凭据明文不出调用函数作用域；
- 所有身份/来源指纹共用一个实现：身份指纹（`CredentialKey`）、来源指纹
  （客户端 IP 指纹）、参数值观测哈希以外的全部"可关联但不可见值"场景。

### 2.2 盐与降级

- 盐取自网关配置 `identity_salt`；API 安全补全第一批起，`identity_salt` 可经管理面
  发布通道下发（`system_settings` 组 `gateway_runtime` → GuardConfig 同名字段，
  见 `server/internal/guardconfig/apiruntime.go:64`），不再是只能手改 Caddy JSON 的隐藏开关；
- **缺盐降级**：盐为空时以固定域分隔前缀 `jiuzhang/wdsp-identity-fingerprint/v1`
  作为 HMAC key（fingerprint.go:9-12）。此时指纹未加盐，仅保证与其他用途的域分隔，
  跨部署可复现、**不具备抗彩虹表能力**；网关在 Provision 时对缺盐给出 Warn 启动日志。
  生产部署必须配置 `identity_salt`。

### 2.3 身份键与计数键分离（CredentialKey / TrackingKey）

`authentication.go:279-317`：

| 键 | 派生来源 | 匿名单值 | 用途 |
|----|----------|----------|------|
| `CredentialKey` | 仅凭据：`auth:`+指纹（Authorization）/ `key:`+指纹（X-API-Key）/ `sess:`+指纹（Cookie 整头），优先级依次递减 | 空串 | 身份维度：事件 `identity_fingerprint`、画像、环境异常聚合 |
| `TrackingKey` | 凭据指纹优先；无凭据回退 `ip:`+客户端 IP | `ip:` 回退 | 仅供 behavior / api_ratelimit / resource 检测器滑窗与游标计数（避免匿名流量并入同一桶），**不得**作为身份指纹输出到事件或画像 |

已知边界：`sess:` 指纹对整个 Cookie 头哈希，会话轮换（Set-Cookie 更换）即产生新身份；
匿名流量无身份维度数据（设计取舍，宁缺毋假）。

## 三、认证识别现状

### 3.1 存在性信号（CheckIdentitySignals）

`detectors/schema.go`：解析层脱敏后按头的存在性置位——`authorization` →
`AuthenticationType=bearer_or_basic`；`x-api-key` → `api_key`；`cookie` →
`cookie_session`（优先级最低，不覆盖前两者），并追加 INFO 级 match
（`identity.token_present` / `identity.cookie_present`）。INFO 级 match 被决策引擎
显式跳过，只作上下文与事件明细，永不抬高 FinalAction。

### 3.2 认证有效性规则（CheckAuthentication）

`authentication.go:28-68` 及 `checkAuthorization`，只 AddMatch 不定案：

| 规则 ID | 触发条件 | 类别 / 严重度 |
|---------|----------|---------------|
| `auth.unauthenticated_api` | 无 Authorization 且无 X-API-Key，且流量判定为 API | OBSERVE / MEDIUM |
| `auth.malformed_credential` | Authorization 无法拆出 scheme/凭据两段，或 scheme 非 bearer/basic/digest | OBSERVE / MEDIUM |
| `auth.weak_credential` | 凭据为空 / 长度 < 8 / 字符集异常 / X-API-Key 过短（证据只含长度分档） | OBSERVE / LOW |
| `auth.jwt_malformed_header` | Bearer JWT header 不可解码/非 JSON | OBSERVE / LOW |
| `auth.jwt_alg_none` | JWT alg 为 none 或空 | OBSERVE / HIGH |
| `auth.jwt_kid_traversal` | JWT kid 含 `../`、`file:`、`/etc/` 形态 | OBSERVE / HIGH |
| `auth.jwt_empty_signature` | JWT 签名段为空 | OBSERVE / MEDIUM |
| `auth.jwt_expired` | JWT exp 已过期（不验签，仅结构级信号） | OBSERVE / MEDIUM |

JWT 检查为结构级：只解 header/claims 的 alg/exp/kid 形态，**不做签名校验**、
不把 sub/email 等写入证据（authentication.go:140-238）。

### 3.3 未识别的认证形态（后续迭代）

- OAuth 2.0 / OIDC 流程识别、HMAC 签名认证、mTLS 客户端证书、自定义认证头：
  当前均归入 `bearer_or_basic` 或匿名，无专项识别；
- Token 跨应用复用检测、已吊销凭据继续使用检测：未实现（无吊销清单数据源）；
- 认证覆盖率约 1/3 的判断详见 docs/API_SECURITY_CURRENT_STATE.md P0-14。

## 四、Identity Profile 生产线

```text
api_runtime_events（identity_fingerprint 非空，近 24h 窗口）
  ▼ aggregations.RunIdentityProfiles（aggregations/identity.go:16，小时级调度）
按 (identity_fingerprint × endpoint_id × auth_type) 聚合
  ▼ UPSERT api_identity_profiles（匿名事件不写画像）
  ▼ 只读 API：GET /api/v1/api-security/identity-profiles（列表 + quality_score）
              GET .../identity-profiles/{fingerprint}/detail（详情 + 风险评估）
  ▼ 前端：/api-identity-profiles 页面
```

- 表结构（迁移 000018）：fingerprint / endpoint_id / auth_type / request_count /
  first_seen_at / last_seen_at；合并语义：request_count 窗口重算覆盖、
  first_seen 取 LEAST、last_seen 取 GREATEST（identity.go:70-77）；
- 质量分 `identityQualityScore`（apisecurity/identity.go:283）：0-100，越高越
  "像正常稳定身份"；详情接口带风险评估（risky_events_total / max_risk_score 等，
  apisecurity/identity.go:139-255）；
- 任务书 §68 画像字段覆盖窄：roles / devices / ips / apis / objects /
  normal_time_ranges / normal_request_rate / risk_score 均无持久化字段，为后续迭代项。

## 五、访问环境异常检测

`detectors/envanomaly.go`（访问微模型·环境维度，账号接管 ATO 主要检出面），
全部 OBSERVE 级、只 AddMatch，动作由统一决策输出；匿名流量直接跳过；证据不含任何
IP/凭据（明文或指纹）：

| 规则 ID | 语义 | 默认阈值 | 可配键（gateway_runtime 组） |
|---------|------|----------|------------------------------|
| `auth.credential_ip_spread` | 同凭据滑窗 distinct 来源 IP 达阈值（IP 以加盐指纹入集合） | 3 | `credential_ip_spread_limit` |
| `auth.credential_concurrency` | 同凭据并发 in-flight 达阈值 | 8 | `credential_concurrency_limit` |
| `auth.credential_unusual_hour` | 同凭据非常规访问小时（历史时段基线） | — | — |
| `auth.credential_ua_change` | 同凭据 UA 族突变 | — | — |
| `auth.env_anomaly_stack` | 同请求多环境异常信号叠加升档 | — | — |

两个阈值键自 API 安全补全第一批起可经发布通道下发（此前只能手改 Caddy JSON）。
计数存储默认进程内 LRU（定容 10000 键，单窗 distinct IP 集合上限 1024 防 botnet
泛洪撑爆内存）；滑窗类状态可经 `behavior_store=valkey` 切换为跨节点共享
（见 docs/API_BEHAVIOR_DISTRIBUTED_STATE.md 口径与 P0-18 现状）。

## 六、授权辅助信号现状（BOLA）

### 6.1 已落地：辅助信号（非越权认定）

`detectors/resource.go`（详见 docs/API_AUTHORIZATION_ANALYSIS.md）：

- 对象标识来源：归一化路径对象段（`{id}`/`{uuid}`/`{hex}`，逐段提取）、
  Query 参数值形态识别、BODY 字段经参数模型 `semantic_type` 联动；
- 规则：无凭据 + 对象标识 → `resource.unauthenticated_object_access`（OBSERVE/MEDIUM）；
  连续数字 ID + 写方法 → 升档 BLOCK/HIGH（进程内 LRU 游标，可注入 Valkey）；
- 纪律：不得仅因访问不同对象 ID 就直接确认 BOLA——当前输出供统一决策与人工研判。

### 6.2 未落地：Ownership 实体关系（后续迭代）

- `api_object_models`（000018）仍无生产写入方（TABLE_ONLY）；
- 无 Identity→ObjectType→ObjectID→Owner→Tenant 任何实体表与写入链；
- 对象候选来源缺响应字段、前后 API 关系、人工标注三条通路；
- 结论分级词表（POLICY_CONFIRMED / HIGH_CONFIDENCE / LIKELY / POSSIBLE /
  INSUFFICIENT_EVIDENCE）在代码中不存在；
- 现状评价：信号方向正确、基线没有（docs/API_SECURITY_CURRENT_STATE.md P0-15）。

## 七、整体未实现项（后续迭代，如实标注)

| 能力 | 任务书条目 | 现状 |
|------|-----------|------|
| BFLA 功能级授权基线 | P0-16 | NOT_IMPLEMENTED：无 Role 概念、无 Role→BusinessFunction→API→Method→Action 基线表、无运行时检测；PURPOSE=ADMIN 分类标签未下发网关未接检测 |
| 字段权限 / Mass Assignment | P0-17 | NOT_IMPLEMENTED：无 `api_field_permissions` 表；READABLE/WRITABLE 等词汇不存在；最近邻信号仅为 schema 结构符合性（undefined_field/type_mismatch/missing_field），无角色×字段可写性语义 |
| Token 跨应用 / 已吊销凭据 | 任务书 §67 | 未实现 |
| 画像字段扩展（§68 全量） | P0-14 | 部分：见第四节缺口 |

## 八、与任务书对应章节

- 补全任务书 §228（身份权限文档口径）：本文档；
- 任务书 §65-68（身份检测/指纹/画像字段）：第二~四节；
- 任务书 §4.7 与第四十章（BOLA 辅助纪律）：第六节；
- 现状盘点：docs/API_SECURITY_CURRENT_STATE.md P0-14 / P0-15 / P0-16 / P0-17；
- 相邻文档：docs/API_IDENTITY_SECURITY.md（凭据存在性与认证有效性细粒度规则）、
  docs/API_AUTHORIZATION_ANALYSIS.md（BOLA 辅助信号实现细节）、
  docs/API_MICRO_MODELS.md（三微模型统一维度框架）。
