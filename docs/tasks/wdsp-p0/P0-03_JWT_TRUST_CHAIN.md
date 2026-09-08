# P0-03：业务 JWT 信任链与身份标识开发任务书

日期：2026-09-06。状态：待实施。优先级：产品 P0。

前置：[总纲](README.md)、[证据契约](P0-01_CAPABILITY_EVIDENCE.md)。身份结果需接入 [P0-04 最终处置](P0-04_DECISION_SCOPED_EXCEPTIONS.md)。

## 1. 问题与目标

当前业务 JWT 有结构级识别和身份关联线索，不能因此视为已建立签名、issuer、audience 和密钥轮换的完整信任链。本任务针对经过 WDSP 的**业务请求 JWT**，不是替换管理后台登录认证，也不把可信身份等同于业务对象授权。

目标：增加按应用配置、默认关闭的 JWT 验证策略；可信声明只能来自验证成功的 Token；故障、过期、轮换和缓存行为可预测；现有身份键与历史数据兼容。

算法与密钥绑定、issuer/audience 校验须遵守 JWT 安全最佳实践，避免信任 Token 自带的算法/密钥地址。[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) 是技术依据。时间和 audience 等声明按 [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html) 解释；本任务要求存在 exp/iss/aud/sub 和 kid 属于产品接入约束，不声称 RFC 对所有 JWT 都强制这些字段。

## 2. 现有代码与集成位置

| 现有位置 | 现状/使用方式 |
|---|---|
| `gateway/dynamic_security/detectors/authentication.go` | `checkJWTStructure` 做结构识别，注释明确不验签、仅 OBSERVE |
| `gateway/modules/jiuzhang_guard/identitybehavior/identity.go` | 现有 Credential、未验证声明关联、HMAC identity_key；不能把 JWTSubject 直接变为可信主体 |
| `gateway/modules/jiuzhang_guard/identitybehavior/engine.go` | 身份行为 Begin/End，异常 fail-open |
| `gateway/modules/jiuzhang_guard/module.go` | 请求顺序和身份/API 管线挂接点 |
| `gateway/dynamic_security/context/context.go`、`decision/engine.go` | 传递结构化结果，保持 API 决策语义 |
| `server/internal/guardconfig/identity_behavior.go`、`apiruntime.go` | 现有配置供应链；观测配置错误的降级不可照搬给 JWT PROTECT |
| `server/internal/gatewayconfig/` | 复用编译、发布、有效版本、节点回执与回退 |
| `server/internal/validation/domain.go`、`gatewayconfig/caddyclient.go` | SSRF/DNS 复查设计参考；内部网关管理地址策略不等于外部 JWKS 策略 |
| `server/internal/app/app.go`、`server/openapi/fragments/CONTRACT.md` | 真实依赖接线、路由/权限与 OpenAPI 约束 |

新增包建议：`server/internal/jwttrust/` 与 `gateway/dynamic_security/jwtverify/`。它们是**待创建路径**。网关不能跨 Go 模块导入 server 的 internal 包；共用逻辑需按现有模块边界放置并测试。

## 3. 最小产品范围

- 按应用管理 JWT trust policy，支持 OFF / OBSERVE / PROTECT，默认 OFF。
- 仅支持 Authorization 中的单个 Bearer JWT；不从 URL、Cookie、请求正文自动提取 Token。
- 支持 RS256、ES256，显式算法白名单；拒绝 none、HS 系列和算法/密钥类型不匹配。本轮不支持 JWE、Token introspection、登录签发、刷新 Token 或业务权限判定。
- 两种密钥来源：上传配置的静态公钥 JWKS，或管理员配置的 HTTPS JWKS 地址。离线部署可只用静态公钥。
- 验证一次并向检测、身份和事件传递结构化结果；不向源站注入“可信用户”请求头。
- 需要的后端、网关、页面、迁移、权限、审计、测试、发布回执必须一起完成；只有验证函数不算交付。

## 4. 配置与管理接口契约（新增约定）

### 4.1 策略字段

| 字段 | 契约 |
|---|---|
| `application_id`、`version` | 服务端绑定应用；不可变策略版本；修改须防并发覆盖 |
| `mode` | OFF / OBSERVE / PROTECT；默认 OFF |
| `selectors` | 必填非空（OFF 可空）；每项包含 methods、path_exact 或 path_prefix，以及 token_required |
| `issuers` | 初始最多 8 项；每项 issuer 精确值唯一，包含 audiences、algorithms 和 key_source |
| `audiences` | 非空字符串集合；Token 的 aud 字符串/数组与配置至少匹配一项 |
| `algorithms` | RS256 / ES256 的非空子集；不由 Token 扩展白名单 |
| `key_source` | STATIC_JWKS / REMOTE_JWKS；二选一，静态仅公钥，远程仅预配置 HTTPS URL |
| `clock_skew_seconds` | 建议默认 30，范围 0～120；前后端一致 |
| `tenant_claim` | 可选、管理员选定的单一受信声明名；只在 VERIFIED 后读取；不自动猜测 tenant 字段 |
| `reason` | 非空变更理由，进入操作审计 |

方法转大写并去重；path 仅按网关已确定的请求路径规范匹配，排除 query，禁止另一套隐式 URL 解码。prefix 必须按完整路径段匹配，例如 `/api` 匹配 `/api` 与 `/api/orders`，不匹配 `/apix`。不同 selector 匹配采用 OR；有重叠时 token_required 取 true 优先。所有 issuer 校验使用大小写敏感精确值，不擅自去掉路径或末尾斜杠。

OFF 不校验 Token，也不产生 VERIFIED 主体。未命中 selector 的请求维持原行为，并标记校验范围外；不能宣传为全应用 JWT 强制防护。PROTECT 要求应用 API 动态管线启用且为 PROTECT，并且所有目标网关支持配置版本，否则拒绝发布。防止外层 OBSERVE 把 JWT 强制策略静默降级。

### 4.2 新增 API

以下路径是本任务待实现接口，不是当前已有 API：

| 方法与路径 | 权限 | 结果 |
|---|---|---|
| `GET /api/v1/applications/{id}/jwt-trust-policy` | `jwt_trust.read` | 草稿、已发布/已生效版本、状态摘要；不含业务 Token |
| `PUT /api/v1/applications/{id}/jwt-trust-policy` | `jwt_trust.manage` | 校验并保存草稿；携带 expected_version，冲突 409 |
| `POST /api/v1/applications/{id}/jwt-trust-policy/preflight` | `jwt_trust.manage` | 检查草稿结构、公钥、目标节点能力及受限连通性；不自动发布 |

路径权限沿用项目角色模型：安全配置管理角色拥有 manage，只读审计角色可按现有策略获得 read；不能因为系统管理员能改系统设置就自动获得所有安全策略写权限。不存在的应用 404、无权限按现有错误约定、字段错误 400/422 选择仓库统一规范并冻结。列表/读取须执行应用范围校验。

数据库新增策略与不可变版本记录，或扩展现有策略版本表；先检查迁移编号，不能猜测。初始配置 OFF，不改变既有流量。保存、预检、发布、失败、回退均进入操作审计；记录字段差异摘要，不保存 Token。

继续使用现有配置发布流程，不新增绕过审核的直接推送端点。OpenAPI 按 fragments/CONTRACT.md 编写，片段路径不重复 `/api/v1` 前缀，并同步生成文件。

## 5. 验证结果与身份契约（新增约定）

建议定义不可变 `VerificationResult`，至少有：

```text
status: NOT_PRESENT | UNVERIFIED | VERIFIED | INVALID | UNAVAILABLE
reason_code: 固定枚举，不含原始 Token 或声明
policy_version, issuer_config_id, keyset_version
verified_principal_id: 仅 VERIFIED 可非空
verified_tenant_id: 仅 VERIFIED 且配置声明验证成功时可非空
evaluated_at, enforce_action
```

推荐 reason_code：POLICY_OFF、OUT_OF_SCOPE、MISSING_TOKEN、MALFORMED_TOKEN、ALGORITHM_REJECTED、UNKNOWN_ISSUER、UNKNOWN_KID、SIGNATURE_INVALID、ISSUER_MISMATCH、AUDIENCE_MISMATCH、EXPIRED、NOT_YET_VALID、CLAIM_INVALID、KEYSET_UNAVAILABLE、VERIFIER_ERROR、VALID。接口与事件共享枚举，其他错误映射成固定内部错误类型。

`NOT_PRESENT` 表示范围内未发现 Bearer；`UNVERIFIED` 表示策略关闭或不在范围；`INVALID` 表示根据可用信任配置明确不合法；`UNAVAILABLE` 表示缺可用密钥或验证基础设施异常，不能推出 Token 有效/无效。

### 5.1 可信身份

1. `verified_principal_id` 为应用隔离的 HMAC 指纹，输入包含带长度编码的 application_id、精确 issuer、sub；配置 tenant_claim 时加入可信 tenant 值。避免简单字符串拼接歧义。
2. 使用部署提供的专用非空密钥或现有合规密钥派生机制，不能使用固定默认盐。缺密钥时禁止启用可信身份功能并阻止相关 PROTECT 配置发布。
3. 同应用、同 issuer、同 sub 的正常 Token 刷新可得到相同主体；不同应用、issuer 或 tenant 不得碰撞。密钥轮换带 key_version；不在本项自动合并历史主体和风险计数。
4. 保留原 `identity_key` 与 `identity_type` 枚举及其含义。新增字段不能把 APPLICATION/SERVICE 等改写成 HUMAN，也不能因未验证 sub 相同合并可信主体。
5. 验证通过只证明所配置发行方签发了 Token，**不证明主体有权访问某对象**。BOLA/角色分析需要独立业务授权真值；不得基于 JWT VERIFIED 直接放行其他检测。
6. 事件保存验证状态、原因、策略/密钥版本和主体指纹，不落原始 Token、完整 payload、明文 sub/tenant。监控维度不得使用无界 kid、sub 或 Token 字符串。

### 5.2 解析与验证

初始限制：Token ≤ 16 KiB，kid ≤ 256 字节，单份 JWKS ≤ 256 KiB 且 ≤ 32 个公钥；这些是可测试的产品限制。

- 拒绝重复 Authorization、多 Token、错误 Bearer 格式、JWT 段数错误、重复 JSON 键、超限字段、未知 critical header 和不支持的签名格式。
- kid 必须非空；拒绝同一 issuer 的重复 kid。kid 仅作缓存内键查找，不能拼接路径、SQL 或 URL。
- 选择 issuer 时可以读取未验证 iss 作为**有限配置集合中的索引**，但在签名验证后必须再次验证其精确值；不能据此访问任意网络。
- 必须验证签名、算法/公钥绑定、issuer、audience、exp、nbf（存在时）及 sub。exp/nbf 采用库支持的 NumericDate 严格解析，不能字符串弱转换、整数溢出或吞解析错误。
- `now >= exp + leeway` 视为过期；`now + leeway < nbf` 视为未生效。sub 必须非空且长度有界，aud 类型仅合法字符串或非空字符串数组。
- RSA 公钥至少 2048 位；ES256 使用 P-256。静态 JWKS 拒绝私钥参数和对称密钥；不从 x5u/jku 下载证书或密钥。不实现自研签名算法。
- 使用锁定且经过依赖安全检查的 JOSE 库；仓库已有间接依赖不代表其版本可直接升级为受信核心依赖。

## 6. JWKS 网络、缓存和轮换

### 6.1 网络边界

只允许配置中的 HTTPS 地址；禁用跳转及环境代理继承，使用受控 CA 验证，禁止 insecureSkipVerify。超时建议 2 秒，限制响应字节、解压后大小、并发数和刷新频率。

默认拒绝回环、私有、链路本地、组播、保留及云元数据地址。确需企业内网 IdP 时，由有权限的管理员显式登记目标主机及允许 CIDR；仍禁止云元数据和链路本地地址，且不得允许任意私网通配。保存时校验，实际拨号时再次解析并验证所有候选地址，绑定已验证地址拨号，防止 DNS 重绑定；TLS ServerName 保持配置主机。

预检与运行时使用同等 SSRF 规则。管理端可达不代表网关可达，页面必须区分预检结果和各节点实际密钥状态。网关热路径不发 HTTP、DNS 或数据库请求。

### 6.2 缓存契约

建议默认：后台每 5 分钟刷新，成功获取的密钥集最长信任 15 分钟，额外 stale 宽限为 0。静态公钥随已发布策略生效，不按远程 TTL 自动失效。

使用不可变快照与原子替换。成功刷新后以新集合完全替换旧集合，已删除的 key 立即不再用于新请求；不能通过旧缓存续用已撤回公钥。失败刷新不延长最后成功时间。

远程故障但缓存仍在信任期内时，可以用缓存完成完整签名校验并返回 VERIFIED；超过硬到期或冷启动无可用集合时返回 UNAVAILABLE。不能仅凭“以前请求验过”跨 Token 或跨过期时间复用通过结果。

对于有效缓存内未知 kid，当前请求返回 INVALID/UNKNOWN_KID，并异步触发受限刷新；无可用缓存时返回 UNAVAILABLE。按 issuer 做 singleflight、刷新冷却（建议至少 30 秒）和有界负缓存，禁止攻击者用随机 kid 导致请求级联网或无限内存增长。上游应在开始签发新 kid 前公布公钥；页面/接入文档明确这个轮换条件。

并发请求读取同一代快照；配置切换、节点重启和回退不得混用不同 issuer 的缓存。时钟前后跳场景要测试，缓存年龄尽量使用单调时钟；JWT 声明使用经同步的墙钟，异常有状态提示。

## 7. 请求顺序与故障处置

真实 IP 处理后、身份观测前可执行一次本地验证，供观测使用；此时仅计算结果。强制处置在现有 API 动态管线阶段执行，保持人工封禁、访问控制、配额和 CC 的既有顺序。

身份观测关闭或 recover 不能跳过 JWT 验证/执行。JWT 模块异常须形成 VERIFIER_ERROR/UNAVAILABLE，并按以下规则处理，不能经过一般 OBSERVE 的 fail-open 分支无条件放行。

| 场景 | OBSERVE | PROTECT |
|---|---|---|
| 未命中 selector 或 OFF | 保持原行为，无可信主体 | 保持原行为；明确范围外 |
| selector 内未携带 Bearer，token_required=false | 允许，NOT_PRESENT | 允许，NOT_PRESENT |
| selector 内缺少必需 Bearer | 允许并记录 MISSING_TOKEN | 401，认证失败事件 |
| 提供 Bearer 且 INVALID | 允许并记录，不产生可信主体 | 401，认证失败事件 |
| 提供 Bearer 且 UNAVAILABLE | 允许并记录，不产生可信主体 | 503，验证服务不可用事件 |
| VERIFIED | 继续后续检测 | 继续后续检测，不绕过其他防护 |

对外 401 采用统一简短文案与规范的 Bearer challenge，不回显详细签名/发行方内部错误；详细固定 reason_code 仅给有权限的管理端。503 不伪装成 Token 错误，避免诱导用户反复登录。

策略保存成功但发布失败时保留旧有效版本；已存在 PROTECT 策略加载失败不能静默删除。新配置激活前校验依赖并原子切换；明确报告部分节点失败和旧版本仍在运行。

## 8. UI / UX 与事件

复用应用配置入口，新增“JWT 信任策略”页签或面板；实现前读取项目 UI/UX 规范。必须显示应用范围、模式、路径/方法、Token 是否必需、issuer/audience、密钥来源、轮换说明、草稿与生效版本、节点状态。

- 用户保存后显示“草稿已保存”，发布并获节点回执后才显示生效。
- 展示“未配置、观察中、强制验证、密钥将过期、密钥不可用、部分节点未生效”等可区分状态。
- 静态 JWKS 只接收公钥；提交私钥立即拒绝并避免回显。无需提供粘贴真实业务 Token 的在线调试框。
- 事件详情增加“JWT 验证状态、原因、可信主体指纹、策略版本”，保留历史无此字段的空态；不将 UNVERIFIED 显示成“非法用户”。
- 保留已有安全事件到 APM Trace 的关联；无探针、未采样、无权限时分别说明。

## 9. 实施步骤

1. 核对现有身份契约和配置链，定义 DTO/枚举/迁移/OpenAPI，冻结版本和字段兼容规则。
2. 先编写签名、claims、算法混淆与状态表失败测试，实现纯本地 verifier。
3. 实现受限 JWKS 获取、缓存、轮换及故障测试；确保热路径没有网络 IO。
4. 将验证结果接入 guard、身份和 API 执行层，验证请求顺序、白名单和观察模块独立性。
5. 实现后端配置/权限/审计、真实发布、节点状态和前端操作；补集成和 E2E。
6. 完成回退与旧数据兼容验证，更新能力清单并把 JWT 配对基准加入 P0-02。

## 10. 必须通过的验收用例

| ID | 条件 | 预期 |
|---|---|---|
| JWT-01 | 合法 RS256/ES256，正确 iss/aud/exp/sub | VERIFIED，可信主体稳定，继续其他防护 |
| JWT-02 | 伪造签名、none、HS 混淆、错误曲线/短 RSA | INVALID，PROTECT 401，OBSERVE 不产生可信主体 |
| JWT-03 | 错误/缺失 iss/aud/sub/exp，aud 字符串/数组 | 严格符合声明契约，不发生弱类型通过 |
| JWT-04 | exp/nbf 恰好边界、leeway、时钟跳变 | 边界符合第 5 节；无永久有效缓存 |
| JWT-05 | Token 格式错误/超长/重复 JSON 键/重复 Authorization | 有界拒绝，无 panic、无解析歧义 |
| JWT-06 | 未签名声明含伪造 sub/tenant、多个应用相同 sub | 不污染可信主体；跨应用/issuer/tenant 隔离 |
| JWT-07 | 新旧公钥重叠轮换、删除旧 key、未知 kid 洪泛 | 轮换可用；删除后新请求不再信任旧 key；刷新与内存有界 |
| JWT-08 | JWKS 失败但缓存未过期、硬过期、冷启动 | 分别本地验签、UNAVAILABLE、UNAVAILABLE；符合模式动作表 |
| JWT-09 | jku/x5u、跳转、DNS 重绑定、IPv6/元数据/代理 | 不访问 Token 指定地址；受限拨号和响应大小防护有效 |
| JWT-10 | OFF、范围外、optional/required、观察/保护组合 | 与第 7 节逐项一致；发布拒绝冲突模式 |
| JWT-11 | 身份观测关闭/异常、白名单/L7 allow、人工封禁 | JWT 按链路执行且不被白名单绕过；人工封禁仍优先 |
| JWT-12 | 已有 API/WAF 攻击与 VERIFIED JWT 同时出现 | JWT 不产生全局放行；最终处置可关联 |
| JWT-13 | 未授权角色、跨应用访问、并发编辑 | 拒绝越权；409 防覆盖；审计无 Token |
| JWT-14 | 保存草稿、发布失败/部分失败、回退/旧节点 | 有效版本正确；不静默关闭原 PROTECT；旧节点不接受未知强制语义 |
| JWT-15 | 页面新建→预检→发布→事件→回退 | 真实接口和网关可验证，状态与权限正确 |
| JWT-16 | 高并发验证、缓存更换、race、异常恢复 | 无数据竞争/泄漏/无界标签；热路径零网络 IO |
| JWT-17 | 旧事件、旧 identity_key、现有风险策略与 APM 关联 | 兼容；不自动迁移/合并身份或错误推断授权 |
| JWT-18 | P0-02 同配置启用/关闭 JWT 配对实验 | 真实记录延迟、CPU、事件开销；不虚构性能结果 |

JWT-01～12、16 需单元与真实网关组合验证；JWT-13～15 需接口/E2E；JWT-18 在基准环境完成。使用本地生成的专用测试密钥，不引用生产凭据。

## 11. 迁移、回退与完成定义

迁移以新增可空字段/新表为主，旧应用默认 OFF；历史事件显示“当时未记录”，不能回填为 VERIFIED。回退配置须走真实发布，保留审计；静态/远程密钥集不能在回退时跨 issuer 串用。

含 PROTECT 配置的系统回退到不支持 JWT 验证的旧二进制前，必须显式处理不兼容策略并提示防护变化；不能把未知字段忽略当作安全回退。数据库破坏性降级前导出不含敏感信息的策略版本，禁止自动删除用户配置。

完成条件：配置、运行时验证、可信身份、实际执行、事件、UI、权限、审计、回退全部接线并通过必测用例。任何仅 OBSERVE 的替代实现不能宣称本任务 PROTECT 已完成。
