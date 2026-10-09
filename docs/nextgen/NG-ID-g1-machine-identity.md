# NG-ID g1（可选机器客户端可信身份试点）阶段级冻结设计（S7 设计稿，2026-10-08）

> 依据：`docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md` §12 全节（方向七：12.1 两条路线表「不同时强推、先选一个实际客户场景端到端试点」/12.2 接入要求七条/12.3 弱指纹不纳入首期）+ §15.2 NG-ID-01~03（三行完成证据）+ §16.4 NG-T-I01~I05（验收矩阵逐条）+ §4 共用安全契约（4.2 不变量：主体必须来自验证后的身份链/热路径零公网/日志不落凭据；4.3 模式分离；4.5 故障与未知矩阵）+ §13.1 数据模型（机器身份登记：身份、租户、公钥引用、算法、范围、有效期、撤销水位）+ §14.3（时钟漂移超批准上限禁止启用依赖时效的严格保护）。
> 阶段级冻结：NG-ID-01（路线选择与接入契约）/02（本地验证、重放、密钥轮换撤销）/03（权限与 Bot 协同、发布）共享同一登记模型、验证链与执行面，不可分割设计；本文一次冻结契约与决策点，按 §5 拆分分批实施。
> 范围锚点（任务书+§12.1 原文冻结）：**单选一条路线**端到端试点，不许两条都做；DPoP 留移交项。机器身份是**可选叠加**能力：缺省 OFF，未配置流量零行为变化（NG-T-C01）。
> 前置事实（inventory 复核 2026-10-08，逐项读码核实）：
> - **JWT 信任链现状**（`gateway/modules/jiuzhang_guard/jwt_trust.go`）：**验证点**在 serveGuard——真实 IP 处理后、身份观测前一次纯本地验证（compute-only，结果入请求上下文 jwtResultKey；jwt_trust.go:206-224）；VERIFIED 时注入 `identitybehavior.VerifiedIdentity{PrincipalID(应用隔离 HMAC 指纹)/TenantID/IssuerConfigID/PolicyVersion}`（jwt_trust.go:216-223）。**处置点**在 serveNext 统一放行出口最前（jwt_trust.go:235-274，apiprotect.go:172）：INVALID/缺必需 Bearer → PROTECT **401 + `WWW-Authenticate: Bearer realm="jiuzhang-waf"` 固定 JSON 短语**（jwt_trust.go:323-336）；UNAVAILABLE → **503 不伪装 Token 错误**（jwt_trust.go:340-352）；白名单/L7 allow 不绕过（安全底线）。配置段**严格解码 fail-closed**（DisallowUnknownFields+schema_version+未知 mode 拒载，jwt_trust.go:73-97；装配失败拒绝整体配置加载，jwt_trust.go:99-129）。身份指纹密钥复用 identity_salt 且域分隔（jwt_trust.go:13-15,175-181）；热路径零网络 IO（jwt_trust.go:16-17）。`jwtverify.VerificationResult` 五态 NOT_PRESENT/UNVERIFIED/VERIFIED/INVALID/UNAVAILABLE + 固定 ReasonCode 枚举（`jwtverify/types.go:14-42`），VerifiedPrincipalID/TenantID/Roles 仅验签通过后非空（types.go:101-117）。
> - **身份观测现状**（`gateway/modules/jiuzhang_guard/identitybehavior/identity.go`）：identity_key=确定性 HMAC 键（凭据>浏览器指纹>IP，identity.go:52-56）；**VerifiedPrincipalID/VerifiedTenantID 是 JWT VERIFIED 注入的独立可信信号——「不改写 Type、不合并、不参与 identity_key 计算」（identity.go:63-70，AGENTS.md 红线同文）**；上下文注入机制 `WithVerifiedIdentity`/`VerifiedIdentityFrom` 现成（identity.go:72-96）。TLSFingerprint 注释明示「拿不到 ClientHello，不做 JA3/JA4」（identity.go:60——§12.3 弱指纹纪律的现状锚点）。CredentialType 枚举已含 MTLS（identity.go:37），机器身份新凭据类型可同形扩展。
> - **Valkey 原子操作先例**（`gateway/dynamic_security/detectors/flowguard/reserve.go`）：**Lua 单次原子往返**+fencing=INCR 单调序号（reserve.go:1-3）；版本化键命名空间 `sflow:v1:{实例}:` hash tag 同槽（reserve.go:5-10,37-39）；**lease 判定一律 Valkey 服务端 TIME 单一时间源，不消费网关本地时钟**（reserve.go:19-20）；**故障 D8 红线：Valkey 不可用/超时/协议异常 → 恒 UNKNOWN（放行+披露），严禁切换本地内存**（reserve.go:21-23）；`Evaluator` 接口 `Eval(ctx, script, keys, args)` 与 `counters.ValkeyClient.Eval` 同签名、装配层结构化满足、**零新依赖类型**（reserve.go:70-74）；单次 Eval 超时 300ms（reserve.go:46-48）；原因码词表冻结（reserve.go:59-68）；warnf 节流告警（reserve.go:104-115）。
> - **撤销水位先例**（`server/internal/apiauthz/`）：撤销事实与水位推进（manual_seq+1）**同一事务原子提交**（relations.go:356）；单行 upsert **只增**（relations.go:389-390）；到期废止同纪律（relations.go:439）；NG-AZ-02 D1 语义：撤销水位单调不下降、PreviousValid 资格过滤、普通策略回滚不复活已撤销。
> - **能力自报/能力门现状**：ProtocolLevels 仅 http/graphql/grpc/mcp 四协议（`capability/types.go:22-27`——**机器身份无预登记层级，走 detectors 命名空间新键**）；检测器版本 `ns/N` 序数比较（types.go:134-146）；自报**恒报进程能力不绑配置态**（S5 偏差 2 教训，capability_report.go:155-162）；能力门：任一 PROTECT 段 → required `detectors.X=ns/N` fail-closed CAP_MISSING，全 OBSERVE 零需求（capability_gate.go:52-63,217-260，S6 三态 stage5 实证）。
> - **发布链/管理面现状**（S6 已落地在册）：迁移基线 **000182**；OpenAPI 对账基线 **715**（S6 出口 reconcile 双向零差集）；CRUD 范式 `server/internal/apimcp/`（routes.go:14-35 权限复用零新增、写操作 HIGH 审计、乐观锁 409）；guardconfig 段加载稳定序+失败 Warn 跳过；GuardConfig 段 omitempty+handler 哈希映射；网关装配 fail-safe 归一。**权限词表实证：`jwt_trust.read`/`jwt_trust.manage` 已注册在用**（`server/internal/app/app.go:1045-1047`，jwttrust/handler.go:3-6——机器身份与 JWT 信任链同属可信密钥管理域）。
> - **事件通道现状**：JWT 验证事件走 **access_control_events**（events.JWTAuthFailed/JWTUnavailable/JWTObserved，jwt_trust.go:255-272）；机器身份同为认证层信号，事件通道跟随此先例。
> - **体保全现状**：`preserveRequestBody` 上限 4MiB 全量读出还原，超限/失败 → 跳过管线 + `request.body_preserve_skipped` OBSERVE/HIGH 披露（apiprotect.go:1181-1210——content-digest 体预算的同源参照）。
> - **S6 联调教训承接**：跨轨算法/分隔符须**逐字冻结**（S6 偏差 1：catalog_hash 分隔符不一致致整目录拒装）；能力门清单注入保属主纪律；bot OFF 墓碑 CC 探针兼容（S6 偏差 6）。

## 1. 冻结契约

### 1.1 路线选择与适用范围（NG-ID-01；D1）

**路线单选（冻结）：HTTP Message Signatures（RFC 9421）**，内容摘要头按 RFC 9530（Content-Digest），结构化字段语法按 RFC 8941。DPoP（RFC 9449）**本期不做**，留移交项（§6）。

四维权衡（任务书要求维度，冻结理由）：

| 维度 | HTTP Signatures（选定） | DPoP（未选） |
|---|---|---|
| 反代落地难度 | 直接对网关所见请求成分（@method/@authority/@path/@query/content-digest）验签，纯本地无第三方依赖 | 需「AS 签发 cnf.jkt 绑定 Token + 客户端每请求证明 JWT」双侧到位，ath/htu 校验与既有 jwt_trust 链深度耦合 |
| 密钥管理 | 公钥**静态离线导入登记**（§12.2-1 原生形态，与 gRPC 描述符/MCP 目录同一管理面导入范式） | 要求客户已有可改造 OAuth 授权服务器（试点场景不具备） |
| 重放存储 | nonce 原子共享存储（Valkey Lua，flowguard 先例直复用） | jti 同左——两者等价，不构成区分度 |
| 客户端改造成本 | 试点=§12.1 表右列「可登记机器身份和公钥的受控集成/Agent」：预登记公钥+签名库即可 | 需 AS 侧先行改造（表左列「可改造 OAuth 授权服务器和客户端」前提不满足） |

**适用范围**：绑定 selector 命中的应用端点（path_exact|path_prefix，jwt selector 同形）；仅 HTTPS 部署形态（签名不加密，传输机密性由 TLS 承载；明文 h2c/http 回源不影响客户端→网关段的签名验证，网关验证点在入站侧）。**不宣称**：通用 Agent 标识标准（§12.1 末行原文——不把任何试验性标识协议当通用强制标准）；弱指纹（JA3/JA4/设备指纹/行为相似度）**不作确定性身份或对象所有权证据**（§12.3 原文承接，identity.go:60 现状锚点）。

**外部 URI 规范化（§12.2-4 冻结）**：@authority 取**可信代理处理后的 Host 原文**（只信任批准的转发信息——真实 IP/可信代理链现状口径）；@path 取 **raw path 不做归一化**；@query 取原文；scheme 仅用于 @target-uri 形态时的外部 scheme 重建（可信代理链 X-Forwarded-Proto 现状口径）。**G1 排除存在路径改写（rewrite）的路由**——绑定 selector 与路径改写规则冲突时管理面拒绝保存（不猜改写后形态）。HTTP 签名与 DPoP 规则不混用（本期无 DPoP 天然成立）。

**与既有 jwt_trust 的关系（冻结：并列叠加）**：机器身份是**独立第二条信任链**，不替代不改写 JWT 链。验证点紧随 JWT 验证之后（真实 IP 改写后、身份观测前，compute-only 入上下文——jwt_trust.go:206-224 同形挂点）；处置点在 serveNext 与 enforceJWTTrust 同段（白名单/L7 allow 不绕过）。VERIFIED 注入**独立信号**（VerifiedMachineID 指纹/MachineKeyID/RegistryVersion，WithVerifiedIdentity 同形机制），**不改 identity_key/identity_type 语义**（AGENTS.md 红线+identity.go:63-70 先例）。同请求可双 VERIFIED（JWT 主体+机器身份并存，授权层分别消费）；身份行声明 `principal_binding` 且 JWT 同请求 VERIFIED 时**两者必须一致**，不一致 → 401（MID-PRINCIPAL-MISMATCH，不融合裁决不静默择优）。

### 1.2 机器身份登记模型（NG-ID-01/02；D2）

**四表（迁移 000183/000184，§1.12；逻辑模型冻结，物理索引以实施批 schema 检索为准——§13.1 纪律）**：

- `machine_identities`（身份）：`id` / `identity_name`（唯一，≤128）/ `tenant_id`（可空，跨租户共享身份为 NULL+显式）/ `principal_binding`（可空——绑定 JWT VerifiedPrincipalID 指纹值，声明即强制一致，§1.1）/ `status`（ENABLED|DISABLED）/ `bot_challenge_exempt`（BOOL **缺省 false**——§1.7 精确豁免前提）/ `version` 乐观锁 / 审计列。
- `machine_identity_keys`（公钥）：`identity_id` FK CASCADE / `kid`（≤128，身份内唯一）/ `alg`（CHECK 词表：**ed25519|ecdsa-p256-sha256|rsa-pss-sha512**，其余拒收——hmac-sha256 共享密钥形态**排除**（机器身份只要非对称；rsa-v1_5-sha256 排除（RFC 9421 标注不推荐））/ `public_key_pem`（公钥非秘密，明文存储合法）/ `status`（**ACTIVE|RETIRED|REVOKED** 状态机：ACTIVE=可签发可验证；RETIRED=重叠窗口内仅验证（不得用于新签名——管理面展示），窗口终点 `retire_overlap_until`；REVOKED=立即拒验）/ `not_before`/`not_after` / `revoked_seq`（撤销时水位值，溯源）/ 审计列。
- `machine_identity_bindings`（绑定）：`application_id` FK CASCADE / `path_exact`|`path_prefix` 二选一（jwt selector 同形校验）/ `mode`（OBSERVE 缺省|PROTECT）/ `proof_required`（BOOL：绑定命中且 true 时**未签名请求=拒绝**（401）；false=未签名按普通流量继续既有防护）/ `version` 乐观锁 / 唯一 `(application_id, path)`。
- `machine_identity_revocation_watermark`（水位，单行表）：`id` 单行哨兵 / `seq` BIGINT **只增 upsert**（apiauthz relations.go:389-390 同形）；**撤销事实与 seq+1 同一事务原子提交**（relations.go:356 同纪律）。

### 1.3 公钥导入纪律（§12.2-1 原文承接；D3）

- **唯一来源=管理面静态离线导入**（PEM 粘贴/文件上传，管理面解析校验算法词表与密钥形态）；「控制面批准的同步」通道**本期不建**（移交项）。
- **禁止根据请求中的任意密钥 URL 自动抓取**（§12.2-1 原文红线）：网关热路径零网络 IO（jwt_trust.go:16-17 同纪律）；签名参数中的 keyid 只做**登记册精确查找**，任何形式 URL/URI 形态 keyid 不触发抓取（查找失败即 MID-KEY-UNKNOWN）。
- 导入即审计（HIGH）；公钥指纹（sha256 前 16 hex）为管理面与事件的稳定引用（不落完整公钥进事件）。

### 1.4 验证链固定序（NG-ID-02；NG-T-I01/I02；D4）

绑定命中且请求携带 `Signature-Input`/`Signature` 头时，按**固定序**执行（前步失败即短路，逐步独立 reason code；全部计算在请求 goroutine 内，无后台任务）：

| 序 | 步骤 | 失败 reason code（事件词表） | HTTP 语义 |
|---|---|---|---|
| 1 | 头形态解析（RFC 8941 SF 解析子集；**恰好一个签名标签**（多标签 G1 拒收）；签名参数 created/expires/nonce/keyid/alg 齐全性） | MID-SIGNATURE-MALFORMED | 401 |
| 2 | keyid → 登记册精确查找（身份 ENABLED 前提） | MID-KEY-UNKNOWN | 401 |
| 3 | 算法白名单（§1.2 词表；与键登记算法一致性双重核对） | MID-ALG-REJECTED | 401 |
| 4 | 密钥状态机（REVOKED 即拒；RETIRED 窗口内放行、窗口外拒；not_before/not_after 生效域） | MID-KEY-REVOKED / MID-KEY-RETIRED-EXPIRED / MID-KEY-EXPIRED | 401 |
| 5 | 证明时效（**created 必填**且在偏移窗口（±30s 缺省，夹紧 ≤120s——jwtverify 同纪律）；**expires 必填**且 expires-created ≤ **120s**（证明寿命有界=重放窗口上界）；nonce 必填 8~64 字符） | MID-PROOF-EXPIRED / MID-CLOCK-SKEW / MID-NONCE-INVALID | 401 |
| 6 | 覆盖成分充分性（**必含 @method、@authority、@path、created、expires、nonce、keyid**；请求有 query **必含 @query**；请求有 body **必含 content-digest**（§12.2-3 原文「涉及 Body 时必须验证其内容摘要」）；**权限关键头（Authorization 等被可信消费的头）若存在必须被覆盖——未签名的权限关键头不得进入可信上下文**（§12.2-3 原文）） | MID-COVERAGE-INSUFFICIENT | 401 |
| 7 | 目标绑定（@method 与请求一致；@authority/@path/@query 按 §1.1 规范化口径逐字节比对） | MID-TARGET-MISMATCH | 401 |
| 8 | content-digest 重算比对（sha-256/sha-512；体不可读/超预算 → 不判无效，按 UNKNOWN 走 D8/D10（PROTECT 413/503）） | MID-DIGEST-MISMATCH | 401 |
| 9 | 签名基线重构 + 密码学验签（stdlib crypto；失败不区分「签名错/基线错」防探测——事件内可细分） | MID-SIGNATURE-INVALID | 401 |
| 10 | 重放原子检查（§1.5；重复 → MID-REPLAY-DETECTED 401；存储缺席 → UNAVAILABLE 按 D8/D10，**不判无效**） | MID-REPLAY-DETECTED | 401 |
| — | 全部通过后**范围核对**：绑定 selector 命中且（身份 status ENABLED）——身份合法但请求越出登记范围（绑定未覆盖该路径/proof 与绑定不符） | MID-SCOPE-DENIED | **403** |

**成功产出（冻结）**：`MachineVerificationResult{Status(VERIFIED/INVALID/UNAVAILABLE/NOT_PRESENT/OUT_OF_SCOPE), ReasonCode, MachineID(指纹), KeyID, RegistryVersion, RevocationWatermark, EvaluatedAt}` 入请求上下文（jwtverify.VerificationResult 同形纪律：不可变值类型，不落签名原文/公钥原文/nonce 原文——nonce 仅以 sha256 摘要参与存储与事件）。**证明存在≠已通过授权**（§12.2-2 原文）：VERIFIED 只是身份事实，授权/配额/WAF/API 防护后续照常（§1.7）。

### 1.5 重放存储（NG-ID-02；NG-T-I03；D5）

- **形态（冻结）**：Valkey Lua **单次原子往返** `SET NX PX`（存在即重放）；键 `mid:v1:nonce:{identity_fp}:{nonce_sha256_hex32}`（版本化命名空间+hash tag 同槽，flowguard reserve.go:5-10,37-39 同形）；TTL=证明 expires 剩余期（上界 120s，§1.4-5）。
- **接口零新依赖**：复用 `Evaluator` 接口形态（`Eval(ctx, script, keys, args)`，`counters.ValkeyClient.Eval` 结构化满足——reserve.go:70-74 先例）；单次 Eval 超时 300ms 同量纲（reserve.go:46-48）。
- **存储缺席的明示严格策略（§12.2-5 原文「不悄悄只在本机去重」）**：Valkey 不可用/超时/协议异常 → **UNAVAILABLE：OBSERVE 放行+披露（dependency_unavailable）/ PROTECT 503 固定短语**（jwt_trust UNAVAILABLE 503 先例，jwt_trust.go:340-352——不伪装签名错误）；**严禁本地内存回退去重**（flowguard D8 红线 reserve.go:21-23 同文承接）；网关重启后无进程内权威态（存储即唯一事实源）。
- **时钟纪律**：重放窗口由证明自身 expires（已过时效校验）+PX 相对 TTL 承载，不依赖跨节点时钟一致；created/expires 校验消费本地时钟，偏移夹紧 ≤120s；**跨节点时钟漂移超批准上限时禁止启用 PROTECT**（§14.3 原文承接，管理面展示原因）。
- **两节点重放断言（I03 设计锚点）**：node A 接受 nonce N 后，node B 携同 nonce 同身份重放 → Lua SET NX 原子拒（MID-REPLAY-DETECTED）；停 Valkey → 双节点 PROTECT 均 503（各自计数证明无本机去重）。

### 1.6 密钥轮换与撤销水位（NG-ID-02；NG-T-I04；D6）

- **轮换（冻结）**：管理面 rotate 原子操作=新键 ACTIVE + 旧键 RETIRED + `retire_overlap_until`（重叠窗口终点，缺省 24h，上限 168h——审批面显式）；窗口内新旧键均可验证（旧键事件标注 RETIRED 事实），窗口外旧键 MID-KEY-RETIRED-EXPIRED 拒验。**旧键状态管理面可见**（§12.2-6「旧节点与旧密钥状态要显示」）。
- **撤销（冻结）**：revoke 即时生效（下一发布快照携带）；撤销事实与水位 seq+1 **同事务**；事件与管理面展示 revoked_seq。
- **水位单调不下降（AZ-02 同语义承载）**：发布快照 `api_machine_identity_meta.revocation_watermark` 与网关机 applied_watermark 比较——**快照水位 < applied_watermark → 拒绝该快照（fail-closed，不静默降级）**；普通策略回滚通道回到低水位快照同样被拒——**普通策略回滚不复活已撤销密钥**（§12.2-6 原文）；回滚申请面如实展示拒绝原因（水位差）。节点 ACK 与撤销传播时延报告随 NG-ID-02 测试产出（AZ-02 同形态）。

### 1.7 与防护链协同（NG-ID-03；NG-T-I05；D7）

- **VERIFIED ≠ 授权通过**（§12.2 末条原文）：机器身份验证成功后，请求**照常经过**对象/功能授权、资源预算、WAF（Coraza/CRS）、API 动态防护、CC——任何一层照判照拦（I05 断言锚点：VERIFIED 机器携 SQLi 载荷 → WAF 事件在册照拦）。
- **Bot 挑战协同（精确范围显式策略）**：VERIFIED 机器身份**默认不免 Bot 挑战**；豁免成立当且仅当 ①身份行 `bot_challenge_exempt=true` 且 ②当前请求命中该身份的绑定 selector 且 ③验证链全步通过——豁免事实进事件（reason=MID-BOT-EXEMPT，含身份指纹与绑定 ID；**未豁免的 VERIFIED 机器照走挑战**）。bot_step 消费点为既有模块的显式扩展（集成测试覆盖，S6 C04「白名单不绕过 JWT」同形实证）。
- **与 JWT 并存**：双链各自独立强制（各自 PROTECT 各自处置）；principal_binding 一致性见 §1.1。机器身份不产生全局放行（VERIFIED 后继续后续检测——jwt_trust.go:230-244 处置表同纪律）。

### 1.8 UNKNOWN 与降级红线（D8）

**五态如实 + `id.coverage_v1` 读数，恒不把 UNKNOWN 当违规阻断**（AZ/FLOW/GRPC/MCP 同一红线）：

| 情形 | 处置（冻结） |
|---|---|
| 登记册缺席/装配失败/摘要不符 | 覆盖 SKIPPED(COV_NO_REGISTRY)；OBSERVE 放行 / PROTECT **503**（依赖不可用不伪装签名错误）；Warn 不静默 |
| 重放存储缺席 | §1.5（OBSERVE 放行披露 / PROTECT 503）；严禁本机去重 |
| 体不可读/超预算（content-digest 待验） | UNKNOWN：OBSERVE 放行披露 / PROTECT **413**（预算语义）；覆盖 PARTIAL(COV_INPUT_TRUNCATED) |
| 未签名请求 | proof_required=false → NOT_APPLICABLE(MID-NA-UNSIGNED-001) 按普通流量；proof_required=true → 401（这是**准入策略判定**不是 UNKNOWN） |
| 验证器内部异常 | recover → UNAVAILABLE（jwtverify Verifier.Verify 内部 recover 同纪律，jwt_trust.go:209-210）；覆盖 ERROR；OBSERVE 放行 / PROTECT 503 |
| 时钟漂移超限 | §14.3：禁止启用 PROTECT 并展示原因；OBSERVE 不受影响 |
| 弱指纹信号（TLS 组态/UA 族等） | 仅观测线索现状不动（identity.go:60）；**永不升级为确定性身份证据**（§12.3） |

**证明存在≠授权通过**（§12.2-2）与**身份验证成功≠内容可信**（I05）两条红线进测试矩阵。覆盖观测独立 Emitter（ADR-2 永不贡献攻击分）；`id.coverage_v1` 双承载（Emitter+INFO DetectorMatch 零分值，grpcguard/mcpguard 先例）。

### 1.9 资源预算与性能（D9）

| 维度 | 预算（冻结常量首批，§14.1 隔离实验纪律） | 依据 |
|---|---|---|
| Signature-Input+Signature 头合计 | ≤ **8 KiB** | 头解析内存上界（SF 解析子集有界） |
| 覆盖成分数 | ≤ **32**/签名标签；成分名 ≤128 字符；参数 ≤8 个/成分 | 签名基线重构 CPU/内存上界 |
| content-digest 体预算 | ≤ **4 MiB**（preserveRequestBody 同源上限，apiprotect.go:1181） | 体保全现状量纲 |
| 验签次数 | **每请求至多 1 次**（单签名标签 G1 冻结） | CPU 放大封顶 |
| 验签 CPU 候选门槛 | ed25519/ecdsa-p256 p99 ≤ **2ms**/请求；rsa-pss-sha512 p99 ≤ **5ms**/请求（§14.2 下挂，普通 amd64+兆芯双报告） | stdlib crypto 量级经验值，实施批实测校准 |
| 公钥登记册 | 装配期编译进程内缓存，热路径 map 查找 O(1) | jwtverify 静态 JWKS 同形态 |
| nonce 存储量级 | 绑定端点签名 QPS × ≤120s 窗口 × ~80B/键（示例 1krps ≈ 120k 键 ≈ 10MB）——登记公式进运维手册 | §14.1 端到端算账 |
| 重放存储往返 | 每签名请求至多 1 次 Lua Eval（300ms 超时上界） | reserve.go:46-48 同量纲 |
| 全 OFF 开销 | 吞吐降 ≤2%/P99 增量 ≤1ms（§14.2 门槛沿用） | 候选门槛 |

### 1.10 错误语义与执行面（D10）

- **401（证明未通过）**：固定 JSON `{"error":"machine_identity_failed","request_id":...}`（防探测固定短语，jwt_trust.go:323-336 同形）；**不携带 WWW-Authenticate 签名方案**——RFC 9421 未注册标准 challenge 方案，自带即冒用（§11.3 同纪律「自定义错误要明确为产品扩展，不能冒用标准语义」；G1 冻结不带，客户端重试策略由接入契约文档约定）；真实 reason code 只落事件与管理面。
- **403（证明通过但越界）**：MID-SCOPE-DENIED 固定 JSON `{"error":"machine_identity_scope_denied","request_id":...}`——**401≠403 形态区分**（认证/授权分离，M01 同思想）。
- **503（依赖不可用）**：登记册缺席/重放存储缺席/验证器异常且策略 PROTECT → 固定短语 503（jwt_trust.go:340-352 先例——不伪装证明错误、不带重试诱导）。
- **413（体预算）**：content-digest 覆盖但体超 4MiB → PROTECT 413 固定短语（§13.3「大小上限不得一律 403」）。
- **事件通道**：access_control_events（JWT 事件同通道）；事件含 Status/ReasonCode/身份指纹/KeyID/RegistryVersion/水位/request_id；**不落签名原文、nonce 原文、公钥原文、体原文**（§4.2-8/§14.3 红线）。
- **执行面挂接**：serveNext 与 enforceJWTTrust 同段（committed 直写，不走 Caddy 错误链阻断页——API 调用方按协议消费）；非绑定流量零形态变化（NG-T-C01）。

### 1.11 能力门与滚动升级（D11）

- **自报（恒报进程能力，S5 偏差 2/S6 承接）**：detectors 新增 **`machineid=mid/1`**（G1 完成态=登记册消费+十步验证链+重放原子存储+轮换撤销水位+协议化执行）；ProtocolLevels **不动**（机器身份是检测器能力不是协议层级——capability/types.go:22-27 现实约束）；actions 不动（复用 block 语义）。
- **能力门**：`CapabilityFacts` 新增 `MachineIDProtect`（`api_machine_identity_bindings` 含任一 mode=PROTECT）→ required **`detectors.machineid=mid/1`** fail-closed `CAP_MISSING:detectors.machineid`（旧节点不得把签名验证漏做或误形态处置）；**全 OBSERVE/无绑定零需求**（滚动升级可行——az/3、flow/1、grpc/2、mcp/2 同纪律）。三态 stage5 实证（S6 能力门三态同形态：旧清单注入→fail-closed；全 OBSERVE→SUCCESS；mid/1 收载→SUCCESS）。

### 1.12 管理面、发布链与 OpenAPI 预估（D12）

- **迁移（000183/000184，不预占更多号）**：000183=`machine_identities`+`machine_identity_keys`；000184=`machine_identity_bindings`+`machine_identity_revocation_watermark`（单行种子 seq=0）。FK CASCADE、CHECK 词表、乐观锁、审计列——apimcp/apigrpcdesc 范式对齐。
- **CRUD 端点（统一 /api/v1/api-security 前缀；权限复用 `jwt_trust.read`/`jwt_trust.manage` 零新增——可信密钥管理同域（app.go:1045-1047 实证已注册；RD_PLAN §13.1「复用可信密钥管理原则」原文支撑）；写操作 HIGH 审计、乐观锁 409）**：

| # | 端点 | 权限 | 语义 |
|---|---|---|---|
| 1 | POST /machine-identities | manage | 创建身份（租户/绑定主体/exempt 声明） |
| 2 | GET /machine-identities | read | 列表（含键状态摘要/水位） |
| 3 | GET /machine-identities/{id} | read | 详情（键行含状态/窗口/revoked_seq） |
| 4 | PUT /machine-identities/{id} | manage | 改范围/状态/exempt/绑定主体（乐观锁） |
| 5 | DELETE /machine-identities/{id} | manage | 删除（FK 级联；绑定引用先决 409） |
| 6 | POST /machine-identities/{id}/keys | manage | 公钥静态导入（§1.3 纪律；PEM 解析校验） |
| 7 | POST /machine-identities/{id}/keys/{keyId}/rotate | manage | 轮换（新 ACTIVE+旧 RETIRED+重叠窗口，§1.6） |
| 8 | POST /machine-identities/{id}/keys/{keyId}/revoke | manage | 撤销（水位同事务推进，§1.6） |
| 9 | GET /machine-identity-bindings | read | 绑定列表（按应用） |
| 10 | POST /machine-identity-bindings | manage | 新建绑定（selector/mode/proof_required） |
| 11 | PUT /machine-identity-bindings/{id} | manage | 改 mode/proof_required（乐观锁） |
| 12 | DELETE /machine-identity-bindings/{id} | manage | 解绑 |

- **发布链**：guardconfig 加载器（ENABLED 身份+键全行稳定序；失败 Warn 跳过同现状）→ GuardConfig 三段（下述逐字冻结）→ 网关 module.go 同 tag 接收 → 装配（fail-safe：mode 词表外归一 OBSERVE+Warn、字段空缺跳行+Warn、公钥 PEM 解析失败行拒装+Warn——**含 PROTECT 绑定时装配失败拒绝整体配置加载**（jwt_trust.go:99-129 fail-closed 同纪律：已存在 PROTECT 策略不得被静默降级））；绑定/身份/键/水位变更触发发布（SetPublishFunc 先例）。
- **发布段形状（逐字冻结，跨轨契约不得改名；S6 偏差 1 教训——哈希/拼接规则若有亦逐字冻结）**：
  ```json
  "api_machine_identities": [{"identity_name","tenant_id","principal_binding","status","bot_challenge_exempt",
    "keys":[{"kid","alg","public_key_pem","status","not_before","not_after","retire_overlap_until","revoked_seq"}]}]
  "api_machine_identity_bindings": [{"application_id","path_exact","path_prefix","mode","proof_required"}]
  "api_machine_identity_meta": {"revocation_watermark": 0, "registry_version": 0}
  ```
- **OpenAPI 增量预估 +12 → 727**（上表逐端点；基线 715（S6 出口 reconcile 双向零差集）；实施批 reconcile 收口，预估偏差 ±2 内属正常）。
- **NG-T-C01**：无身份/无绑定/未签名流量 = 全链零行为（装配 nil 零行为；存量回归不回退）。

### 1.13 覆盖账本接入（D13）

- 检测器名 **`machineid`**；每绑定命中请求一条 **`id.coverage_v1`**（INFO 双承载）：phase、identity 指纹（判定时）、kid、registry_version、水位、skip_reason、completion。
- **五态**：FULL（验证链全步执行完毕——无论通过或拒绝，判定完成即 FULL）/ SKIPPED（COV_DISABLED 策略 OFF、**COV_NO_REGISTRY 新增注册**（登记册缺席）、COV_DEPENDENCY_UNAVAILABLE 重放存储缺席（OBSERVE 放行时））/ NOT_APPLICABLE（COV_NA_FROZEN_RULE+NARuleID=**MID-NA-UNSIGNED-001** 未签名按普通流量）/ PARTIAL（体超预算 content-digest 未验，COV_INPUT_TRUNCATED 复用）/ ERROR（验证器异常）。**新增 reason 注册仅 1 个：COV_NO_REGISTRY**（其余全复用存量——coverage/types.go:52-68 注册表纪律）。
- E=0 → `no_applicable_traffic=true`（零分母纪律）；覆盖永不贡献攻击分（ADR-2）。

### 1.14 接入契约（NG-ID-01 完成证据「发行方/客户端配合确认」承载；D14）

- **客户端约定（冻结）**：签名标签恒 `sig1`；必含成分与参数按 §1.4-6；alg 按 §1.2 词表；nonce 取密码学随机 16~32 字节 base64；created/expires  Unix 秒、窗口 ≤120s；Content-Digest 头按 RFC 9530（sha-256 优先）。
- **试点场景（冻结）**：受控集成 Agent（§12.1 表右列）——stage5 双应用（OBSERVE/PROTECT 各一）+ 参照实现客户端（§4）；真实客户场景接入表单列「身份名/公钥/范围/窗口/豁免声明」五项。
- **文档交付**：接入契约一节随管理面手册交付（docs/manuals 先例），含成分清单、规范化口径、错误码表、轮换/撤销操作序列。

## 2. 冻结决策点（D1~D14）

| # | 结论（一句话） | 理由要点 |
|---|---|---|
| D1 路线 | **单选 HTTP Message Signatures（RFC 9421+9530+8941）**；DPoP 移交；@authority=可信代理后 Host 原文、@path raw 不归一、rewrite 路由管理面拒存；与 jwt_trust 并列叠加（同挂点家族、独立信号注入、principal_binding 一致性强校验） | §12.1「不同时强推/先选一条」；四维权衡（§1.1 表）；§12.2-4 只信任批准转发信息；AGENTS.md 身份红线 |
| D2 登记模型 | 四表（身份/键/绑定/水位单行）；键状态机 ACTIVE/RETIRED/REVOKED+窗口终点+revoked_seq；算法词表 ed25519/ecdsa-p256/rsa-pss-sha512（排除 hmac 与 rsa-v1_5） | §13.1 机器身份登记行；非对称才配称机器身份；RFC 9421 算法纪律 |
| D3 公钥导入 | 唯一来源=管理面静态离线导入；keyid 仅登记册精确查找，任何 URL 形态不抓取；热路径零网络 IO | §12.2-1 原文红线；jwt_trust 热路径纪律 |
| D4 验证链 | 十步固定序（解析→keyid→算法→键状态→时效→覆盖成分→目标绑定→体摘要→验签→重放）+通过后范围核对；逐步 reason code；401/403 分明；证明存在≠授权通过 | §12.2-2/3/4 原文逐条落位；NG-T-I01「与协议规范一致」 |
| D5 重放 | Valkey Lua SET NX PX 单次原子往返（mid:v1:nonce: 键+hash tag）；存储缺席 OBSERVE 放行披露/PROTECT 503；严禁本机去重；PX 相对 TTL 不依赖跨节点时钟 | §12.2-5 原文；flowguard D8 红线与 Evaluator 先例直复用 |
| D6 轮换/撤销 | rotate 原子（新 ACTIVE+旧 RETIRED+重叠窗口 ≤168h）；revoke 与水位 seq+1 同事务；快照水位低于已应用水位→拒载（fail-closed）；普通回滚不复活已撤销 | §12.2-6 原文；apiauthz 水位同事务/单调不下降先例 |
| D7 防护协同 | VERIFIED 照过授权/预算/WAF/API/CC；Bot 豁免=身份 exempt∩绑定命中∩验证通过三重显式（事件记录）；未豁免照走挑战 | §12.2 末条原文；NG-T-I05；S6 C04 同形实证 |
| D8 UNKNOWN 红线 | 登记册缺席/存储缺席/体不可读/验证器异常全五态如实+id.coverage_v1；OBSERVE 放行披露/PROTECT 503·413 不伪装证明错误；弱指纹永不升级确定性证据 | §4.5 故障矩阵；§12.3；UNKNOWN 恒不阻断全项目红线 |
| D9 预算 | 头 8KiB/成分 32/体 4MiB/验签每请求 1 次/p99 2ms（rsa-pss 5ms）/nonce 存储公式登记/全 OFF ≤2%+1ms | §14.1 端到端；§14.2 候选门槛下挂 |
| D10 错误语义 | 401 固定短语**不带 WWW-Authenticate**（不冒用未注册方案）；403 越界；503 依赖；413 体预算；事件 access_control_events 不落签名/nonce/公钥原文 | 防探测统一短语纪律；§13.3 状态映射；§4.2-8 日志红线 |
| D11 能力门 | detectors.machineid=mid/1 恒报；任一 PROTECT 绑定 → required mid/1 fail-closed；全 OBSERVE 零需求滚动升级；ProtocolLevels 不动 | capability/types.go:22-27 现实约束；S5/S6 恒报与三态先例 |
| D12 管理面 | 迁移 000183/000184；12 端点复用 jwt_trust.read/manage 零新增；发布三段逐字冻结；OpenAPI +12→727 | 权限词表实证（app.go:1045-1047）；§13.1 复用可信密钥管理原则原文 |
| D13 覆盖 | machineid 五态+id.coverage_v1 双承载；新 reason 仅 COV_NO_REGISTRY；E=0 no_applicable_traffic | NG-COV-01 契约；grpcguard/mcpguard 先例 |
| D14 接入契约 | sig1 单标签/必含成分/nonce 随机/窗口 ≤120s/Content-Digest sha-256 优先；试点=受控 Agent 双应用（OBSERVE+PROTECT）；接入手册五项表单 | NG-ID-01 完成证据形态；§12.1 表右列场景 |

## 3. 本批不做（范围外，如实标注）

- **DPoP（RFC 9449）整条路线**（AS 改造依赖前置；移交项——路线比对本文 §1.1 已冻结，后续试点不重新评审选型逻辑本身）。
- **控制面批准的公钥同步通道**（G1 仅静态离线导入）；多签名标签（G1 恰一个 sig1）；`@target-uri` 全形态（G1 以 @authority+@path+@query 分解覆盖，@target-uri 形态拒收为 MID-COVERAGE-INSUFFICIENT——接入契约明示）；签名响应（响应签名非本期语义）。
- **弱指纹扩展**（JA3/JA4/设备指纹/行为相似度——§12.3 原文：可独立调研，须核查采集位置/隐私/许可证/误报，不作确定性证据）。
- **机器身份驱动的对象所有权证据**（机器身份是主体信号不是对象关系；与 apiauthz 的融合评审留后续）。
- **路径改写路由下的签名验证**（§1.1 管理面拒存）；mTLS 客户端证书链（CredentialType 枚举在册但验证链不在本期）。
- **撤销传播的节点 ACK 全量可视化**（时延报告随 I04 产出；管理面拓扑增强留后续）。

## 4. 测试计划（NG-T-I01~I05 逐条映射）

**对测纪律（冻结）**：试点客户端=**参照实现**（Go stdlib crypto（ed25519/ecdsa/rsa-pss）+ RFC 8941 结构化字段解析——候选库 `github.com/dunglas/httpsfv`，**许可证与版本实施批核实锁定（TBD；不宽松则自实现最小 SF 子集兜底并登记偏差）**）；**黄金样本=RFC 9421 附录 B 官方测试向量**（规范内嵌，零第三方依赖——ed25519 向量逐字节断言签名基线与验签结果）；禁 curl 冒充（签名构造必须经真实实现）；测试数据 RFC5737/example.com 红线；独立 go.mod（grpc-e2e/mcp-e2e 同形态，`test/waf/mid-e2e/`）；源站复用 testorigin 回显（无需新源站——签名验证全在网关侧）。

| 用例 | 断言 | 实施位置 |
|---|---|---|
| I01 有效证明/方法或 URI 变化 | 有效签名（ed25519+ecdsa+rsa-pss 三算法）通过（VERIFIED 事件在册、源站到达）；改方法/路径/query 任一后重放原签名 → 401 MID-TARGET-MISMATCH（**与协议规范一致**：签名基线成分逐字节比对）；RFC 9421 附录 B 向量黄金样本逐字节通过 | gateway httpsig 单测（向量）+stage5 E2E |
| I02 Token 与密钥绑定不符 | keyid 未登记/指向他身份/alg 与登记不符/principal_binding 与 JWT VERIFIED 主体不一致 → 401（MID-KEY-UNKNOWN/MID-ALG-REJECTED/MID-PRINCIPAL-MISMATCH），**不升级可信机器身份**（事件身份字段为空）；JWT 缺席时机器身份独立成立不冒充人类主体 | stage5 E2E+jwt 组合矩阵 |
| I03 两节点重放/存储不可用 | node A 接受 nonce N → node B 同 nonce 同身份重放 → 401 MID-REPLAY-DETECTED（Valkey SET NX 原子，双节点各自计数证明无一放行两次）；停 Valkey → PROTECT 双节点均 503 固定短语（**无本机去重**）+OBSERVE 应用放行披露 dependency_unavailable；恢复后新 nonce 正常 | stage5 双网关共享 Valkey（compose 双实例，编排 TBD 以 stage5 为准）+故障注入 |
| I04 撤销/轮换/回滚 | revoke 发布后调用 → 401 MID-KEY-REVOKED；rotate 重叠窗口内新旧键均过（旧键事件标 RETIRED）、窗口外旧键拒；**普通策略回滚到低水位快照 → 拒载（水位单调不下降）**，已撤销键不复活（回滚后调用仍 401）；旧节点（无 mid/1）接收含 PROTECT 绑定快照 → 能力门 fail-closed；旧键状态管理面可见 | server PG 契约（水位同事务/只增）+stage5 E2E+能力门三态 |
| I05 合法机器发起 WAF/API 攻击 | VERIFIED 机器携 SQLi 载荷 → **WAF 照拦**（CRS 事件在册）；越权对象访问 → 授权照判；超配额 → 限速照判；未声明 exempt 的 VERIFIED 机器 → Bot 挑战照走；声明 exempt 且绑定命中 → 豁免事件在册 | stage5 E2E（CRS 触发语料+授权用例复用存量） |

**共用矩阵承接**：NG-T-C01（无身份/绑定/未签名全链零行为+存量回归 40/40、13/13 不回退）；C02（OBSERVE 命中不实断留拟动作）；C04（白名单/L7 allow 命中后机器身份 PROTECT 仍执行——serveNext 统一出口顺序实证）；C06（五态/零分母一致）；C09（越权管理拒绝+审计）；集成四断言（客户端响应/源站到达/决策记录/运行态事件）；性能候选门槛（§1.9，普通 amd64+兆芯双报告）。

## 5. 实现拆分与顺序（文件级边界预估，实施批再冻结）

**批次 A：HTTP 签名验证纯库（NG-ID-02 前半，gateway 单轨）**
- `gateway/dynamic_security/httpsig/`（RFC 8941 SF 解析子集+签名基线重构+三算法验签纯函数+头/成分预算+重放 Lua 脚本与 Store（Evaluator 接口））+单测+RFC 9421 附录 B 黄金样本+fuzz（SF 解析）。**零文件交集**：不动 pipeline/coverage/jiuzhang_guard/server。
- 线契约（逐字冻结，B2 直接消费）：
  ```go
  package httpsig
  type Budgets struct { MaxHeaderBytes, MaxComponents, MaxComponentNameLen, MaxParamsPerComponent, MaxBodyBytes int }
  func DefaultBudgets() Budgets // §1.9 冻结常量
  type Key struct { Kid, Alg string; PublicKeyPEM []byte } // 登记册行编译产物
  type Params struct { KeyID, Alg, Nonce string; Created, Expires int64; CoveredComponents []string }
  // 错误三分类：ErrMalformed（形态）/ErrBudget（预算）/ErrVerify（密码学或绑定失败，含冻结 reason 词表）
  func ParseHeaders(signatureInput, signature string, b Budgets) (*Params, error)
  func VerifySignatureBase(r *http.Request, p *Params, body []byte, key Key) error // §1.1 规范化口径+§1.4 步 6/7/8/9
  type ReplayStore struct{ /* Evaluator 接口（counters.ValkeyClient.Eval 同签名）+300ms 超时 */ }
  func (s *ReplayStore) CheckAndSet(ctx context.Context, identityFP, nonceDigestHex32 string, ttl time.Duration) (isReplay bool, err error)
  ```

**批次 B1：登记管理面+发布段（NG-ID-01/02 server 单轨）**
- server：迁移 000183/000184；`server/internal/apimachineid/`（store+handler+routes，apimcp 范式；轮换/撤销/水位同事务状态机）；guardconfig 加载器+gatewayconfig GuardConfig 三段+handler 哈希映射+capability_gate facts（MachineIDProtect）；OpenAPI 片段+merge+reconcile。**零文件交集**：不动 gateway/web。
- 线契约：§1.12 发布段三段 JSON 逐字冻结（跨轨不得改名）。

**批次 B2：网关执行（NG-ID-02 后半/03，gateway 单轨）**
- `gateway/dynamic_security/detectors/machineid/`（十步验证链状态机+事件产出+覆盖双承载+水位资格过滤）；jiuzhang_guard（验证点挂接紧随 verifyJWTTrust 后（compute-only 入上下文）、serveNext 处置（401/403/503/413 committed 直写）、bot_step 三重豁免消费点、能力自报 mid/1 恒报、装配 fail-safe/PROTECT fail-closed）；coverage/types.go 注册 COV_NO_REGISTRY；identitybehavior 机器身份信号同形注入（不改 identity_key 语义）。
- 依赖：A 的库（导入 httpsig）；B1 的段形状（本文已冻结，编译解耦可并行）。
- 线契约（逐字冻结）：
  ```go
  package machineid
  type Config struct { /* per-app: selector → {Registry *Registry, Mode string, ProofRequired bool}; RegistryVersion/RevocationWatermark */ }
  type Result struct { Status, ReasonCode, MachineIDFP, KeyID string; RegistryVersion int64; Watermark int64 }
  func Evaluate(ctx *dsctx.RequestContext, r *http.Request, body []byte, cfg *Config, replay *httpsig.ReplayStore, jwtRes *jwtverify.VerificationResult, engineProtect bool) *coverage.Observation
  ```
  事件 reason 词表（逐字冻结）：MID-SIGNATURE-MALFORMED/MID-KEY-UNKNOWN/MID-ALG-REJECTED/MID-KEY-REVOKED/MID-KEY-RETIRED-EXPIRED/MID-KEY-EXPIRED/MID-PROOF-EXPIRED/MID-CLOCK-SKEW/MID-NONCE-INVALID/MID-COVERAGE-INSUFFICIENT/MID-TARGET-MISMATCH/MID-DIGEST-MISMATCH/MID-SIGNATURE-INVALID/MID-REPLAY-DETECTED/MID-SCOPE-DENIED/MID-PRINCIPAL-MISMATCH/MID-BOT-EXEMPT；NARuleID=MID-NA-UNSIGNED-001；coverage rule_id=`id.coverage_v1`。

**批次 C：联调+管理前端+QA（NG-ID-03，三轨）**
- QA/联调：`test/waf/mid-e2e/` 参照客户端+黄金样本；stage5 双应用（OBSERVE/PROTECT）+双网关共享 Valkey 重放矩阵+I01~I05 全量+能力门三态+性能基准+回归门禁（40/40、13/13 每批必过）。
- web：身份列表/详情（键状态/窗口/水位可见）/导入/轮换/撤销/绑定管理页（权限隐藏/禁用纪律 §13.4）——可在 B1 API 契约（本文已冻结）后提前起步（mock）。
- 出口记录 `docs/nextgen/s7/S7-EXIT-SUMMARY.md`（S5/S6 同形态）；本文 §7 追加实现状态。

## 6. 移交项（后续批次）

- DPoP 路线试点（前提=客户可改造 OAuth AS；ath/htu/cnf.jkt 校验链与 jwt_trust 融合设计另行评审）。
- 控制面批准的公钥同步通道；多签名标签；@target-uri 全形态；签名响应；机器身份↔对象所有权融合（apiauthz 联动评审）。
- 弱指纹独立调研（§12.3 核查清单：采集位置/隐私/许可证/误报）；mTLS 客户端证书链验证。
- 撤销传播节点 ACK 拓扑可视化；nonce 存储容量自动估算面板；24h 稳定性与兆芯性能全量报告（§14.2，与 ha-lab 演练矩阵合并编排）。

## 7. 实现状态

> 本节为实施记录区（S5/S6 同形态），不改上文契约。日期：2026-10-09（批次 C 联调验收出口）。

### 7.1 决策点落点表（D1~D14）

| # | 落点（文件:行） |
|---|---|
| D1 路线 | RFC 9421+9530+8941 自实现纯库 `gateway/dynamic_security/httpsig/`（零第三方依赖——§7.3-4 登记）；@authority=可信代理后 Host 原文、@path raw 不归一（`httpsig/verify.go:7-10` 逐字注释）；与 jwt_trust 并列叠加+principal_binding 一致性强校验（裁决 3 落点 `server/internal/guardconfig/machine_identities.go:184`，§7.3-1） |
| D2 登记模型 | 迁移 `server/migrations/000183_machine_identities.up.sql`（身份/键/水位单行）/`000184_machine_identity_bindings.up.sql`（绑定）；状态机+水位同事务 `server/internal/apimachineid/store.go:365`（只增 upsert+revoked_seq 回填键行） |
| D3 公钥导入 | 管理面静态离线导入唯一来源 `apimachineid/handler.go`（keys POST，PEM 服务端解析+指纹现算）；网关登记册精确查找 `detectors/machineid/registry.go`（keyid URL 形态不抓取——联调实证 MID-KEY-UNKNOWN 401）；热路径零网络 IO |
| D4 验证链 | `detectors/machineid/machineid.go:187`（Evaluate 十步固定序：解析→keyid→算法→键状态→时效→覆盖成分→目标绑定→体摘要→验签→重放，通过后范围核对；逐步 reason 词表冻结于 `machineid.go:60-79`） |
| D5 重放 | `httpsig/replay.go`（Valkey Lua SET NX PX 单次原子往返，`mid:v1:nonce:` 键+hash tag 同槽；返回值形态联调修正见 §7.3-2）；存储缺席 OBSERVE 放行披露/PROTECT 503（I03 故障注入实证）；严禁本机去重 |
| D6 轮换/撤销 | rotate 原子（新 ACTIVE+旧 RETIRED+重叠窗口）`apimachineid/store.go`；revoke 与水位 seq+1 同事务；网关水位回退拒载 `jiuzhang_guard/apimachineid.go:122`（MID_WATERMARK_REGRESSION fail-closed——I04 回滚实证 ROLLBACK_PUBLISH_FAILED+已撤销键不复活） |
| D7 防护协同 | VERIFIED 照过 WAF/CC/Bot/授权（I05 全链实证）；Bot 豁免三重显式消费点 `jiuzhang_guard/bot_step.go:119`（machineIDBotExempt——身份 exempt∩绑定命中∩VERIFIED，豁免事实进 MID_BOT_EXEMPT 事件） |
| D8 UNKNOWN 红线 | 登记册缺席/存储缺席/体不可读/验证器异常全五态如实+`id.coverage_v1`；OBSERVE 放行披露/PROTECT 503·413 不伪装证明错误（I03 Valkey 中断双节点 503+OBSERVE 200 披露逐格实证） |
| D9 预算 | 冻结常量 `httpsig/` DefaultBudgets（头 8KiB/成分 32/体 4MiB/验签每请求 1 次）；nonce 存储公式登记；全 OFF ≤2%+1ms 由 C01 零行为+存量回归不回退承载 |
| D10 错误语义 | `jiuzhang_guard/apimachineid.go:411`（401 固定短语 `{"error":"machine_identity_failed","request_id":...}` **不带 WWW-Authenticate**——`:338-339` 注释逐字）/`:417`（403 越界）；503 依赖/413 体预算；事件不落签名/nonce/公钥原文 |
| D11 能力门 | 自报恒报 `capability_report.go:106`（detectors.machineid=mid/1）；门 `gatewayconfig/capability_gate.go:74`（MachineIDProtect facts——任一 PROTECT 绑定 required mid/1 fail-closed；全 OBSERVE 零需求滚动升级——三态 stage5 实证） |
| D12 管理面 | 迁移 000183/000184；`apimachineid/routes.go` 12 端点（jwt_trust.read/manage 复用零新增权限，写操作 HIGH 审计）；发布三段 `guardconfig/machine_identities.go`+`provider.go:256`（loadAPIMachineIdentitySections）；OpenAPI +12 → 727 双向零差集 |
| D13 覆盖 | machineid 五态+`id.coverage_v1` 双承载（emitCoverage 各收口点）；新 reason COV_NO_REGISTRY 在册；NOT_APPLICABLE+MID-NA-UNSIGNED-001 联调实证（i01-na-coverage.json） |
| D14 接入契约 | 参照客户端 `test/waf/mid-e2e/`（sig1 单标签/必含成分/nonce 随机/窗口 ≤120s/Content-Digest sha-256 优先逐字实现；三算法+RS256 JWT mint 组合矩阵）；试点双应用 OBSERVE+PROTECT 联调全绿 |

### 7.2 验收矩阵结论（I01~I05，stage5 真实环境 2026-10-09）

证据目录 `output/evidence/mid-g1-20261009-035133/`（`all` 单轮全量：records.log 90 PASS 0 FAIL）。

| 用例 | 断言（设计 §4） | 结论与证据 |
|---|---|---|
| I01 有效证明/方法或 URI 变化 | 三算法有效签名通过+VERIFIED 在册+源站到达；改方法/路径/query/body → 401；RFC 9421 附录 B 黄金样本逐字节 | **PASS**：ed25519/ecdsa-p256/rsa-pss 各 200+X-Wdsp-Origin-Mark 源站到达+MID_VERIFIED 在册；篡改 method/path/query → 401 MID-SIGNATURE-INVALID、篡改 body → 401 MID-DIGEST-MISMATCH（裁决 1 集合断言生效）；多标签 → MID-SIGNATURE-MALFORMED；未签名 proof_required → 401（门禁语义 §7.3-5）；omit @path → MID-COVERAGE-INSUFFICIENT；kid URL 形态 → MID-KEY-UNKNOWN（不抓取）；过期/未来 created/寿命超限 → MID-PROOF-EXPIRED/MID-CLOCK-SKEW；OBSERVE 未签名放行 200+NOT_APPLICABLE/MID-NA-UNSIGNED-001 覆盖观测在册、OBSERVE 篡改放行+MID_OBSERVED 在册。黄金样本由 httpsig 单测承载（`go test ./httpsig/` 含附录 B 向量+fuzz+leak 绿） |
| I02 Token 与密钥绑定不符 | keyid 未登记/他身份/alg 不符/principal_binding 不一致 → 401 不升级可信机器身份；JWT 缺席机器身份独立成立 | **PASS**：principal_binding 录入 alice 指纹后——alice 200 放行/bob 401 MID-PRINCIPAL-MISMATCH（事件身份字段为空）/无 JWT 签名独立成立 200（不冒充人类主体）；k-ghost（未登记）与 k-dis（DISABLED 身份键不下发）均 401 MID-KEY-UNKNOWN；alg 声称 rsa-pss-sha512 与登记 ed25519 不符、词表外 hmac-sha256 均 401 MID-ALG-REJECTED；**裁决 3 线值实证**：autosave principal_binding=`871091b247c9ad35a76c665b57459d8f` == HMAC-SHA256(identity_salt,"jwt-principal:"+录入值）[:16]hex（autosave-i02.json） |
| I03 两节点重放/存储不可用 | A 收 nonce N → B 同 nonce 重放 401；停 Valkey PROTECT 双节点 503、OBSERVE 放行披露；恢复后正常 | **PASS**：gateway-b（compose 叠加实例，共享 autosave+共享 Valkey）配置收敛签名探针 200；固定 nonce A 200 → B 401 MID-REPLAY-DETECTED → 回本节点 A 401 MID-REPLAY-DETECTED（无一放行两次）；Valkey 键 `mid:v1:nonce:{a11000b4…}:bbc443b0…` EXISTS=1（hash tag 同槽在册）；停 Valkey → A/B 双节点 503+MID_UNAVAILABLE 事件、OBSERVE 应用 200+MID_OBSERVED 披露；恢复后双节点 200 |
| I04 撤销/轮换/回滚 | revoke 发布后 401 MID-KEY-REVOKED；rotate 窗口内新旧均过；回滚低水位快照拒载 fail-closed 且已撤销键不复活；旧节点能力门 fail-closed | **PASS**：撤销 k-rsa+发布 → 401 MID-KEY-REVOKED；轮换 k-ed→k-ed2 → RETIRED 窗口内旧键 200+新键 200，管理面读回 REVOKED+revoked_seq≥1/RETIRED+retire_overlap_until/ACTIVE（i04-identity.json）；回滚水位 0 快照 → 发布任务 **FAILED(ROLLBACK_PUBLISH_FAILED)**+网关 `MID_WATERMARK_REGRESSION … config load rejected (fail-closed)` 日志在册+回滚被拒后 k-rsa 仍 401（网关保留现行配置）；能力门三态见下（i04 断言与 capgate 合并实证） |
| I05 合法机器发起 WAF/CC/Bot 攻击 | VERIFIED 机器携 SQLi → WAF 照拦；超配额 → CC 照判；未豁免 VERIFIED 机器 → Bot 挑战照走；豁免且命中 → 豁免事件在册 | **PASS**：签名有效 SQLi → 403（CRS anomaly 在册 coraza-audit）且该请求 MID_VERIFIED 在册（签名有效不豁免 WAF）；CC（/submit limit 3/60s REJECT）5 个签名请求前 3×200 后 2×429（不豁免 CC）；Bot PROTECT /articles——k-bot 合格浏览器导航第 3 次 403 挑战+BOT_CHALLENGE_OFFERED 在册（照走挑战）；k-bx（exempt）3×200 直通+MID_BOT_EXEMPT 事件在册（三重显式成立） |

**能力门三态（stage5 实证）**：无 machineid 旧清单（exec 覆写共享卷注入保属主，S6 同纪律；真实清单入口一次快照防恢复源污染）→ 发布 **FAILED CAPABILITY_MISSING**：`CAP_MISSING:detectors.machineid(required=mid/1,actual=)`（不发送 /load，capgate-old-task.json）；五绑定全改 OBSERVE → 旧清单在位发布 **SUCCESS**（零需求滚动升级）；恢复真实清单（mid/1 恒报）+改回 PROTECT → 发布 **SUCCESS** 收载（环境已复原）。

**共用矩阵承接**：**C01**（无绑定应用 waf-s5.local /ping 未签名 → 200 普通流量+零 MID 事件——机器身份零行为 NG-T-C01）；**C04**（ALLOW 198.51.100.77+CC /download limit 1/60s：未签名 XFF 非白名单首发 401（MID-SIGNATURE-MALFORMED）→ 再发 429（CC 先于机器身份饱和实证——顺序：CC 计数在前）；XFF 白名单未签名仍 401（跳过 CC **不绕过**机器身份——serveNext 统一出口顺序实证））；**C09**（未认证 401；AUDIT_ADMIN 探针读 200/写 403（jwt_trust.read 三角色全授+manage 仅 SYSTEM/SECURITY_ADMIN 种子口径实证，§7.3-8）；写操作 HIGH 审计 ≥50 条在册 module=api_security）；**C02**（OBSERVE 全链放行有记录——I01/I03 OBSERVE 逐格）；存量回归 40/40、13/13 不回退。

### 7.3 联调新发现与修正（批次 C，逐条登记）

1. **裁决 3 principal_binding 发布域换算（已闭环，server 修正）**：管理面录入的是 JWT 事件可观测主体指纹（apiauthz 域 HMAC 第一层），网关消费侧比对 jwtverify 产出值域——两域裸值直传则 PROTECT 全误拒（跨轨指纹域不一致）。修正：`guardconfig/machine_identities.go:184` `machineIDPrincipalBindingFP`（HMAC-SHA256(identity_salt, "jwt-principal:"+录入值） 截前 16 字节 hex），装配完成后统一应用（`provider.go` loadAPIMachineIdentitySections 之后）；回滚快照携带换算后值、盐轮换即指纹重置（与 apiauthz 身份指纹同纪律）。单测 `TestMachineIDPrincipalBindingFP` 黄金值；联调线值实证（autosave-i02.json == python 复算）。
2. **重放 Lua 返回值形态跨轨不一致（已闭环，gateway 修正——批次 C 对批次 A 代码的联调修正，请编排者复核）**：`httpsig/replay.go` 原子脚本原 `return ... and 1 or 0` 产标量 int64，而共享装配通道 `counters.ValkeyClient.Eval` 契约只接受 array（`res.ToArray()`）→ 所有 PROTECT 请求 503 `replay_store_error: eval result not array`（联调首日全链实证）。修正为 `return {redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', tonumber(ARGV[2])) and 1 or 0}`（数组包裹，Redis 语义不变）；`httpsig/`+`machineid/` 单测复跑全绿，I03 双节点重放矩阵实证无一放行两次。教训登记：跨轨共享通道的 Lua 返回值形态应在线契约逐字冻结（S6 catalog_hash 分隔符同类）。
3. **RETIRED 窗口放行事件无 RETIRED 标注（登记，B2 遗留）**：轮换重叠窗口内旧键放行事件无 RETIRED 区分标注；窗口事实由管理面读回（keys[].status/retire_overlap_until，i04-identity.json）承载——如需事件侧直读属后续批网关侧增强。
4. **参照客户端 SF 库裁决（登记）**：`github.com/dunglas/httpsfv` 许可证核实 BSD-3-Clause（宽松红线通过），为保参照实现零第三方依赖启用设计 §4 兜底条款自实现最小 SF 子集（`test/waf/mid-e2e/sf.go`）——登记为允许的替代路径。
5. **未签名 401 语义定案（登记）**：proof_required 下未签名 → 401 `MID-SIGNATURE-MALFORMED`（网关门禁语义——准入策略判定非 UNKNOWN，机器身份无 401 专属 reason）；`MID-NA-UNSIGNED-001` 是 proof_required=false 的覆盖观测 NA 规则号——两断言在册互不冲突。
6. **CRS 共存纪律（联调新发现，参照客户端修正）**：PROTECT 应用下 ①Go 默认 UA `Go-http-client/1.1` 命中 CRS 913100 扫描器指纹（phase-1 CRITICAL 5 分 → 9000102 二次阻断评估 403）；②有体 POST 缺 Content-Type 命中 CRS 920340 CRITICAL（同路径 403——`Content-Length` 非零且无 Content-Type）。客户端修正：默认 UA `jiuzhang-mid-e2e/1.0 (RFC9421 reference client)`（诚实标识不冒充浏览器）+有体默认 `Content-Type: application/x-www-form-urlencoded`（CRS 允许清单内，`-ct` 可覆盖）。非网关/规则缺陷；同时反向佐证 I05「机器身份不豁免 WAF」判定成立。
7. **同 rid 多机器身份事件断言修正（联调脚本）**：MID_BOT_EXEMPT（bot 步 4.5 豁免点）与 MID_VERIFIED（apiprotect 统一放行出口）同一 request_id 并存——断言辅助 ev_mid 加事件类型过滤择行（原 tail -1 取末行误配）。
8. **ACL 授权口径实证（登记）**：000126 种子 jwt_trust.read 三角色（SYSTEM_ADMIN/SECURITY_ADMIN/AUDIT_ADMIN）全授、manage 仅前两者——SYSTEM_ADMIN 读 200 为**合规正向**（初版联调断言 403 系测试预期错误，已修正）；越权负向由未认证 401+AUDIT_ADMIN 一次性探针用户写 403 承载。探针用户删除为软删（status=DELETED 仍占用户名唯一约束）→ 探针名带时间戳幂等。
9. **环境适配（stage5，S6 纪律承接+三处新增）**：publish_patient 长退避吸纳身份/键/绑定写操作自动发布与显式发布竞态 LOCK_BUSY；login_patient 会话缓存+新增配对守卫（cookie jar 新于缓存即弃——CSRF token 绑定会话，外部再登录致缓存失配 403 联调实证）；能力门清单 exec 覆写注入保属主（docker cp root 化连锁先例）；gateway-b 叠加 compose（`deployment/docker-compose.stage5-mid.yml`）端口 **18083**（18082 本机占用避让）+独立 logs/admin/data 卷+共享 `stage5-gateway-config:/config`（autosave 同源）；覆盖观测异步落盘（响应返回后写入）→ 断言短轮询吸纳竞态。

### 7.4 已知限制与遗留

- §6 移交项原样：DPoP 路线试点、控制面批准的公钥同步通道、多签名标签、@target-uri 全形态、签名响应、机器身份↔对象所有权融合（apiauthz 联动评审）、弱指纹独立调研（§12.3 核查清单）、mTLS 客户端证书链验证。
- 撤销传播节点 ACK 拓扑可视化与 nonce 存储容量自动估算面板留移交；RETIRED 窗口事件标注（§7.3-3）如需事件侧直读随后续批增强。
- 性能候选门槛（§1.9/D9）正式双报告（普通 amd64+兆芯）与 24h 稳定性留 §6 移交（与 ha-lab 演练矩阵合并编排）。本批 stage5 冒烟（共享 docker 序贯 n=60，access.log duration 读数）：签名+验证全链 p50≈9.3ms/p95≈14.8ms vs 无绑定基线 p50≈1.1ms/p95≈1.7ms——增量含 apiprotect 全管线与 Valkey 重放往返，非 machineid 单步读数（单步 p99 2ms 预算由 httpsig/machineid 单测锚定，正式报告待双架构）。

### 7.5 批次与出口

批次 A（`gateway/dynamic_security/httpsig/` RFC 9421+9530+8941 纯库+黄金样本+fuzz+重放 Store）、B1（server 管理面+发布段：迁移 000183/000184、`apimachineid` 12 端点（jwt_trust.read/manage 零新增）、guardconfig/gatewayconfig 三段+capability_gate facts，OpenAPI +12 → 727 双向零差集）、B2（`detectors/machineid/` 十步验证链+`jiuzhang_guard/apimachineid.go` 装配（水位拒载/committed 直写错误语义）+bot_step 三重豁免+能力自报 mid/1 恒报+coverage 双承载）、批次 C（本批：参照客户端 `test/waf/mid-e2e/`（Go stdlib 三算法签名器+子命令集，零第三方依赖）+双网关叠加 `deployment/docker-compose.stage5-mid.yml`+驱动 `test/waf/mid-e2e/run-stage5.sh`+I01~I05 全过+能力门三态+C01/C04/C09+回归零回退+出口记录 `docs/nextgen/s7/S7-EXIT-SUMMARY.md`）。管理前端页面（身份列表/详情/导入/轮换/撤销/绑定管理）属批次 C web 轨另行交付。
