package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/flowguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/grpcguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/machineid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/mcpguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/gqlast"
	"github.com/jiuzhang-waf/gateway/dynamic_security/grpcdesc"
	"github.com/jiuzhang-waf/gateway/dynamic_security/httpsig"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/pipeline"
	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/accesscontrol"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/botchallenge"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/cidr"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/l7rules"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/riskengine"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/trustedproxy"
	"go.uber.org/zap"
)

// ---------- 配置 JSON 结构（与管理后端配置生成器约定一致） ----------

type proxyJSON struct {
	Name             string `json:"name"`
	CIDR             string `json:"cidr"`
	HeaderType       string `json:"header_type"`
	CustomHeaderName string `json:"custom_header_name,omitempty"`
	Priority         int    `json:"priority"`
}

type ruleJSON struct {
	ID             string `json:"id"`
	Address        string `json:"address"`
	Priority       int    `json:"priority"`
	EffectiveFrom  string `json:"effective_from,omitempty"`
	EffectiveUntil string `json:"effective_until,omitempty"`
}

type policyJSON struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Scope                string `json:"scope,omitempty"` // GLOBAL | APPLICATION
	Dimension            string `json:"dimension"`
	Algorithm            string `json:"algorithm"`
	URIMatchType         string `json:"uri_match_type"`
	URIPattern           string `json:"uri_pattern,omitempty"`
	RequestsLimit        int64  `json:"requests_limit"`
	WindowSeconds        int    `json:"window_seconds"`
	BurstCapacity        int64  `json:"burst_capacity,omitempty"`
	Action               string `json:"action"`
	BlockDurationSeconds int    `json:"block_duration_seconds,omitempty"`
	ObserveOnly          bool   `json:"observe_only,omitempty"`
	Priority             int    `json:"priority"`
	EffectiveFrom        string `json:"effective_from,omitempty"`
	EffectiveUntil       string `json:"effective_until,omitempty"`
}

type valkeyJSON struct {
	Address  string `json:"address"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	DB       int    `json:"db"`
}

// maskRuleJSON 响应脱敏规则（api_mask_rules 数组元素；与管理后端发布通道约定一致）。
// field_path 为点路径（数组段以 [] 结尾，如 users[].phone）；
// algorithm 取值 MASK|HASH|REMOVE|ENCRYPT|MAP，params 支持 keep_head/keep_tail/key_id/map_id。
type maskRuleJSON struct {
	EndpointKey string         `json:"endpoint_key"`
	FieldPath   string         `json:"field_path"`
	DataType    string         `json:"data_type,omitempty"`
	Algorithm   string         `json:"algorithm"`
	Params      map[string]any `json:"params,omitempty"`
}

// maskCryptoJSON ENCRYPT/MAP 密钥配置；key_hex 为 32 字节密钥的 hex，属于秘密材料。
type maskCryptoJSON struct {
	Kid    string `json:"kid"`
	KeyHex string `json:"key_hex"`
}

// scanVerificationJSON 扫描流量识别密钥（api_scan_verification 段；与管理后端发布通道约定一致）。
// key_hex 为 apiscan 签名密钥明文 hex（32 字节 / 64 字符）：秘密材料，不进日志与错误信息；
// 缺省/空 = 未下发，网关降级为仅按 X-JiuZhang-Scan 头存在性识别扫描流量（无法防伪造）。
type scanVerificationJSON struct {
	KeyHex string `json:"key_hex"`
}

// grpcDescriptorJSON gRPC 描述符集（api_grpc_descriptors 数组项；与管理后端发布通道约定一致）。
// content_base64 为 FileDescriptorSet 原始字节 base64（管理面 api_grpc_descriptors 表
// ENABLED 行，上传护栏 1MiB）；name 原样进入观测证据 descriptor 字段。
// json tag 为跨分片契约，不得改动。
type grpcDescriptorJSON struct {
	Name          string `json:"name"`
	ContentBase64 string `json:"content_base64"`
}

// fileWatermarkJSON 文件下载与可选内联 HTML 水印（api_file_watermark 段）。
// nil 或 enabled=false = 未下发/未启用，响应侧零行为变化；content_types/json_key
// 缺省由引擎默认表/"_wm" 兜底。include_inline_html 缺省 false，不改变普通网页行为。
type fileWatermarkJSON struct {
	Enabled           bool     `json:"enabled"`
	TextTemplate      string   `json:"text_template"`                 // 支持 {ip}/{identity}/{time}/{domain} 占位
	ContentTypes      []string `json:"content_types,omitempty"`       // 媒体类型白名单（缺省引擎默认表）
	JSONKey           string   `json:"json_key,omitempty"`            // JSON 顶层水印字段名（缺省 "_wm"）
	IncludeInlineHTML bool     `json:"include_inline_html,omitempty"` // 显式允许内联 HTML 网页水印
}

// fileSignatureJSON 文件签名 v1（api_file_signature 段；与管理后端发布通道约定一致）。
// key_hex 为签名密钥明文 hex（32 字节 / 64 字符）：秘密材料，不进日志与错误信息；
// nil 或 enabled=false = 未下发/未启用，响应侧零行为变化。json tag 为跨分片契约，不得改动。
type fileSignatureJSON struct {
	Enabled bool   `json:"enabled"`
	KID     string `json:"kid"`     // 密钥标识（token 第二段；轮换追踪）
	KeyHex  string `json:"key_hex"` // 32 字节签名密钥的 hex 编码（64 字符）
}

// Guard 是九章访问控制与CC防护 Caddy HTTP 处理器模块。
type Guard struct {
	// 应用标识（事件归属与 CC 维度）
	AppID   string `json:"app_id"`
	AppCode string `json:"app_code"`

	// 部署模式：REVERSE_PROXY（默认，缺省）/ ROUTED（路由牵引，真实客户端 IP 取直连对端，
	// 由发布侧保证此时 trusted_proxies 为空；本字段仅作识别与事件归因）
	DeploymentMode string `json:"deployment_mode,omitempty"`

	// 真实IP识别
	TrustedProxies []proxyJSON `json:"trusted_proxies,omitempty"`
	MaxProxyChain  int         `json:"max_proxy_chain,omitempty"`

	// 保护地址（永不封禁）
	ProtectedAddresses []string `json:"protected_addresses,omitempty"`

	// 黑白名单（本路由应用视角：全局 + 本应用）
	GlobalAllow []ruleJSON `json:"global_allow,omitempty"`
	GlobalDeny  []ruleJSON `json:"global_deny,omitempty"`
	AppAllow    []ruleJSON `json:"app_allow,omitempty"`
	AppDeny     []ruleJSON `json:"app_deny,omitempty"`

	// CC 策略（全局 + 本应用，发布时已过滤）
	RateLimits []policyJSON `json:"rate_limits,omitempty"`

	// 授权配额全局限速（license_max_qps，每秒请求数；发布通道在授权有效且配额>0 时注入，
	// 0=不限制）。生效时请求在 CC 策略之前共用固定键 "license:global" 令牌桶：
	// Valkey 后端跨节点共享，memory 后端每进程独立；超限 429（Retry-After），不产生 CC 事件
	LicenseMaxQPS int `json:"license_max_qps,omitempty"`

	// 自定义 429/阻断响应页面（阶段5 §5.1；发布通道下发 block_response 段，
	// 全产品形态不受 WDSP 门控；nil 或全空 = 内置默认模板，与历史版本逐字节一致；
	// 装配期校验大小硬上限并白名单净化 HTML 正文，见 blockresponse.go）
	BlockResponse *blockResponseJSON `json:"block_response,omitempty"`

	// L7 访问控制规则（发布通道下发；nil 或空 = 未配置，零行为变化）
	L7Rules *l7rules.Config `json:"l7_rules,omitempty"`

	// 计数后端：memory | valkey（默认 valkey，失败按 FailOpen 策略）
	CounterBackend string `json:"counter_backend,omitempty"`
	// 内存计数器键上限（0 = 默认值；Validate 限定 [0, maxCounterKeysLimit]——
	// 内存实现按该值预分配 map，异常大值会在 Provision 阶段 OOM 杀进程）
	MaxCounterKeys int `json:"max_counter_keys,omitempty"`

	// Valkey 连接（临时封禁与共享计数）
	Valkey *valkeyJSON `json:"valkey,omitempty"`

	// 故障策略：默认 true（Fail-open），false 为 Fail-closed
	FailOpen *bool `json:"fail_open,omitempty"`

	// 临时封禁轮询间隔（默认 1s）
	TempBlockPollInterval string `json:"temp_block_poll_interval,omitempty"`

	// 事件输出
	EventsLog   string `json:"events_log"`
	GatewayNode string `json:"gateway_node,omitempty"`

	// API 动态防护（WDSP / 阶段8）：默认关闭，关闭时零行为变化
	APIDynamicProtection bool   `json:"api_dynamic_protection,omitempty"`
	APIProtectionMode    string `json:"api_protection_mode,omitempty"` // OFF | OBSERVE | PROTECT（启用时缺省 OBSERVE）
	APIEventsLog         string `json:"api_events_log,omitempty"`      // 缺省与 events_log 同目录 api-runtime-events.log
	// 冻结正式模型（发布通道下发）：endpoint_key → 字段名 → 期望类型
	APIFormalSchemas map[string]map[string]string `json:"api_formal_schemas,omitempty"`
	// FORMAL 端点请求侧确认参数约束（发布通道下发）：endpoint_key → 参数约束列表
	APIParameterConstraints map[string][]detectors.ParamConstraint `json:"api_parameter_constraints,omitempty"`
	// 已知 API 端点基线（发布通道下发）：endpoint_key → asset_status，供生命周期检测（新端点/DEPRECATED 调用）
	APIKnownEndpoints map[string]string `json:"api_known_endpoints,omitempty"`
	// API 准入策略（WDSP P1，发布通道下发 api_admission 段；nil = 未下发，准入检测零行为）。
	// 键为 application_id（endpoint_key 非全局唯一，按应用分组规避同键冲突）；
	// mode 词表 OFF/OBSERVE/PROTECT，词表外/缺失 fail-safe 视为 OFF（不启用不拦截——
	// 不拦截优于误拦截；与 api_protection_mode 非法值拒载的硬校验刻意不同，故
	// Validate 不对本段报错，归一在 Provision 编译期完成并 Warn 留痕）
	APIAdmissionPolicies *apiAdmissionSectionJSON `json:"api_admission,omitempty"`
	// GraphQL 成本预算策略（NG-GQL-03，发布通道下发 api_graphql 段；nil = 未下发，
	// GraphQL 流量与历史版本零行为变化）。键为 application_id；数值非法在 Provision
	// 归一走引擎默认并 Warn 留痕（fail-safe 与 api_admission 同形态，不拒载）
	APIGraphQLPolicies *apiGraphQLSectionJSON `json:"api_graphql,omitempty"`
	// 写方法 API 每分钟限速（缺省 60，由引擎默认值兜底）
	APIWriteRatePerMinute int `json:"api_write_rate_per_minute,omitempty"`
	// 阶段8 §36 限流下发面（发布通道下发；0/缺省 = 对应检测不启用，不走引擎默认值
	// 冒充已配置——与上方三个限流键的默认兜底语义刻意不同）：
	// APIQuotaPerHour 身份+端点每小时配额（定窗）；APIQuotaPerDay 每日配额（UTC 自然日定窗）；
	// ObjectRatePerMinute 同身份对同对象每分钟上限；CredentialRatePerMinute 同凭据自然分钟窗口上限；
	// TenantRatePerMinute 可信 JWT 租户自然分钟窗口上限；ActionRatePerMinute 应用内操作动作窗口上限；
	// GroupRatePerMinute 应用内业务功能接口组窗口上限；MaxPageSize/MaxBatchSize 分页与批量上限
	APIQuotaPerHour         int `json:"api_quota_per_hour,omitempty"`
	APIQuotaPerDay          int `json:"api_quota_per_day,omitempty"`
	ObjectRatePerMinute     int `json:"object_rate_per_minute,omitempty"`
	CredentialRatePerMinute int `json:"credential_rate_per_minute,omitempty"`
	TenantRatePerMinute     int `json:"tenant_rate_per_minute,omitempty"`
	ActionRatePerMinute     int `json:"action_rate_per_minute,omitempty"`
	// APIEndpointActions 发布下发的 endpoint_key → ACTION 表；仅表内端点参与动作限速
	APIEndpointActions map[string]string `json:"api_endpoint_actions,omitempty"`
	GroupRatePerMinute int               `json:"group_rate_per_minute,omitempty"`
	// APIEndpointGroups application_id → endpoint_key → []group_code；嵌套隔离应用，禁止拍平合并
	APIEndpointGroups map[string]map[string][]string `json:"api_endpoint_groups,omitempty"`
	// APIRateLimitAction 限速处置：空=RATE_LIMIT，可选 BLOCK/TEMP_BLOCK；APITempBlockSeconds 0=60 秒
	APIRateLimitAction  string `json:"api_rate_limit_action,omitempty"`
	APITempBlockSeconds int    `json:"api_temp_block_seconds,omitempty"`
	MaxPageSize         int    `json:"max_page_size,omitempty"`
	MaxBatchSize        int    `json:"max_batch_size,omitempty"`
	// API 响应脱敏规则（发布通道下发；仅 API 流量 + 完整捕获的 JSON 响应生效）
	APIMaskRules []maskRuleJSON `json:"api_mask_rules,omitempty"`
	// APIMaskCrypto ENCRYPT/MAP 密钥；nil = 未配置（含这两种算法时拒绝加载）
	APIMaskCrypto *maskCryptoJSON `json:"api_mask_crypto,omitempty"`
	// 值级敏感检测规则（发布通道下发 api_sensitive_value_rules；对应管理面
	// api_sensitive_data_types 表 ENABLED 且 regex 非空的类型；nil/空 = 关闭值级检测，零行为变化）
	APISensitiveValueRules []detectors.SensitiveValueRule `json:"api_sensitive_value_rules,omitempty"`
	// 角色功能级基线（发布通道下发 api_role_baselines；对应管理面 api_role_baselines 表 confirmed 行；
	// nil/空 = 无端点基线，BFLA 检测零行为）
	APIRoleBaselines []detectors.RoleBaseline `json:"api_role_baselines,omitempty"`
	// 对象授权快照（发布通道下发；OWNER 或 ANY_OF=OWNER/SHARED_WITH，OBSERVE/PROTECT）。
	// 模型/关系中的对象标识仅用于运行时匹配，事件只保留 HMAC objref。
	APIAuthzModels            []detectors.ObjectModel          `json:"api_authz_models,omitempty"`
	APIAuthzRelations         []detectors.ObjectRelation       `json:"api_authz_relations,omitempty"`
	APIAuthzRoleBaselines     []detectors.VerifiedRoleBaseline `json:"api_authz_role_baselines,omitempty"`
	APIAuthzObjectHMACKeyHex  string                           `json:"api_authz_object_hmac_key_hex,omitempty"`
	APIAuthzObjectHMACKey     []byte                           `json:"-"`
	APIAuthzSnapshotStale     bool                             `json:"api_authz_snapshot_stale,omitempty"`
	APIAuthzSnapshotExpiresAt *time.Time                       `json:"api_authz_snapshot_expires_at,omitempty"`
	APIAuthzPreviousValid     *authzSnapshotJSON               `json:"api_authz_previous_valid,omitempty"`
	// ---- NG-AZ-02 v2 快照元数据（omitempty；缺失即 v1，D4-3 兼容）----
	// APIAuthzSchema 快照 schema 闸门（D4-3）：存在即 "authz-snap/2"
	APIAuthzSchema string `json:"api_authz_schema,omitempty"`
	// APIAuthzRevocationWatermark 编译时刻管理面向量撤销水位（D1/D2；D4-1 回退拒绝输入）
	APIAuthzRevocationWatermark *authzWatermarkJSON `json:"api_authz_revocation_watermark,omitempty"`
	// APIAuthzConflictedObjects 决策侧排除集（D7）
	APIAuthzConflictedObjects []authzConflictedObjectJSON `json:"api_authz_conflicted_objects,omitempty"`
	// APIAuthzProducedAt 快照编译时刻（D8 漂移自检基准）
	APIAuthzProducedAt *time.Time `json:"api_authz_produced_at,omitempty"`
	// APIAuthzLeaseSeconds per-app 租约秒数（D5；0=未启用；解析夹紧 15~300）
	APIAuthzLeaseSeconds int `json:"api_authz_lease_seconds,omitempty"`
	// APIAuthzClockSkewMaxSeconds 时钟漂移上限秒数（D8；0=缺省 60；解析夹紧 10~300）
	APIAuthzClockSkewMaxSeconds int                            `json:"api_authz_clock_skew_max_seconds,omitempty"`
	apiAuthzPreviousValid       *detectors.AuthorizationConfig `json:"-"`
	// 字段权限（发布通道下发 api_field_permissions；对应管理面 api_field_permissions 表行；
	// nil/空 = 无字段权限基线，Mass Assignment 检测零行为；响应方向行本波运行时不判定）
	APIFieldPermissions []detectors.FieldPermission `json:"api_field_permissions,omitempty"`
	// 扫描流量识别密钥（发布通道下发 api_scan_verification；apiscan 签名密钥明文 hex；
	// nil/空 = 未下发，仅按 X-JiuZhang-Scan 头存在性识别扫描流量，无法防伪造）
	APIScanVerification *scanVerificationJSON `json:"api_scan_verification,omitempty"`
	// 响应结构基线（发布通道下发 api_response_baselines；对应管理面 api_response_schemas 表
	// sample_count≥20 学习行；nil/空 = 无端点基线，响应偏离检测零行为）
	APIResponseBaselines []detectors.ResponseBaseline `json:"api_response_baselines,omitempty"`
	// 已确认参数条件关系（发布通道下发 api_parameter_relations；对应管理面
	// api_parameter_relations 表 confirmed=true 行；nil/空 = 无端点关系，关系检测零行为）
	APIParameterRelations []detectors.ParamRelation `json:"api_parameter_relations,omitempty"`
	// 业务流程基线（发布通道下发 api_flow_baselines，阶段8 §44；对应管理面
	// api_flow_baselines 表 enabled 行；nil/空 = 无端点流程基线，流程偏离检测零行为；
	// 装配期经 detectors.ValidateFlowBaselines 校验，非法基线拒绝加载，不静默吞错；
	// 运行期全部明细 OBSERVE 级只 AddMatch 不定案）
	APIFlowBaselines []detectors.FlowBaseline `json:"api_flow_baselines,omitempty"`
	// 强流程定义（NG-FLOW-01，docs/nextgen/NG-FLOW-strong-flow.md §1.1；发布通道下发
	// api_strong_flows 段：定义+步骤数组随快照下发，仅 status=ACTIVE；对应管理面
	// api_strong_flow_definitions/steps 表。nil/空数组 = 零行为（NG-T-C01：管线零行为、
	// 无新日志、无新状态）；装配期经 flowguard.BuildRegistry 全量校验（§1.1 冻结规则
	// 逐条，与 server 侧同口径双保险 + 版本不可变断言），非法定义拒绝加载 fail-closed，
	// 不静默吞错；与既有流程观察（api_flow_baselines）并行共存互不消费。
	// 本批（FLOW-01）仅解析/校验/装配，运行时判定属 FLOW-02，不接入请求链）
	APIStrongFlows []flowguard.Definition `json:"api_strong_flows,omitempty"`
	// 已吊销凭据清单（发布通道下发 api_revoked_credentials，阶段8 §35 第10项；对应管理面
	// api_revoked_credentials 表当前生效行；nil/空 = 无吊销清单，吊销检测零行为；
	// 装配期经 detectors.ValidateRevokedCredentials 校验，非法清单拒绝加载，不静默吞错；
	// 载荷仅指纹级（类型 + 32 位 hex 指纹），无凭据明文；运行期 OBSERVE 级只 AddMatch 不定案）
	APIRevokedCredentials []detectors.RevokedCredential `json:"api_revoked_credentials,omitempty"`
	// LLM 授权模型名单（发布通道下发 api_llm_allowed_models；来源 system_settings
	// gateway_runtime 组逗号分隔键；nil/空 = 不下发不判定未授权模型，
	// 与 LLM 端点识别/观测解耦——识别与观测不依赖本名单）
	APILLMAllowedModels []string `json:"api_llm_allowed_models,omitempty"`
	// APILLMSecurityPolicies LLM 输入保护策略（按 application_id 归组；nil/空 = 保持既有行为）
	APILLMSecurityPolicies []detectors.LLMSecurityPolicy `json:"api_llm_security_policies,omitempty"`
	// 响应侧处理失败策略：FAIL_OPEN（默认：跳过转换 + zap Warn，原响应放行）| FAIL_CLOSED
	// （端点有命中规则但响应无法安全处理时，以 500 空明细响应抑制原响应，防未脱敏数据外发）
	APIResponseFailPolicy string `json:"api_response_fail_policy,omitempty"`
	// 文件下载水印 v1（W12-GW / P2-01 最小可行子集；发布通道下发 api_file_watermark；
	// nil 或 enabled=false = 零行为变化）：文本族/JSON 的 Content-Disposition 下载响应
	// 在文件尾追加不可见水印标记 / JSON 顶层加 "_wm" 字段；失败一律 FAIL_OPEN 直通
	APIFileWatermark *fileWatermarkJSON `json:"api_file_watermark,omitempty"`
	// 文件签名 v1（W13-GW / P2-02；发布通道下发 api_file_signature；nil 或 enabled=false =
	// 零行为变化）：文本族/JSON 下载响应在水印之后嵌入 jzsig1 来源追踪 token
	// （文本注释行 / JSON 顶层 "_sig" 字段）；失败一律 FAIL_OPEN 直通
	APIFileSignature *fileSignatureJSON `json:"api_file_signature,omitempty"`
	// 文件合规规则（W13-GW / P2-03；发布通道下发 api_file_compliance_rules；对应管理面
	// api_file_compliance_rules 表 enabled 行；nil/空 = 合规检测零行为）：
	// 上传 multipart 与下载 Content-Disposition 观测按 EXT/MIME/文件名 RE2 评估，
	// BLOCK 动作 PROTECT 上传 403、下载抑制已缓冲响应为 403
	APIFileComplianceRules []detectors.FileComplianceRule `json:"api_file_compliance_rules,omitempty"`
	// 策略版本戳（发布通道下发；原样写入事件 policy_version，溯源"当时生效哪版策略"）
	APIPolicyVersion string `json:"api_policy_version,omitempty"`
	// 节点心跳周期秒数（W17-HB：0=关闭，缺省；开启范围 30-300）。周期向 API 事件日志写
	// 合成心跳记录（gateway_node/policy_version/模型版本摘要数/运行时长），供管理面节点
	// 活性与版本视图在无业务流量时仍保持真实；依赖 API 动态防护事件通道，
	// 仅 api_dynamic_protection 开启时生效
	APINodeHeartbeatSeconds int `json:"api_node_heartbeat_seconds,omitempty"`
	// API 响应捕获上限（字节；0 = 默认 1048576；上限 16 MiB 防内存误配）
	APIResponseCaptureMaxBytes int `json:"api_response_capture_max_bytes,omitempty"`
	// API 响应体采样比例：nil = 未下发（默认 1）；0 = 不解析；(0,1) 仅对超大响应确定性前缀采样。
	// 使用指针保留显式 0，避免 omitempty 将其与未配置混同。
	APIResponseSampleRatio *float64 `json:"api_response_sample_ratio,omitempty"`
	// gRPC 单帧声明长度上限（W14-GW / P2-05；字节；0 = 默认 4 MiB；上限 64 MiB 防内存误配；
	// 发布通道经 gateway_runtime 组 api_grpc_max_frame_bytes 下发）
	APIGRPCMaxFrameBytes int `json:"api_grpc_max_frame_bytes,omitempty"`
	// gRPC 压缩帧许可（W14-GW / P2-05；发布通道经 gateway_runtime 组 api_grpc_allow_compression
	// 下发）。指针三态（NG-GRPC G1 D5）：nil = 未下发——现状 grpc 检测器维持 false 二态
	// （压缩标志位置位产 grpc.unexpected_compression OBSERVE 不解），grpcguard 按 G1 默认
	// true 允许 gzip 并深检；显式 false 两检测器同维持现状二态；显式 true 允许解压深检
	APIGRPCAllowCompression *bool `json:"api_grpc_allow_compression,omitempty"`
	// gRPC 描述符集（W14-DESC / P2-05 深化；发布通道下发 api_grpc_descriptors；
	// 对应管理面 api_grpc_descriptors 表 ENABLED 行；nil/空 = 无描述符，
	// gRPC 处理与 v1 完全一致：仅帧结构校验与计数观测，不做字段级解析）
	APIGRPCDescriptors []grpcDescriptorJSON `json:"api_grpc_descriptors,omitempty"`
	// gRPC 描述符 per-app 绑定（NG-GRPC G1 批次 B2，发布通道下发 api_grpc_bindings；
	// 对应管理面 api_grpc_descriptor_bindings 表行；nil/空 = 空绑定=全局生效（现状语义）。
	// 应用存在任一绑定行时该应用只用其绑定集编译的注册表——同名服务跨应用不错配；
	// 服务名精确匹配（大小写敏感——proto 全限定名语义；server B1 词表偏差登记备查，
	// 消费侧不做归一化放宽）；mode 词表 OBSERVE|PROTECT 缺省 OBSERVE（词表外 fail-safe
	// 归一 OBSERVE + Warn，与 api_admission 同纪律不拒载）；装配期经 buildGRPCGuardConfig
	// 归一，无描述符且无绑定 = grpcguard 零行为 NG-T-C01）
	APIGRPCBindings []grpcBindingJSON `json:"api_grpc_bindings,omitempty"`
	// MCP 工具目录（NG-MCP G1 批次 B2，发布通道下发 api_mcp_tool_catalogs；
	// 对应管理面 mcp_tool_catalogs/mcp_catalog_tools 表（发布段只含 APPROVED 工具行）；
	// nil/空 = 无目录；装配期 catalog_hash 重算比对，不符即整目录拒装（Warn + 其绑定
	// 运行期 SKIPPED(COV_NO_CATALOG) 放行不误断——不消费未验证摘要的目录）。
	// 与 api_mcp_bindings 同缺 = mcpguard 零行为 NG-T-C01）
	APIMCPToolCatalogs []mcpCatalogJSON `json:"api_mcp_tool_catalogs,omitempty"`
	// MCP 绑定（发布通道下发 api_mcp_bindings；对应管理面 mcp_catalog_bindings 表行；
	// 绑定驱动识别——endpoint_path 精确匹配大小写敏感；mode 词表 OBSERVE|PROTECT
	// 缺省 OBSERVE（词表外 fail-safe 归一 OBSERVE + Warn）；装配期经
	// buildMCPGuardConfig 归一）
	APIMCPBindings []mcpBindingJSON `json:"api_mcp_bindings,omitempty"`
	// 机器身份（NG-ID G1 批次 B2，发布通道下发三段——对应管理面 machine_identities/
	// machine_identity_keys/machine_identity_bindings/machine_identity_revocation_watermark
	// 表；机器身份是可选叠加能力：缺省 OFF，三段全缺 = 全链零行为 NG-T-C01。
	// 装配 fail-safe 归一（mode 词表外→OBSERVE+Warn、字段空缺跳行+Warn、公钥 PEM
	// 解析失败行拒装+Warn）；含 PROTECT 绑定时任何装配缺陷拒绝整体配置加载
	// （fail-closed，jwt_trust 同纪律）；快照水位低于已应用水位拒载（§1.6）
	APIMachineIdentities []machineIdentityJSON `json:"api_machine_identities,omitempty"`
	// 机器身份绑定（应用×selector（path_exact|path_prefix 二选一）×mode×
	// proof_required（true=未签名请求拒绝 401——准入策略判定非 UNKNOWN））
	APIMachineIDBindings []machineIDBindingJSON `json:"api_machine_identity_bindings,omitempty"`
	// 机器身份元数据（撤销水位+注册表版本——单调不下降承载）
	APIMachineIDMeta *machineIDMetaJSON `json:"api_machine_identity_meta,omitempty"`
	// FORMAL 模型版本（发布通道下发）：endpoint_key → 版本号；命中时写入事件 model_version
	APIFormalModelVersions map[string]string `json:"api_formal_model_versions,omitempty"`
	// 身份/来源指纹 HMAC 盐（identity_salt）：缺省时指纹未加盐（以固定域分隔前缀代替），启动 Warn 一次
	IdentitySalt string `json:"identity_salt,omitempty"`
	// APIIdentityBlocks 身份封禁名单（identity_key → 记录 ID；nil/空 = 不启用，零行为变化）
	APIIdentityBlocks []identityBlockJSON `json:"api_identity_blocks,omitempty"`
	// 同凭据跨 IP 跳变阈值（滑窗 1 分钟 distinct IP 数；缺省 3，由引擎默认值兜底）
	CredentialIPSpreadLimit int `json:"credential_ip_spread_limit,omitempty"`
	// 同凭据并发度阈值（in-flight 请求数；缺省 8，由引擎默认值兜底）
	CredentialConcurrencyLimit int `json:"credential_concurrency_limit,omitempty"`

	// 行为计数存储（docs/API_MICRO_MODELS.md §四第 9 项）：memory | valkey（默认 memory，零行为变化）。
	// valkey 复用共享引擎 Valkey 连接（需配置 valkey 块且引擎已建连），跨节点共享滑窗/游标；
	// 运行期 Valkey 故障由 behaviorstore 实现内 Fail-open 回退进程内存并告警，检测语义不中断。
	BehaviorStore string `json:"behavior_store,omitempty"`
	// 行为计数 Valkey 键 TTL（秒）：0 或小于内置下限时按内置下限
	// （滑窗 720s、distinct IP 集合 120s、对象游标 3600s、并发计数 300s）。
	BehaviorStoreTTLSeconds int `json:"behavior_store_ttl_seconds,omitempty"`

	// 身份与行为防护（AI 自动化渗透防护增强 阶段1；发布通道下发 identity_behavior；
	// nil 或 enabled=false = 零行为变化；本阶段全部信号仅 OBSERVE，不拦截）
	IdentityBehavior *identityBehaviorJSON `json:"identity_behavior,omitempty"`
	// 身份事件日志（缺省与 events_log 同目录 identity-events.log）
	IdentityEventsLog string `json:"identity_events_log,omitempty"`

	// 身份风险策略（AI 自动化渗透防护增强 阶段3：Risk Engine + Enforcement；发布通道下发
	// risk_policy，与 identity_behavior 同级；nil 或 enabled=false = 零行为变化。
	// OBSERVE 只记录"假设会处置"事件不实断；PROTECT 按阈值 403/429；
	// 任何配置缺失/非法 fail-open 按 OBSERVE——绝不据非法配置实断）
	RiskPolicy *riskPolicyJSON `json:"risk_policy,omitempty"`
	// RiskPolicyOverrides 按应用覆盖风险策略；未配置的应用沿用 RiskPolicy。
	RiskPolicyOverrides []riskPolicyOverrideJSON `json:"risk_policy_overrides,omitempty"`

	// JWT 信任链策略（WDSP P0-03；发布通道下发 jwt_trust 处理器段，仅 WDSP 开启时；
	// 缺省 = 未下发，零行为变化。本段是 guard 配置「容忍未知字段」惯例的显式例外：
	// 严格解码，未知字段/不支持的 schema_version/未知 mode 强制语义一律拒绝加载
	// （fail-closed，任务书 JWT-14）——旧节点不得把未知强制语义静默忽略当作安全回退。
	// 原始 JSON 保留，装配期经 parseJWTTrustSection 严格解码后转 jwtverify.Policy）
	JWTTrust json.RawMessage `json:"jwt_trust,omitempty"`

	// API 受限例外（WDSP P0-04；发布通道下发 api_exceptions 段，key=应用编码；
	// 缺省 = 未下发，零行为变化。与 jwt_trust 同一 fail-closed 纪律：严格解码 +
	// 全量校验，schema_version 不支持/未知字段/范围非法一律拒绝加载——旧节点不得
	// 把不理解的内容静默忽略当作安全回退。原始 JSON 保留，装配期经
	// ParseAPIExceptionsSection 严格解码；运行时每请求经 FilterAPIExceptions 范围
	// 筛选后传入决策引擎 Finding 级豁免重算，命中写 disposition.matched_exceptions）
	APIExceptions json.RawMessage `json:"api_exceptions,omitempty"`

	// Bot 挑战策略（WDSP P1-02 B1；发布通道下发 bot_policy 处理器段，仅 WDSP 开启时；
	// 缺省 = 未下发，零行为变化。与 jwt_trust 同一 fail-closed 纪律：严格解码 +
	// 全量校验，非法配置拒绝加载——本段携带 PROTECT 强制语义，不采用 risk_policy 的
	// 消毒 fail-open。B1 仅解析/校验/装配，不接入请求链；挑战/verify/Eval 属 B2/B3。
	// 原始 JSON 保留，装配期经 parseAndValidateBotPolicy 严格解码）
	BotPolicy json.RawMessage `json:"bot_policy,omitempty"`

	// 全量访问日志（二期）：默认关闭（nil 或 enabled=false 时零行为变化）
	AccessLog *accessLogJSON `json:"access_log,omitempty"`

	// W3C trace 外部上下文信任开关（APM 阶段1，ADR D5）：默认 false——总是新建 trace_id，
	// 不信任外部 traceparent；true 且外部 traceparent 严格校验通过时续接其 trace_id
	// （span_id 仍重新生成）。无论开关：不向客户端返回 trace_id/tracestate；
	// 是否向上游注入 traceparent 由 trace_inject_upstream 决定（默认不注入）。
	TraceTrustExternal bool `json:"trace_trust_external,omitempty"`

	// W3C traceparent 上游注入开关（APM 阶段2 Agent 模式前提，ADR D6）：默认 false——
	// 发往源站的请求字节与阶段1 完全一致（零行为变化）；true 时放行链路（serveNext
	// 统一放行出口，前置拦截分支到不了上游）在进入下游（WAF/反向代理）前写请求头
	// traceparent: 00-<trace_id>-<span_id>-01——一律覆盖入站外部值（不透传外部
	// span_id）并清除 tracestate（跨信任域清理，ADR D5-3）。
	TraceInjectUpstream bool `json:"trace_inject_upstream,omitempty"`

	// HTTP 头合规与代理配置（阶段8；默认关闭，零行为变化）
	// 注：下划线请求头由 Caddy 内核在处理器链之前强制丢弃（GHSA-f59h-q822-g45g），
	// 模块无法观测也无需再拦截，故不提供配置项。
	RedirectPortRewrite int `json:"redirect_port_rewrite,omitempty"` // 0=关闭；>0 改写 302 Location 显式端口为该值；80=剥离端口

	// DebugCCCounter CC 计数调试回显端点开关（阶段5 §十七 发布后冒烟 CC_EXACT 探针；
	// 见 debug_cccounter.go）：缺省 false = 零行为变化，/_wdsp/debug/v1/ 前缀不抢占
	// 业务路径；true 时该前缀本地处理（绝不反向代理），cc-counter 仅允许本机/内网
	// 连接源（按 TCP 连接对端判定，XFF 不可伪造），端点请求先于 CC 步骤挂接、
	// 本身不计入 CC 计数（探针自污染防控）
	DebugCCCounter bool `json:"debug_cc_counter,omitempty"`

	// PublishSmoke 单次发布的独立 HMAC 认证材料（见 publish_smoke.go）。与 Bot、
	// API 授权等密钥完全分离；nil 时精确内部端点仍本地拒绝，不落入源站。
	PublishSmoke *publishSmokeJSON `json:"publish_smoke,omitempty"`

	// 运行时
	logger         *zap.Logger
	resolver       clientip.Resolver
	proxies        *trustedproxy.Set
	protected      *cidr.Matcher
	allowG         *accesscontrol.RuleSet
	allowA         *accesscontrol.RuleSet
	denyG          *accesscontrol.RuleSet
	denyA          *accesscontrol.RuleSet
	policies       []*compiledPolicy
	l7             *l7rules.Engine // L7 访问控制编译结果（nil = 未配置）
	events         *events.Logger
	apiEvents      *apievents.Logger
	apiEventsClose func() error // 测试注入钩子；生产路径为空时直接关闭 apiEvents
	accessLog      *accessLogWriter
	engine         *sharedEngine
	failOpen       bool                   // 本实例故障策略（Provision 时确定，配置重载即可切换）
	blockResponse  *compiledBlockResponse // 自定义 429/阻断响应（Provision 编译；nil = 内置默认模板）
	heartbeat      *heartbeatRunner       // 节点心跳（nil = 关闭；Cleanup 停止并等待退出）

	behaviorStores            *detectors.StoreOverrides     // 按 BehaviorStore 构建（nil = 进程内默认内存）
	apiIdentityBlocks         map[string]string             // 按 APIIdentityBlocks 编译（identity_key → 记录 ID）
	ibh                       *identitybehavior.Engine      // 身份与行为防护引擎（nil = 未启用，请求链路零变化）
	risk                      *riskengine.Engine            // 全局身份风险引擎（nil = risk_policy 未启用）
	riskOverrides             map[string]*riskengine.Engine // 按应用覆盖；map 中 nil 表示显式停用
	sharedDeviceAccountLimits map[string]int                // 按应用群控观察阈值；缺省使用检测器默认值
	cleaned                   bool                          // Cleanup 幂等标记（只关资源不置 nil 字段，见 Cleanup 注释）
	cleanupErr                error
	apiMaskRules              map[string][]response.MaskRule          // 按 APIMaskRules 编译（endpoint_key 归组；nil = 无规则）
	apiMaskCrypto             *response.MaskCrypto                    // 按 APIMaskCrypto 编译（nil = 未配置；密钥不导出）
	apiRoleBaselines          map[string][]detectors.RoleBaseline     // 按 APIRoleBaselines 归组（endpoint_key；nil = 无基线）
	apiAuthzRelationIndex     map[string][]detectors.ObjectRelation   // 按应用/对象类型/对象引用索引（nil = 无关系）
	apiFieldPerms             map[string][]detectors.FieldPermission  // 按 APIFieldPermissions 归组（endpoint_key；nil = 无权限行）
	apiScanKey                []byte                                  // 按 APIScanVerification 解码（nil = 未下发，仅存在性识别；秘密材料不落日志）
	apiRespBaselines          map[string][]detectors.ResponseBaseline // 按 APIResponseBaselines 归组（endpoint_key；nil = 无基线，偏离检测零行为）
	apiParamRelations         map[string][]detectors.ParamRelation    // 按 APIParameterRelations 归组（endpoint_key；nil = 无关系，关系检测零行为）
	apiFlowBaselines          map[string][]detectors.FlowBaseline     // 按 APIFlowBaselines 归组（endpoint_key；nil = 无基线，流程偏离检测零行为）
	apiStrongFlows            *flowguard.Registry                     // 按 APIStrongFlows 装配（nil = 未下发/空段，强流程零行为 NG-T-C01；FLOW-02 消费入口，Provision 后只读）
	apiStrongFlowIndex        map[string][]flowguard.BoundStep        // 按 apiStrongFlows 归组（endpoint_key；nil = 无端点绑定，强流程检测零行为）
	strongFlowRuntime         *flowguard.Runtime                      // 强流程运行时（nil = 未下发定义，零行为；Valkey/密钥缺席时 Runtime 内部恒 UNKNOWN 放行+披露，D8 严禁本地内存回退）
	apiFileWatermark          *response.FileWatermarkConfig           // 按 APIFileWatermark 编译（nil = 未下发/未启用，响应侧零行为变化）
	apiFileSignature          *response.FileSignatureConfig           // 按 APIFileSignature 编译（nil = 未下发/未启用，响应侧零行为变化；密钥为秘密材料不落日志）
	apiFileCompliance         *detectors.FileComplianceRuleSet        // 按 APIFileComplianceRules 编译（nil = 无规则，合规检测零行为）
	apiGRPCRegistry           *grpcdesc.Registry                      // 按 APIGRPCDescriptors 编译（nil = 无描述符，gRPC 与 v1 一致）
	apiGRPCGuard              *grpcguard.Config                       // 按 APIGRPCDescriptors+APIGRPCBindings 装配（nil = 无描述符且无绑定，grpcguard 零行为 NG-T-C01；Provision 后只读）
	apiMCPGuard               *mcpguard.Config                        // 按 APIMCPToolCatalogs+APIMCPBindings 装配（nil = 无目录且无绑定，mcpguard 零行为 NG-T-C01；Provision 后只读）
	apiMachineID              *machineid.Config                       // 按 APIMachineIdentities+APIMachineIDBindings+APIMachineIDMeta 装配（nil = 三段全缺，机器身份全链零行为 NG-T-C01；Provision 后只读）
	machineIDReplay           *httpsig.ReplayStore                    // 重放原子存储（nil cli = 存储缺席——运行期 UNAVAILABLE 披露（OBSERVE 放行/PROTECT 503），严禁本机去重（§1.5 红线））
	jwtVerifier               *jwtverify.Verifier                     // 按 JWTTrust 装配（nil = 未下发/OFF，请求链路零变化）
	apiExceptions             map[string][]APIException               // 按 APIExceptions 装配（nil = 未下发，请求链路零变化）
	apiAdmission              map[string]detectors.AdmissionPolicy    // 按 APIAdmissionPolicies 装配（nil = 无准入策略，准入检测零行为；Provision 后只读，热加载经实例整体替换生效）
	apiGraphQL                map[string]*pipeline.GraphQLPolicy      // 按 APIGraphQLPolicies 装配（nil = 无 GraphQL 策略，GraphQL 流量零行为变化；同上只读）
	apiLLMSecurity            map[string]detectors.LLMSecurityPolicy  // 按 APILLMSecurityPolicies 归组（nil = 无输入保护策略）
	jwtFetcher                *jwtverify.Fetcher                      // 测试注入钩子（nil = 存在 REMOTE_JWKS 时装配期建默认受限获取器）
	jwtCancel                 context.CancelFunc                      // 远程 JWKS 后台刷新取消（nil = 未启动；Cleanup 调用）
	botPolicy                 *botPolicyJSON                          // 按 BotPolicy 装配（nil = 未下发；OFF 也保留段内容以维持 verify 命名空间墓碑；B3 起请求链经 serveNextViaBot 消费）
	botSvc                    *botchallenge.Service                   // Bot 挑战服务（nil = OFF/未下发/OBSERVE 依赖缺失降级；PROTECT 依赖缺失在装配期 fail-closed 拒载）
	publishSmokeKey           []byte                                  // 按 PublishSmoke 解码（单次发布独立秘密，不落日志/快照）
}

// authzSnapshotJSON is the explicit hand-off contract for the last known
// usable authorization snapshot. It is injected by the publish coordinator;
// Guard does not infer or persist history across independent processes.
type authzSnapshotJSON struct {
	Models            []detectors.ObjectModel          `json:"models,omitempty"`
	Relations         []detectors.ObjectRelation       `json:"relations,omitempty"`
	RoleBaselines     []detectors.VerifiedRoleBaseline `json:"role_baselines,omitempty"`
	ObjectHMACKeyHex  string                           `json:"object_hmac_key_hex,omitempty"`
	PolicyVersion     string                           `json:"policy_version,omitempty"`
	Stale             bool                             `json:"stale,omitempty"`
	SnapshotExpiresAt *time.Time                       `json:"snapshot_expires_at,omitempty"`
	// ---- NG-AZ-02 v2 快照字段（omitempty；缺失即 v1 快照按 D4-3 逐字节兼容）----
	Schema              string                      `json:"schema,omitempty"`
	RevocationWatermark *authzWatermarkJSON         `json:"revocation_watermark,omitempty"`
	LeaseSeconds        int                         `json:"lease_seconds,omitempty"`
	ConflictedObjects   []authzConflictedObjectJSON `json:"conflicted_objects,omitempty"`
	ProducedAt          *time.Time                  `json:"produced_at,omitempty"`
}

// authzWatermarkJSON 向量撤销水位（NG-AZ-02 §1.1 冻结形状；与 server 侧
// gatewayconfig.RevocationWatermark 线契约一致——跨仓镜像，不得改名）。
type authzWatermarkJSON struct {
	ManualSeq int64            `json:"manual_seq"`
	Sources   map[string]int64 `json:"sources,omitempty"`
}

// atLeast 分量比较：w ≥ other ⇔ manual_seq 与 other.sources 每键均不小于
// （缺失键按 0 计；D3/D4 比较语义与 server 侧 RevocationWatermarkAtLeast 同口径）。
func (w *authzWatermarkJSON) atLeast(other *authzWatermarkJSON) bool {
	if other == nil {
		return true
	}
	if w == nil {
		w = &authzWatermarkJSON{}
	}
	if w.ManualSeq < other.ManualSeq {
		return false
	}
	for k, ov := range other.Sources {
		if w.Sources[k] < ov {
			return false
		}
	}
	return true
}

// authzConflictedObjectJSON 决策侧排除对象键（NG-AZ-02 D7；与 server 侧
// GuardAuthzConflictedObject 线契约一致）。
type authzConflictedObjectJSON struct {
	ApplicationID string `json:"application_id"`
	ObjectType    string `json:"object_type"`
	TenantDomain  string `json:"tenant_domain,omitempty"`
	ObjectRef     string `json:"object_ref"`
}

// apiAdmissionSectionJSON 发布通道 api_admission 段（WDSP P1 冻结契约）：
// policies 键为 application_id，值为准入模式 + 已确认端点键集合（只含 CONFIRMED；
// IGNORED/DEPRECATED/ZOMBIE 不下发——不在集合即拒绝，语义一致）。
type apiAdmissionSectionJSON struct {
	Policies map[string]apiAdmissionPolicyJSON `json:"policies"`
}

// apiAdmissionPolicyJSON 单应用准入策略下发物。mode 词表 OFF/OBSERVE/PROTECT；
// 词表外/缺失 fail-safe 视为 OFF（Provision 编译期归一并 Warn 留痕，不拒载——
// 不拦截优于误拦截）。
type apiAdmissionPolicyJSON struct {
	Mode               string   `json:"mode"`
	ConfirmedEndpoints []string `json:"confirmed_endpoints"`
}

// apiGraphQLSectionJSON 发布通道 api_graphql 段（NG-GQL-03 冻结契约）：
// policies 键为 application_id，值为该应用 GraphQL 成本预算策略（无段/无键 = 关闭，
// 管线零行为变化）。
type apiGraphQLSectionJSON struct {
	Policies map[string]apiGraphQLPolicyJSON `json:"policies"`
}

// apiGraphQLPolicyJSON 单应用 GraphQL 成本预算策略下发物。
// 数值字段非法（负值/超硬上限）在 Provision 归一为零值走引擎默认并 Warn 留痕
// （fail-safe 与 api_admission 同形态：不拦截优于误拦截，不拒载）。
type apiGraphQLPolicyJSON struct {
	Enabled           bool                 `json:"enabled"`
	Limits            apiGraphQLLimitsJSON `json:"limits,omitempty"`
	Weights           gqlast.WeightsConfig `json:"weights,omitempty"`
	Budget            gqlast.BudgetConfig  `json:"budget,omitempty"`
	TrustedDocDigests []string             `json:"trusted_doc_digests,omitempty"`
}

// apiGraphQLLimitsJSON 解析硬边界覆盖（零值字段 = 引擎默认；gqlast.Limits 无 JSON
// 标签故冻结线契约在此显式定义）。
type apiGraphQLLimitsJSON struct {
	MaxDocBytes    int `json:"max_doc_bytes,omitempty"`
	MaxDepth       int `json:"max_depth,omitempty"`
	MaxNodes       int `json:"max_nodes,omitempty"`
	MaxAliases     int `json:"max_aliases,omitempty"`
	MaxFragmentExp int `json:"max_fragment_exp,omitempty"`
}

// toPolicy 编译为管线策略（硬边界单项超 64MiB 归零走默认，防 OOM 配置）。
func (p apiGraphQLPolicyJSON) toPolicy() *pipeline.GraphQLPolicy {
	lim := gqlast.Limits{
		MaxDocBytes:    p.Limits.MaxDocBytes,
		MaxDepth:       p.Limits.MaxDepth,
		MaxNodes:       p.Limits.MaxNodes,
		MaxAliases:     p.Limits.MaxAliases,
		MaxFragmentExp: p.Limits.MaxFragmentExp,
	}
	if lim.MaxDocBytes < 0 || lim.MaxDocBytes > 64<<20 {
		lim.MaxDocBytes = 0
	}
	return &pipeline.GraphQLPolicy{
		Enabled:           p.Enabled,
		Limits:            lim,
		Weights:           p.Weights,
		Budget:            p.Budget,
		TrustedDocDigests: p.TrustedDocDigests,
	}
}
