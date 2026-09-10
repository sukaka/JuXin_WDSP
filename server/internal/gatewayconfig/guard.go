// guard.go 阶段5访问控制/CC防护配置：类型定义与向 Caddy JSON 注入 jiuzhang_guard 处理器。
// 配置结构与 gateway/modules/jiuzhang_guard 的 JSON 约定一一对应。
package gatewayconfig

import (
	"encoding/json"
	"time"

	"github.com/jiuzhang-waf/server/internal/applications"
)

// GuardProxy 可信代理（下发网关）。
type GuardProxy struct {
	Name             string `json:"name"`
	CIDR             string `json:"cidr"`
	HeaderType       string `json:"header_type"`
	CustomHeaderName string `json:"custom_header_name,omitempty"`
	Priority         int    `json:"priority"`
}

// GuardRule IP 访问控制规则（下发网关）。
type GuardRule struct {
	ID             string `json:"id"`
	Address        string `json:"address"`
	Priority       int    `json:"priority"`
	EffectiveFrom  string `json:"effective_from,omitempty"`
	EffectiveUntil string `json:"effective_until,omitempty"`
}

// GuardPolicy CC 防护策略（下发网关）。
type GuardPolicy struct {
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

// GuardValkey Valkey 连接（下发网关）。
type GuardValkey struct {
	Address  string `json:"address"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	DB       int    `json:"db"`
}

// GuardAccessLog 全量访问日志采集配置（下发网关，对应 gateway jiuzhang_guard access_log 段）。
type GuardAccessLog struct {
	Enabled                bool   `json:"enabled"`
	CaptureRequestHeaders  bool   `json:"capture_request_headers"`
	CaptureRequestBody     bool   `json:"capture_request_body"`
	CaptureResponseHeaders bool   `json:"capture_response_headers"`
	CaptureResponseBody    bool   `json:"capture_response_body"`
	BodyLimitKB            int    `json:"body_limit_kb"`
	LogPath                string `json:"log_path"`
}

// GuardAppRules 单应用视角的规则与策略。
type GuardAppRules struct {
	Allow    []GuardRule   `json:"allow"`
	Deny     []GuardRule   `json:"deny"`
	Policies []GuardPolicy `json:"policies"`
}

// GuardParamConstraint 单参数确认约束（下发网关；词汇与 apimodels.ParamConstraint 一致）。
type GuardParamConstraint struct {
	Location    string         `json:"location"`    // QUERY / HEADER / BODY / PATH / COOKIE
	Name        string         `json:"name"`        // 参数名（QUERY/HEADER 键名；BODY 末段名）
	Path        string         `json:"path"`        // 结构化路径（BODY 点路径）
	BaseType    string         `json:"base_type"`   // string|number|bool|object|array|null
	Required    bool           `json:"required"`    // 必填
	Constraints map[string]any `json:"constraints"` // 下发词汇：min_length/max_length/minimum/maximum/enum/regex/nullable/empty_allowed（未知键网关宽容忽略）
}

// GuardMaskRule 响应脱敏规则（下发网关，对应 api_masking_rules 表 enabled 规则；
// 该表由迁移 000040 建立，列契约：endpoint_key/field_path/data_type/algorithm/params_json）。
// json tag 为跨分片契约，不得改动。
type GuardMaskRule struct {
	EndpointKey string         `json:"endpoint_key"` // 作用端点（空 = 应用/全局级，按 scope 约定）
	FieldPath   string         `json:"field_path"`   // 响应体字段路径
	DataType    string         `json:"data_type"`    // 敏感数据类型
	Algorithm   string         `json:"algorithm"`    // MASK / HASH / ENCRYPT / MAP / REMOVE
	Params      map[string]any `json:"params,omitempty"`
}

// GuardSensitiveValueRule 值级敏感检测规则（下发网关，对应 api_sensitive_data_types 表
// status=ENABLED 且 regex 非空的类型；该表由迁移 000040 建立）。
// 网关对 locations 声明位置（query/json/form/header/path）的值做 RE2 匹配，
// 证据只含 data_type/location/字段名/level，绝不落值。json tag 为跨分片契约，不得改动。
type GuardSensitiveValueRule struct {
	DataType  string   `json:"data_type"` // 数据类型标签（与网关 evidence.data_type 对齐）
	Regex     string   `json:"regex"`     // 值级正则（RE2）
	Locations []string `json:"locations"` // 可能出现位置（query/json/form/xml/header/cookie/path/response_body）
	Level     string   `json:"level"`     // 五级敏感等级（NON_SENSITIVE/GENERAL/SENSITIVE/IMPORTANT/CORE）
}

// GuardRoleBaseline 角色功能级基线（下发网关，对应 api_role_baselines 表 confirmed=true 行；
// 该表由迁移 000043 建立）。网关按 endpoint+method+role 归并判定 BFLA：
// action 为管理面业务动作语义，运行时随契约透传但不参与匹配（网关无法观测业务动作）。
// json tag 为跨分片契约，不得改动。
type GuardRoleBaseline struct {
	EndpointKey string `json:"endpoint_key"` // 作用端点（METHOD + 空格 + 路径模板）
	Role        string `json:"role"`         // 角色码（与 JWT role/roles 自定义 claim 对齐）
	Method      string `json:"method"`       // HTTP 方法（大写）
	Action      string `json:"action"`       // 业务动作（READ/WRITE/DELETE/EXPORT…）
	Allowed     bool   `json:"allowed"`      // 允许/显式拒绝
}

// GuardAuthzObjectIdentifier describes the single request location used to
// extract an authorization object identifier.
type GuardAuthzObjectIdentifier struct {
	Location string `json:"location"`
	Name     string `json:"name"`
	Primary  bool   `json:"primary,omitempty"`
}

// GuardAuthzObjectModel is the publishable OWNER-only object model consumed by
// the gateway's OBSERVE authorization evaluator.
type GuardAuthzObjectModel struct {
	ApplicationID          string                       `json:"application_id"`
	EndpointKey            string                       `json:"endpoint_key"`
	Method                 string                       `json:"method,omitempty"`
	PathTemplate           string                       `json:"path_template,omitempty"`
	ObjectType             string                       `json:"object_type"`
	Identifiers            []GuardAuthzObjectIdentifier `json:"identifiers"`
	RequiredRelation       string                       `json:"required_relation"`
	OwnerExclusive         bool                         `json:"owner_exclusive"`
	Publishable            bool                         `json:"publishable"`
	UniqueEndpointTemplate bool                         `json:"unique_endpoint_template"`
	PolicyVersion          string                       `json:"policy_version,omitempty"`
	ModelVersion           string                       `json:"model_version,omitempty"`
	SnapshotExpiresAt      *time.Time                   `json:"snapshot_expires_at,omitempty"`
	Stale                  bool                         `json:"stale,omitempty"`
}

type GuardAuthzObjectRelation struct {
	ApplicationID string     `json:"application_id"`
	PrincipalID   string     `json:"principal_id"`
	ObjectType    string     `json:"object_type"`
	ObjectRef     string     `json:"object_ref"`
	Relation      string     `json:"relation"`
	Status        string     `json:"status"`
	TenantID      string     `json:"tenant_id,omitempty"`
	ValidFrom     *time.Time `json:"valid_from,omitempty"`
	ValidUntil    *time.Time `json:"valid_until,omitempty"`
}

type GuardAuthzRoleBaseline struct {
	ApplicationID string `json:"application_id"`
	EndpointKey   string `json:"endpoint_key"`
	Method        string `json:"method,omitempty"`
	Role          string `json:"role"`
	Action        string `json:"action,omitempty"`
	Allowed       bool   `json:"allowed"`
	Confirmed     bool   `json:"confirmed"`
}

// GuardAuthzSnapshot is an immutable authorization snapshot. PreviousValid
// is supplied by the publish coordinator when the current snapshot is known
// to be stale; it is deliberately explicit because this config package does
// not persist gateway runtime state by itself.
type GuardAuthzSnapshot struct {
	Models            []GuardAuthzObjectModel    `json:"models,omitempty"`
	Relations         []GuardAuthzObjectRelation `json:"relations,omitempty"`
	RoleBaselines     []GuardAuthzRoleBaseline   `json:"role_baselines,omitempty"`
	ObjectHMACKeyHex  string                     `json:"object_hmac_key_hex,omitempty"`
	PolicyVersion     string                     `json:"policy_version,omitempty"`
	Stale             bool                       `json:"stale,omitempty"`
	SnapshotExpiresAt *time.Time                 `json:"snapshot_expires_at,omitempty"`
}

// GuardFieldPermission 字段权限（下发网关，对应 api_field_permissions 表行；
// 该表由迁移 000044 建立）。role/tenant 空串 = 默认行（对该端点全部角色/租户生效）。
// 本波网关仅消费 direction=REQUEST 且 field_path 为 json. 前缀的行（Mass Assignment）；
// 响应方向与租户覆盖行随契约透传，运行时暂不判定。
// json tag 为跨分片契约，不得改动。
type GuardFieldPermission struct {
	EndpointKey string `json:"endpoint_key"` // 作用端点
	FieldPath   string `json:"field_path"`   // 字段路径（location.a.b 风格，如 json.buyer.phone）
	Direction   string `json:"direction"`    // REQUEST / RESPONSE
	Attribute   string `json:"attribute"`    // READABLE/WRITABLE/READ_ONLY/ADMIN_WRITABLE/SERVER_GENERATED/SENSITIVE/FORBIDDEN
	Role        string `json:"role"`         // 空 = 默认行；非空 = 角色覆盖行
	Tenant      string `json:"tenant"`       // 空 = 默认行；非空 = 租户覆盖行
}

// GuardScanVerification 扫描流量识别密钥（下发网关，对应 apiscan 签名密钥：
// system_settings api_scan.signing_key 密文经加密服务解密后的明文 hex）。
// 网关据此校验 X-JiuZhang-Scan 签名头（"{job_id}.{hex(HMAC-SHA256(key, job_id))}"，
// 构造见 server/internal/apiscan/sign.go），识别扫描流量并打标（学习样本排除）；
// 不下发时网关降级为仅按头存在性识别（无法防伪造）。
// key_hex 为秘密材料：版本快照经 RedactGuardConfig 脱敏，回滚时由发布侧重新注入。
// json tag 为跨分片契约，不得改动。
type GuardScanVerification struct {
	KeyHex string `json:"key_hex"` // 32 字节签名密钥的 hex 编码（64 字符）
}

// GuardGRPCDescriptor gRPC 描述符集（下发网关，对应 api_grpc_descriptors 表 ENABLED 行；
// 该表由迁移 000076 建立）。content_base64 为 FileDescriptorSet 原始字节的 base64
// 编码，网关装配期编译为动态消息注册表（protodesc + dynamicpb），按 :path
// /package.Service/Method 解码请求消息做字段级观测；不下发时网关退化为 v1 帧结构
// 校验，行为与历史版本一致。name 原样进入网关观测证据 descriptor 字段。
// json tag 为跨分片契约，不得改动。
type GuardGRPCDescriptor struct {
	Name          string `json:"name"`           // 描述符集名称（唯一键）
	ContentBase64 string `json:"content_base64"` // FileDescriptorSet 字节 base64
}

// GuardResponseBaseline 端点响应结构基线（下发网关，对应 api_response_schemas 表
// sample_count 达阈值的学习行；该表由迁移 000018 建立、000051 补齐运行时学习列）。
// 网关按 endpoint_key×status_code 比对响应一级字段：基线外新字段/基线字段缺失/
// 未见状态码产偏离明细；无基线下发时响应偏离检测零行为。
// json tag 为跨分片契约，不得改动。
type GuardResponseBaseline struct {
	EndpointKey string            `json:"endpoint_key"` // 作用端点（METHOD + 空格 + 路径模板）
	StatusCode  int               `json:"status_code"`  // 学习到的响应状态码
	Fields      map[string]string `json:"fields"`       // 一级字段路径 → 类型（只含路径与类型标签，不落值）
}

// GuardFileWatermark 文件下载水印 v1（W12-GW / P2-01 最小可行子集，任务书 §109 子集；
// 下发网关，对应 gateway jiuzhang_guard api_file_watermark 段）。
// 来源 system_settings gateway_runtime 组 api_file_watermark_* 键（guardconfig 校验后注入）；
// 仅文本族（text/plain、text/csv、text/markdown）与 application/json 的
// Content-Disposition 下载响应生效：文本族文件尾追加不可见注释行，JSON 顶层加
// json_key 字段；网关侧失败一律 FAIL_OPEN 直通。
// json tag 为跨分片契约，不得改动。
type GuardFileWatermark struct {
	Enabled      bool     `json:"enabled"`
	TextTemplate string   `json:"text_template"`           // 水印文本模板（支持 {ip}/{identity}/{time}/{domain} 占位）
	ContentTypes []string `json:"content_types,omitempty"` // 媒体类型白名单（缺省网关默认表）
	JSONKey      string   `json:"json_key,omitempty"`      // JSON 顶层水印字段名（缺省 "_wm"）
}

// GuardFileSignature 文件签名 v1（W13-GW / P2-02，任务书 §110 子集；下发网关，对应
// gateway jiuzhang_guard api_file_signature 段）。来源 system_settings gateway_runtime 组
// api_file_signature_key（密文，经加密服务解密为明文 hex）与 api_file_signature_kid。
// 网关对文本族/JSON 下载响应在水印之后嵌入 jzsig1.{kid}.{unixts}.{hmac} 来源追踪 token
// （文本注释行 / JSON 顶层 "_sig" 字段）；网关侧失败一律 FAIL_OPEN 直通。
// key_hex 为秘密材料：版本快照经 RedactGuardConfig 脱敏，回滚时由发布侧按当前设置重新注入；
// 秘密材料不参与 api_policy_version 计算（与 api_scan_verification 同一纪律）。
// json tag 为跨分片契约，不得改动。
type GuardFileSignature struct {
	Enabled bool   `json:"enabled"`
	KID     string `json:"kid"`     // 密钥标识（token 第二段；轮换追踪）
	KeyHex  string `json:"key_hex"` // 32 字节签名密钥的 hex 编码（64 字符）
}

// GuardFileComplianceRule 文件合规规则（W13-GW / P2-03，任务书 §44 文件异常检测子集；
// 下发网关，对应 api_file_compliance_rules 表 enabled 行；该表由迁移 000071 另一分片建立，
// 表列：direction/match_type/match_value/action/reason/enabled，下发键见下方 json tag）。
// 网关对上传 multipart 与下载 Content-Disposition 文件观测评估：EXT 精确（小写带点/不带点统一）、
// MIME 前缀、FILENAME_REGEX（RE2）；action=BLOCK 在 PROTECT 上传 403、下载抑制已缓冲响应为 403。
// json tag 为跨分片契约，不得改动。
type GuardFileComplianceRule struct {
	Direction string `json:"direction"` // UPLOAD / DOWNLOAD
	Match     string `json:"match"`     // EXT / MIME / FILENAME_REGEX
	Value     string `json:"value"`     // 匹配值（EXT 带点/不带点均可，网关归一小写无点）
	Action    string `json:"action"`    // OBSERVE / BLOCK
	Reason    string `json:"reason,omitempty"`
}

// GuardParamRef 参数条件关系一端参数引用（下发网关）。
// json tag 为跨分片契约，不得改动。
type GuardParamRef struct {
	Location string `json:"location"` // QUERY / HEADER / BODY / PATH / COOKIE
	Path     string `json:"path"`     // 结构化路径（BODY 点路径）
	Name     string `json:"name"`     // 参数名
}

// GuardParamRelation 已确认参数条件关系（下发网关，对应 api_parameter_relations 表
// confirmed=true 行；该表由迁移 000018 建立、000068 补确认列）。
// 网关运行时按存在性判定：REQUIRES：A 存在 B 必须存在（缺失违例）；MUTEX/EXCLUDES：
// A 与 B 互斥（同现违例）；CO_OCCURS：统计共现偏离仅观察（不阻断）。
// 证据只含参数名/路径/位置，不落值。json tag 为跨分片契约，不得改动。
type GuardParamRelation struct {
	EndpointKey  string        `json:"endpoint_key"`  // 作用端点（METHOD + 空格 + 路径模板）
	RelationType string        `json:"relation_type"` // REQUIRES / MUTEX / EXCLUDES / CO_OCCURS
	ParamA       GuardParamRef `json:"param_a"`
	ParamB       GuardParamRef `json:"param_b"`
}

// ---------- L7 访问控制（契约一 l7_rules 段；仅 WAF/WDSP 下发） ----------

// GuardL7Condition L7 匹配条件（下发网关）。
// method/client_ip 用 Values（等价 op=in）；uri 用 Op+Value；header/cookie/query 用 Name+Op+Value。
type GuardL7Condition struct {
	Type   string   `json:"type"`
	Name   string   `json:"name,omitempty"`
	Op     string   `json:"op,omitempty"`
	Value  string   `json:"value,omitempty"`
	Values []string `json:"values,omitempty"`
}

// GuardL7ActionConfig L7 动作配置（下发网关）。六键恒出（与契约一示例一致），按动作取对应字段。
type GuardL7ActionConfig struct {
	Status         int    `json:"status"`
	Message        string `json:"message"`
	RedirectURL    string `json:"redirect_url"`
	RedirectStatus int    `json:"redirect_status"`
	ContentType    string `json:"content_type"`
	Body           string `json:"body"`
}

// GuardL7Rule L7 访问控制规则（下发网关）。
type GuardL7Rule struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	Priority     int                 `json:"priority"`
	Enabled      bool                `json:"enabled"`
	Conditions   []GuardL7Condition  `json:"conditions"`
	Action       string              `json:"action"`
	ActionConfig GuardL7ActionConfig `json:"action_config"`
}

// GuardL7Rules l7_rules 段（rules 恒为数组，空数组用于清空网关旧规则）。
type GuardL7Rules struct {
	Rules []GuardL7Rule `json:"rules"`
}

// GuardIdentityBehavior 侦察/枚举行为检测策略（WDSP AI 自动化渗透防护增强 阶段1；
// 下发网关，对应 security_behavior_policy 表 GLOBAL 行；该表由迁移 000098 建立）。
// 网关按窗口统计身份行为并与阈值比对产 recon_signal（identity-events.log）；
// enabled=false 时网关行为检测零行为。policy_version 为策略 version 十进制字符串
// （网关随 recon_signal 回报，供版本溯源）。scores 键限定 10 种信号。
// json tag 为跨分片契约（网关工作流已冻结），不得改动。
type GuardIdentityBehavior struct {
	Enabled                  bool           `json:"enabled"`
	Mode                     string         `json:"mode"`
	PolicyVersion            string         `json:"policy_version"`
	URIEnumUniqueThreshold   int            `json:"uri_enum_unique_threshold"`
	URIEnumNewRatioThreshold float64        `json:"uri_enum_new_ratio_threshold"`
	NotFoundRatioThreshold   float64        `json:"not_found_ratio_threshold"`
	NotFoundMinRequests      int            `json:"not_found_min_requests"`
	MethodEnumThreshold      int            `json:"method_enum_threshold"`
	ParamMutationThreshold   int            `json:"param_mutation_threshold"`
	AuthFailThreshold        int            `json:"auth_fail_threshold"`
	LowSlowSensitiveMinHits  int            `json:"low_slow_sensitive_min_hits"`
	AccountEnumThreshold     int            `json:"account_enum_threshold"`
	ObjectEnumThreshold      int            `json:"object_enum_threshold"`
	AccountIdentifierFields  []string       `json:"account_identifier_fields"`
	ObjectIdentifierFields   []string       `json:"object_identifier_fields"`
	SensitivePaths           []string       `json:"sensitive_paths"`
	Scores                   map[string]int `json:"scores"`
	WhitelistIPs             []string       `json:"whitelist_ips"`
	WhitelistUAs             []string       `json:"whitelist_uas"`
}

// GuardRiskPolicy 身份风险处置策略（WDSP AI 自动化渗透防护增强 阶段3；
// 下发网关，对应 security_risk_policy 表 GLOBAL 行；该表由迁移 000101 建立）。
// 网关按 signal_window_seconds 窗口聚合身份风险分（各信号分值经 scores 覆盖），
// 达 rate_limit_threshold 限速（rate_limit_rps RPS）、达 block_threshold 阻断；
// mode=OBSERVE 仅观测（事件 action_taken=would_block/would_rate_limit），
// PROTECT 实际处置（blocked/rate_limited）；enabled=false 时网关风险处置零行为。
// version 为策略乐观锁版本号（网关随处置事件回报 policy_version 供溯源）；
// risk_levels 为风险等级阈值（medium/high/critical）。
// json tag 为跨分片契约（网关并行开发已冻结），不得改动。
type GuardRiskPolicy struct {
	Enabled             bool           `json:"enabled"`
	Mode                string         `json:"mode"`
	Version             int            `json:"version"`
	BlockThreshold      int            `json:"block_threshold"`
	RateLimitThreshold  int            `json:"rate_limit_threshold"`
	RateLimitRPS        int            `json:"rate_limit_rps"`
	SignalWindowSeconds int            `json:"signal_window_seconds"`
	Scores              map[string]int `json:"scores"`
	RiskLevels          map[string]int `json:"risk_levels"`
}

// ---------- WDSP P0-03：业务 JWT 信任链（jwt_trust 段，跨分片契约已冻结） ----------

// GuardJWTSelector 请求范围选择器（下发网关）：methods 大写去重；
// path_exact/path_prefix 二选一；prefix 按完整路径段匹配；路径不含 query。
type GuardJWTSelector struct {
	Methods       []string `json:"methods"`
	PathExact     string   `json:"path_exact,omitempty"`
	PathPrefix    string   `json:"path_prefix,omitempty"`
	TokenRequired bool     `json:"token_required"`
}

// GuardJWTIssuer 受信发行方配置（下发网关；issuer_config_id 由管理面按
// 应用+issuer 精确值派生并保持跨发布稳定；静态 JWKS 仅含公钥——公钥非秘密可以下发；
// keyset_version 为密钥集内容哈希，供网关事件溯源与轮换比对）。
type GuardJWTIssuer struct {
	IssuerConfigID   string          `json:"issuer_config_id"`
	Issuer           string          `json:"issuer"`
	Audiences        []string        `json:"audiences"`
	Algorithms       []string        `json:"algorithms"` // RS256/ES256 非空子集
	ClockSkewSeconds int             `json:"clock_skew_seconds"`
	TenantClaim      string          `json:"tenant_claim,omitempty"`
	RoleClaims       []string        `json:"role_claims,omitempty"`
	KeySourceType    string          `json:"key_source_type"` // STATIC_JWKS | REMOTE_JWKS
	JWKS             json.RawMessage `json:"jwks,omitempty"`  // STATIC_JWKS：公钥集（已校验无私钥/对称密钥）
	RemoteURL        string          `json:"remote_url,omitempty"`
	KeysetVersion    string          `json:"keyset_version,omitempty"`
}

// GuardJWTTrustPolicy 应用 JWT 信任策略（下发网关 jwt_trust 段；schema_version
// 供网关识别配置结构版本——不支持该段的旧节点必须拒绝加载而非忽略强制语义）。
type GuardJWTTrustPolicy struct {
	SchemaVersion int                `json:"schema_version"`
	ApplicationID string             `json:"application_id"`
	Mode          string             `json:"mode"` // OFF | OBSERVE | PROTECT
	Version       int                `json:"version"`
	Selectors     []GuardJWTSelector `json:"selectors"`
	Issuers       []GuardJWTIssuer   `json:"issuers"`
}

// ---------- WDSP P0-04：API 引擎受限例外（api_exceptions 段契约） ----------

// GuardAPIRuleRef API 例外目标规则引用：匹配 Finding 的 detector+rule_id
// （+可选 model_version 钉版；空=不限版本）。detector_id 必须在网关受支持注册表内，
// 不允许自由字符串。
type GuardAPIRuleRef struct {
	DetectorID   string `json:"detector_id"`
	RuleID       string `json:"rule_id"`
	ModelVersion string `json:"model_version,omitempty"`
}

// GuardAPIException 单条 API 受限例外（OBSERVE_RULE）。范围各维度为 AND，
// methods 非空；uri_exact/uri_prefix 恰一（路径不含 query；prefix 按路径段边界）；
// 时间为 UTC epoch 秒半开区间 [effective_from, effective_until)，网关运行时判断。
type GuardAPIException struct {
	SchemaVersion  int               `json:"schema_version"` // 初始 1
	ExceptionID    string            `json:"exception_id"`
	Version        int               `json:"version"`
	Domain         string            `json:"domain,omitempty"`
	URIExact       string            `json:"uri_exact,omitempty"`
	URIPrefix      string            `json:"uri_prefix,omitempty"`
	Methods        []string          `json:"methods"`
	SourceIPs      []string          `json:"source_ips,omitempty"` // 可信代理处理后的客户端 IP
	EffectiveFrom  *int64            `json:"effective_from,omitempty"`
	EffectiveUntil *int64            `json:"effective_until,omitempty"`
	RuleRefs       []GuardAPIRuleRef `json:"rule_refs"`
}

// ---------- WDSP P1-02：Bot 挑战策略（bot_policy 段，跨分片契约 B0 冻结） ----------

// GuardBotSelector 挑战适用范围选择器（下发网关）：仅 GET 浏览器文档导航；
// path_exact/path_prefix 二选一；prefix 按完整路径段匹配；路径为解码后形式、
// 大小写敏感；禁止正则、百分号编码与全站通配。
type GuardBotSelector struct {
	PathExact  string `json:"path_exact,omitempty"`
	PathPrefix string `json:"path_prefix,omitempty"`
}

// GuardBotSignalRule 单条信号规则（下发网关；threshold 语义按指标冻结——
// 占比/计数类 ≥ 阈值触发，known_uri_ratio ≤ 阈值触发，声明匹配类命中即触发）。
type GuardBotSignalRule struct {
	ID            string            `json:"id"`
	Group         string            `json:"group"` // request_behavior | access_sequence | client_claim
	Metric        string            `json:"metric"`
	Params        map[string]string `json:"params,omitempty"`
	WindowSeconds int               `json:"window_seconds"`
	Weight        float64           `json:"weight"`
	Threshold     float64           `json:"threshold"`
}

// GuardBotSignalRules 多信号判定配置（B0：≥min_independent_groups 个独立信号组
// 同时满足且至少 1 个行为组才可提出挑战；client_claim 为可伪造弱信号组）。
type GuardBotSignalRules struct {
	MinIndependentGroups int                  `json:"min_independent_groups"`
	RequireBehaviorGroup bool                 `json:"require_behavior_group"`
	Rules                []GuardBotSignalRule `json:"rules"`
}

// GuardBotChallenge 挑战参数（B0 默认：nonce_ttl=90s、clearance_ttl=900s、
// difficulty=14bit、max_attempts=3；key_ref 仅预置内部签名密钥引用名，非密钥材料）。
type GuardBotChallenge struct {
	Type                string `json:"type"` // 仅 JS
	NonceTTLSeconds     int    `json:"nonce_ttl_seconds"`
	ClearanceTTLSeconds int    `json:"clearance_ttl_seconds"`
	Difficulty          int    `json:"difficulty"`
	MaxAttempts         int    `json:"max_attempts"`
	KeyRef              string `json:"key_ref,omitempty"`
}

// GuardBotRouteReservation 保留路由状态（版本化配置：
// ENABLED / RESERVED_TOMBSTONE / RELEASED；namespace 恒为 /_wdsp/bot/v1/）。
type GuardBotRouteReservation struct {
	State     string `json:"state"`
	Namespace string `json:"namespace"`
}

// GuardBotPolicy 应用 Bot 挑战策略（下发网关 bot_policy 段；schema_version
// 供网关识别配置结构版本——与 jwt_trust 同一纪律：不识别即拒绝加载，
// 不得忽略强制语义静默降级）。
type GuardBotPolicy struct {
	SchemaVersion    int                      `json:"schema_version"`
	ApplicationID    string                   `json:"application_id"`
	Mode             string                   `json:"mode"` // OFF | OBSERVE | PROTECT
	Version          int                      `json:"version"`
	Selectors        []GuardBotSelector       `json:"selectors"`
	SignalRules      GuardBotSignalRules      `json:"signal_rules"`
	Challenge        GuardBotChallenge        `json:"challenge"`
	RouteReservation GuardBotRouteReservation `json:"route_reservation"`
}

// guardBotPolicyWithKeys 渲染进应用 bot_policy 段的包装（仅 buildGuardHandler 使用）：
// 签名密钥材料以 signing_keys 键并入段 JSON，策略本体（GuardBotPolicy）保持无秘密材料——
// GuardConfig.BotPolicy 快照/api_policy_version 版本戳不含密钥，密钥仅在渲染产物中出现
// （与 api_scan_verification.key_hex 进入同一渲染通道的既有先例一致）。
type guardBotPolicyWithKeys struct {
	*GuardBotPolicy
	SigningKeys map[string]string `json:"signing_keys,omitempty"`
}

// GuardConfig 阶段5访问控制/CC 全量配置（全局 + 按应用）。
// 该结构整体序列化后同时作为 access_control_versions 的快照。
type GuardConfig struct {
	TrustedProxies     []GuardProxy              `json:"trusted_proxies"`
	MaxProxyChain      int                       `json:"max_proxy_chain"`
	ProtectedAddresses []string                  `json:"protected_addresses"`
	GlobalAllow        []GuardRule               `json:"global_allow"`
	GlobalDeny         []GuardRule               `json:"global_deny"`
	GlobalPolicies     []GuardPolicy             `json:"global_policies"`
	AppRules           map[string]*GuardAppRules `json:"app_rules"` // key: 应用编码
	Valkey             *GuardValkey              `json:"valkey,omitempty"`
	CounterBackend     string                    `json:"counter_backend"`
	MaxCounterKeys     int                       `json:"max_counter_keys"`
	FailOpen           bool                      `json:"fail_open"`
	EventsLog          string                    `json:"events_log"`
	GatewayNode        string                    `json:"gateway_node"`
	// 阶段8 / WDSP：API 动态防护（默认关闭，关闭时下发 JSON 与纯 WAF 完全一致）
	APIDynamicProtection bool   `json:"api_dynamic_protection,omitempty"`
	APIProtectionMode    string `json:"api_protection_mode,omitempty"` // OFF | OBSERVE | PROTECT
	APIEventsLog         string `json:"api_events_log,omitempty"`
	// APIFormalSchemas 冻结正式模型（endpoint_key → 字段名 → 期望类型），经发布通道下发网关
	APIFormalSchemas map[string]map[string]string `json:"api_formal_schemas,omitempty"`
	// APIFormalModelVersions 冻结正式模型版本号（endpoint_key → 版本号十进制字符串），经发布通道下发网关；
	// 网关随运行时事件回报 model_version，供「命中时生效模型版本」审计溯源
	APIFormalModelVersions map[string]string `json:"api_formal_model_versions,omitempty"`
	// APIParameterConstraints FORMAL 端点请求侧确认参数约束（endpoint_key → 约束列表），经发布通道下发网关
	APIParameterConstraints map[string][]GuardParamConstraint `json:"api_parameter_constraints,omitempty"`
	// APIKnownEndpoints 已知 API 端点基线（endpoint_key → asset_status），经发布通道下发网关
	APIKnownEndpoints map[string]string `json:"api_known_endpoints,omitempty"`
	// APIPolicyVersion API 策略版本戳（本次发布 API 防护内容哈希：冻结模型+确认约束+脱敏规则），
	// 供生效校验与网关回报比对「发布内容与实际生效」
	APIPolicyVersion string `json:"api_policy_version,omitempty"`
	// 网关运行时设置（system_settings gateway_runtime 组，字符串键值；缺省不下发=网关内置默认值兜底）
	BehaviorStore           string `json:"behavior_store,omitempty"`
	BehaviorStoreTTLSeconds int    `json:"behavior_store_ttl_seconds,omitempty"`
	IdentitySalt            string `json:"identity_salt,omitempty"`
	// TLSSessionTicketKey TLS 会话票据密钥（32 字节 hex；gateway_runtime 组
	// tls_session_ticket_key 设置）。随发布下发到 apps.tls.session_tickets.key_source
	// （tls.stek.jiuzhang），主备多节点共用同一份票据密钥使会话恢复跨节点可用
	// （docs/HA_ACTIVE_STANDBY_DESIGN.md §7.2）；快照按 identity_salt 同纪律脱敏。
	TLSSessionTicketKey        string `json:"tls_session_ticket_key,omitempty"`
	CredentialIPSpreadLimit    int    `json:"credential_ip_spread_limit,omitempty"`
	CredentialConcurrencyLimit int    `json:"credential_concurrency_limit,omitempty"`
	APIWriteRatePerMinute      int    `json:"api_write_rate_per_minute,omitempty"`
	// APIMaskRules 响应脱敏规则（api_masking_rules 表 enabled 规则；表由迁移 000040 建立，
	// 表缺失/查询失败时发布侧 Warn 跳过不下发）
	APIMaskRules []GuardMaskRule `json:"api_mask_rules,omitempty"`
	// APISensitiveValueRules 值级敏感检测规则（api_sensitive_data_types 表 status=ENABLED
	// 且 regex 非空的类型；表由迁移 000040 建立，表缺失/查询失败时发布侧 Warn 跳过不下发；
	// 不下发时网关关闭值级检测，行为与历史版本一致）
	APISensitiveValueRules []GuardSensitiveValueRule `json:"api_sensitive_value_rules,omitempty"`
	// APIRoleBaselines 角色功能级基线（api_role_baselines 表 confirmed=true 行；
	// 表由迁移 000043 建立，表缺失/查询失败时发布侧 Warn 跳过不下发；
	// 不下发时网关 BFLA 基线检测零行为，与历史版本一致）
	APIRoleBaselines []GuardRoleBaseline `json:"api_role_baselines,omitempty"`
	// AUTHZ-01 trusted authorization snapshot. The HMAC key is redacted from
	// stored versions and re-injected from the current encrypted setting.
	APIAuthzModels            []GuardAuthzObjectModel    `json:"api_authz_models,omitempty"`
	APIAuthzRelations         []GuardAuthzObjectRelation `json:"api_authz_relations,omitempty"`
	APIAuthzRoleBaselines     []GuardAuthzRoleBaseline   `json:"api_authz_role_baselines,omitempty"`
	APIAuthzObjectHMACKeyHex  string                     `json:"api_authz_object_hmac_key_hex,omitempty"`
	APIAuthzSnapshotStale     bool                       `json:"api_authz_snapshot_stale,omitempty"`
	APIAuthzSnapshotExpiresAt *time.Time                 `json:"api_authz_snapshot_expires_at,omitempty"`
	APIAuthzPreviousValid     *GuardAuthzSnapshot        `json:"api_authz_previous_valid,omitempty"`
	// APIFieldPermissions 字段权限（api_field_permissions 表行；表由迁移 000044 建立，
	// 表缺失/查询失败时发布侧 Warn 跳过不下发；不下发时网关字段权限检测零行为）
	APIFieldPermissions []GuardFieldPermission `json:"api_field_permissions,omitempty"`
	// APIScanVerification 扫描流量识别密钥（apiscan 签名密钥明文 hex；
	// 未配置/解密失败时发布侧 Warn 跳过不下发，网关降级为仅按头存在性识别；
	// 版本快照经 RedactGuardConfig 脱敏，回滚时按当前设置重新注入）
	APIScanVerification *GuardScanVerification `json:"api_scan_verification,omitempty"`
	// APIResponseBaselines 响应结构基线（api_response_schemas 表 sample_count≥20 学习行；
	// 表由迁移 000018/000051 建立，表缺失/查询失败时发布侧 Warn 跳过不下发；
	// 不下发时网关响应偏离检测零行为，与历史版本一致）
	APIResponseBaselines []GuardResponseBaseline `json:"api_response_baselines,omitempty"`
	// APIParameterRelations 已确认参数条件关系（api_parameter_relations 表 confirmed=true 行；
	// 表由迁移 000018/000068 建立；仅 FORMAL 端点的 confirmed 关系下发，
	// 未确认候选不下发不生效；不下发时网关关系检测零行为，与历史版本一致）
	APIParameterRelations []GuardParamRelation `json:"api_parameter_relations,omitempty"`
	// APILLMAllowedModels LLM 授权模型名单（W10-LLM / P2-04；来源 system_settings
	// gateway_runtime 组 api_llm_allowed_models 逗号分隔键；缺省/空不下发=网关不判定
	// 未授权模型，与 LLM 端点识别/观测解耦——识别与观测不依赖本名单）
	APILLMAllowedModels []string `json:"api_llm_allowed_models,omitempty"`
	// APIFileWatermark 文件下载水印 v1（W12-GW / P2-01 最小可行子集；来源 system_settings
	// gateway_runtime 组 api_file_watermark_* 键，guardconfig 校验后注入；
	// nil = 未配置/未启用，网关响应侧零行为变化）
	APIFileWatermark *GuardFileWatermark `json:"api_file_watermark,omitempty"`
	// APIFileSignature 文件签名 v1（W13-GW / P2-02；来源 system_settings gateway_runtime 组
	// api_file_signature_key（密文解密）与 api_file_signature_kid，guardconfig 注入；
	// nil = 未配置/未启用，网关响应侧零行为变化；版本快照经 RedactGuardConfig 脱敏，
	// 回滚时按当前设置重新解密注入）
	APIFileSignature *GuardFileSignature `json:"api_file_signature,omitempty"`
	// APIFileComplianceRules 文件合规规则（W13-GW / P2-03；api_file_compliance_rules 表
	// enabled 行，表由另一分片迁移建立，表缺失/查询失败时发布侧 Warn 跳过不下发；
	// 不下发时网关文件合规检测零行为，与历史版本一致；内容纳入 api_policy_version 版本戳）
	APIFileComplianceRules []GuardFileComplianceRule `json:"api_file_compliance_rules,omitempty"`
	// APIResponseFailPolicy 响应处理失败策略（FAIL_OPEN|FAIL_CLOSED；缺省网关 FAIL_OPEN）
	APIResponseFailPolicy string `json:"api_response_fail_policy,omitempty"`
	// APIResponseCaptureMaxBytes 响应捕获上限（字节；缺省网关 1MiB，网关侧硬上限 16MiB）
	APIResponseCaptureMaxBytes int `json:"api_response_capture_max_bytes,omitempty"`
	// APIGRPCMaxFrameBytes gRPC 单帧声明长度上限（W14-GW / P2-05；字节；缺省网关 4MiB，
	// 网关侧硬上限 64MiB；来源 gateway_runtime 组 api_grpc_max_frame_bytes）
	APIGRPCMaxFrameBytes int `json:"api_grpc_max_frame_bytes,omitempty"`
	// APIGRPCAllowCompression gRPC 压缩帧许可（W14-GW / P2-05；缺省 false =
	// 压缩标志位置位产 grpc.unexpected_compression OBSERVE；
	// 来源 gateway_runtime 组 api_grpc_allow_compression）
	APIGRPCAllowCompression bool `json:"api_grpc_allow_compression,omitempty"`
	// APIGRPCDescriptors gRPC 描述符集（W14-DESC / P2-05 深化；api_grpc_descriptors 表
	// ENABLED 行，表由迁移 000076 建立，表缺失/查询失败时发布侧 Warn 跳过不下发；
	// 不下发时网关字段级解析零行为，退化为 v1 帧结构校验；内容纳入 api_policy_version 版本戳）
	APIGRPCDescriptors []GuardGRPCDescriptor `json:"api_grpc_descriptors,omitempty"`
	// AccessLog 全量访问日志（二期；nil 或 enabled=false 时网关零行为变化）
	AccessLog *GuardAccessLog `json:"access_log,omitempty"`
	// TraceTrustExternal / TraceInjectUpstream W3C trace 上下文开关（APM，ADR D5/D6；
	// 对应网关 trace_trust_external / trace_inject_upstream）。
	// 取值来源待 APM 阶段2 管理面接线——gateway_runtime 组运行时设置的读取与下发
	// 整体挂在 WDSP 门控内（provider.applyGatewayRuntime / stripAPIGuardSections），
	// 不适用于该底座能力；当前恒为 false 不下发，网关按默认（不信任外部 trace、
	// 不向上游注入 traceparent）运行，与历史版本逐字节一致。
	TraceTrustExternal  bool `json:"trace_trust_external,omitempty"`
	TraceInjectUpstream bool `json:"trace_inject_upstream,omitempty"`
	// L7Rules L7 访问控制（契约一 l7_rules 段；nil 时不下发——API 形态与历史版本零行为变化）
	L7Rules *GuardL7Rules `json:"l7_rules,omitempty"`
	// IdentityBehavior 侦察/枚举行为检测策略（WDSP AI 自动化渗透防护增强 阶段1；
	// security_behavior_policy 表 GLOBAL 行，表由迁移 000098 建立；nil 时不下发——
	// 网关行为检测零行为变化；enabled=false 时下发 enabled:false 网关零行为）
	IdentityBehavior *GuardIdentityBehavior `json:"identity_behavior,omitempty"`
	// IdentityEventsLog 身份与行为事件日志路径（网关容器内；随 identity_behavior
	// 段一并下发，与 events_log 同目录推导——GATEWAY_IDENTITY_EVENTS_LOG）
	IdentityEventsLog string `json:"identity_events_log,omitempty"`
	// RiskPolicy 身份风险处置策略（WDSP AI 自动化渗透防护增强 阶段3；
	// security_risk_policy 表 GLOBAL 行，表由迁移 000101 建立；nil 时不下发——
	// 网关风险处置零行为变化；enabled=false 时下发 enabled:false 网关零处置）
	RiskPolicy *GuardRiskPolicy `json:"risk_policy,omitempty"`
	// JWTTrust 业务 JWT 信任链策略（WDSP P0-03；jwt_trust_policies 表按应用行，
	// 表由迁移 000125 建立；nil/空 map 时不下发——网关 JWT 校验零行为变化；
	// key 为应用编码，随 WDSP API 动态防护门控下发并纳入 api_policy_version 版本戳；
	// 静态 JWKS 仅公钥（非秘密），不含任何业务 Token 或私钥材料）
	JWTTrust map[string]*GuardJWTTrustPolicy `json:"jwt_trust,omitempty"`
	// BotPolicy Bot 挑战策略（WDSP P1-02 B1；bot_policies 表按应用行，
	// 表由迁移 000128 建立；nil/空 map 时不下发——网关 Bot 判定零行为变化；
	// key 为应用编码，随 WDSP API 动态防护门控下发并纳入 api_policy_version 版本戳；
	// 读取失败中止发布（fail-hard），OFF 策略同样下发以覆盖网关旧配置残留；
	// 内容无秘密材料——challenge.key_ref 仅为预置密钥引用名。
	// 本阶段（B1）网关侧仅解析/校验/装配，请求链无挑战行为（B3 挂接））
	BotPolicy map[string]*GuardBotPolicy `json:"bot_policy,omitempty"`
	// BotSigningKeys Bot 挑战签名密钥（WDSP P1-02 B3 预备；key_ref → 密钥材料 hex，
	// 来源 system_settings gateway_runtime 组 bot_signing_keys 密文，发布时解密注入）。
	// 秘密材料纪律（与 api_scan_verification/api_file_signature 同一口径）：
	// 快照经 RedactGuardConfig 脱敏为占位、回滚由 replayRuntimeSecrets 按当前设置
	// 重新解密注入、不参与 api_policy_version 版本戳（密钥轮换不视为防护内容变更）、
	// 不进审计/日志/API 响应；渲染进应用 bot_policy 段时以 signing_keys 键并入
	// （网关 bot_policy 段装配处按 key_ref 构造 botchallenge.NewKeyring）。
	BotSigningKeys map[string]string `json:"bot_signing_keys,omitempty"`
	// APIExceptions API 引擎受限例外（WDSP P0-04；exception_policies 表
	// target_engine='API' 且启用行，列由迁移 000130 建立；nil/空 map 时不下发——
	// 网关 API 决策零行为变化；key 为应用编码，随 WDSP API 动态防护门控下发
	// 并纳入 api_policy_version 版本戳；读取失败中止发布 fail-hard）。
	// 仅 OBSERVE_RULE 动作：命中 Finding 保留并标 OBSERVED，取消其本次执法贡献后重算；
	// JWT/协议底线/人工封禁/访问控制/CC/配额/全局风险策略不可经此例外跳过。
	APIExceptions map[string][]GuardAPIException `json:"api_exceptions,omitempty"`
	// LicenseMaxQPS 授权配额全局限速（每秒请求数，0=不限制；授权有效且配额 max_qps>0 时
	// 由发布侧注入，网关对所有请求做全局限速，超限 429）
	LicenseMaxQPS int `json:"license_max_qps,omitempty"`
}

// buildGuardHandler 构建单应用路由的 jiuzhang_guard 处理器 JSON。
// publicPort 为路由所在监听的接入端口（302 Location 端口改写目标；0 表示不改写）。
// 部署模式（docs/NETWORK_MODES_DESIGN.md §4.1）：ROUTED（路由牵引）下客户端直连本网关，
// 不下发可信代理链（trusted_proxies 输出空数组），网关按直连对端识别真实客户端 IP，
// 并附加 deployment_mode 字段便于事件/排障识别（网关模块对未知字段容忍）；
// REVERSE_PROXY（含缺省）输出与历史版本逐字节一致。
func buildGuardHandler(g *GuardConfig, app AppData, publicPort int) mapT {
	trustedProxies := g.TrustedProxies
	routed := app.DeploymentMode == applications.DeployModeRouted
	if routed {
		trustedProxies = []GuardProxy{}
	}
	h := mapT{
		"handler":             "jiuzhang_guard",
		"app_id":              app.AppID,
		"app_code":            app.Code,
		"trusted_proxies":     trustedProxies,
		"max_proxy_chain":     g.MaxProxyChain,
		"protected_addresses": g.ProtectedAddresses,
		"global_allow":        g.GlobalAllow,
		"global_deny":         g.GlobalDeny,
		"counter_backend":     g.CounterBackend,
		"max_counter_keys":    g.MaxCounterKeys,
		"fail_open":           g.FailOpen,
		"events_log":          g.EventsLog,
		"gateway_node":        g.GatewayNode,
	}
	if routed {
		h["deployment_mode"] = applications.DeployModeRouted
	}
	appAllow := []GuardRule{}
	appDeny := []GuardRule{}
	policies := make([]GuardPolicy, 0, len(g.GlobalPolicies)+8)
	for _, p := range g.GlobalPolicies {
		cp := p
		if cp.Scope == "" {
			cp.Scope = "GLOBAL"
		}
		policies = append(policies, cp)
	}
	if ar, ok := g.AppRules[app.Code]; ok && ar != nil {
		appAllow = ar.Allow
		appDeny = ar.Deny
		for _, p := range ar.Policies {
			cp := p
			if cp.Scope == "" {
				cp.Scope = "APPLICATION"
			}
			policies = append(policies, cp)
		}
	}
	h["app_allow"] = appAllow
	h["app_deny"] = appDeny
	h["rate_limits"] = policies
	if g.Valkey != nil {
		h["valkey"] = g.Valkey
	}
	// 全量访问日志（二期）：非 nil 时注入（网关按 enabled 决定是否采集）
	if g.AccessLog != nil {
		h["access_log"] = g.AccessLog
	}
	// W3C trace 上下文开关（APM 底座能力，不受 WDSP 门控；沿用「true 显式下发」模式，
	// false/缺省不下发=网关内置默认兜底——不信任外部 trace、不向上游注入 traceparent，
	// 与历史版本逐字节一致；取值来源待 APM 阶段2 管理面接线，见 GuardConfig 字段注释）
	if g.TraceTrustExternal {
		h["trace_trust_external"] = true
	}
	if g.TraceInjectUpstream {
		h["trace_inject_upstream"] = true
	}
	// L7 访问控制（契约一 l7_rules 段）：非 nil 时注入，位于每个应用的 guard 处理器配置内
	// （与 global_allow 等全局段同级，网关按 priority 首中即停评估）
	if g.L7Rules != nil {
		h["l7_rules"] = g.L7Rules
	}
	// 侦察/枚举行为检测（identity_behavior 段，WDSP AI 自动化渗透防护增强 阶段1）：
	// 非 nil 时注入（含 enabled=false 显式下发——网关行为检测零行为）；
	// identity_events_log 随策略段一并下发（身份/行为事件日志落点，跨分片契约）
	if g.IdentityBehavior != nil {
		h["identity_behavior"] = g.IdentityBehavior
		if g.IdentityEventsLog != "" {
			h["identity_events_log"] = g.IdentityEventsLog
		}
	}
	// 身份风险策略处置（risk_policy 段，WDSP AI 自动化渗透防护增强 阶段3）：
	// 非 nil 时注入（含 enabled=false 显式下发——网关风险处置零行为）。
	// 注意：access_control_versions 快照序列化 GuardConfig 自带 risk_policy 键，
	// 网关实际消费的是本处理器 map——两处都必须有，缺一即「快照有、网关无」。
	if g.RiskPolicy != nil {
		h["risk_policy"] = g.RiskPolicy
	}
	// 授权配额全局限速（LicenseMaxQPS > 0 时注入；0=不限制不下发，网关零行为变化）
	if g.LicenseMaxQPS > 0 {
		h["license_max_qps"] = g.LicenseMaxQPS
	}
	// 阶段8：仅在 WDSP 开启时注入 API 动态防护配置（关闭时 JSON 与纯 WAF 一致）
	if g.APIDynamicProtection {
		h["api_dynamic_protection"] = true
		if g.APIProtectionMode != "" {
			h["api_protection_mode"] = g.APIProtectionMode
		}
		if g.APIEventsLog != "" {
			h["api_events_log"] = g.APIEventsLog
		}
		if len(g.APIFormalSchemas) > 0 {
			h["api_formal_schemas"] = g.APIFormalSchemas
		}
		if len(g.APIFormalModelVersions) > 0 {
			h["api_formal_model_versions"] = g.APIFormalModelVersions
		}
		if len(g.APIParameterConstraints) > 0 {
			h["api_parameter_constraints"] = g.APIParameterConstraints
		}
		if len(g.APIKnownEndpoints) > 0 {
			h["api_known_endpoints"] = g.APIKnownEndpoints
		}
		// API 策略版本戳（本次发布内容哈希；网关可按此回报生效版本）
		if g.APIPolicyVersion != "" {
			h["api_policy_version"] = g.APIPolicyVersion
		}
		// 网关运行时设置（gateway_runtime 组；缺省键不下发，网关内置默认值兜底）
		if g.BehaviorStore != "" {
			h["behavior_store"] = g.BehaviorStore
		}
		if g.BehaviorStoreTTLSeconds > 0 {
			h["behavior_store_ttl_seconds"] = g.BehaviorStoreTTLSeconds
		}
		if g.IdentitySalt != "" {
			h["identity_salt"] = g.IdentitySalt
		}
		if g.CredentialIPSpreadLimit > 0 {
			h["credential_ip_spread_limit"] = g.CredentialIPSpreadLimit
		}
		if g.CredentialConcurrencyLimit > 0 {
			h["credential_concurrency_limit"] = g.CredentialConcurrencyLimit
		}
		if g.APIWriteRatePerMinute > 0 {
			h["api_write_rate_per_minute"] = g.APIWriteRatePerMinute
		}
		// 响应脱敏规则（api_masking_rules 表 enabled 规则）
		if len(g.APIMaskRules) > 0 {
			h["api_mask_rules"] = g.APIMaskRules
		}
		// 值级敏感检测规则（api_sensitive_data_types 表 ENABLED 且 regex 非空类型）
		if len(g.APISensitiveValueRules) > 0 {
			h["api_sensitive_value_rules"] = g.APISensitiveValueRules
		}
		// 角色功能级基线（api_role_baselines 表 confirmed 行；仅 WDSP 开启且非空时注入）
		if len(g.APIRoleBaselines) > 0 {
			h["api_role_baselines"] = g.APIRoleBaselines
		}
		if len(g.APIAuthzModels) > 0 || len(g.APIAuthzRoleBaselines) > 0 {
			if len(g.APIAuthzModels) > 0 {
				h["api_authz_models"] = g.APIAuthzModels
				h["api_authz_relations"] = g.APIAuthzRelations
				h["api_authz_object_hmac_key_hex"] = g.APIAuthzObjectHMACKeyHex
			}
			if len(g.APIAuthzRoleBaselines) > 0 {
				h["api_authz_role_baselines"] = g.APIAuthzRoleBaselines
			}
		}
		if g.APIAuthzSnapshotStale {
			h["api_authz_snapshot_stale"] = true
		}
		if g.APIAuthzSnapshotExpiresAt != nil {
			h["api_authz_snapshot_expires_at"] = g.APIAuthzSnapshotExpiresAt
		}
		if g.APIAuthzPreviousValid != nil {
			// The HMAC key is runtime secret material. It is injected from the
			// current setting by config_secrets, just like the current snapshot.
			previous := *g.APIAuthzPreviousValid
			if len(previous.Models) > 0 {
				previous.ObjectHMACKeyHex = g.APIAuthzObjectHMACKeyHex
			}
			h["api_authz_previous_valid"] = previous
		}
		// 字段权限（api_field_permissions 表行；仅 WDSP 开启且非空时注入）
		if len(g.APIFieldPermissions) > 0 {
			h["api_field_permissions"] = g.APIFieldPermissions
		}
		// 扫描流量识别密钥（apiscan 签名密钥；非空时注入，网关校验 X-JiuZhang-Scan 签名）
		if g.APIScanVerification != nil && g.APIScanVerification.KeyHex != "" {
			h["api_scan_verification"] = g.APIScanVerification
		}
		// 响应结构基线（api_response_schemas 表达阈值学习行；仅 WDSP 开启且非空时注入）
		if len(g.APIResponseBaselines) > 0 {
			h["api_response_baselines"] = g.APIResponseBaselines
		}
		// 已确认参数条件关系（api_parameter_relations 表 confirmed 行；仅 WDSP 开启且非空时注入）
		if len(g.APIParameterRelations) > 0 {
			h["api_parameter_relations"] = g.APIParameterRelations
		}
		// LLM 授权模型名单（gateway_runtime 组 api_llm_allowed_models；仅 WDSP 开启且非空时注入，
		// 缺省不下发=网关不判定未授权模型）
		if len(g.APILLMAllowedModels) > 0 {
			h["api_llm_allowed_models"] = g.APILLMAllowedModels
		}
		// 文件下载水印 v1（gateway_runtime 组 api_file_watermark_*；仅 WDSP 开启且配置时注入，
		// 未配置=网关响应侧零行为变化）
		if g.APIFileWatermark != nil {
			h["api_file_watermark"] = g.APIFileWatermark
		}
		// 文件签名 v1（W13-GW / P2-02：gateway_runtime 组 api_file_signature_* 密文解密注入；
		// 未配置=网关响应侧零行为变化）
		if g.APIFileSignature != nil && g.APIFileSignature.Enabled {
			h["api_file_signature"] = g.APIFileSignature
		}
		// 文件合规规则（W13-GW / P2-03：api_file_compliance_rules 表 enabled 行；
		// 仅 WDSP 开启且非空时注入，未配置=网关合规检测零行为）
		if len(g.APIFileComplianceRules) > 0 {
			h["api_file_compliance_rules"] = g.APIFileComplianceRules
		}
		// 响应处理失败策略与捕获上限（缺省不下发，网关 FAIL_OPEN/1MiB 兜底）
		if g.APIResponseFailPolicy != "" {
			h["api_response_fail_policy"] = g.APIResponseFailPolicy
		}
		if g.APIResponseCaptureMaxBytes > 0 {
			h["api_response_capture_max_bytes"] = g.APIResponseCaptureMaxBytes
		}
		// gRPC 帧校验配置（W14-GW / P2-05：缺省不下发，网关 4MiB/不允许压缩兜底；
		// allow_compression 为布尔开关，true 时显式下发覆盖网关默认）
		if g.APIGRPCMaxFrameBytes > 0 {
			h["api_grpc_max_frame_bytes"] = g.APIGRPCMaxFrameBytes
		}
		if g.APIGRPCAllowCompression {
			h["api_grpc_allow_compression"] = true
		}
		// gRPC 描述符集（W14-DESC / P2-05 深化：api_grpc_descriptors 表 ENABLED 行；
		// 仅 WDSP 开启且非空时注入，未配置=网关字段级解析零行为，与 v1 一致）
		if len(g.APIGRPCDescriptors) > 0 {
			h["api_grpc_descriptors"] = g.APIGRPCDescriptors
		}
		// 业务 JWT 信任链（P0-03 jwt_trust 段；按应用注入本应用策略——
		// OFF 同样下发以覆盖旧配置残留，网关按 mode 关闭校验；内容含策略版本与
		// issuer 配置 ID/keyset_version 溯源标识，无任何秘密材料）
		if pol, ok := g.JWTTrust[app.Code]; ok && pol != nil {
			h["jwt_trust"] = pol
		}
		// Bot 挑战策略（P1-02 bot_policy 段；按应用注入本应用策略——OFF 同样下发
		// 以覆盖旧配置残留；B1 网关侧仅解析/校验/装配，请求链零行为变化）。
		// B3 预备：签名密钥材料以 signing_keys 键并入段内（策略本体仍无秘密材料，
		// 版本戳与快照口径不变；无密钥时不下发该键，与既有版本逐字节一致）
		if pol, ok := g.BotPolicy[app.Code]; ok && pol != nil {
			if len(g.BotSigningKeys) > 0 {
				h["bot_policy"] = guardBotPolicyWithKeys{GuardBotPolicy: pol, SigningKeys: g.BotSigningKeys}
			} else {
				h["bot_policy"] = pol
			}
		}
		// API 引擎受限例外（P0-04 api_exceptions 段；按应用注入本应用例外集——
		// 网关侧 ParseAPIExceptionsSection 以应用编码为 key 严格解码（fail-closed），
		// 故以单条目 map 形态下发本应用切片；无启用例外时不下发，网关零行为变化；
		// 仅 OBSERVE_RULE 动作，JWT/访问控制/CC/配额等模块不可经此豁免）
		if list, ok := g.APIExceptions[app.Code]; ok && len(list) > 0 {
			h["api_exceptions"] = map[string][]GuardAPIException{app.Code: list}
		}
	}
	// 头合规：302 Location 端口改写（来自应用头合规配置）。
	// 注：下划线请求头由 Caddy 内核入口强制丢弃（GHSA-f59h-q822-g45g），无需下发开关。
	if app.HeaderConfig != nil && app.HeaderConfig.RedirectPortRewrite && publicPort > 0 {
		h["redirect_port_rewrite"] = publicPort
	}
	return h
}
