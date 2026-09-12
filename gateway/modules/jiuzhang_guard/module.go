// Package jiuzhang_guard 实现九章自主 Caddy 防护模块（阶段5：访问控制与CC防护；阶段8：API 动态防护挂点）。
//
// 请求处理顺序（与 ServeHTTP 实现一致）：真实IP识别 → JWT 信任链本地验证（可选，仅计算入上下文）
// → 身份解析与行为观测（可选）→ 保护地址
// → 人工临时封禁 → 全局白 → 应用白 → 全局黑 → 应用黑 → L7 访问控制（首中即停）→ 自动临时封禁
// → 身份风险策略处置（risk_policy，可选，OBSERVE 默认不实断）→ 授权全局限速（可选，默认关闭）
// → CC限速 → Bot 挑战判定（bot_policy，可选，默认 OFF；OBSERVE 只记录不实断，PROTECT 挑战/verify，
// 保护地址/白名单/L7 allow 不跳过 Bot；保留命名空间 /_wdsp/bot/v1/ 在本步骤最前置本地处理，
// verify 固定协议端点与墓碑均不反向代理）
// → API 动态防护管线（可选，默认关闭；JWT 强制处置在管线阶段统一放行出口 serveNext 执行，
// 白名单/L7 allow 不绕过 JWT PROTECT）→ 下一处理器（WAF）。
// 人工临时封禁查询在黑白名单之前（白名单不绕过人工封禁）；自动 CC 封禁可被白名单/L7 allow 绕过。
// 白名单命中直接放行：跳过 L7 访问控制、自动临时封禁、授权全局限速与 CC，
// 不绕过 Bot 挑战、API 动态防护、协议校验与 WAF（安全底线）；
// L7 allow 命中跳过自动临时封禁、授权全局限速与 CC 等后续 guard 检查，同样不绕过 Bot 挑战、
// API 动态防护与 WAF。
// 注：下划线请求头由 Caddy 内核在处理器链之前强制丢弃（GHSA-f59h-q822-g45g），无需模块处理。
package jiuzhang_guard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/grpcdesc"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/accesscontrol"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/botchallenge"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/cidr"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
	// tls.stek.jiuzhang：静态 TLS 会话票据密钥提供模块（主备共享票据，HA §7.2）；
	// 空白导入触发 caddy.RegisterModule 注册（xcaddy 构建随 jiuzhang_guard 一并注入）
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/l7rules"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/ratelimit"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/riskengine"
	_ "github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/stek"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/temporaryblock"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/trustedproxy"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&Guard{})
}

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
// field_path 为点路径（数组段以 [] 结尾，如 users[].phone）；algorithm 取值 MASK|HASH|REMOVE；
// params 支持 keep_head/keep_tail（MASK，非负整数，默认 3/4）。
type maskRuleJSON struct {
	EndpointKey string         `json:"endpoint_key"`
	FieldPath   string         `json:"field_path"`
	DataType    string         `json:"data_type,omitempty"`
	Algorithm   string         `json:"algorithm"`
	Params      map[string]any `json:"params,omitempty"`
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

// fileWatermarkJSON 文件下载水印 v1（api_file_watermark 段；与管理后端发布通道约定一致）。
// nil 或 enabled=false = 未下发/未启用，响应侧零行为变化；content_types/json_key
// 缺省由引擎默认表/"_wm" 兜底。json tag 为跨分片契约，不得改动。
type fileWatermarkJSON struct {
	Enabled      bool     `json:"enabled"`
	TextTemplate string   `json:"text_template"`           // 支持 {ip}/{identity}/{time}/{domain} 占位
	ContentTypes []string `json:"content_types,omitempty"` // 媒体类型白名单（缺省引擎默认表）
	JSONKey      string   `json:"json_key,omitempty"`      // JSON 顶层水印字段名（缺省 "_wm"）
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
	// 写方法 API 每分钟限速（缺省 60，由引擎默认值兜底）
	APIWriteRatePerMinute int `json:"api_write_rate_per_minute,omitempty"`
	// 阶段8 §36 限流下发面（发布通道下发；0/缺省 = 对应检测不启用，不走引擎默认值
	// 冒充已配置——与上方三个限流键的默认兜底语义刻意不同）：
	// APIQuotaPerHour 身份+端点每小时配额（定窗）；APIQuotaPerDay 每日配额（UTC 自然日定窗）；
	// ObjectRatePerMinute 同身份对同对象每分钟上限；MaxPageSize 分页大小上限；MaxBatchSize 批量数量上限
	APIQuotaPerHour     int `json:"api_quota_per_hour,omitempty"`
	APIQuotaPerDay      int `json:"api_quota_per_day,omitempty"`
	ObjectRatePerMinute int `json:"object_rate_per_minute,omitempty"`
	MaxPageSize         int `json:"max_page_size,omitempty"`
	MaxBatchSize        int `json:"max_batch_size,omitempty"`
	// API 响应脱敏规则（发布通道下发；仅 API 流量 + 完整捕获的 JSON 响应生效）
	APIMaskRules []maskRuleJSON `json:"api_mask_rules,omitempty"`
	// 值级敏感检测规则（发布通道下发 api_sensitive_value_rules；对应管理面
	// api_sensitive_data_types 表 ENABLED 且 regex 非空的类型；nil/空 = 关闭值级检测，零行为变化）
	APISensitiveValueRules []detectors.SensitiveValueRule `json:"api_sensitive_value_rules,omitempty"`
	// 角色功能级基线（发布通道下发 api_role_baselines；对应管理面 api_role_baselines 表 confirmed 行；
	// nil/空 = 无端点基线，BFLA 检测零行为）
	APIRoleBaselines []detectors.RoleBaseline `json:"api_role_baselines,omitempty"`
	// AUTHZ-01 对象授权快照（发布通道下发；仅 gateway 侧 OBSERVE 判定）。
	// 模型/关系中的对象标识仅用于运行时匹配，事件只保留 HMAC objref。
	APIAuthzModels            []detectors.ObjectModel          `json:"api_authz_models,omitempty"`
	APIAuthzRelations         []detectors.ObjectRelation       `json:"api_authz_relations,omitempty"`
	APIAuthzRoleBaselines     []detectors.VerifiedRoleBaseline `json:"api_authz_role_baselines,omitempty"`
	APIAuthzObjectHMACKeyHex  string                           `json:"api_authz_object_hmac_key_hex,omitempty"`
	APIAuthzObjectHMACKey     []byte                           `json:"-"`
	APIAuthzSnapshotStale     bool                             `json:"api_authz_snapshot_stale,omitempty"`
	APIAuthzSnapshotExpiresAt *time.Time                       `json:"api_authz_snapshot_expires_at,omitempty"`
	APIAuthzPreviousValid     *authzSnapshotJSON               `json:"api_authz_previous_valid,omitempty"`
	apiAuthzPreviousValid     *detectors.AuthorizationConfig   `json:"-"`
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
	// 已吊销凭据清单（发布通道下发 api_revoked_credentials，阶段8 §35 第10项；对应管理面
	// api_revoked_credentials 表当前生效行；nil/空 = 无吊销清单，吊销检测零行为；
	// 装配期经 detectors.ValidateRevokedCredentials 校验，非法清单拒绝加载，不静默吞错；
	// 载荷仅指纹级（类型 + 32 位 hex 指纹），无凭据明文；运行期 OBSERVE 级只 AddMatch 不定案）
	APIRevokedCredentials []detectors.RevokedCredential `json:"api_revoked_credentials,omitempty"`
	// LLM 授权模型名单（发布通道下发 api_llm_allowed_models；来源 system_settings
	// gateway_runtime 组逗号分隔键；nil/空 = 不下发不判定未授权模型，
	// 与 LLM 端点识别/观测解耦——识别与观测不依赖本名单）
	APILLMAllowedModels []string `json:"api_llm_allowed_models,omitempty"`
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
	// gRPC 单帧声明长度上限（W14-GW / P2-05；字节；0 = 默认 4 MiB；上限 64 MiB 防内存误配；
	// 发布通道经 gateway_runtime 组 api_grpc_max_frame_bytes 下发）
	APIGRPCMaxFrameBytes int `json:"api_grpc_max_frame_bytes,omitempty"`
	// gRPC 压缩帧许可（W14-GW / P2-05；默认 false：压缩标志位置位产 grpc.unexpected_compression
	// OBSERVE；发布通道经 gateway_runtime 组 api_grpc_allow_compression 下发）
	APIGRPCAllowCompression bool `json:"api_grpc_allow_compression,omitempty"`
	// gRPC 描述符集（W14-DESC / P2-05 深化；发布通道下发 api_grpc_descriptors；
	// 对应管理面 api_grpc_descriptors 表 ENABLED 行；nil/空 = 无描述符，
	// gRPC 处理与 v1 完全一致：仅帧结构校验与计数观测，不做字段级解析）
	APIGRPCDescriptors []grpcDescriptorJSON `json:"api_grpc_descriptors,omitempty"`
	// FORMAL 模型版本（发布通道下发）：endpoint_key → 版本号；命中时写入事件 model_version
	APIFormalModelVersions map[string]string `json:"api_formal_model_versions,omitempty"`
	// 身份/来源指纹 HMAC 盐（identity_salt）：缺省时指纹未加盐（以固定域分隔前缀代替），启动 Warn 一次
	IdentitySalt string `json:"identity_salt,omitempty"`
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

	behaviorStores        *detectors.StoreOverrides // 按 BehaviorStore 构建（nil = 进程内默认内存）
	ibh                   *identitybehavior.Engine  // 身份与行为防护引擎（nil = 未启用，请求链路零变化）
	risk                  *riskengine.Engine        // 身份风险引擎（nil = risk_policy 未启用，请求链路零变化）
	cleaned               bool                      // Cleanup 幂等标记（只关资源不置 nil 字段，见 Cleanup 注释）
	cleanupErr            error
	apiMaskRules          map[string][]response.MaskRule          // 按 APIMaskRules 编译（endpoint_key 归组；nil = 无规则）
	apiRoleBaselines      map[string][]detectors.RoleBaseline     // 按 APIRoleBaselines 归组（endpoint_key；nil = 无基线）
	apiAuthzRelationIndex map[string][]detectors.ObjectRelation   // 按应用/对象类型/对象引用索引（nil = 无关系）
	apiFieldPerms         map[string][]detectors.FieldPermission  // 按 APIFieldPermissions 归组（endpoint_key；nil = 无权限行）
	apiScanKey            []byte                                  // 按 APIScanVerification 解码（nil = 未下发，仅存在性识别；秘密材料不落日志）
	apiRespBaselines      map[string][]detectors.ResponseBaseline // 按 APIResponseBaselines 归组（endpoint_key；nil = 无基线，偏离检测零行为）
	apiParamRelations     map[string][]detectors.ParamRelation    // 按 APIParameterRelations 归组（endpoint_key；nil = 无关系，关系检测零行为）
	apiFlowBaselines      map[string][]detectors.FlowBaseline     // 按 APIFlowBaselines 归组（endpoint_key；nil = 无基线，流程偏离检测零行为）
	apiFileWatermark      *response.FileWatermarkConfig           // 按 APIFileWatermark 编译（nil = 未下发/未启用，响应侧零行为变化）
	apiFileSignature      *response.FileSignatureConfig           // 按 APIFileSignature 编译（nil = 未下发/未启用，响应侧零行为变化；密钥为秘密材料不落日志）
	apiFileCompliance     *detectors.FileComplianceRuleSet        // 按 APIFileComplianceRules 编译（nil = 无规则，合规检测零行为）
	apiGRPCRegistry       *grpcdesc.Registry                      // 按 APIGRPCDescriptors 编译（nil = 无描述符，gRPC 与 v1 一致）
	jwtVerifier           *jwtverify.Verifier                     // 按 JWTTrust 装配（nil = 未下发/OFF，请求链路零变化）
	apiExceptions         map[string][]APIException               // 按 APIExceptions 装配（nil = 未下发，请求链路零变化）
	jwtFetcher            *jwtverify.Fetcher                      // 测试注入钩子（nil = 存在 REMOTE_JWKS 时装配期建默认受限获取器）
	jwtCancel             context.CancelFunc                      // 远程 JWKS 后台刷新取消（nil = 未启动；Cleanup 调用）
	botPolicy             *botPolicyJSON                          // 按 BotPolicy 装配（nil = 未下发；OFF 也保留段内容以维持 verify 命名空间墓碑；B3 起请求链经 serveNextViaBot 消费）
	botSvc                *botchallenge.Service                   // Bot 挑战服务（nil = OFF/未下发/OBSERVE 依赖缺失降级；PROTECT 依赖缺失在装配期 fail-closed 拒载）
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
}

// compiledPolicy 编译后的 CC 策略。
type compiledPolicy struct {
	cfg   policyJSON
	uriRe *regexp.Regexp
	from  *time.Time
	until *time.Time
}

// CaddyModule 返回模块信息。
func (Guard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jiuzhang_guard",
		New: func() caddy.Module { return new(Guard) },
	}
}

// ---------- 共享引擎（进程级：Valkey 连接/临时封禁缓存/内存计数器） ----------

type sharedEngine struct {
	mu          sync.Mutex
	initialized bool
	sig         string // 配置指纹（backend/addr/密码/DB/maxKeys）
	valkey      counters.ValkeyClient
	limiter     ratelimit.Limiter
	memLimiter  *ratelimit.MemoryLimiter
	blockStore  *temporaryblock.Store
	blockCache  *temporaryblock.Cache
	failOpen    bool
	cancelPoll  context.CancelFunc
	// 引擎错误告警节流（每分钟每类最多一条事件）
	lastErrEmit map[string]time.Time
}

var (
	engineMu   sync.Mutex
	engineInst *sharedEngine
)

// engineFingerprint 用于判断共享引擎是否需重建（凭据/后端变化）。
func engineFingerprint(g *Guard) string {
	backend := g.CounterBackend
	if backend == "" {
		backend = "valkey"
	}
	addr, user, pass, db := "", "", "", 0
	if g.Valkey != nil {
		addr = g.Valkey.Address
		user = g.Valkey.Username
		pass = g.Valkey.Password
		db = g.Valkey.DB
	}
	return fmt.Sprintf("%s|%s|%s|%s|%d|%d", backend, addr, user, pass, db, g.MaxCounterKeys)
}

// getEngine 初始化或复用共享引擎；失败不缓存半初始化实例，配置指纹变化时重建。
// 重建顺序（HIGH-5）：先完整构建并 init 新引擎（不触碰旧实例）→ 验证必需组件就绪 →
// 原子替换 engineInst → 替换成功后再关闭旧实例。init 失败时旧实例保持存活——Caddy 拒绝
// 新配置但在线旧配置的引擎（封禁轮询、CC/配额限速）不受失败重载影响。
func getEngine(g *Guard) (*sharedEngine, error) {
	engineMu.Lock()
	defer engineMu.Unlock()
	sig := engineFingerprint(g)
	if engineInst != nil && engineInst.initialized && engineInst.sig == sig &&
		engineInst.limiter != nil && engineInst.blockCache != nil {
		return engineInst, nil
	}
	e := &sharedEngine{lastErrEmit: map[string]time.Time{}, sig: sig}
	if err := e.init(g); err != nil {
		return nil, err
	}
	if e.limiter == nil || e.blockCache == nil {
		// init 未装配完整：回收半成品（不污染共享指针），旧实例继续服务
		e.shutdown()
		return nil, fmt.Errorf("engine init incomplete")
	}
	old := engineInst
	engineInst = e
	// 替换成功后停止旧轮询并关闭旧 Valkey 连接：不关则每次改 Valkey 配置的 reload
	// 都会泄漏一条（Close 失败仅告警；在途请求由引擎 FailOpen 策略兜底）
	if old != nil {
		old.shutdown()
	}
	return engineInst, nil
}

// shutdown 停止封禁轮询并关闭 Valkey 连接（引擎被替换或半成品回收时调用；幂等）。
func (e *sharedEngine) shutdown() {
	if e.cancelPoll != nil {
		e.cancelPoll()
		e.cancelPoll = nil
	}
	if e.valkey != nil {
		if err := e.valkey.Close(); err != nil {
			slog.Warn("jiuzhang_guard old valkey connection close on engine rebuild failed", "error", err)
		}
		e.valkey = nil
	}
}

// resetSharedEngineForTest 测试辅助：清空进程级引擎。
func resetSharedEngineForTest() {
	engineMu.Lock()
	defer engineMu.Unlock()
	if engineInst != nil {
		engineInst.shutdown()
	}
	engineInst = nil
}

func (e *sharedEngine) init(g *Guard) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failOpen = g.FailOpen == nil || *g.FailOpen
	e.memLimiter = ratelimit.NewMemoryLimiter(g.MaxCounterKeys)
	backend := g.CounterBackend
	if backend == "" {
		backend = "valkey"
	}
	if backend == "valkey" && g.Valkey != nil && g.Valkey.Address != "" {
		cli, err := counters.NewValkeyClient(counters.ValkeyConfig{
			Address:  g.Valkey.Address,
			Username: g.Valkey.Username,
			Password: g.Valkey.Password,
			DB:       g.Valkey.DB,
		})
		if err != nil {
			return fmt.Errorf("valkey init: %w", err)
		}
		e.valkey = cli
		e.limiter = ratelimit.NewValkeyLimiter(cli, "")
		e.blockStore = temporaryblock.NewStore(cli, "")
		poll, _ := time.ParseDuration(g.TempBlockPollInterval)
		e.blockCache = temporaryblock.NewCache(e.blockStore, poll)
		ctx, cancel := context.WithCancel(context.Background())
		e.cancelPoll = cancel
		if err := e.initialBlockRefresh(g, ctx); err != nil {
			// fail-closed 首刷失败拒绝加载：回收半成品（关 Valkey 连接/取消 ctx），
			// 旧引擎保持存活（HIGH-5），Caddy 拒绝新配置
			e.shutdown()
			return err
		}
		e.blockCache.Start(ctx)
	} else {
		// 纯内存模式：临时封禁仅进程内有效（单节点模式）
		e.blockCache = temporaryblock.NewCache(nil, 0)
		e.limiter = e.memLimiter
	}
	e.initialized = true
	return nil
}

// tempBlockRefreshErrKey 启动首刷失败告警的节流键（无策略维度，引擎级固定键）。
const tempBlockRefreshErrKey = "__tempblock_initial_refresh__"

// initialBlockRefresh 启动首刷（M-13）：失败除 Error 日志外产节流事件（与请求路径
// emitEngineErrorThrottled 同一节流口径，共享 lastErrEmit）；fail-closed 下首刷失败
// 返回错误拒绝加载，fail-open（默认）行为不变——空缓存启动、下一轮轮询重试。
// 调用方须已持有 e.mu。
func (e *sharedEngine) initialBlockRefresh(g *Guard, ctx context.Context) error {
	if err := e.blockCache.Refresh(ctx); err != nil {
		slog.Error("jiuzhang_guard tempblock initial refresh failed", "error", err)
		if engineErrThrottleLocked(e, tempBlockRefreshErrKey) {
			g.emitStartupEngineError(err)
		}
		if !e.failOpen {
			return fmt.Errorf("tempblock initial refresh: %w", err)
		}
	}
	return nil
}

// ---------- Provision / Validate ----------

// Provision 解析配置并初始化运行时。
func (g *Guard) Provision(ctx caddy.Context) error {
	g.logger = ctx.Logger()
	if g.EventsLog == "" {
		return fmt.Errorf("events_log is required")
	}
	if g.GatewayNode == "" {
		g.GatewayNode = "gateway-unknown"
	}
	g.resolver = clientip.NewResolver(g.MaxProxyChain)
	g.failOpen = g.FailOpen == nil || *g.FailOpen
	if strings.TrimSpace(g.APIAuthzObjectHMACKeyHex) != "" {
		key, err := hex.DecodeString(strings.TrimSpace(g.APIAuthzObjectHMACKeyHex))
		if err != nil || len(key) != 32 {
			return fmt.Errorf("api_authz_object_hmac_key_hex must be 32-byte hex")
		}
		g.APIAuthzObjectHMACKey = key
	}
	if len(g.APIAuthzModels) > 0 && len(g.APIAuthzObjectHMACKey) != 32 {
		return fmt.Errorf("api_authz_object_hmac_key_hex is required when api_authz_models is configured")
	}
	if g.APIAuthzPreviousValid != nil {
		previous := g.APIAuthzPreviousValid
		key := []byte(nil)
		if strings.TrimSpace(previous.ObjectHMACKeyHex) != "" {
			decoded, err := hex.DecodeString(strings.TrimSpace(previous.ObjectHMACKeyHex))
			if err != nil || len(decoded) != 32 {
				return fmt.Errorf("api_authz_previous_valid.object_hmac_key_hex must be 32-byte hex")
			}
			key = decoded
		}
		if len(previous.Models) > 0 && len(key) != 32 {
			return fmt.Errorf("api_authz_previous_valid.object_hmac_key_hex is required when models are configured")
		}
		g.apiAuthzPreviousValid = &detectors.AuthorizationConfig{
			ApplicationID: g.AppID,
			Models:        previous.Models, Relations: previous.Relations,
			RelationIndex: detectors.BuildAuthorizationRelationIndex(previous.Relations),
			RoleBaselines: previous.RoleBaselines, ObjectRefHMACKey: key,
			PolicyVersion: previous.PolicyVersion, Stale: previous.Stale,
			SnapshotExpiresAt: previous.SnapshotExpiresAt,
		}
	}
	g.apiAuthzRelationIndex = detectors.BuildAuthorizationRelationIndex(g.APIAuthzRelations)

	// 可信代理
	proxies := make([]trustedproxy.Proxy, 0, len(g.TrustedProxies))
	for _, p := range g.TrustedProxies {
		pfx, err := cidr.ParseAddress(p.CIDR)
		if err != nil {
			return fmt.Errorf("trusted proxy %q: %w", p.Name, err)
		}
		proxies = append(proxies, trustedproxy.Proxy{
			Name:             p.Name,
			Prefix:           pfx,
			HeaderType:       trustedproxy.HeaderType(p.HeaderType),
			CustomHeaderName: p.CustomHeaderName,
			Priority:         p.Priority,
		})
	}
	set, err := trustedproxy.NewSet(proxies)
	if err != nil {
		return err
	}
	g.proxies = set

	// 保护地址
	entries := make([]cidr.Entry, 0, len(g.ProtectedAddresses))
	for _, a := range g.ProtectedAddresses {
		pfx, err := cidr.ParseAddress(a)
		if err != nil {
			return fmt.Errorf("protected address %q: %w", a, err)
		}
		entries = append(entries, cidr.Entry{Prefix: pfx, Meta: a})
	}
	g.protected = cidr.NewMatcher(entries)

	// 黑白名单
	if g.allowG, err = buildRuleSet(g.GlobalAllow); err != nil {
		return fmt.Errorf("global allow: %w", err)
	}
	if g.allowA, err = buildRuleSet(g.AppAllow); err != nil {
		return fmt.Errorf("app allow: %w", err)
	}
	if g.denyG, err = buildRuleSet(g.GlobalDeny); err != nil {
		return fmt.Errorf("global deny: %w", err)
	}
	if g.denyA, err = buildRuleSet(g.AppDeny); err != nil {
		return fmt.Errorf("app deny: %w", err)
	}

	// CC 策略
	policies, err := compilePolicies(g.RateLimits)
	if err != nil {
		return err
	}
	g.policies = policies

	// 授权配额全局限速（license_max_qps）：0=不限制；负数拒绝加载，不静默吞错
	if g.LicenseMaxQPS < 0 {
		return fmt.Errorf("license_max_qps must be non-negative, got %d", g.LicenseMaxQPS)
	}

	// 自定义 429/阻断响应页面（block_response 段）：装配期校验 + 白名单净化；
	// 非法配置拒绝加载（fail-closed），nil = 内置默认模板（writeTooMany 原路径）
	blockResponse, err := compileBlockResponse(g.BlockResponse)
	if err != nil {
		return err
	}
	g.blockResponse = blockResponse

	// L7 访问控制规则（编译失败的规则整条拒绝并告警，不影响其余规则加载；
	// 配置重载即整体原子替换，与黑白名单同一热更新路径）
	if g.L7Rules != nil {
		eng, ruleErrs := l7rules.Compile(g.L7Rules)
		for _, re := range ruleErrs {
			g.logger.Warn("l7rules: 规则编译失败，已整条拒绝",
				zap.String("rule_id", re.RuleID), zap.Error(re.Err))
		}
		g.l7 = eng
		g.logger.Info("l7 access rules loaded",
			zap.Int("configured", len(g.L7Rules.Rules)),
			zap.Int("compiled", eng.RulesCount()),
			zap.Int("rejected", len(ruleErrs)))
	}

	// 事件记录器
	el, err := events.NewLogger(g.EventsLog, g.GatewayNode)
	if err != nil {
		return err
	}
	g.events = el

	// 网口清单采集器（WDSP 阶段A；进程级常驻，同签名复用，失败仅告警，见 netcollector.go）
	ensureNetifCollector(g)

	// API 动态防护事件记录器（独立事件流，由管理面采集入 api_runtime_events）
	if g.APIDynamicProtection {
		p := g.APIEventsLog
		if p == "" {
			p = filepath.Join(filepath.Dir(g.EventsLog), "api-runtime-events.log")
		}
		al, err := apievents.NewLogger(p, g.GatewayNode)
		if err != nil {
			return fmt.Errorf("api events log: %w", err)
		}
		g.apiEvents = al
		// 响应脱敏规则编译（endpoint_key 归组；配置错误拒绝加载，不静默吞错）
		rules, err := compileAPIMaskRules(g.APIMaskRules)
		if err != nil {
			return err
		}
		g.apiMaskRules = rules
		// 值级敏感检测规则预编译（RE2；非法规则拒绝加载并说明，不静默吞错）
		if _, err := detectors.CompileSensitiveValueRules(g.APISensitiveValueRules); err != nil {
			return fmt.Errorf("api_sensitive_value_rules: %w", err)
		}
		// 授权基线校验与按端点归组（配置错误拒绝加载，不静默吞错；运行期按端点 O(1) 选取）
		if err := detectors.ValidateAuthzRules(g.APIRoleBaselines, g.APIFieldPermissions); err != nil {
			return err
		}
		g.apiRoleBaselines = detectors.GroupRoleBaselines(g.APIRoleBaselines)
		g.apiFieldPerms = detectors.GroupFieldPermissions(g.APIFieldPermissions)
		// 扫描流量识别密钥解码（W9-GW；nil = 未下发，降级仅按头存在性识别；
		// 密钥材料为秘密，配置错误信息不含密钥值）
		scanKey, err := parseAPIScanVerificationKey(g.APIScanVerification)
		if err != nil {
			return err
		}
		g.apiScanKey = scanKey
		// 响应结构基线校验与按端点归组（W9-GW；配置错误拒绝加载，不静默吞错）
		if err := detectors.ValidateResponseBaselines(g.APIResponseBaselines); err != nil {
			return err
		}
		g.apiRespBaselines = detectors.GroupResponseBaselines(g.APIResponseBaselines)
		// 已确认参数条件关系校验与按端点归组（W11-REL；配置错误拒绝加载，不静默吞错）
		if err := detectors.ValidateParamRelations(g.APIParameterRelations); err != nil {
			return err
		}
		g.apiParamRelations = detectors.GroupParamRelations(g.APIParameterRelations)
		// 业务流程基线校验与按端点归组（§44；配置错误拒绝加载，不静默吞错；
		// 运行期按命中端点 O(1) 选取，与参数关系同一模式）
		if err := detectors.ValidateFlowBaselines(g.APIFlowBaselines); err != nil {
			return err
		}
		g.apiFlowBaselines = detectors.GroupFlowBaselines(g.APIFlowBaselines)
		// 已吊销凭据清单校验（§35 第10项；配置错误拒绝加载，不静默吞错；
		// 运行期管线编译比对集合后按请求凭据键 O(1) 查找，过期条目自行失效不判定）
		if err := detectors.ValidateRevokedCredentials(g.APIRevokedCredentials); err != nil {
			return err
		}
		// LLM 授权模型名单归一（W10-LLM：去空白/去重/去空项；名单语义宽容，
		// 单项非法不致配置拒绝——逐项 trim 后空项丢弃，与既有名单归一纪律一致）
		g.APILLMAllowedModels = normalizeLLMAllowedModels(g.APILLMAllowedModels)
		// 文件下载水印 v1 编译（W12-GW：nil 段/enabled=false = 未启用，响应侧零行为变化；
		// 启用但配置非法拒绝加载并说明，不静默吞错）
		if g.APIFileWatermark != nil {
			wm, err := response.NewFileWatermarkConfig(g.APIFileWatermark.Enabled,
				g.APIFileWatermark.TextTemplate, g.APIFileWatermark.ContentTypes, g.APIFileWatermark.JSONKey)
			if err != nil {
				return err
			}
			if wm.Enabled {
				g.apiFileWatermark = wm
			}
		}
		// 文件签名 v1 编译（W13-GW：nil 段/enabled=false = 未启用，响应侧零行为变化；
		// 密钥为秘密材料，配置错误信息不含密钥值）
		if g.APIFileSignature != nil {
			sig, err := response.NewFileSignatureConfig(g.APIFileSignature.Enabled,
				g.APIFileSignature.KID, g.APIFileSignature.KeyHex)
			if err != nil {
				return err
			}
			if sig.Enabled {
				g.apiFileSignature = sig
			}
		}
		// 文件合规规则编译（W13-GW：配置错误拒绝加载并说明，不静默吞错；nil/空 = 合规检测零行为）
		fc, err := detectors.CompileFileComplianceRules(g.APIFileComplianceRules)
		if err != nil {
			return err
		}
		g.apiFileCompliance = fc
		// gRPC 描述符注册表装配（W14-DESC / P2-05 深化；语义见 buildAPIGRPCRegistry）
		g.apiGRPCRegistry = g.buildAPIGRPCRegistry()
		// 参数约束 regex 预检：配置问题装配期 Warn（运行期对该约束保守 OBSERVE，见 detectors schema.go）
		warnInvalidConstraintRegexes(g)
		if g.IdentitySalt == "" {
			g.logger.Warn("identity_salt 未配置，指纹未加盐")
		}
		g.logger.Info("api dynamic protection enabled",
			zap.String("mode", string(apiDecisionMode(g.APIProtectionMode))),
			zap.String("events_log", p),
			zap.Int("formal_schemas", len(g.APIFormalSchemas)),
			zap.Int("parameter_constraints", len(g.APIParameterConstraints)),
			zap.Int("known_endpoints", len(g.APIKnownEndpoints)),
			zap.Int("mask_rules", len(g.APIMaskRules)),
			zap.Int("sensitive_value_rules", len(g.APISensitiveValueRules)),
			zap.Int("role_baselines", len(g.APIRoleBaselines)),
			zap.Int("field_permissions", len(g.APIFieldPermissions)),
			zap.Bool("scan_verification", len(g.apiScanKey) > 0),
			zap.Int("response_baselines", len(g.APIResponseBaselines)),
			zap.Int("parameter_relations", len(g.APIParameterRelations)),
			zap.Int("flow_baselines", len(g.APIFlowBaselines)),
			zap.Int("revoked_credentials", len(g.APIRevokedCredentials)),
			zap.Int("llm_allowed_models", len(g.APILLMAllowedModels)),
			zap.Bool("file_watermark", g.apiFileWatermark != nil),
			zap.Bool("file_signature", g.apiFileSignature != nil),
			zap.Int("file_compliance_rules", len(g.APIFileComplianceRules)),
			zap.String("response_fail_policy", g.resolvedResponseFailPolicy()),
			zap.Int("response_capture_max_bytes", g.responseCaptureMax()),
			zap.Int("grpc_max_frame_bytes", g.APIGRPCMaxFrameBytes),
			zap.Bool("grpc_allow_compression", g.APIGRPCAllowCompression),
			zap.Int("grpc_descriptor_sets", grpcRegistrySets(g.apiGRPCRegistry)),
			zap.Int("grpc_descriptor_methods", grpcRegistryMethods(g.apiGRPCRegistry)))
		// 节点心跳（W17-HB：周期上报活性+策略版本，独立于业务流量；0=关闭零行为变化）
		g.startAPINodeHeartbeat()
	}

	// 全量访问日志记录器（二期；enabled=false 时不打开文件，零行为变化）
	if g.AccessLog != nil && g.AccessLog.Enabled {
		p := g.AccessLog.LogPath
		if p == "" {
			p = defaultAccessLogPath
		}
		aw, err := newAccessLogWriter(p)
		if err != nil {
			return fmt.Errorf("access log: %w", err)
		}
		g.accessLog = aw
		g.logger.Info("full access log enabled",
			zap.String("log_path", p),
			zap.Bool("capture_request_headers", g.AccessLog.CaptureRequestHeaders),
			zap.Bool("capture_request_body", g.AccessLog.CaptureRequestBody),
			zap.Bool("capture_response_headers", g.AccessLog.CaptureResponseHeaders),
			zap.Bool("capture_response_body", g.AccessLog.CaptureResponseBody),
			zap.Int("body_limit_kb", g.AccessLog.BodyLimitKB))
	}

	// 共享引擎
	eng, err := getEngine(g)
	if err != nil {
		return err
	}
	g.engine = eng
	// 行为计数存储按 Guard 实例持有（memory/缺省 = nil，进程内默认零变化）。
	// 请求管线显式绑定本实例选择，配置重载与同进程多实例不会互相覆盖或残留。
	g.behaviorStores = buildBehaviorStores(g, eng)
	// 身份与行为防护装配（identity_behavior；nil/disabled = 零行为变化；装配失败 fail-open 置 nil）
	g.provisionIdentityBehavior(eng)
	// 身份风险策略装配（risk_policy；nil/disabled = 零行为变化；配置非法 fail-open 按 OBSERVE。
	// 须在 provisionIdentityBehavior 之后：装配期向身份引擎注入信号汇聚回调）
	g.provisionRiskPolicy(eng)
	// JWT 信任链验证器装配（jwt_trust 段；严格解码 + 构造任一失败即拒绝整体配置加载——
	// fail-closed，已存在 PROTECT 策略不得被静默删除/降级；段缺失/OFF = 零行为变化）
	if err := g.assembleJWTTrust(); err != nil {
		return err
	}
	// API 受限例外装配（api_exceptions 段；与 jwt_trust 同一 fail-closed 纪律——
	// 严格解码/校验任一失败即拒绝整体配置加载；段缺失 = 零行为变化。
	// 无条件装配：段存在即严格解析，不以 api_dynamic_protection 开关为前提——
	// 开关关闭时下发了例外段同样是配置错误，不得静默忽略）
	if err := g.assembleAPIExceptions(); err != nil {
		return err
	}
	// Bot 挑战策略装配（bot_policy 段；与 jwt_trust 同一 fail-closed 纪律——解析/校验
	// 失败拒绝整体配置加载；段缺失 = 零行为变化。B3 起接入请求链：非 OFF 装配挑战
	// 服务 g.botSvc（PROTECT 依赖缺失拒载、OBSERVE 降级仅装配持有），请求链经
	// serveNextViaBot 在 CC 之后、serveNext 之前消费）
	if err := g.assembleBotPolicy(); err != nil {
		return err
	}
	// 远程 JWKS 后台刷新（热路径零网络 IO；装配最后一步启动，Provision 失败不泄漏 goroutine）
	if g.jwtVerifier != nil {
		rctx, cancel := context.WithCancel(context.Background())
		g.jwtCancel = cancel
		g.jwtVerifier.StartBackgroundRefresh(rctx)
	}
	return nil
}

// assembleAPIExceptions 装配 API 受限例外（api_exceptions 段，WDSP P0-04）。
// 段缺失 = 零行为变化；段存在即严格解码+全量校验，任一失败拒绝整体配置加载
// （fail-closed，与 assembleJWTTrust 同一纪律）。
func (g *Guard) assembleAPIExceptions() error {
	if len(g.APIExceptions) == 0 {
		g.apiExceptions = nil
		return nil
	}
	sec, err := ParseAPIExceptionsSection(g.APIExceptions)
	if err != nil {
		return err
	}
	g.apiExceptions = sec
	return nil
}

// maxCounterKeysLimit max_counter_keys 上限（MED-8）：内存计数/身份行为/风险存储均按该值
// make 预分配（counters.NewMemoryMap 等），无上限时异常大值在 Provision 阶段即可 OOM 杀进程。
const maxCounterKeysLimit = 10_000_000

// Validate 配置校验。
func (g *Guard) Validate() error {
	if g.EventsLog == "" {
		return fmt.Errorf("events_log is required")
	}
	if g.MaxCounterKeys < 0 || g.MaxCounterKeys > maxCounterKeysLimit {
		return fmt.Errorf("max_counter_keys must be between 0 and %d", maxCounterKeysLimit)
	}
	// 自定义 429/阻断响应页面装配期校验（caddy validate 同样拦截非法配置）
	if err := validateBlockResponse(g.BlockResponse); err != nil {
		return err
	}
	for _, p := range g.RateLimits {
		if p.RequestsLimit <= 0 || p.WindowSeconds <= 0 {
			return fmt.Errorf("rate limit %q: limit/window must be positive", p.ID)
		}
	}
	if g.APIDynamicProtection {
		switch g.APIProtectionMode {
		case "", "OFF", "OBSERVE", "PROTECT":
		default:
			return fmt.Errorf("api_protection_mode must be OFF, OBSERVE or PROTECT")
		}
		switch g.APIResponseFailPolicy {
		case "", apiFailOpen, apiFailClosed:
		default:
			return fmt.Errorf("api_response_fail_policy must be FAIL_OPEN or FAIL_CLOSED")
		}
		if g.APIResponseCaptureMaxBytes < 0 || g.APIResponseCaptureMaxBytes > maxAPIResponseCaptureMaxBytes {
			return fmt.Errorf("api_response_capture_max_bytes must be between 0 and %d", maxAPIResponseCaptureMaxBytes)
		}
		if g.APIGRPCMaxFrameBytes < 0 || g.APIGRPCMaxFrameBytes > maxAPIGRPCMaxFrameBytes {
			return fmt.Errorf("api_grpc_max_frame_bytes must be between 0 and %d", maxAPIGRPCMaxFrameBytes)
		}
		// §36 限流阈值：负数非法（0 = 不启用），装配期显式拒绝
		for name, v := range map[string]int{
			"api_quota_per_hour": g.APIQuotaPerHour, "api_quota_per_day": g.APIQuotaPerDay,
			"object_rate_per_minute": g.ObjectRatePerMinute,
			"max_page_size":          g.MaxPageSize, "max_batch_size": g.MaxBatchSize,
		} {
			if v < 0 {
				return fmt.Errorf("%s must be >= 0", name)
			}
		}
		// gRPC 描述符集结构校验（W14-DESC：名/体量硬违例装配期显式拒绝；
		// FileDescriptorSet 线格式与 protodesc 语义编译失败在 Provision 逐集 Warn 跳过——
		// 描述符解析为增量观测能力，失败集降级为 v1 帧结构观测，不拖垮整体配置）
		for i, d := range g.APIGRPCDescriptors {
			if d.Name == "" || len(d.Name) > 128 {
				return fmt.Errorf("api_grpc_descriptors[%d]: bad name (empty or > 128 chars)", i)
			}
			raw, err := base64.StdEncoding.DecodeString(d.ContentBase64)
			if err != nil {
				return fmt.Errorf("api_grpc_descriptors[%d] (%s): bad base64", i, d.Name)
			}
			if len(raw) == 0 || len(raw) > grpcdesc.MaxSetBytes {
				return fmt.Errorf("api_grpc_descriptors[%d] (%s): content size %d out of range (1..%d)",
					i, d.Name, len(raw), grpcdesc.MaxSetBytes)
			}
		}
		if len(g.APIPolicyVersion) > 128 {
			return fmt.Errorf("api_policy_version must be <= 128 chars")
		}
		if _, err := compileAPIMaskRules(g.APIMaskRules); err != nil {
			return err
		}
		if _, err := detectors.CompileSensitiveValueRules(g.APISensitiveValueRules); err != nil {
			return fmt.Errorf("api_sensitive_value_rules: %w", err)
		}
		if err := detectors.ValidateAuthzRules(g.APIRoleBaselines, g.APIFieldPermissions); err != nil {
			return err
		}
		// 文件下载水印 v1 装配期校验（配置错误显式返回，不静默吞错）
		if g.APIFileWatermark != nil {
			if _, err := response.NewFileWatermarkConfig(g.APIFileWatermark.Enabled,
				g.APIFileWatermark.TextTemplate, g.APIFileWatermark.ContentTypes, g.APIFileWatermark.JSONKey); err != nil {
				return err
			}
		}
		// 文件签名 v1 与文件合规规则装配期校验（配置错误显式返回，不静默吞错；
		// 签名密钥为秘密材料，错误信息不含密钥值）
		if g.APIFileSignature != nil {
			if _, err := response.NewFileSignatureConfig(g.APIFileSignature.Enabled,
				g.APIFileSignature.KID, g.APIFileSignature.KeyHex); err != nil {
				return err
			}
		}
		if _, err := detectors.CompileFileComplianceRules(g.APIFileComplianceRules); err != nil {
			return err
		}
		// 扫描流量识别密钥与响应结构基线装配期校验（配置错误显式返回，不静默吞错）
		if _, err := parseAPIScanVerificationKey(g.APIScanVerification); err != nil {
			return err
		}
		if err := detectors.ValidateResponseBaselines(g.APIResponseBaselines); err != nil {
			return err
		}
		// 业务流程基线装配期校验（§44；配置错误显式返回，不静默吞错）
		if err := detectors.ValidateFlowBaselines(g.APIFlowBaselines); err != nil {
			return err
		}
		// 已吊销凭据清单装配期校验（§35 第10项；配置错误显式返回，不静默吞错）
		if err := detectors.ValidateRevokedCredentials(g.APIRevokedCredentials); err != nil {
			return err
		}
		for ek, v := range g.APIFormalModelVersions {
			if ek == "" || len(ek) > 560 {
				return fmt.Errorf("api_formal_model_versions: bad endpoint_key")
			}
			if v == "" || len(v) > 128 {
				return fmt.Errorf("api_formal_model_versions: bad version for %q", ek)
			}
		}
	}
	// 节点心跳：0=关闭；开启须为 30-300 秒且依赖 API 动态防护事件通道
	// （心跳记录写入 API 事件日志，通道随 api_dynamic_protection 装配）
	if g.APINodeHeartbeatSeconds != 0 {
		if !g.APIDynamicProtection {
			return fmt.Errorf("api_node_heartbeat_seconds requires api_dynamic_protection enabled")
		}
		if g.APINodeHeartbeatSeconds < minHeartbeatSeconds || g.APINodeHeartbeatSeconds > maxHeartbeatSeconds {
			return fmt.Errorf("api_node_heartbeat_seconds must be 0 or between %d and %d",
				minHeartbeatSeconds, maxHeartbeatSeconds)
		}
	}
	switch g.BehaviorStore {
	case "", "memory", "valkey":
	default:
		return fmt.Errorf("behavior_store must be memory or valkey")
	}
	if g.BehaviorStoreTTLSeconds < 0 {
		return fmt.Errorf("behavior_store_ttl_seconds must be >= 0")
	}
	// 身份与行为防护装配期校验（identity_behavior 启用时；比率 0-1、阈值非负、白名单可解析）
	if g.IdentityBehavior != nil && g.IdentityBehavior.Enabled {
		if err := identitybehavior.ValidateParams(g.IdentityBehavior); err != nil {
			return fmt.Errorf("identity_behavior: %w", err)
		}
	}
	// 身份风险策略（risk_policy）装配期不硬校验：冻结契约约定任何配置缺失/非法 fail-open
	// 按 OBSERVE（riskengine.Compile 逐项消毒 + Warn）——风险策略配置问题不得阻断整体配置加载
	// JWT 信任链（jwt_trust 段）装配期校验：严格解码 + 完整构造预检（静态 JWKS 解析、
	// 算法白名单、PROTECT 身份密钥门禁），任一失败显式拒绝（fail-closed，JWT-14；
	// 与「容忍未知字段」惯例相反是本段的显式例外）
	if len(g.JWTTrust) > 0 {
		sec, err := parseJWTTrustSection(g.JWTTrust)
		if err != nil {
			return err
		}
		if jwtverify.Mode(sec.Mode) != jwtverify.ModeOff {
			if _, err := g.buildJWTVerifier(sec); err != nil {
				return err
			}
		}
	}
	// Bot 挑战策略（bot_policy 段）装配期校验：严格解码 + 全量结构校验，任一失败
	// 显式拒绝（fail-closed，与 jwt_trust 同一纪律；OFF 同样校验——配置面与管理面
	// 同口径，避免「保存合法、网关拒载」分叉）
	if len(g.BotPolicy) > 0 {
		if _, err := parseAndValidateBotPolicy(g.BotPolicy); err != nil {
			return err
		}
	}
	// API 受限例外（api_exceptions 段）装配期预检：严格解码 + 全量校验，
	// 任一失败显式拒绝（fail-closed，与 jwt_trust 同一纪律）
	if len(g.APIExceptions) > 0 {
		if _, err := ParseAPIExceptionsSection(g.APIExceptions); err != nil {
			return err
		}
	}
	if g.RedirectPortRewrite < 0 || g.RedirectPortRewrite > 65535 {
		return fmt.Errorf("redirect_port_rewrite must be between 0 and 65535")
	}
	return nil
}

// Cleanup 关闭事件记录器（共享引擎随进程生命周期，不在配置重载时关闭）。
// 只关闭资源、不置 nil 字段（幂等，LOW-G4）：配置重载时 Cleanup 与旧配置的在途请求
// 并发，请求路径无锁读 g.ibh/g.risk/g.accessLog/g.events/g.apiEvents，置 nil 构成数据
// 竞态且 check-then-use 可 nil 解引用 panic；关闭后的在途写入由各记录器内部锁 +
// fail-open 告警兜底（写已关闭文件仅 Warn，不 panic）。Caddy 对同一实例串行调用
// Cleanup，故幂等标记无需加锁。
func (g *Guard) Cleanup() error {
	if g.cleaned {
		return g.cleanupErr
	}
	g.cleaned = true
	g.cleanupErr = g.cleanup()
	return g.cleanupErr
}

func (g *Guard) cleanup() error {
	// 先停心跳 goroutine 与 JWT 远程 JWKS 后台刷新（取消并等待退出，避免向已关闭的日志文件写），再关记录器
	if g.heartbeat != nil {
		g.heartbeat.stop()
	}
	if g.jwtCancel != nil {
		g.jwtCancel() // 只取消不置 nil（Cleanup 幂等纪律：请求路径无锁读字段不置空）
	}
	// 身份与行为防护引擎（关闭其事件记录器与存储；Valkey 共享连接归引擎不在此关）
	if g.ibh != nil {
		_ = g.ibh.Close()
	}
	// 身份风险引擎（关闭其存储；Valkey 共享连接归引擎不在此关）
	if g.risk != nil {
		_ = g.risk.Close()
	}
	if g.accessLog != nil {
		_ = g.accessLog.close()
	}
	var closeErr error
	if g.apiEvents != nil {
		if g.apiEventsClose != nil {
			closeErr = g.apiEventsClose()
		} else {
			closeErr = g.apiEvents.Close()
		}
	}
	if g.events != nil {
		closeErr = errors.Join(closeErr, g.events.Close())
	}
	return closeErr
}

// parseAPIScanVerificationKey 解码 api_scan_verification.key_hex（hex 解码 + 32 字节校验）：
// nil 段/空串 = 未下发（返回 nil，网关降级为仅按头存在性识别）；
// 非法编码/长度为配置错误显式返回（不静默吞错）。key_hex 为秘密材料：错误信息不含密钥值。
func parseAPIScanVerificationKey(v *scanVerificationJSON) ([]byte, error) {
	if v == nil || strings.TrimSpace(v.KeyHex) == "" {
		return nil, nil
	}
	key, err := hex.DecodeString(strings.TrimSpace(v.KeyHex))
	if err != nil {
		return nil, fmt.Errorf("api_scan_verification.key_hex: invalid hex encoding")
	}
	if err := detectors.ValidateScanVerificationKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

// buildAPIGRPCRegistry 装配 gRPC 描述符注册表：逐集 protodesc 编译入注册表；
// 单集失败 Warn 跳过不拒绝整体配置——描述符解析为增量观测能力，失败集对应服务
// 降级为 v1 帧结构观测（与 warnInvalidConstraintRegexes 的装配期 Warn 降级同一纪律，
// 错误如实记日志不静默）；无配置或全部失败返回 nil（gRPC 处理与 v1 完全一致）。
func (g *Guard) buildAPIGRPCRegistry() *grpcdesc.Registry {
	if len(g.APIGRPCDescriptors) == 0 {
		return nil
	}
	reg := grpcdesc.NewRegistry()
	for _, d := range g.APIGRPCDescriptors {
		if err := reg.AddSet(d.Name, d.ContentBase64); err != nil {
			g.logger.Warn("api grpc descriptor set skipped (degraded to frame-only observation)",
				zap.String("set", d.Name), zap.Error(err))
		}
	}
	if reg.Sets() == 0 {
		return nil
	}
	return reg
}

// grpcRegistrySets/Methods 注册表观测计数（nil 安全；装配日志使用）。
func grpcRegistrySets(r *grpcdesc.Registry) int {
	if r == nil {
		return 0
	}
	return r.Sets()
}

func grpcRegistryMethods(r *grpcdesc.Registry) int {
	if r == nil {
		return 0
	}
	return r.Methods()
}

// normalizeLLMAllowedModels LLM 授权模型名单归一：逐项去空白、去空项、去重（保序）。
// 名单语义宽容（发布侧已做长度/条数校验），网关侧不因此拒绝配置加载。
func normalizeLLMAllowedModels(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, m := range in {
		m = strings.TrimSpace(m)
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}

// warnInvalidConstraintRegexes 参数约束 regex 装配期预检：编译失败/超长逐条 Warn
// （运行期对该约束保守 OBSERVE 不阻断，见 detectors schema.go；预检仅让配置问题在装配期可见）。
func warnInvalidConstraintRegexes(g *Guard) {
	if g.logger == nil {
		return
	}
	for ek, list := range g.APIParameterConstraints {
		for i := range list {
			raw, ok := list[i].Constraints[detectors.ConstraintRegex]
			if !ok {
				continue
			}
			pattern, ok := raw.(string)
			if !ok || pattern == "" {
				continue
			}
			if _, err := detectors.CompileConstraintRegex(pattern); err != nil {
				g.logger.Warn("api_parameter_constraints: invalid regex constraint (runtime observe-only)",
					zap.String("endpoint_key", ek), zap.String("param", list[i].Name), zap.Error(err))
			}
		}
	}
}

// buildRuleSet 解析规则 JSON。
func buildRuleSet(rules []ruleJSON) (*accesscontrol.RuleSet, error) {
	out := make([]accesscontrol.Rule, 0, len(rules))
	for _, r := range rules {
		pfx, err := cidr.ParseAddress(r.Address)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		rule := accesscontrol.Rule{
			ID:       r.ID,
			Address:  r.Address,
			Prefix:   pfx,
			Priority: r.Priority,
		}
		if r.EffectiveFrom != "" {
			t, err := time.Parse(time.RFC3339, r.EffectiveFrom)
			if err != nil {
				return nil, fmt.Errorf("rule %q: bad effective_from", r.ID)
			}
			rule.EffectiveFrom = &t
		}
		if r.EffectiveUntil != "" {
			t, err := time.Parse(time.RFC3339, r.EffectiveUntil)
			if err != nil {
				return nil, fmt.Errorf("rule %q: bad effective_until", r.ID)
			}
			rule.EffectiveUntil = &t
		}
		out = append(out, rule)
	}
	return accesscontrol.NewRuleSet(out)
}

// maxURIPatternLen 正则/模式长度上限（配合 RE2 线性时间引擎防正则拒绝服务）。
const maxURIPatternLen = 256

// compilePolicies 编译 CC 策略（优先级升序）。
func compilePolicies(in []policyJSON) ([]*compiledPolicy, error) {
	out := make([]*compiledPolicy, 0, len(in))
	for _, p := range in {
		cp := &compiledPolicy{cfg: p}
		switch p.Dimension {
		case "CLIENT_IP", "APPLICATION", "CLIENT_IP_AND_URI", "CLIENT_IP_AND_APPLICATION":
		default:
			return nil, fmt.Errorf("policy %q: unknown dimension %q", p.ID, p.Dimension)
		}
		switch p.Algorithm {
		case string(ratelimit.TokenBucket), string(ratelimit.SlidingWindow):
		default:
			return nil, fmt.Errorf("policy %q: unknown algorithm %q", p.ID, p.Algorithm)
		}
		switch p.Action {
		case "LOG", "OBSERVE", "REJECT", "TEMP_BLOCK":
		default:
			return nil, fmt.Errorf("policy %q: unknown action %q", p.ID, p.Action)
		}
		if p.Action == "TEMP_BLOCK" && p.BlockDurationSeconds <= 0 {
			return nil, fmt.Errorf("policy %q: block_duration required for TEMP_BLOCK", p.ID)
		}
		if len(p.URIPattern) > maxURIPatternLen {
			return nil, fmt.Errorf("policy %q: uri_pattern too long", p.ID)
		}
		switch p.URIMatchType {
		case "", "ALL":
		case "EXACT", "PREFIX":
			if p.URIPattern == "" {
				return nil, fmt.Errorf("policy %q: uri_pattern required", p.ID)
			}
		case "REGEX":
			re, err := regexp.Compile(p.URIPattern)
			if err != nil {
				return nil, fmt.Errorf("policy %q: bad regex: %w", p.ID, err)
			}
			cp.uriRe = re
		default:
			return nil, fmt.Errorf("policy %q: unknown uri_match_type %q", p.ID, p.URIMatchType)
		}
		if p.EffectiveFrom != "" {
			t, err := time.Parse(time.RFC3339, p.EffectiveFrom)
			if err != nil {
				return nil, fmt.Errorf("policy %q: bad effective_from", p.ID)
			}
			cp.from = &t
		}
		if p.EffectiveUntil != "" {
			t, err := time.Parse(time.RFC3339, p.EffectiveUntil)
			if err != nil {
				return nil, fmt.Errorf("policy %q: bad effective_until", p.ID)
			}
			cp.until = &t
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].cfg.Priority < out[j].cfg.Priority })
	return out, nil
}

// ---------- 请求处理 ----------

// ServeHTTP 主流程。
func (g *Guard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// APM 阶段1（ADR D5/D6）：trace 上下文在任何拦截分支之前建立，
	// 全链路（含前置拦截）经请求上下文可取
	tc := g.resolveTraceContext(r)
	ctx := context.WithValue(r.Context(), traceContextKey{}, tc)

	// 请求最终处置上下文（WDSP P0-04；契约 S4_DESIGN_BASELINE §7：ServeHTTP 入口创建，
	// 不依赖访问日志开关；defer Finalize 幂等——panic 展开路径同样补全
	// completion_status/finalized_at，两路分支（访问日志开/关）都经过）
	ctx, dispo := WithDisposition(ctx, g.GatewayNode)
	defer dispo.Finalize()

	// 全量访问日志（APM 阶段1 D9：采集点由 serveNext 上移至入口，人工封禁/黑白名单/L7/CC/
	// 限速等前置拦截同样产生记录）：保留原始连接端口（下方 RemoteAddr 会被改写为真实IP+端口0）；
	// waf_action 标注与 TTFB 计量随请求上下文传递（defer 保证单请求只记一条）
	if g.accessLog != nil {
		ctx = context.WithValue(ctx, accessLogAnnotationKey{}, &accessLogAnnotation{})
		ctx = context.WithValue(ctx, ttfbTrackerKey{}, &ttfbTracker{})
		if _, port, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			if p, err := strconv.Atoi(port); err == nil {
				ctx = context.WithValue(ctx, accessLogConnPortKey{}, p)
			}
		}
		*r = *r.WithContext(ctx)
		return g.captureAccessLog(w, r, func(w http.ResponseWriter, r *http.Request) error {
			return g.serveGuard(w, r, next)
		})
	}
	*r = *r.WithContext(ctx)
	return g.serveGuard(w, r, next)
}

// serveGuard 防护判定主流程（ServeHTTP 摘除 trace/访问日志入口埋点后的原处理链）。
func (g *Guard) serveGuard(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) (err error) {
	now := time.Now().UTC()
	requestID := r.Header.Get("X-Request-Id")
	dispo := DispositionFrom(r.Context())

	// 兜底事实采集（WDSP P0-04）：serveGuard 返回时处置上下文仍无任何完成/终止
	// 事实的——err==nil：放行路径下游正常完成（非 API 流量不经 finishAPIResponse），
	// 补记源站完成（写出码不可得，http_status 省略）；err 携带 Coraza 中断哨兵：
	// 非 API 路径 WAF 拦截，记 WAF 终止 + PENDING_CORRELATION（规则明细由
	// eventparser 从审计日志异步补全，同步仅知 executor+status——契约 §7）。
	// RecordOrigin/RecordTerminal 均先到先得，已记录事实的分支此处为零操作。
	defer func() {
		if err == nil {
			dispo.RecordOrigin(0, true)
			return
		}
		if txID, status, ok := corazaInterruption(err); ok {
			// 中断码口径与 attributeWAFIntercept 一致：非 4xx/5xx 归一 403
			if status < 400 || status > 599 {
				status = http.StatusForbidden
			}
			dispo.RecordTerminal(ExecutorWAF, DisActionBlock, status, false, []string{"WAF_INTERCEPT"}, nil)
			if txID != "" {
				dispo.AddEvidenceRef(txID)
			}
			dispo.NotePendingCorrelation()
		}
	}()

	// 1. 真实IP识别
	res := g.resolver.Resolve(r, g.proxies)
	if !res.ClientIP.IsValid() {
		// 连接源不可解析：拒绝（无法实施任何基于IP的防护）
		accessLogAnnotate(r.Context(), wafActionBlock)
		dispo.RecordTerminal(ExecutorUnknown, DisActionBlock, http.StatusForbidden, false, []string{"UNPARSEABLE_REMOTE_ADDR"}, nil)
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("unparseable remote addr"))
	}
	// 识别结果存入请求上下文：统一 RequestContext 桥接复用（避免重复解析代理头）
	*r = *r.WithContext(context.WithValue(r.Context(), clientIPResultKey{}, res))
	dispo.SetRequest(requestID, g.AppID)
	base := g.eventBase(r, requestID, res)
	if res.HeaderInvalid {
		g.emit(base, events.ForwardedHeaderInvalid, "CONNECTION_FALLBACK", 0)
	}
	if res.ChainTooLong {
		g.emit(base, events.ForwardedChainTooLong, "CONNECTION_FALLBACK", 0)
	}
	// 全链可信回落：最左端声明可被客户端注入，不采信并回落连接源（M-26/S11）；
	// 复用伪造检测事件口径 TRUSTED_PROXY_INVALID + CONNECTION_FALLBACK
	if res.ChainAllTrusted {
		g.emit(base, events.TrustedProxyInvalid, "CONNECTION_FALLBACK", 0)
	}
	// 伪造检测：携带代理头但连接源不可信 → TRUSTED_PROXY_INVALID
	if res.TrustedProxyUsed == "" && hasProxyHeaders(r) {
		g.emit(base, events.TrustedProxyInvalid, "IGNORED", 0)
	}

	clientIP := res.ClientIP
	// 下游（WAF/日志/代理）统一使用真实IP
	r.RemoteAddr = net.JoinHostPort(clientIP.String(), "0")
	r.Header.Set("X-Real-Ip", clientIP.String())

	// 1.6 调试保留命名空间 /_wdsp/debug/v1/（debug_cc_counter 启用时；阶段5 §十七
	// CC 精确计数探针）：真实 IP 识别之后、CC 限速之前挂接——回显请求本身不进入
	// CC 计数（探针自污染防控），也不进入 JWT/身份观测步骤；全部结局本地响应，
	// 结构上不可能反向代理（见 debug_cccounter.go）
	if g.DebugCCCounter && strings.HasPrefix(r.URL.Path, debugReservedNamespace) {
		return g.serveDebugNamespace(w, r, res)
	}

	// 1.4 JWT 信任链本地验证（WDSP P0-03；jwt_trust 段下发且非 OFF 时）。
	// 仅计算——结果入请求上下文：身份观测（VERIFIED 可信信号）与 API 动态管线
	// 阶段的强制处置点（serveNext）消费。本步骤独立于身份观测引擎：观测关闭
	// 或其 panic recover 均不影响 JWT 验证与执行（不经过观测的 fail-open 分支）。
	if g.jwtVerifier != nil {
		g.verifyJWTTrust(r)
	}

	// 1.5 身份与行为观测（AI 自动化渗透防护增强 阶段1；identity_behavior 启用时。
	// Begin：解析身份→请求上下文、包装 ResponseWriter 记状态码、身份行为白名单判断
	// （命中返回原 w 与 nil，零开销）；End：请求收束时原子记账/评估/发事件，全部
	// fail-open——本阶段纯 OBSERVE，不拦截、不改变任何响应）
	var ibObs *identitybehavior.Observation
	if g.ibh != nil {
		w, ibObs = g.ibh.Begin(w, r, res)
		if ibObs != nil {
			// 传入返回错误（LOW-G6）：前置拦截（temp block/IP deny/risk BLOCK/Coraza
			// 中断）经 caddyhttp.Error 返回时响应在 wrapper 链之外写出，statusWriter
			// 采集不到状态码，End 从错误链兜底取拦截状态码
			defer func() { g.ibh.End(r, ibObs, err) }()
		}
	}

	// 2. 保护地址：仅当「客户端 IP」命中时跳过 ACL/CC（仍过 Bot 挑战、WAF 与 API 动态防护）。
	// 连接源（LB/本机反代）不得用于旁路真实客户端的访问控制。
	if g.protected.Contains(clientIP) {
		dispo.RecordStep(ExecutorProtectedAddress, StepExecuted, "client IP in protected addresses")
		recordBypassedSteps(dispo, "PROTECTED_ADDRESS",
			ExecutorManualBan, StepModuleIPAllowlist, ExecutorIPBlacklist, ExecutorL7ACL,
			ExecutorAutoBan, ExecutorRiskPolicy, ExecutorLicenseQuota, ExecutorCC)
		return g.serveNextViaBot(w, r, next, base, res)
	}

	// 3. 临时封禁查询（人工封禁优先于白名单；自动 CC 封禁可由白名单绕过）
	var autoBlock *temporaryblock.Block
	if blk, ok := g.engine.blockCache.Blocked(clientIP, g.AppID); ok {
		if !blk.Auto {
			dispo.RecordTerminal(ExecutorManualBan, DisActionTempBlock, http.StatusForbidden, false,
				[]string{"MANUAL_TEMP_BLOCK"}, []string{blk.ID})
			ev := base
			ev.Action = "TEMP_BLOCK"
			ev.PolicyID = blk.ID
			exp := blk.ExpiresAt
			ev.BlockExpiresAt = &exp
			ev.FinalDecision = dispo.JSON()
			g.emit(ev, events.CCRequestRejected, "TEMP_BLOCK", http.StatusForbidden)
			accessLogAnnotate(r.Context(), wafActionBlock)
			return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("temporarily blocked"))
		}
		b := blk
		autoBlock = &b
	}

	// 4. 黑白名单（白名单命中直接放行：跳过 L7、自动封禁、授权限速与 CC，
	// 不跳过 Bot 挑战、API 动态防护与 WAF；不绕过人工临时封禁——封禁查询已在上方执行）
	dec := accesscontrol.Evaluate(clientIP, now, g.allowG, g.allowA, g.denyG, g.denyA)
	switch dec.Action {
	case accesscontrol.ActionAllow:
		// 白名单命中放行（P0-04 事实记录）：只记录实际绕过的步骤（SKIPPED + detail）；
		// 放行非终止，不挂 final_decision（该请求仍过 Bot 挑战、API 动态防护与 WAF——安全底线）
		dispo.RecordStep(StepModuleIPAllowlist, StepExecuted, "allow hit rule="+dec.RuleID)
		recordBypassedSteps(dispo, "IP_ALLOWLIST",
			ExecutorIPBlacklist, ExecutorL7ACL, ExecutorAutoBan,
			ExecutorRiskPolicy, ExecutorLicenseQuota, ExecutorCC)
		ev := base
		ev.AccessRuleID = dec.RuleID
		g.emit(ev, events.IPAllowMatch, "ALLOW", 0)
		return g.serveNextViaBot(w, r, next, base, res)
	case accesscontrol.ActionDeny:
		dispo.RecordTerminal(ExecutorIPBlacklist, DisActionBlock, http.StatusForbidden, false,
			[]string{"IP_IN_BLACKLIST"}, []string{dec.RuleID})
		ev := base
		ev.AccessRuleID = dec.RuleID
		ev.FinalDecision = dispo.JSON()
		g.emit(ev, events.IPDenyMatch, "DENY", http.StatusForbidden)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("access denied"))
	}

	// 4.5 L7 访问控制（IP 黑白名单之后、CC 之前；按优先级首中即停）
	if g.l7 != nil {
		if l7dec, ok := g.l7.Eval(r, clientIP); ok {
			return g.executeL7(w, r, next, base, res, l7dec)
		}
	}

	// 5. 自动临时封禁（未被白名单/L7 allow 绕过）
	if autoBlock != nil {
		dispo.RecordTerminal(ExecutorAutoBan, DisActionTempBlock, http.StatusForbidden, false,
			[]string{"AUTO_TEMP_BLOCK"}, []string{autoBlock.ID})
		ev := base
		ev.Action = "TEMP_BLOCK"
		ev.PolicyID = autoBlock.ID
		exp := autoBlock.ExpiresAt
		ev.BlockExpiresAt = &exp
		ev.FinalDecision = dispo.JSON()
		g.emit(ev, events.CCRequestRejected, "TEMP_BLOCK", http.StatusForbidden)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("temporarily blocked"))
	}

	// 5.4 身份风险策略处置（risk_policy 启用时；执行点在身份解析之后、授权限速与 CC 之前，
	// 与人工/自动临时封禁同层。IP 白名单/L7 allow 已在上方提前放行——白名单优先；
	// 身份行为白名单命中在执行点内显式跳过。OBSERVE 只记录"假设会处置"事件永不实断；
	// PROTECT 达阈 403/429，事件 reason 固定 identity_risk_policy，不伪装成规则阻断；
	// 不改 dynamic_security/decision 的可信 BLOCK 源——红线）
	if g.risk != nil {
		if handled, err := g.enforceRiskPolicy(w, r, res, base); handled {
			return err
		}
	}

	// 5.5 授权配额全局限速（LicenseMaxQPS > 0 时生效；全局限速优先于 CC 策略。
	// 不产生 CC 事件避免污染 CC 统计，超限 429；0=不检查，零行为变化）
	if g.LicenseMaxQPS > 0 && g.enforceLicenseRateLimit(w, r, base.RequestID) {
		accessLogAnnotate(r.Context(), wafActionBlock)
		return nil
	}

	// 6. CC 限速
	if handled, err := g.enforceRateLimits(w, r, clientIP, base, now); handled {
		return err
	}

	// 7. 放行（经 Bot 挑战判定与 API 动态防护管线后进入 WAF 等后续处理器）
	return g.serveNextViaBot(w, r, next, base, res)
}

// l7SkipKey 请求上下文标记：L7 allow 命中后设置，CC 等后续 guard 检查据此跳过。
// 正常路径在 L7 命中点已直接 serveNext 放行，该标记为纵深防御（防后续链路调整时语义漂移）。
type l7SkipKey struct{}

// l7Skip 判断请求是否已被 L7 allow 规则放行。
func l7Skip(ctx context.Context) bool {
	return ctx.Value(l7SkipKey{}) != nil
}

// executeL7 执行 L7 规则命中动作。
// block/redirect/custom_page 直接写响应终结请求；allow 放行并设置跳过标记，
// 跳过自动封禁与 CC 等后续 guard 检查（仍经 Bot 挑战判定与 serveNext 过 API 动态防护与 WAF——安全底线）。
func (g *Guard) executeL7(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, base events.Event, res clientip.Result, dec l7rules.Decision) error {
	dispo := DispositionFrom(r.Context())
	ev := base
	ev.AccessRuleID = dec.RuleID
	switch dec.Action {
	case l7rules.ActionAllow:
		// L7 allow 放行（P0-04 事实记录）：只记录实际绕过的步骤；放行非终止，
		// 不挂 final_decision（仍经 Bot 挑战判定与 serveNext 过 API 动态防护与 WAF——安全底线）
		dispo.RecordStep(ExecutorL7ACL, StepExecuted, "allow hit rule="+dec.RuleID)
		recordBypassedSteps(dispo, "L7_ACL",
			ExecutorAutoBan, ExecutorRiskPolicy, ExecutorLicenseQuota, ExecutorCC)
		g.emit(ev, events.L7RuleAllow, "ALLOW", 0)
		*r = *r.WithContext(context.WithValue(r.Context(), l7SkipKey{}, dec.RuleID))
		return g.serveNextViaBot(w, r, next, base, res)
	case l7rules.ActionBlock:
		g.writeL7Block(w, r, base.RequestID, dec.Config.Status, dec.Config.Message)
		dispo.RecordTerminal(ExecutorL7ACL, DisActionBlock, dec.Config.Status, true,
			[]string{"L7_RULE_BLOCK"}, []string{dec.RuleID})
		ev.FinalDecision = dispo.JSON()
		g.emit(ev, events.L7RuleBlock, "BLOCK", dec.Config.Status)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return nil
	case l7rules.ActionRedirect:
		// redirect_url 在配置加载时已强制校验 scheme 仅 http/https。
		// 重定向是网关终止但非安全动作（P0-04）：security_action=NONE、executor=L7_ACL
		w.Header().Set("Location", dec.Config.RedirectURL)
		w.Header().Set("X-Jiuzhang-Request-ID", base.RequestID)
		w.WriteHeader(dec.Config.RedirectStatus)
		dispo.RecordTerminal(ExecutorL7ACL, DisActionNone, dec.Config.RedirectStatus, true,
			[]string{"L7_RULE_REDIRECT"}, []string{dec.RuleID})
		ev.FinalDecision = dispo.JSON()
		g.emit(ev, events.L7RuleRedirect, "REDIRECT", dec.Config.RedirectStatus)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return nil
	case l7rules.ActionCustomPage:
		w.Header().Set("Content-Type", dec.Config.ContentType)
		w.Header().Set("X-Jiuzhang-Request-ID", base.RequestID)
		w.WriteHeader(dec.Config.Status)
		_, _ = io.WriteString(w, dec.Config.Body)
		dispo.RecordTerminal(ExecutorL7ACL, DisActionNone, dec.Config.Status, true,
			[]string{"L7_RULE_CUSTOM_PAGE"}, []string{dec.RuleID})
		ev.FinalDecision = dispo.JSON()
		g.emit(ev, events.L7RuleCustom, "CUSTOM_PAGE", dec.Config.Status)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return nil
	default:
		// 未知动作（编译期已拦截，此处兜底不放任）：拒绝
		dispo.RecordTerminal(ExecutorL7ACL, DisActionBlock, http.StatusForbidden, false,
			[]string{"L7_ACTION_UNAVAILABLE"}, []string{dec.RuleID})
		ev.FinalDecision = dispo.JSON()
		g.emit(ev, events.L7RuleBlock, "BLOCK", http.StatusForbidden)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("l7 rule action unavailable"))
	}
}

// writeL7Block L7 阻止响应：可配状态码与文案（默认 403），JSON/HTML 按 Accept 选择；
// 文案经 HTML 转义（防存储型 XSS 反射给管理面配置的文案读者），Request ID 为服务端生成 UUID 仍转义。
func (g *Guard) writeL7Block(w http.ResponseWriter, r *http.Request, requestID string, status int, message string) {
	w.Header().Set("X-Jiuzhang-Request-ID", requestID)
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		body, _ := json.Marshal(map[string]string{
			"error":      "access_blocked",
			"message":    message,
			"request_id": requestID,
		})
		_, _ = w.Write(body)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>访问被拦截</title></head>`+
		`<body><h1>%d 访问被拦截</h1><p>%s</p><p>请求编号：%s</p></body></html>`,
		status, html.EscapeString(message), html.EscapeString(requestID))
}

// licenseRateLimitKey 授权配额全局限速固定桶键：全部请求共享同一桶，
// Valkey 后端跨节点共享、memory 后端每进程独立（与 CC 计数后端差异一致）。
const licenseRateLimitKey = "license:global"

// enforceLicenseRateLimit 授权配额全局限速；返回 true 表示已响应（429）。
// 算法沿用 CC 同款令牌桶，1s 窗口；burst 传 0 由限速器缺省取 limit，
// 与未配置 burst_capacity 的 CC 策略同口径。超限不产生 CC 事件（避免污染 CC 统计），
// 仅 slog 告警（带 limit 值，不记请求体）；引擎故障沿用本实例故障策略
// （Fail-open 放行 / Fail-closed 429），同样仅 slog 告警。
func (g *Guard) enforceLicenseRateLimit(w http.ResponseWriter, r *http.Request, requestID string) bool {
	dispo := DispositionFrom(r.Context())
	res, err := g.engine.limiter.Allow(r.Context(), licenseRateLimitKey,
		ratelimit.TokenBucket, int64(g.LicenseMaxQPS), time.Second, 0)
	if err != nil {
		slog.Warn("jiuzhang_guard license rate limit engine error",
			"limit", g.LicenseMaxQPS, "fail_open", g.failOpen, "error", err)
		if g.failOpen {
			return false
		}
		g.writeTooMany(w, r, requestID, 60)
		dispo.RecordTerminal(ExecutorLicenseQuota, DisActionRateLimit, http.StatusTooManyRequests, true,
			[]string{"LICENSE_QUOTA_ENGINE_ERROR_FAIL_CLOSED"}, nil)
		return true
	}
	if res.Allowed {
		return false
	}
	retrySec := int(res.RetryAfter.Seconds()) + 1
	slog.Warn("jiuzhang_guard license max qps exceeded",
		"limit", g.LicenseMaxQPS, "retry_after_sec", retrySec)
	g.writeTooMany(w, r, requestID, retrySec)
	// P0-04：配额超限不产生事件（避免污染 CC 统计——既有纪律），final_decision 仅内存态
	// 记录事实；本分支无事件通道落库（已确认拦截优先去重对此无影响）
	dispo.RecordTerminal(ExecutorLicenseQuota, DisActionRateLimit, http.StatusTooManyRequests, true,
		[]string{"LICENSE_MAX_QPS_EXCEEDED"}, nil)
	return true
}

// enforceRateLimits 执行 CC 策略；handled=true 表示已响应。
func (g *Guard) enforceRateLimits(w http.ResponseWriter, r *http.Request, clientIP netip.Addr, base events.Event, now time.Time) (bool, error) {
	dispo := DispositionFrom(r.Context())
	// L7 allow 命中：跳过 CC（纵深防御，正常路径已在 L7 命中点直接放行）
	if l7Skip(r.Context()) {
		return false, nil
	}
	path := r.URL.Path
	for _, p := range g.policies {
		if p.from != nil && now.Before(*p.from) {
			continue
		}
		if p.until != nil && !now.Before(*p.until) {
			continue
		}
		if !p.matchURI(path) {
			continue
		}
		key := p.cfg.ID + ":" + p.dimensionKey(clientIP, g.AppID)
		res, err := g.engine.limiter.Allow(r.Context(), key,
			ratelimit.Algorithm(p.cfg.Algorithm), p.cfg.RequestsLimit,
			time.Duration(p.cfg.WindowSeconds)*time.Second, p.cfg.BurstCapacity)
		if err != nil {
			// 故障策略：Fail-open 放行 / Fail-closed 拒绝；均告警（节流）
			g.emitEngineErrorThrottled(base, p, err)
			if g.failOpen {
				continue
			}
			g.writeTooMany(w, r, base.RequestID, 60)
			dispo.RecordTerminal(ExecutorCC, DisActionRateLimit, http.StatusTooManyRequests, true,
				[]string{"CC_ENGINE_ERROR_FAIL_CLOSED"}, []string{p.cfg.ID})
			ev := withPolicy(base, p)
			ev.FinalDecision = dispo.JSON()
			g.emit(ev, events.CCRequestRejected, "REJECT", http.StatusTooManyRequests)
			accessLogAnnotate(r.Context(), wafActionBlock)
			return true, nil
		}
		if res.Allowed {
			continue
		}
		// 超限
		ev := withPolicy(base, p)
		ev.CurrentCount = res.Current
		ev.LimitValue = p.cfg.RequestsLimit
		ev.WindowSeconds = p.cfg.WindowSeconds
		if p.cfg.ObserveOnly || p.cfg.Action == "LOG" || p.cfg.Action == "OBSERVE" {
			dispo.RecordStep(ExecutorCC, StepObserved, "policy="+p.cfg.ID)
			g.emit(ev, events.CCThresholdExceeded, "OBSERVE", 0)
			accessLogAnnotate(r.Context(), wafActionObserve)
			continue
		}
		switch p.cfg.Action {
		case "REJECT":
			retrySec := int(res.RetryAfter.Seconds()) + 1
			g.writeTooMany(w, r, base.RequestID, retrySec)
			dispo.RecordTerminal(ExecutorCC, DisActionRateLimit, http.StatusTooManyRequests, true,
				[]string{"CC_THRESHOLD_EXCEEDED"}, []string{p.cfg.ID})
			ev.FinalDecision = dispo.JSON()
			g.emit(ev, events.CCRequestRejected, "REJECT", http.StatusTooManyRequests)
			accessLogAnnotate(r.Context(), wafActionBlock)
			return true, nil
		case "TEMP_BLOCK":
			exp := now.Add(time.Duration(p.cfg.BlockDurationSeconds) * time.Second)
			// 全局策略写全局 ban key（AppID 空），应用策略写本应用
			banAppID := g.AppID
			if strings.EqualFold(p.cfg.Scope, "GLOBAL") {
				banAppID = ""
			}
			blk := temporaryblock.Block{
				ID:        p.cfg.ID,
				ClientIP:  clientIP.String(),
				AppID:     banAppID,
				ExpiresAt: exp,
				Reason:    "cc_threshold_exceeded",
				Auto:      true,
			}
			if err := g.engine.blockCache.PutLocal(r.Context(), blk); err != nil {
				g.emitEngineErrorThrottled(base, p, err)
			}
			ev.BlockExpiresAt = &exp
			g.writeTooMany(w, r, base.RequestID, p.cfg.BlockDurationSeconds)
			dispo.RecordTerminal(ExecutorCC, DisActionTempBlock, http.StatusTooManyRequests, true,
				[]string{"CC_THRESHOLD_EXCEEDED"}, []string{p.cfg.ID})
			ev.FinalDecision = dispo.JSON()
			g.emit(ev, events.CCTempBlockCreated, "TEMP_BLOCK", 0)
			g.emit(ev, events.CCRequestRejected, "TEMP_BLOCK", http.StatusTooManyRequests)
			accessLogAnnotate(r.Context(), wafActionBlock)
			return true, nil
		}
	}
	return false, nil
}

// matchURI URI 匹配。
func (p *compiledPolicy) matchURI(path string) bool {
	switch p.cfg.URIMatchType {
	case "", "ALL":
		return true
	case "EXACT":
		return path == p.cfg.URIPattern
	case "PREFIX":
		return strings.HasPrefix(path, p.cfg.URIPattern)
	case "REGEX":
		return p.uriRe.MatchString(path)
	}
	return false
}

// dimensionKey 按限速维度生成键（哈希化，禁止拼接原始输入）。
// CLIENT_IP_AND_URI 使用策略的 URI 模式而非具体路径：
// 策略本身即 URI 分组，用具体路径会导致随机 URI 绕过与键爆炸。
func (p *compiledPolicy) dimensionKey(clientIP netip.Addr, appID string) string {
	switch p.cfg.Dimension {
	case "CLIENT_IP":
		return counters.HashParts("ip", clientIP.String())
	case "APPLICATION":
		return counters.HashParts("app", appID)
	case "CLIENT_IP_AND_URI":
		pattern := p.cfg.URIPattern
		if pattern == "" {
			pattern = "*"
		}
		return counters.HashParts("ipuri", clientIP.String(), pattern)
	case "CLIENT_IP_AND_APPLICATION":
		return counters.HashParts("ipapp", clientIP.String(), appID)
	}
	return counters.HashParts("ip", clientIP.String())
}

// ---------- 响应与事件辅助 ----------

// setRiskResponseHeaders 附加身份风险处置的可追溯元数据。
// Request ID 同时作为风险事件关联 ID；不把身份键、阈值或信号明细暴露给客户端。
func (g *Guard) setRiskResponseHeaders(w http.ResponseWriter, requestID string, policyVersion int) {
	w.Header().Set("X-Jiuzhang-Risk-Reason", "identity_risk_policy")
	w.Header().Set("X-Jiuzhang-Policy-Version", strconv.Itoa(policyVersion))
	w.Header().Set("X-Jiuzhang-Risk-Event-ID", requestID)
}

// writeTooMany 429 响应（Retry-After + Request ID，不暴露内部阈值/计数/算法/节点）。
// 自定义阻断页面（block_response 段，阶段5 §5.1）：未配置时走内置默认模板，
// 与历史版本逐字节一致；配置后按段渲染（正文装配期已白名单净化，标题/Request ID
// 渲染时整串转义；JSON 错误码/文案经 JSON 编码）。Retry-After 与
// X-Jiuzhang-Request-ID 行为不随自定义改变。
func (g *Guard) writeTooMany(w http.ResponseWriter, r *http.Request, requestID string, retryAfterSec int) {
	if retryAfterSec <= 0 {
		retryAfterSec = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSec))
	w.Header().Set("X-Jiuzhang-Request-ID", requestID)
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		errCode, errMsg := "too_many_requests", "请求过于频繁，请稍后重试"
		if br := g.blockResponse; br != nil {
			if br.jsonCode != "" {
				errCode = br.jsonCode
			}
			if br.jsonMessage != "" {
				errMsg = br.jsonMessage
			}
		}
		bodyFields := map[string]string{
			"error":      errCode,
			"message":    errMsg,
			"request_id": requestID,
		}
		if reason := w.Header().Get("X-Jiuzhang-Risk-Reason"); reason != "" {
			bodyFields["reason_code"] = reason
			bodyFields["policy_version"] = w.Header().Get("X-Jiuzhang-Policy-Version")
			bodyFields["event_id"] = w.Header().Get("X-Jiuzhang-Risk-Event-ID")
		}
		body, _ := json.Marshal(bodyFields)
		_, _ = w.Write(body)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	br := g.blockResponse
	if br == nil || (br.title == "" && br.body == "") {
		// 内置默认模板（未配置自定义 HTML 页面；与历史版本逐字节一致）。
		// 静态模板，Request ID 为服务端生成 UUID，仍做 HTML 转义（纵深防御）
		fmt.Fprintf(w, `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>请求过于频繁</title></head>`+
			`<body><h1>429 请求过于频繁</h1><p>请稍后重试。</p><p>请求编号：%s</p></body></html>`, html.EscapeString(requestID))
		return
	}
	// 自定义页面：缺省字段回落内置默认；body 装配期已白名单净化（无脚本/无属性），
	// title 与 Request ID 渲染时整串转义；请求编号行恒保留（与响应头一致的可追溯锚点）
	title := br.title
	if title == "" {
		title = "请求过于频繁"
	}
	body := br.body
	if body == "" {
		body = `<h1>429 请求过于频繁</h1><p>请稍后重试。</p>`
	}
	fmt.Fprintf(w, `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>%s</title></head>`+
		`<body>%s<p>请求编号：%s</p></body></html>`, html.EscapeString(title), body, html.EscapeString(requestID))
}

// eventBase 构造事件公共字段。
func (g *Guard) eventBase(r *http.Request, requestID string, res clientip.Result) events.Event {
	return events.Event{
		RequestID:     requestID,
		OccurredAt:    time.Now().UTC(),
		ApplicationID: g.AppID,
		AppCode:       g.AppCode,
		ClientIP:      res.ClientIP.String(),
		ConnectionIP:  res.ConnectionIP.String(),
		// 阶段5 §6.5 日志字段：真实 IP 识别来源/可信代理命中/代理链摘要
		ClientIPSource:        string(res.Source),
		TrustedProxyUsed:      res.TrustedProxyUsed,
		ForwardedChainSummary: res.ChainSummary,
		Domain:                r.Host,
		Method:                r.Method,
		Path:                  r.URL.RequestURI(),
		Proto:                 r.Proto,
		GatewayNode:           g.GatewayNode,
	}
}

// withPolicy 附加策略字段。
func withPolicy(e events.Event, p *compiledPolicy) events.Event {
	e.PolicyID = p.cfg.ID
	return e
}

// emit 输出事件（失败记录到网关日志，不阻断请求）。
func (g *Guard) emit(e events.Event, t events.Type, action string, status int) {
	e.EventType = t
	if action != "" {
		e.Action = action
	}
	if status != 0 {
		e.ResponseStatus = status
	}
	if err := g.events.Emit(e); err != nil {
		g.logger.Error("guard: emit event failed", zap.String("type", string(t)), zap.Error(err))
	}
}

// engineErrThrottleLocked 引擎错误告警节流判定（每分钟每键最多一条，防日志洪泛）。
// 调用方须已持有 engine.mu（请求路径与启动路径共用同一节流表 lastErrEmit）。
func engineErrThrottleLocked(e *sharedEngine, key string) bool {
	last, ok := e.lastErrEmit[key]
	if ok && time.Since(last) <= time.Minute {
		return false
	}
	e.lastErrEmit[key] = time.Now()
	return true
}

// emitEngineErrorThrottled 引擎错误告警（每分钟每策略最多一条，防日志洪泛）。
func (g *Guard) emitEngineErrorThrottled(base events.Event, p *compiledPolicy, err error) {
	g.engine.mu.Lock()
	emit := engineErrThrottleLocked(g.engine, p.cfg.ID)
	g.engine.mu.Unlock()
	if !emit {
		return
	}
	ev := withPolicy(base, p)
	ev.Message = err.Error()
	g.emit(ev, events.RateLimitEngineError, "ENGINE_ERROR", 0)
}

// emitStartupEngineError 启动期引擎错误事件（无请求上下文，与 RATE_LIMIT_ENGINE_ERROR
// 同通道入 access_control_events）。client_ip 用未指定地址占位——采集端 client_ip
// 非空且须可解析，真实错误与来源在 message 中说明。
func (g *Guard) emitStartupEngineError(err error) {
	if g.events == nil || g.logger == nil {
		return
	}
	ev := events.Event{
		OccurredAt:    time.Now().UTC(),
		ApplicationID: g.AppID,
		AppCode:       g.AppCode,
		ClientIP:      "0.0.0.0",
		GatewayNode:   g.GatewayNode,
		Message:       "tempblock initial refresh failed: " + err.Error(),
	}
	g.emit(ev, events.RateLimitEngineError, "ENGINE_ERROR", 0)
}

// hasProxyHeaders 请求是否携带代理头（伪造检测用）。
func hasProxyHeaders(r *http.Request) bool {
	return r.Header.Get("X-Forwarded-For") != "" ||
		r.Header.Get("X-Real-IP") != "" ||
		r.Header.Get("Forwarded") != ""
}

// 接口断言
var _ caddyhttp.MiddlewareHandler = (*Guard)(nil)
var _ caddy.Provisioner = (*Guard)(nil)
var _ caddy.Validator = (*Guard)(nil)
var _ caddy.CleanerUpper = (*Guard)(nil)
