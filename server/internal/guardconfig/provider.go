// Package guardconfig 阶段5访问控制/CC 配置组装：
// 从可信代理/保护地址/黑白名单/CC策略仓储读取生效数据，
// 组装为下发网关的 GuardConfig，并管理版本快照。
package guardconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/l7rules"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/ratelimitpolicies"
	"github.com/jiuzhang-waf/server/internal/trustedproxies"
	"github.com/jiuzhang-waf/server/internal/urlwhitelists"
)

// Provider 是阶段5配置组装器（实现 gatewayconfig.GuardProvider）。
type Provider struct {
	proxies            *trustedproxies.Store
	protected          *protectedaddresses.Store
	rules              *accessrules.Store
	policies           *ratelimitpolicies.Store
	versions           *accesscontrolversions.Store
	apiModels          *apimodels.Store // 阶段8：冻结模型下发（nil 时跳过）
	apiAssets          *apiassets.Store // 阶段8：已知端点基线下发（nil 时跳过）
	apiEndpointActions APIEndpointActionLister
	apiEndpointGroups  APIEndpointGroupLister
	l7Rules            *l7rules.Store       // L7 访问控制规则（nil 时不下发 l7_rules 段——API 形态零行为变化）
	urlWhitelists      *urlwhitelists.Store // URL 白名单规则（nil 时不下发）

	valkeyAddr     string
	valkeyPassword string
	valkeyDB       int
	eventsLog      string // 网关容器内事件日志路径
	gatewayNode    string
	maxProxyChain  int
	maxCounterKeys int
	failOpen       bool

	// 阶段8 / WDSP：API 动态防护下发配置
	apiEnabled   bool
	apiMode      string
	apiEventsLog string // 网关容器内 API 事件日志路径

	// apiModeOverride settings 表模式覆盖读取（nil 时仅用构造配置 apiMode）；
	// 返回 found=false 表示无覆盖。取值顺序：settings 表覆盖 > 构造配置（env/默认）。
	apiModeOverride func(ctx context.Context) (value string, found bool, err error)

	// 全量访问日志（二期）：settings 读取（nil 时不下发 access_log 段）
	accessLogPath   string // 网关容器内日志路径（env 注入）
	accessLogLoader func(ctx context.Context) (AccessLogSettings, error)

	// gateway_runtime 组系统设置读取（P0-18：behavior_store/identity_salt 等随发布下发；
	// nil 时不下发运行时键，网关内置默认值兜底）
	runtimeSettingsLoader GatewayRuntimeSettingsLoader
	// 响应脱敏规则读取（api_masking_rules 表，迁移 000040；nil 或查询失败时 Warn 跳过）
	maskRules  MaskRuleLister
	maskCrypto MaskCryptoLoader
	// 值级敏感检测规则读取（api_sensitive_data_types 表，迁移 000040；nil 或查询失败时 Warn 跳过）
	sensitiveValueRules SensitiveValueRuleLister
	// 角色功能级基线读取（api_role_baselines 表 confirmed 行，迁移 000043；nil 或查询失败时 Warn 跳过）
	roleBaselines RoleBaselineLister
	// 字段权限读取（api_field_permissions 表，迁移 000044；nil 或查询失败时 Warn 跳过）
	fieldPermissions FieldPermissionLister
	// LLM 输入保护策略读取（api_llm_security_policies 表 enabled 行；nil = 不下发该段）
	llmSecurityPolicies LLMSecurityPolicyLister
	// 流程基线读取（api_flow_baselines 表 enabled 行，迁移 000155；nil 或查询失败时 Warn 跳过）
	flowBaselines FlowBaselineLister
	strongFlows   StrongFlowLister
	// 已吊销凭据清单读取（api_revoked_credentials 表当前生效行，迁移 000156；
	// nil 或查询失败时 Warn 跳过，与 FlowBaselineLister 同一模式）
	revokedCredentials RevokedCredentialLister
	// 扫描签名密钥读取（system_settings api_scan.signing_key 密文解密；nil/未配置时
	// 不下发 api_scan_verification；读取/解密失败中止发布——降级为仅按头存在性识别
	// 会放行伪造扫描头投毒学习样本，不静默降级）
	scanVerification ScanVerificationLoader
	// 响应结构基线读取（api_response_schemas 表达阈值学习行，迁移 000018/000051；nil 或查询失败时 Warn 跳过）
	responseBaselines ResponseBaselineLister
	// 文件合规规则读取（api_file_compliance_rules 表 enabled 行，表由另一分片迁移建立；
	// nil 或查询失败时 Warn 跳过，与 MaskRuleStore 同一模式）
	fileComplianceRules FileComplianceRuleLister
	// gRPC 描述符集读取（api_grpc_descriptors 表 ENABLED 行，迁移 000076；
	// nil 或查询失败时 Warn 跳过，与 MaskRuleStore 同一模式）
	grpcDescriptors GRPCDescriptorLister
	// gRPC 描述符 per-app 绑定读取（api_grpc_bindings 表全行，迁移 000179；
	// nil 或查询失败时 Warn 跳过（空绑定=全局可见现状语义），与 MaskRuleStore 同一模式）
	grpcBindings GRPCBindingLister
	// MCP 工具目录读取（mcp_tool_catalogs 表 ENABLED 行 + APPROVED 工具集，迁移 000181；
	// nil 或查询失败时 Warn 跳过不下发 api_mcp_tool_catalogs 段，与 GRPCBindingLister 同一模式）
	mcpCatalogs MCPToolCatalogLister
	// MCP 目录 per-app 绑定读取（mcp_catalog_bindings 表全行，迁移 000182；
	// nil 或查询失败时 Warn 跳过不下发 api_mcp_bindings 段——空绑定=网关 MCP 管控零行为变化）
	mcpBindings MCPBindingLister
	// 机器身份登记册读取（machine_identities 表 ENABLED 行+machine_identity_keys 全状态
	// 键行，迁移 000183；nil 或查询失败时 Warn 跳过不下发 api_machine_identities 段，
	// 与 MCPToolCatalogLister 同一模式）
	machineIdentities MachineIdentityLister
	// 机器身份 per-app 绑定读取（machine_identity_bindings 表全行，迁移 000184；
	// nil 或查询失败时 Warn 跳过不下发 api_machine_identity_bindings 段——空绑定=网关
	// 机器身份验证零行为变化）
	machineIDBindings MachineIdentityBindingLister
	// 机器身份元数据读取（撤销水位+登记册版本；身份或绑定任一非空才读取下发；
	// 读取失败 → 三段整体不下发（登记册不带水位单独下发制造模糊态——网关保留旧
	// 配置更安全），见 machine_identities.go loadAPIMachineIdentitySections）
	machineIDMeta MachineIdentityMetaLister
	// 文件签名密钥读取（system_settings gateway_runtime 组 api_file_signature_key 密文解密
	// + api_file_signature_kid；nil/未配置时不下发 api_file_signature，网关零行为变化；
	// 读取/解密失败中止发布——静默停用签名会让管理面显示与网关行为不一致）
	fileSignature FileSignatureLoader
	// 行为策略读取（security_behavior_policy 表 GLOBAL 行，迁移 000098；nil 或查询失败时
	// Warn 跳过不下发 identity_behavior 段，与 MaskRuleStore 同一模式）
	behaviorPolicy BehaviorPolicyLister
	identityBlocks IdentityBlockLister
	// 身份与行为事件日志网关容器内路径（随 identity_behavior 段下发）
	identityEventsLog string
	// 风险策略读取（security_risk_policy 表 GLOBAL 行，迁移 000101；nil 或查询失败时
	// Warn 跳过不下发 risk_policy 段，与 BehaviorPolicyLister 同一模式）
	riskPolicy RiskPolicyLister
	// JWT 信任策略读取（jwt_trust_policies 表按应用行，迁移 000125；仅 WDSP 开启时下发
	// jwt_trust 段；读取失败中止发布——fail-hard，防止已 PROTECT 应用被静默关闭强制校验）
	jwtTrust JWTTrustLister
	// JWT PROTECT 发布的节点门禁（nil 时仅执行管线模式门禁）
	jwtTrustNodeGuard JWTTrustNodeGuard
	// Bot 挑战策略读取（bot_policies 表按应用行，迁移 000128；仅 WDSP 开启时下发
	// bot_policy 段；读取失败中止发布——fail-hard，与 jwt_trust 同一口径）
	botPolicy BotPolicyLister
	// Bot 挑战签名密钥读取（system_settings gateway_runtime 组 bot_signing_keys 密文
	// 解密；nil/未配置时不下发 bot_signing_keys，存在 PROTECT 策略时由就绪门禁拒绝发布；
	// 读取/解密失败中止发布——fail-hard，与 scanVerification/fileSignature 同一纪律）
	botSigningKeys BotSigningKeysLoader
	// AI 爬虫治理策略与离线迷宫签名密钥（Phase 9A-2；迁移 000245；仅 WDSP 开启时下发
	// ai_crawl_policy 段，读取失败 fail-hard，迷宫密钥单独经加密设置注入并脱敏）
	aiCrawl             AICrawlLister
	aiCrawlLabyrinthKey AICrawlLabyrinthKeyLoader
	// 客户端供应链安全策略读取（Phase 9B；迁移 000246；仅 WDSP 开启时下发
	// client_side_policy 段，读取失败 fail-hard，无任何秘密材料）
	clientSide ClientSideLister
	// A2A 协议安全策略读取（Phase 9C-1；迁移 000247；仅 WDSP 开启时下发
	// api_a2a_policy 段，读取失败 fail-hard，无任何秘密材料）
	a2a A2ALister
	// 本地离线 ONNX/SLM 语义防火墙策略读取（Phase 9C-2；迁移 000248；仅 WDSP 开启时下发
	// semantic_guard_policy 段，读取失败 fail-hard，无任何秘密材料）
	semanticGuard SemanticGuardLister
	// Wasm 自定义检测插件读取（Phase 9D-1；迁移 000249；仅 WDSP 开启时下发
	// wasm_plugins 段，读取失败 fail-hard，版本戳仅纳入元数据+sha256 不含原始 base64）
	wasmPlugins WasmPluginLister
	// API 引擎受限例外读取（exception_policies 表 target_engine='API' 的 ENABLED+VALID
	// 行，列由迁移 000130 建立；仅 WDSP 开启时下发 api_exceptions 段；读取失败中止
	// 发布——fail-hard，与 jwt_trust 同一口径；nil 时不下发该段，网关零行为变化）
	apiExceptions APIExceptionLister
	// API 准入策略读取（applications.api_admission_mode<>'OFF' 行 + 各应用确认集，
	// 列由迁移 000166 建立；仅 WDSP 开启时下发 api_admission 段；读取失败中止发布——
	// fail-hard，与 jwt_trust 同一口径；nil 时不下发该段，网关准入判定零行为变化）
	apiAdmission APIAdmissionLister
	// apiGraphQL GraphQL 成本预算策略读取（NG-GQL-03；nil = 不下发该段）
	apiGraphQL APIGraphQLLister
	// AUTHZ-01：只下发已确认的对象模型、OWNER 关系与 VERIFIED 角色基线；
	// 对象引用 HMAC 密钥单独从加密设置读取，禁止进入版本快照。
	authzSnapshot      AuthzSnapshotLister
	authzObjectHMACKey AuthzObjectHMACKeyLoader
}

// AccessLogSettings 是 logging 组系统设置（全量访问日志开关快照）。
type AccessLogSettings struct {
	Enabled                bool
	CaptureRequestHeaders  bool
	CaptureRequestBody     bool
	CaptureResponseHeaders bool
	CaptureResponseBody    bool
	BodyLimitKB            int
}

// Config 是组装器配置。
type Config struct {
	ValkeyAddress  string
	ValkeyPassword string
	ValkeyDB       int
	EventsLog      string // 网关容器内路径（如 /var/log/caddy/guard-events.log）
	GatewayNode    string
	MaxProxyChain  int  // 默认 16
	MaxCounterKeys int  // 默认 100000
	FailOpen       bool // 计数引擎故障策略
	// 阶段8 / WDSP：APIDynamicProtection 为 false 时下发 JSON 与纯 WAF 完全一致
	APIDynamicProtection bool
	APIProtectionMode    string // OFF | OBSERVE | PROTECT（启用时缺省 OBSERVE）
	APIEventsLog         string // 网关容器内路径（如 /var/log/caddy/api-runtime-events.log）
	// AccessLogPath 全量访问日志网关容器内路径（如 /var/log/caddy/access-full.jsonl）
	AccessLogPath string
	// IdentityEventsLog 身份与行为事件日志网关容器内路径（如 /var/log/caddy/identity-events.log；
	// 随 identity_behavior 段下发，与 EventsLog 同目录推导——GATEWAY_IDENTITY_EVENTS_LOG）
	IdentityEventsLog string
}

// NewProvider 创建组装器。
func NewProvider(
	proxies *trustedproxies.Store,
	protected *protectedaddresses.Store,
	rules *accessrules.Store,
	policies *ratelimitpolicies.Store,
	versions *accesscontrolversions.Store,
	cfg Config,
) *Provider {
	if cfg.MaxProxyChain <= 0 {
		cfg.MaxProxyChain = 16
	}
	if cfg.MaxCounterKeys <= 0 {
		cfg.MaxCounterKeys = 100000
	}
	if cfg.EventsLog == "" {
		cfg.EventsLog = "/var/log/caddy/guard-events.log"
	}
	if cfg.AccessLogPath == "" {
		cfg.AccessLogPath = "/var/log/caddy/access-full.jsonl"
	}
	if cfg.IdentityEventsLog == "" {
		cfg.IdentityEventsLog = "/var/log/caddy/identity-events.log"
	}
	return &Provider{
		proxies: proxies, protected: protected, rules: rules, policies: policies, versions: versions,
		valkeyAddr: cfg.ValkeyAddress, valkeyPassword: cfg.ValkeyPassword, valkeyDB: cfg.ValkeyDB,
		eventsLog: cfg.EventsLog, gatewayNode: cfg.GatewayNode,
		maxProxyChain: cfg.MaxProxyChain, maxCounterKeys: cfg.MaxCounterKeys, failOpen: cfg.FailOpen,
		apiEnabled: cfg.APIDynamicProtection, apiMode: cfg.APIProtectionMode, apiEventsLog: cfg.APIEventsLog,
		accessLogPath: cfg.AccessLogPath, identityEventsLog: cfg.IdentityEventsLog,
	}
}

// SetAPIModels 注入模型版本仓储（阶段8：冻结正式模型随发布下发网关；nil 表示不下发）。
func (p *Provider) SetAPIModels(m *apimodels.Store) { p.apiModels = m }

// SetAPIModeOverride 注入 settings 表模式覆盖读取（app 装配时接线 settings.Service；
// 覆盖读取失败时发布失败，不静默回退）。
func (p *Provider) SetAPIModeOverride(fn func(ctx context.Context) (value string, found bool, err error)) {
	p.apiModeOverride = fn
}

// 防护模式下发白名单（与网关 jiuzhang_guard / 管理面策略接口约定一致）。
var validAPIProtectionModes = map[string]bool{"OFF": true, "OBSERVE": true, "PROTECT": true}

// resolveAPIProtectionMode 计算下发模式：settings 表覆盖（合法值）优先于构造配置；
// 覆盖值非法时回退构造配置（fail-safe，网关行为不被脏数据改变）。
func resolveAPIProtectionMode(configured, override string, found bool) string {
	if found {
		if v := strings.ToUpper(strings.TrimSpace(override)); validAPIProtectionModes[v] {
			return v
		}
	}
	return configured
}

// SetAPIAssets 注入端点资产仓储（阶段8：已知端点基线随发布下发网关；nil 表示不下发）。
func (p *Provider) SetAPIAssets(s *apiassets.Store) { p.apiAssets = s }

// SetL7Rules 注入 L7 访问控制规则仓储（仅 WAF/WDSP 装配；nil 表示不下发 l7_rules 段）。
func (p *Provider) SetL7Rules(s *l7rules.Store) { p.l7Rules = s }

// SetURLWhitelists 注入 URL 白名单仓储（nil 表示不下发）。
func (p *Provider) SetURLWhitelists(s *urlwhitelists.Store) { p.urlWhitelists = s }

// SetAccessLogLoader 注入 logging 组系统设置读取（全量访问日志开关，发布时随 GuardConfig 下发；
// 读取失败时发布失败，不静默回退——避免开关状态与管理面显示不一致）。
func (p *Provider) SetAccessLogLoader(fn func(ctx context.Context) (AccessLogSettings, error)) {
	p.accessLogLoader = fn
}

// BuildGuardConfig 从数据库读取生效配置并组装。
func (p *Provider) BuildGuardConfig(ctx context.Context) (*gatewayconfig.GuardConfig, error) {
	cfg := &gatewayconfig.GuardConfig{
		TrustedProxies:     []gatewayconfig.GuardProxy{},
		MaxProxyChain:      p.maxProxyChain,
		ProtectedAddresses: []string{},
		GlobalAllow:        []gatewayconfig.GuardRule{},
		GlobalDeny:         []gatewayconfig.GuardRule{},
		GlobalPolicies:     []gatewayconfig.GuardPolicy{},
		AppRules:           map[string]*gatewayconfig.GuardAppRules{},
		CounterBackend:     "valkey",
		MaxCounterKeys:     p.maxCounterKeys,
		FailOpen:           p.failOpen,
		EventsLog:          p.eventsLog,
		GatewayNode:        p.gatewayNode,
	}
	if p.valkeyAddr != "" {
		cfg.Valkey = &gatewayconfig.GuardValkey{
			Address:  p.valkeyAddr,
			Password: p.valkeyPassword,
			DB:       p.valkeyDB,
		}
	} else {
		cfg.CounterBackend = "memory"
	}

	// 可信代理（启用；NODE 级仅本节点）
	proxies, err := p.proxies.ListEnabled(ctx)
	if err != nil {
		return nil, fmt.Errorf("list trusted proxies: %w", err)
	}
	for _, tp := range proxies {
		if tp.Scope == "NODE" && tp.NodeName != p.gatewayNode {
			continue
		}
		cfg.TrustedProxies = append(cfg.TrustedProxies, gatewayconfig.GuardProxy{
			Name:             tp.Name,
			CIDR:             tp.CIDR,
			HeaderType:       tp.HeaderType,
			CustomHeaderName: tp.CustomHeaderName,
			Priority:         tp.Priority,
		})
	}
	sort.Slice(cfg.TrustedProxies, func(i, j int) bool { return cfg.TrustedProxies[i].Priority < cfg.TrustedProxies[j].Priority })

	// 保护地址（启用）
	protected, err := p.protected.List(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("list protected addresses: %w", err)
	}
	for _, pa := range protected {
		addr := pa.Address
		if addr == "" {
			addr = pa.CIDR
		}
		if addr != "" {
			cfg.ProtectedAddresses = append(cfg.ProtectedAddresses, addr)
		}
	}
	sort.Strings(cfg.ProtectedAddresses)

	// 黑白名单（ACTIVE，专用无分页全量查询，避免分页 20 条截断静默丢失规则）
	rules, err := p.rules.ListAllActive(ctx)
	if err != nil {
		return nil, fmt.Errorf("list access rules: %w", err)
	}
	appIDs := map[uuid.UUID]bool{}
	for _, r := range rules {
		if r.ApplicationID != nil {
			appIDs[*r.ApplicationID] = true
		}
	}
	idList := make([]uuid.UUID, 0, len(appIDs))
	for id := range appIDs {
		idList = append(idList, id)
	}
	appCodes, err := p.rules.ApplicationCodes(ctx, idList)
	if err != nil {
		return nil, fmt.Errorf("resolve application codes: %w", err)
	}
	appRules := map[string]*gatewayconfig.GuardAppRules{}
	for _, r := range rules {
		gr := gatewayconfig.GuardRule{
			ID:             r.ID.String(),
			Address:        r.Address,
			Priority:       r.Priority,
			EffectiveFrom:  formatTime(r.EffectiveFrom),
			EffectiveUntil: formatTime(r.EffectiveUntil),
		}
		switch {
		case r.ScopeType == "GLOBAL" && r.RuleType == "ALLOW":
			cfg.GlobalAllow = append(cfg.GlobalAllow, gr)
		case r.ScopeType == "GLOBAL":
			cfg.GlobalDeny = append(cfg.GlobalDeny, gr)
		default: // APPLICATION
			if r.ApplicationID == nil {
				continue
			}
			code := appCodes[*r.ApplicationID]
			if code == "" {
				continue
			}
			ar := appRules[code]
			if ar == nil {
				ar = &gatewayconfig.GuardAppRules{
					Allow: []gatewayconfig.GuardRule{}, Deny: []gatewayconfig.GuardRule{}, Policies: []gatewayconfig.GuardPolicy{},
				}
				appRules[code] = ar
			}
			if r.RuleType == "ALLOW" {
				ar.Allow = append(ar.Allow, gr)
			} else {
				ar.Deny = append(ar.Deny, gr)
			}
		}
	}

	// CC 策略（ACTIVE，专用无分页全量查询，避免分页 20 条截断静默丢失策略）
	policies, err := p.policies.ListAllActive(ctx)
	if err != nil {
		return nil, fmt.Errorf("list rate limit policies: %w", err)
	}
	polAppIDs := map[uuid.UUID]bool{}
	for _, pl := range policies {
		if pl.ApplicationID != nil {
			polAppIDs[*pl.ApplicationID] = true
		}
	}
	polIDList := make([]uuid.UUID, 0, len(polAppIDs))
	for id := range polAppIDs {
		polIDList = append(polIDList, id)
	}
	polAppCodes, err := p.rules.ApplicationCodes(ctx, polIDList)
	if err != nil {
		return nil, fmt.Errorf("resolve policy application codes: %w", err)
	}
	for _, pl := range policies {
		gp := gatewayconfig.GuardPolicy{
			ID:                   pl.ID.String(),
			Name:                 pl.Name,
			Dimension:            pl.Dimension,
			Algorithm:            pl.Algorithm,
			URIMatchType:         pl.URIMatchType,
			URIPattern:           pl.URIPattern,
			RequestsLimit:        int64(pl.RequestsLimit),
			WindowSeconds:        pl.WindowSeconds,
			BurstCapacity:        int64(pl.BurstCapacity),
			Action:               pl.Action,
			BlockDurationSeconds: pl.BlockDurationSeconds,
			ObserveOnly:          pl.ObserveOnly,
			Priority:             pl.Priority,
			EffectiveFrom:        formatTime(pl.EffectiveFrom),
			EffectiveUntil:       formatTime(pl.EffectiveUntil),
		}
		if pl.ScopeType == "GLOBAL" {
			cfg.GlobalPolicies = append(cfg.GlobalPolicies, gp)
			continue
		}
		if pl.ApplicationID == nil {
			continue
		}
		code := polAppCodes[*pl.ApplicationID]
		if code == "" {
			continue
		}
		ar := appRules[code]
		if ar == nil {
			ar = &gatewayconfig.GuardAppRules{
				Allow: []gatewayconfig.GuardRule{}, Deny: []gatewayconfig.GuardRule{}, Policies: []gatewayconfig.GuardPolicy{},
			}
			appRules[code] = ar
		}
		ar.Policies = append(ar.Policies, gp)
	}
	// URL 白名单规则（ACTIVE，注入仓储后读取失败中止发布 fail-hard）
	if p.urlWhitelists != nil {
		urlRules, _, err := p.urlWhitelists.List(ctx, urlwhitelists.ListFilter{Status: urlwhitelists.StatusActive, Page: 1, PageSize: 10000})
		if err != nil {
			return nil, fmt.Errorf("list url whitelist rules: %w", err)
		}
		urlAppIDs := map[uuid.UUID]bool{}
		for _, ur := range urlRules {
			if ur.ApplicationID != nil {
				urlAppIDs[*ur.ApplicationID] = true
			}
		}
		urlIDList := make([]uuid.UUID, 0, len(urlAppIDs))
		for id := range urlAppIDs {
			urlIDList = append(urlIDList, id)
		}
		urlAppCodes, err := p.urlWhitelists.ApplicationCodes(ctx, urlIDList)
		if err != nil {
			return nil, fmt.Errorf("resolve url whitelist application codes: %w", err)
		}
		for _, ur := range urlRules {
			gr := gatewayconfig.GuardURLAllowRule{
				ID:             ur.ID.String(),
				MatchType:      ur.MatchType,
				URIPattern:     ur.URIPattern,
				Methods:        ur.Methods,
				Priority:       ur.Priority,
				EffectiveFrom:  formatTime(ur.EffectiveFrom),
				EffectiveUntil: formatTime(ur.EffectiveUntil),
			}
			if ur.ScopeType == urlwhitelists.ScopeGlobal {
				cfg.GlobalURLAllow = append(cfg.GlobalURLAllow, gr)
				continue
			}
			code := urlAppCodes[*ur.ApplicationID]
			if code == "" {
				continue
			}
			ar := appRules[code]
			if ar == nil {
				ar = &gatewayconfig.GuardAppRules{
					Allow: []gatewayconfig.GuardRule{}, Deny: []gatewayconfig.GuardRule{}, Policies: []gatewayconfig.GuardPolicy{},
				}
				appRules[code] = ar
			}
			ar.URLAllow = append(ar.URLAllow, gr)
		}
	}
	cfg.AppRules = appRules

	// L7 访问控制（契约一 l7_rules 段）：注入仓储后恒下发（含全部规则与 enabled 标志；
	// 空数组用于清空网关旧规则）。读取失败中止发布，禁止静默降级为空集。
	if p.l7Rules != nil {
		l7List, err := p.l7Rules.ListAllOrdered(ctx)
		if err != nil {
			return nil, fmt.Errorf("list l7 access rules: %w", err)
		}
		cfg.L7Rules = toGuardL7Rules(l7List)
	}

	// 阶段8 / WDSP：API 动态防护开关与冻结模型（仅开启时注入；关闭时 GuardConfig 与纯 WAF 一致）
	if p.apiEnabled {
		cfg.APIDynamicProtection = true
		mode := p.apiMode
		if p.apiModeOverride != nil {
			override, found, err := p.apiModeOverride(ctx)
			if err != nil {
				return nil, fmt.Errorf("read api protection mode override: %w", err)
			}
			mode = resolveAPIProtectionMode(p.apiMode, override, found)
		}
		cfg.APIProtectionMode = mode
		cfg.APIEventsLog = p.apiEventsLog
		if p.apiModels != nil {
			schemas, err := p.apiModels.ListFormalSchemas(ctx)
			if err != nil {
				return nil, fmt.Errorf("list formal api schemas: %w", err)
			}
			if len(schemas) > 0 {
				cfg.APIFormalSchemas = schemas
			}
			// FORMAL 模型版本号随发布下发（网关事件回报 model_version，供版本溯源）
			versions, err := p.apiModels.ListFormalModelVersions(ctx)
			if err != nil {
				return nil, fmt.Errorf("list formal api model versions: %w", err)
			}
			if len(versions) > 0 {
				cfg.APIFormalModelVersions = versions
			}
			// P0-2：FORMAL 端点请求侧确认参数约束随发布下发
			constraints, err := p.apiModels.ListFormalParameterConstraints(ctx)
			if err != nil {
				return nil, fmt.Errorf("list formal api parameter constraints: %w", err)
			}
			if len(constraints) > 0 {
				out := make(map[string][]gatewayconfig.GuardParamConstraint, len(constraints))
				for ek, list := range constraints {
					items := make([]gatewayconfig.GuardParamConstraint, 0, len(list))
					for _, pc := range list {
						items = append(items, gatewayconfig.GuardParamConstraint{
							Location:    pc.Location,
							Name:        pc.Name,
							Path:        pc.Path,
							BaseType:    pc.BaseType,
							Required:    pc.Required,
							Constraints: pc.Constraints,
						})
					}
					out[ek] = items
				}
				cfg.APIParameterConstraints = out
			}
			// W11-REL / P0-02：FORMAL 端点已确认参数条件关系随发布下发
			// （confirmed=true 才下发；候选不生效——任务书 §45「只有 Confirmed 关系进入强制检测」）
			relations, err := p.apiModels.ListConfirmedParameterRelations(ctx)
			if err != nil {
				return nil, fmt.Errorf("list confirmed api parameter relations: %w", err)
			}
			if len(relations) > 0 {
				out := make([]gatewayconfig.GuardParamRelation, 0, len(relations))
				for _, r := range relations {
					out = append(out, gatewayconfig.GuardParamRelation{
						EndpointKey:  r.EndpointKey,
						RelationType: r.RelationType,
						ParamA: gatewayconfig.GuardParamRef{
							Location: r.ParamA.Location, Path: r.ParamA.Path, Name: r.ParamA.Name,
						},
						ParamB: gatewayconfig.GuardParamRef{
							Location: r.ParamB.Location, Path: r.ParamB.Path, Name: r.ParamB.Name,
						},
					})
				}
				cfg.APIParameterRelations = out
			}
		}
		if p.apiAssets != nil {
			known, err := p.apiAssets.ListKeyStatus(ctx)
			if err != nil {
				return nil, fmt.Errorf("list api endpoint key status: %w", err)
			}
			if len(known) > 0 {
				cfg.APIKnownEndpoints = known
			}
		}
		// P0-18：gateway_runtime 组运行时设置随发布下发（behavior_store/identity_salt 等；
		// 缺省不下发=网关默认；读取失败或取值非法中止发布，不静默回退）
		if err := p.applyGatewayRuntime(ctx, cfg); err != nil {
			return nil, err
		}
		if err := p.loadAPIEndpointActions(ctx, cfg); err != nil {
			return nil, err
		}
		if err := p.loadAPIEndpointGroups(ctx, cfg); err != nil {
			return nil, err
		}
		// WDSP 规则读取对旧格式仅容忍明确缺失的 legacy 表；真实查询错误必须中止
		// 候选发布，避免把读取失败误当成空策略发布到网关。
		var loaderErr error
		cfg.APILLMSecurityPolicies, loaderErr = p.loadLLMSecurityPolicies(ctx)
		if loaderErr != nil {
			return nil, loaderErr
		}
		cfg.APIMaskRules, loaderErr = p.loadAPIMaskRulesStrict(ctx)
		if loaderErr != nil {
			return nil, loaderErr
		}
		cfg.APIMaskCrypto, loaderErr = p.loadAPIMaskCrypto(ctx, cfg.APIMaskRules)
		if loaderErr != nil {
			return nil, loaderErr
		}
		cfg.APISensitiveValueRules, loaderErr = p.loadAPISensitiveValueRulesStrict(ctx)
		if loaderErr != nil {
			return nil, loaderErr
		}
		cfg.APIRoleBaselines, loaderErr = p.loadAPIRoleBaselinesStrict(ctx)
		if loaderErr != nil {
			return nil, loaderErr
		}
		cfg.APIFieldPermissions, loaderErr = p.loadAPIFieldPermissionsStrict(ctx)
		if loaderErr != nil {
			return nil, loaderErr
		}
		// 阶段8 §44 发布下发面：流程基线随发布下发（表由迁移 000155 建立；
		// 缺表容忍 Warn 跳过，真实查询错误中止候选发布——纪律同授权基线）
		cfg.APIFlowBaselines, loaderErr = p.loadAPIFlowBaselinesStrict(ctx)
		if loaderErr != nil {
			return nil, loaderErr
		}
		// NG-FLOW-01：强流程定义（ACTIVE 行+步骤）随发布下发 api_strong_flows 段
		// （表由迁移 000176 建立；缺表容忍 Warn 跳过，真实查询错误中止候选发布 fail-hard）
		cfg.APIStrongFlows, loaderErr = p.loadAPIStrongFlowsStrict(ctx)
		if loaderErr != nil {
			return nil, loaderErr
		}
		// 阶段8 §35 凭据异常「已吊销凭据使用」数据源：当前生效吊销指纹清单随发布下发
		// （表由迁移 000156 建立；缺表容忍 Warn 跳过，真实查询错误中止候选发布——
		// 纪律同流程基线；指纹级载荷，无凭据明文）
		cfg.APIRevokedCredentials, loaderErr = p.loadAPIRevokedCredentialsStrict(ctx)
		if loaderErr != nil {
			return nil, loaderErr
		}
		// AUTHZ-01：授权事实编译采用 fail-hard。存在可发布对象模型时，关系、
		// VERIFIED 角色基线及专用 HMAC 密钥必须形成同一份有期限快照。
		authzModels, authzRelations, authzRoles, authzKeyHex, err := p.loadAPIAuthzSnapshot(ctx)
		if err != nil {
			return nil, err
		}
		cfg.APIAuthzModels = authzModels
		cfg.APIAuthzRelations = authzRelations
		cfg.APIAuthzRoleBaselines = authzRoles
		cfg.APIAuthzObjectHMACKeyHex = authzKeyHex
		// NG-AZ-02 v2 快照元数据（仅存在可发布授权模型时编译：schema 闸门/管理面向量水位/
		// 决策侧排除集/编译时刻/per-app 租约；lister 未实现 v2 接口（测试/旧装配形态）时
		// 按 v1 零行为跳过；读取失败中止发布 fail-hard 与关系编译同口径）
		if len(authzModels) > 0 {
			if l, ok := p.authzSnapshot.(AuthzSnapshotV2Lister); ok {
				wm, err := l.LoadManagementRevocationWatermark(ctx)
				if err != nil {
					return nil, err
				}
				conflicts, err := l.ListOpenAuthzConflicts(ctx)
				if err != nil {
					return nil, err
				}
				lease, err := l.ListAuthzLeaseSeconds(ctx)
				if err != nil {
					return nil, err
				}
				producedAt := time.Now().UTC()
				cfg.APIAuthzSchema = gatewayconfig.AuthzSnapshotSchemaV2
				cfg.APIAuthzRevocationWatermark = wm
				cfg.APIAuthzConflictedObjects = conflicts
				cfg.APIAuthzProducedAt = &producedAt
				cfg.APIAuthzLeaseSeconds = lease
			}
		}
		if len(authzModels) > 0 && authzModels[0].SnapshotExpiresAt != nil {
			expiresAt := authzModels[0].SnapshotExpiresAt.UTC()
			cfg.APIAuthzSnapshotExpiresAt = &expiresAt
		}
		// AUTHZ-01：只从最近一次 SUCCESS 版本保留上一授权快照。
		// 快照有效期沿用原版本，由网关在请求时决定是否仍可回退。
		previousValid, err := p.loadLatestSuccessfulAuthzSnapshot(ctx)
		if err != nil {
			return nil, err
		}
		// NG-FLOW-02：含 ACTIVE 强流程定义同样需要对象 HMAC 密钥（实例键构造复用——
		// 无授权模型且无上一快照时，强流程-only 形态也触发加载，缺失 fail-hard）
		authzKeyHex, err = p.ensureAuthzSnapshotKey(ctx, authzKeyHex, len(authzModels) > 0 || len(cfg.APIStrongFlows) > 0, previousValid)
		if err != nil {
			return nil, err
		}
		cfg.APIAuthzObjectHMACKeyHex = authzKeyHex
		cfg.APIAuthzPreviousValid = previousValid
		// W9-GW：扫描签名密钥随发布下发（system_settings 密文解密；未配置不下发，
		// 读取/解密失败中止发布——降级为仅按头存在性识别会放行伪造扫描头投毒学习样本；
		// 快照脱敏，回滚时按当前设置重新注入）
		scanVerification, err := p.loadAPIScanVerification(ctx)
		if err != nil {
			return nil, err
		}
		cfg.APIScanVerification = scanVerification
		// W9-GW：响应结构基线随发布下发（表由迁移 000018/000051 建立；缺表容忍，真实查询错误中止发布 fail-hard）
		cfg.APIResponseBaselines, loaderErr = p.loadAPIResponseBaselinesStrict(ctx)
		if loaderErr != nil {
			return nil, loaderErr
		}
		// W13-GW / P2-03：旧格式缺表可兼容，真实查询错误中止候选发布。
		cfg.APIFileComplianceRules, loaderErr = p.loadAPIFileComplianceRulesStrict(ctx)
		if loaderErr != nil {
			return nil, loaderErr
		}
		// W13-GW / P2-02：文件签名密钥随发布下发（system_settings 密文解密；未配置不下发，
		// 读取/解密失败中止发布——静默停用签名会让管理面显示与网关行为不一致；
		// 快照脱敏，回滚时按当前设置重新注入；秘密材料不参与版本戳）
		fileSignature, err := p.loadAPIFileSignature(ctx)
		if err != nil {
			return nil, err
		}
		cfg.APIFileSignature = fileSignature
		// W14-DESC / P2-05 深化：gRPC 描述符集随发布下发（表由迁移 000076 建立；缺表容忍，真实查询错误 fail-hard）
		cfg.APIGRPCDescriptors, loaderErr = p.loadAPIGRPCDescriptorsStrict(ctx)
		if loaderErr != nil {
			return nil, loaderErr
		}
		// NG-GRPC G1 批次 B1：per-app 绑定随发布下发（表由迁移 000179 建立；缺表容忍，真实查询错误 fail-hard）
		cfg.APIGRPCBindings, loaderErr = p.loadAPIGRPCBindingsStrict(ctx)
		if loaderErr != nil {
			return nil, loaderErr
		}
		// NG-MCP G1 批次 B1：MCP 工具目录与 per-app 绑定随发布下发；缺表容忍，真实查询错误 fail-hard
		cfg.APIMCPToolCatalogs, loaderErr = p.loadAPIMCPToolCatalogsStrict(ctx)
		if loaderErr != nil {
			return nil, loaderErr
		}
		cfg.APIMCPBindings, loaderErr = p.loadAPIMCPBindingsStrict(ctx)
		if loaderErr != nil {
			return nil, loaderErr
		}
		// NG-ID g1 批次 B1：机器身份登记册、per-app 绑定及撤销水位元数据随发布下发；
		// 缺表容忍，真实查询错误中止候选发布 fail-hard
		cfg.APIMachineIdentities, cfg.APIMachineIdentityBindings, cfg.APIMachineIdentityMeta, loaderErr =
			p.loadAPIMachineIdentitySectionsStrict(ctx)
		if loaderErr != nil {
			return nil, loaderErr
		}
		// S7 批次 C 裁决 3（跨轨指纹域对齐，S6 偏差 1 先例）：principal_binding 发布前
		// 换算到网关比对域（HMAC(identity_salt, "jwt-principal:"+录入值)——网关运行期
		// 按同域指纹与 JWT VerifiedPrincipalID 比对；B1 原文透传会致合法请求
		// MID-PRINCIPAL-MISMATCH 误拒）。须在 applyGatewayRuntime 之后（同快照盐）。
		applyMachineIDPrincipalBindingFP(cfg)
		// P0-03：JWT 信任策略随发布下发 jwt_trust 段（表由迁移 000125 建立；
		// 读取失败或 PROTECT 门禁不满足时中止发布——拒绝发布并保留旧有效版本，
		// 不静默关闭原 PROTECT；含策略版本与 issuer 配置 ID/keyset 版本标识，无秘密材料）
		if err := p.loadJWTTrust(ctx, cfg, mode); err != nil {
			return nil, err
		}
		// P1-02 B1：Bot 挑战策略随发布下发 bot_policy 段（表由迁移 000128 建立；
		// 读取失败或 PROTECT 依赖门禁（共享 Valkey 未配置）不满足时中止发布——
		// 拒绝发布并保留旧有效版本，不静默关闭原 PROTECT；无任何秘密材料）
		if err := p.loadBotPolicy(ctx, cfg); err != nil {
			return nil, err
		}
		// Phase 9A-2：AI 爬虫治理策略随发布下发 ai_crawl_policy 段（迁移 000245；
		// 读取失败或 PROTECT+Labyrinth 缺签名密钥中止发布 fail-hard）
		if err := p.loadAICrawlPolicy(ctx, cfg); err != nil {
			return nil, err
		}
		// Phase 9B：客户端供应链安全策略随发布下发 client_side_policy 段（迁移 000246；
		// 读取失败中止发布 fail-hard；无任何秘密材料）
		if err := p.loadClientSidePolicy(ctx, cfg); err != nil {
			return nil, err
		}
		// Phase 9C-1：A2A 协议安全策略随发布下发 api_a2a_policy 段（迁移 000247；
		// 读取失败中止发布 fail-hard；无任何秘密材料）
		if err := p.loadA2APolicy(ctx, cfg); err != nil {
			return nil, err
		}
		// Phase 9C-2：本地离线 ONNX/SLM 语义防火墙策略随发布下发 semantic_guard_policy 段（迁移 000248；
		// 读取失败中止发布 fail-hard；无任何秘密材料）
		if err := p.loadSemanticGuardPolicy(ctx, cfg); err != nil {
			return nil, err
		}
		// Phase 9D-1：Wasm 自定义检测插件随发布下发 wasm_plugins 段（迁移 000249；
		// 读取失败中止发布 fail-hard；元数据+sha256 纳入 api_policy_version）
		if err := p.loadWasmPlugins(ctx, cfg); err != nil {
			return nil, err
		}
		// P0-04 A：API 引擎受限例外随发布下发 api_exceptions 段（列由迁移 000130
		// 建立；读取失败中止发布 fail-hard——不静默丢失已启用例外；无启用行/未注入
		// lister 时不下发该段，网关零行为变化；key=应用编码，仅 OBSERVE_RULE）
		if err := p.loadAPIExceptions(ctx, cfg); err != nil {
			return nil, err
		}
		// WDSP P1：API 准入策略随发布下发 api_admission 段（列由迁移 000166 建立；
		// key=application_id；读取失败中止发布 fail-hard——不静默丢失已 PROTECT 应用的
		// 准入拦截；无启用行/未注入 lister 时不下发该段，网关准入判定零行为变化）
		if err := p.loadAPIAdmission(ctx, cfg); err != nil {
			return nil, err
		}
		// NG-GQL-03：GraphQL 成本预算策略随发布下发 api_graphql 段（表由迁移 000171
		// 建立；key=application_id；读取失败中止发布 fail-hard 同上口径；无启用行/
		// 未注入 lister 时不下发该段，网关 GraphQL 判定零行为变化）
		if err := p.loadAPIGraphQL(ctx, cfg); err != nil {
			return nil, err
		}
		// NG-MCP G1 批次 B1（§1.5/§1.14）：PROTECT MCP 绑定端点未被同应用 jwt_trust
		// 覆盖 → 非阻断 Warn 警示（配置缺口；运行时按 COV_NO_TRUSTED_SUBJECT 放行+披露，
		// UNKNOWN 恒不阻断——strict 组合属业务端点逐项批准，不硬失败）
		warnMCPJWTTrustCoverage(cfg)
		cfg.APIIdentityBlocks, loaderErr = p.loadAPIIdentityBlocks(ctx)
		if loaderErr != nil {
			return nil, loaderErr
		}
		// P0-03/21：API 策略版本戳（本次发布内容哈希，恒下发供生效校验与网关回报比对；
		// 覆盖面对齐 guard.go 实际下发面，密钥三段与 identity_salt 不参与）
		cfg.APIPolicyVersion = computeAPIPolicyVersion(cfg)
	}
	// 全量访问日志（二期）：logging 组设置随发布下发网关
	if p.accessLogLoader != nil {
		s, err := p.accessLogLoader(ctx)
		if err != nil {
			return nil, fmt.Errorf("read access log settings: %w", err)
		}
		limitKB := s.BodyLimitKB
		if limitKB <= 0 {
			limitKB = 64
		}
		cfg.AccessLog = &gatewayconfig.GuardAccessLog{
			Enabled:                s.Enabled,
			CaptureRequestHeaders:  s.CaptureRequestHeaders,
			CaptureRequestBody:     s.CaptureRequestBody,
			CaptureResponseHeaders: s.CaptureResponseHeaders,
			CaptureResponseBody:    s.CaptureResponseBody,
			BodyLimitKB:            limitKB,
			LogPath:                p.accessLogPath,
		}
	}
	// 侦察/枚举行为检测策略（WDSP AI 自动化渗透防护增强 阶段1）：缺表容忍，真实数据库错误中止发布 fail-hard
	if err := p.loadIdentityBehaviorStrict(ctx, cfg); err != nil {
		return nil, err
	}
	// 身份风险处置策略（WDSP AI 自动化渗透防护增强 阶段3）：缺表容忍，真实数据库错误中止发布 fail-hard
	if err := p.loadRiskPolicyStrict(ctx, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
func RedactGuardConfig(cfg *gatewayconfig.GuardConfig) *gatewayconfig.GuardConfig {
	if cfg == nil {
		return nil
	}
	cp := *cfg
	if cfg.Valkey != nil {
		v := *cfg.Valkey
		if v.Password != "" {
			v.Password = "***"
		}
		cp.Valkey = &v
	}
	// identity_salt 为敏感盐值，快照脱敏（与 valkey.password 同一纪律）；
	// 回滚发布时由 GetVersionConfig 按当前 gateway_runtime 设置重新注入
	if cfg.IdentitySalt != "" {
		cp.IdentitySalt = "***"
	}
	// tls_session_ticket_key / tls_session_ticket_keys 为 TLS 会话票据密钥明文，快照脱敏（同一纪律）；
	// 回滚发布时按当前 gateway_runtime 设置重新注入
	if cfg.TLSSessionTicketKey != "" {
		cp.TLSSessionTicketKey = "***"
	}
	if len(cfg.TLSSessionTicketKeys) > 0 {
		redactedKeys := make([]string, len(cfg.TLSSessionTicketKeys))
		for i, k := range cfg.TLSSessionTicketKeys {
			if k != "" {
				redactedKeys[i] = "***"
			}
		}
		cp.TLSSessionTicketKeys = redactedKeys
	}
	if cfg.APIAuthzObjectHMACKeyHex != "" {
		cp.APIAuthzObjectHMACKeyHex = "***"
	}
	// api_authz_previous_valid.object_hmac_key_hex 同样是秘密材料；上一快照
	// 只保存事实与版本信息，渲染时由 gatewayconfig 按当前密钥重新注入。
	if cfg.APIAuthzPreviousValid != nil {
		previous := *cfg.APIAuthzPreviousValid
		if previous.ObjectHMACKeyHex != "" {
			previous.ObjectHMACKeyHex = "***"
		}
		cp.APIAuthzPreviousValid = &previous
	}
	// api_scan_verification.key_hex 为扫描签名密钥明文，快照脱敏（同一纪律）；
	// 回滚发布时由 GetVersionConfig 按当前设置重新解密注入
	if cfg.APIScanVerification != nil {
		v := *cfg.APIScanVerification
		if v.KeyHex != "" {
			v.KeyHex = "***"
		}
		cp.APIScanVerification = &v
	}
	if cfg.APIMaskCrypto != nil {
		v := *cfg.APIMaskCrypto
		if v.KeyHex != "" {
			v.KeyHex = "***"
		}
		cp.APIMaskCrypto = &v
	}
	// api_file_signature.key_hex 为文件签名密钥明文，快照脱敏（同一纪律）；
	// kid 非秘密（随 token 明文嵌入文件），保留以便快照审计；
	// 回滚发布时由 GetVersionConfig 按当前设置重新解密注入
	if cfg.APIFileSignature != nil {
		v := *cfg.APIFileSignature
		if v.KeyHex != "" {
			v.KeyHex = "***"
		}
		cp.APIFileSignature = &v
	}
	// bot_signing_keys 为 Bot 挑战签名密钥明文（key_ref → hex），快照脱敏（同一纪律）；
	// key_ref 引用名非秘密（随 clearance token key_id 明文嵌入），保留以便快照审计；
	// 回滚发布时由 GetVersionConfig 按当前设置重新解密注入
	if cfg.BotSigningKeys != nil {
		v := make(map[string]string, len(cfg.BotSigningKeys))
		for ref, key := range cfg.BotSigningKeys {
			if key != "" {
				v[ref] = "***"
			} else {
				v[ref] = key
			}
		}
		cp.BotSigningKeys = v
	}
	// ai_crawl_labyrinth_key_hex 及 ai_crawl_policy[*].labyrinth_key_hex 为 AI 迷宫签名密钥，
	// 快照脱敏为 "***"（回滚时由 replayRuntimeSecrets / reinjectConfigSecrets 重新解密注入）
	if cfg.AICrawlLabyrinthKeyHex != "" {
		cp.AICrawlLabyrinthKeyHex = "***"
	}
	if cfg.AICrawlPolicy != nil {
		cp.AICrawlPolicy = make(map[string]*gatewayconfig.GuardAICrawlPolicy, len(cfg.AICrawlPolicy))
		for code, pol := range cfg.AICrawlPolicy {
			if pol == nil {
				cp.AICrawlPolicy[code] = nil
				continue
			}
			polCopy := *pol
			if polCopy.LabyrinthKeyHex != "" {
				polCopy.LabyrinthKeyHex = "***"
			}
			cp.AICrawlPolicy[code] = &polCopy
		}
	}
	// 深拷贝 AppRules map，避免调用方修改影响快照
	if cfg.AppRules != nil {
		cp.AppRules = make(map[string]*gatewayconfig.GuardAppRules, len(cfg.AppRules))
		for k, ar := range cfg.AppRules {
			if ar == nil {
				cp.AppRules[k] = nil
				continue
			}
			arCopy := *ar
			cp.AppRules[k] = &arCopy
		}
	}
	return &cp
}

// InjectRuntimeSecrets 将当前运行时 Valkey 凭据注入历史配置（回滚用，不信任快照中的密码）。
func (p *Provider) InjectRuntimeSecrets(cfg *gatewayconfig.GuardConfig) {
	if cfg == nil {
		return
	}
	if p.valkeyAddr == "" {
		cfg.Valkey = nil
		if cfg.CounterBackend == "valkey" {
			cfg.CounterBackend = "memory"
		}
		return
	}
	if cfg.Valkey == nil {
		cfg.Valkey = &gatewayconfig.GuardValkey{}
	}
	cfg.Valkey.Address = p.valkeyAddr
	cfg.Valkey.Password = p.valkeyPassword
	cfg.Valkey.DB = p.valkeyDB
	if cfg.CounterBackend == "" {
		cfg.CounterBackend = "valkey"
	}
}

// LoadCurrentSecrets 仅读取当前运行时密钥与 Valkey 连接配置（专供历史配置回滚时的
// reinjectConfigSecrets 使用），不扫描业务策略表、不执行 PROTECT 发布门禁，避免当前策略或
// 非密钥配置异常阻塞应急回滚。
func (p *Provider) LoadCurrentSecrets(ctx context.Context) (*gatewayconfig.GuardConfig, error) {
	cfg := &gatewayconfig.GuardConfig{}
	p.InjectRuntimeSecrets(cfg)
	if p.runtimeSettingsLoader != nil {
		kv, err := p.runtimeSettingsLoader(ctx)
		if err != nil {
			return nil, fmt.Errorf("read gateway runtime settings: %w", err)
		}
		if rawSalt := strings.TrimSpace(kv["identity_salt"]); rawSalt != "" && rawSalt != redactPlaceholder {
			cfg.IdentitySalt = rawSalt
		}
		if rawTicket := strings.TrimSpace(kv["tls_session_ticket_key"]); rawTicket != "" && rawTicket != redactPlaceholder {
			keys, err := parseTLSSessionTicketKeys(rawTicket)
			if err != nil {
				return nil, err
			}
			if len(keys) > 0 {
				cfg.TLSSessionTicketKeys = keys
				cfg.TLSSessionTicketKey = keys[0]
			}
		}
	}
	if p.scanVerification != nil {
		sv, err := p.loadAPIScanVerification(ctx)
		if err != nil {
			return nil, err
		}
		cfg.APIScanVerification = sv
	}
	if p.fileSignature != nil {
		fs, err := p.loadAPIFileSignature(ctx)
		if err != nil {
			return nil, err
		}
		cfg.APIFileSignature = fs
	}
	if p.maskCrypto != nil {
		kid, keyHex, err := p.maskCrypto(ctx)
		if err != nil {
			return nil, fmt.Errorf("load api mask crypto: %w", err)
		}
		if kid != "" && keyHex != "" {
			key, err := hex.DecodeString(keyHex)
			if err != nil || len(key) != maskCryptoKeyBytes {
				return nil, fmt.Errorf("api mask crypto loader 返回非 32 字节 hex 密钥")
			}
			cfg.APIMaskCrypto = &gatewayconfig.GuardMaskCrypto{KID: kid, KeyHex: hex.EncodeToString(key)}
		}
	}
	if p.authzObjectHMACKey != nil {
		keyHex, err := p.authzObjectHMACKey(ctx)
		if err != nil {
			return nil, fmt.Errorf("load authz object hmac key: %w", err)
		}
		if keyHex != "" && keyHex != redactPlaceholder {
			cfg.APIAuthzObjectHMACKeyHex = keyHex
		}
	}
	if p.botSigningKeys != nil {
		botKeys, err := p.loadBotSigningKeys(ctx)
		if err != nil {
			return nil, err
		}
		cfg.BotSigningKeys = botKeys
	}
	if p.aiCrawlLabyrinthKey != nil {
		keyHex, err := p.aiCrawlLabyrinthKey(ctx, false)
		if err != nil {
			return nil, fmt.Errorf("load ai crawl labyrinth key: %w", err)
		}
		if keyHex != "" && keyHex != redactPlaceholder {
			cfg.AICrawlLabyrinthKeyHex = keyHex
		}
	}
	return cfg, nil
}

// SaveVersionSnapshot 保存访问控制配置版本快照（PENDING，发布结果由 MarkVersionResult 回填）。
// 快照中的 Valkey 密码已脱敏，回滚时由 InjectRuntimeSecrets 重新注入。
func (p *Provider) SaveVersionSnapshot(ctx context.Context, cfg *gatewayconfig.GuardConfig, taskID, createdBy uuid.UUID) (uuid.UUID, error) {
	data, err := json.Marshal(RedactGuardConfig(cfg))
	if err != nil {
		return uuid.Nil, err
	}
	sum := sha256.Sum256(data)
	latest, err := p.versions.GetLatestSuccessful(ctx)
	prevID, err := latestSuccessfulVersionID(latest, err)
	if err != nil {
		return uuid.Nil, err
	}
	summary := fmt.Sprintf("可信代理%d 保护地址%d 全局白%d 全局黑%d 应用规则组%d 全局CC%d",
		len(cfg.TrustedProxies), len(cfg.ProtectedAddresses), len(cfg.GlobalAllow), len(cfg.GlobalDeny),
		len(cfg.AppRules), len(cfg.GlobalPolicies))
	if cfg.L7Rules != nil {
		summary += fmt.Sprintf(" L7规则%d", len(cfg.L7Rules.Rules))
	}
	v, err := p.versions.Create(ctx, accesscontrolversions.CreateInput{
		Config:            data,
		ConfigHash:        hex.EncodeToString(sum[:]),
		ChangeSummary:     summary,
		PreviousVersionID: prevID,
		PublishTaskID:     &taskID,
		CreatedBy:         &createdBy,
	})
	if err != nil {
		return uuid.Nil, err
	}
	return v.ID, nil
}

// MarkVersionResult 回填版本发布结果；
// P0-03/21 联动：整站发布结果同时回写端点级运行时策略状态机
// （SUCCESS → 待发布集合落 ACTIVE、旧 ACTIVE 退 ROLLED_BACK；其余 → FAILED+原因）。
func (p *Provider) MarkVersionResult(ctx context.Context, id uuid.UUID, result string) error {
	if err := p.versions.SetResult(ctx, id, result); err != nil {
		return err
	}
	if p.apiModels != nil {
		if err := p.apiModels.MarkRuntimePoliciesPublishResult(ctx, result == "SUCCESS",
			"整站发布失败: "+result); err != nil {
			return fmt.Errorf("mark runtime policies publish result: %w", err)
		}
	}
	return nil
}

// GetVersionConfig 读取历史版本的 Guard 配置快照（回滚用），并注入当前运行时密钥。
func (p *Provider) GetVersionConfig(ctx context.Context, versionID uuid.UUID) (*gatewayconfig.GuardConfig, error) {
	v, err := p.versions.GetByID(ctx, versionID)
	if err != nil {
		return nil, err
	}
	cfg, err := decodeGuardConfigSnapshot(v.Config)
	if err != nil {
		return nil, fmt.Errorf("decode version config: %w", err)
	}
	p.InjectRuntimeSecrets(&cfg)
	if err := p.replayRuntimeSecrets(ctx, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// replayRuntimeSecrets 回滚重放（GetVersionConfig 快照反序列化后调用）：
// 快照中的 gateway_runtime 运行时键与密钥段已脱敏为占位/已过期，先清零快照旧值，
// 再按当前设置、ACTION/业务分组映射及身份封禁状态重放；读取/解密失败如实返回（回滚也是发布，
// 与 BuildGuardConfig 同一 fail-hard 纪律——不下发脱敏占位、不静默降级为无密钥或旧映射配置）。
// 清零清单必须覆盖 RedactGuardConfig 脱敏段与 applyGatewayRuntimeSettings 全部写入键：
// 漏清零时快照中的 "***" 占位会被原样发布（如 tls_session_ticket_key 非 hex 致
// Caddy /load 拒绝、回滚失败）。当前设置值为 Redact 占位符的键由
// applyGatewayRuntimeSettings 视同取不到跳过（不写入）。
func (p *Provider) replayRuntimeSecrets(ctx context.Context, cfg *gatewayconfig.GuardConfig) error {
	if p.runtimeSettingsLoader != nil {
		cfg.BehaviorStore = ""
		cfg.BehaviorStoreTTLSeconds = 0
		cfg.IdentitySalt = ""
		cfg.TLSSessionTicketKey = ""
		cfg.TLSSessionTicketKeys = nil
		cfg.CredentialIPSpreadLimit = 0
		cfg.CredentialConcurrencyLimit = 0
		cfg.CredentialRatePerMinute = 0
		cfg.TenantRatePerMinute = 0
		cfg.ActionRatePerMinute = 0
		cfg.APIEndpointActions = nil
		cfg.GroupRatePerMinute = 0
		cfg.APIEndpointGroups = nil
		cfg.APIWriteRatePerMinute = 0
		cfg.APIRateLimitAction = ""
		cfg.APITempBlockSeconds = 0
		cfg.APIQuotaPerHour = 0
		cfg.APIQuotaPerDay = 0
		cfg.ObjectRatePerMinute = 0
		cfg.APIMaxPageSize = 0
		cfg.APIMaxBatchSize = 0
		cfg.APIResponseFailPolicy = ""
		cfg.APIResponseCaptureMaxBytes = 0
		cfg.APIResponseSampleRatio = nil
		cfg.APILLMAllowedModels = nil
		cfg.APIFileWatermark = nil
		cfg.APIGRPCMaxFrameBytes = 0
		cfg.APIGRPCAllowCompression = false
		cfg.DebugCCCounter = false
		cfg.APINodeHeartbeatSeconds = 0
		cfg.APIAuthzClockSkewMaxSeconds = 0
		if err := p.applyGatewayRuntime(ctx, cfg); err != nil {
			return err
		}
		if err := p.loadAPIEndpointActions(ctx, cfg); err != nil {
			return err
		}
		if err := p.loadAPIEndpointGroups(ctx, cfg); err != nil {
			return err
		}
	}
	// api_scan_verification.key_hex 快照已脱敏为占位：按当前设置重新解密注入
	// （与 identity_salt 同一纪律；读取/解密失败如实返回，回滚发布失败）
	if p.scanVerification != nil {
		scanVerification, err := p.loadAPIScanVerification(ctx)
		if err != nil {
			return err
		}
		cfg.APIScanVerification = scanVerification
	}
	// api_file_signature.key_hex 快照已脱敏为占位：按当前设置重新解密注入（同一纪律）
	if p.fileSignature != nil {
		fileSignature, err := p.loadAPIFileSignature(ctx)
		if err != nil {
			return err
		}
		cfg.APIFileSignature = fileSignature
	}
	maskCrypto, err := p.loadAPIMaskCrypto(ctx, cfg.APIMaskRules)
	if err != nil {
		return err
	}
	cfg.APIMaskCrypto = maskCrypto
	identityBlocks, err := p.loadAPIIdentityBlocks(ctx)
	if err != nil {
		return err
	}
	cfg.APIIdentityBlocks = identityBlocks
	// bot_signing_keys 快照已脱敏为占位：清零后按当前设置重新解密注入（同一纪律；
	// 未配置 → nil 不下发，含 PROTECT 策略的快照由下方门禁以可读原因拒绝回滚发布）
	if p.botSigningKeys != nil {
		cfg.BotSigningKeys = nil
		botKeys, err := p.loadBotSigningKeys(ctx)
		if err != nil {
			return err
		}
		cfg.BotSigningKeys = botKeys
	}
	// Phase 9A-2：ai_crawl_labyrinth_key_hex 快照已脱敏为占位，清零后按当前加密设置重放
	if p.aiCrawlLabyrinthKey != nil {
		cfg.AICrawlLabyrinthKeyHex = ""
		anyLabyrinth := false
		for _, pol := range cfg.AICrawlPolicy {
			if pol == nil {
				continue
			}
			if pol.LabyrinthKeyHex == redactPlaceholder {
				pol.LabyrinthKeyHex = ""
			}
			if pol.LabyrinthEnabled {
				anyLabyrinth = true
			}
		}
		keyHex, err := p.aiCrawlLabyrinthKey(ctx, anyLabyrinth)
		if err != nil {
			return fmt.Errorf("load ai crawl labyrinth key: %w", err)
		}
		if keyHex != "" {
			cfg.AICrawlLabyrinthKeyHex = keyHex
		}
	}
	// AUTHZ-01 / NG-FLOW-02 对象引用 HMAC 密钥快照已脱敏，授权模型或强流程任一存在时均按当前加密设置重新注入。
	needsAuthzKey := len(cfg.APIAuthzModels) > 0 || len(cfg.APIStrongFlows) > 0
	keyHex, err := p.ensureAuthzSnapshotKey(ctx, "", needsAuthzKey, cfg.APIAuthzPreviousValid)
	if err != nil {
		return err
	}
	if needsAuthzKey || keyHex != "" {
		cfg.APIAuthzObjectHMACKeyHex = keyHex
	}
	// P0-03 回滚门禁：快照含 PROTECT JWT 信任策略而当前身份指纹密钥未配置时，
	// 回滚发布必然被网关 fail-closed 拒载——提前以可读原因失败（与 loadJWTTrust 同一口径），
	// 不静默降级为无密钥配置
	if len(cfg.JWTTrust) > 0 {
		protectApps := []string{}
		for code, pol := range cfg.JWTTrust {
			if pol != nil && pol.Mode == "PROTECT" {
				protectApps = append(protectApps, code)
			}
		}
		if len(protectApps) > 0 {
			sort.Strings(protectApps)
			if err := checkJWTTrustSecret(cfg, protectApps); err != nil {
				return err
			}
		}
	}
	// P1-02 B1 回滚门禁：快照含 PROTECT Bot 策略而共享状态存储（Valkey）未配置时，
	// 回滚后网关只能 fail-closed 503——提前以可读原因失败（与 loadBotPolicy 同一口径）；
	// B3 预备：同门禁覆盖 key_ref 签名密钥就绪（上方已按当前设置重放 bot_signing_keys，
	// 快照中的脱敏占位不参与判定）
	if len(cfg.BotPolicy) > 0 {
		protectApps := []string{}
		for code, pol := range cfg.BotPolicy {
			if pol != nil && pol.Mode == "PROTECT" {
				protectApps = append(protectApps, code)
			}
		}
		if len(protectApps) > 0 {
			sort.Strings(protectApps)
			if err := checkBotPolicyDeps(cfg, protectApps, cfg.BotPolicy); err != nil {
				return err
			}
		}
	}
	// Phase 9A-2 回滚门禁：快照含 PROTECT + Labyrinth AI 爬虫策略而迷宫密钥未就绪时失败
	if len(cfg.AICrawlPolicy) > 0 {
		protectLabyrinthApps := []string{}
		for code, pol := range cfg.AICrawlPolicy {
			if pol != nil && pol.Mode == "PROTECT" && pol.LabyrinthEnabled {
				protectLabyrinthApps = append(protectLabyrinthApps, code)
			}
		}
		if len(protectLabyrinthApps) > 0 {
			sort.Strings(protectLabyrinthApps)
			if err := checkAICrawlLabyrinthKey(cfg, protectLabyrinthApps); err != nil {
				return err
			}
		}
	}
	return nil
}

// ensureAuthzSnapshotKey supplies the current runtime key whenever either the
// current snapshot or its PreviousValid fallback contains object models.
// Historical snapshots intentionally omit secrets, including the case where
// the current snapshot is BFLA-only and therefore has no key of its own.
func (p *Provider) ensureAuthzSnapshotKey(ctx context.Context, currentKey string, currentNeedsKey bool, previous *gatewayconfig.GuardAuthzSnapshot) (string, error) {
	if currentKey != "" && currentKey != redactPlaceholder {
		return currentKey, nil
	}
	if !currentNeedsKey && (previous == nil || len(previous.Models) == 0) {
		return "", nil
	}
	if p.authzObjectHMACKey == nil {
		return "", fmt.Errorf("authz snapshot requires dedicated object HMAC key loader")
	}
	keyHex, err := p.authzObjectHMACKey(ctx)
	if err != nil {
		return "", err
	}
	if keyHex == "" {
		return "", fmt.Errorf("authz snapshot requires api_authz.object_hmac_key")
	}
	return keyHex, nil
}

// formatTime RFC3339 格式化（nil → 空串）。
func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
