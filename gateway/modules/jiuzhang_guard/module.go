// Package jiuzhang_guard 实现九章自主 Caddy 防护模块（阶段5：访问控制与CC防护；阶段8：API 动态防护挂点）。
//
// 请求处理顺序（与 ServeHTTP 实现一致）：真实IP识别 → JWT 信任链本地验证（可选，仅计算入上下文）
// → 身份解析与行为观测（可选）→ 保护地址
// → 人工临时封禁 → 全局 IP 白 → 应用 IP 白 → 全局 URL 白 → 应用 URL 白 → 全局 IP 黑 → 应用 IP 黑 → L7 请求阶段（首中即停）→ 自动临时封禁
// → 身份风险策略处置（risk_policy，可选，OBSERVE 默认不实断；CHALLENGE 仅登记请求内待挑战事实）
// → 授权全局限速（可选，默认关闭）→ CC限速 → 发布冒烟精确端点
// （/_wdsp/internal/v1/publish-smoke，独立 HMAC，本地应答且不进源站）→ Bot 挑战判定
// （bot_policy，可选，默认 OFF；消费风险待挑战事实；OBSERVE 只记录不实断，PROTECT 挑战/verify，
// 保护地址/白名单/L7 allow 不跳过 Bot；发布探针之后才处理 Bot 保留命名空间 /_wdsp/bot/v1/，
// verify 固定协议端点与墓碑均不反向代理）
// → API 动态防护管线（可选，默认关闭；JWT 强制处置在管线阶段统一放行出口 serveNext 执行，
// 白名单/L7 allow 不绕过 JWT PROTECT）→ 下一处理器（WAF）。
// 含响应头/响应体条件的 L7 规则由 l7content.go 在下游响应回程受控缓冲后评估；
// 完整正文超过 1 MiB、流式或无法解码时不产生正文匹配，原响应完整透传并记录降级告警。
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
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/flowguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/grpcdesc"
	"github.com/jiuzhang-waf/gateway/dynamic_security/httpsig"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/dynamic_security/pipeline"
	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/accesscontrol"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/cidr"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
	// tls.stek.jiuzhang：静态 TLS 会话票据密钥提供模块（主备共享票据，HA §7.2）；
	// 空白导入触发 caddy.RegisterModule 注册（xcaddy 构建随 jiuzhang_guard 一并注入）
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/l7rules"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/ratelimit"
	_ "github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/stek"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/temporaryblock"
	// caddy.listeners.jiuzhang_tls_mux 与 http.reverse_proxy.transport.jiuzhang_tls：
	// 同端口国密 TLCP/国际 TLS 自识别、ClientHello 加密会话分析与国密/降级回源传输模块
	_ "github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/tlsmux"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/trustedproxy"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/urlwhitelist"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&Guard{})
}

// CaddyModule 返回模块信息。
func (Guard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jiuzhang_guard",
		New: func() caddy.Module { return new(Guard) },
	}
}

// ---------- Provision / Validate ----------

// Provision 解析配置并初始化运行时。
func (g *Guard) Provision(ctx caddy.Context) error {
	g.logger = ctx.Logger()
	if g.EventsLog == "" {
		return fmt.Errorf("events_log is required")
	}
	// 单次发布探针使用独立密钥；非法认证段拒绝装配，绝不退化为固定头认证。
	if err := g.assemblePublishSmoke(); err != nil {
		return err
	}
	// 进程级环境变量 GATEWAY_NODE_NAME 优先于 JSON 配置中的 gateway_node（与
	// netcollector.go、software_bypass.go 口径一致），使跨节点扇出同一份配置时各节点自动保有唯一身份。
	if envNode := strings.TrimSpace(os.Getenv("GATEWAY_NODE_NAME")); envNode != "" {
		g.GatewayNode = envNode
	} else {
		g.GatewayNode = strings.TrimSpace(g.GatewayNode)
	}
	if g.GatewayNode == "" {
		g.GatewayNode = "gateway-unknown"
	}
	g.resolver = clientip.NewResolver(g.MaxProxyChain)
	g.failOpen = g.FailOpen == nil || *g.FailOpen
	g.allowedHTTPVersionSet = compileAllowedHTTPVersions(g.AllowedHTTPVersions)
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
		previousCfg := detectors.CloneAuthorizationConfig(detectors.AuthorizationConfig{
			ApplicationID: g.AppID,
			Models:        previous.Models, Relations: previous.Relations,
			RelationIndex: detectors.BuildAuthorizationRelationIndex(previous.Relations),
			RoleBaselines: previous.RoleBaselines, ObjectRefHMACKey: key,
			PolicyVersion: previous.PolicyVersion, Stale: previous.Stale,
			SnapshotExpiresAt: previous.SnapshotExpiresAt,
			// NG-AZ-02 v2 元数据（D4-2 PreviousValid 回退二次水位校验/D7 冲突集输入；
			// 租约与漂移上限取当前配置值（D5 per-app 配置优先于历史快照随行值），
			// 应用时刻与当前快照同源（同一配置加载），produced_at 保留历史快照原值）
			Schema:              previous.Schema,
			RevocationWatermark: authzWatermarkToDetectors(previous.RevocationWatermark),
			LeaseSeconds:        g.APIAuthzLeaseSeconds,
			AppliedAt:           g.authzSnapshotAppliedAt(),
			ConflictedObjects:   authzConflictsToDetectors(previous.ConflictedObjects),
			ConflictedIndex:     detectors.BuildConflictedObjectIndex(authzConflictsToDetectors(previous.ConflictedObjects)),
			ProducedAt:          previous.ProducedAt,
			ClockSkewMaxSeconds: g.APIAuthzClockSkewMaxSeconds,
		})
		g.apiAuthzPreviousValid = &previousCfg
	}
	g.apiAuthzRelationIndex = detectors.BuildAuthorizationRelationIndex(g.APIAuthzRelations)

	// NG-AZ-02 D5/D8 配置键夹紧（≤0 由夹紧函数归一：租约未启用=0、漂移缺省 60）
	g.APIAuthzLeaseSeconds = clampAuthzLeaseSeconds(g.APIAuthzLeaseSeconds)
	g.APIAuthzClockSkewMaxSeconds = clampAuthzClockSkewMax(g.APIAuthzClockSkewMaxSeconds)

	// NG-AZ-02 D4-1 水位回退拒绝：新快照携带 v2 水位且低于本应用已应用水位（分量比较）
	// 即拒绝整个配置加载——Caddy 拒绝 /load，节点保留旧配置与旧水位（fail-closed）。
	// v1 快照（无水位字段）按 D4-3 兼容不校验；无授权内容（纯 baselines/无模型）清除注册项。
	if err := g.checkAuthzWatermarkRegression(); err != nil {
		return err
	}
	// NG-ID G1 D6：机器身份撤销水位单调不下降——快照水位低于本应用已应用水位
	// 即拒绝该快照（fail-closed 保留旧配置；普通策略回滚不复活已撤销密钥，§1.6）
	if err := g.checkMachineIDWatermarkRegression(); err != nil {
		return err
	}

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

	g.apiIdentityBlocks, err = compileAPIIdentityBlocks(g.APIIdentityBlocks)
	if err != nil {
		return err
	}

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
	if g.urlAllowG, err = buildURLWhitelistSet(g.GlobalURLAllow); err != nil {
		return fmt.Errorf("global url allow: %w", err)
	}
	if g.urlAllowA, err = buildURLWhitelistSet(g.AppURLAllow); err != nil {
		return fmt.Errorf("app url allow: %w", err)
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
	if g.CredentialRatePerMinute < 0 {
		return fmt.Errorf("credential_rate_per_minute must be >= 0")
	}
	if g.TenantRatePerMinute < 0 {
		return fmt.Errorf("tenant_rate_per_minute must be >= 0")
	}
	if g.ActionRatePerMinute < 0 {
		return fmt.Errorf("action_rate_per_minute must be >= 0")
	}
	if g.GroupRatePerMinute < 0 {
		return fmt.Errorf("group_rate_per_minute must be >= 0")
	}
	if err := validateAPIEndpointActions(g.APIEndpointActions); err != nil {
		return err
	}
	if err := validateAPIEndpointGroups(g.APIEndpointGroups); err != nil {
		return err
	}
	if err := validateAPIRateLimitDisposition(g.APIRateLimitAction, g.APITempBlockSeconds); err != nil {
		return err
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
		crypto, err := compileAPIMaskCrypto(g.APIMaskCrypto, rules)
		if err != nil {
			return err
		}
		g.apiMaskRules = rules
		g.apiMaskCrypto = crypto
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
		// 强流程定义装配（NG-FLOW-01：§1.1 校验逐条 + 版本不可变断言，配置错误
		// 拒绝加载 fail-closed，不静默吞错；nil/空段 BuildRegistry 返回 nil = 零行为；
		// 本批仅装配供 FLOW-02 消费，运行时无任何判定逻辑）
		sf, err := flowguard.BuildRegistry(g.APIStrongFlows)
		if err != nil {
			return err
		}
		g.apiStrongFlows = sf
		g.apiStrongFlowIndex = flowguard.IndexByEndpoint(g.apiStrongFlows)
		// 已吊销凭据清单校验（§35 第10项；配置错误拒绝加载，不静默吞错；
		// 运行期管线编译比对集合后按请求凭据键 O(1) 查找，过期条目自行失效不判定）
		if err := detectors.ValidateRevokedCredentials(g.APIRevokedCredentials); err != nil {
			return err
		}
		// LLM 授权模型名单归一（W10-LLM：去空白/去重/去空项；名单语义宽容，
		// 单项非法不致配置拒绝——逐项 trim 后空项丢弃，与既有名单归一纪律一致）
		g.APILLMAllowedModels = normalizeLLMAllowedModels(g.APILLMAllowedModels)
		if err := detectors.ValidateLLMSecurityPolicies(g.APILLMSecurityPolicies); err != nil {
			return err
		}
		g.apiLLMSecurity = detectors.GroupLLMSecurityPolicies(g.APILLMSecurityPolicies)
		// 文件下载水印 v1 编译（W12-GW：nil 段/enabled=false = 未启用，响应侧零行为变化；
		// 启用但配置非法拒绝加载并说明，不静默吞错）
		if g.APIFileWatermark != nil {
			wm, err := response.NewFileWatermarkConfig(g.APIFileWatermark.Enabled,
				g.APIFileWatermark.TextTemplate, g.APIFileWatermark.ContentTypes, g.APIFileWatermark.JSONKey)
			if err != nil {
				return err
			}
			wm.IncludeInlineHTML = g.APIFileWatermark.IncludeInlineHTML
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
		// grpcguard G1 深检装配置（NG-GRPC 批次 B2：绑定归一+per-app 注册表+
		// content_hash 读数；无描述符且无绑定 = nil 零行为 NG-T-C01）
		g.apiGRPCGuard = g.buildGRPCGuardConfig()
		// mcpguard G1 装配置（NG-MCP 批次 B2：目录 hash 重算比对+绑定归一；
		// 无目录且无绑定 = nil 零行为 NG-T-C01）
		g.apiMCPGuard = g.buildMCPGuardConfig()
		// API 准入策略装配（WDSP P1：fail-safe 归一——mode 词表外/缺失按 OFF 不启用并
		// Warn 留痕，不拒载（不拦截优于误拦截）；nil 段 = 准入检测零行为）
		g.apiAdmission = g.compileAPIAdmissionPolicies()
		// GraphQL 成本预算策略装配（NG-GQL-03：nil 段 = GraphQL 流量零行为变化；
		// 空 application_id 键跳过并 Warn——与准入同 fail-safe 形态）
		g.apiGraphQL = g.compileAPIGraphQLPolicies()
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
			zap.Int("admission_policies", len(g.apiAdmission)),
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
			zap.Bool("grpc_allow_compression", g.grpcCompressionAllowLegacy()),
			zap.Int("grpc_descriptor_sets", grpcRegistrySets(g.apiGRPCRegistry)),
			zap.Int("grpc_descriptor_methods", grpcRegistryMethods(g.apiGRPCRegistry)))
		// 强流程装配留痕仅在有定义时（NG-T-C01：无定义零行为——无新日志、无新状态）
		if g.apiStrongFlows != nil {
			g.logger.Info("api strong flow definitions assembled",
				zap.Int("definitions", g.apiStrongFlows.Len()))
		}
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
	// 强流程运行时装配（NG-FLOW-02：nil 定义 = 零行为；Valkey/密钥缺席不拒载——
	// D8 运行期恒 UNKNOWN 放行+披露，严禁本地内存回退）
	g.strongFlowRuntime = g.buildStrongFlowRuntime(eng)
	// 机器身份重放存储装配（NG-ID G1 §1.5：共享引擎 Valkey 连接（可为 nil——
	// 缺席语义由 Evaluate 运行期 UNAVAILABLE 承载，严禁本机去重）；装配期不拒载）
	if eng != nil && eng.valkey != nil {
		g.machineIDReplay = httpsig.NewReplayStore(eng.valkey)
	} else {
		g.machineIDReplay = httpsig.NewReplayStore(nil)
	}
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
	// 机器身份装配（NG-ID G1 批次 B2；三段全缺 = nil 零行为变化。fail-safe 归一 +
	// 含 PROTECT 绑定时任何装配缺陷拒绝整体配置加载（fail-closed，jwt_trust 同纪律））
	midCfg, err := g.buildMachineIDConfig()
	if err != nil {
		return err
	}
	g.apiMachineID = midCfg
	if midCfg != nil && midCfg.Registry != nil {
		registerMachineIDAppliedWatermark(g.AppID, midCfg.Registry.RevocationWatermark)
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
	// 风险 CHALLENGE 仅在 Bot PROTECT 就绪时可执行；OBSERVE 或非法/倒置而关闭的新档不引入依赖。
	if err := g.validateRiskChallengeDependency(g.botPolicy); err != nil {
		return err
	}
	// AI 爬虫治理与离线迷宫策略装配（Phase 9A-2；严格解码 DisallowUnknownFields，
	// 非法配置 fail-closed 拒绝加载；段缺失/OFF = 零行为变化；热路径零网络 IO）
	if err := g.assembleAICrawl(); err != nil {
		return err
	}
	// 客户端供应链安全策略装配（Phase 9B / PCI DSS 4.0 6.4.3 & 11.6.1；严格解码
	// DisallowUnknownFields，非法配置 fail-closed 拒绝加载；段缺失/OFF = 零开销直通）
	if err := g.assembleClientSide(); err != nil {
		return err
	}
	// 远程 JWKS 后台刷新（热路径零网络 IO；装配最后一步启动，Provision 失败不泄漏 goroutine）
	if g.jwtVerifier != nil {
		rctx, cancel := context.WithCancel(context.Background())
		g.jwtCancel = cancel
		g.jwtVerifier.StartBackgroundRefresh(rctx)
	}
	// AI 爬虫目录可选远程后台刷新（仅在配置了 directory_url 时启动；随 Cleanup 取消退出）
	if g.aiCrawl != nil && g.aiCrawl.HasRemoteDirectories() {
		actx, cancel := context.WithCancel(context.Background())
		g.aiCrawlCancel = cancel
		g.aiCrawl.StartBackgroundRefresh(actx)
	}
	// 节点能力清单自报（NG-COV-04；默认开启，CAPABILITY_REPORT_DISABLED=1 可关——
	// 关闭后发布门禁按「清单缺失」fail-closed；进程级单例，本次 Provision 刷新
	// grpc 层级/max_grpc_frame_bytes 等可变输入）
	g.provisionCapabilityReport()
	// NG-AZ-02 D4-1/D6：登记本应用已应用授权快照状态（水位记忆与心跳合并源；
	// 无授权内容时清除注册项——「无授权模型」即发布真相，决策自然回到无基线形态）
	g.registerAuthzAppliedState()
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
	if err := validatePublishSmokeConfig(g.PublishSmoke); err != nil {
		return err
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
	if g.CredentialRatePerMinute < 0 {
		return fmt.Errorf("credential_rate_per_minute must be >= 0")
	}
	if g.TenantRatePerMinute < 0 {
		return fmt.Errorf("tenant_rate_per_minute must be >= 0")
	}
	if g.ActionRatePerMinute < 0 {
		return fmt.Errorf("action_rate_per_minute must be >= 0")
	}
	if g.GroupRatePerMinute < 0 {
		return fmt.Errorf("group_rate_per_minute must be >= 0")
	}
	if err := validateAPIEndpointActions(g.APIEndpointActions); err != nil {
		return err
	}
	if err := validateAPIEndpointGroups(g.APIEndpointGroups); err != nil {
		return err
	}
	if err := validateAPIRateLimitDisposition(g.APIRateLimitAction, g.APITempBlockSeconds); err != nil {
		return err
	}
	if _, err := compileAPIIdentityBlocks(g.APIIdentityBlocks); err != nil {
		return err
	}
	if g.APIDynamicProtection {
		switch g.APIProtectionMode {
		case "", "OFF", "OBSERVE", "PROTECT":
		default:
			return fmt.Errorf("api_protection_mode must be OFF, OBSERVE or PROTECT")
		}
		// api_admission 段刻意不做硬校验：mode 词表外/缺失 fail-safe 视为 OFF
		// （不启用不拦截优于误拦截），归一与留痕在 Provision 编译期完成
		// （compileAPIAdmissionPolicies）；这与 api_protection_mode 非法值拒载
		// 的硬校验是两条刻意的不同纪律（全局模式错位影响面大，准入逐应用下发）
		switch g.APIResponseFailPolicy {
		case "", apiFailOpen, apiFailClosed:
		default:
			return fmt.Errorf("api_response_fail_policy must be FAIL_OPEN or FAIL_CLOSED")
		}
		if g.APIResponseCaptureMaxBytes < 0 || g.APIResponseCaptureMaxBytes > maxAPIResponseCaptureMaxBytes {
			return fmt.Errorf("api_response_capture_max_bytes must be between 0 and %d", maxAPIResponseCaptureMaxBytes)
		}
		if ratio := g.APIResponseSampleRatio; ratio != nil &&
			(*ratio < 0 || *ratio > 1 || math.IsNaN(*ratio) || math.IsInf(*ratio, 0)) {
			return fmt.Errorf("api_response_sample_ratio must be a finite number between 0 and 1")
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
		rules, err := compileAPIMaskRules(g.APIMaskRules)
		if err != nil {
			return err
		}
		if _, err := compileAPIMaskCrypto(g.APIMaskCrypto, rules); err != nil {
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
		// 强流程定义装配期校验（NG-FLOW-01；与 Provision 共用 flowguard.BuildRegistry——
		// §1.1 校验逐条 + 版本不可变断言一并预检，配置错误显式返回，不静默吞错）
		if _, err := flowguard.BuildRegistry(g.APIStrongFlows); err != nil {
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
	// 身份风险策略（risk_policy）自身仍逐项消毒 fail-open；唯一强制依赖例外是 PROTECT
	// 挑战档必须搭配 Bot PROTECT，避免把已达阈挑战静默降级为放行。校验在 Bot 段解析后执行。
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
	var botPolicy *botPolicyJSON
	if len(g.BotPolicy) > 0 {
		sec, err := parseAndValidateBotPolicy(g.BotPolicy)
		if err != nil {
			return err
		}
		botPolicy = sec
	}
	if err := g.validateRiskChallengeDependency(botPolicy); err != nil {
		return err
	}
	// API 受限例外（api_exceptions 段）装配期预检：严格解码 + 全量校验，
	// 任一失败显式拒绝（fail-closed，与 jwt_trust 同一纪律）
	if len(g.APIExceptions) > 0 {
		if _, err := ParseAPIExceptionsSection(g.APIExceptions); err != nil {
			return err
		}
	}
	// AI 爬虫治理策略（ai_crawl_policy 段）装配期预检：严格解码 DisallowUnknownFields +
	// 全量校验（PROTECT+labyrinth 必含密钥、SSRF directory_url 预检、公钥 PEM 校验）
	if len(g.AICrawlPolicy) > 0 {
		if err := g.validateAICrawlPolicy(); err != nil {
			return err
		}
	}
	// 客户端供应链安全策略（client_side_policy 段）装配期预检：严格解码 DisallowUnknownFields +
	// 全量校验（CSP 来源令牌、无 CR/LF 控制字符、路径与 SRI 校验）
	if len(g.ClientSidePolicy) > 0 {
		if err := g.validateClientSidePolicy(); err != nil {
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
	if g.aiCrawlCancel != nil {
		g.aiCrawlCancel() // 只取消不置 nil（Cleanup 幂等纪律）
		if g.aiCrawl != nil {
			g.aiCrawl.WaitBackgroundRefresh()
		}
	}
	if g.clientSide != nil {
		g.clientSide.Close() // 只关资源不置 nil（Cleanup 幂等纪律）
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

// compileAPIAdmissionPolicies 装配 API 准入策略（WDSP P1）：按应用归一为运行时查找结构。
// fail-safe 纪律：mode 词表外/缺失按 OFF 不启用（Warn 留痕，不拒载——不拦截优于误拦截，
// 与 normalizeLLMAllowedModels 的宽容归一同一哲学）；显式 OFF 策略不入库（语义=不启用，
// 与无策略同一行为）；确认端点键逐项去空白/去空项/去重（server 与管线同一 endpoint_key
// 口径，网关侧不再二次归一化路径，避免口径漂移）。返回 nil = 无生效策略，准入检测零行为。
func (g *Guard) compileAPIAdmissionPolicies() map[string]detectors.AdmissionPolicy {
	sec := g.APIAdmissionPolicies
	if sec == nil || len(sec.Policies) == 0 {
		return nil
	}
	out := make(map[string]detectors.AdmissionPolicy, len(sec.Policies))
	for appID, p := range sec.Policies {
		if strings.TrimSpace(appID) == "" {
			g.logger.Warn("api_admission: 空 application_id 策略跳过")
			continue
		}
		mode := strings.ToUpper(strings.TrimSpace(p.Mode))
		if mode == "" || mode == detectors.AdmissionModeOff {
			continue // 缺失/显式 OFF：不启用（与无策略同义，无需留痕）
		}
		if mode != detectors.AdmissionModeObserve && mode != detectors.AdmissionModeProtect {
			g.logger.Warn("api_admission: 非法 mode 按 OFF 处理（不启用准入判定）",
				zap.String("application_id", appID), zap.String("mode", p.Mode))
			continue
		}
		confirmed := make(map[string]struct{}, len(p.ConfirmedEndpoints))
		for _, ek := range p.ConfirmedEndpoints {
			ek = strings.TrimSpace(ek)
			if ek == "" {
				continue
			}
			confirmed[ek] = struct{}{}
		}
		out[appID] = detectors.AdmissionPolicy{Mode: mode, Confirmed: confirmed}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// apiAdmissionPolicyForApp 解析本实例应用的准入策略。请求→应用解析与事件/访问日志同一
// 口径：Guard 实例级 AppID 绑定（保护地址/Host 绑定在站点配置层完成，AppID 随配置下发）；
// 应用未识别（AppID 空）或应用无策略 → nil（不判定直接放行，与 KnownEndpoints 现状一致）。
func (g *Guard) apiAdmissionPolicyForApp() *detectors.AdmissionPolicy {
	if len(g.apiAdmission) == 0 || g.AppID == "" {
		return nil
	}
	p, ok := g.apiAdmission[g.AppID]
	if !ok {
		return nil
	}
	return &p
}

// compileAPIGraphQLPolicies 装配 GraphQL 成本预算策略（NG-GQL-03）：按应用归一为
// 管线策略查找结构；空 application_id 键跳过并 Warn（与准入同一 fail-safe 形态）。
func (g *Guard) compileAPIGraphQLPolicies() map[string]*pipeline.GraphQLPolicy {
	sec := g.APIGraphQLPolicies
	if sec == nil || len(sec.Policies) == 0 {
		return nil
	}
	out := make(map[string]*pipeline.GraphQLPolicy, len(sec.Policies))
	for appID, pol := range sec.Policies {
		if appID == "" {
			g.logger.Warn("api_graphql: 空 application_id 策略跳过")
			continue
		}
		p := pol
		out[appID] = p.toPolicy()
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// apiGraphQLPolicyForApp 本实例应用的 GraphQL 策略（未配置 = nil，管线零行为变化）。
func (g *Guard) apiGraphQLPolicyForApp() *pipeline.GraphQLPolicy {
	if len(g.apiGraphQL) == 0 || g.AppID == "" {
		return nil
	}
	return g.apiGraphQL[g.AppID]
}

// normalizeLLMAllowedModels LLM 授权模型名单归一：逐项去空白、去空项、去重（保序）。// 名单语义宽容（发布侧已做长度/条数校验），网关侧不因此拒绝配置加载。
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

// connectionAddrHeader 是 guard 注入的内部请求头（值=原始 TCP 对端 host:port），
// 供 server 侧安全事件采集回填 connection_ip/client_port（RemoteAddr 改写后
// Coraza 审计事务不再携带该事实）。
const connectionAddrHeader = "X-Jiuzhang-Connection-Addr"

// ---------- 请求处理 ----------

// ServeHTTP 主流程。
func (g *Guard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 加密会话元数据桥接（须在 RemoteAddr 改写与访问日志采集前执行：为国密 TLCP 连接补齐 r.TLS，
	// 并将 ClientHello / JA3 / 协议版本与国密标识写入请求上下文）
	ctx := attachTLSConnMeta(r.Context(), r)

	// APM 阶段1（ADR D5/D6）：trace 上下文在任何拦截分支之前建立，
	// 全链路（含前置拦截）经请求上下文可取
	tc := g.resolveTraceContext(r)
	ctx = context.WithValue(ctx, traceContextKey{}, tc)

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
	DefaultCovCounters.Inc(StageTotal)
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
	// 1.5 站点级 HTTP 协议版本降级门控（未配置 allowed_http_versions 时零开销直通；放行发布冒烟精确探针）
	if !g.isHTTPVersionAllowed(r) && r.URL.Path != publishSmokePath {
		accessLogAnnotate(r.Context(), wafActionBlock)
		dispo.RecordTerminal(ExecutorUnknown, DisActionBlock, http.StatusHTTPVersionNotSupported, false, []string{"HTTP_VERSION_NOT_ALLOWED"}, nil)
		return caddyhttp.Error(http.StatusHTTPVersionNotSupported, fmt.Errorf("http version %s not allowed by site policy", r.Proto))
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
	// 内部头携带原始 TCP 对端地址：RemoteAddr 改写后 Coraza 审计事务只能看到真实 IP，
	// server 侧事件采集经此头回填 connection_ip/client_port。改写点在 guard 入口、先于
	// 一切下游（WAF/代理），客户端注入的同名头在此被覆盖。
	r.Header.Set(connectionAddrHeader, r.RemoteAddr)
	// 下游（WAF/日志/代理）统一使用真实IP
	r.RemoteAddr = net.JoinHostPort(clientIP.String(), "0")
	r.Header.Set("X-Real-Ip", clientIP.String())
	// coraza-caddy 审计事务优先取 {http.vars.client_ip}（accept 时固化的连接源 IP，
	// 其 PrepareRequest 返回值被丢弃，不跟随上方 RemoteAddr 改写）；同步该变量，
	// 保证 WAF 审计事件 client_ip 与真实 IP 识别结果一致
	caddyhttp.SetVar(r.Context(), caddyhttp.ClientIPVarKey, clientIP.String())

	// 1.6 调试保留命名空间 /_wdsp/debug/v1/（debug_cc_counter 启用时；阶段5 §十七
	// CC 精确计数探针）：真实 IP 识别之后、CC 限速之前挂接——回显请求本身不进入
	// CC 计数（探针自污染防控），也不进入 JWT/身份观测步骤；全部结局本地响应，
	// 结构上不可能反向代理（见 debug_cccounter.go）
	if g.DebugCCCounter && strings.HasPrefix(normalizer.CanonicalPath(r.URL.Path), debugReservedNamespace) {
		return g.serveDebugNamespace(w, r, res)
	}

	// 1.4 JWT 信任链本地验证（WDSP P0-03；jwt_trust 段下发且非 OFF 时）。
	// 仅计算——结果入请求上下文：身份观测（VERIFIED 可信信号）与 API 动态管线
	// 阶段的强制处置点（serveNext）消费。本步骤独立于身份观测引擎：观测关闭
	// 或其 panic recover 均不影响 JWT 验证与执行（不经过观测的 fail-open 分支）。
	if g.jwtVerifier != nil {
		g.verifyJWTTrust(r)
	}

	// 1.45 机器身份本地验证（NG-ID G1：紧随 JWT 验证之后、身份观测前——
	// compute-only 入上下文（jwt_trust 同形挂点）；纯本地热路径零网络 IO；
	// recover → UNAVAILABLE 不 panic；VERIFIED 注入独立信号不改
	// identity_key/identity_type 语义（AGENTS.md 红线）；机器身份是独立第二条
	// 信任链，不替代不改写 JWT 链，同请求可双 VERIFIED）
	if g.apiMachineID != nil {
		g.verifyMachineIdentity(r)
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

	// 1.55 身份封禁名单：身份观测后、保护地址/白名单之前执行。
	// identity_key 与 identitybehavior 同盐同算法，命中立即 403，后续 Bot/API/WAF 不得绕过；
	// 事件只携带名单记录 ID，不携带身份键或凭据原文。
	if len(g.apiIdentityBlocks) > 0 {
		identity := identitybehavior.ResolveIdentity(r, g.IdentitySalt, clientIP.String())
		for _, key := range identity.CandidateKeys(g.IdentitySalt) {
			if blockID, blocked := g.apiIdentityBlocks[key]; blocked {
				dispo.RecordTerminal(ExecutorManualBan, DisActionBlock, http.StatusForbidden, false,
					[]string{"IDENTITY_MANUAL_BLOCK"}, []string{blockID})
				ev := base
				ev.Action = "BLOCK"
				ev.PolicyID = blockID
				ev.FinalDecision = dispo.JSON()
				g.emit(ev, events.IdentityManualBlock, "BLOCK", http.StatusForbidden)
				accessLogAnnotate(r.Context(), wafActionBlock)
				DefaultCovCounters.Inc(StageManualBan)
				return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("identity blocked"))
			}
		}
	}

	// 2. 保护地址：仅当「客户端 IP」命中时跳过 ACL/CC（仍过 Bot 挑战、WAF 与 API 动态防护）。
	// 连接源（LB/本机反代）不得用于旁路真实客户端的访问控制。
	if g.protected.Contains(clientIP) {
		dispo.RecordStep(ExecutorProtectedAddress, StepExecuted, "client IP in protected addresses")
		recordBypassedSteps(dispo, "PROTECTED_ADDRESS",
			ExecutorManualBan, StepModuleIPAllowlist, StepModuleURLAllowlist, ExecutorIPBlacklist, ExecutorL7ACL,
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
			DefaultCovCounters.Inc(StageManualBan)
			return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("temporarily blocked"))
		}
		b := blk
		autoBlock = &b
	}

	// 4. IP 白名单 → URL 白名单 → IP 黑名单
	// 白名单命中直接放行：跳过 IP 黑名单、L7、自动封禁、身份风险策略、授权限速与 CC，
	// 不跳过 Bot 挑战、API 动态防护与 WAF（安全底线）；不绕过人工临时封禁。
	if allowDec := accesscontrol.Evaluate(clientIP, now, g.allowG, g.allowA, nil, nil); allowDec.Action == accesscontrol.ActionAllow {
		// IP 白名单命中放行（P0-04 事实记录）：只记录实际绕过的步骤（SKIPPED + detail）；
		// 放行非终止，不挂 final_decision（该请求仍过 Bot 挑战、API 动态防护与 WAF——安全底线）
		dispo.RecordStep(StepModuleIPAllowlist, StepExecuted, "allow hit rule="+allowDec.RuleID)
		recordBypassedSteps(dispo, "IP_ALLOWLIST",
			StepModuleURLAllowlist, ExecutorIPBlacklist, ExecutorL7ACL, ExecutorAutoBan,
			ExecutorRiskPolicy, ExecutorLicenseQuota, ExecutorCC)
		ev := base
		ev.AccessRuleID = allowDec.RuleID
		g.emit(ev, events.IPAllowMatch, "ALLOW", 0)
		return g.serveNextViaBot(w, r, next, base, res)
	}
	if urlDec := urlwhitelist.Evaluate(r.URL.Path, r.Method, now, g.urlAllowG, g.urlAllowA); urlDec.Matched {
		dispo.RecordStep(StepModuleURLAllowlist, StepExecuted, "url allow hit rule="+urlDec.RuleID)
		recordBypassedSteps(dispo, "URL_ALLOWLIST",
			ExecutorIPBlacklist, ExecutorL7ACL, ExecutorAutoBan,
			ExecutorRiskPolicy, ExecutorLicenseQuota, ExecutorCC)
		ev := base
		ev.AccessRuleID = urlDec.RuleID
		g.emit(ev, events.URLAllowMatch, "ALLOW", 0)
		return g.serveNextViaBot(w, r, next, base, res)
	}
	if denyDec := accesscontrol.Evaluate(clientIP, now, nil, nil, g.denyG, g.denyA); denyDec.Action == accesscontrol.ActionDeny {
		dispo.RecordTerminal(ExecutorIPBlacklist, DisActionBlock, http.StatusForbidden, false,
			[]string{"IP_IN_BLACKLIST"}, []string{denyDec.RuleID})
		ev := base
		ev.AccessRuleID = denyDec.RuleID
		ev.FinalDecision = dispo.JSON()
		g.emit(ev, events.IPDenyMatch, "DENY", http.StatusForbidden)
		accessLogAnnotate(r.Context(), wafActionBlock)
		DefaultCovCounters.Inc(StageIPBlacklist)
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("access denied"))
	}

	// 4.5 L7 请求阶段（IP 黑白名单之后、CC 之前）；响应条件规则在下游返回后评估。
	// 已通过本次发布独立 HMAC 鉴权的精确冒烟探针跳过 L7 规则，避免域名级重定向（如裸域跳 www）
	// 拦截发布后 REAL_IP/CC 流量验证并误触发自动回滚；未鉴权请求仍正常经过 L7 规则。
	var l7RequestBody []byte
	l7RequestBodyReady := true
	if g.l7 != nil && !g.isAuthenticatedPublishSmoke(r, now) {
		if g.l7.NeedsRequestBody() {
			l7RequestBody, l7RequestBodyReady = g.readL7RequestBody(r)
		}
		if l7dec, ok := g.l7.EvalRequest(r, clientIP, l7RequestBody, l7RequestBodyReady); ok {
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
		DefaultCovCounters.Inc(StageAutoBan)
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("temporarily blocked"))
	}

	// 5.4 身份风险策略处置（risk_policy 启用时；执行点在身份解析之后、授权限速与 CC 之前，
	// 与人工/自动临时封禁同层。IP 白名单/L7 allow 已在上方提前放行——白名单优先；
	// 身份行为白名单命中在执行点内显式跳过。OBSERVE 只记录"假设会处置"事件永不实断；
	// PROTECT 达阈 403/429，事件 reason 固定 identity_risk_policy，不伪装成规则阻断；
	// 不改 dynamic_security/decision 的可信 BLOCK 源——红线）
	if g.riskEngineForApp() != nil {
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

	// 7. 放行；存在响应条件规则时先挂留受控响应，完成 L7 响应阶段评估。
	return g.serveNextWithL7Response(w, r, next, base, res, clientIP, l7RequestBody, l7RequestBodyReady)
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
		// redirect_url 在配置加载时已强制校验 scheme 仅 http/https；开启 preserve_path_query 时拼接原路径与查询参数。
		// 重定向是网关终止但非安全动作（P0-04）：security_action=NONE、executor=L7_ACL
		w.Header().Set("Location", dec.Config.RedirectTarget(r.URL))
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
		DefaultCovCounters.Inc(StageL7ACL)
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
		DefaultCovCounters.Inc(StageLicenseQuota)
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
	DefaultCovCounters.Inc(StageLicenseQuota)
	return true
}

// enforceRateLimits 执行 CC 策略；handled=true 表示已响应。
func (g *Guard) enforceRateLimits(w http.ResponseWriter, r *http.Request, clientIP netip.Addr, base events.Event, now time.Time) (bool, error) {
	dispo := DispositionFrom(r.Context())
	// L7 allow 命中：跳过 CC（纵深防御，正常路径已在 L7 命中点直接放行）
	if l7Skip(r.Context()) {
		return false, nil
	}
	path := normalizer.CanonicalPath(r.URL.Path)
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
			DefaultCovCounters.Inc(StageCC)
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
			DefaultCovCounters.Inc(StageCC)
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
			DefaultCovCounters.Inc(StageCC)
			ev.FinalDecision = dispo.JSON()
			g.emit(ev, events.CCTempBlockCreated, "TEMP_BLOCK", 0)
			g.emit(ev, events.CCRequestRejected, "TEMP_BLOCK", http.StatusTooManyRequests)
			accessLogAnnotate(r.Context(), wafActionBlock)
			return true, nil
		}
	}
	return false, nil
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
