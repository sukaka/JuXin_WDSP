// capability_gate.go 节点能力发布门（NG-COV-04 server 侧；契约 NG-BASE-02 §2.1 /
// RD_PLAN §4.4/§4.5，类型与集合包含校验在 gateway/dynamic_security/capability）。
//
// 门禁语义（契约，唯一事实源）：
//   - required_capabilities 由「本次发布负载实际包含的特性段」推导
//     （RequiredCapabilities，映射见下）；节点缺任一必需项 → 该节点发布失败并
//     展示缺口（CAP_MISSING:<key>，failure_code CAPABILITY_MISSING），不发送 /load；
//   - 清单缺失/解析失败/契约校验失败/过期（generated_at 超 3×tick=180s）→
//     同样 fail-closed（CAPABILITY_MANIFEST_UNAVAILABLE，注明路径与陈旧度）；
//     能力缺失/清单缺失/过期不得 ACK 成功、不得静默降级；
//   - 空需求 = 免门禁（现有行为零变化——关键兼容约束：存量发布不得因门禁失败；
//     当前映射只覆盖 grpc 现存特性段，未配置 grpc 特性的发布不触发门禁）；
//   - v1 边界：次要节点（http 扇出）manifest 通道未建——有需求且存在次要节点时
//     按「清单缺失」fail-closed 拒绝并展示节点清单（docs/nextgen/NG-S1-TASKBOOK.md §4）。
//
// 特性段 → 需求键映射（当前实际存在的特性段；测试逐键锚定）：
//
//	APIGRPCDescriptors 非空      → protocols.grpc="unary_g1" + detectors.grpc.unary("grpc/1")
//	APIGRPCAllowCompression=true → protocols.grpc="frame" + detectors.grpc.frame("grpc/1")
//	APIGRPCMaxFrameBytes>0       → limits.max_grpc_frame_bytes=配置值（节点硬上限须 ≥ 配置）
//	APIAuthzSchema 非空           → detectors.authzdecide("az/2")（NG-AZ-02 v2 快照消费语义）
//	APIAuthz 模型/角色基线含任一 enforcement=PROTECT
//	                             → detectors.authzdecide("az/3")（NG-AZ-03 实断消费语义；覆盖 az/2 需求）
//	当前/PreviousValid APIAuthz 模型含任一 ANY_OF
//	                             → detectors.authzdecide("az/4")（含 OBSERVE；覆盖 az/2/az/3 需求）
//	APIStrongFlows 含任一 mode=PROTECT
//	                             → detectors.flowguard("flow/1")（NG-FLOW-02 强流程实断消费语义）
//	APIMCPBindings 含任一 mode=PROTECT
//	                             → protocols.mcp="acl_v1" + detectors.mcp.toolcall("mcp/2")
//	                               （NG-MCP G1 批次 B1：MCP 工具调用 ACL 实断消费语义）
//	APIMachineIdentityBindings 含任一 mode=PROTECT
//	                             → detectors.machineid("mid/1")
//	                               （NG-ID g1 批次 B1：机器身份签名验证实断消费语义；
//	                               ProtocolLevels 不动——检测器能力非协议层级）
//
// 不在 v1 映射内（有文档注明）：GraphQL cost_v1（未实现）、coverage 观测（可降级
// 观测而非执行阻断资格）、actions（grpc_error 等协议适配执行层未实现）。
package gatewayconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/capability"
	"github.com/jiuzhang-waf/server/internal/applications"
)

// 清单文件名与陈旧阈值（网关侧 janitor 60s 刷新；超过 3×tick 即 stale——
// 停刷新即声明节点自报不可用，fail-closed）。
const (
	capabilityManifestFile = "capability.json"
	capabilityStaleAfter   = 3 * 60 * time.Second
)

// CapabilityFacts 发布负载能力事实（由 GuardConfig 特性段推导；零值 = 无特性需求）。
type CapabilityFacts struct {
	GRPCDescriptorSets   int  // api_grpc_descriptors 集数（>0 需要 unary 级字段解析）
	GRPCAllowCompression bool // api_grpc_allow_compression（帧级压缩标志解析）
	GRPCMaxFrameBytes    int  // api_grpc_max_frame_bytes 配置上限（>0 需要节点硬上限 ≥ 配置）
	// GRPCBindingProtect NG-GRPC G1 批次 B1：api_grpc_bindings 含任一 mode=PROTECT
	// 绑定（gRPC 字段结构违规协议化执行（trailers-only grpc-status）消费需要 grpc/2——
	// 旧节点（grpc/1=帧校验+描述符观测）会把违规实断成 HTTP 403 误形态，fail-closed）
	GRPCBindingProtect    bool
	AuthzSnapshotV2       bool // NG-AZ-02 D4-4：api_authz_schema 非空（v2 快照——水位/租约/冲突集消费需要 az/2）
	AuthzEnforceProtect   bool // NG-AZ-03 D6：api_authz_models/api_authz_role_baselines 含任一 enforcement=PROTECT（实断消费需要 az/3）
	AuthzComplexRelations bool // 当前或 PreviousValid 含 ANY_OF（OWNER/SHARED_WITH 消费需要 az/4，包括 OBSERVE）
	StrongFlowProtect     bool // NG-FLOW-02 D6/D12：api_strong_flows 含任一 mode=PROTECT 定义（强流程实断消费需要 flow/1）
	// MCPToolCallProtect NG-MCP G1 批次 B1：api_mcp_bindings 含任一 mode=PROTECT 绑定
	//（MCP 工具调用 ACL 实断消费需要 mcp/2 + protocols.mcp=acl_v1——不认识 MCP 目录
	// 段的旧节点会把 PROTECT 绑定漏放行，fail-closed；全 OBSERVE/空绑定不产生需求）
	MCPToolCallProtect bool
	// MachineIDProtect NG-ID g1 批次 B1：api_machine_identity_bindings 含任一 mode=PROTECT
	// 绑定（机器身份签名验证 PROTECT 消费需要 detectors.machineid=mid/1——不认识机器
	// 身份段的旧节点会把签名验证漏做或误形态处置，fail-closed；ProtocolLevels 不动——
	// 机器身份是检测器能力不是协议层级（capability/types.go:22-27 现实约束）；
	// 全 OBSERVE/空绑定不产生需求，滚动升级可行）
	MachineIDProtect bool
	// RiskChallenge 表示发布范围内至少一个最终生效的已启用风险策略配置了 CHALLENGE 阈值。
	RiskChallenge bool
	// TLSMuxRequired 表示发布配置需要使用 caddy.listeners.jiuzhang_tls_mux 监听包装器
	// 或 http.reverse_proxy.transport.jiuzhang_tls 回源传输模块（需要节点能力 protocols.tls_mux="v1"）。
	TLSMuxRequired bool
	// TLCPRequired 表示发布配置包含国密 SM_TLCP 双证书、TLCP1.1 协议策略或 tlcp 回源源站
	// （需要节点能力 protocols.tlcp="1.1"）。
	TLCPRequired bool
	// JWTBindingProtect Phase 9A-1：jwt_trust 含任一 mode=PROTECT 且至少一个 issuer 启用了
	// 非 NONE 的 token_binding（DPoP / mTLS）——需要节点自报 detectors.jwt.binding="jwtbind/1"。
	JWTBindingProtect bool
	// AICrawlProtect Phase 9A-2：ai_crawl_policy 含任一 mode=PROTECT 策略——
	// 需要节点自报 detectors.aicrawl="aicrawl/1" 与 actions "tarpit" / "http_402"。
	AICrawlProtect bool
	// ClientSideProtect Phase 9B：client_side_policy 含任一 mode=PROTECT 或 csp_mode=ENFORCE 策略——
	// 需要节点自报 detectors.clientside="clientside/1"。
	ClientSideProtect bool
}

// capabilityFactsFromApps 从发布应用快照推导 TLS Mux 与国密 TLCP 能力需求。
// 纯存量国际 TLS/HTTP 应用（无 GM 证书、无自定义 TLSConfig、无 tlcp 源站）返回 (false, false)，
// 保证存量发布空需求免门禁、零行为变化。
func capabilityFactsFromApps(appsData []AppData) (tlsMuxRequired, tlcpRequired bool) {
	for _, app := range appsData {
		if app.DeploymentMode == applications.DeployModeMirror {
			continue
		}
		if appHasActiveHTTPS(app) {
			if appNeedsTLSMux(app) {
				tlsMuxRequired = true
			}
			if app.HasGMCert {
				tlsMuxRequired = true
				tlcpRequired = true
			}
			if app.TLSConfig != nil {
				if strings.EqualFold(strings.TrimSpace(app.TLSConfig.TLSProtocolMode), TLSProtocolModeGMOnly) ||
					sliceContainsFold(app.TLSConfig.AllowedTLSVersions, TLSVersionTLCP11) {
					tlsMuxRequired = true
					tlcpRequired = true
				}
			}
		}
		for _, u := range app.Upstreams {
			if u.Status != "ACTIVE" {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(u.Scheme), "tlcp") {
				tlsMuxRequired = true
				tlcpRequired = true
			} else if upstreamUsesJiuzhangTLSTransport(u, app.TLSConfig) {
				tlsMuxRequired = true
			}
		}
		for _, pr := range app.PathRoutes {
			if !strings.HasPrefix(pr.PathPrefix, "/") {
				continue
			}
			u := applications.Upstream{
				Scheme:         pr.UpstreamScheme,
				NormalizedHost: pr.UpstreamHost,
				Port:           pr.UpstreamPort,
				Status:         "ACTIVE",
				TLSVerify:      true,
			}
			if strings.EqualFold(strings.TrimSpace(pr.UpstreamScheme), "tlcp") {
				tlsMuxRequired = true
				tlcpRequired = true
			} else if upstreamUsesJiuzhangTLSTransport(u, app.TLSConfig) {
				tlsMuxRequired = true
			}
		}
	}
	return tlsMuxRequired, tlcpRequired
}

// mergeAppCapabilityFacts 将应用级 TLS Mux / TLCP 能力事实并入 GuardConfig 能力事实。
func mergeAppCapabilityFacts(facts CapabilityFacts, appsData []AppData) CapabilityFacts {
	tlsMux, tlcp := capabilityFactsFromApps(appsData)
	facts.TLSMuxRequired = facts.TLSMuxRequired || tlsMux
	facts.TLCPRequired = facts.TLCPRequired || tlcp
	return facts
}

// capabilityFactsFromGuard 从发布负载提取能力事实（nil guardCfg = 无特性需求）。
// targetAppIDs 为空表示全局发布，非空表示仅按这些应用的最终生效策略计算风险挑战需求。
func capabilityFactsFromGuard(guardCfg *GuardConfig, targetAppIDs ...uuid.UUID) CapabilityFacts {
	if guardCfg == nil {
		return CapabilityFacts{}
	}
	facts := CapabilityFacts{
		GRPCDescriptorSets:   len(guardCfg.APIGRPCDescriptors),
		GRPCAllowCompression: guardCfg.APIGRPCAllowCompression,
		GRPCMaxFrameBytes:    guardCfg.APIGRPCMaxFrameBytes,
		AuthzSnapshotV2:      guardCfg.APIAuthzSchema != "",
	}
	// NG-GRPC G1 批次 B1：绑定任一 PROTECT → grpc/2 需求（全 OBSERVE/空绑定
	// 不产生需求，滚动升级可行——az/3、flow/1 同纪律）
	for _, b := range guardCfg.APIGRPCBindings {
		if b.Mode == "PROTECT" {
			facts.GRPCBindingProtect = true
			break
		}
	}
	// 当前与 PreviousValid 都可能被网关消费；任一 ANY_OF 即需要 az/4，
	// 与 enforcement 无关。PROTECT 仍按既有规则聚合 az/3，最终由 az/4 覆盖。
	for _, m := range guardCfg.APIAuthzModels {
		if strings.EqualFold(strings.TrimSpace(m.RequiredRelation), "ANY_OF") {
			facts.AuthzComplexRelations = true
		}
		if m.Enforcement == "PROTECT" {
			facts.AuthzEnforceProtect = true
		}
	}
	if guardCfg.APIAuthzPreviousValid != nil {
		for _, m := range guardCfg.APIAuthzPreviousValid.Models {
			if strings.EqualFold(strings.TrimSpace(m.RequiredRelation), "ANY_OF") {
				facts.AuthzComplexRelations = true
				break
			}
		}
	}
	if !facts.AuthzEnforceProtect {
		for _, b := range guardCfg.APIAuthzRoleBaselines {
			if b.Enforcement == "PROTECT" {
				facts.AuthzEnforceProtect = true
				break
			}
		}
	}
	// NG-FLOW-02 D12：强流程定义含任一 PROTECT → flow/1 需求（全 OBSERVE 不产生需求，
	// 滚动升级可行——az/3 同纪律先例）
	for _, f := range guardCfg.APIStrongFlows {
		if f.Mode == "PROTECT" {
			facts.StrongFlowProtect = true
			break
		}
	}
	// NG-MCP G1 批次 B1：MCP 绑定任一 PROTECT → mcp/2 + acl_v1 需求（全 OBSERVE/空
	// 绑定不产生需求，滚动升级可行——grpc/2、flow/1 同纪律）
	for _, b := range guardCfg.APIMCPBindings {
		if b.Mode == "PROTECT" {
			facts.MCPToolCallProtect = true
			break
		}
	}
	// NG-ID g1 批次 B1：机器身份绑定任一 PROTECT → mid/1 需求（全 OBSERVE/空绑定
	// 不产生需求，滚动升级可行——az/3、flow/1、mcp/2 同纪律）
	for _, b := range guardCfg.APIMachineIdentityBindings {
		if b.Mode == "PROTECT" {
			facts.MachineIDProtect = true
			break
		}
	}
	// Phase 9A-1：JWT 信任策略 PROTECT 且至少一个 issuer 启用了非 NONE 的 token_binding → jwt.binding
	for _, pol := range guardCfg.JWTTrust {
		if pol == nil || pol.Mode != "PROTECT" {
			continue
		}
		for _, iss := range pol.Issuers {
			if iss.TokenBinding != nil && iss.TokenBinding.Mode != "" && iss.TokenBinding.Mode != "NONE" {
				facts.JWTBindingProtect = true
				break
			}
		}
		if facts.JWTBindingProtect {
			break
		}
	}
	// Phase 9A-2：AI 爬虫治理策略含任一 PROTECT → aicrawl + tarpit/http_402
	for _, pol := range guardCfg.AICrawlPolicy {
		if pol != nil && pol.Mode == "PROTECT" {
			facts.AICrawlProtect = true
			break
		}
	}
	// Phase 9B：客户端供应链安全策略含任一 PROTECT 或 CSP ENFORCE → clientside/1
	for _, pol := range guardCfg.ClientSidePolicy {
		if pol != nil && (pol.Mode == "PROTECT" || pol.CSPMode == "ENFORCE") {
			facts.ClientSideProtect = true
			break
		}
	}
	facts.RiskChallenge = riskChallengeRequired(guardCfg, targetAppIDs)
	return facts
}

func riskChallengeRequired(guardCfg *GuardConfig, targetAppIDs []uuid.UUID) bool {
	if len(targetAppIDs) == 0 {
		if riskPolicyChallengeEnabled(guardCfg.RiskPolicy) {
			return true
		}
		for i := range guardCfg.RiskPolicyOverrides {
			if riskPolicyChallengeEnabled(&guardCfg.RiskPolicyOverrides[i].Policy) {
				return true
			}
		}
		return false
	}
	for _, appID := range targetAppIDs {
		policy := guardCfg.RiskPolicy
		for i := range guardCfg.RiskPolicyOverrides {
			override := &guardCfg.RiskPolicyOverrides[i]
			if override.ApplicationID == appID.String() {
				policy = &override.Policy
			}
		}
		if riskPolicyChallengeEnabled(policy) {
			return true
		}
	}
	return false
}

func riskPolicyChallengeEnabled(policy *GuardRiskPolicy) bool {
	return policy != nil && policy.Enabled && policy.ChallengeThreshold > 0
}

// RequiredCapabilities 从负载事实推导需求清单（同构子集；空需求 = 免门禁）。
func RequiredCapabilities(f CapabilityFacts) capability.Manifest {
	required := capability.Manifest{ContractVersion: capability.ContractVersion}
	protocols := map[string]string{}
	var detectors []capability.DetectorCap
	var actions []string
	if f.GRPCDescriptorSets > 0 {
		protocols["grpc"] = "unary_g1"
	}
	if f.GRPCDescriptorSets > 0 || f.GRPCBindingProtect {
		grpcUnaryVersion := "grpc/1"
		if f.GRPCBindingProtect {
			// NG-GRPC G1 批次 B1：含任一 PROTECT 绑定的快照需要 grpc/2 协议化执行
			// 消费语义（trailers-only grpc-status 形态）——grpc/1 旧节点 fail-closed
			// 拒绝（不得把违规实断成 HTTP 403 误形态）；全 OBSERVE/空绑定不产生需求
			grpcUnaryVersion = "grpc/2"
		}
		detectors = append(detectors, capability.DetectorCap{Name: "grpc.unary", Version: grpcUnaryVersion})
	} else if f.GRPCAllowCompression {
		// 压缩帧解析属帧级同族能力（有描述符时 unary_g1 已隐含 frame）
		protocols["grpc"] = "frame"
		detectors = append(detectors, capability.DetectorCap{Name: "grpc.frame", Version: "grpc/1"})
	}
	limits := map[string]int64{}
	if f.GRPCMaxFrameBytes > 0 {
		limits["max_grpc_frame_bytes"] = int64(f.GRPCMaxFrameBytes)
	}
	// ANY_OF 是当前/PreviousValid 的关系集合消费语义，OBSERVE 同样要求 az/4；
	// 纯旧 OWNER 模型继续维持 az/2（v2）或 az/3（PROTECT）。
	if f.AuthzComplexRelations {
		detectors = append(detectors, capability.DetectorCap{Name: "authzdecide", Version: "az/4"})
	} else if f.AuthzEnforceProtect {
		detectors = append(detectors, capability.DetectorCap{Name: "authzdecide", Version: "az/3"})
	} else if f.AuthzSnapshotV2 {
		detectors = append(detectors, capability.DetectorCap{Name: "authzdecide", Version: "az/2"})
	}
	// NG-FLOW-02 D12：含任一 mode=PROTECT 强流程定义的快照需要 flow/1 实断消费语义——
	// 不认识强流程段的旧节点 fail-closed 拒绝（不得在看不见定义的节点上漏断）；
	// 全 OBSERVE 定义不产生需求（滚动升级可行）
	if f.StrongFlowProtect {
		detectors = append(detectors, capability.DetectorCap{Name: "flowguard", Version: "flow/1"})
	}
	// NG-MCP G1 批次 B1：含任一 PROTECT MCP 绑定的快照需要 protocols.mcp=acl_v1 +
	// mcp/2 工具调用 ACL 实断消费语义——不认识 MCP 目录段的旧节点 fail-closed 拒绝
	//（不得在看不见目录准入规则的节点上漏放行 PROTECT 绑定）；全 OBSERVE/空绑定
	// 不产生需求（滚动升级可行）
	if f.MCPToolCallProtect {
		protocols["mcp"] = "acl_v1"
		detectors = append(detectors, capability.DetectorCap{Name: "mcp.toolcall", Version: "mcp/2"})
	}
	// NG-ID g1 批次 B1（D11）：含任一 PROTECT 机器身份绑定的快照需要
	// detectors.machineid=mid/1 消费语义（登记册消费+十步验证链+重放原子存储+轮换撤销
	// 水位+协议化执行）——不认识机器身份段的旧节点 fail-closed 拒绝（不得把签名验证
	// 漏做或误形态处置）；全 OBSERVE/空绑定不产生需求（滚动升级可行）；
	// ProtocolLevels 不动（机器身份是检测器能力不是协议层级）
	if f.MachineIDProtect {
		detectors = append(detectors, capability.DetectorCap{Name: "machineid", Version: "mid/1"})
	}
	if f.JWTBindingProtect {
		detectors = append(detectors, capability.DetectorCap{Name: "jwt.binding", Version: "jwtbind/1"})
	}
	if f.AICrawlProtect {
		detectors = append(detectors, capability.DetectorCap{Name: "aicrawl", Version: "aicrawl/1"})
		actions = append(actions, "tarpit", "http_402")
	}
	if f.ClientSideProtect {
		detectors = append(detectors, capability.DetectorCap{Name: "clientside", Version: "clientside/1"})
	}
	if f.RiskChallenge {
		actions = append(actions, "risk_challenge")
	}
	if f.TLSMuxRequired {
		protocols["tls_mux"] = "v1"
	}
	if f.TLCPRequired {
		protocols["tlcp"] = "1.1"
	}
	if len(protocols) > 0 {
		required.Protocols = protocols
	}
	required.Detectors = detectors
	required.Actions = actions
	if len(limits) > 0 {
		required.Limits = limits
	}
	return required
}

// requiredEmpty 空需求判定（ContractVersion 恒置，不计入——空需求 = 免门禁）。
func requiredEmpty(m capability.Manifest) bool {
	return len(m.Protocols) == 0 && len(m.Detectors) == 0 && len(m.Actions) == 0 && len(m.Limits) == 0
}

// LoadNodeManifest 读取节点能力清单（<sidecarDir>/capability.json）并做契约校验；
// 文件缺失/解析失败/契约违规均返回错误（调用方按 fail-closed 处理）。
func LoadNodeManifest(sidecarDir string) (capability.Manifest, error) {
	path := filepath.Join(sidecarDir, capabilityManifestFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		return capability.Manifest{}, fmt.Errorf("读取节点能力清单失败（%s）: %w", path, err)
	}
	var m capability.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return capability.Manifest{}, fmt.Errorf("节点能力清单解析失败（%s）: %w", path, err)
	}
	if msg := m.Validate(); msg != "" {
		return capability.Manifest{}, fmt.Errorf("节点能力清单契约校验失败（%s）: %s", path, msg)
	}
	return m, nil
}

// ManifestStale 陈旧判定：generated_at 距今超过 staleAfter（3×tick）即过期；
// generated_at 不可解析按过期处理（不静默放行）。
func ManifestStale(m capability.Manifest, now time.Time, staleAfter time.Duration) (bool, time.Duration) {
	gen, err := time.Parse(time.RFC3339, m.GeneratedAt)
	if err != nil {
		return true, 0
	}
	age := now.Sub(gen)
	return age > staleAfter, age
}

// sidecarDirOrDefault 发布器 sidecar 目录（空用默认；与 SetSidecarDir 注释同口径）。
func (p *Publisher) sidecarDirOrDefault() string {
	if p.sidecarDir != "" {
		return p.sidecarDir
	}
	return DefaultSidecarDir
}

// formatMissing 缺口明细（CAP_MISSING:<key>(required=…,actual=…) 逐条，与契约展示口径一致）。
func formatMissing(missing []capability.Missing) string {
	parts := make([]string, 0, len(missing))
	for _, m := range missing {
		parts = append(parts, fmt.Sprintf("CAP_MISSING:%s(required=%s,actual=%s)", m.Key, m.Required, m.Actual))
	}
	return strings.Join(parts, "; ")
}

// evaluateCapabilityGate 节点能力发布门评估（兼容仅基于 GuardConfig 的存量调用方与单测）。
func (p *Publisher) evaluateCapabilityGate(ctx context.Context, guardCfg *GuardConfig, targetAppIDs ...uuid.UUID) (bool, string, string) {
	return p.evaluateCapabilityGateWithApps(ctx, guardCfg, nil, targetAppIDs...)
}

// evaluateCapabilityGateWithApps 节点能力发布门评估（executePublish 在回归门禁之后、
// 发往节点 /load 之前调用）。合并 GuardConfig 与 appsData（TLS Mux / 国密 TLCP 需求）；
// targetAppIDs 为空表示全局发布，非空仅评估目标应用。
// 返回 (是否继续发布, 失败码, 失败消息)；空需求/全部满足时放行。
func (p *Publisher) evaluateCapabilityGateWithApps(ctx context.Context, guardCfg *GuardConfig, appsData []AppData, targetAppIDs ...uuid.UUID) (bool, string, string) {
	facts := mergeAppCapabilityFacts(capabilityFactsFromGuard(guardCfg, targetAppIDs...), appsData)
	required := RequiredCapabilities(facts)
	if requiredEmpty(required) {
		return true, "", "" // 空需求免门禁——存量发布零变化
	}

	// 主节点（stage5 主路径：unix socket，经共享 sidecar 卷读取自报清单）
	dir := p.sidecarDirOrDefault()
	manifest, err := LoadNodeManifest(dir)
	if err != nil {
		return false, "CAPABILITY_MANIFEST_UNAVAILABLE",
			"节点能力清单不可用，发布已拒绝（fail-closed 不静默降级）: " + err.Error()
	}
	if stale, age := ManifestStale(manifest, time.Now().UTC(), capabilityStaleAfter); stale {
		return false, "CAPABILITY_MANIFEST_UNAVAILABLE",
			fmt.Sprintf("节点能力清单过期，发布已拒绝（fail-closed；路径 %s，generated_at=%s，陈旧 %.0f 秒超过阈值 %.0f 秒）",
				filepath.Join(dir, capabilityManifestFile), manifest.GeneratedAt, age.Seconds(), capabilityStaleAfter.Seconds())
	}
	if missing := capability.CheckRequirements(required, manifest); len(missing) > 0 {
		return false, "CAPABILITY_MISSING",
			fmt.Sprintf("节点 %q 缺少本次发布所需能力，发布已拒绝（不发送 /load）: %s",
				manifest.NodeID, formatMissing(missing))
	}

	// 次要节点（http 扇出）：v1 manifest 通道未建——有需求且存在次要节点时
	// 按「清单缺失」fail-closed 拒绝并展示节点清单（v1 边界见包注释与任务书 §4）。
	if p.nodeSync != nil {
		targets, err := p.nodeSync.ListSyncTargets(ctx)
		if err != nil {
			return false, "CAPABILITY_MANIFEST_UNAVAILABLE",
				"次要节点清单查询失败，发布已拒绝（fail-closed）: " + err.Error()
		}
		if len(targets) > 0 {
			names := make([]string, 0, len(targets))
			for _, t := range targets {
				names = append(names, t.NodeName)
			}
			return false, "CAPABILITY_MANIFEST_UNAVAILABLE",
				fmt.Sprintf("次要节点能力清单通道 v1 未建，无法校验 %d 个次要节点，发布已拒绝（fail-closed）: %s",
					len(targets), strings.Join(names, ","))
		}
	}
	return true, "", ""
}
