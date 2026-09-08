// jwt_trust.go 业务 JWT 信任链策略下发（WDSP P0-03）：jwt_trust_policies 表按应用行
// → GuardConfig.jwt_trust 段（key=应用编码）随发布通道下发网关（表由迁移 000125 建立；
// 仅 WDSP 开启（APIDynamicProtection）时下发，回滚覆盖快照经 stripAPIGuardSections 剥除——
// 与 API 动态防护其余段同一门控口径；内容纳入 api_policy_version 版本戳）。
// 纪律（任务书 §4.1 末段/§7）：
//   - 读取失败中止发布（fail-hard，与 l7_rules 同一模式）——静默跳过会让已 PROTECT 的
//     应用在新配置中丢失 jwt_trust 段，等于静默关闭强制校验；
//   - 任一应用策略为 PROTECT 而 API 动态管线未启用或模式非 PROTECT 时拒绝发布
//     （防止外层 OBSERVE 把 JWT 强制静默降级）；
//   - 存在 PROTECT 策略而身份指纹密钥（gateway_runtime.identity_salt，网关复用为
//     JWT 可信主体指纹密钥）未配置时拒绝发布并给出可读原因——与网关
//     jwtverify.NewVerifier 对 PROTECT 空密钥的 fail-closed 拒载相对应
//     （网关侧集成：gateway/modules/jiuzhang_guard/jwt_trust.go）；
//   - jwtTrustNodeGuard 注入时：存在已知同步失败的目标扇出节点拒绝发布 PROTECT 策略。
package guardconfig

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// JWTTrustLister JWT 信任策略读取接口（由 jwttrust.Store 实现——
// 返回按应用编码组织的网关下发契约，含策略版本与 issuer 配置 ID/keyset 版本标识）。
type JWTTrustLister interface {
	ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardJWTTrustPolicy, error)
}

// JWTTrustNodeGuard 节点发布门禁（装配层以 jwttrust.NodePublishGuard 注入；
// protectApps 为本次发布中 PROTECT 策略的应用编码列表；nil 时跳过节点检查）。
type JWTTrustNodeGuard func(ctx context.Context, protectApps []string) error

// SetJWTTrustLister 注入 JWT 信任策略读取（nil 时不下发 jwt_trust 段）。
func (p *Provider) SetJWTTrustLister(l JWTTrustLister) { p.jwtTrust = l }

// SetJWTTrustNodeGuard 注入节点发布门禁（nil 时仅执行管线模式门禁）。
func (p *Provider) SetJWTTrustNodeGuard(g JWTTrustNodeGuard) { p.jwtTrustNodeGuard = g }

// loadJWTTrust 读取 JWT 信任策略并填充 jwt_trust 段（仅 WDSP 开启时调用）。
// apiMode 为本次发布解析后的 API 动态管线有效模式（settings 覆盖已生效）。
// 返回错误即中止发布（拒绝发布并给出可读原因，旧有效版本保留）。
func (p *Provider) loadJWTTrust(ctx context.Context, cfg *gatewayconfig.GuardConfig, apiMode string) error {
	if p.jwtTrust == nil {
		return nil
	}
	policies, err := p.jwtTrust.ListForGuard(ctx)
	if err != nil {
		return fmt.Errorf("list jwt trust policies: %w", err)
	}
	if len(policies) == 0 {
		return nil
	}
	// PROTECT 发布前置校验：API 动态管线必须为 PROTECT（本函数仅在 apiEnabled=true
	// 分支内调用，enabled 条件已由外层保证），防外层 OBSERVE 静默降级 JWT 强制
	protectApps := []string{}
	for code, pol := range policies {
		if pol != nil && pol.Mode == "PROTECT" {
			protectApps = append(protectApps, code)
		}
	}
	if len(protectApps) > 0 {
		sort.Strings(protectApps)
		if apiMode != "PROTECT" {
			return fmt.Errorf(
				"应用 %v 的 JWT 信任策略为 PROTECT，但 API 动态管线模式为 %s，发布会把强制校验静默降级为观测，拒绝发布",
				protectApps, apiMode)
		}
		// 身份指纹密钥门禁（任务书 §5.1/§7）：身份指纹密钥（gateway_runtime 组
		// identity_salt，网关复用为 JWT 可信主体指纹密钥）未配置时，网关侧对
		// PROTECT 策略 fail-closed 拒绝加载——发布侧同步拒绝并给出可读原因，
		// 避免发布一个网关必然拒载的配置
		if err := checkJWTTrustSecret(cfg, protectApps); err != nil {
			return err
		}
		if p.jwtTrustNodeGuard != nil {
			if err := p.jwtTrustNodeGuard(ctx, protectApps); err != nil {
				return err
			}
		}
	}
	cfg.JWTTrust = policies
	return nil
}

// checkJWTTrustSecret 身份指纹密钥门禁：存在 PROTECT 策略而身份指纹密钥未配置
// （空串或快照脱敏占位均视同未配置）时拒绝发布并给出可读原因。
// 供 loadJWTTrust（正常发布）与 replayRuntimeSecrets（回滚重放）共用同一口径。
func checkJWTTrustSecret(cfg *gatewayconfig.GuardConfig, protectApps []string) error {
	if strings.TrimSpace(cfg.IdentitySalt) == "" || cfg.IdentitySalt == redactPlaceholder {
		return fmt.Errorf(
			"应用 %v 的 JWT 信任策略为 PROTECT，但身份指纹密钥（gateway_runtime.identity_salt）未配置："+
				"网关对该策略 fail-closed 拒绝加载，拒绝发布；请先在系统设置配置 identity_salt",
			protectApps)
	}
	return nil
}
