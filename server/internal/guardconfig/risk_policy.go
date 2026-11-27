// risk_policy.go 身份风险处置策略下发（WDSP AI 自动化渗透防护增强 阶段3）：
// security_risk_policy 表 GLOBAL 行 → risk_policy 段随发布通道下发网关
// （表由迁移 000101 建立；读取失败 Warn 跳过，与 identity_behavior 同一模式——
// 增量能力，缺失时保持发布通道既有行为，网关无策略下发时风险处置零行为，
// 与历史版本一致；不受 API 动态防护门控——client_identity 体系为全产品形态能力）。
package guardconfig

import (
	"context"
	"log/slog"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// RiskPolicyLister 风险策略读取接口（由 riskpolicy.Store 实现——
// GetGuardRiskPolicy 返回网关下发契约，version 为策略乐观锁版本号）。
type RiskPolicyLister interface {
	GetGuardRiskPolicy(ctx context.Context) (*gatewayconfig.GuardRiskPolicy, error)
}

// RiskPolicyOverrideLister 是可选扩展，旧实现没有该接口时保持原行为。
type RiskPolicyOverrideLister interface {
	ListGuardRiskPolicyOverrides(ctx context.Context) ([]gatewayconfig.GuardRiskPolicyOverride, error)
}

// SetRiskPolicyLister 注入风险策略读取（nil 时不下发 risk_policy 段）。
func (p *Provider) SetRiskPolicyLister(l RiskPolicyLister) { p.riskPolicy = l }

// loadRiskPolicy 读取风险策略并填充 risk_policy 段（兼容旧调用方；BuildGuardConfig 走 Strict）。
func (p *Provider) loadRiskPolicy(ctx context.Context, cfg *gatewayconfig.GuardConfig) {
	if err := p.loadRiskPolicyStrict(ctx, cfg); err != nil {
		slog.Warn("load security risk policy failed, skip risk_policy or overrides", "error", err)
	}
}

// loadRiskPolicyStrict 仅容忍旧库未建表（42P01）；真实数据库错误中止候选发布（fail-hard），
// 防止已启用的身份风险 PROTECT 策略或应用级覆盖在瞬时 DB 故障时被静默清零。
func (p *Provider) loadRiskPolicyStrict(ctx context.Context, cfg *gatewayconfig.GuardConfig) error {
	if p.riskPolicy == nil {
		return nil
	}
	pol, err := p.riskPolicy.GetGuardRiskPolicy(ctx)
	if err != nil {
		if isMissingLegacyTableError(err, "security_risk_policy") {
			slog.Warn("optional legacy table security_risk_policy is unavailable", "error", err)
			return nil
		}
		return wrapLegacyLoaderError("security_risk_policy", err)
	}
	if pol == nil {
		return nil
	}
	cfg.RiskPolicy = pol
	lister, ok := p.riskPolicy.(RiskPolicyOverrideLister)
	if !ok {
		return nil
	}
	overrides, err := lister.ListGuardRiskPolicyOverrides(ctx)
	if err != nil {
		if isMissingLegacyTableError(err, "security_risk_policy_overrides") {
			slog.Warn("optional legacy table security_risk_policy_overrides is unavailable, keep global policy", "error", err)
			return nil
		}
		return wrapLegacyLoaderError("security_risk_policy_overrides", err)
	}
	if len(overrides) > 0 {
		cfg.RiskPolicyOverrides = overrides
	}
	return nil
}
