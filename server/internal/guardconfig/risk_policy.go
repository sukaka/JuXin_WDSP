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

// SetRiskPolicyLister 注入风险策略读取（nil 时不下发 risk_policy 段）。
func (p *Provider) SetRiskPolicyLister(l RiskPolicyLister) { p.riskPolicy = l }

// loadRiskPolicy 读取风险策略并填充 risk_policy 段；
// 查询失败（如迁移 000101 尚未应用）Warn 并跳过，不阻断发布主流程。
// enabled=false 时同样下发（网关按 enabled:false 风险处置零行为）。
func (p *Provider) loadRiskPolicy(ctx context.Context, cfg *gatewayconfig.GuardConfig) {
	if p.riskPolicy == nil {
		return
	}
	pol, err := p.riskPolicy.GetGuardRiskPolicy(ctx)
	if err != nil {
		slog.Warn("get security risk policy failed, skip risk_policy", "error", err)
		return
	}
	if pol == nil {
		return
	}
	cfg.RiskPolicy = pol
}
