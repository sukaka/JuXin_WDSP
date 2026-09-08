// identity_behavior.go 侦察/枚举行为检测策略下发（WDSP AI 自动化渗透防护增强 阶段1）：
// security_behavior_policy 表 GLOBAL 行 → identity_behavior 段随发布通道下发网关
// （表由迁移 000098 建立；读取失败 Warn 跳过，与 MaskRuleStore 同一模式——增量能力，
// 缺失时保持发布通道既有行为，网关无策略下发时行为检测零行为，与历史版本一致）。
package guardconfig

import (
	"context"
	"log/slog"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// BehaviorPolicyLister 行为策略读取接口（由 behaviorpolicy.Store 实现——
// GetGuardBehaviorPolicy 返回网关下发契约，policy_version 为策略 version 字符串）。
type BehaviorPolicyLister interface {
	GetGuardBehaviorPolicy(ctx context.Context) (*gatewayconfig.GuardIdentityBehavior, error)
}

// SetBehaviorPolicyLister 注入行为策略读取（nil 时不下发 identity_behavior 段）。
func (p *Provider) SetBehaviorPolicyLister(l BehaviorPolicyLister) { p.behaviorPolicy = l }

// loadIdentityBehavior 读取行为策略并填充 identity_behavior 段与身份事件日志路径；
// 查询失败（如迁移 000098 尚未应用）Warn 并跳过，不阻断发布主流程。
// enabled=false 时同样下发（网关按 enabled:false 行为检测零行为），
// identity_events_log 随策略段一并下发（网关事件落点，跨分片契约）。
func (p *Provider) loadIdentityBehavior(ctx context.Context, cfg *gatewayconfig.GuardConfig) {
	if p.behaviorPolicy == nil {
		return
	}
	pol, err := p.behaviorPolicy.GetGuardBehaviorPolicy(ctx)
	if err != nil {
		slog.Warn("get security behavior policy failed, skip identity_behavior", "error", err)
		return
	}
	if pol == nil {
		return
	}
	cfg.IdentityBehavior = pol
	cfg.IdentityEventsLog = p.identityEventsLog
}
