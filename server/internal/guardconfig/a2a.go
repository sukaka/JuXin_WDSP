// a2a.go A2A 协议安全策略下发（Phase 9C-1）：
//   - api_a2a_policies → GuardConfig.APIA2APolicy（key=应用编码）；
//   - 读取失败中止发布（fail-hard，与 jwt_trust / bot_policy / ai_crawl / client_side 同口径）；
//   - 无任何秘密材料，纳入 api_policy_version 版本戳计算。
package guardconfig

import (
	"context"
	"fmt"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// A2ALister A2A 协议安全策略读取接口（由 apia2a.Store 实现）。
type A2ALister interface {
	ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardA2APolicy, error)
}

// SetA2ALister 注入 A2A 协议安全策略读取（nil 时不下发 api_a2a_policy 段）。
func (p *Provider) SetA2ALister(l A2ALister) { p.a2a = l }

// loadA2APolicy 读取 A2A 协议安全策略并填充 api_a2a_policy 段（仅 WDSP 开启时调用）。
// 读取失败中止发布（fail-hard）；无配置记录/未注入 lister 时不下发该段，网关零行为变化。
func (p *Provider) loadA2APolicy(ctx context.Context, cfg *gatewayconfig.GuardConfig) error {
	if p.a2a == nil {
		return nil
	}
	policies, err := p.a2a.ListForGuard(ctx)
	if err != nil {
		return fmt.Errorf("list a2a policies: %w", err)
	}
	if len(policies) == 0 {
		return nil
	}
	cfg.APIA2APolicy = policies
	return nil
}
