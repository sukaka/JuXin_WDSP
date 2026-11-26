// client_side.go 客户端供应链安全策略下发（Phase 9B）：
//   - client_side_policies + 已授权/已封禁 client_script_inventory → GuardConfig.ClientSidePolicy（key=应用编码）；
//   - 读取失败中止发布（fail-hard，与 jwt_trust / bot_policy / ai_crawl 同口径）；
//   - 无任何秘密材料，纳入 api_policy_version 版本戳计算。
package guardconfig

import (
	"context"
	"fmt"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// ClientSideLister 客户端供应链安全策略读取接口（由 clientside.Store 实现）。
type ClientSideLister interface {
	ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardClientSidePolicy, error)
}

// SetClientSideLister 注入客户端供应链安全策略读取（nil 时不下发 client_side_policy 段）。
func (p *Provider) SetClientSideLister(l ClientSideLister) { p.clientSide = l }

// loadClientSidePolicy 读取客户端供应链安全策略并填充 client_side_policy 段（仅 WDSP 开启时调用）。
// 读取失败中止发布（fail-hard）；无配置记录/未注入 lister 时不下发该段，网关零行为变化。
func (p *Provider) loadClientSidePolicy(ctx context.Context, cfg *gatewayconfig.GuardConfig) error {
	if p.clientSide == nil {
		return nil
	}
	policies, err := p.clientSide.ListForGuard(ctx)
	if err != nil {
		return fmt.Errorf("list client side policies: %w", err)
	}
	if len(policies) == 0 {
		return nil
	}
	cfg.ClientSidePolicy = policies
	return nil
}
