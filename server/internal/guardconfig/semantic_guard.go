// semantic_guard.go 本地离线 ONNX/SLM 语义防火墙策略下发（Phase 9C-2）：
//   - semantic_guard_policies → GuardConfig.SemanticGuardPolicy（key=应用编码）；
//   - 读取失败中止发布（fail-hard，与 jwt_trust / bot_policy / ai_crawl / client_side / api_a2a 同口径）；
//   - 无任何秘密材料，纳入 api_policy_version 版本戳计算。
package guardconfig

import (
	"context"
	"fmt"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// SemanticGuardLister 本地离线语义防火墙策略读取接口（由 semanticguard.Store 实现）。
type SemanticGuardLister interface {
	ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardSemanticGuardPolicy, error)
}

// SetSemanticGuardLister 注入本地语义防火墙策略读取（nil 时不下发 semantic_guard_policy 段）。
func (p *Provider) SetSemanticGuardLister(l SemanticGuardLister) { p.semanticGuard = l }

// loadSemanticGuardPolicy 读取本地语义防火墙策略并填充 semantic_guard_policy 段（仅 WDSP 开启时调用）。
// 读取失败中止发布（fail-hard）；无配置记录/未注入 lister 时不下发该段，网关零行为变化。
func (p *Provider) loadSemanticGuardPolicy(ctx context.Context, cfg *gatewayconfig.GuardConfig) error {
	if p.semanticGuard == nil {
		return nil
	}
	policies, err := p.semanticGuard.ListForGuard(ctx)
	if err != nil {
		return fmt.Errorf("list semantic guard policies: %w", err)
	}
	if len(policies) == 0 {
		return nil
	}
	cfg.SemanticGuardPolicy = policies
	return nil
}
