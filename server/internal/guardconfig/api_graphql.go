// api_graphql.go GraphQL 成本预算策略下发（NG-GQL-03）：api_graphql_policies 表
// enabled=true 的应用行 → GuardConfig.api_graphql（key=application_id）随发布通道下发
// 网关（表由迁移 000171 建立；仅 WDSP 开启（APIDynamicProtection）时下发，回滚覆盖
// 快照经 stripAPIGuardSections 剥除——与 API 动态防护其余段同一门控口径；内容纳入
// api_policy_version 版本戳）。
// 纪律（与 api_admission 同一口径）：读取失败中止发布（fail-hard）——静默跳过会让
// 已启用成本预算的应用在新配置中丢失 api_graphql 段，等于静默关闭预算拦截；
// 无启用应用时不下发该段（nil map = 网关 GraphQL 判定零行为变化）。
package guardconfig

import (
	"context"
	"fmt"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// APIGraphQLLister GraphQL 策略读取接口（由 *apigql.PGStore 实现——
// 返回按 application_id 组织的网关下发契约）。
type APIGraphQLLister interface {
	ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardGraphQLPolicy, error)
}

// SetAPIGraphQLLister 注入 GraphQL 策略读取（nil 时不下发 api_graphql 段）。
func (p *Provider) SetAPIGraphQLLister(l APIGraphQLLister) { p.apiGraphQL = l }

// loadAPIGraphQL 读取 GraphQL 策略并填充 api_graphql 段（仅 WDSP 开启时调用）。
// 返回错误即中止发布（fail-hard，与 loadAPIAdmission 同一纪律）。
func (p *Provider) loadAPIGraphQL(ctx context.Context, cfg *gatewayconfig.GuardConfig) error {
	if p.apiGraphQL == nil {
		return nil
	}
	policies, err := p.apiGraphQL.ListForGuard(ctx)
	if err != nil {
		return fmt.Errorf("list api graphql policies: %w", err)
	}
	if len(policies) == 0 {
		return nil
	}
	cfg.APIGraphQL = policies
	return nil
}
