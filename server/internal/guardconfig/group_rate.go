package guardconfig

import (
	"context"
	"fmt"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type APIEndpointGroupLister interface {
	ListEndpointGroups(ctx context.Context) (map[string]map[string][]string, error)
}

func (p *Provider) SetAPIEndpointGroupsLister(l APIEndpointGroupLister) {
	p.apiEndpointGroups = l
}

func (p *Provider) loadAPIEndpointGroups(ctx context.Context, cfg *gatewayconfig.GuardConfig) error {
	cfg.APIEndpointGroups = nil
	if cfg.GroupRatePerMinute <= 0 {
		return nil
	}
	if p.apiEndpointGroups == nil {
		return fmt.Errorf("gateway_runtime.group_rate_per_minute 已启用但分组映射读取器未配置")
	}
	groups, err := p.apiEndpointGroups.ListEndpointGroups(ctx)
	if err != nil {
		return fmt.Errorf("read api endpoint groups with group_rate_per_minute enabled: %w", err)
	}
	if len(groups) > 0 {
		cfg.APIEndpointGroups = groups
	}
	return nil
}
