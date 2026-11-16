package guardconfig

import (
	"context"
	"fmt"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type APIEndpointActionLister interface {
	ListEndpointActions(ctx context.Context) (map[string]string, error)
}

func (p *Provider) SetAPIEndpointActionsLister(l APIEndpointActionLister) {
	p.apiEndpointActions = l
}

func (p *Provider) loadAPIEndpointActions(ctx context.Context, cfg *gatewayconfig.GuardConfig) error {
	cfg.APIEndpointActions = nil
	if cfg.ActionRatePerMinute <= 0 {
		return nil
	}
	if p.apiEndpointActions == nil {
		return fmt.Errorf("gateway_runtime.action_rate_per_minute 已启用但 ACTION 映射读取器未配置")
	}
	actions, err := p.apiEndpointActions.ListEndpointActions(ctx)
	if err != nil {
		return fmt.Errorf("read api endpoint actions with action_rate_per_minute enabled: %w", err)
	}
	if len(actions) > 0 {
		cfg.APIEndpointActions = actions
	}
	return nil
}
