package guardconfig

import (
	"context"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type LLMSecurityPolicyLister interface {
	ListEnabledSecurityPolicies(context.Context) ([]gatewayconfig.GuardLLMSecurityPolicy, error)
}

func (p *Provider) SetLLMSecurityPolicyLister(l LLMSecurityPolicyLister) {
	p.llmSecurityPolicies = l
}

func (p *Provider) loadLLMSecurityPolicies(ctx context.Context) ([]gatewayconfig.GuardLLMSecurityPolicy, error) {
	if p.llmSecurityPolicies == nil {
		return nil, nil
	}
	policies, err := p.llmSecurityPolicies.ListEnabledSecurityPolicies(ctx)
	if err != nil {
		if isMissingLegacyTableError(err, "api_llm_security_policies") {
			return nil, nil
		}
		return nil, wrapLegacyLoaderError("api_llm_security_policies", err)
	}
	if len(policies) == 0 {
		return nil, nil
	}
	return policies, nil
}
