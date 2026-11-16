package guardconfig

import (
	"context"
	"fmt"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type IdentityBlockLister interface {
	ListBlockedIdentities(ctx context.Context) ([]gatewayconfig.GuardIdentityBlock, error)
}

func (p *Provider) SetIdentityBlockLister(l IdentityBlockLister) { p.identityBlocks = l }

func (p *Provider) loadAPIIdentityBlocks(ctx context.Context) ([]gatewayconfig.GuardIdentityBlock, error) {
	if p.identityBlocks == nil {
		return nil, nil
	}
	blocks, err := p.identityBlocks.ListBlockedIdentities(ctx)
	if err != nil {
		return nil, fmt.Errorf("list current blocked client identities: %w", err)
	}
	if len(blocks) == 0 {
		return nil, nil
	}
	return blocks, nil
}
