package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeIdentityBlockLister struct {
	blocks []gatewayconfig.GuardIdentityBlock
	err    error
	calls  int
}

func (f *fakeIdentityBlockLister) ListBlockedIdentities(context.Context) ([]gatewayconfig.GuardIdentityBlock, error) {
	f.calls++
	return f.blocks, f.err
}

func TestLoadAPIIdentityBlocks(t *testing.T) {
	provider := &Provider{}
	blocks, err := provider.loadAPIIdentityBlocks(context.Background())
	if err != nil || blocks != nil {
		t.Fatalf("nil lister = %+v, %v", blocks, err)
	}

	lister := &fakeIdentityBlockLister{blocks: []gatewayconfig.GuardIdentityBlock{{ID: "id-1", IdentityKey: "fp-1"}}}
	provider.identityBlocks = lister
	blocks, err = provider.loadAPIIdentityBlocks(context.Background())
	if err != nil || len(blocks) != 1 || blocks[0].IdentityKey != "fp-1" {
		t.Fatalf("blocks = %+v, err=%v", blocks, err)
	}
	lister.blocks = nil
	blocks, err = provider.loadAPIIdentityBlocks(context.Background())
	if err != nil || blocks != nil {
		t.Fatalf("empty current blocks = %+v, %v", blocks, err)
	}
	lister.err = errors.New("db down")
	if _, err := provider.loadAPIIdentityBlocks(context.Background()); err == nil {
		t.Fatal("read failure must abort publish")
	}
}

func TestReplayIdentityBlocksUsesCurrentStateAndVersion(t *testing.T) {
	lister := &fakeIdentityBlockLister{}
	provider := &Provider{identityBlocks: lister}
	cfg := &gatewayconfig.GuardConfig{APIIdentityBlocks: []gatewayconfig.GuardIdentityBlock{{ID: "old", IdentityKey: "old-key"}}}
	if err := provider.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("replay NORMAL current state: %v", err)
	}
	if cfg.APIIdentityBlocks != nil {
		t.Fatalf("NORMAL identity remained blocked after replay: %+v", cfg.APIIdentityBlocks)
	}

	lister.blocks = []gatewayconfig.GuardIdentityBlock{{ID: "new", IdentityKey: "new-key"}}
	if err := provider.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("replay BLOCKED current state: %v", err)
	}
	if len(cfg.APIIdentityBlocks) != 1 || cfg.APIIdentityBlocks[0].ID != "new" {
		t.Fatalf("current blocks not replayed: %+v", cfg.APIIdentityBlocks)
	}
	base := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{})
	withBlock := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIIdentityBlocks: lister.blocks})
	if base == withBlock {
		t.Fatal("identity block list must affect api_policy_version")
	}
}
