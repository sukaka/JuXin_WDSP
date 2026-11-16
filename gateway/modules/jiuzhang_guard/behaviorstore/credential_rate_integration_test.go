package behaviorstore

import (
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
	"go.uber.org/zap"
)

func TestCredentialRateRealValkey(t *testing.T) {
	addr := objectEnumerationValkey(t)
	newClient := func() counters.ValkeyClient {
		cli, err := counters.NewValkeyClient(counters.ValkeyConfig{Address: addr})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cli.Close() })
		return cli
	}
	prefix := "test:credrate:" + counters.HashParts(t.Name(), time.Now().String())
	clk := &testClock{now: baseTime}
	nodeA := New(newClient(), prefix, 0, zap.NewNop())
	nodeB := New(newClient(), prefix, 0, zap.NewNop())
	nodeA.now, nodeB.now = clk.Now, clk.Now
	credKey := credentialRateTestKey(t)

	const limit = 3
	for hit := 1; hit <= limit+1; hit++ {
		node := nodeA
		if hit%2 == 0 {
			node = nodeB
		}
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		ctx.BindDetectorStoreOverrides(node.Overrides())
		detectors.CheckCredentialRate(ctx, credKey, limit)
		matches := ctx.CopyMatches()
		if hit <= limit {
			if len(matches) != 0 {
				t.Fatalf("hit %d at/below limit must not match: %+v", hit, matches)
			}
			continue
		}
		if len(matches) != 1 || matches[0].RuleID != "ratelimit.credential_rate" || matches[0].Evidence["window_count"] != "4" {
			t.Fatalf("cross-node credential rate must exceed at hit four: %+v", matches)
		}
	}

	clk.Advance(time.Minute)
	count, history := nodeA.Overrides().CredentialRateWindow.AddAndCount(credKey)
	if count != 1 || len(history) != 1 || history[0] != limit+1 {
		t.Fatalf("real Valkey natural minute roll: count=%d history=%v", count, history)
	}
}
