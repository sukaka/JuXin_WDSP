package behaviorstore

import (
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
	"go.uber.org/zap"
)

func TestGroupRateRealValkey(t *testing.T) {
	addr := objectEnumerationValkey(t)
	newClient := func() counters.ValkeyClient {
		cli, err := counters.NewValkeyClient(counters.ValkeyConfig{Address: addr})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cli.Close() })
		return cli
	}
	prefix := "test:grouprate:" + counters.HashParts(t.Name(), time.Now().String())
	clk := &testClock{now: baseTime}
	nodeA := New(newClient(), prefix, 0, zap.NewNop())
	nodeB := New(newClient(), prefix, 0, zap.NewNop())
	nodeA.now, nodeB.now = clk.Now, clk.Now
	const app = "app-group-real-secret"
	const limit = 3

	for hit := 1; hit <= limit+1; hit++ {
		node := nodeA
		if hit%2 == 0 {
			node = nodeB
		}
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		ctx.BindDetectorStoreOverrides(node.Overrides())
		detectors.CheckGroupRate(ctx, app, "order_query", limit)
		matches := ctx.CopyMatches()
		if hit <= limit {
			if len(matches) != 0 {
				t.Fatalf("hit %d at/below limit must not match: %+v", hit, matches)
			}
			continue
		}
		if len(matches) != 1 || matches[0].RuleID != "ratelimit.group_rate" || matches[0].Evidence["window_count"] != "4" || matches[0].Evidence["group_code"] != "ORDER_QUERY" {
			t.Fatalf("cross-node group rate must exceed at hit four: %+v", matches)
		}
		if _, ok := matches[0].Evidence["application_id"]; ok {
			t.Fatalf("application id must not enter evidence: %+v", matches[0].Evidence)
		}
	}

	clk.Advance(time.Minute)
	count, history := nodeA.Overrides().GroupRateWindow.AddAndCount(app + "|ORDER_QUERY")
	if count != 1 || len(history) != 1 || history[0] != limit+1 {
		t.Fatalf("real Valkey natural minute roll: count=%d history=%v", count, history)
	}
}
