package behaviorstore

import (
	"sync"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
	"go.uber.org/zap"
)

func TestQuotaRealValkey(t *testing.T) {
	addr := objectEnumerationValkey(t)
	newClient := func() counters.ValkeyClient {
		cli, err := counters.NewValkeyClient(counters.ValkeyConfig{Address: addr})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cli.Close() })
		return cli
	}
	prefix := "test:quota:" + counters.HashParts(t.Name(), time.Now().String())

	t.Run("shared detectors and window reset", func(t *testing.T) {
		clk := &testClock{now: baseTime}
		nodeA := New(newClient(), prefix+"-shared", 0, zap.NewNop())
		nodeB := New(newClient(), prefix+"-shared", 0, zap.NewNop())
		nodeA.now, nodeB.now = clk.Now, clk.Now
		const identity, endpoint = "auth:real-quota-fingerprint", "GET /v1/orders"
		key := identity + "|" + endpoint
		const limit = 3
		for hit := 1; hit <= limit+1; hit++ {
			node := nodeA
			if hit%2 == 0 {
				node = nodeB
			}
			ctx := dsctx.New("t", dsctx.DefaultParseLimits())
			ctx.BindDetectorStoreOverrides(node.Overrides())
			detectors.CheckAPIHourlyQuota(ctx, identity, endpoint, limit)
			detectors.CheckAPIDailyQuota(ctx, identity, endpoint, limit)
			matches := ctx.CopyMatches()
			if hit <= limit {
				if len(matches) != 0 {
					t.Fatalf("hit %d at/below limit must not match: %+v", hit, matches)
				}
				continue
			}
			if len(matches) != 2 {
				t.Fatalf("cross-node hourly and daily quotas must both exceed: %+v", matches)
			}
			seen := map[string]bool{}
			for _, match := range matches {
				seen[match.RuleID] = match.Evidence["window_count"] == "4"
			}
			if !seen["ratelimit.api_hourly_quota"] || !seen["ratelimit.api_daily_quota"] {
				t.Fatalf("unexpected cross-node quota matches: %+v", matches)
			}
		}

		clk.Advance(time.Hour)
		if count := nodeA.Overrides().HourlyQuota.AddAndCount(key); count != 1 {
			t.Fatalf("real Valkey hour rollover must reset hourly quota: %d", count)
		}
		if count := nodeA.Overrides().DailyQuota.AddAndCount(key); count != limit+2 {
			t.Fatalf("real Valkey hour rollover must retain daily quota: %d", count)
		}
		clk.Advance(24 * time.Hour)
		if count := nodeB.Overrides().DailyQuota.AddAndCount(key); count != 1 {
			t.Fatalf("real Valkey UTC day rollover must reset daily quota: %d", count)
		}
	})

	t.Run("atomic concurrent counts", func(t *testing.T) {
		nodeA := New(newClient(), prefix+"-concurrent", 0, zap.NewNop())
		nodeB := New(newClient(), prefix+"-concurrent", 0, zap.NewNop())
		a := nodeA.Overrides()
		b := nodeB.Overrides()
		const workers = 64
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				stores := a
				if i%2 == 1 {
					stores = b
				}
				stores.HourlyQuota.AddAndCount(quotaTestRawMaterial)
				stores.DailyQuota.AddAndCount(quotaTestRawMaterial)
			}(i)
		}
		wg.Wait()
		if count := a.HourlyQuota.AddAndCount(quotaTestRawMaterial); count != workers+1 {
			t.Fatalf("real atomic hourly count=%d want=%d", count, workers+1)
		}
		if count := a.DailyQuota.AddAndCount(quotaTestRawMaterial); count != workers+1 {
			t.Fatalf("real atomic daily count=%d want=%d", count, workers+1)
		}
	})
}
