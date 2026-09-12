package detectors

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// resetEnvAnomalyForTest 重置同凭据环境异常追踪器（滑窗用 fakeClock 保证确定性）。
func resetEnvAnomalyForTest(clk *fakeClock) {
	defaultIPSpreadTracker = newIPSpreadTracker(envAnomalyMaxKeys, clk.Now)
	defaultCredentialConcurrency = &credentialConcurrencyTracker{entries: newLRU(envAnomalyMaxKeys)}
}

// credSpreadRequest 构造携带凭据与来源地址的请求（RemoteAddr 模拟 guard 入口改写后的真实客户端 IP）。
func credSpreadRequest(token, remoteAddr string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.RemoteAddr = remoteAddr
	return r
}

// 跨 IP 跳变：滑窗 distinct IP 达到阈值（默认 3）→ OBSERVE/MEDIUM，ScoreDelta 15。
func TestAuthCredentialIPSpread_ThresholdHit(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetEnvAnomalyForTest(clk)
	const salt = "test-salt"
	r := credSpreadRequest("spread-token-1", "")
	credKey := CredentialKey(r, salt)
	if credKey == "" {
		t.Fatal("credential key must not be empty")
	}
	ips := []string{"203.0.113.1:1001", "203.0.113.2:1002", "203.0.113.3:1003"}
	for i, addr := range ips {
		ctx := authTestCtx()
		r.RemoteAddr = addr
		CheckCredentialIPSpread(ctx, r, credKey, salt, 0) // 0 → 默认阈值 3
		m := findMatch(ctx, "auth.credential_ip_spread")
		if i < 2 && m != nil {
			t.Fatalf("distinct %d below threshold must not match", i+1)
		}
		if i == 2 {
			if m == nil {
				t.Fatalf("distinct 3 at threshold must match, got %+v", ctx.CopyMatches())
			}
			if m.Category != "OBSERVE" || m.Severity != "MEDIUM" || m.ScoreDelta != 15 {
				t.Fatalf("bad attrs: %+v", m)
			}
			if m.Evidence["distinct_ips"] != "3" || m.Evidence["window"] != "1m" {
				t.Fatalf("bad evidence: %+v", m.Evidence)
			}
			// 证据不得含任何 IP（明文或指纹），只允许 distinct 数与窗口
			if len(m.Evidence) != 2 {
				t.Fatalf("evidence must only carry distinct count and window: %+v", m.Evidence)
			}
			for _, v := range m.Evidence {
				for _, addr := range ips {
					ip := strings.Split(addr, ":")[0]
					if strings.Contains(v, ip) || strings.Contains(v, Fingerprint(salt, ip)) {
						t.Fatalf("ip leaked into evidence: %+v", m.Evidence)
					}
				}
			}
		}
	}
}

// 负例：未达阈值不报；同 IP 重复访问去重（distinct 不增长）。
func TestAuthCredentialIPSpread_BelowThreshold(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetEnvAnomalyForTest(clk)
	const salt = "test-salt"
	credKey := CredentialKey(credSpreadRequest("spread-token-2", ""), salt)
	for _, addr := range []string{"203.0.113.10:1", "203.0.113.10:2", "203.0.113.11:1"} {
		ctx := authTestCtx()
		CheckCredentialIPSpread(ctx, credSpreadRequest("spread-token-2", addr), credKey, salt, 0)
		if ctx.MatchCount() != 0 {
			t.Fatalf("distinct 2 below threshold 3 must not match, got %+v", ctx.CopyMatches())
		}
	}
}

// 负例：匿名流量（credKey 为空）直接跳过，不产生 match 也不入追踪器。
func TestAuthCredentialIPSpread_AnonymousSkipped(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetEnvAnomalyForTest(clk)
	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil) // 无凭据
	r.RemoteAddr = "203.0.113.20:9000"
	if k := CredentialKey(r, "s"); k != "" {
		t.Fatalf("anonymous credential key must be empty, got %q", k)
	}
	for i := 0; i < 5; i++ {
		ctx := authTestCtx()
		r.RemoteAddr = "203.0.113.2" + strconv.Itoa(i) + ":9000"
		CheckCredentialIPSpread(ctx, r, CredentialKey(r, "s"), "s", 0)
		if ctx.MatchCount() != 0 {
			t.Fatalf("anonymous traffic must not match, got %+v", ctx.CopyMatches())
		}
	}
	if defaultIPSpreadTracker.entries.ll.Len() != 0 {
		t.Fatal("anonymous traffic must not populate spread tracker")
	}
}

// 窗口滚动：跨自然分钟后 distinct 集合重置（fakeClock 确定性）。
func TestAuthCredentialIPSpread_WindowRolls(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetEnvAnomalyForTest(clk)
	const salt = "test-salt"
	credKey := CredentialKey(credSpreadRequest("spread-token-3", ""), salt)
	for _, addr := range []string{"203.0.113.30:1", "203.0.113.31:1"} {
		CheckCredentialIPSpread(authTestCtx(), credSpreadRequest("spread-token-3", addr), credKey, salt, 0)
	}
	clk.Advance(time.Minute) // 新窗口：distinct 重置
	ctx := authTestCtx()
	CheckCredentialIPSpread(ctx, credSpreadRequest("spread-token-3", "203.0.113.32:1"), credKey, salt, 0)
	if ctx.MatchCount() != 0 {
		t.Fatalf("new window distinct 1 must not match, got %+v", ctx.CopyMatches())
	}
}

// 无来源地址（RemoteAddr 空）跳过：无环境事实不入集合。
func TestAuthCredentialIPSpread_NoRemoteAddrSkipped(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetEnvAnomalyForTest(clk)
	credKey := CredentialKey(credSpreadRequest("spread-token-4", ""), "s")
	r := credSpreadRequest("spread-token-4", "")
	r.RemoteAddr = ""
	ctx := authTestCtx()
	CheckCredentialIPSpread(ctx, r, credKey, "s", 0)
	if ctx.MatchCount() != 0 {
		t.Fatalf("empty remote addr must not match, got %+v", ctx.CopyMatches())
	}
	if defaultIPSpreadTracker.entries.ll.Len() != 0 {
		t.Fatal("empty remote addr must not populate spread tracker")
	}
}

// 并发度：in-flight 达到阈值（默认 8）→ OBSERVE/LOW，ScoreDelta 10；释放后回落不报。
func TestAuthCredentialConcurrency_ThresholdHitAndRelease(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetEnvAnomalyForTest(clk)
	const credKey = "auth:concurrency-token-1"
	releases := make([]func(), 0, 8)
	for i := 1; i <= 8; i++ {
		n, release := AcquireCredentialInFlight(credKey)
		if n != i {
			t.Fatalf("acquire %d: current=%d", i, n)
		}
		releases = append(releases, release)
		ctx := authTestCtx()
		CheckCredentialConcurrency(ctx, credKey, 0) // 0 → 默认阈值 8
		m := findMatch(ctx, "auth.credential_concurrency")
		if i < 8 && m != nil {
			t.Fatalf("inflight %d below threshold must not match", i)
		}
		if i == 8 {
			if m == nil {
				t.Fatal("inflight 8 at threshold must match")
			}
			if m.Category != "OBSERVE" || m.Severity != "LOW" || m.ScoreDelta != 10 {
				t.Fatalf("bad attrs: %+v", m)
			}
			if m.Evidence["inflight"] != "8" || m.Evidence["threshold"] != "8" {
				t.Fatalf("bad evidence: %+v", m.Evidence)
			}
		}
	}
	// 释放一个 → 回落到 7，低于阈值不报
	releases[7]()
	ctx := authTestCtx()
	CheckCredentialConcurrency(ctx, credKey, 0)
	if ctx.MatchCount() != 0 {
		t.Fatalf("inflight 7 after release must not match, got %+v", ctx.CopyMatches())
	}
	// 释放函数幂等：重复调用不击穿计数
	releases[7]()
	if n := defaultCredentialConcurrency.current(credKey); n != 7 {
		t.Fatalf("release must be idempotent, current=%d", n)
	}
	for _, rel := range releases[:7] {
		rel()
	}
	if n := defaultCredentialConcurrency.current(credKey); n != 0 {
		t.Fatalf("all released, current=%d", n)
	}
}

// 负例：匿名不跟踪（Acquire 返回 0 与空释放），自定义阈值生效。
func TestAuthCredentialConcurrency_AnonymousAndCustomLimit(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	resetEnvAnomalyForTest(clk)
	n, release := AcquireCredentialInFlight("")
	if n != 0 {
		t.Fatalf("anonymous acquire must return 0, got %d", n)
	}
	release() // 空释放必须无害
	if defaultCredentialConcurrency.entries.ll.Len() != 0 {
		t.Fatal("anonymous traffic must not populate concurrency tracker")
	}
	// 匿名直接跳 Check 也不报
	ctx := authTestCtx()
	CheckCredentialConcurrency(ctx, "", 0)
	if ctx.MatchCount() != 0 {
		t.Fatalf("anonymous must not match, got %+v", ctx.CopyMatches())
	}
	// 自定义阈值 2：第 2 个并发即命中
	const credKey = "auth:concurrency-token-2"
	r1, rel1 := AcquireCredentialInFlight(credKey)
	defer rel1()
	r2, rel2 := AcquireCredentialInFlight(credKey)
	defer rel2()
	if r1 != 1 || r2 != 2 {
		t.Fatalf("acquire counts: %d, %d", r1, r2)
	}
	ctx2 := authTestCtx()
	CheckCredentialConcurrency(ctx2, credKey, 2)
	m := findMatch(ctx2, "auth.credential_concurrency")
	if m == nil || m.Evidence["inflight"] != "2" || m.Evidence["threshold"] != "2" {
		t.Fatalf("custom limit 2 must match at inflight 2, got %+v", ctx2.CopyMatches())
	}
}
