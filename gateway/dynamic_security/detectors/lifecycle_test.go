package detectors

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestLifecycle_NewEndpoint(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	known := map[string]string{"GET /v1/users": "CONFIRMED"}
	CheckLifecycle(ctx, "POST /v1/unknown", known)
	m := findMatch(ctx, "lifecycle.new_endpoint")
	if m == nil {
		t.Fatalf("expected NEW_ENDPOINT, got %+v", ctx.CopyMatches())
	}
	if m.Category != "OBSERVE" || m.Severity != "LOW" || m.ScoreDelta != 5 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["endpoint_key"] != "POST /v1/unknown" || m.Evidence["signal"] != "shadow_candidate" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
}

func TestLifecycle_DeprecatedCall(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	known := map[string]string{"GET /v1/old": "DEPRECATED"}
	CheckLifecycle(ctx, "GET /v1/old", known)
	m := findMatch(ctx, "lifecycle.deprecated_api_call")
	if m == nil {
		t.Fatalf("expected DEPRECATED_API_CALL, got %+v", ctx.CopyMatches())
	}
	if m.Category != "OBSERVE" || m.Severity != "MEDIUM" || m.ScoreDelta != 10 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["asset_status"] != "DEPRECATED" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
}

func TestLifecycle_KnownActiveEndpointNoMatch(t *testing.T) {
	// 负例：已知且活跃的端点不报
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	known := map[string]string{"GET /v1/users": "CONFIRMED", "GET /v1/x": "DISCOVERED"}
	CheckLifecycle(ctx, "GET /v1/users", known)
	CheckLifecycle(ctx, "GET /v1/x", known)
	if ctx.MatchCount() != 0 {
		t.Fatalf("known endpoints must not match, got %+v", ctx.CopyMatches())
	}
}

func TestLifecycle_NilBaselineSkips(t *testing.T) {
	// 负例：未下发基线（nil）时整个检测关闭
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckLifecycle(ctx, "GET /v1/anything", nil)
	if ctx.MatchCount() != 0 {
		t.Fatalf("nil baseline must skip, got %+v", ctx.CopyMatches())
	}
}
