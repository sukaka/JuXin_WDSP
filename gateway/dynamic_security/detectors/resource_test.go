package detectors

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func resetObjectTrackerForTest() {
	defaultObjectTracker = &objectTracker{entries: newLRU(objectTrackerMaxKeys)}
}

func TestResource_UnauthenticatedObjectAccess(t *testing.T) {
	resetObjectTrackerForTest()
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		Method:         "GET",
		RawPath:        "/v1/users/123",
		NormalizedPath: "/v1/users/{id}",
		Headers:        map[string]string{},
	}
	CheckResourceAccess(ctx, p, "ip:192.0.2.1")
	m := findMatch(ctx, "resource.unauthenticated_object_access")
	if m == nil {
		t.Fatalf("expected UNAUTHENTICATED_OBJECT_ACCESS, got %+v", ctx.CopyMatches())
	}
	if m.Category != "OBSERVE" || m.Severity != "MEDIUM" || m.ScoreDelta != 15 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["object_type"] != "numeric" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	if got := ctx.Extensions["api.object_id_type"]; got != "numeric" {
		t.Fatalf("extension api.object_id_type=%v", got)
	}
}

func TestResource_WithCredentialNoMatchButExtension(t *testing.T) {
	// 负例：携带凭据的对象访问不报（仍记录对象类型扩展供学习/关联）
	resetObjectTrackerForTest()
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		Method:         "GET",
		RawPath:        "/v1/users/550e8400-e29b-41d4-a716-446655440000",
		NormalizedPath: "/v1/users/{uuid}",
		Headers:        map[string]string{"authorization": "[redacted]"},
	}
	CheckResourceAccess(ctx, p, "auth:abc")
	if ctx.MatchCount() != 0 {
		t.Fatalf("authenticated object access must not match, got %+v", ctx.CopyMatches())
	}
	if got := ctx.Extensions["api.object_id_type"]; got != "uuid" {
		t.Fatalf("extension api.object_id_type=%v", got)
	}
}

func TestResource_SequentialNumericIDWriteEscalates(t *testing.T) {
	resetObjectTrackerForTest()
	mk := func(idPath string) (*dsctx.RequestContext, *parser.Parsed) {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		p := &parser.Parsed{
			Method:         "PUT",
			RawPath:        "/v1/users/" + idPath,
			NormalizedPath: "/v1/users/{id}",
			Headers:        map[string]string{},
		}
		return ctx, p
	}
	// 第一次：无凭据写对象，仅 OBSERVE
	ctx1, p1 := mk("100")
	CheckResourceAccess(ctx1, p1, "ip:192.0.2.1")
	m1 := findMatch(ctx1, "resource.unauthenticated_object_access")
	if m1 == nil || m1.Category != "OBSERVE" {
		t.Fatalf("first access should be OBSERVE, got %+v", ctx1.CopyMatches())
	}
	// 第二次：连续数字 ID + 写方法 + 无凭据 → 升 BLOCK 类 HIGH
	ctx2, p2 := mk("101")
	CheckResourceAccess(ctx2, p2, "ip:192.0.2.1")
	m2 := findMatch(ctx2, "resource.unauthenticated_object_access")
	if m2 == nil {
		t.Fatalf("expected escalated match, got %+v", ctx2.CopyMatches())
	}
	if m2.Category != "BLOCK" || m2.Severity != "HIGH" || m2.ScoreDelta != 30 {
		t.Fatalf("bad escalated attrs: %+v", m2)
	}
	if m2.Evidence["pattern"] != "sequential_numeric_id" {
		t.Fatalf("bad escalated evidence: %+v", m2.Evidence)
	}
}

func TestResource_NonSequentialIDStaysObserve(t *testing.T) {
	// 负例：非连续数字 ID 不升级
	resetObjectTrackerForTest()
	mk := func(idPath string) (*dsctx.RequestContext, *parser.Parsed) {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		return ctx, &parser.Parsed{
			Method:         "POST",
			RawPath:        "/v1/users/" + idPath,
			NormalizedPath: "/v1/users/{id}",
			Headers:        map[string]string{},
		}
	}
	ctx1, p1 := mk("100")
	CheckResourceAccess(ctx1, p1, "ip:192.0.2.1")
	ctx2, p2 := mk("500")
	CheckResourceAccess(ctx2, p2, "ip:192.0.2.1")
	m2 := findMatch(ctx2, "resource.unauthenticated_object_access")
	if m2 == nil || m2.Category != "OBSERVE" {
		t.Fatalf("non-sequential id must stay OBSERVE, got %+v", ctx2.CopyMatches())
	}
}

func TestResource_NoObjectSegmentNoMatch(t *testing.T) {
	// 负例：无对象段
	resetObjectTrackerForTest()
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		Method:         "GET",
		RawPath:        "/v1/users/list",
		NormalizedPath: "/v1/users/list",
		Headers:        map[string]string{},
	}
	CheckResourceAccess(ctx, p, "ip:192.0.2.1")
	if ctx.MatchCount() != 0 {
		t.Fatalf("no object segment must not match, got %+v", ctx.CopyMatches())
	}
	if _, ok := ctx.Extensions["api.object_id_type"]; ok {
		t.Fatal("extension must not be set without object segment")
	}
}
