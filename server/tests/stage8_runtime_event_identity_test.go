// stage8_runtime_event_identity_test.go 运行时事件身份字段（WDSP 身份微模型第一批，服务端持久化）。
// 覆盖：迁移 000029 两列与部分索引落位；SavePrimary 写入 identity_fingerprint/auth_type
// 且 request_id 幂等重放不覆盖；读取接口带出两字段并支持 identity_fingerprint 精确过滤
// （空串不过滤；匿名事件身份字段为空串，见 docs/API_MICRO_MODELS.md §2.2 边界规则）。
package tests

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// TestStage8RuntimeEventIdentity 身份字段写入/读取/按身份过滤端到端验证。
func TestStage8RuntimeEventIdentity(t *testing.T) {
	env := setupStage8Env(t)
	cookies, _ := env.s5Login(t, "s8id", "SECURITY_ADMIN")
	ctx := context.Background()

	// 迁移落位：两列存在；身份部分索引存在（匿名空串不占索引；000242 将 000029 的单列部分索引升级为复合部分索引 idx_api_runtime_events_identity_occurred）
	if n := s8Count(t, env, `
SELECT count(*) FROM information_schema.columns
WHERE table_name='api_runtime_events' AND column_name IN ('identity_fingerprint','auth_type')`); n != 2 {
		t.Fatalf("identity columns = %d, want 2", n)
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM pg_indexes
WHERE tablename='api_runtime_events' AND indexname='idx_api_runtime_events_identity_occurred'`); n != 1 {
		t.Fatalf("idx_api_runtime_events_identity_occurred index missing")
	}

	// 写入：两条带身份（api_key / bearer_or_basic）+ 一条匿名（空串）
	rid := s5Rand()
	epKey := "GET /s8" + rid + "/orders/{id}"
	rt := apiruntime.NewStore(env.db)
	mk := func(reqID, fp, authType string) *apiruntime.PrimaryEvent {
		return &apiruntime.PrimaryEvent{
			PrimaryEvent: events.PrimaryEvent{
				RequestID: reqID, EndpointKey: epKey,
				RiskScore: 90, RiskLevel: "HIGH", FinalAction: "BLOCK",
				OccurredAt: time.Now().UTC(),
			},
			IdentityFingerprint: fp,
			AuthType:            authType,
		}
	}
	if err := rt.SavePrimary(ctx, mk("req-id-"+rid+"-1", "fp-"+rid+"-a", "api_key")); err != nil {
		t.Fatalf("SavePrimary authed: %v", err)
	}
	if err := rt.SavePrimary(ctx, mk("req-id-"+rid+"-2", "fp-"+rid+"-b", "bearer_or_basic")); err != nil {
		t.Fatalf("SavePrimary bearer: %v", err)
	}
	if err := rt.SavePrimary(ctx, mk("req-id-"+rid+"-3", "", "")); err != nil {
		t.Fatalf("SavePrimary anonymous: %v", err)
	}
	// request_id 幂等重放：不同身份不生成新行、不覆盖原身份
	if err := rt.SavePrimary(ctx, mk("req-id-"+rid+"-1", "fp-other", "cookie_session")); err != nil {
		t.Fatalf("SavePrimary replay: %v", err)
	}

	var fp, at string
	if err := env.db.QueryRow(ctx,
		`SELECT identity_fingerprint, auth_type FROM api_runtime_events WHERE request_id=$1`,
		"req-id-"+rid+"-1").Scan(&fp, &at); err != nil {
		t.Fatal(err)
	}
	if fp != "fp-"+rid+"-a" || at != "api_key" {
		t.Errorf("persisted identity = %q/%q, want fp-%s-a/api_key", fp, at, rid)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_runtime_events WHERE request_id=$1`,
		"req-id-"+rid+"-1"); n != 1 {
		t.Errorf("replayed request_id rows = %d, want 1 (idempotent)", n)
	}

	// Store.List（/api/v1/api-runtime-events 数据源）map 输出带身份字段
	list, _, err := rt.List(ctx, 1, 100)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, item := range list {
		if item["request_id"] == "req-id-"+rid+"-2" {
			found = true
			if item["identity_fingerprint"] != "fp-"+rid+"-b" || item["auth_type"] != "bearer_or_basic" {
				t.Errorf("List identity = %v/%v", item["identity_fingerprint"], item["auth_type"])
			}
		}
	}
	if !found {
		t.Errorf("List missing seeded event req-id-%s-2", rid)
	}

	// 查询接口：响应带出身份字段；identity_fingerprint 精确过滤
	page := s8Page(t, env.get(t,
		"/api/v1/api-security/runtime/events?identity_fingerprint=fp-"+rid+"-a", cookies), "events by identity")
	if page.Data.Total != 1 {
		t.Fatalf("events by identity total = %d, want 1", page.Data.Total)
	}
	item := page.Data.Items[0]
	if item["identity_fingerprint"] != "fp-"+rid+"-a" || item["auth_type"] != "api_key" {
		t.Errorf("event identity fields = %v/%v", item["identity_fingerprint"], item["auth_type"])
	}

	// 未命中指纹 → 空集
	page = s8Page(t, env.get(t,
		"/api/v1/api-security/runtime/events?identity_fingerprint=fp-nonexistent", cookies), "events identity miss")
	if page.Data.Total != 0 {
		t.Errorf("identity miss total = %d, want 0", page.Data.Total)
	}

	// 空串不过滤：按 endpoint_key 取回本组 3 条，匿名行身份字段为空串
	page = s8Page(t, env.get(t,
		"/api/v1/api-security/runtime/events?endpoint_key="+url.QueryEscape(epKey), cookies), "events by endpoint")
	if page.Data.Total != 3 {
		t.Fatalf("events by endpoint total = %d, want 3", page.Data.Total)
	}
	anonSeen := false
	for _, it := range page.Data.Items {
		if it["request_id"] == "req-id-"+rid+"-3" {
			anonSeen = true
			if it["identity_fingerprint"] != "" || it["auth_type"] != "" {
				t.Errorf("anonymous identity = %v/%v, want empty", it["identity_fingerprint"], it["auth_type"])
			}
		}
	}
	if !anonSeen {
		t.Errorf("anonymous event req-id-%s-3 not returned", rid)
	}

	// 权限底线：未登录访问仍 401（身份过滤参数不削弱既有鉴权）
	resp := env.do(t, http.MethodGet,
		"/api/v1/api-security/runtime/events?identity_fingerprint=fp-"+rid+"-a", "", nil, "")
	s5Expect(t, resp, http.StatusUnauthorized, "unauthenticated events query")
}
