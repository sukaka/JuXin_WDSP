// handler_test.go LLM 观测 HTTP 入口测试：权限矩阵 / 参数校验 /
// 列表过滤分页 / stats 聚合（内存仓储驱动真实 Handler 与路由）。
package apillm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// injectPrincipal 模拟认证链：注入持有给定权限点集合的主体。
func injectPrincipal(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "w10llm-tester", PermsSet: set}
			ctx := authz.WithPrincipal(r.Context(), p)
			ctx = context.WithValue(ctx, response.RequestIDKey, "w10llm-rid")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// noPrincipal 模拟未注入主体的认证链（权限中间件应 401）。
func noPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// newTestMux 装配 LLM 观测路由（内存仓储）。
func newTestMux(store *MemStore, authzFn func(http.Handler) http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, authzFn, NewHandler(store))
	return mux
}

// do 发请求。
func do(t *testing.T, mux http.Handler, url string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// seedObservations 造数：覆盖模型/端点/命中/流式/窗口外维度。
func seedObservations(store *MemStore) {
	now := time.Now().UTC()
	store.addObservation(Observation{
		ID: uuid.New(), EndpointKey: "POST /v1/chat/completions", Model: "gpt-4o",
		IdentityFingerprint: "auth:u1", PromptLenBucket: "S", TotalTokens: 120,
		OccurredAt: now.Add(-time.Hour), CreatedAt: now.Add(-time.Hour),
		Findings: []dsctx.DetectorMatch{},
	})
	store.addObservation(Observation{
		ID: uuid.New(), EndpointKey: "POST /v1/chat/completions", Model: "claude-3-opus",
		IdentityFingerprint: "auth:u2", PromptLenBucket: "M", TotalTokens: 800, Stream: true,
		OccurredAt: now, CreatedAt: now,
		Findings: []dsctx.DetectorMatch{
			{Detector: "llm", RuleID: "llm.prompt_injection", Severity: "LOW", Evidence: map[string]string{"rule": "ignore_previous_instructions", "message_index": "0", "role": "user"}},
			{Detector: "llm", RuleID: "llm.unauthorized_model", Severity: "MEDIUM", Evidence: map[string]string{"model": "claude-3-opus"}},
		},
	})
	store.addObservation(Observation{
		ID: uuid.New(), EndpointKey: "POST /v1/embeddings", Model: "text-embedding-3-large",
		IdentityFingerprint: "auth:u1", PromptLenBucket: "XS", TotalTokens: 12,
		OccurredAt: now.Add(-2 * time.Hour), CreatedAt: now.Add(-2 * time.Hour),
		Findings: []dsctx.DetectorMatch{},
	})
	// 窗口外观测（9 天前）：默认 7 天窗口不计
	store.addObservation(Observation{
		ID: uuid.New(), EndpointKey: "POST /v1/chat/completions", Model: "gpt-4o",
		IdentityFingerprint: "auth:u9", PromptLenBucket: "L", TotalTokens: 9999,
		OccurredAt: now.AddDate(0, 0, -9), CreatedAt: now.AddDate(0, 0, -9),
		Findings: []dsctx.DetectorMatch{},
	})
}

// 权限矩阵：未登录 401 / 无权限 403 / api_runtime.read 200（两个端点同口径）。
func TestLLMObsPermissionMatrix(t *testing.T) {
	store := NewMemStore()
	for _, path := range []string{
		"/api/v1/api-security/llm/observations",
		"/api/v1/api-security/llm/stats",
	} {
		if rr := do(t, newTestMux(store, noPrincipal), path); rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s no principal: got %d", path, rr.Code)
		}
		if rr := do(t, newTestMux(store, injectPrincipal("other.read")), path); rr.Code != http.StatusForbidden {
			t.Fatalf("%s wrong perm: got %d", path, rr.Code)
		}
		if rr := do(t, newTestMux(store, injectPrincipal(PermRuntimeRead)), path); rr.Code != http.StatusOK {
			t.Fatalf("%s api_runtime.read: got %d body=%s", path, rr.Code, rr.Body.String())
		}
	}
}

// 参数校验：超长 model/endpoint_key、非法 findings_only 400。
func TestLLMObsFilterValidation(t *testing.T) {
	mux := newTestMux(NewMemStore(), injectPrincipal(PermRuntimeRead))
	for _, url := range []string{
		"/api/v1/api-security/llm/observations?model=" + strings.Repeat("m", 129),
		"/api/v1/api-security/llm/observations?endpoint_key=" + strings.Repeat("e", 561),
		"/api/v1/api-security/llm/observations?findings_only=maybe",
	} {
		if rr := do(t, mux, url); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: got %d body=%s", url, rr.Code, rr.Body.String())
		}
	}
}

// 列表过滤分页：model/endpoint_key/findings_only/时间窗。
func TestLLMObsListFilters(t *testing.T) {
	store := NewMemStore()
	seedObservations(store)
	mux := newTestMux(store, injectPrincipal(PermRuntimeRead))

	var page struct {
		Data struct {
			Items []Observation `json:"items"`
			Total int64         `json:"total"`
		} `json:"data"`
	}
	// 默认窗口 7 天：3 条（窗口外 1 条不计）
	rr := do(t, mux, "/api/v1/api-security/llm/observations")
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Data.Total != 3 || len(page.Data.Items) != 3 {
		t.Fatalf("default window: total=%d items=%d", page.Data.Total, len(page.Data.Items))
	}
	// model 精确过滤
	rr = do(t, mux, "/api/v1/api-security/llm/observations?model=gpt-4o")
	_ = json.Unmarshal(rr.Body.Bytes(), &page)
	if page.Data.Total != 1 || page.Data.Items[0].Model != "gpt-4o" {
		t.Fatalf("model filter: %+v", page.Data)
	}
	// endpoint 精确过滤
	rr = do(t, mux, "/api/v1/api-security/llm/observations?endpoint_key="+
		strings.ReplaceAll("POST /v1/embeddings", " ", "%20"))
	_ = json.Unmarshal(rr.Body.Bytes(), &page)
	if page.Data.Total != 1 || page.Data.Items[0].Model != "text-embedding-3-large" {
		t.Fatalf("endpoint filter: %+v", page.Data)
	}
	// findings_only：仅命中观测
	rr = do(t, mux, "/api/v1/api-security/llm/observations?findings_only=true")
	_ = json.Unmarshal(rr.Body.Bytes(), &page)
	if page.Data.Total != 1 || len(page.Data.Items[0].Findings) != 2 {
		t.Fatalf("findings_only: %+v", page.Data)
	}
	// 时间窗放大到 10 天：窗口外行计入
	rr = do(t, mux, "/api/v1/api-security/llm/observations?days=10")
	_ = json.Unmarshal(rr.Body.Bytes(), &page)
	if page.Data.Total != 4 {
		t.Fatalf("days=10: total=%d", page.Data.Total)
	}
	// 分页
	rr = do(t, mux, "/api/v1/api-security/llm/observations?days=10&page=2&page_size=3")
	_ = json.Unmarshal(rr.Body.Bytes(), &page)
	if page.Data.Total != 4 || len(page.Data.Items) != 1 {
		t.Fatalf("paging: total=%d items=%d", page.Data.Total, len(page.Data.Items))
	}
}

// stats 聚合：模型分布/token 趋势/命中规则计数（复用 findings 口径）/窗口纪律。
func TestLLMObsStats(t *testing.T) {
	store := NewMemStore()
	seedObservations(store)
	mux := newTestMux(store, injectPrincipal(PermRuntimeRead))

	rr := do(t, mux, "/api/v1/api-security/llm/stats")
	if rr.Code != http.StatusOK {
		t.Fatalf("stats: %d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Data StatsData `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	stats := body.Data
	// 窗口内 3 条：观测 3、带命中 1、token 932、流式 1、模型 3
	if stats.Summary.Observations != 3 || stats.Summary.WithFindings != 1 ||
		stats.Summary.TotalTokens != 932 || stats.Summary.StreamCalls != 1 || stats.Summary.DistinctModels != 3 {
		t.Fatalf("summary: %+v", stats.Summary)
	}
	// 模型分布：gpt-4o 1 条 120 token
	var gptFound bool
	for _, m := range stats.ByModel {
		if m.Model == "gpt-4o" {
			gptFound = true
			if m.Observations != 1 || m.TotalTokens != 120 || m.Findings != 0 {
				t.Fatalf("by_model gpt-4o: %+v", m)
			}
		}
	}
	if !gptFound || len(stats.ByModel) != 3 {
		t.Fatalf("by_model: %+v", stats.ByModel)
	}
	// 命中规则分布：prompt_injection×1 + unauthorized_model×1
	if len(stats.FindingsByRule) != 2 {
		t.Fatalf("findings_by_rule: %+v", stats.FindingsByRule)
	}
	ruleCount := map[string]int64{}
	for _, r := range stats.FindingsByRule {
		ruleCount[r.RuleID] = r.Count
	}
	if ruleCount["llm.prompt_injection"] != 1 || ruleCount["llm.unauthorized_model"] != 1 {
		t.Fatalf("rule counts: %+v", ruleCount)
	}
	// token 趋势：按天聚合非空且总量一致
	var trendSum int64
	for _, p := range stats.TokenTrend {
		trendSum += p.TotalTokens
	}
	if len(stats.TokenTrend) == 0 || trendSum != 932 {
		t.Fatalf("token_trend: %+v", stats.TokenTrend)
	}
	// 窗口纪律：days=10 计入窗口外行
	rr = do(t, mux, "/api/v1/api-security/llm/stats?days=10")
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	stats = body.Data
	if stats.Summary.Observations != 4 || stats.Summary.TotalTokens != 10931 {
		t.Fatalf("days=10: %+v", stats.Summary)
	}
}
