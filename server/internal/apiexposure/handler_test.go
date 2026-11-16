// handler_test.go 暴露面判定 HTTP 入口测试：权限矩阵（401/403）/ 正常读 /
// 即时重评（写维度 + 写审计 + applied 语义）/ 404 与无效 ID。
package apiexposure

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// spyAudits 审计间谍（断言重评审计写入）。
type spyAudits struct{ entries []audits.RecordInput }

func (s *spyAudits) Record(_ context.Context, in audits.RecordInput) error {
	s.entries = append(s.entries, in)
	return nil
}

// injectPrincipal 模拟认证链：注入持有给定权限点集合的主体。
func injectPrincipal(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "exposure-tester", PermsSet: set}
			ctx := authz.WithPrincipal(r.Context(), p)
			ctx = context.WithValue(ctx, response.RequestIDKey, "exp-rid")
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

// newExposureMux 装配暴露面路由（内存仓储 + 假 DNS + 审计间谍）。
func newExposureMux(store *MemStore, spy *spyAudits, authzFn func(http.Handler) http.Handler) *http.ServeMux {
	sweeper := newTestSweeper(store, &fakeSettings{}, nil)
	h := NewHandler(store, nil).SetSweeper(sweeper)
	if spy != nil {
		h.audits = spy
	}
	mux := http.NewServeMux()
	RegisterRoutes(mux, authzFn, h)
	return mux
}

// exposureRespBody GET/POST 响应解码（仅需断言字段）。
type exposureRespBody struct {
	Code string `json:"code"`
	Data struct {
		EndpointID string `json:"endpoint_id"`
		Locked     bool   `json:"locked"`
		Current    struct {
			Value      string  `json:"value"`
			Source     string  `json:"source"`
			Confidence float64 `json:"confidence"`
		} `json:"current"`
		Assessment *struct {
			Verdict    string `json:"verdict"`
			Source     string `json:"source"`
			Confidence string `json:"confidence"`
			Evidence   []struct {
				Type    string `json:"type"`
				Summary string `json:"summary"`
			} `json:"evidence"`
		} `json:"assessment"`
		Applied bool `json:"applied"`
	} `json:"data"`
}

func doRequest(t *testing.T, mux http.Handler, method, url string) (int, exposureRespBody) {
	t.Helper()
	req := httptest.NewRequest(method, url, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	var body exposureRespBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rr.Body.String())
	}
	return rr.Code, body
}

func TestExposurePermissionMatrix(t *testing.T) {
	store := NewMemStore()
	id := uuid.New()
	store.addEndpoint(id, "GET /users/{id}", "api.example.com", DeployReverseProxy, false, "", "", 0)
	getURL := "/api/v1/api-security/endpoints/" + id.String() + "/exposure"
	postURL := getURL + "/reassess"

	// 未登录 → 401（两个端点）
	if code, _ := doRequest(t, newExposureMux(store, nil, noPrincipal), http.MethodGet, getURL); code != http.StatusUnauthorized {
		t.Fatalf("GET no principal: %d, want 401", code)
	}
	if code, _ := doRequest(t, newExposureMux(store, nil, noPrincipal), http.MethodPost, postURL); code != http.StatusUnauthorized {
		t.Fatalf("POST no principal: %d, want 401", code)
	}
	// 权限不足 → 403
	if code, _ := doRequest(t, newExposureMux(store, nil, injectPrincipal("api_asset.edit")), http.MethodGet, getURL); code != http.StatusForbidden {
		t.Fatalf("GET wrong perm: %d, want 403", code)
	}
	if code, _ := doRequest(t, newExposureMux(store, nil, injectPrincipal("api_asset.read")), http.MethodPost, postURL); code != http.StatusForbidden {
		t.Fatalf("POST wrong perm: %d, want 403", code)
	}
	// 正确权限 → 200
	if code, _ := doRequest(t, newExposureMux(store, nil, injectPrincipal("api_asset.read")), http.MethodGet, getURL); code != http.StatusOK {
		t.Fatalf("GET with perm: %d, want 200", code)
	}
	if code, _ := doRequest(t, newExposureMux(store, nil, injectPrincipal("api_asset.edit")), http.MethodPost, postURL); code != http.StatusOK {
		t.Fatalf("POST with perm: %d, want 200", code)
	}
}

func TestGetExposure(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	id := uuid.New()
	store.addEndpoint(id, "GET /orders", "orders.example.com", DeployReverseProxy, false, VerdictInternal, SourceManual, 1)
	// 一次历史评估（verdict 与人工维度不同：如实并存，维度以人工为准）
	if _, err := store.WriteAssessment(ctx, id, Assessment{
		Verdict: VerdictPublic, Source: SourceTraffic, Confidence: ConfidenceHigh,
		Evidence: []EvidenceItem{{Type: "traffic_public", Summary: "近7天存在公网来源调用（3 个来源，覆盖 5 天）"}},
	}, fixedNow()); err != nil {
		t.Fatal(err)
	}
	mux := newExposureMux(store, nil, injectPrincipal("api_asset.read"))
	code, body := doRequest(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+id.String()+"/exposure")
	if code != http.StatusOK {
		t.Fatalf("status=%d", code)
	}
	if body.Data.Current.Value != VerdictInternal || body.Data.Current.Source != SourceManual ||
		body.Data.Current.Confidence != 1 || body.Data.Locked {
		t.Fatalf("current = %+v locked=%v", body.Data.Current, body.Data.Locked)
	}
	if body.Data.Assessment == nil || body.Data.Assessment.Verdict != VerdictPublic ||
		body.Data.Assessment.Evidence[0].Summary == "" {
		t.Fatalf("assessment = %+v", body.Data.Assessment)
	}
	// 从未评估端点：assessment 为 null
	id2 := uuid.New()
	store.addEndpoint(id2, "GET /never", "never.example.com", DeployReverseProxy, false, "", "", 0)
	code, body = doRequest(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+id2.String()+"/exposure")
	if code != http.StatusOK || body.Data.Assessment != nil || body.Data.Current.Value != "" {
		t.Fatalf("never assessed: code=%d body=%+v", code, body.Data)
	}
}

func TestReassessWritesAuditAndApplies(t *testing.T) {
	store := NewMemStore()
	id := uuid.New()
	store.addEndpoint(id, "GET /re", "re.example.com", DeployReverseProxy, false, "", "", 0)
	seedTraffic(t, store, id, ScopePublic, 3, 10)
	spy := &spyAudits{}
	mux := newExposureMux(store, spy, injectPrincipal("api_asset.edit"))

	code, body := doRequest(t, mux, http.MethodPost,
		"/api/v1/api-security/endpoints/"+id.String()+"/exposure/reassess")
	if code != http.StatusOK {
		t.Fatalf("status=%d", code)
	}
	if body.Data.Assessment == nil || body.Data.Assessment.Verdict != VerdictPublic || !body.Data.Applied {
		t.Fatalf("reassess resp = %+v", body.Data)
	}
	// 维度已更新
	ectx, _ := store.EndpointContext(context.Background(), id)
	if ectx.ExistingValue != VerdictPublic || ectx.ExistingSource != SourceTraffic {
		t.Fatalf("dimension = (%s, %s)", ectx.ExistingValue, ectx.ExistingSource)
	}
	// 审计已写（模块/动作/对象/风险等级）
	if len(spy.entries) != 1 {
		t.Fatalf("audit entries=%d, want 1", len(spy.entries))
	}
	entry := spy.entries[0]
	if entry.Module != "api_exposure" || entry.Action != "reassess" ||
		entry.ObjectType != "api_endpoint" || entry.ObjectID != id.String() ||
		entry.RiskLevel != audits.RiskLow || entry.Result != audits.ResultSuccess ||
		entry.Username != "exposure-tester" {
		t.Fatalf("audit entry = %+v", entry)
	}
}

func TestReassessManualNotApplied(t *testing.T) {
	store := NewMemStore()
	id := uuid.New()
	store.addEndpoint(id, "GET /manual", "m.example.com", DeployReverseProxy, false, VerdictPartner, SourceManual, 1)
	seedTraffic(t, store, id, ScopePublic, 3, 10)
	spy := &spyAudits{}
	mux := newExposureMux(store, spy, injectPrincipal("api_asset.edit"))

	code, body := doRequest(t, mux, http.MethodPost,
		"/api/v1/api-security/endpoints/"+id.String()+"/exposure/reassess")
	if code != http.StatusOK || body.Data.Applied {
		t.Fatalf("manual reassess: code=%d applied=%v", code, body.Data.Applied)
	}
	if body.Data.Assessment == nil || body.Data.Assessment.Source != SourceManual ||
		body.Data.Assessment.Verdict != VerdictPartner {
		t.Fatalf("manual assessment = %+v", body.Data.Assessment)
	}
	// 审计仍写（重评动作本身）
	if len(spy.entries) != 1 {
		t.Fatalf("audit entries=%d, want 1", len(spy.entries))
	}
}

func TestExposureNotFoundAndBadID(t *testing.T) {
	store := NewMemStore()
	mux := newExposureMux(store, &spyAudits{}, injectPrincipal("api_asset.read", "api_asset.edit"))
	if code, _ := doRequest(t, mux, http.MethodGet,
		"/api/v1/api-security/endpoints/"+uuid.New().String()+"/exposure"); code != http.StatusNotFound {
		t.Fatalf("GET missing: %d, want 404", code)
	}
	if code, _ := doRequest(t, mux, http.MethodPost,
		"/api/v1/api-security/endpoints/"+uuid.New().String()+"/exposure/reassess"); code != http.StatusNotFound {
		t.Fatalf("POST missing: %d, want 404", code)
	}
	if code, _ := doRequest(t, mux, http.MethodGet,
		"/api/v1/api-security/endpoints/not-a-uuid/exposure"); code != http.StatusBadRequest {
		t.Fatalf("GET bad id: %d, want 400", code)
	}
}

// TestReassessWithoutSweeper 评估器未装配时重评 503（如实降级）。
func TestReassessWithoutSweeper(t *testing.T) {
	store := NewMemStore()
	id := uuid.New()
	store.addEndpoint(id, "GET /ns", "ns.example.com", DeployReverseProxy, false, "", "", 0)
	h := NewHandler(store, nil) // 不注入 sweeper
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPrincipal("api_asset.edit"), h)
	if code, _ := doRequest(t, mux, http.MethodPost,
		"/api/v1/api-security/endpoints/"+id.String()+"/exposure/reassess"); code != http.StatusServiceUnavailable {
		t.Fatalf("no sweeper: %d, want 503", code)
	}
}
