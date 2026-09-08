// risk_handler_test.go 风险中心 handler 测试：权限点 401/403、参数校验、状态机非法迁移 400、
// 操作审计落间谍、全生命周期 HTTP 流、三视图聚合与详情（RiskMemStore 驱动真实 Handler，不依赖数据库）。
package apisecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// spyRiskAudits 审计间谍（记录每次 Record 输入）。
type spyRiskAudits struct{ entries []audits.RecordInput }

func (s *spyRiskAudits) Record(_ context.Context, in audits.RecordInput) error {
	s.entries = append(s.entries, in)
	return nil
}

// injectRiskPrincipal 模拟认证链：注入持有权限点的主体与 Request ID。
func injectRiskPrincipal(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: set}
			ctx := authz.WithPrincipal(r.Context(), p)
			ctx = context.WithValue(ctx, response.RequestIDKey, "test-rid")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func newRiskTestMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectRiskPrincipal("api_risk.read", "api_risk.handle"), h)
	return mux
}

func doRiskJSON(t *testing.T, mux http.Handler, method, url string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, url, reader)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// decodeRiskData 解包响应 envelope 的 data 字段。
func decodeRiskData(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var env struct {
		Code string         `json:"code"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v body=%s", err, rr.Body.String())
	}
	if env.Code != "SUCCESS" {
		t.Fatalf("code=%s body=%s", env.Code, rr.Body.String())
	}
	return env.Data
}

// riskAllRoutes 全部风险中心路由（权限矩阵测试用）。
var riskAllRoutes = []struct{ method, path string }{
	{http.MethodGet, "/api/v1/api-security/findings/summary"},
	{http.MethodGet, "/api/v1/api-security/findings/" + uuid.NewString()},
	{http.MethodPost, "/api/v1/api-security/findings/" + uuid.NewString() + "/confirm"},
	{http.MethodPost, "/api/v1/api-security/findings/" + uuid.NewString() + "/start"},
	{http.MethodPost, "/api/v1/api-security/findings/" + uuid.NewString() + "/resolve"},
	{http.MethodPost, "/api/v1/api-security/findings/" + uuid.NewString() + "/false-positive"},
	{http.MethodPost, "/api/v1/api-security/findings/" + uuid.NewString() + "/ignore"},
	{http.MethodPost, "/api/v1/api-security/findings/" + uuid.NewString() + "/archive"},
}

// TestRiskRoutesPermission 未登录 401、无权限 403（权限校验在访问仓储之前，nil 仓储不触发 panic）。
func TestRiskRoutesPermission(t *testing.T) {
	h := NewHandler(nil, nil)

	muxNoAuth := http.NewServeMux()
	RegisterRoutes(muxNoAuth, func(next http.Handler) http.Handler { return next }, h)
	for _, rt := range riskAllRoutes {
		rr := doRiskJSON(t, muxNoAuth, rt.method, rt.path, nil)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("no-auth %s %s status=%d", rt.method, rt.path, rr.Code)
		}
	}

	muxNoPerm := http.NewServeMux()
	RegisterRoutes(muxNoPerm, injectRiskPrincipal(), h)
	for _, rt := range riskAllRoutes {
		rr := doRiskJSON(t, muxNoPerm, rt.method, rt.path, nil)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("no-perm %s %s status=%d", rt.method, rt.path, rr.Code)
		}
	}

	// 只读权限：读接口放行、处置接口 403（api_risk.read 不含 handle）
	muxReadOnly := http.NewServeMux()
	RegisterRoutes(muxReadOnly, injectRiskPrincipal("api_risk.read"), h)
	if rr := doRiskJSON(t, muxReadOnly, http.MethodGet, "/api/v1/api-security/findings/summary", nil); rr.Code == http.StatusForbidden {
		t.Fatal("read perm must allow summary")
	}
	if rr := doRiskJSON(t, muxReadOnly, http.MethodPost, "/api/v1/api-security/findings/"+uuid.NewString()+"/confirm", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("read-only confirm status=%d, want 403", rr.Code)
	}
}

// TestRiskUnavailable 仓储未装配（nil store 且未 SetRiskRepository）→ 503。
func TestRiskUnavailable(t *testing.T) {
	mux := newRiskTestMux(NewHandler(nil, nil))
	if rr := doRiskJSON(t, mux, http.MethodGet, "/api/v1/api-security/findings/summary", nil); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("summary status=%d, want 503", rr.Code)
	}
	if rr := doRiskJSON(t, mux, http.MethodGet, "/api/v1/api-security/findings/"+uuid.NewString(), nil); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("detail status=%d, want 503", rr.Code)
	}
	if rr := doRiskJSON(t, mux, http.MethodPost, "/api/v1/api-security/findings/"+uuid.NewString()+"/confirm", nil); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("confirm status=%d, want 503", rr.Code)
	}
}

// TestRiskTransitionValidation 流转请求体校验：非法 ID 400、不存在 404、
// resolve 缺 resolution 400、false-positive 缺 reason 400、超长 note 400、非法 JSON 400；
// 校验失败不得产生流转。
func TestRiskTransitionValidation(t *testing.T) {
	mem := NewRiskMemStore()
	h := NewHandler(nil, nil)
	h.SetRiskRepository(mem)
	mux := newRiskTestMux(h)

	f := newSeededFinding(nil)
	mem.SeedFinding(f)
	base := "/api/v1/api-security/findings/" + f.ID.String()

	// 非法 ID → 400；不存在 → 404
	if rr := doRiskJSON(t, mux, http.MethodPost, "/api/v1/api-security/findings/not-a-uuid/confirm", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad id status=%d", rr.Code)
	}
	if rr := doRiskJSON(t, mux, http.MethodPost, "/api/v1/api-security/findings/"+uuid.NewString()+"/confirm", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("missing id status=%d", rr.Code)
	}
	// resolve：空 body / 空 resolution / 超长 resolution → 400
	if rr := doRiskJSON(t, mux, http.MethodPost, base+"/resolve", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("resolve empty body status=%d", rr.Code)
	}
	if rr := doRiskJSON(t, mux, http.MethodPost, base+"/resolve", map[string]any{"resolution": "  "}); rr.Code != http.StatusBadRequest {
		t.Fatalf("resolve blank resolution status=%d", rr.Code)
	}
	if rr := doRiskJSON(t, mux, http.MethodPost, base+"/resolve", map[string]any{"resolution": strings.Repeat("处", 513)}); rr.Code != http.StatusBadRequest {
		t.Fatalf("resolve long resolution status=%d", rr.Code)
	}
	// false-positive：缺 reason → 400
	if rr := doRiskJSON(t, mux, http.MethodPost, base+"/false-positive", map[string]any{}); rr.Code != http.StatusBadRequest {
		t.Fatalf("false-positive missing reason status=%d", rr.Code)
	}
	// 超长 note → 400（不静默截断）
	if rr := doRiskJSON(t, mux, http.MethodPost, base+"/confirm", map[string]any{"note": strings.Repeat("备", 513)}); rr.Code != http.StatusBadRequest {
		t.Fatalf("long note status=%d", rr.Code)
	}
	// 非法 JSON → 400
	req := httptest.NewRequest(http.MethodPost, base+"/confirm", bytes.NewReader([]byte("not-json")))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad json status=%d", rr.Code)
	}
	// 校验失败不得产生流转
	got, err := mem.GetFinding(context.Background(), f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != RiskStatusNew {
		t.Fatalf("invalid requests must not transition: %+v", got)
	}
}

// TestRiskLifecycleHTTP 全生命周期 HTTP 流：
// confirm→start→resolve→archive 主路径；另起两条覆盖 false-positive / ignore 分支；
// 非法迁移 400；终态后操作 400；审计逐条断言。
func TestRiskLifecycleHTTP(t *testing.T) {
	mem := NewRiskMemStore()
	spy := &spyRiskAudits{}
	h := NewHandler(nil, nil)
	h.SetRiskRepository(mem)
	h.audits = spy
	mux := newRiskTestMux(h)
	ctx := context.Background()

	f := newSeededFinding(nil)
	mem.SeedFinding(f)
	base := "/api/v1/api-security/findings/" + f.ID.String()
	statusOf := func() string {
		got, err := mem.GetFinding(ctx, f.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.Status
	}

	// 非法迁移：NEW 直接 start → 400
	if rr := doRiskJSON(t, mux, http.MethodPost, base+"/start", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("start from NEW status=%d, want 400", rr.Code)
	}
	// confirm（空 body 合法）
	rr := doRiskJSON(t, mux, http.MethodPost, base+"/confirm", nil)
	if rr.Code != http.StatusOK || statusOf() != RiskStatusConfirmed {
		t.Fatalf("confirm status=%d body=%s", rr.Code, rr.Body.String())
	}
	// 重复 confirm（CONFIRMED 状态）→ 400
	if rr := doRiskJSON(t, mux, http.MethodPost, base+"/confirm", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("re-confirm status=%d, want 400", rr.Code)
	}
	// start
	if rr := doRiskJSON(t, mux, http.MethodPost, base+"/start", map[string]any{"note": "排查中"}); rr.Code != http.StatusOK || statusOf() != RiskStatusInProgress {
		t.Fatalf("start status=%d", rr.Code)
	}
	// resolve（必填 resolution）
	rr = doRiskJSON(t, mux, http.MethodPost, base+"/resolve", map[string]any{"resolution": "已加对象属主校验"})
	if rr.Code != http.StatusOK || statusOf() != RiskStatusResolved {
		t.Fatalf("resolve status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeRiskData(t, rr)
	got := data["finding"].(map[string]any)
	detail := got["detail"].(map[string]any)
	handling := detail["handling"].(map[string]any)
	if handling["action"] != RiskActionResolve || handling["note"] != "已加对象属主校验" || handling["actor"] != "tester" {
		t.Fatalf("handling: %v", handling)
	}
	// archive
	if rr := doRiskJSON(t, mux, http.MethodPost, base+"/archive", nil); rr.Code != http.StatusOK || statusOf() != RiskStatusArchived {
		t.Fatalf("archive status=%d", rr.Code)
	}
	// 终态后任何操作 → 400
	if rr := doRiskJSON(t, mux, http.MethodPost, base+"/ignore", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("ignore from ARCHIVED status=%d, want 400", rr.Code)
	}

	// false-positive 分支（NEW 直接标记误报）
	f2 := newSeededFinding(nil)
	mem.SeedFinding(f2)
	rr = doRiskJSON(t, mux, http.MethodPost, "/api/v1/api-security/findings/"+f2.ID.String()+"/false-positive",
		map[string]any{"reason": "内部扫描器流量"})
	if rr.Code != http.StatusOK {
		t.Fatalf("false-positive status=%d body=%s", rr.Code, rr.Body.String())
	}
	got2, _ := mem.GetFinding(ctx, f2.ID)
	if got2.Status != RiskStatusFalsePositive {
		t.Fatalf("f2 status=%s", got2.Status)
	}

	// ignore 分支（NEW 直接忽略）
	f3 := newSeededFinding(nil)
	mem.SeedFinding(f3)
	if rr := doRiskJSON(t, mux, http.MethodPost, "/api/v1/api-security/findings/"+f3.ID.String()+"/ignore",
		map[string]any{"note": "接受风险"}); rr.Code != http.StatusOK {
		t.Fatalf("ignore status=%d", rr.Code)
	}
	got3, _ := mem.GetFinding(ctx, f3.ID)
	if got3.Status != RiskStatusIgnored {
		t.Fatalf("f3 status=%s", got3.Status)
	}

	// 审计：confirm/start/resolve/archive + false_positive + ignore 共 6 条（400/404 不记审计）
	if len(spy.entries) != 6 {
		t.Fatalf("audit entries=%d, want 6", len(spy.entries))
	}
	first := spy.entries[0]
	if first.Module != "api_security" || first.ObjectType != "api_runtime_finding" || first.Action != "confirm" ||
		first.ObjectID != f.ID.String() || first.Username != "tester" || first.Result != audits.ResultSuccess ||
		first.RequestID != "test-rid" || first.BeforeSummary != "status=NEW" || first.AfterSummary != "status=CONFIRMED" ||
		first.RiskLevel != audits.RiskMedium {
		t.Fatalf("first audit entry: %+v", first)
	}
	if spy.entries[2].Action != "resolve" || spy.entries[2].AfterSummary != "status=RESOLVED" {
		t.Fatalf("resolve audit entry: %+v", spy.entries[2])
	}
	if spy.entries[4].Action != "false_positive" || spy.entries[5].Action != "ignore" {
		t.Fatalf("last audit entries: %+v / %+v", spy.entries[4], spy.entries[5])
	}
}

// TestRiskSummaryHTTP 聚合接口：三视图桶数与关键字段（mem 预置数据经真实 HTTP 路径）。
func TestRiskSummaryHTTP(t *testing.T) {
	mem := NewRiskMemStore()
	ep := uuid.New()
	mem.SetEndpointKey(ep, "GET /api/users/{id}")
	f1 := newSeededFinding(&ep)
	f1.SubjectType, f1.SubjectID = "IDENTITY", "fp-1"
	mem.SeedFinding(f1)
	f2 := newSeededFinding(&ep)
	f2.SubjectType, f2.SubjectID = "IDENTITY", "fp-1"
	f2.FindingType, f2.Severity, f2.Count = "SHADOW", "CRITICAL", 7
	mem.SeedFinding(f2)

	h := NewHandler(nil, nil)
	h.SetRiskRepository(mem)
	mux := newRiskTestMux(h)

	rr := doRiskJSON(t, mux, http.MethodGet, "/api/v1/api-security/findings/summary", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("summary status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeRiskData(t, rr)
	bySubject := data["by_subject"].([]any)
	if len(bySubject) != 1 {
		t.Fatalf("by_subject=%d, want 1", len(bySubject))
	}
	bucket := bySubject[0].(map[string]any)
	if bucket["subject_id"] != "fp-1" || bucket["count"].(float64) != 2 || bucket["hits"].(float64) != 10 ||
		bucket["max_severity"] != "CRITICAL" || bucket["last_seen_at"] == nil {
		t.Fatalf("subject bucket: %v", bucket)
	}
	if len(data["by_endpoint"].([]any)) != 1 || len(data["by_finding_type"].([]any)) != 2 {
		t.Fatalf("views: %v", data)
	}
}

// TestRiskDetailHTTP 详情接口：全字段视图 + evidence 脱敏原样 + 关联 request_id 列表。
func TestRiskDetailHTTP(t *testing.T) {
	mem := NewRiskMemStore()
	ep := uuid.New()
	mem.SetEndpointKey(ep, "GET /api/users/{id}")
	f := newSeededFinding(&ep)
	f.SubjectType, f.SubjectID = "IDENTITY", "fp-1"
	score := 80
	f.RiskScore = &score
	f.RiskLevel = "HIGH"
	f.ModelVersion = "v3"
	f.PolicyVersion = "p1"
	mem.SeedFinding(f)
	now := time.Now().UTC()
	mem.SeedEvent("GET /api/users/{id}", "fp-1", "rid-2", now)
	mem.SeedEvent("GET /api/users/{id}", "fp-1", "rid-1", now.Add(-time.Minute))
	mem.SeedEvent("GET /api/users/{id}", "fp-9", "rid-other", now) // 其他身份不关联

	h := NewHandler(nil, nil)
	h.SetRiskRepository(mem)
	mux := newRiskTestMux(h)

	rr := doRiskJSON(t, mux, http.MethodGet, "/api/v1/api-security/findings/"+f.ID.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("detail status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeRiskData(t, rr)
	got := data["finding"].(map[string]any)
	if got["endpoint_key"] != "GET /api/users/{id}" || got["status"] != RiskStatusNew ||
		got["risk_score"].(float64) != 80 || got["model_version"] != "v3" || got["policy_version"] != "p1" ||
		got["count"].(float64) != 3 {
		t.Fatalf("finding: %v", got)
	}
	// evidence 原样返回（生产方落库时已脱敏，不再二次处理）
	ev := got["evidence"].(map[string]any)
	if ev["field"] != "id" || ev["type"] != "integer" {
		t.Fatalf("evidence: %v", ev)
	}
	// 关联 request_id：同端点同身份，occurred_at 倒序
	related := data["related_request_ids"].([]any)
	if len(related) != 2 || related[0] != "rid-2" || related[1] != "rid-1" {
		t.Fatalf("related: %v", related)
	}
	if data["related_request_note"] == "" {
		t.Fatal("related_request_note missing")
	}
}
