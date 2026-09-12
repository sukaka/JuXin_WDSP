// handler_test.go 弱点中心 handler 测试：权限点、参数校验、状态机非法迁移 400、
// 操作审计落间谍、全生命周期 HTTP 流（MemStore 驱动真实 Handler，不依赖数据库）。
package apiweakness

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

// spyAudits 审计间谍（记录每次 Record 输入）。
type spyAudits struct{ entries []audits.RecordInput }

func (s *spyAudits) Record(_ context.Context, in audits.RecordInput) error {
	s.entries = append(s.entries, in)
	return nil
}

// injectPrincipal 模拟认证链：注入持有权限点的主体与 Request ID。
func injectPrincipal(perms ...string) func(http.Handler) http.Handler {
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

func newTestMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPrincipal(PermRead, PermHandle), h)
	return mux
}

func doJSON(t *testing.T, mux http.Handler, method, url string, body any) *httptest.ResponseRecorder {
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

// decodeData 解包响应 envelope 的 data 字段。
func decodeData(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
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

// allRoutes 全部路由（权限矩阵测试用）。
var allRoutes = []struct{ method, path string }{
	{http.MethodGet, "/api/v1/api-security/weaknesses"},
	{http.MethodGet, "/api/v1/api-security/weaknesses/" + uuid.NewString()},
	{http.MethodPost, "/api/v1/api-security/weaknesses/" + uuid.NewString() + "/confirm"},
	{http.MethodPost, "/api/v1/api-security/weaknesses/" + uuid.NewString() + "/assign"},
	{http.MethodPost, "/api/v1/api-security/weaknesses/" + uuid.NewString() + "/fixed"},
	{http.MethodPost, "/api/v1/api-security/weaknesses/" + uuid.NewString() + "/retest"},
	{http.MethodPost, "/api/v1/api-security/weaknesses/" + uuid.NewString() + "/ignore"},
	{http.MethodPost, "/api/v1/api-security/weaknesses/" + uuid.NewString() + "/archive"},
}

// TestRoutesPermission 未登录 401、无权限 403（权限校验在访问 store 之前，nil store 不触发 panic）。
func TestRoutesPermission(t *testing.T) {
	h := NewHandler(nil, nil)

	muxNoAuth := http.NewServeMux()
	RegisterRoutes(muxNoAuth, func(next http.Handler) http.Handler { return next }, h)
	for _, rt := range allRoutes {
		rr := doJSON(t, muxNoAuth, rt.method, rt.path, nil)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("no-auth %s %s status=%d", rt.method, rt.path, rr.Code)
		}
	}

	muxNoPerm := http.NewServeMux()
	RegisterRoutes(muxNoPerm, injectPrincipal(), h)
	for _, rt := range allRoutes {
		rr := doJSON(t, muxNoPerm, rt.method, rt.path, nil)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("no-perm %s %s status=%d", rt.method, rt.path, rr.Code)
		}
	}
}

// TestListValidation 列表过滤参数校验（400 在访问 store 之前返回）。
func TestListValidation(t *testing.T) {
	mux := newTestMux(NewHandler(nil, nil))
	for _, q := range []string{
		"?status=OPEN", "?severity=P0", "?category=NETWORK", "?endpoint_id=not-a-uuid",
	} {
		rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/weaknesses"+q, nil)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d, want 400", q, rr.Code)
		}
	}
}

// TestDetailValidation 详情：非法 ID 400、不存在 404。
func TestDetailValidation(t *testing.T) {
	mux := newTestMux(NewHandler(NewMemStore(), nil))
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/weaknesses/not-a-uuid", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad id status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/weaknesses/"+uuid.NewString(), nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing id status=%d", rr.Code)
	}
}

// TestTransitionValidation 流转请求体校验：assign 缺 owner 400、retest 非法 result 400、超长 note 400。
func TestTransitionValidation(t *testing.T) {
	mem := NewMemStore()
	mux := newTestMux(NewHandler(mem, nil))
	w := seedDerived(t, mem, uuid.New(), CodeSensitiveInQuery, time.Now().UTC())
	base := "/api/v1/api-security/weaknesses/" + w.ID.String()

	// assign：空 body / 空 owner / 超长 owner → 400
	if rr := doJSON(t, mux, http.MethodPost, base+"/assign", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("assign empty body status=%d", rr.Code)
	}
	if rr := doJSON(t, mux, http.MethodPost, base+"/assign", map[string]any{"owner": "  "}); rr.Code != http.StatusBadRequest {
		t.Fatalf("assign blank owner status=%d", rr.Code)
	}
	if rr := doJSON(t, mux, http.MethodPost, base+"/assign", map[string]any{"owner": strings.Repeat("a", 129)}); rr.Code != http.StatusBadRequest {
		t.Fatalf("assign long owner status=%d", rr.Code)
	}
	// retest：缺 result / 非法 result → 400
	if rr := doJSON(t, mux, http.MethodPost, base+"/retest", map[string]any{}); rr.Code != http.StatusBadRequest {
		t.Fatalf("retest missing result status=%d", rr.Code)
	}
	if rr := doJSON(t, mux, http.MethodPost, base+"/retest", map[string]any{"result": "MAYBE"}); rr.Code != http.StatusBadRequest {
		t.Fatalf("retest bad result status=%d", rr.Code)
	}
	// 超长 note → 400（不静默截断）
	longNote := map[string]any{"note": strings.Repeat("备", 513)}
	if rr := doJSON(t, mux, http.MethodPost, base+"/confirm", longNote); rr.Code != http.StatusBadRequest {
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
	got, _ := mem.GetByID(context.Background(), w.ID)
	if got.Status != StatusNew {
		t.Fatalf("invalid requests must not transition: %+v", got)
	}
}

// TestLifecycleHTTP 全生命周期 HTTP 流：confirm→assign→fixed→retest(FAIL)→assign→fixed→retest(PASS)，
// 逐步断言状态/副作用字段/审计；非法迁移 400；终态后操作 400。
func TestLifecycleHTTP(t *testing.T) {
	mem := NewMemStore()
	spy := &spyAudits{}
	h := &Handler{store: mem, audits: spy}
	mux := newTestMux(h)
	ctx := context.Background()
	w := seedDerived(t, mem, uuid.New(), CodeUnauthenticatedSensitiveAPI, time.Now().UTC())
	base := "/api/v1/api-security/weaknesses/" + w.ID.String()

	statusOf := func() string {
		got, err := mem.GetByID(ctx, w.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.Status
	}

	// 非法迁移：NEW 直接 fixed → 400
	if rr := doJSON(t, mux, http.MethodPost, base+"/fixed", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("fixed from NEW status=%d, want 400", rr.Code)
	}
	// 不存在弱点 → 404；非法 ID → 400
	if rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/weaknesses/"+uuid.NewString()+"/confirm", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("missing id status=%d", rr.Code)
	}
	if rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/weaknesses/bad-id/confirm", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad id status=%d", rr.Code)
	}

	// confirm（空 body 合法）
	rr := doJSON(t, mux, http.MethodPost, base+"/confirm", nil)
	if rr.Code != http.StatusOK || statusOf() != StatusConfirmed {
		t.Fatalf("confirm status=%d body=%s", rr.Code, rr.Body.String())
	}
	// 重复 confirm（CONFIRMED 状态）→ 400
	if rr := doJSON(t, mux, http.MethodPost, base+"/confirm", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("re-confirm status=%d, want 400", rr.Code)
	}
	// assign（owner + due_date + note）
	due := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	rr = doJSON(t, mux, http.MethodPost, base+"/assign", map[string]any{
		"owner": "zhangsan", "due_date": due.Format(time.RFC3339), "note": "本周整改",
	})
	if rr.Code != http.StatusOK || statusOf() != StatusToFix {
		t.Fatalf("assign status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	got := data["weakness"].(map[string]any)
	if got["owner"] != "zhangsan" || got["due_date"] == nil {
		t.Fatalf("assign weakness: %v", got)
	}
	// fixed
	rr = doJSON(t, mux, http.MethodPost, base+"/fixed", map[string]any{"note": "已加认证"})
	if rr.Code != http.StatusOK || statusOf() != StatusFixed {
		t.Fatalf("fixed status=%d body=%s", rr.Code, rr.Body.String())
	}
	// retest FAIL → REPRODUCED
	rr = doJSON(t, mux, http.MethodPost, base+"/retest", map[string]any{"result": "fail", "note": "仍可匿名访问"})
	if rr.Code != http.StatusOK || statusOf() != StatusReproduced {
		t.Fatalf("retest fail status=%d body=%s", rr.Code, rr.Body.String())
	}
	// REPRODUCED 重新指派 → FIXED → retest PASS → ARCHIVED
	if rr = doJSON(t, mux, http.MethodPost, base+"/assign", map[string]any{"owner": "lisi"}); rr.Code != http.StatusOK {
		t.Fatalf("re-assign status=%d", rr.Code)
	}
	if rr = doJSON(t, mux, http.MethodPost, base+"/fixed", nil); rr.Code != http.StatusOK {
		t.Fatalf("re-fixed status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodPost, base+"/retest", map[string]any{"result": "PASS"})
	if rr.Code != http.StatusOK || statusOf() != StatusArchived {
		t.Fatalf("retest pass status=%d body=%s", rr.Code, rr.Body.String())
	}
	// 终态后任何操作 → 400
	if rr := doJSON(t, mux, http.MethodPost, base+"/ignore", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("ignore from ARCHIVED status=%d, want 400", rr.Code)
	}

	// 审计：confirm/assign/fixed/retest/assign/fixed/retest 共 7 条（400/404 不记审计）
	if len(spy.entries) != 7 {
		t.Fatalf("audit entries=%d, want 7", len(spy.entries))
	}
	first := spy.entries[0]
	if first.Module != "api_security" || first.ObjectType != "api_weakness" || first.Action != "confirm" ||
		first.ObjectID != w.ID.String() || first.Username != "tester" || first.Result != audits.ResultSuccess ||
		first.RequestID != "test-rid" || first.BeforeSummary != "status=NEW" || first.AfterSummary != "status=CONFIRMED" {
		t.Fatalf("first audit entry: %+v", first)
	}
	last := spy.entries[6]
	if last.Action != "retest" || last.AfterSummary != "status=ARCHIVED" {
		t.Fatalf("last audit entry: %+v", last)
	}

	// 详情：弱点 + 完整历史轨迹（DERIVED + 7 次流转 = 8 条）
	rr = doJSON(t, mux, http.MethodGet, base, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("detail status=%d", rr.Code)
	}
	data = decodeData(t, rr)
	actions := data["actions"].([]any)
	if len(actions) != 8 {
		t.Fatalf("actions=%d, want 8", len(actions))
	}
	// 列表能按 status 过滤到
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/weaknesses?status=ARCHIVED", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d", rr.Code)
	}
	var env struct {
		Data struct {
			Total int64 `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil || env.Data.Total != 1 {
		t.Fatalf("list archived total=%d err=%v", env.Data.Total, err)
	}
}
