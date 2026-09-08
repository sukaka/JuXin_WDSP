// handler_test.go AI 定时运营任务 handler 测试（MemStore 驱动真实 Handler）：
// 权限点矩阵（401/403）、参数校验（词表/cron/config 白名单）、CRUD、启停游标语义、
// 立即执行（未装配 503/开关 503/冲突 409/成功 200）、执行记录查询与 404。
package apiops

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
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// injectPrincipal 模拟认证链：注入指定用户与权限点的主体。
func injectPrincipal(userID uuid.UUID, perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: userID, Username: "tester", PermsSet: set}
			ctx := authz.WithPrincipal(r.Context(), p)
			ctx = context.WithValue(ctx, response.RequestIDKey, "test-rid")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func newTestMux(h *Handler, userID uuid.UUID) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPrincipal(userID, PermRead, PermExecute), h)
	return mux
}

func doJSON(t *testing.T, mux http.Handler, method, url string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, url, bytes.NewReader(raw))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

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

// opsRoutes 全部路由（权限矩阵测试用）。
var opsRoutes = []struct{ method, path string }{
	{http.MethodGet, "/api/v1/api-security/ai-ops/task-types"},
	{http.MethodGet, "/api/v1/api-security/ai-ops/schedules"},
	{http.MethodPost, "/api/v1/api-security/ai-ops/schedules"},
	{http.MethodGet, "/api/v1/api-security/ai-ops/schedules/" + uuid.NewString()},
	{http.MethodPut, "/api/v1/api-security/ai-ops/schedules/" + uuid.NewString()},
	{http.MethodDelete, "/api/v1/api-security/ai-ops/schedules/" + uuid.NewString()},
	{http.MethodPost, "/api/v1/api-security/ai-ops/schedules/" + uuid.NewString() + "/enable"},
	{http.MethodPost, "/api/v1/api-security/ai-ops/schedules/" + uuid.NewString() + "/disable"},
	{http.MethodPost, "/api/v1/api-security/ai-ops/schedules/" + uuid.NewString() + "/run"},
	{http.MethodGet, "/api/v1/api-security/ai-ops/schedules/" + uuid.NewString() + "/runs"},
	{http.MethodGet, "/api/v1/api-security/ai-ops/runs/" + uuid.NewString()},
}

// TestOpsRoutesPermission 未登录 401、无权限 403（权限校验在访问 store 之前，nil store 不触发 panic）。
func TestOpsRoutesPermission(t *testing.T) {
	h := NewHandler(nil, nil)

	muxNoAuth := http.NewServeMux()
	RegisterRoutes(muxNoAuth, func(next http.Handler) http.Handler { return next }, h)
	for _, rt := range opsRoutes {
		rr := doJSON(t, muxNoAuth, rt.method, rt.path, nil)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("no-auth %s %s status=%d", rt.method, rt.path, rr.Code)
		}
	}

	muxNoPerm := http.NewServeMux()
	RegisterRoutes(muxNoPerm, injectPrincipal(uuid.New()), h)
	for _, rt := range opsRoutes {
		rr := doJSON(t, muxNoPerm, rt.method, rt.path, nil)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("no-perm %s %s status=%d", rt.method, rt.path, rr.Code)
		}
	}

	// 只读权限：读接口放行（404/200 而非 403），写接口拒绝（写接口在访问 store 前被拦截，nil store 不触发 panic）
	muxRead := http.NewServeMux()
	RegisterRoutes(muxRead, injectPrincipal(uuid.New(), PermRead), NewHandler(NewMemStore(), nil))
	for _, rt := range opsRoutes {
		rr := doJSON(t, muxRead, rt.method, rt.path, nil)
		if rt.method == http.MethodGet {
			if rr.Code == http.StatusForbidden {
				t.Fatalf("read-perm %s %s should not be 403", rt.method, rt.path)
			}
		} else if rr.Code != http.StatusForbidden {
			t.Fatalf("read-perm %s %s status=%d, want 403", rt.method, rt.path, rr.Code)
		}
	}
}

// createViaAPI 经 HTTP 创建计划并返回 ID。
func createViaAPI(t *testing.T, mux http.Handler, body map[string]any) string {
	t.Helper()
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/ai-ops/schedules", body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	sc, _ := data["schedule"].(map[string]any)
	id, _ := sc["id"].(string)
	if id == "" {
		t.Fatalf("no id in response: %s", rr.Body.String())
	}
	return id
}

func validCreateBody() map[string]any {
	return map[string]any{
		"task_type": TaskRiskDigest, "name": "每日高危摘要", "cron_expr": "0 9 * * *",
		"config": map[string]any{"window_hours": 24, "limit": 20},
	}
}

func TestScheduleCreateValidation(t *testing.T) {
	mux := newTestMux(NewHandler(NewMemStore(), nil), uuid.New())
	bad := []struct {
		name string
		body map[string]any
	}{
		{"非法任务类型", map[string]any{"task_type": "HACK", "name": "x", "cron_expr": "0 9 * * *"}},
		{"空名称", map[string]any{"task_type": TaskRiskDigest, "name": "  ", "cron_expr": "0 9 * * *"}},
		{"非法cron", map[string]any{"task_type": TaskRiskDigest, "name": "x", "cron_expr": "61 * * * *"}},
		{"cron段数不足", map[string]any{"task_type": TaskRiskDigest, "name": "x", "cron_expr": "0 9 * *"}},
		{"非法config键", map[string]any{"task_type": TaskRiskDigest, "name": "x", "cron_expr": "0 9 * * *", "config": map[string]any{"evil": 1}}},
		{"config越界", map[string]any{"task_type": TaskRiskDigest, "name": "x", "cron_expr": "0 9 * * *", "config": map[string]any{"limit": 101}}},
	}
	for _, c := range bad {
		rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/ai-ops/schedules", c.body)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d body=%s", c.name, rr.Code, rr.Body.String())
		}
	}
}

func TestScheduleCRUDFlow(t *testing.T) {
	userID := uuid.New()
	mux := newTestMux(NewHandler(NewMemStore(), nil), userID)

	// 创建（默认停用、无排期游标）
	id := createViaAPI(t, mux, validCreateBody())
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/ai-ops/schedules/"+id, nil)
	data := decodeData(t, rr)
	sc := data["schedule"].(map[string]any)
	if sc["enabled"].(bool) || sc["next_run_at"] != nil {
		t.Fatalf("default should be disabled without cursor: %v", sc)
	}
	if sc["created_by"] != userID.String() {
		t.Fatalf("created_by=%v", sc["created_by"])
	}

	// 创建即启用：带游标
	enBody := validCreateBody()
	enBody["enabled"] = true
	enID := createViaAPI(t, mux, enBody)
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/ai-ops/schedules/"+enID, nil)
	sc = decodeData(t, rr)["schedule"].(map[string]any)
	if !sc["enabled"].(bool) || sc["next_run_at"] == nil {
		t.Fatalf("enabled create should carry cursor: %v", sc)
	}

	// 列表 + 过滤
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/ai-ops/schedules?enabled=true", nil)
	data = decodeData(t, rr)
	if data["total"].(float64) != 1 {
		t.Fatalf("enabled filter total=%v", data["total"])
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/ai-ops/schedules?task_type=BAD", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad task_type filter status=%d", rr.Code)
	}

	// 更新（task_type 不可变；cron 变更对启用中计划重算游标）
	rr = doJSON(t, mux, http.MethodPut, "/api/v1/api-security/ai-ops/schedules/"+id,
		map[string]any{"task_type": TaskShadowReview, "name": "x", "cron_expr": "0 9 * * *"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("task_type change status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodPut, "/api/v1/api-security/ai-ops/schedules/"+enID,
		map[string]any{"name": "改名摘要", "cron_expr": "30 8 * * 1-5", "config": map[string]any{"window_hours": 48}})
	if rr.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", rr.Code, rr.Body.String())
	}
	sc = decodeData(t, rr)["schedule"].(map[string]any)
	if sc["name"] != "改名摘要" || sc["cron_expr"] != "30 8 * * 1-5" || sc["next_run_at"] == nil {
		t.Fatalf("updated: %v", sc)
	}

	// 启停
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/ai-ops/schedules/"+id+"/enable", nil)
	sc = decodeData(t, rr)["schedule"].(map[string]any)
	if !sc["enabled"].(bool) || sc["next_run_at"] == nil {
		t.Fatalf("enable: %v", sc)
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/ai-ops/schedules/"+id+"/disable", nil)
	sc = decodeData(t, rr)["schedule"].(map[string]any)
	if sc["enabled"].(bool) || sc["next_run_at"] != nil {
		t.Fatalf("disable: %v", sc)
	}

	// 删除 → 404
	rr = doJSON(t, mux, http.MethodDelete, "/api/v1/api-security/ai-ops/schedules/"+id, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/ai-ops/schedules/"+id, nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("get deleted status=%d", rr.Code)
	}
	// 不存在 ID 的写操作 → 404
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/ai-ops/schedules/"+uuid.NewString()+"/enable", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("enable missing status=%d", rr.Code)
	}
}

// fakeRunner 测试立即执行器。
type fakeRunner struct {
	run *Run
	err error
	got uuid.UUID
}

func (f *fakeRunner) RunNow(_ context.Context, id uuid.UUID) (*Run, error) {
	f.got = id
	return f.run, f.err
}

func TestRunScheduleEndpoint(t *testing.T) {
	userID := uuid.New()
	store := NewMemStore()

	// 未装配 runner → 503
	mux := newTestMux(NewHandler(store, nil), userID)
	id := createViaAPI(t, mux, validCreateBody())
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/ai-ops/schedules/"+id+"/run", nil)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no runner status=%d", rr.Code)
	}

	// 开关关闭 → 503；冲突 → 409；成功 → 200 且返回执行记录
	h := NewHandler(store, nil).SetRunner(&fakeRunner{err: ErrSchedulesDisabled})
	mux = newTestMux(h, userID)
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/ai-ops/schedules/"+id+"/run", nil)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled status=%d", rr.Code)
	}

	h.SetRunner(&fakeRunner{err: ErrRunConflict})
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/ai-ops/schedules/"+id+"/run", nil)
	if rr.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d", rr.Code)
	}

	finished := time.Now()
	okRunner := &fakeRunner{run: &Run{ID: uuid.New(), ScheduleID: uuid.MustParse(id), Status: RunStatusSuccess,
		Summary: "摘要", Report: json.RawMessage(`{"open_high_total":8}`), StartedAt: finished, FinishedAt: &finished}}
	h.SetRunner(okRunner)
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/ai-ops/schedules/"+id+"/run", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("run status=%d body=%s", rr.Code, rr.Body.String())
	}
	run := decodeData(t, rr)["run"].(map[string]any)
	if run["status"] != RunStatusSuccess || run["summary"] != "摘要" {
		t.Fatalf("run: %v", run)
	}
	if okRunner.got.String() != id {
		t.Fatalf("runner got id=%s", okRunner.got)
	}

	// 计划不存在 → 404（runner 返回 NotFound 透传）
	h.SetRunner(&fakeRunner{err: ErrScheduleNotFound})
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/ai-ops/schedules/"+id+"/run", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("notfound status=%d", rr.Code)
	}
}

func TestRunsEndpoints(t *testing.T) {
	userID := uuid.New()
	store := NewMemStore()
	mux := newTestMux(NewHandler(store, nil), userID)
	id := createViaAPI(t, mux, validCreateBody())

	// 空列表
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/ai-ops/schedules/"+id+"/runs", nil)
	data := decodeData(t, rr)
	if data["total"].(float64) != 0 {
		t.Fatalf("empty runs total=%v", data["total"])
	}
	// 不存在计划的 runs → 404
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/ai-ops/schedules/"+uuid.NewString()+"/runs", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("runs of missing schedule status=%d", rr.Code)
	}

	// 造一条已终结执行记录（经 store 直造，handler 只读展示）
	run := &Run{ScheduleID: uuid.MustParse(id), StartedAt: time.Now()}
	if err := store.CreateRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishRun(context.Background(), run.ID, RunStatusSuccess, "完成", json.RawMessage(`{"a":1}`), time.Now()); err != nil {
		t.Fatal(err)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/ai-ops/schedules/"+id+"/runs", nil)
	data = decodeData(t, rr)
	if data["total"].(float64) != 1 {
		t.Fatalf("runs total=%v", data["total"])
	}
	// 详情
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/ai-ops/runs/"+run.ID.String(), nil)
	got := decodeData(t, rr)["run"].(map[string]any)
	if got["status"] != RunStatusSuccess || got["summary"] != "完成" {
		t.Fatalf("run detail: %v", got)
	}
	report, _ := got["report"].(map[string]any)
	if report["a"].(float64) != 1 {
		t.Fatalf("report: %v", got["report"])
	}
	// 详情 404
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/ai-ops/runs/"+uuid.NewString(), nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing run status=%d", rr.Code)
	}
}

func TestListTaskTypes(t *testing.T) {
	mux := newTestMux(NewHandler(NewMemStore(), nil), uuid.New())
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/ai-ops/task-types", nil)
	data := decodeData(t, rr)
	items, _ := data["items"].([]any)
	if len(items) != 5 {
		t.Fatalf("task types=%d, want 5", len(items))
	}
	first, _ := items[0].(map[string]any)
	if first["task_type"] == "" || first["name"] == "" || !strings.Contains(first["description"].(string), "") {
		t.Fatalf("task type meta: %v", first)
	}
}
