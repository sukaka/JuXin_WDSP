// handler_test.go 主动扫描 handler 测试（MemStore 驱动真实 Handler）：
// 权限点矩阵、参数校验、双人分离、开关拒绝、发现处置状态机、复测桥接、紧急停止。
package apiscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiweakness"
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
	RegisterRoutes(mux, injectPrincipal(userID, PermRead, PermExecute, PermManage), h)
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

// scanRoutes 全部路由（权限矩阵测试用）。
var scanRoutes = []struct{ method, path string }{
	{http.MethodGet, "/api/v1/api-security/scans/targets"},
	{http.MethodPost, "/api/v1/api-security/scans/targets"},
	{http.MethodGet, "/api/v1/api-security/scans/targets/" + uuid.NewString()},
	{http.MethodPut, "/api/v1/api-security/scans/targets/" + uuid.NewString()},
	{http.MethodPost, "/api/v1/api-security/scans/targets/" + uuid.NewString() + "/authorize"},
	{http.MethodGet, "/api/v1/api-security/scans/targets/" + uuid.NewString() + "/authorizations"},
	{http.MethodPost, "/api/v1/api-security/scans/authorizations/" + uuid.NewString() + "/revoke"},
	{http.MethodGet, "/api/v1/api-security/scans/jobs"},
	{http.MethodPost, "/api/v1/api-security/scans/jobs"},
	{http.MethodGet, "/api/v1/api-security/scans/jobs/" + uuid.NewString()},
	{http.MethodPost, "/api/v1/api-security/scans/jobs/" + uuid.NewString() + "/start"},
	{http.MethodPost, "/api/v1/api-security/scans/jobs/" + uuid.NewString() + "/stop"},
	{http.MethodPost, "/api/v1/api-security/scans/jobs/" + uuid.NewString() + "/emergency-stop"},
	{http.MethodGet, "/api/v1/api-security/scans/findings"},
	{http.MethodPost, "/api/v1/api-security/scans/findings/" + uuid.NewString() + "/confirm"},
	{http.MethodPost, "/api/v1/api-security/scans/findings/" + uuid.NewString() + "/false-positive"},
	{http.MethodPost, "/api/v1/api-security/scans/findings/" + uuid.NewString() + "/retest"},
}

// TestScanRoutesPermission 未登录 401、无权限 403（权限校验在访问 store 之前，nil store 不触发 panic）。
func TestScanRoutesPermission(t *testing.T) {
	h := NewHandler(nil, nil)

	muxNoAuth := http.NewServeMux()
	RegisterRoutes(muxNoAuth, func(next http.Handler) http.Handler { return next }, h)
	for _, rt := range scanRoutes {
		rr := doJSON(t, muxNoAuth, rt.method, rt.path, nil)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("no-auth %s %s status=%d", rt.method, rt.path, rr.Code)
		}
	}

	muxNoPerm := http.NewServeMux()
	RegisterRoutes(muxNoPerm, injectPrincipal(uuid.New()), h) // 无任何权限点
	for _, rt := range scanRoutes {
		rr := doJSON(t, muxNoPerm, rt.method, rt.path, nil)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("no-perm %s %s status=%d", rt.method, rt.path, rr.Code)
		}
	}
}

// TestCreateTargetValidation 目标创建参数校验。
func TestCreateTargetValidation(t *testing.T) {
	h := NewHandler(NewMemStore(), nil)
	mux := newTestMux(h, uuid.New())

	cases := []struct {
		name string
		body map[string]any
	}{
		{"缺 application_id", map[string]any{"name": "x", "base_url": "http://a.com"}},
		{"缺 name", map[string]any{"application_id": uuid.NewString(), "base_url": "http://a.com"}},
		{"非法 base_url", map[string]any{"application_id": uuid.NewString(), "name": "x", "base_url": "ftp://a.com"}},
		{"base_url 无主机", map[string]any{"application_id": uuid.NewString(), "name": "x", "base_url": "http://"}},
		{"路径不带斜杠", map[string]any{"application_id": uuid.NewString(), "name": "x", "base_url": "http://a.com", "allowed_paths": []string{"abc"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/scans/targets", c.body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}

	// 合法创建
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/scans/targets", map[string]any{
		"application_id": uuid.NewString(), "name": "测试目标",
		"base_url": "http://127.0.0.1:8080", "allowed_paths": []string{"/v1/users"},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
}

// TestAuthorizeSeparationOfDuty 双人分离：建标人签发授权被拒（403），他人可签。
func TestAuthorizeSeparationOfDuty(t *testing.T) {
	store := NewMemStore()
	h := NewHandler(store, nil)
	creator := uuid.New()
	other := uuid.New()

	muxCreator := newTestMux(h, creator)
	rr := doJSON(t, muxCreator, http.MethodPost, "/api/v1/api-security/scans/targets", map[string]any{
		"application_id": uuid.NewString(), "name": "目标A", "base_url": "http://a.com",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d", rr.Code)
	}
	target := decodeData(t, rr)["target"].(map[string]any)
	targetID := target["id"].(string)

	validBody := map[string]any{"expires_at": time.Now().Add(time.Hour)}
	// 建标人自签 → 403
	rr = doJSON(t, muxCreator, http.MethodPost, "/api/v1/api-security/scans/targets/"+targetID+"/authorize", validBody)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("self-authorize status=%d", rr.Code)
	}
	// 他人签发 → 201
	muxOther := newTestMux(h, other)
	rr = doJSON(t, muxOther, http.MethodPost, "/api/v1/api-security/scans/targets/"+targetID+"/authorize", validBody)
	if rr.Code != http.StatusCreated {
		t.Fatalf("authorize status=%d body=%s", rr.Code, rr.Body.String())
	}
	// 过期时间非法 → 400
	rr = doJSON(t, muxOther, http.MethodPost, "/api/v1/api-security/scans/targets/"+targetID+"/authorize",
		map[string]any{"expires_at": time.Now().Add(-time.Hour)})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("past expires_at status=%d", rr.Code)
	}
	// 画像词表外 → 400
	rr = doJSON(t, muxOther, http.MethodPost, "/api/v1/api-security/scans/targets/"+targetID+"/authorize",
		map[string]any{"expires_at": time.Now().Add(time.Hour), "test_profile": "FUZZ"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad profile status=%d", rr.Code)
	}
}

// TestAuthorizeFailClosedNilCreator 双人分离 fail-closed：目标缺建标人信息时
// 无法完成校验，必须拒绝授权（403 中文说明），不得跳过检查放行。
func TestAuthorizeFailClosedNilCreator(t *testing.T) {
	store := NewMemStore()
	// 直接落库一个 CreatedBy 为 nil 的目标（绕过 CreateTarget 的建标人回填）
	target := &Target{
		ApplicationID: uuid.New(), Name: "历史目标", BaseURL: "http://a.com",
		Status: TargetStatusEnabled,
	}
	if err := store.CreateTarget(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(store, nil)
	mux := newTestMux(h, uuid.New())

	rr := doJSON(t, mux, http.MethodPost,
		"/api/v1/api-security/scans/targets/"+target.ID.String()+"/authorize",
		map[string]any{"expires_at": time.Now().Add(time.Hour)})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("nil creator authorize status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "目标缺少建标人信息") {
		t.Fatalf("body=%s", rr.Body.String())
	}
	// 副作用确认：未签发任何授权单
	if _, total, err := store.ListAuthorizations(context.Background(), target.ID, 1, 10); err != nil || total != 0 {
		t.Fatalf("authorizations total=%d err=%v", total, err)
	}
}

// setupTargetAuthz 预置目标（creator 建）+授权（other 签），返回 (targetID, authzID)。
func setupTargetAuthz(t *testing.T, store *MemStore) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	target := &Target{
		ApplicationID: uuid.New(), Name: "目标", BaseURL: "http://127.0.0.1:8080",
		AllowedPaths: []string{"/open"}, Status: TargetStatusEnabled,
	}
	creator := uuid.New()
	target.CreatedBy = &creator
	if err := store.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	authz := &Authorization{
		TargetID: target.ID, AuthorizedBy: uuid.New(),
		MaxQPS: 5, MaxConcurrency: 1, ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := store.CreateAuthorization(ctx, authz); err != nil {
		t.Fatal(err)
	}
	return target.ID, authz.ID
}

// TestCreateJobSwitchAndValidation 任务发起：开关关闭 403；非法探针集 400；授权无效 400；合法 201。
func TestCreateJobSwitchAndValidation(t *testing.T) {
	store := NewMemStore()
	targetID, authzID := setupTargetAuthz(t, store)

	// 开关关闭 → 403
	hOff := NewHandler(store, nil).SetSettings(fakeSettings{enabled: false})
	muxOff := newTestMux(hOff, uuid.New())
	rr := doJSON(t, muxOff, http.MethodPost, "/api/v1/api-security/scans/jobs", map[string]any{
		"target_id": targetID.String(), "authorization_id": authzID.String(),
	})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("disabled create status=%d", rr.Code)
	}

	h := NewHandler(store, nil).SetSettings(fakeSettings{enabled: true})
	mux := newTestMux(h, uuid.New())
	// 词表外探针集 → 400
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/scans/jobs", map[string]any{
		"target_id": targetID.String(), "authorization_id": authzID.String(), "probe_set": "DELETE_ALL",
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad probe set status=%d", rr.Code)
	}
	// 授权不属于目标 → 400
	_, otherAuthz := setupTargetAuthz(t, store)
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/scans/jobs", map[string]any{
		"target_id": targetID.String(), "authorization_id": otherAuthz.String(),
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("mismatched authz status=%d", rr.Code)
	}
	// 合法 → 201
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/scans/jobs", map[string]any{
		"target_id": targetID.String(), "authorization_id": authzID.String(),
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create job status=%d body=%s", rr.Code, rr.Body.String())
	}
	job := decodeData(t, rr)["job"].(map[string]any)
	if job["status"] != JobStatusPending {
		t.Fatalf("job=%v", job)
	}
	// 默认探针集 = 全部内置
	if job["probe_set"] == "" {
		t.Fatal("probe_set should default to all probe sets")
	}
}

// TestFindingDisposal 发现处置：NEW→CONFIRMED（关联弱点）/FALSE_POSITIVE；重复处置 400。
func TestFindingDisposal(t *testing.T) {
	store := NewMemStore()
	targetID, authzID := setupTargetAuthz(t, store)
	ctx := context.Background()
	job := &Job{TargetID: targetID, AuthorizationID: authzID}
	if err := store.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	finding := &Finding{
		JobID: job.ID, Template: ProbeAuthRequired, EndpointKey: "GET /open",
		Category: CategoryAuthn, Severity: SeverityHigh,
	}
	if err := store.CreateFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}

	h := NewHandler(store, nil)
	mux := newTestMux(h, uuid.New())
	base := "/api/v1/api-security/scans/findings/" + finding.ID.String()

	// 确认并关联弱点
	weaknessID := uuid.NewString()
	rr := doJSON(t, mux, http.MethodPost, base+"/confirm", map[string]any{"weakness_id": weaknessID})
	if rr.Code != http.StatusOK {
		t.Fatalf("confirm status=%d body=%s", rr.Code, rr.Body.String())
	}
	got := decodeData(t, rr)["finding"].(map[string]any)
	if got["status"] != FindingStatusConfirmed || got["weakness_id"] != weaknessID {
		t.Fatalf("finding=%v", got)
	}
	// 重复处置 → 400
	rr = doJSON(t, mux, http.MethodPost, base+"/false-positive", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("re-dispose status=%d", rr.Code)
	}
	// 非法 weakness_id → 400
	f2 := &Finding{JobID: job.ID, Template: ProbeMethodEnum, EndpointKey: "OPTIONS /open"}
	if err := store.CreateFinding(ctx, f2); err != nil {
		t.Fatal(err)
	}
	rr = doJSON(t, mux, http.MethodPost,
		"/api/v1/api-security/scans/findings/"+f2.ID.String()+"/confirm", map[string]any{"weakness_id": "not-uuid"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad weakness_id status=%d", rr.Code)
	}
	// 误报
	rr = doJSON(t, mux, http.MethodPost,
		"/api/v1/api-security/scans/findings/"+f2.ID.String()+"/false-positive", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("false-positive status=%d", rr.Code)
	}
}

// fakeEngine 复测用引擎替身（reproduce=true 时重放一条同探针发现；
// runs 非 nil 时记录 Run 调用次数，用于验证发包前校验零探测流量）。
type fakeEngine struct {
	reproduce bool
	runs      *int
}

func (f fakeEngine) ProbeSets() []string { return AllProbeSets() }

func (f fakeEngine) Run(_ context.Context, task *ProbeTask, emit func(*ProbeResult) error) (RunSummary, error) {
	if f.runs != nil {
		*f.runs++
	}
	if f.reproduce {
		if err := emit(&ProbeResult{
			Template: task.ProbeSets[0], EndpointKey: "GET " + task.Paths[0],
			Category: CategoryAuthn, Severity: SeverityHigh, Evidence: map[string]any{"rule": "replay"},
		}); err != nil {
			return RunSummary{}, err
		}
	}
	return RunSummary{EndpointsDone: len(task.Paths), Requests: len(task.Paths)}, nil
}

// fakeRetestWriter 弱点复测回写替身（status/statusErr 控制发包前状态预检结果，
// 默认返回 FIXED 让流程走到真实发包）。
type fakeRetestWriter struct {
	calls     int
	pass      bool
	err       error
	status    string
	statusErr error
}

func (f *fakeRetestWriter) RetestWeakness(_ context.Context, _ uuid.UUID, pass bool, _, _ string) error {
	f.calls++
	f.pass = pass
	return f.err
}

func (f *fakeRetestWriter) WeaknessStatus(_ context.Context, _ uuid.UUID) (string, error) {
	if f.statusErr != nil {
		return "", f.statusErr
	}
	if f.status == "" {
		return apiweakness.StatusFixed, nil
	}
	return f.status, nil
}

// setupRetestFinding 预置复测场景（目标/授权/任务/关联弱点的发现）。
func setupRetestFinding(t *testing.T, store *MemStore) (*Finding, *Authorization) {
	t.Helper()
	targetID, authzID := setupTargetAuthz(t, store)
	ctx := context.Background()
	authz, err := store.GetAuthorization(ctx, authzID)
	if err != nil {
		t.Fatal(err)
	}
	job := &Job{TargetID: targetID, AuthorizationID: authzID, Status: JobStatusCompleted}
	if err := store.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	weaknessID := uuid.New()
	finding := &Finding{
		JobID: job.ID, Template: ProbeAuthRequired, EndpointKey: "GET /open",
		Category: CategoryAuthn, Severity: SeverityHigh, Status: FindingStatusConfirmed,
		WeaknessID: &weaknessID,
	}
	if err := store.CreateFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	return finding, authz
}

// TestRetestFinding 复测桥接：复现 → RETEST_FAIL；未复现 → RETEST_PASS；
// 未关联弱点 400；回写失败如实报错（不伪造结论）；未装配 503。
func TestRetestFinding(t *testing.T) {
	store := NewMemStore()
	finding, _ := setupRetestFinding(t, store)
	base := "/api/v1/api-security/scans/findings/" + finding.ID.String() + "/retest"

	// 未装配 → 503
	hNoEngine := NewHandler(store, nil).SetSettings(fakeSettings{enabled: true})
	rr := doJSON(t, newTestMux(hNoEngine, uuid.New()), http.MethodPost, base, nil)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("not assembled status=%d", rr.Code)
	}

	// 复现 → FAIL 回写
	writer := &fakeRetestWriter{}
	h := NewHandler(store, nil).SetSettings(fakeSettings{enabled: true})
	h.SetRetest(fakeEngine{reproduce: true}, nil, writer)
	rr = doJSON(t, newTestMux(h, uuid.New()), http.MethodPost, base, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("retest status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	if data["result"] != RetestResultFail || data["reproduced"] != true {
		t.Fatalf("data=%v", data)
	}
	if writer.calls != 1 || writer.pass {
		t.Fatalf("writer=%+v", writer)
	}

	// 未复现 → PASS 回写
	h2 := NewHandler(store, nil).SetSettings(fakeSettings{enabled: true})
	h2.SetRetest(fakeEngine{reproduce: false}, nil, writer)
	rr = doJSON(t, newTestMux(h2, uuid.New()), http.MethodPost, base, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("retest2 status=%d", rr.Code)
	}
	if decodeData(t, rr)["result"] != RetestResultPass || !writer.pass {
		t.Fatalf("writer=%+v", writer)
	}

	// 回写失败（弱点非 FIXED 等）→ 400 如实报错
	badWriter := &fakeRetestWriter{err: errors.New("invalid weakness status transition: ARCHIVED 状态不允许 RETEST_PASS")}
	h3 := NewHandler(store, nil).SetSettings(fakeSettings{enabled: true})
	h3.SetRetest(fakeEngine{reproduce: false}, nil, badWriter)
	rr = doJSON(t, newTestMux(h3, uuid.New()), http.MethodPost, base, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("writeback failure status=%d", rr.Code)
	}

	// 未关联弱点 → 400
	ctx := context.Background()
	noWeakness := &Finding{JobID: finding.JobID, Template: ProbeAuthRequired, EndpointKey: "GET /open"}
	if err := store.CreateFinding(ctx, noWeakness); err != nil {
		t.Fatal(err)
	}
	rr = doJSON(t, newTestMux(h2, uuid.New()), http.MethodPost,
		"/api/v1/api-security/scans/findings/"+noWeakness.ID.String()+"/retest", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("no weakness status=%d", rr.Code)
	}
}

// TestRetestValidationBeforeProbe 复测校验顺序：note 超长、弱点非 FIXED、弱点不存在
// 均为必败请求，必须在真实发包前被拒（引擎零调用，不产生探测流量）。
func TestRetestValidationBeforeProbe(t *testing.T) {
	store := NewMemStore()
	finding, _ := setupRetestFinding(t, store)
	base := "/api/v1/api-security/scans/findings/" + finding.ID.String() + "/retest"

	newMux := func(writer *fakeRetestWriter, runs *int) *http.ServeMux {
		h := NewHandler(store, nil).SetSettings(fakeSettings{enabled: true})
		h.SetRetest(fakeEngine{reproduce: true, runs: runs}, nil, writer)
		return newTestMux(h, uuid.New())
	}

	// note 超长 → 400，且未查弱点状态、未发包
	var runs int
	writer := &fakeRetestWriter{}
	rr := doJSON(t, newMux(writer, &runs), http.MethodPost, base,
		map[string]any{"note": strings.Repeat("注", 513)})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("long note status=%d body=%s", rr.Code, rr.Body.String())
	}
	if runs != 0 || writer.calls != 0 {
		t.Fatalf("long note should not probe: runs=%d writeback=%d", runs, writer.calls)
	}

	// 弱点非 FIXED → 400，未发包、未回写
	runs = 0
	writer = &fakeRetestWriter{status: apiweakness.StatusReproduced}
	rr = doJSON(t, newMux(writer, &runs), http.MethodPost, base, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("non-fixed status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "仅 FIXED") {
		t.Fatalf("body=%s", rr.Body.String())
	}
	if runs != 0 || writer.calls != 0 {
		t.Fatalf("non-fixed should not probe: runs=%d writeback=%d", runs, writer.calls)
	}

	// 弱点不存在 → 400，未发包、未回写
	runs = 0
	writer = &fakeRetestWriter{statusErr: apiweakness.ErrNotFound}
	rr = doJSON(t, newMux(writer, &runs), http.MethodPost, base, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing weakness status=%d body=%s", rr.Code, rr.Body.String())
	}
	if runs != 0 || writer.calls != 0 {
		t.Fatalf("missing weakness should not probe: runs=%d writeback=%d", runs, writer.calls)
	}

	// 对照：弱点 FIXED 时正常发包并回写（确认前置校验不误伤合法请求）
	runs = 0
	writer = &fakeRetestWriter{status: apiweakness.StatusFixed}
	rr = doJSON(t, newMux(writer, &runs), http.MethodPost, base, nil)
	if rr.Code != http.StatusOK || runs != 1 || writer.calls != 1 {
		t.Fatalf("fixed retest status=%d runs=%d writeback=%d", rr.Code, runs, writer.calls)
	}
}

// TestEmergencyStopRequiresExecute 紧急停止副作用含撤销授权（revoke 超集），
// 必须挂 execute 权限点：仅持 manage 的主体调用被拒（403），execute 主体可过权限层。
func TestEmergencyStopRequiresExecute(t *testing.T) {
	h := NewHandler(NewMemStore(), nil)
	jobID := uuid.NewString()
	stopPath := "/api/v1/api-security/scans/jobs/" + jobID

	// 仅 manage：emergency-stop 403（权限倒挂已修复），普通 stop 不受限（404 任务不存在）
	muxManage := http.NewServeMux()
	RegisterRoutes(muxManage, injectPrincipal(uuid.New(), PermRead, PermManage), h)
	if rr := doJSON(t, muxManage, http.MethodPost, stopPath+"/emergency-stop", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("manage-only emergency-stop status=%d", rr.Code)
	}
	if rr := doJSON(t, muxManage, http.MethodPost, stopPath+"/stop", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("manage-only stop status=%d", rr.Code)
	}

	// 仅 execute：emergency-stop 通过权限层（404 任务不存在而非 403）
	muxExecute := http.NewServeMux()
	RegisterRoutes(muxExecute, injectPrincipal(uuid.New(), PermRead, PermExecute), h)
	if rr := doJSON(t, muxExecute, http.MethodPost, stopPath+"/emergency-stop", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("execute emergency-stop status=%d", rr.Code)
	}
}

// TestEmergencyStopEndpoint 紧急停止接口：任务停止 + 授权撤销 + 审计留痕。
func TestEmergencyStopEndpoint(t *testing.T) {
	store := NewMemStore()
	targetID, authzID := setupTargetAuthz(t, store)
	ctx := context.Background()
	job := &Job{TargetID: targetID, AuthorizationID: authzID}
	if err := store.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}

	spy := &spyAudits{}
	worker := NewWorker(store, NewBuiltinEngine(nil), nil, fakeSettings{enabled: true}, nil)
	h := &Handler{store: store, audits: spy, controller: worker}
	mux := newTestMux(h, uuid.New())

	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/scans/jobs/"+job.ID.String()+"/emergency-stop", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("emergency-stop status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	if data["stopped_jobs"].(float64) != 1 {
		t.Fatalf("data=%v", data)
	}
	// 授权已撤销、任务已停止
	a, _ := store.GetAuthorization(ctx, authzID)
	if a.RevokedAt == nil {
		t.Fatal("authorization not revoked")
	}
	j, _ := store.GetJob(ctx, job.ID)
	if j.Status != JobStatusStopped {
		t.Fatalf("job status=%s", j.Status)
	}
	// 审计留痕（紧急停止是高危操作，必须落审计）
	found := false
	for _, e := range spy.entries {
		if e.Action == "scan_emergency_stop" {
			found = true
		}
	}
	if !found {
		t.Fatalf("emergency stop audit not recorded: %+v", spy.entries)
	}
}

// TestStopJobEndpoint 停止接口：PENDING → STOPPED；终态 → 400。
func TestStopJobEndpoint(t *testing.T) {
	store := NewMemStore()
	targetID, authzID := setupTargetAuthz(t, store)
	ctx := context.Background()
	job := &Job{TargetID: targetID, AuthorizationID: authzID}
	if err := store.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	worker := NewWorker(store, NewBuiltinEngine(nil), nil, fakeSettings{enabled: true}, nil)
	h := NewHandler(store, nil).SetController(worker)
	mux := newTestMux(h, uuid.New())

	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/scans/jobs/"+job.ID.String()+"/stop", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("stop status=%d", rr.Code)
	}
	if decodeData(t, rr)["job"].(map[string]any)["status"] != JobStatusStopped {
		t.Fatal("job not stopped")
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/scans/jobs/"+job.ID.String()+"/stop", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("stop terminal status=%d", rr.Code)
	}
}

// TestRevokeEndpoint 撤销授权接口：撤销即停（排队任务联动停止）。
func TestRevokeEndpoint(t *testing.T) {
	store := NewMemStore()
	_, authzID := setupTargetAuthz(t, store)
	worker := NewWorker(store, NewBuiltinEngine(nil), nil, fakeSettings{enabled: true}, nil)
	h := NewHandler(store, nil).SetController(worker)
	mux := newTestMux(h, uuid.New())

	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/scans/authorizations/"+authzID.String()+"/revoke", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke status=%d", rr.Code)
	}
	a, _ := store.GetAuthorization(context.Background(), authzID)
	if a.RevokedAt == nil {
		t.Fatal("not revoked")
	}
	// 幂等：再次撤销仍 200
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/scans/authorizations/"+authzID.String()+"/revoke", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("re-revoke status=%d", rr.Code)
	}
}

// TestStartJobEndpoint 启动接口：PENDING 任务后台执行至完成。
func TestStartJobEndpoint(t *testing.T) {
	store := NewMemStore()
	targetID, authzID := setupTargetAuthz(t, store)
	ctx := context.Background()
	// 指向本地不可达地址：执行会失败（FAILED），但启动语义可验证
	target, _ := store.GetTarget(ctx, targetID)
	target.BaseURL = "http://127.0.0.1:9"
	if err := store.UpdateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	job := &Job{TargetID: targetID, AuthorizationID: authzID}
	if err := store.CreateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	worker := NewWorker(store, NewBuiltinEngine(nil), nil, fakeSettings{enabled: true}, nil)
	h := NewHandler(store, nil).SetController(worker)
	mux := newTestMux(h, uuid.New())

	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/scans/jobs/"+job.ID.String()+"/start", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("start status=%d body=%s", rr.Code, rr.Body.String())
	}
	// 后台执行至终结（连接失败 → FAILED；轮询等待）
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		j, _ := store.GetJob(ctx, job.ID)
		if j.Terminal() {
			if j.Status != JobStatusFailed || j.Progress.LastError == "" {
				t.Fatalf("job=%+v", j)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("job did not finish in time")
}
