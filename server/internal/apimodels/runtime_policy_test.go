// runtime_policy_test.go 运行时策略接口组测试（httptest + fake RuntimePolicyStore，不依赖数据库）：
// 路由权限校验（401/403）、参数校验、回滚状态机语义（404/409/503/成功路径）。
package apimodels

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// runtimePerms 本测试覆盖的权限点（读 + 激活/回滚）。
var runtimePerms = []string{"api_model.read", "api_model.activate"}

// injectRuntimePrincipal 模拟认证链：注入持有权限点的主体与 Request ID。
func injectRuntimePrincipal(next http.Handler) http.Handler {
	perms := map[string]bool{}
	for _, p := range runtimePerms {
		perms[p] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: perms}
		ctx := authz.WithPrincipal(r.Context(), p)
		ctx = context.WithValue(ctx, response.RequestIDKey, "test-rid")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// fakeRuntimeStore 内存版 RuntimePolicyStore（记录调用，可注入错误路径）。
type fakeRuntimeStore struct {
	list           []RuntimePolicy
	total          int64
	byModel        []RuntimePolicy
	byID           *RuntimePolicy
	listErr        error
	getErr         error
	rollbackOut    *RuntimePolicyRollback
	rollbackErr    error
	lastFilter     RuntimePolicyFilter
	rollbackCalls  int
	lastOperator   uuid.UUID
	markCalls      int
	lastMarkID     uuid.UUID
	lastMarkReason string
	markErr        error
	seq            []string // 调用顺序（内容源一致性：模型恢复必先于发布触发）
}

func (f *fakeRuntimeStore) ListRuntimePolicies(ctx context.Context, filter RuntimePolicyFilter) ([]RuntimePolicy, int64, error) {
	_ = ctx
	f.lastFilter = filter
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	return f.list, f.total, nil
}

func (f *fakeRuntimeStore) ListRuntimePoliciesByModel(ctx context.Context, modelVersionID uuid.UUID) ([]RuntimePolicy, error) {
	_ = ctx
	_ = modelVersionID
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.byModel, nil
}

func (f *fakeRuntimeStore) GetRuntimePolicyByID(ctx context.Context, id uuid.UUID) (*RuntimePolicy, error) {
	_ = ctx
	_ = id
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.byID, nil
}

func (f *fakeRuntimeStore) RollbackToKnownGood(ctx context.Context, id, operatorID uuid.UUID) (*RuntimePolicyRollback, error) {
	_ = ctx
	_ = id
	f.rollbackCalls++
	f.lastOperator = operatorID
	f.seq = append(f.seq, "rollback")
	if f.rollbackErr != nil {
		return nil, f.rollbackErr
	}
	return f.rollbackOut, nil
}

func (f *fakeRuntimeStore) MarkRuntimePolicyFailed(ctx context.Context, id uuid.UUID, reason string) error {
	_ = ctx
	f.markCalls++
	f.lastMarkID = id
	f.lastMarkReason = reason
	return f.markErr
}

func newRuntimeTestMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectRuntimePrincipal, h)
	return mux
}

func doRuntimeReq(t *testing.T, mux http.Handler, method, url string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, url, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func decodeRuntimeData(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
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

func testPolicy(status string) *RuntimePolicy {
	now := time.Now()
	return &RuntimePolicy{
		ID: uuid.New(), EndpointID: uuid.New(), EndpointKey: "POST /v1/orders/{id}",
		SourceModelVersionID: uuid.New(), RuntimeVersion: "v2", CompilerVersion: CompilerVersion,
		Content: json.RawMessage(`{"endpoint_key":"POST /v1/orders/{id}"}`), ContentHash: "abc",
		Status: status, CreatedAt: now, ActivatedAt: &now,
	}
}

// TestRuntimePolicyRoutesPermission 未登录 401、无权限 403（列表/溯源/回滚三路由）。
func TestRuntimePolicyRoutesPermission(t *testing.T) {
	h := NewHandler(nil, nil)
	targets := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/api-security/runtime-policies"},
		{http.MethodGet, "/api/v1/api-security/models/" + uuid.NewString() + "/runtime"},
		{http.MethodPost, "/api/v1/api-security/runtime-policies/" + uuid.NewString() + "/rollback"},
	}
	muxNoAuth := http.NewServeMux()
	RegisterRoutes(muxNoAuth, func(next http.Handler) http.Handler { return next }, h)
	for _, tg := range targets {
		if rr := doRuntimeReq(t, muxNoAuth, tg.method, tg.path); rr.Code != http.StatusUnauthorized {
			t.Fatalf("no-auth %s %s status=%d", tg.method, tg.path, rr.Code)
		}
	}
	muxNoPerm := http.NewServeMux()
	RegisterRoutes(muxNoPerm, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "nobody", PermsSet: map[string]bool{}}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}, h)
	for _, tg := range targets {
		if rr := doRuntimeReq(t, muxNoPerm, tg.method, tg.path); rr.Code != http.StatusForbidden {
			t.Fatalf("no-perm %s %s status=%d", tg.method, tg.path, rr.Code)
		}
	}
}

// TestListRuntimePolicies 列表：状态白名单校验、过滤透传、分页响应；存储错误 500。
func TestListRuntimePolicies(t *testing.T) {
	fs := &fakeRuntimeStore{list: []RuntimePolicy{*testPolicy(PolicyStatusActive)}, total: 1}
	h := NewHandler(nil, nil)
	h.SetRuntimePolicyStore(fs)
	mux := newRuntimeTestMux(h)

	// 非法 status → 400（白名单校验在访问存储之前）
	if rr := doRuntimeReq(t, mux, http.MethodGet, "/api/v1/api-security/runtime-policies?status=BOGUS"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad status=%d", rr.Code)
	}
	// 非法 endpoint_id → 400
	if rr := doRuntimeReq(t, mux, http.MethodGet, "/api/v1/api-security/runtime-policies?endpoint_id=bad"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad endpoint_id=%d", rr.Code)
	}
	// 合法过滤透传 + 分页响应
	endpointID := uuid.New()
	rr := doRuntimeReq(t, mux, http.MethodGet,
		"/api/v1/api-security/runtime-policies?endpoint_id="+endpointID.String()+"&status=ACTIVE&page=2&page_size=5")
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rr.Code, rr.Body.String())
	}
	if fs.lastFilter.Status != PolicyStatusActive || fs.lastFilter.EndpointID == nil ||
		*fs.lastFilter.EndpointID != endpointID || fs.lastFilter.Page != 2 || fs.lastFilter.PageSize != 5 {
		t.Fatalf("filter = %+v", fs.lastFilter)
	}
	data := decodeRuntimeData(t, rr)
	if data["total"].(float64) != 1 {
		t.Fatalf("total = %v", data)
	}
	// 存储错误 → 500（不静默）
	fs.listErr = errors.New("db down")
	if rr := doRuntimeReq(t, mux, http.MethodGet, "/api/v1/api-security/runtime-policies"); rr.Code != http.StatusInternalServerError {
		t.Fatalf("list err status=%d", rr.Code)
	}
}

// TestGetModelRuntimePolicies 模型 → 策略溯源：非法 ID 400；成功返回 items。
func TestGetModelRuntimePolicies(t *testing.T) {
	fs := &fakeRuntimeStore{byModel: []RuntimePolicy{*testPolicy(PolicyStatusRolledBack)}}
	h := NewHandler(nil, nil)
	h.SetRuntimePolicyStore(fs)
	mux := newRuntimeTestMux(h)

	if rr := doRuntimeReq(t, mux, http.MethodGet, "/api/v1/api-security/models/bad/runtime"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad id status=%d", rr.Code)
	}
	rr := doRuntimeReq(t, mux, http.MethodGet, "/api/v1/api-security/models/"+uuid.NewString()+"/runtime")
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeRuntimeData(t, rr)
	items, ok := data["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("items = %v", data)
	}
	if items[0].(map[string]any)["runtime_version"] != "v2" {
		t.Fatalf("item = %v", items[0])
	}
}

// TestRollbackRuntimePolicy 回滚：404/409（无良好版本/状态不允许/模型不可恢复）/503（未接发布）/
// 成功路径（内容源一致性：模型恢复先于发布触发、草稿内容源=恢复模型）/发布失败路径（孤儿 DRAFT 兜底 + 502）。
func TestRollbackRuntimePolicy(t *testing.T) {
	newMuxWith := func(fs *fakeRuntimeStore, publishFn RuntimePolicyPublishFunc) *http.ServeMux {
		h := NewHandler(nil, nil) // 无审计服务：recordAuditOutcome 应安全跳过
		h.SetRuntimePolicyStore(fs)
		h.SetRuntimePolicyPublishFunc(publishFn)
		return newRuntimeTestMux(h)
	}
	active := testPolicy(PolicyStatusActive)
	noopPublish := func(ctx context.Context, uid uuid.UUID, rid string) (*RuntimePolicyPublishResult, error) {
		return nil, nil
	}

	// 策略不存在 → 404（发布通道已接线，越过 503 前置检查）
	mux := newMuxWith(&fakeRuntimeStore{getErr: ErrRuntimePolicyNotFound}, noopPublish)
	if rr := doRuntimeReq(t, mux, http.MethodPost, "/api/v1/api-security/runtime-policies/"+uuid.NewString()+"/rollback"); rr.Code != http.StatusNotFound {
		t.Fatalf("not found status=%d", rr.Code)
	}
	// 无上一已知良好版本 → 409
	mux = newMuxWith(&fakeRuntimeStore{byID: active, rollbackErr: ErrNoPreviousGoodPolicy}, noopPublish)
	if rr := doRuntimeReq(t, mux, http.MethodPost, "/api/v1/api-security/runtime-policies/"+active.ID.String()+"/rollback"); rr.Code != http.StatusConflict {
		t.Fatalf("no prev good status=%d", rr.Code)
	}
	// 当前状态不允许回滚（如 DRAFT）→ 409
	mux = newMuxWith(&fakeRuntimeStore{byID: active, rollbackErr: ErrInvalidTransition}, noopPublish)
	if rr := doRuntimeReq(t, mux, http.MethodPost, "/api/v1/api-security/runtime-policies/"+active.ID.String()+"/rollback"); rr.Code != http.StatusConflict {
		t.Fatalf("invalid transition status=%d", rr.Code)
	}
	// 上一良好版本的来源模型不可恢复（已归档）→ 409
	mux = newMuxWith(&fakeRuntimeStore{byID: active, rollbackErr: ErrModelNotRestorable}, noopPublish)
	if rr := doRuntimeReq(t, mux, http.MethodPost, "/api/v1/api-security/runtime-policies/"+active.ID.String()+"/rollback"); rr.Code != http.StatusConflict {
		t.Fatalf("model not restorable status=%d", rr.Code)
	}
	// 未接发布通道 → 503（且不触发回滚）
	fs := &fakeRuntimeStore{byID: active}
	mux = newMuxWith(fs, nil)
	if rr := doRuntimeReq(t, mux, http.MethodPost, "/api/v1/api-security/runtime-policies/"+active.ID.String()+"/rollback"); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no publish fn status=%d", rr.Code)
	}
	if fs.rollbackCalls != 0 {
		t.Fatalf("rollback must not run when publish unavailable: %d", fs.rollbackCalls)
	}

	// 成功：恢复模型 + 创建回滚草稿 + 重触发发布（透传操作者与 Request ID）。
	// 内容源一致性：RollbackToKnownGood 必先于发布触发（恢复 FORMAL=旧模型，发布内容源随之回到旧模型），
	// 且回滚草稿的 source_model_version_id 即恢复模型（草稿内容=旧模型编译内容）。
	draft := testPolicy(PolicyStatusDraft)
	draft.RuntimeVersion = "v3"
	restored := &Version{ID: draft.SourceModelVersionID, VersionNumber: 1, Status: StatusFormal}
	outcome := &RuntimePolicyRollback{Draft: draft, RestoredModel: restored}
	var gotRid string
	fs = &fakeRuntimeStore{byID: active, rollbackOut: outcome}
	mux = newMuxWith(fs, func(ctx context.Context, uid uuid.UUID, rid string) (*RuntimePolicyPublishResult, error) {
		fs.seq = append(fs.seq, "publish")
		gotRid = rid
		if uid == uuid.Nil {
			t.Fatal("operator id must be passed")
		}
		return &RuntimePolicyPublishResult{TaskID: uuid.NewString(), Status: "SUCCESS"}, nil
	})
	rr := doRuntimeReq(t, mux, http.MethodPost, "/api/v1/api-security/runtime-policies/"+active.ID.String()+"/rollback")
	if rr.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rr.Code, rr.Body.String())
	}
	if fs.rollbackCalls != 1 || gotRid != "test-rid" {
		t.Fatalf("rollbackCalls=%d rid=%s", fs.rollbackCalls, gotRid)
	}
	if fs.lastOperator == uuid.Nil {
		t.Fatal("operator id must be passed to rollback store")
	}
	if len(fs.seq) != 2 || fs.seq[0] != "rollback" || fs.seq[1] != "publish" {
		t.Fatalf("model restore must precede publish trigger: seq=%v", fs.seq)
	}
	if fs.markCalls != 0 {
		t.Fatalf("mark failed must not run on success: %d", fs.markCalls)
	}
	data := decodeRuntimeData(t, rr)
	if data["status"] != "SUCCESS" || data["task_id"] == "" {
		t.Fatalf("rollback result = %v", data)
	}
	policy := data["policy"].(map[string]any)
	if policy["runtime_version"] != "v3" {
		t.Fatalf("rollback draft = %v", data["policy"])
	}
	if policy["source_model_version_id"] != restored.ID.String() {
		t.Fatalf("draft content source must be the restored model: %v", policy["source_model_version_id"])
	}

	// 发布触发失败 → 500，且草稿落 FAILED（不残留操作者无感知的孤儿 DRAFT）
	fs = &fakeRuntimeStore{byID: active, rollbackOut: outcome}
	mux = newMuxWith(fs, func(ctx context.Context, uid uuid.UUID, rid string) (*RuntimePolicyPublishResult, error) {
		return nil, errors.New("gateway unreachable")
	})
	if rr := doRuntimeReq(t, mux, http.MethodPost, "/api/v1/api-security/runtime-policies/"+active.ID.String()+"/rollback"); rr.Code != http.StatusInternalServerError {
		t.Fatalf("publish err status=%d", rr.Code)
	}
	if fs.markCalls != 1 || fs.lastMarkID != draft.ID {
		t.Fatalf("rollback draft must be marked FAILED: calls=%d id=%s", fs.markCalls, fs.lastMarkID)
	}
	if fs.lastMarkReason == "" || !strings.Contains(fs.lastMarkReason, "gateway unreachable") {
		t.Fatalf("mark reason must carry publish error: %q", fs.lastMarkReason)
	}

	// 发布触发失败 + 标记 FAILED 本身失败 → 仍 500（尽力而为，不掩盖原始错误）
	fs = &fakeRuntimeStore{byID: active, rollbackOut: outcome, markErr: errors.New("db down")}
	mux = newMuxWith(fs, func(ctx context.Context, uid uuid.UUID, rid string) (*RuntimePolicyPublishResult, error) {
		return nil, errors.New("gateway unreachable")
	})
	if rr := doRuntimeReq(t, mux, http.MethodPost, "/api/v1/api-security/runtime-policies/"+active.ID.String()+"/rollback"); rr.Code != http.StatusInternalServerError {
		t.Fatalf("publish err + mark err status=%d", rr.Code)
	}

	// 发布执行失败（任务 FAILED）→ 502，不假报「已回退」；发布回写已落 FAILED，不再单条标记
	fs = &fakeRuntimeStore{byID: active, rollbackOut: outcome}
	mux = newMuxWith(fs, func(ctx context.Context, uid uuid.UUID, rid string) (*RuntimePolicyPublishResult, error) {
		return &RuntimePolicyPublishResult{TaskID: uuid.NewString(), Status: "FAILED"}, nil
	})
	rr = doRuntimeReq(t, mux, http.MethodPost, "/api/v1/api-security/runtime-policies/"+active.ID.String()+"/rollback")
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("publish failed task status=%d body=%s", rr.Code, rr.Body.String())
	}
	if fs.markCalls != 0 {
		t.Fatalf("writeback settles FAILED, single mark must not run: %d", fs.markCalls)
	}
}

// TestValidPolicyStatus 状态白名单（与迁移 CHECK 约束一致）。
func TestValidPolicyStatus(t *testing.T) {
	for _, s := range []string{"DRAFT", "VALIDATED", "PUBLISHED", "ACTIVE", "ROLLED_BACK", "FAILED"} {
		if !ValidPolicyStatus(s) {
			t.Errorf("%s must be valid", s)
		}
	}
	for _, s := range []string{"", "draft", "SUPERSEDED", "BOGUS"} {
		if ValidPolicyStatus(s) {
			t.Errorf("%s must be invalid", s)
		}
	}
}
