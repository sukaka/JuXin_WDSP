// handler_test.go 容器运维管理接口单元测试：权限/认证门控、密码二次确认、
// 更新确认文本、服务名格式、通道不可用映射、审计记录。
package containerops

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/users"
)

const testPassword = "Correct-Horse-42!"

// auditSpy 审计记录 spy。
type auditSpy struct {
	mu     sync.Mutex
	inputs []audits.RecordInput
}

func (s *auditSpy) Record(_ context.Context, in audits.RecordInput) error {
	s.mu.Lock()
	s.inputs = append(s.inputs, in)
	s.mu.Unlock()
	return nil
}

func (s *auditSpy) last() audits.RecordInput {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.inputs) == 0 {
		return audits.RecordInput{}
	}
	return s.inputs[len(s.inputs)-1]
}

func (s *auditSpy) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.inputs)
}

// userStub 用户查询 stub。
type userStub struct {
	user *users.User
	err  error
}

func (s *userStub) GetByID(_ context.Context, _ uuid.UUID) (*users.User, error) {
	return s.user, s.err
}

// opsStub sidecar 调用 stub。
type opsStub struct {
	available  bool
	containers []Container
	logs       *LogsResult
	job        *ActionJob
	err        error

	gotService string
	gotAction  string
	gotJobID   string
	gotTail    int
	gotDelay   int
	gotSince   int64
	calls      int
}

func (s *opsStub) Available() bool { return s.available }

func (s *opsStub) ListContainers(context.Context) ([]Container, error) {
	s.calls++
	return s.containers, s.err
}

func (s *opsStub) ContainerLogs(_ context.Context, service string, tail int, since int64) (*LogsResult, error) {
	s.calls++
	s.gotService, s.gotTail, s.gotSince = service, tail, since
	return s.logs, s.err
}

func (s *opsStub) SubmitAction(_ context.Context, service, action string, delaySeconds int) (*ActionJob, error) {
	s.calls++
	s.gotService, s.gotAction, s.gotDelay = service, action, delaySeconds
	return s.job, s.err
}

func (s *opsStub) ActionStatus(_ context.Context, jobID string) (*ActionJob, error) {
	s.calls++
	s.gotJobID = jobID
	return s.job, s.err
}

// injectPrincipal 构造注入指定权限点主体的认证链。
func injectPrincipal(userID uuid.UUID, perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: userID, Username: "tester", PermsSet: set}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
}

// passThrough 不注入主体的认证链（模拟未登录）。
func passThrough(next http.Handler) http.Handler { return next }

type handlerEnv struct {
	handler http.Handler
	audits  *auditSpy
	ops     *opsStub
	userID  uuid.UUID
}

func newHandlerEnv(t *testing.T, authenticated bool, perms ...string) *handlerEnv {
	t.Helper()
	hash, err := security.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("生成密码哈希: %v", err)
	}
	spy := &auditSpy{}
	uid := uuid.New()
	authChain := passThrough
	if authenticated {
		authChain = injectPrincipal(uid, perms...)
	}
	stub := &opsStub{
		available:  true,
		containers: []Container{{Service: "web", Running: true, Health: "healthy"}},
		logs:       &LogsResult{Service: "web", Lines: []LogLine{{Stream: "stdout", Message: "ok"}}, NextSince: 123},
		job:        &ActionJob{JobID: "0123456789abcdef0123456789abcdef", Service: "web", Action: "start", Status: "ACCEPTED"},
	}
	h := NewHandler(stub, &userStub{user: &users.User{ID: uid, Username: "tester", PasswordHash: hash}}, spy)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, authChain)
	return &handlerEnv{handler: mux, audits: spy, ops: stub, userID: uid}
}

type apiBody struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func doJSON(t *testing.T, h http.Handler, method, path, body string) (int, apiBody) {
	t.Helper()
	var rdr *strings.Reader
	if body == "" {
		rdr = strings.NewReader("")
	} else {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out apiBody
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("响应非 JSON: %v body=%s", err, rec.Body.String())
		}
	}
	return rec.Code, out
}

// --- 权限与认证门控 ---

func TestNoPermission(t *testing.T) {
	env := newHandlerEnv(t, true) // 无任何权限点
	routes := []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/system/containers", ""},
		{http.MethodGet, "/api/v1/system/containers/web/logs", ""},
		{http.MethodGet, "/api/v1/system/containers/actions/0123456789abcdef0123456789abcdef", ""},
		{http.MethodPost, "/api/v1/system/containers/web/start", `{"password":"` + testPassword + `"}`},
		{http.MethodPost, "/api/v1/system/containers/web/stop", `{"password":"` + testPassword + `"}`},
		{http.MethodPost, "/api/v1/system/containers/web/restart", `{"password":"` + testPassword + `"}`},
		{http.MethodPost, "/api/v1/system/containers/web/update", `{"password":"` + testPassword + `","confirmText":"更新容器"}`},
	}
	for _, rt := range routes {
		code, body := doJSON(t, env.handler, rt.method, rt.path, rt.body)
		if code != http.StatusForbidden || body.Code != "PERMISSION_DENIED" {
			t.Fatalf("%s %s 应 403: code=%d body=%+v", rt.method, rt.path, code, body)
		}
	}
	if env.audits.count() != 0 {
		t.Fatalf("权限拒绝不应记审计，实际 %d 条", env.audits.count())
	}
}

func TestUnauthenticated(t *testing.T) {
	env := newHandlerEnv(t, false)
	code, body := doJSON(t, env.handler, http.MethodGet, "/api/v1/system/containers", "")
	if code != http.StatusUnauthorized || body.Code != "UNAUTHENTICATED" {
		t.Fatalf("未认证应 401: code=%d body=%+v", code, body)
	}
}

// --- 列表 ---

func TestListSuccess(t *testing.T) {
	env := newHandlerEnv(t, true, PermRead)
	code, body := doJSON(t, env.handler, http.MethodGet, "/api/v1/system/containers", "")
	if code != http.StatusOK || body.Code != "SUCCESS" {
		t.Fatalf("列表应 200: code=%d body=%+v", code, body)
	}
	var data struct {
		Containers []Container `json:"containers"`
	}
	if err := json.Unmarshal(body.Data, &data); err != nil || len(data.Containers) != 1 || data.Containers[0].Service != "web" {
		t.Fatalf("列表数据错误: err=%v data=%s", err, body.Data)
	}
	au := env.audits.last()
	if au.Action != auditList || au.Result != audits.ResultSuccess || au.RiskLevel != audits.RiskMedium ||
		au.Module != auditModule || au.ObjectType != auditObjectType {
		t.Fatalf("列表应记 SUCCESS/MEDIUM 审计: %+v", au)
	}
}

func TestListUnavailable(t *testing.T) {
	env := newHandlerEnv(t, true, PermRead)
	env.ops.available = false
	code, body := doJSON(t, env.handler, http.MethodGet, "/api/v1/system/containers", "")
	if code != http.StatusServiceUnavailable || body.Code != "SERVICE_UNAVAILABLE" {
		t.Fatalf("通道未配置应 503: code=%d body=%+v", code, body)
	}
	au := env.audits.last()
	if au.Result != audits.ResultFailure || au.RiskLevel != audits.RiskMedium {
		t.Fatalf("降级应记 FAILURE 审计: %+v", au)
	}
	if env.ops.calls != 0 {
		t.Fatal("通道不可用时不应发起调用")
	}
}

func TestListUpstreamError(t *testing.T) {
	env := newHandlerEnv(t, true, PermRead)
	env.ops.err = &Error{Kind: KindUpstream, Status: http.StatusInternalServerError, Code: "DOCKER_ERROR", Message: "boom"}
	code, body := doJSON(t, env.handler, http.MethodGet, "/api/v1/system/containers", "")
	if code != http.StatusBadGateway || body.Code != "SERVICE_UNAVAILABLE" {
		t.Fatalf("上游 500 应映射 502: code=%d body=%+v", code, body)
	}
	if au := env.audits.last(); au.Result != audits.ResultFailure {
		t.Fatalf("上游失败应记 FAILURE 审计: %+v", au)
	}
}

// --- 日志 ---

func TestLogsSuccessAndParams(t *testing.T) {
	env := newHandlerEnv(t, true, PermLogs)
	code, body := doJSON(t, env.handler, http.MethodGet, "/api/v1/system/containers/web/logs?tail=5000&since=1699999999", "")
	if code != http.StatusOK {
		t.Fatalf("日志应 200: code=%d body=%+v", code, body)
	}
	if env.ops.gotService != "web" || env.ops.gotTail != MaxLogTail || env.ops.gotSince != 1699999999 {
		t.Fatalf("参数透传/夹紧错误: service=%q tail=%d since=%d", env.ops.gotService, env.ops.gotTail, env.ops.gotSince)
	}
	var data LogsResult
	if err := json.Unmarshal(body.Data, &data); err != nil || data.NextSince != 123 {
		t.Fatalf("日志数据错误: err=%v data=%s", err, body.Data)
	}
	if au := env.audits.last(); au.Action != auditLogs || au.ObjectName != "web" || au.RiskLevel != audits.RiskMedium {
		t.Fatalf("日志审计错误: %+v", au)
	}
}

func TestLogsBadParams(t *testing.T) {
	env := newHandlerEnv(t, true, PermLogs)
	for _, path := range []string{
		"/api/v1/system/containers/web/logs?tail=abc",
		"/api/v1/system/containers/web/logs?tail=-1",
		"/api/v1/system/containers/web/logs?since=-5",
		"/api/v1/system/containers/bad%3Bname/logs",
	} {
		code, body := doJSON(t, env.handler, http.MethodGet, path, "")
		if code != http.StatusBadRequest || body.Code != "INVALID_ARGUMENT" {
			t.Fatalf("%s 应 400: code=%d body=%+v", path, code, body)
		}
	}
	if env.ops.calls != 0 {
		t.Fatal("参数非法时不应发起调用")
	}
}

// --- 写操作（start/stop/restart/update） ---

func TestControlWrongPassword(t *testing.T) {
	env := newHandlerEnv(t, true, PermControl)
	code, body := doJSON(t, env.handler, http.MethodPost, "/api/v1/system/containers/web/restart", `{"password":"wrong"}`)
	if code != http.StatusBadRequest || body.Code != "INVALID_ARGUMENT" {
		t.Fatalf("密码错误应 400: code=%d body=%+v", code, body)
	}
	au := env.audits.last()
	if au.Result != audits.ResultFailure || au.Action != auditRestart || au.RiskLevel != audits.RiskHigh || au.FailureReason == "" {
		t.Fatalf("密码错误应记 FAILURE/HIGH 审计: %+v", au)
	}
	if env.ops.calls != 0 {
		t.Fatal("密码错误不应发起调用")
	}
}

func TestControlSuccess(t *testing.T) {
	env := newHandlerEnv(t, true, PermControl)
	for _, action := range []string{"start", "stop", "restart"} {
		code, body := doJSON(t, env.handler, http.MethodPost,
			"/api/v1/system/containers/web/"+action, `{"password":"`+testPassword+`","delaySeconds":3}`)
		if code != http.StatusAccepted || body.Code != "SUCCESS" {
			t.Fatalf("%s 应 202: code=%d body=%+v", action, code, body)
		}
		if env.ops.gotAction != action || env.ops.gotDelay != 3 || env.ops.gotService != "web" {
			t.Fatalf("%s 透传错误: %+v", action, env.ops)
		}
	}
	au := env.audits.last()
	if au.Result != audits.ResultSuccess || au.Action != auditRestart || au.RiskLevel != audits.RiskHigh {
		t.Fatalf("写操作应记 SUCCESS/HIGH 审计: %+v", au)
	}
}

func TestControlBadServiceName(t *testing.T) {
	env := newHandlerEnv(t, true, PermControl)
	code, body := doJSON(t, env.handler, http.MethodPost, "/api/v1/system/containers/bad%3Bname/stop", `{"password":"`+testPassword+`"}`)
	if code != http.StatusBadRequest || body.Code != "INVALID_ARGUMENT" {
		t.Fatalf("非法服务名应 400: code=%d body=%+v", code, body)
	}
	if env.ops.calls != 0 || env.audits.count() != 0 {
		t.Fatal("服务名非法不应发起调用或记审计")
	}
}

func TestControlDelaySecondsOutOfRange(t *testing.T) {
	env := newHandlerEnv(t, true, PermControl)
	for _, body := range []string{
		`{"password":"` + testPassword + `","delaySeconds":-1}`,
		`{"password":"` + testPassword + `","delaySeconds":301}`,
	} {
		code, resp := doJSON(t, env.handler, http.MethodPost, "/api/v1/system/containers/web/start", body)
		if code != http.StatusBadRequest || resp.Code != "INVALID_ARGUMENT" {
			t.Fatalf("delaySeconds 越界应 400: code=%d body=%+v", code, resp)
		}
	}
}

func TestControlUnavailable(t *testing.T) {
	env := newHandlerEnv(t, true, PermControl)
	env.ops.available = false
	code, body := doJSON(t, env.handler, http.MethodPost, "/api/v1/system/containers/web/start", `{"password":"`+testPassword+`"}`)
	if code != http.StatusServiceUnavailable || body.Code != "SERVICE_UNAVAILABLE" {
		t.Fatalf("通道未配置应 503: code=%d body=%+v", code, body)
	}
	if au := env.audits.last(); au.Result != audits.ResultFailure || au.RiskLevel != audits.RiskHigh {
		t.Fatalf("降级应记 FAILURE/HIGH 审计: %+v", au)
	}
}

func TestControlUpstreamNotFound(t *testing.T) {
	env := newHandlerEnv(t, true, PermControl)
	env.ops.err = &Error{Kind: KindUpstream, Status: http.StatusNotFound, Code: "CONTAINER_NOT_FOUND", Message: "容器不存在"}
	code, body := doJSON(t, env.handler, http.MethodPost, "/api/v1/system/containers/ghost/start", `{"password":"`+testPassword+`"}`)
	if code != http.StatusNotFound || body.Code != "RESOURCE_NOT_FOUND" {
		t.Fatalf("上游 404 应透传: code=%d body=%+v", code, body)
	}
	if au := env.audits.last(); au.Result != audits.ResultFailure {
		t.Fatalf("受理失败应记 FAILURE 审计: %+v", au)
	}
}

// --- update ---

func TestUpdateConfirmTextMismatch(t *testing.T) {
	env := newHandlerEnv(t, true, PermUpdate)
	code, body := doJSON(t, env.handler, http.MethodPost, "/api/v1/system/containers/web/update",
		`{"password":"`+testPassword+`","confirmText":"更新"}`)
	if code != http.StatusBadRequest || body.Code != "INVALID_ARGUMENT" {
		t.Fatalf("确认文本错误应 400: code=%d body=%+v", code, body)
	}
	au := env.audits.last()
	if au.Result != audits.ResultFailure || au.Action != auditUpdate || au.RiskLevel != audits.RiskCritical {
		t.Fatalf("确认文本错误应记 FAILURE/CRITICAL 审计: %+v", au)
	}
	if env.ops.calls != 0 {
		t.Fatal("确认文本错误不应发起调用")
	}
}

func TestUpdateSuccess(t *testing.T) {
	env := newHandlerEnv(t, true, PermUpdate)
	code, body := doJSON(t, env.handler, http.MethodPost, "/api/v1/system/containers/web/update",
		`{"password":"`+testPassword+`","confirmText":"更新容器"}`)
	if code != http.StatusAccepted || body.Code != "SUCCESS" {
		t.Fatalf("更新受理应 202: code=%d body=%+v", code, body)
	}
	if env.ops.gotAction != "update" {
		t.Fatalf("动作透传错误: %q", env.ops.gotAction)
	}
	au := env.audits.last()
	if au.Result != audits.ResultSuccess || au.Action != auditUpdate || au.RiskLevel != audits.RiskCritical ||
		au.ObjectName != "web" {
		t.Fatalf("更新应记 SUCCESS/CRITICAL 审计: %+v", au)
	}
}

func TestControlUserNotFound(t *testing.T) {
	env := newHandlerEnv(t, true, PermControl)
	stubUsers := &userStub{err: users.ErrNotFound}
	h := NewHandler(env.ops, stubUsers, env.audits)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, injectPrincipal(uuid.New(), PermControl))
	code, body := doJSON(t, mux, http.MethodPost, "/api/v1/system/containers/web/start", `{"password":"`+testPassword+`"}`)
	if code != http.StatusForbidden || body.Code != "PERMISSION_DENIED" {
		t.Fatalf("用户不存在应 403: code=%d body=%+v", code, body)
	}
}

// --- 任务状态查询 ---

func TestActionStatusSuccess(t *testing.T) {
	env := newHandlerEnv(t, true, PermRead)
	code, body := doJSON(t, env.handler, http.MethodGet, "/api/v1/system/containers/actions/0123456789abcdef0123456789abcdef", "")
	if code != http.StatusOK || body.Code != "SUCCESS" {
		t.Fatalf("任务查询应 200: code=%d body=%+v", code, body)
	}
	if env.ops.gotJobID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("任务 ID 透传错误: %q", env.ops.gotJobID)
	}
	if env.audits.count() != 0 {
		t.Fatalf("状态轮询不应记审计，实际 %d 条", env.audits.count())
	}
}

func TestActionStatusBadID(t *testing.T) {
	env := newHandlerEnv(t, true, PermRead)
	for _, id := range []string{"short", "0123456789abcdef0123456789abcde", "0x123456789abcdef0123456789abcdef"} {
		code, body := doJSON(t, env.handler, http.MethodGet, "/api/v1/system/containers/actions/"+id, "")
		if code != http.StatusBadRequest || body.Code != "INVALID_ARGUMENT" {
			t.Fatalf("id=%q 应 400: code=%d body=%+v", id, code, body)
		}
	}
	if env.ops.calls != 0 {
		t.Fatal("非法任务 ID 不应发起调用")
	}
}

func TestActionStatusNotFound(t *testing.T) {
	env := newHandlerEnv(t, true, PermRead)
	env.ops.err = &Error{Kind: KindUpstream, Status: http.StatusNotFound, Code: "JOB_NOT_FOUND", Message: "任务不存在"}
	code, body := doJSON(t, env.handler, http.MethodGet, "/api/v1/system/containers/actions/0123456789abcdef0123456789abcdef", "")
	if code != http.StatusNotFound || body.Code != "RESOURCE_NOT_FOUND" {
		t.Fatalf("上游任务 404 应透传: code=%d body=%+v", code, body)
	}
}

// TestErrorMappingUnreachable 兜底：非 typed 错误映射为 500。
func TestErrorMappingInternal(t *testing.T) {
	env := newHandlerEnv(t, true, PermRead)
	env.ops.err = errors.New("unexpected")
	code, body := doJSON(t, env.handler, http.MethodGet, "/api/v1/system/containers", "")
	if code != http.StatusInternalServerError || body.Code != "INTERNAL_ERROR" {
		t.Fatalf("未知错误应 500: code=%d body=%+v", code, body)
	}
}
