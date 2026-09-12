// handler_test.go 系统控制接口单元测试：权限/认证门控、密码二次校验、
// 恢复出厂确认文本、标志文件原子写入、审计记录。
package systemops

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// userStub 用户查询 stub（返回带固定密码哈希的用户）。
type userStub struct {
	user *users.User
	err  error
}

func (s *userStub) GetByID(_ context.Context, _ uuid.UUID) (*users.User, error) {
	return s.user, s.err
}

// injectPrincipal 构造注入指定权限点主体的 authz 包装（仿 license handler_test 模式）。
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
	dir     string
	userID  uuid.UUID
}

func newHandlerEnv(t *testing.T, dir string, authenticated bool, perms ...string) *handlerEnv {
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
	h := NewHandler(&userStub{user: &users.User{ID: uid, Username: "tester", PasswordHash: hash}}, spy, dir)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, authChain)
	return &handlerEnv{handler: mux, audits: spy, dir: dir, userID: uid}
}

type apiBody struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// flagEntries 返回目录中的待处理标志文件（*.json；.hostctl-secret 等非标志文件除外）。
func flagEntries(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取标志目录: %v", err)
	}
	var flags []os.DirEntry
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			flags = append(flags, e)
		}
	}
	return flags
}

func doJSON(t *testing.T, h http.Handler, path, body string) (int, apiBody) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out apiBody
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应非 JSON: %v body=%s", err, rec.Body.String())
	}
	return rec.Code, out
}

func TestNoPermission(t *testing.T) {
	env := newHandlerEnv(t, t.TempDir(), true) // 无任何权限点
	for _, path := range []string{"/api/v1/system/reboot", "/api/v1/system/shutdown", "/api/v1/system/factory-reset"} {
		code, body := doJSON(t, env.handler, path, `{"password":"`+testPassword+`","confirmText":"恢复出厂"}`)
		if code != http.StatusForbidden || body.Code != "PERMISSION_DENIED" {
			t.Fatalf("%s 应 403: code=%d body=%+v", path, code, body)
		}
	}
	if got := len(env.audits.inputs); got != 0 {
		t.Fatalf("权限拒绝不应记审计，实际 %d 条", got)
	}
}

func TestUnauthenticated(t *testing.T) {
	env := newHandlerEnv(t, t.TempDir(), false)
	code, body := doJSON(t, env.handler, "/api/v1/system/reboot", `{"password":"`+testPassword+`"}`)
	if code != http.StatusUnauthorized || body.Code != "UNAUTHENTICATED" {
		t.Fatalf("未认证应 401: code=%d body=%+v", code, body)
	}
}

func TestWrongPassword(t *testing.T) {
	env := newHandlerEnv(t, t.TempDir(), true, "system.reboot")
	code, body := doJSON(t, env.handler, "/api/v1/system/reboot", `{"password":"wrong-password"}`)
	if code != http.StatusBadRequest || body.Code != "INVALID_ARGUMENT" {
		t.Fatalf("密码错误应 400: code=%d body=%+v", code, body)
	}
	au := env.audits.last()
	if au.Result != audits.ResultFailure || au.Action != ActionReboot ||
		au.Module != "system" || au.ObjectType != "system" || au.RiskLevel != audits.RiskCritical {
		t.Fatalf("密码错误应记 FAILURE/CRITICAL 审计: %+v", au)
	}
	if au.FailureReason == "" {
		t.Fatal("FAILURE 审计应携带失败原因")
	}
}

func TestFactoryResetConfirmTextMismatch(t *testing.T) {
	env := newHandlerEnv(t, t.TempDir(), true, "system.factory_reset")
	code, body := doJSON(t, env.handler, "/api/v1/system/factory-reset",
		`{"password":"`+testPassword+`","confirmText":"恢复出厂 "}`)
	if code != http.StatusBadRequest || body.Code != "INVALID_ARGUMENT" {
		t.Fatalf("确认文本错误应 400: code=%d body=%+v", code, body)
	}
	au := env.audits.last()
	if au.Result != audits.ResultFailure || au.Action != ActionFactoryReset {
		t.Fatalf("确认文本错误应记 FAILURE 审计: %+v", au)
	}
	entries, err := os.ReadDir(env.dir)
	if err != nil {
		t.Fatalf("读取标志目录: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("确认文本错误不应写标志文件，实际 %d 个", len(entries))
	}
}

func TestRebootFlagFileWritten(t *testing.T) {
	env := newHandlerEnv(t, t.TempDir(), true, "system.reboot")
	code, body := doJSON(t, env.handler, "/api/v1/system/reboot", `{"password":"`+testPassword+`"}`)
	if code != http.StatusAccepted || body.Code != "SUCCESS" {
		t.Fatalf("重启受理应 202: code=%d body=%+v", code, body)
	}
	var data struct {
		Message string `json:"message"`
		Action  string `json:"action"`
	}
	if err := json.Unmarshal(body.Data, &data); err != nil {
		t.Fatalf("解析 data: %v", err)
	}
	if data.Action != ActionReboot || !strings.Contains(data.Message, "指令已受理") {
		t.Fatalf("受理响应内容不符: %+v", data)
	}

	entries := flagEntries(t, env.dir)
	if len(entries) != 1 {
		t.Fatalf("应写入 1 个标志文件，实际 %d 个", len(entries))
	}
	name := entries[0].Name()
	if !strings.HasPrefix(name, "reboot-") || !strings.HasSuffix(name, ".json") {
		t.Fatalf("标志文件名格式不符: %s", name)
	}
	raw, err := os.ReadFile(filepath.Join(env.dir, name))
	if err != nil {
		t.Fatalf("读取标志文件: %v", err)
	}
	var cmd Command
	if err := json.Unmarshal(raw, &cmd); err != nil {
		t.Fatalf("标志文件非合法 JSON: %v", err)
	}
	if cmd.Action != ActionReboot || cmd.RequestedBy != "tester" ||
		cmd.UserID != env.userID.String() || cmd.DelaySeconds != 3 || cmd.RequestedAt == "" {
		t.Fatalf("标志文件内容不符: %+v", cmd)
	}
	if cmd.HMAC == "" {
		t.Fatal("标志文件缺少 hmac 签名字段")
	}
	secret, err := LoadOrCreateHostctlSecret(env.dir)
	if err != nil {
		t.Fatalf("读取共享密钥: %v", err)
	}
	unsigned := cmd
	SignCommand(&unsigned, secret)
	if unsigned.HMAC != cmd.HMAC {
		t.Fatal("标志文件签名无法用目录内共享密钥复算")
	}
	au := env.audits.last()
	if au.Result != audits.ResultSuccess || au.Action != ActionReboot || au.RiskLevel != audits.RiskCritical {
		t.Fatalf("成功应记 SUCCESS/CRITICAL 审计: %+v", au)
	}
}

func TestShutdownFlagFileWritten(t *testing.T) {
	env := newHandlerEnv(t, t.TempDir(), true, "system.shutdown")
	code, _ := doJSON(t, env.handler, "/api/v1/system/shutdown", `{"password":"`+testPassword+`"}`)
	if code != http.StatusAccepted {
		t.Fatalf("关机受理应 202: code=%d", code)
	}
	entries := flagEntries(t, env.dir)
	if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "shutdown-") {
		t.Fatalf("关机标志文件不符: entries=%v", entries)
	}
}

func TestFactoryResetSuccess(t *testing.T) {
	env := newHandlerEnv(t, t.TempDir(), true, "system.factory_reset")
	code, _ := doJSON(t, env.handler, "/api/v1/system/factory-reset",
		`{"password":"`+testPassword+`","confirmText":"恢复出厂"}`)
	if code != http.StatusAccepted {
		t.Fatalf("恢复出厂受理应 202: code=%d", code)
	}
	entries := flagEntries(t, env.dir)
	if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "factory_reset-") {
		t.Fatalf("恢复出厂标志文件不符: entries=%v", entries)
	}
}

func TestFlagDirNotWritable(t *testing.T) {
	// 用普通文件占用目录路径：MkdirAll/CreateTemp 必然失败（与运行用户权限无关）。
	blocker := filepath.Join(t.TempDir(), "hostctl")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("创建占用文件: %v", err)
	}
	env := newHandlerEnv(t, blocker, true, "system.reboot")
	code, body := doJSON(t, env.handler, "/api/v1/system/reboot", `{"password":"`+testPassword+`"}`)
	if code != http.StatusInternalServerError || body.Code != "INTERNAL_ERROR" {
		t.Fatalf("目录不可写应 500: code=%d body=%+v", code, body)
	}
	au := env.audits.last()
	if au.Result != audits.ResultFailure || au.Action != ActionReboot {
		t.Fatalf("写标志失败应记 FAILURE 审计: %+v", au)
	}
}

func TestBadJSON(t *testing.T) {
	env := newHandlerEnv(t, t.TempDir(), true, "system.reboot")
	code, body := doJSON(t, env.handler, "/api/v1/system/reboot", `{"password":`)
	if code != http.StatusBadRequest || body.Code != "INVALID_ARGUMENT" {
		t.Fatalf("非法 JSON 应 400: code=%d body=%+v", code, body)
	}
	if got := len(env.audits.inputs); got != 0 {
		t.Fatalf("参数错误不应记审计，实际 %d 条", got)
	}
}
