// quota_test.go 授权应用配额强制单元测试：Create 在配额已达上限时 403
// （LICENSE_QUOTA_EXCEEDED）且不触达 store.Create；计数失败如实 500。
// Store 为 PG 具体实现无法伪造——计数经 h.countApps 注入 fake，
// 与 license handler 的 auditRecorder 同一测试纪律（不 mock 冒充 PG 行为）。
package applications

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/license"
)

// deadAudits 构造 Record 立即失败（连接拒绝）的审计服务：审计错误走兜底日志/计数、
// 不影响业务响应（recordQuotaDeniedAudit 内 RecordWithFallback），403 断言不依赖审计落库，
// 也不伪造 PG 行为。
func deadAudits(t *testing.T) *audits.Service {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://127.0.0.1:1/postgres?connect_timeout=1")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return audits.NewService(pool)
}

// createReq 构造注入主体的 Create 请求。
func createReq(t *testing.T, code string) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/applications",
		strings.NewReader(`{"code":"`+code+`","name":"测试应用"}`))
	req.Header.Set("Content-Type", "application/json")
	p := &authz.Principal{UserID: uuid.New(), Username: "tester"}
	req = req.WithContext(authz.WithPrincipal(req.Context(), p))
	return req, httptest.NewRecorder()
}

func TestCreateLicenseQuotaExceeded(t *testing.T) {
	h := NewHandler(nil, deadAudits(t), nil)
	h.countApps = func(context.Context) (int64, error) { return 10, nil }
	h.SetMaxApplicationsProvider(func(context.Context) int64 { return 10 })

	req, rec := createReq(t, "shop-new")
	h.Create(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("配额已达上限应 403，got %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应非 JSON: %v", err)
	}
	if body.Code != license.CodeLicenseQuotaExceeded {
		t.Fatalf("业务码应为 %s，got %s", license.CodeLicenseQuotaExceeded, body.Code)
	}
	if !strings.Contains(body.Message, "10") {
		t.Fatalf("错误信息应含配额上限: %s", body.Message)
	}
}

func TestCreateLicenseQuotaZeroUnlimited(t *testing.T) {
	// quota=0（不限制）：跳过计数与拒绝，进入后续创建流程
	// （nil store 在 store.Create 触达数据库时 panic 即证明未走配额分支——
	// 本用例只断言配额分支未拦截：recover 到的应是 nil store panic 而非 403 响应）。
	h := NewHandler(nil, deadAudits(t), nil)
	countCalled := false
	h.countApps = func(context.Context) (int64, error) { countCalled = true; return 0, nil }
	h.SetMaxApplicationsProvider(func(context.Context) int64 { return 0 })

	req, rec := createReq(t, "shop-new")
	func() {
		defer func() { _ = recover() }() // nil store.Create panic 预期内
		h.Create(rec, req)
	}()
	if countCalled {
		t.Fatal("quota=0 不应触发计数")
	}
	if rec.Code == http.StatusForbidden {
		t.Fatal("quota=0 不应 403")
	}
}

func TestCreateLicenseQuotaCountError(t *testing.T) {
	h := NewHandler(nil, deadAudits(t), nil)
	h.countApps = func(context.Context) (int64, error) { return 0, errors.New("db down") }
	h.SetMaxApplicationsProvider(func(context.Context) int64 { return 10 })

	req, rec := createReq(t, "shop-new")
	h.Create(rec, req)

	// 计数失败如实 500（不静默放行）
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("计数失败应 500，got %d", rec.Code)
	}
}

func TestCreateLicenseQuotaNotYetExceeded(t *testing.T) {
	// count(3) < quota(10)：配额分支放行（同样以 nil store panic 证明未拦截）
	h := NewHandler(nil, deadAudits(t), nil)
	h.countApps = func(context.Context) (int64, error) { return 3, nil }
	h.SetMaxApplicationsProvider(func(context.Context) int64 { return 10 })

	req, rec := createReq(t, "shop-new")
	func() {
		defer func() { _ = recover() }()
		h.Create(rec, req)
	}()
	if rec.Code == http.StatusForbidden {
		t.Fatal("未达配额不应 403")
	}
}
