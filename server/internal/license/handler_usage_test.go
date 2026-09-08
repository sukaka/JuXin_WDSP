// handler_usage_test.go 授权状态配额用量测试：provider 注入时 status/import 响应
// 携带 usage；无 provider 或用量读取失败时省略该字段且状态查询不受影响。
package license

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// usageBody status 响应壳（State 内嵌展开 + 可选 usage）。
type usageBody struct {
	Code string `json:"code"`
	Data struct {
		Valid bool `json:"valid"`
		Usage *struct {
			Applications int64 `json:"applications"`
			APIEndpoints int64 `json:"api_endpoints"`
		} `json:"usage"`
	} `json:"data"`
}

func getStatus(t *testing.T, h http.Handler) (int, usageBody) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/license/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out usageBody
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应非 JSON: %v body=%s", err, rec.Body.String())
	}
	return rec.Code, out
}

func TestHandlerStatusUsageOmittedWithoutProvider(t *testing.T) {
	he := newHandlerEnv(t, "")
	code, body := getStatus(t, he.handler)
	if code != http.StatusOK {
		t.Fatalf("status 应 200，got %d", code)
	}
	if body.Data.Usage != nil {
		t.Fatalf("无 provider 时应省略 usage: %+v", body.Data.Usage)
	}
}

func TestHandlerStatusUsagePresent(t *testing.T) {
	env := newTestSvcEnv(t, "")
	h := NewHandler(env.svc).SetUsageProvider(func(context.Context) (int64, int64, error) {
		return 7, 42, nil
	})
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPrincipal(uuid.New()), h)

	code, body := getStatus(t, mux)
	if code != http.StatusOK {
		t.Fatalf("status 应 200，got %d", code)
	}
	if body.Data.Usage == nil || body.Data.Usage.Applications != 7 || body.Data.Usage.APIEndpoints != 42 {
		t.Fatalf("usage 应为 {7,42}: %+v", body.Data.Usage)
	}
}

func TestHandlerStatusUsageErrorOmitted(t *testing.T) {
	env := newTestSvcEnv(t, "")
	h := NewHandler(env.svc).SetUsageProvider(func(context.Context) (int64, int64, error) {
		return 0, 0, errors.New("db down")
	})
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPrincipal(uuid.New()), h)

	// 用量读取失败：省略 usage，状态查询不受影响
	code, body := getStatus(t, mux)
	if code != http.StatusOK {
		t.Fatalf("用量失败不应阻断 status，got %d", code)
	}
	if body.Data.Usage != nil {
		t.Fatalf("用量失败应省略 usage: %+v", body.Data.Usage)
	}
}

func TestHandlerImportResponseIncludesUsage(t *testing.T) {
	env := newTestSvcEnv(t, "")
	spy := &auditSpy{}
	h := NewHandler(env.svc).SetAudits(spy).SetUsageProvider(func(context.Context) (int64, int64, error) {
		return 3, 9, nil
	})
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPrincipal(uuid.New(), PermManage), h)

	fileBytes := signTestLicense(t, env.priv, buildPayloadForTest(validSample(), env.now, testKeyID))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/license/import",
		strings.NewReader(`{"file_content":`+strconvQuote(string(fileBytes))+`}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("导入应 200，got %d body=%s", rec.Code, rec.Body.String())
	}
	var out usageBody
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应非 JSON: %v", err)
	}
	if !out.Data.Valid || out.Data.Usage == nil || out.Data.Usage.Applications != 3 || out.Data.Usage.APIEndpoints != 9 {
		t.Fatalf("导入响应应含 usage {3,9}: %+v", out.Data)
	}
}
