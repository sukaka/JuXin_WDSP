// gate_test.go 授权门控中间件单元测试：无授权 423 锁定/白名单放行、
// waf 授权锁 api-security、api 授权锁 l7-rules、状态翻转即时生效（恢复后放行）。
package license

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// okHandler 模拟被门控保护的下游路由（放行即 200）。
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// gateCode 请求 gate 并返回（HTTP 状态码，响应信封业务码；放行路径下游为空体时业务码为 ”）。
func gateCode(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Body.Len() == 0 {
		return rec.Code, ""
	}
	var body apiBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应非 JSON: %v body=%s", err, rec.Body.String())
	}
	return rec.Code, body.Code
}

func TestGateLocked423AndWhitelist(t *testing.T) {
	env := newTestSvcEnv(t, "") // 未导入授权：初始状态无效
	h := Gate(env.svc)(okHandler())

	// 白名单外业务接口一律 423 + LICENSE_INVALID
	for _, p := range []string{"/api/v1/applications", "/api/v1/waf-rules", "/api/v1/api-security/endpoints", "/api/v1/l7-rules"} {
		code, bizCode := gateCode(t, h, p)
		if code != http.StatusLocked || bizCode != CodeLicenseInvalid {
			t.Errorf("%s 应 423/%s，got %d/%s", p, CodeLicenseInvalid, code, bizCode)
		}
	}
	// 白名单放行：登录/会话、健康检查、授权管理、能力探测
	for _, p := range []string{
		"/api/v1/auth/login", "/api/v1/auth/captcha", "/api/v1/auth/me",
		"/api/v1/health",
		"/api/v1/license/status", "/api/v1/license/import", "/api/v1/license/history",
		"/api/v1/product/edition",
	} {
		if code, _ := gateCode(t, h, p); code != http.StatusOK {
			t.Errorf("白名单 %s 应放行，got %d", p, code)
		}
	}
	// 非 API 路径不拦截
	if code, _ := gateCode(t, h, "/assets/index.js"); code != http.StatusOK {
		t.Errorf("非 API 路径应放行，got %d", code)
	}
}

func TestGateWafProductLocksAPISecurity(t *testing.T) {
	env := newTestSvcEnv(t, "")
	rec := validSample()
	rec.Product = "waf"
	if err := env.importSample(t, rec); err != nil {
		t.Fatalf("Import: %v", err)
	}
	h := Gate(env.svc)(okHandler())

	// waf 授权：api-security 命名空间 403 + LICENSE_FEATURE_DENIED
	for _, p := range []string{"/api/v1/api-security", "/api/v1/api-security/endpoints", "/api/v1/api-security/metrics"} {
		code, bizCode := gateCode(t, h, p)
		if code != http.StatusForbidden || bizCode != CodeLicenseFeatureDenied {
			t.Errorf("%s 应 403/%s，got %d/%s", p, CodeLicenseFeatureDenied, code, bizCode)
		}
	}
	// Web 防护与共享底座能力不锁
	for _, p := range []string{"/api/v1/applications", "/api/v1/l7-rules", "/api/v1/waf-rules"} {
		if code, _ := gateCode(t, h, p); code != http.StatusOK {
			t.Errorf("waf 授权下 %s 应放行，got %d", p, code)
		}
	}
}

func TestGateAPIProductLocksL7Rules(t *testing.T) {
	env := newTestSvcEnv(t, "")
	rec := validSample()
	rec.Product = "api"
	if err := env.importSample(t, rec); err != nil {
		t.Fatalf("Import: %v", err)
	}
	h := Gate(env.svc)(okHandler())

	// api 授权：Web 防护专属接口（与 WebWAFProtectionEnabled 门控路由集合一致）403
	for _, p := range []string{"/api/v1/l7-rules", "/api/v1/l7-rules/some-id", "/api/v1/l7-rules/publish"} {
		code, bizCode := gateCode(t, h, p)
		if code != http.StatusForbidden || bizCode != CodeLicenseFeatureDenied {
			t.Errorf("%s 应 403/%s，got %d/%s", p, CodeLicenseFeatureDenied, code, bizCode)
		}
	}
	// 形似但非同一路由不误伤；API 能力域与共享底座不锁
	for _, p := range []string{"/api/v1/l7-rulesx", "/api/v1/api-security/endpoints", "/api/v1/applications"} {
		if code, _ := gateCode(t, h, p); code != http.StatusOK {
			t.Errorf("api 授权下 %s 应放行，got %d", p, code)
		}
	}
}

func TestGateStateFlipTakesEffectImmediately(t *testing.T) {
	env := newTestSvcEnv(t, "")
	// 到期日为当天（含当天有效）：env.now = 2026-08-27 10:00 UTC
	expires := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
	rec := validSample()
	rec.ExpiresAt = &expires
	if err := env.importSample(t, rec); err != nil {
		t.Fatalf("Import: %v", err)
	}
	h := Gate(env.svc)(okHandler())

	if code, _ := gateCode(t, h, "/api/v1/applications"); code != http.StatusOK {
		t.Fatalf("有效授权应放行，got %d", code)
	}
	// 时钟推进到次日：复核翻转 EXPIRED → 立即 423（无需重启/重建中间件）
	env.now = env.now.AddDate(0, 0, 1)
	if err := env.svc.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if code, bizCode := gateCode(t, h, "/api/v1/applications"); code != http.StatusLocked || bizCode != CodeLicenseInvalid {
		t.Fatalf("到期翻转后应 423/%s，got %d/%s", CodeLicenseInvalid, code, bizCode)
	}
	// 导入新授权：恢复放行
	recB := validSample()
	recB.LicenseID = "LIC-2026-0002"
	if err := env.importSample(t, recB); err != nil {
		t.Fatalf("Import B: %v", err)
	}
	if code, _ := gateCode(t, h, "/api/v1/applications"); code != http.StatusOK {
		t.Fatalf("恢复有效授权后应放行，got %d", code)
	}
}

func TestGateNilServicePassThrough(t *testing.T) {
	// nil svc 直通（装配保证非 nil；防御空指针，不改变既有链路行为）
	h := Gate(nil)(okHandler())
	if code, _ := gateCode(t, h, "/api/v1/applications"); code != http.StatusOK {
		t.Fatalf("nil svc 应直通，got %d", code)
	}
}
