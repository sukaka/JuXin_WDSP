// gate_test.go APM 运行期总开关门控单测：开启透传 / 关闭 503 且报文与原
// APM_ENABLED=false 启动期 stub 完全一致 / 开关运行期翻转即时生效 /
// Agent 机器端点 MachineGate 两种形态。
package apm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jiuzhang-waf/server/internal/response"
)

// okHandler 透传侧探针处理器。
func okHandler(calls *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		w.WriteHeader(http.StatusOK)
	})
}

func TestGateEnabledPassesThrough(t *testing.T) {
	rc := NewRuntimeConfig(&fakeRuntimeSettings{bools: map[string]bool{"apm:enabled": true}}, false, "")
	calls := 0
	h := NewGate(rc, okHandler(&calls))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/apm/overview", nil))
	if rr.Code != 200 || calls != 1 {
		t.Errorf("开启时应透传：status=%d calls=%d", rr.Code, calls)
	}
}

func TestGateDisabled503MatchesLegacyStub(t *testing.T) {
	rc := NewRuntimeConfig(&fakeRuntimeSettings{}, false, "")
	calls := 0
	h := NewGate(rc, okHandler(&calls))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/apm/overview", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("关闭时应 503，got %d", rr.Code)
	}
	if calls != 0 {
		t.Error("关闭时不得调用下游处理器")
	}
	// 报文与原启动期 stub 完全一致（code + 文案）
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode 503 body: %v", err)
	}
	if body.Code != response.CodeServiceUnavailable {
		t.Errorf("code = %q, want %q", body.Code, response.CodeServiceUnavailable)
	}
	want := "APM 业务性能监控已关闭（APM_ENABLED=false），WAF 核心防护不受影响"
	if body.Message != want {
		t.Errorf("message = %q, want %q", body.Message, want)
	}
}

func TestGateRuntimeFlip(t *testing.T) {
	settings := &fakeRuntimeSettings{bools: map[string]bool{"apm:enabled": false}}
	rc := NewRuntimeConfig(settings, false, "")
	calls := 0
	h := NewGate(rc, okHandler(&calls))
	// 关 → 503
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/apm/overview", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("关闭时应 503，got %d", rr.Code)
	}
	// 界面开启 → 同一路由立即透传（热生效，无需重启）
	settings.bools["apm:enabled"] = true
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/api/v1/apm/overview", nil))
	if rr.Code != 200 || calls != 1 {
		t.Errorf("开启后应立即透传：status=%d calls=%d", rr.Code, calls)
	}
}

func TestMachineGate(t *testing.T) {
	settings := &fakeRuntimeSettings{bools: map[string]bool{"apm:enabled": true}}
	rc := NewRuntimeConfig(settings, false, "")
	calls := 0
	authzCalls := 0
	authz := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authzCalls++
			next.ServeHTTP(w, r)
		})
	}
	h := NewMachineGate(rc, okHandler(&calls), authz)

	// 开启：直通机器端点，不经 authz（无会话/CSRF 面）
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/api/v1/apm/agent/heartbeat", nil))
	if rr.Code != 200 || calls != 1 {
		t.Errorf("开启时应直通：status=%d calls=%d", rr.Code, calls)
	}
	if authzCalls != 0 {
		t.Error("开启时机器端点不应经 authz 链")
	}

	// 关闭：走 authz + 503 stub（与原 APM_ENABLED=false 形态一致）
	settings.bools["apm:enabled"] = false
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/api/v1/apm/agent/heartbeat", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("关闭时应 503，got %d", rr.Code)
	}
	if authzCalls != 1 {
		t.Error("关闭时机器端点应经 authz 链（保持原 stub 前置行为）")
	}
}
