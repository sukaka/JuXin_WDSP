package jiuzhang_guard

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"go.uber.org/zap"
)

type nextFunc func(http.ResponseWriter, *http.Request) error

func (f nextFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error { return f(w, r) }

// newAPITestGuard 构造仅启用 API 动态防护所需字段的 Guard（不经过 Provision）。
func newAPITestGuard(t *testing.T, mode string, schemas map[string]map[string]string) (*Guard, string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "api-runtime-events.log")
	al, err := apievents.NewLogger(logPath, "test-node")
	if err != nil {
		t.Fatalf("new api events logger: %v", err)
	}
	t.Cleanup(func() { _ = al.Close() })
	g := &Guard{
		AppID:                "app-1",
		AppCode:              "shop",
		APIDynamicProtection: true,
		APIProtectionMode:    mode,
		APIFormalSchemas:     schemas,
		apiEvents:            al,
		logger:               zap.NewNop(),
	}
	return g, logPath
}

func readAPIRecords(t *testing.T, path string) []apievents.Record {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read api events log: %v", err)
	}
	var out []apievents.Record
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var rec apievents.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad json line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// 关闭时：零行为变化，不产事件、不进管线。
func TestServeNext_DisabledPassthrough(t *testing.T) {
	g := &Guard{APIDynamicProtection: false, logger: zap.NewNop()}
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called {
		t.Fatal("next handler not called when API protection disabled")
	}
	if RequestContextFrom(req) != nil {
		t.Fatal("request context should not carry RequestContext when disabled")
	}
}

// OBSERVE 模式 + 模型偏离：放行、上下文注入、事件落盘且含 type_mismatch 明细。
func TestServeNext_ObserveModeRecordsDeviation(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"id": "number"}}
	g, logPath := newAPITestGuard(t, "OBSERVE", schemas)

	var gotBody string
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-observe-1")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if gotBody != `{"id":"abc"}` {
		t.Fatalf("downstream body corrupted: %q", gotBody)
	}
	rc := RequestContextFrom(req)
	if rc == nil {
		t.Fatal("RequestContext not injected into request context")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	rec := recs[0]
	if rec.RequestID != "req-observe-1" || rec.EndpointKey != "POST /v1/orders" {
		t.Fatalf("bad record identity: %+v", rec)
	}
	if !rec.IsAPI || rec.Method != "POST" || rec.PathTemplate != "/v1/orders" {
		t.Fatalf("bad discovery fields: %+v", rec)
	}
	found := false
	for _, d := range rec.Details {
		if d.RuleID == "schema.type_mismatch" && d.Category == "BLOCK" {
			found = true
		}
	}
	if !found {
		t.Fatalf("type_mismatch detail missing: %+v", rec.Details)
	}
	if rec.FinalAction == "BLOCK" {
		t.Fatal("OBSERVE mode must not finalize BLOCK")
	}
}

// PROTECT 模式 + 类型偏离：403 拦截且事件落盘。
func TestServeNext_ProtectModeBlocks(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"id": "number"}}
	g, logPath := newAPITestGuard(t, "PROTECT", schemas)

	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-protect-1")
	err := g.serveNext(httptest.NewRecorder(), req, next)
	if err == nil {
		t.Fatal("expect block error")
	}
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 HandlerError, got %v", err)
	}
	if called {
		t.Fatal("next handler must not run when blocked")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 || recs[0].FinalAction != "BLOCK" {
		t.Fatalf("want 1 BLOCK event, got %+v", recs)
	}
}

// 无冻结模型 + 正常请求：放行且不阻断（缺失字段不抬升至 BLOCK）。
func TestServeNext_NoSchemaPassthrough(t *testing.T) {
	g, _ := newAPITestGuard(t, "PROTECT", nil)
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called {
		t.Fatal("next handler not called")
	}
}

// 非 API 的 GET 请求：放行且不产事件（由访问日志/WAF 事件覆盖）。
func TestServeNext_NonAPIGETNoEvent(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if recs := readAPIRecords(t, logPath); len(recs) != 0 {
		t.Fatalf("want no events for plain GET, got %+v", recs)
	}
}
