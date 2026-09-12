// noise_handler_test.go AI 自动降噪端点测试：权限校验（403）、参数校验（400）、
// suppress/resolve 状态流转（内存仓储，语义与 SQL 实现一致）。
package aihandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/ainoise"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/settings"
)

// noiseMux 构造注入指定主体的降噪路由（authChain 打桩：仅注入 Principal）。
func noiseMux(d *Deps, p *authz.Principal) http.Handler {
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	})
	return mux
}

func noisePrincipal(perms ...string) *authz.Principal {
	set := map[string]bool{}
	for _, perm := range perms {
		set[perm] = true
	}
	return &authz.Principal{UserID: uuid.New(), Username: "secadmin", PermsSet: set}
}

// seedNoise 种入一个 WAF 簇并返回 ID。
func seedNoise(t *testing.T, store *ainoise.MemStore) uuid.UUID {
	t.Helper()
	rule := 942100
	_, id, err := store.UpsertEvent(context.Background(), ainoise.EventInput{
		EventID: uuid.New(), Source: ainoise.SourceWAF, Host: "a.com", RawURI: "/search",
		RuleID: &rule, ClientIP: "1.2.3.4", OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func doRequest(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestNoiseClusterListForbidden(t *testing.T) {
	d := NewDeps(Deps{Noise: ainoise.NewMemStore()})
	h := noiseMux(d, noisePrincipal("ai.chat.use")) // 无降噪权限
	rec := doRequest(t, h, "GET", "/api/v1/ai/noise/clusters", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rec.Code)
	}
}

func TestNoiseClusterListOK(t *testing.T) {
	store := ainoise.NewMemStore()
	seedNoise(t, store)
	d := NewDeps(Deps{Noise: store})
	h := noiseMux(d, noisePrincipal("ai.noise_reduction.use"))
	rec := doRequest(t, h, "GET", "/api/v1/ai/noise/clusters?source=WAF&status=ACTIVE", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Total int64 `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.Total != 1 {
		t.Fatalf("total=%d want 1", body.Data.Total)
	}
}

func TestNoiseClusterListInvalidFilter(t *testing.T) {
	d := NewDeps(Deps{Noise: ainoise.NewMemStore()})
	h := noiseMux(d, noisePrincipal("ai.noise_reduction.use"))
	rec := doRequest(t, h, "GET", "/api/v1/ai/noise/clusters?status=BOGUS", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rec.Code)
	}
}

func TestNoiseClusterGetInvalidID(t *testing.T) {
	d := NewDeps(Deps{Noise: ainoise.NewMemStore()})
	h := noiseMux(d, noisePrincipal("ai.noise_reduction.use"))
	rec := doRequest(t, h, "GET", "/api/v1/ai/noise/clusters/not-a-uuid", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rec.Code)
	}
	rec = doRequest(t, h, "GET", "/api/v1/ai/noise/clusters/"+uuid.NewString(), "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404", rec.Code)
	}
}

func TestNoiseClusterSuppressResolveFlow(t *testing.T) {
	store := ainoise.NewMemStore()
	id := seedNoise(t, store)
	d := NewDeps(Deps{Noise: store}) // Audit=nil：recordAIAudit 空值守卫
	h := noiseMux(d, noisePrincipal("ai.noise_reduction.use"))

	rec := doRequest(t, h, "POST", "/api/v1/ai/noise/clusters/"+id.String()+"/suppress", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("suppress status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.Status != "SUPPRESSED" {
		t.Fatalf("status=%s want SUPPRESSED", body.Data.Status)
	}

	// 已抑制再抑制 → 409
	rec = doRequest(t, h, "POST", "/api/v1/ai/noise/clusters/"+id.String()+"/suppress", "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("re-suppress status=%d want 409", rec.Code)
	}

	// 抑制态可解决 → RESOLVED；之后不可再流转
	rec = doRequest(t, h, "POST", "/api/v1/ai/noise/clusters/"+id.String()+"/resolve", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("resolve status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = doRequest(t, h, "POST", "/api/v1/ai/noise/clusters/"+id.String()+"/resolve", "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("re-resolve status=%d want 409", rec.Code)
	}
}

func TestNoiseSweepManagePermission(t *testing.T) {
	store := ainoise.NewMemStore()
	d := NewDeps(Deps{Noise: store, NoiseWorker: ainoise.NewWorker(store, nil, nil, nil, nil)})
	// use 权限不足以手动触发扫描（manage）
	h := noiseMux(d, noisePrincipal("ai.noise_reduction.use"))
	rec := doRequest(t, h, "POST", "/api/v1/ai/noise/sweeps", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rec.Code)
	}
	// manage 权限：worker 源未装配 → 200 + FAILED 统计（降级不致命，如实记录）
	h = noiseMux(d, noisePrincipal("ai.noise_reduction.manage"))
	rec = doRequest(t, h, "POST", "/api/v1/ai/noise/sweeps", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.Status != "FAILED" {
		t.Fatalf("sweep status=%s want FAILED (source 未装配)", body.Data.Status)
	}
}

func TestNoiseSettingsValidation(t *testing.T) {
	// Settings 非 nil（db=nil 仅在校验通过后才会触达，非法输入先行 400）
	d := NewDeps(Deps{Noise: ainoise.NewMemStore(), Settings: settings.NewService(nil)})
	h := noiseMux(d, noisePrincipal("ai.noise_reduction.manage"))
	for _, body := range []string{
		`{"interval_seconds": 5}`,      // 低于下限
		`{"interval_seconds": 999999}`, // 高于上限
		`{"sweep_window_minutes": 0}`,  // 低于下限
		`{"min_events_threshold": -1}`, // 低于下限
		`{"interval_seconds": "abc"}`,  // 类型错误
	} {
		rec := doRequest(t, h, "PUT", "/api/v1/ai/noise/settings", body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d want 400", body, rec.Code)
		}
	}
	// use 权限不足以改设置
	h2 := noiseMux(d, noisePrincipal("ai.noise_reduction.use"))
	rec := doRequest(t, h2, "PUT", "/api/v1/ai/noise/settings", `{"enabled": true}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rec.Code)
	}
}
