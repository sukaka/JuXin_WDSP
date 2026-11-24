package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apidataflow"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/config"
)

func TestNewRejectsMissingMasterKeyInProduction(t *testing.T) {
	t.Setenv("JIUZHANG_MASTER_KEY", "")

	if _, err := New(&config.Config{Env: "prod"}, nil, nil); err == nil {
		t.Fatal("New() accepted production configuration without JIUZHANG_MASTER_KEY")
	}
}

func TestNewRejectsInvalidMasterKeyInProduction(t *testing.T) {
	t.Setenv("JIUZHANG_MASTER_KEY", "invalid")

	if _, err := New(&config.Config{Env: "prod"}, nil, nil); err == nil {
		t.Fatal("New() accepted an invalid production JIUZHANG_MASTER_KEY")
	}
}

func TestMS1NewNormalizesEnvAndFailsClosed(t *testing.T) {
	t.Setenv("JIUZHANG_MASTER_KEY", "")

	// "PROD" / " production " 必须归一化为 prod 并拒绝缺少 JIUZHANG_MASTER_KEY
	for _, rawEnv := range []string{"PROD", " production ", "PRODUCTION"} {
		cfg := &config.Config{Env: rawEnv}
		if _, err := New(cfg, nil, nil); err == nil {
			t.Errorf("New(Env=%q) accepted missing JIUZHANG_MASTER_KEY", rawEnv)
		}
		if cfg.Env != "prod" {
			t.Errorf("New(Env=%q) did not normalize cfg.Env, got %q", rawEnv, cfg.Env)
		}
	}

	// 未识别环境名必须 fail-closed 拒绝（即使配置了主密钥）
	t.Setenv("JIUZHANG_MASTER_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if _, err := New(&config.Config{Env: "staging"}, nil, nil); err == nil {
		t.Fatal("New(Env=staging) should fail closed")
	}
	if _, err := initEncryption(&config.Config{Env: "staging"}); err == nil {
		t.Fatal("initEncryption(Env=staging) should fail closed")
	}
}

func TestNewAPIDataflowReaderWithoutDependencies(t *testing.T) {
	reader := newAPIDataflowReader(nil, nil)
	if reader == nil {
		t.Fatal("newAPIDataflowReader() returned nil")
	}
	_, err := reader.Graph(context.Background(), apidataflow.GraphFilter{
		Start: time.Unix(0, 0),
		End:   time.Unix(1, 0),
	})
	if !errors.Is(err, apidataflow.ErrObservationDataPlane) {
		t.Fatalf("Graph() error = %v, want ErrObservationDataPlane", err)
	}
}

func TestRequireAnyPermBigScreenIsolation(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	runtimeScreenGate := requireAnyPerm("system_health.read", "big_screen.runtime.read")(okHandler)
	runtimeOverviewGate := requireAnyPerm("dashboard.runtime.read", "big_screen.runtime.read")(okHandler)

	runReq := func(h http.Handler, perms ...string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/system-health", nil)
		if perms != nil {
			set := make(map[string]bool, len(perms))
			for _, perm := range perms {
				set[perm] = true
			}
			req = req.WithContext(authz.WithPrincipal(req.Context(), &authz.Principal{
				UserID:   uuid.New(),
				Username: "tester",
				PermsSet: set,
			}))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := runReq(runtimeScreenGate); code != http.StatusUnauthorized {
		t.Errorf("unauthenticated = %d, want 401", code)
	}
	if code := runReq(runtimeScreenGate, "system_health.read"); code != http.StatusOK {
		t.Errorf("system_health.read = %d, want 200", code)
	}
	if code := runReq(runtimeScreenGate, "big_screen.runtime.read"); code != http.StatusOK {
		t.Errorf("big_screen.runtime.read on system-health = %d, want 200", code)
	}
	if code := runReq(runtimeOverviewGate, "big_screen.runtime.read"); code != http.StatusOK {
		t.Errorf("big_screen.runtime.read on runtime-overview = %d, want 200", code)
	}
	if code := runReq(runtimeOverviewGate, "dashboard.runtime.read"); code != http.StatusOK {
		t.Errorf("dashboard.runtime.read on runtime-overview = %d, want 200", code)
	}
	if code := runReq(runtimeScreenGate, "audits.read"); code != http.StatusForbidden {
		t.Errorf("audits.read on system-health = %d, want 403", code)
	}
	if code := runReq(runtimeOverviewGate, "audits.read"); code != http.StatusForbidden {
		t.Errorf("audits.read on runtime-overview = %d, want 403", code)
	}
}
