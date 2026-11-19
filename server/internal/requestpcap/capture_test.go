package requestpcap

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/systemops"
)

type captureSettingsStub struct{ value string }

func (s *captureSettingsStub) GetStringWithSource(context.Context, string, string) (string, bool, error) {
	return s.value, s.value != "", nil
}
func (s *captureSettingsStub) UpsertString(_ context.Context, _, _, value, _ string, _ uuid.UUID) error {
	s.value = value
	return nil
}

func newCaptureFixture(t *testing.T, permissions ...string) (*CaptureController, *captureSettingsStub, *requestAuditSpy, *http.ServeMux) {
	t.Helper()
	settings := &captureSettingsStub{}
	spy := &requestAuditSpy{}
	controller := NewCaptureController(settings, t.TempDir(), "gw-capture", spy)
	controller.now = func() time.Time { return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC) }
	mux := http.NewServeMux()
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			permissionSet := map[string]bool{}
			for _, permission := range permissions {
				permissionSet[permission] = true
			}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), &authz.Principal{UserID: uuid.New(),
				Username: "system-admin", SessionID: "capture-session", PermsSet: permissionSet})))
		})
	}
	mux.Handle("GET /api/v1/request-pcap/capture", auth(middleware.RequirePermission(PermissionCaptureControl)(http.HandlerFunc(controller.Get))))
	mux.Handle("POST /api/v1/request-pcap/capture", auth(middleware.RequirePermission(PermissionCaptureControl)(http.HandlerFunc(controller.Set))))
	return controller, settings, spy, mux
}

func captureCommands(t *testing.T, controller *CaptureController) []systemops.Command {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(controller.hostctl, "pcap_capture-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	commands := make([]systemops.Command, 0, len(matches))
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var command systemops.Command
		if err := json.Unmarshal(raw, &command); err != nil {
			t.Fatal(err)
		}
		commands = append(commands, command)
	}
	return commands
}

func TestCaptureControlRequiresSystemAdminPermission(t *testing.T) {
	_, _, _, mux := newCaptureFixture(t)
	if got := requestJSON(t, mux, http.MethodGet, "/api/v1/request-pcap/capture", nil); got.Code != http.StatusForbidden {
		t.Fatalf("GET capture without permission = %d", got.Code)
	}
	body := map[string]interface{}{"enabled": true, "interface": "eth0", "ports": []int{80}, "hot_dir": "/srv/jiuzhang-hot", "warm_dir": "/srv/jiuzhang-warm", "reason": "test"}
	if got := requestJSON(t, mux, http.MethodPost, "/api/v1/request-pcap/capture", body); got.Code != http.StatusForbidden {
		t.Fatalf("POST capture without permission = %d", got.Code)
	}
}

func TestCaptureEnableAndDisableUseRealSignedCommands(t *testing.T) {
	controller, _, spy, mux := newCaptureFixture(t, PermissionCaptureControl)
	body := map[string]interface{}{"enabled": true, "interface": "eth0", "ports": []int{443, 80}, "hot_dir": "/srv/jiuzhang-hot", "warm_dir": "/srv/jiuzhang-warm", "reason": "业务取证"}
	if got := requestJSON(t, mux, http.MethodPost, "/api/v1/request-pcap/capture", body); got.Code != http.StatusAccepted {
		t.Fatalf("enable = %d: %s", got.Code, got.Body.String())
	}
	commands := captureCommands(t, controller)
	if len(commands) != 1 || commands[0].Enabled == nil || !*commands[0].Enabled || commands[0].HMAC == "" {
		t.Fatalf("invalid signed enable command: %+v", commands)
	}
	if commands[0].Ports[0] != 443 || commands[0].Ports[1] != 80 || commands[0].NodeID != "gw-capture" {
		t.Fatalf("unexpected enable scope: %+v", commands[0])
	}
	if got := spy.last().Action; got != "request_pcap.capture_enable" || spy.last().RiskLevel != audits.RiskHigh {
		t.Fatalf("missing enable audit: %+v", spy.last())
	}
	if got := requestJSON(t, mux, http.MethodPost, "/api/v1/request-pcap/capture", map[string]interface{}{"enabled": false, "reason": "停止取证"}); got.Code != http.StatusAccepted {
		t.Fatalf("disable = %d: %s", got.Code, got.Body.String())
	}
	commands = captureCommands(t, controller)
	if len(commands) != 2 {
		t.Fatalf("commands = %d", len(commands))
	}
	var last systemops.Command
	for _, command := range commands {
		if command.Enabled != nil && !*command.Enabled {
			last = command
		}
	}
	if last.Enabled == nil || *last.Enabled || last.Interface != "eth0" || last.HotDir != "/srv/jiuzhang-hot" || last.WarmDir != "/srv/jiuzhang-warm" {
		t.Fatalf("disable did not preserve scope: %+v", last)
	}
	statusRaw, _ := json.Marshal(map[string]string{"requestID": last.RequestID, "state": "DISABLED"})
	if err := os.WriteFile(filepath.Join(controller.hostctl, "pcap-status.state"), statusRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	status := controller.status(&CaptureConfig{Enabled: true, RequestID: last.RequestID, RequestedAt: controller.now()})
	if status.Enabled || status.State != "DISABLED" {
		t.Fatalf("actual disable status incorrect: %+v", status)
	}
}

func TestCaptureRejectsInvalidScopeWithoutWritingCommand(t *testing.T) {
	controller, _, _, mux := newCaptureFixture(t, PermissionCaptureControl)
	body := map[string]interface{}{"enabled": true, "interface": "eth0;id", "ports": []int{80}, "hot_dir": "/srv/jiuzhang-hot", "warm_dir": "/srv/jiuzhang-warm", "reason": "test"}
	if got := requestJSON(t, mux, http.MethodPost, "/api/v1/request-pcap/capture", body); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid interface = %d", got.Code)
	}
	body["interface"] = "eth0"
	body["hot_dir"] = "/srv/jiuzhang-warm/nested"
	if got := requestJSON(t, mux, http.MethodPost, "/api/v1/request-pcap/capture", body); got.Code != http.StatusBadRequest {
		t.Fatalf("nested storage = %d", got.Code)
	}
	for _, badDir := range []string{"/var/lib/docker", "/var/lib/systemd", "/srv/other", "/var/lib/jiuzhang-other", "/srv/jiuzhang"} {
		body["hot_dir"] = badDir
		body["warm_dir"] = "/srv/jiuzhang-warm"
		if got := requestJSON(t, mux, http.MethodPost, "/api/v1/request-pcap/capture", body); got.Code != http.StatusBadRequest {
			t.Fatalf("unsafe storage dir %s accepted with status=%d", badDir, got.Code)
		}
	}
	if commands := captureCommands(t, controller); len(commands) != 0 {
		t.Fatalf("invalid request wrote command: %+v", commands)
	}
}

func TestCaptureFailedStatusDoesNotLookEnabled(t *testing.T) {
	controller, _, _, _ := newCaptureFixture(t, PermissionCaptureControl)
	config := &CaptureConfig{Enabled: true, RequestID: uuid.NewString(), RequestedAt: controller.now()}
	raw, _ := json.Marshal(map[string]string{"requestID": config.RequestID, "state": "FAILED", "message": "pcapd启动失败"})
	if err := os.WriteFile(filepath.Join(controller.hostctl, "pcap-status.state"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	status := controller.status(config)
	if status.Enabled || status.State != "FAILED" || status.Message != "pcapd启动失败" {
		t.Fatalf("failure hidden: %+v", status)
	}
}

func TestCaptureUnreadableStatusIsFailureNotPending(t *testing.T) {
	controller, _, _, _ := newCaptureFixture(t, PermissionCaptureControl)
	if err := os.Mkdir(filepath.Join(controller.hostctl, "pcap-status.state"), 0o700); err != nil {
		t.Fatal(err)
	}
	status := controller.status(&CaptureConfig{Enabled: true, RequestID: uuid.NewString(), RequestedAt: controller.now()})
	if status.Enabled || status.State != "FAILED" {
		t.Fatalf("unreadable host status was treated as pending: %+v", status)
	}
}

func TestCaptureWriteFlagFailureDoesNotDesyncSettings(t *testing.T) {
	controller, settings, _, mux := newCaptureFixture(t, PermissionCaptureControl)
	blocker := filepath.Join(t.TempDir(), "hostctl-file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	controller.hostctl = blocker
	body := map[string]interface{}{"enabled": true, "interface": "eth0", "ports": []int{443}, "hot_dir": "/var/lib/jiuzhang-pcap/hot", "warm_dir": "/var/lib/jiuzhang-pcap/warm", "reason": "test"}
	if got := requestJSON(t, mux, http.MethodPost, "/api/v1/request-pcap/capture", body); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("hostctl failure status = %d, want 503", got.Code)
	}
	if settings.value != "" {
		t.Fatalf("settings desynced after flag write failure: %s", settings.value)
	}
}

func TestCaptureDisableRetriesWhenHostNotDisabled(t *testing.T) {
	controller, settings, _, mux := newCaptureFixture(t, PermissionCaptureControl)
	prevReqID := uuid.NewString()
	prev := CaptureConfig{
		Enabled:     false,
		Interface:   "eth0",
		Ports:       []int{443},
		HotDir:      "/var/lib/jiuzhang-pcap/hot",
		WarmDir:     "/var/lib/jiuzhang-pcap/warm",
		RequestID:   prevReqID,
		RequestedAt: controller.now(),
	}
	raw, _ := json.Marshal(prev)
	settings.value = string(raw)
	statusRaw, _ := json.Marshal(map[string]string{"requestID": prevReqID, "state": "FAILED", "message": "stop failed"})
	if err := os.WriteFile(filepath.Join(controller.hostctl, "pcap-status.state"), statusRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	got := requestJSON(t, mux, http.MethodPost, "/api/v1/request-pcap/capture", map[string]interface{}{"enabled": false, "reason": "retry disable"})
	if got.Code != http.StatusAccepted {
		t.Fatalf("retry disable when host FAILED = %d, want 202 (%s)", got.Code, got.Body.String())
	}
	commands := captureCommands(t, controller)
	if len(commands) != 1 || commands[0].Enabled == nil || *commands[0].Enabled {
		t.Fatalf("expected fresh disable command, got %+v", commands)
	}
}
