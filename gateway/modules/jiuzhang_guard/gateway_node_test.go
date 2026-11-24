package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestProvisionGatewayNodeEnvPrecedence(t *testing.T) {
	t.Setenv("CAPABILITY_REPORT_DISABLED", "1")
	t.Cleanup(resetSharedEngineForTest)
	t.Cleanup(resetNetifCollectorForTest)

	cases := []struct {
		name           string
		envVal         string
		configuredNode string
		wantNode       string
	}{
		{
			name:           "env overrides configured node",
			envVal:         "  gw-b  ",
			configuredNode: "gw-a",
			wantNode:       "gw-b",
		},
		{
			name:           "empty env keeps configured node",
			envVal:         "",
			configuredNode: "gw-a",
			wantNode:       "gw-a",
		},
		{
			name:           "whitespace env keeps configured node",
			envVal:         "   ",
			configuredNode: "  gw-cfg  ",
			wantNode:       "gw-cfg",
		},
		{
			name:           "both empty falls back to gateway-unknown",
			envVal:         "",
			configuredNode: "",
			wantNode:       "gateway-unknown",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GATEWAY_NODE_NAME", tc.envVal)
			eventsPath := filepath.Join(t.TempDir(), "guard-events.log")
			g := &Guard{
				AppID:          "app-node-test",
				AppCode:        "node-test",
				EventsLog:      eventsPath,
				GatewayNode:    tc.configuredNode,
				CounterBackend: "memory",
				GlobalDeny: []ruleJSON{
					{ID: "deny-1", Address: "198.51.100.10/32", Priority: 1},
				},
			}
			if err := g.Provision(caddy.Context{Context: context.Background()}); err != nil {
				t.Fatalf("Provision: %v", err)
			}
			defer func() { _ = g.Cleanup() }()

			if g.GatewayNode != tc.wantNode {
				t.Fatalf("GatewayNode = %q, want %q", g.GatewayNode, tc.wantNode)
			}

			// Trigger an access-control event and verify events_log records the resolved node identity.
			req := httptest.NewRequest(http.MethodGet, "http://example.com/probe", nil)
			req.RemoteAddr = "198.51.100.10:12345"
			rec := httptest.NewRecorder()
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(http.StatusOK)
				return nil
			})
			err := g.ServeHTTP(rec, req, next)
			var he caddyhttp.HandlerError
			if !errors.As(err, &he) || he.StatusCode != http.StatusForbidden {
				t.Fatalf("ServeHTTP err = %v, want HTTP 403 HandlerError", err)
			}
			_ = g.Cleanup()

			raw, err := os.ReadFile(eventsPath)
			if err != nil {
				t.Fatalf("read events log: %v", err)
			}
			line := strings.TrimSpace(string(raw))
			if line == "" {
				t.Fatal("expected guard event line in events_log")
			}
			var ev struct {
				GatewayNode string `json:"gateway_node_id"`
			}
			if err := json.Unmarshal([]byte(strings.Split(line, "\n")[0]), &ev); err != nil {
				t.Fatalf("unmarshal event: %v (raw=%s)", err, line)
			}
			if ev.GatewayNode != tc.wantNode {
				t.Fatalf("event gateway_node = %q, want %q", ev.GatewayNode, tc.wantNode)
			}
		})
	}
}
