package jiuzhang_guard

import (
	"bufio"
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
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
)

const identityBlockTestSalt = "identity-block-test-salt"

func identityBlockTestRequest(ip string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://waf-test.local/v1/orders", nil)
	r.RemoteAddr = ip + ":1001"
	r.Header.Set("X-Request-Id", "identity-block-request")
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	return r
}

func identityBlockTestKey(r *http.Request, ip string) string {
	return identitybehavior.ResolveIdentity(r, identityBlockTestSalt, ip).Key
}

func requireIdentityBlockStatus(t *testing.T, err error) {
	t.Helper()
	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusForbidden {
		t.Fatalf("error=%v want 403", err)
	}
}

func readIdentityBlockEvents(t *testing.T, path string) []events.Event {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var out []events.Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event events.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		out = append(out, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCompileAPIIdentityBlocksValidation(t *testing.T) {
	validKey := strings.Repeat("a", 32)
	for _, tc := range []struct {
		name  string
		items []identityBlockJSON
	}{
		{name: "empty id", items: []identityBlockJSON{{IdentityKey: validKey}}},
		{name: "invalid id", items: []identityBlockJSON{{ID: "bad id", IdentityKey: validKey}}},
		{name: "long id", items: []identityBlockJSON{{ID: strings.Repeat("a", 65), IdentityKey: validKey}}},
		{name: "empty key", items: []identityBlockJSON{{ID: "block-1"}}},
		{name: "non hex key", items: []identityBlockJSON{{ID: "block-1", IdentityKey: strings.Repeat("z", 32)}}},
		{name: "uppercase key", items: []identityBlockJSON{{ID: "block-1", IdentityKey: strings.Repeat("A", 32)}}},
		{name: "short key", items: []identityBlockJSON{{ID: "block-1", IdentityKey: "abc"}}},
		{name: "duplicate id", items: []identityBlockJSON{{ID: "block-1", IdentityKey: validKey}, {ID: "block-1", IdentityKey: strings.Repeat("b", 32)}}},
		{name: "duplicate key", items: []identityBlockJSON{{ID: "block-1", IdentityKey: validKey}, {ID: "block-2", IdentityKey: validKey}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &Guard{EventsLog: filepath.Join(t.TempDir(), "events.log"), APIIdentityBlocks: tc.items}
			if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "api_identity_blocks") {
				t.Fatalf("Validate must reject invalid identity blocks: %v", err)
			}
			if err := g.Provision(caddy.Context{Context: context.Background()}); err == nil || !strings.Contains(err.Error(), "api_identity_blocks") {
				t.Fatalf("Provision must reject invalid identity blocks: %v", err)
			}
			_ = g.Cleanup()
		})
	}
	compiled, err := compileAPIIdentityBlocks([]identityBlockJSON{{ID: "block-1", IdentityKey: validKey}})
	if err != nil || compiled[validKey] != "block-1" {
		t.Fatalf("valid identity block rejected: %v %v", compiled, err)
	}
	if compiled, err := compileAPIIdentityBlocks(nil); err != nil || compiled != nil {
		t.Fatalf("nil blocks must stay nil: %v %v", compiled, err)
	}
}

func TestIdentityBlockTypesAndEventBoundary(t *testing.T) {
	const credential = "identity-block-secret-token"
	for _, tc := range []struct {
		name     string
		ip       string
		headers  map[string]string
		wantType string
	}{
		{name: "human", ip: "203.0.113.220", headers: map[string]string{"User-Agent": "Mozilla/5.0 Chrome/120.0 Safari/537.36"}, wantType: identitybehavior.IdentityHuman},
		{name: "bot", ip: "203.0.113.221", headers: map[string]string{"User-Agent": "curl/8.1"}, wantType: identitybehavior.IdentityBot},
		{name: "credential", ip: "203.0.113.222", headers: map[string]string{"Authorization": "Bearer " + credential, "User-Agent": "Mozilla/5.0"}},
		{name: "anonymous browser", ip: "203.0.113.223", headers: map[string]string{"User-Agent": "custom-agent"}},
		{name: "ip fallback", ip: "203.0.113.224"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := identityBlockTestRequest(tc.ip, tc.headers)
			identity := identitybehavior.ResolveIdentity(req, identityBlockTestSalt, tc.ip)
			if tc.wantType != "" && identity.Type != tc.wantType {
				t.Fatalf("fixture identity type=%s want=%s", identity.Type, tc.wantType)
			}
			logPath := filepath.Join(t.TempDir(), "events.log")
			g := provisionIBHTestGuard(t, Guard{
				AppID: "app1", EventsLog: logPath, IdentitySalt: identityBlockTestSalt,
				APIIdentityBlocks: []identityBlockJSON{{ID: "identity-block-1", IdentityKey: identity.Key}},
			})
			called := false
			err := g.ServeHTTP(httptest.NewRecorder(), req, nextHandler{&called})
			requireIdentityBlockStatus(t, err)
			if called {
				t.Fatal("identity block must not reach upstream")
			}
			records := readIdentityBlockEvents(t, logPath)
			if len(records) != 1 {
				t.Fatalf("events=%d want 1: %+v", len(records), records)
			}
			event := records[0]
			if event.EventType != events.IdentityManualBlock || event.Action != "BLOCK" || event.PolicyID != "identity-block-1" || event.ResponseStatus != http.StatusForbidden {
				t.Fatalf("bad identity block event: %+v", event)
			}
			finalDecision := string(event.FinalDecision)
			for _, want := range []string{"MANUAL_BAN", "BLOCK", "identity-block-1", "IDENTITY_MANUAL_BLOCK"} {
				if !strings.Contains(finalDecision, want) {
					t.Fatalf("final_decision missing contribution %q: %s", want, finalDecision)
				}
			}
			raw, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{identity.Key, credential, "identity_key"} {
				if forbidden != "" && strings.Contains(string(raw), forbidden) {
					t.Fatalf("identity plaintext %q leaked into event: %s", forbidden, raw)
				}
			}
		})
	}
}

func TestIdentityBlockPrecedesProtectedAllowBotAndAPI(t *testing.T) {
	const ip = "203.0.113.225"
	req := identityBlockTestRequest(ip, nil)
	logPath := filepath.Join(t.TempDir(), "events.log")
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: logPath, IdentitySalt: identityBlockTestSalt,
		APIIdentityBlocks:    []identityBlockJSON{{ID: "identity-priority", IdentityKey: identityBlockTestKey(req, ip)}},
		ProtectedAddresses:   []string{"203.0.113.0/24"},
		GlobalAllow:          []ruleJSON{{ID: "allow-ip", Address: "203.0.113.0/24", Priority: 1}},
		APIDynamicProtection: true,
		APIProtectionMode:    "PROTECT",
		IdentityBehavior:     &identityBehaviorJSON{Enabled: true},
	})
	called := false
	err := g.ServeHTTP(httptest.NewRecorder(), req, nextHandler{&called})
	requireIdentityBlockStatus(t, err)
	if called {
		t.Fatal("protected address, allowlist, Bot or API must not bypass identity block")
	}
	if RequestContextFrom(req) != nil {
		t.Fatal("API pipeline must not run after identity block")
	}
	records := readIdentityBlockEvents(t, logPath)
	if len(records) != 1 || records[0].EventType != events.IdentityManualBlock || records[0].PolicyID != "identity-priority" {
		t.Fatalf("unexpected priority event: %+v", records)
	}
}

func TestIdentityBlockDefaultAndRemoval(t *testing.T) {
	const ip = "203.0.113.226"
	req := identityBlockTestRequest(ip, nil)
	t.Run("default zero change", func(t *testing.T) {
		logPath := filepath.Join(t.TempDir(), "events.log")
		g := provisionIBHTestGuard(t, Guard{AppID: "app1", EventsLog: logPath, IdentitySalt: identityBlockTestSalt})
		called := false
		if err := g.ServeHTTP(httptest.NewRecorder(), req, nextHandler{&called}); err != nil || !called {
			t.Fatalf("no identity list must preserve default behavior: err=%v called=%v", err, called)
		}
		for _, event := range readIdentityBlockEvents(t, logPath) {
			if event.EventType == events.IdentityManualBlock {
				t.Fatalf("no list must not emit identity block: %+v", event)
			}
		}
	})
	t.Run("publish removal unblocks", func(t *testing.T) {
		blocked := provisionIBHTestGuard(t, Guard{
			AppID: "app1", EventsLog: filepath.Join(t.TempDir(), "events.log"), IdentitySalt: identityBlockTestSalt,
			APIIdentityBlocks: []identityBlockJSON{{ID: "identity-remove", IdentityKey: identityBlockTestKey(req, ip)}},
		})
		called := false
		err := blocked.ServeHTTP(httptest.NewRecorder(), req, nextHandler{&called})
		requireIdentityBlockStatus(t, err)
		if called {
			t.Fatal("fixture must initially block")
		}
		unblocked := provisionIBHTestGuard(t, Guard{AppID: "app1", EventsLog: filepath.Join(t.TempDir(), "events.log"), IdentitySalt: identityBlockTestSalt})
		called = false
		if err := unblocked.ServeHTTP(httptest.NewRecorder(), req, nextHandler{&called}); err != nil || !called {
			t.Fatalf("removing identity list must allow request: err=%v called=%v", err, called)
		}
	})
}
