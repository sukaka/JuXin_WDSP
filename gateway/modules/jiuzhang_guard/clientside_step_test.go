package jiuzhang_guard

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/dynamic_security/capability"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientside"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/l7rules"
)

func TestClientSideValidateAndProvisionFailClosed(t *testing.T) {
	// Unknown field rejected by Validate.
	g := &Guard{
		EventsLog:        t.TempDir() + "/events.log",
		ClientSidePolicy: json.RawMessage(`{"schema_version":1,"mode":"OBSERVE","bogus":1}`),
	}
	if err := g.Validate(); err == nil {
		t.Fatal("expected unknown field in client_side_policy to fail Validate")
	}

	// CR/LF injection in custom_csp_directives rejected by Validate.
	g2 := &Guard{
		EventsLog:        t.TempDir() + "/events.log",
		ClientSidePolicy: json.RawMessage(`{"schema_version":1,"mode":"PROTECT","csp_mode":"ENFORCE","custom_csp_directives":"object-src 'none'\r\nX-Bad: 1"}`),
	}
	if err := g2.Validate(); err == nil {
		t.Fatal("expected CR/LF in custom_csp_directives to fail Validate")
	}

	// Unsupported schema_version rejected.
	g3 := &Guard{
		EventsLog:        t.TempDir() + "/events.log",
		ClientSidePolicy: json.RawMessage(`{"schema_version":99,"mode":"OFF"}`),
	}
	if err := g3.Validate(); err == nil {
		t.Fatal("expected unsupported schema_version to fail Validate")
	}
}

func TestClientSideStep_ReservedEndpointsNeverProxiedEvenWhenOffOrAllowlisted(t *testing.T) {
	// Guard with NO client_side_policy configured + allowlists/protected addresses.
	g := newTestGuard(t, Guard{
		AppID:              "app-cs-off",
		AppCode:            "shop",
		ProtectedAddresses: []string{"198.51.100.10/32"},
		GlobalAllow:        []ruleJSON{{ID: "allow-ip", Address: "198.51.100.20/32", Priority: 1}},
		GlobalURLAllow:     []urlAllowRuleJSON{{ID: "allow-url", MatchType: "PREFIX", URIPattern: "/_wdsp", Priority: 1}},
	})

	cases := []struct {
		method string
		path   string
		ip     string
		want   int
	}{
		{http.MethodPost, "/_wdsp/csp/v1/report", "203.0.113.1:1234", http.StatusNotFound},
		{http.MethodGet, "/_wdsp/csp/v1/report", "198.51.100.10:1234", http.StatusMethodNotAllowed},
		{http.MethodPost, "/_wdsp/csp/v1/unknown", "198.51.100.20:1234", http.StatusNotFound},
		{http.MethodGet, "/_wdsp/cs/v1/probe.js", "203.0.113.1:1234", http.StatusNotFound},
		{http.MethodGet, "/_wdsp/cs/v1/other", "198.51.100.10:1234", http.StatusNotFound},
	}
	for _, tc := range cases {
		called := false
		r := httptest.NewRequest(tc.method, "https://shop.example.com"+tc.path, strings.NewReader(`{}`))
		r.RemoteAddr = tc.ip
		rec := httptest.NewRecorder()
		if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
			t.Fatalf("%s %s err: %v", tc.method, tc.path, err)
		}
		if called {
			t.Fatalf("%s %s MUST NEVER be reverse-proxied!", tc.method, tc.path)
		}
		if rec.Code != tc.want {
			t.Fatalf("%s %s status = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}

	// Normal business path passes through untouched with zero CSP or body modification.
	htmlNext := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head></head><body><script src="https://evil.example/x.js"></script></body></html>`))
		return nil
	})
	rBiz := httptest.NewRequest(http.MethodGet, "https://shop.example.com/checkout", nil)
	rBiz.RemoteAddr = "203.0.113.2:1234"
	recBiz := httptest.NewRecorder()
	if err := g.ServeHTTP(recBiz, rBiz, htmlNext); err != nil {
		t.Fatal(err)
	}
	if recBiz.Code != http.StatusOK || recBiz.Header().Get(clientside.HeaderCSP) != "" || recBiz.Header().Get(clientside.HeaderCSPReportOnly) != "" {
		t.Fatalf("OFF guard must not inject CSP or alter business traffic: code=%d headers=%v", recBiz.Code, recBiz.Header())
	}
	if !strings.Contains(recBiz.Body.String(), "evil.example/x.js") {
		t.Fatal("OFF guard must pass body through untouched")
	}
}

func TestClientSideStep_ProtectStripProbeCSPAndReportEndToEnd(t *testing.T) {
	pinnedSRI := "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
	pol := clientside.Policy{
		SchemaVersion:            1,
		ApplicationID:            "app-cs-protect",
		Mode:                     clientside.ModeProtect,
		Version:                  2,
		CSPMode:                  clientside.CSPModeEnforce,
		SensitivePaths:           []string{"/checkout", "/pay"},
		ProbeEnabled:             true,
		StripUnauthorizedScripts: true,
		AllowedScriptOrigins:     []string{"'self'", "https://cdn.example.com"},
		AllowedConnectOrigins:    []string{"'self'"},
		AllowedFormOrigins:       []string{"'self'"},
		CustomCSPDirectives:      "object-src 'none'",
		AuthorizedScripts: []clientside.AuthorizedScript{
			{
				ScriptURL:  "https://cdn.example.com/pay.js",
				ScriptType: clientside.ScriptTypeExternal,
				SRIHash:    pinnedSRI,
				Status:     clientside.ScriptStatusAuthorized,
			},
		},
	}

	g := newTestGuard(t, Guard{
		AppID:              "app-cs-protect",
		AppCode:            "pay",
		ProtectedAddresses: []string{"198.51.100.10/32"},
		GlobalAllow:        []ruleJSON{{ID: "allow-ip", Address: "198.51.100.20/32", Priority: 1}},
		GlobalURLAllow:     []urlAllowRuleJSON{{ID: "allow-url", MatchType: "PREFIX", URIPattern: "/checkout", Priority: 1}},
		L7Rules: &l7rules.Config{
			Rules: []l7rules.RuleJSON{{
				ID:       "l7-allow",
				Name:     "L7 Allow",
				Enabled:  true,
				Priority: 1,
				Action:   "allow",
				Conditions: []l7rules.ConditionJSON{{
					Type:  "uri",
					Op:    "prefix",
					Value: "/pay",
				}},
			}},
		},
		ClientSidePolicy: mustJSON(t, pol),
	})
	if err := g.assembleClientSide(); err != nil {
		t.Fatalf("assembleClientSide: %v", err)
	}

	// 1. Sensitive path + allowlist/L7 allow MUST NOT bypass CSP, script stripping, or probe injection.
	htmlOrigin := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		doc := `<!doctype html><html><head><title>Pay</title>` +
			`<script src="https://cdn.example.com/pay.js" integrity="sha384-TAMPEREDHASH"></script>` +
			`<script src="https://skimmer.evil.example/card.js?k=secret"></script>` +
			`<script src="/assets/ui.js"></script>` +
			`</head><body><form action="/pay/submit"></form></body></html>`
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(doc)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(doc))
		return nil
	})

	for _, tc := range []struct {
		name string
		ip   string
		path string
	}{
		{"protected_ip", "198.51.100.10:1111", "/checkout"},
		{"ip_allowlist", "198.51.100.20:1111", "/checkout/step2"},
		{"url_allowlist", "203.0.113.5:1111", "/checkout"},
		{"l7_allow", "203.0.113.6:1111", "/pay/card"},
	} {
		t.Run("non_bypass_"+tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://shop.example.com"+tc.path, nil)
			r.RemoteAddr = tc.ip
			rec := httptest.NewRecorder()
			if err := g.ServeHTTP(rec, r, htmlOrigin); err != nil {
				t.Fatalf("ServeHTTP: %v", err)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			csp := rec.Header().Get(clientside.HeaderCSP)
			if !strings.Contains(csp, "script-src 'self' https://cdn.example.com") || !strings.Contains(csp, "report-uri /_wdsp/csp/v1/report") {
				t.Fatalf("CSP header missing/malformed: %q", csp)
			}
			body := rec.Body.String()
			if strings.Contains(body, "skimmer.evil.example") || strings.Contains(body, "TAMPEREDHASH") {
				t.Fatalf("unauthorized/tampered scripts must be stripped: %s", body)
			}
			if !strings.Contains(body, `/assets/ui.js`) {
				t.Fatalf("same-origin script must remain: %s", body)
			}
			if !strings.Contains(body, clientside.ProbeScriptTag()) {
				t.Fatalf("probe tag must be injected on sensitive path %q: %s", tc.path, body)
			}
			if rec.Header().Get("Content-Length") != strconv.Itoa(len(body)) {
				t.Fatalf("Content-Length %q != actual %d", rec.Header().Get("Content-Length"), len(body))
			}
		})
	}

	// 2. Non-sensitive path (/about) gets CSP + stripping but NO probe script injected.
	{
		r := httptest.NewRequest(http.MethodGet, "https://shop.example.com/about", nil)
		r.RemoteAddr = "203.0.113.9:1111"
		rec := httptest.NewRecorder()
		if err := g.ServeHTTP(rec, r, htmlOrigin); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(rec.Body.String(), clientside.ProbeScriptPath) {
			t.Fatal("non-sensitive path /about must not receive probe script")
		}
		if rec.Header().Get(clientside.HeaderCSP) == "" {
			t.Fatal("non-sensitive HTML path must still receive CSP header")
		}
	}

	// 3. GET /_wdsp/cs/v1/probe.js served locally (never proxied) with matching SRI.
	{
		called := false
		r := httptest.NewRequest(http.MethodGet, "https://shop.example.com/_wdsp/cs/v1/probe.js", nil)
		r.RemoteAddr = "203.0.113.10:1111"
		rec := httptest.NewRecorder()
		if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
			t.Fatal(err)
		}
		if called || rec.Code != http.StatusOK {
			t.Fatalf("probe.js expected local 200, got code=%d called=%v", rec.Code, called)
		}
		if rec.Header().Get("Cache-Control") != "public, max-age=300" ||
			rec.Header().Get("Content-Type") != "application/javascript; charset=utf-8" {
			t.Fatalf("unexpected probe headers: %v", rec.Header())
		}
		if rec.Body.String() != clientside.ProbeScriptJS {
			t.Fatal("probe.js body mismatch")
		}
	}

	// 4. POST /_wdsp/csp/v1/report (CSP violation + Probe alert) served locally (never proxied) -> 204 + events emitted.
	{
		called := false
		cspPayload := `{"csp-report":{"document-uri":"https://shop.example.com/checkout?sid=secret","effective-directive":"script-src","blocked-uri":"https://u:p@evil.example/x.js?k=v","disposition":"enforce"}}`
		r := httptest.NewRequest(http.MethodPost, "https://shop.example.com/_wdsp/csp/v1/report", strings.NewReader(cspPayload))
		r.RemoteAddr = "203.0.113.11:1111"
		rec := httptest.NewRecorder()
		if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
			t.Fatal(err)
		}
		if called || rec.Code != http.StatusNoContent {
			t.Fatalf("CSP report expected local 204, got code=%d called=%v", rec.Code, called)
		}

		probePayload := `{"type":"probe-alert","kind":"cross_origin_beacon","target":"https://evil.example/exfil?cc=4111","page":"/pay?token=abc"}`
		r2 := httptest.NewRequest(http.MethodPost, "https://shop.example.com/_wdsp/csp/v1/report", strings.NewReader(probePayload))
		r2.RemoteAddr = "203.0.113.11:1111"
		rec2 := httptest.NewRecorder()
		if err := g.ServeHTTP(rec2, r2, nextHandler{&called}); err != nil {
			t.Fatal(err)
		}
		if called || rec2.Code != http.StatusNoContent {
			t.Fatalf("probe alert expected local 204, got code=%d called=%v", rec2.Code, called)
		}
	}

	// 5. Compressed gzip HTML passes through untouched (no false claims).
	{
		var gzBuf bytes.Buffer
		gz := gzip.NewWriter(&gzBuf)
		_, _ = gz.Write([]byte(`<html><head></head><body><script src="https://evil.example/gz.js"></script></body></html>`))
		_ = gz.Close()
		gzNext := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(gzBuf.Bytes())
			return nil
		})
		r := httptest.NewRequest(http.MethodGet, "https://shop.example.com/checkout", nil)
		r.RemoteAddr = "203.0.113.12:1111"
		rec := httptest.NewRecorder()
		if err := g.ServeHTTP(rec, r, gzNext); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rec.Body.Bytes(), gzBuf.Bytes()) {
			t.Fatal("gzip HTML must pass through byte-for-byte untouched")
		}
		if rec.Header().Get(clientside.HeaderCSP) == "" {
			t.Fatal("gzip HTML must still get CSP header")
		}
	}

	// 6. Verify all 5 CLIENT_SIDE_* event types emitted to events.log with clean URLs.
	evs := g.readEvents(t)
	counts := map[events.Type]int{}
	for _, ev := range evs {
		counts[ev.EventType]++
		if ev.ClientSide != nil {
			if strings.Contains(ev.ClientSide.ScriptURL, "secret") ||
				strings.Contains(ev.ClientSide.BlockedURI, "4111") ||
				strings.Contains(ev.ClientSide.PagePath, "sid=") ||
				strings.Contains(ev.ClientSide.BlockedURI, "u:p@") {
				t.Fatalf("sensitive query/creds leaked in client_side event: %+v", ev.ClientSide)
			}
		}
	}
	for _, wantType := range []events.Type{
		events.ClientSideScriptObserved,
		events.ClientSideUnauthorizedScript,
		events.ClientSideScriptTampered,
		events.ClientSideCSPViolation,
		events.ClientSideProbeAlert,
	} {
		if counts[wantType] == 0 {
			t.Errorf("expected at least 1 %s event, got counts=%v", wantType, counts)
		}
	}
}

func TestCapabilityManifest_Phase9BClientSideDetector(t *testing.T) {
	m := buildCapabilityManifest(capabilityInputs{NodeID: "gw-phase9b", GRPCUnary: true}, time.Now())
	if msg := m.Validate(); msg != "" {
		t.Fatalf("manifest invalid: %s", msg)
	}
	req := capability.Manifest{
		ContractVersion: capability.ContractVersion,
		Detectors: []capability.DetectorCap{
			{Name: "clientside", Version: "clientside/1"},
		},
	}
	if missing := capability.CheckRequirements(req, m); len(missing) != 0 {
		t.Fatalf("Phase 9B clientside capability missing from manifest: %+v", missing)
	}
}

func TestClientSideStep_ProvisionAndCleanupLifecycle(t *testing.T) {
	t.Setenv(capDisabledEnv, "1")
	pol := clientside.Policy{
		SchemaVersion:        1,
		ApplicationID:        "app-cs-life",
		Mode:                 clientside.ModeObserve,
		Version:              1,
		CSPMode:              clientside.CSPModeReportOnly,
		AllowedScriptOrigins: []string{"'self'"},
	}
	g := &Guard{
		AppID:            "app-cs-life",
		AppCode:          "life",
		CounterBackend:   "memory",
		EventsLog:        t.TempDir() + "/events.log",
		ClientSidePolicy: mustJSON(t, pol),
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if err := g.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	if g.clientSide == nil {
		t.Fatal("expected g.clientSide initialized by Provision")
	}
	if err := g.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	if err := g.Cleanup(); err != nil {
		t.Fatalf("second Cleanup failed: %v", err)
	}
}
