package clientside

import (
	"net/url"
	"strings"
	"testing"
)

func TestCompileCSP_ModesAndProbeSelfEnforcement(t *testing.T) {
	// 1. Mode OFF -> no header even if CSPMode ENFORCE.
	name, val, err := CompileCSP(&Policy{
		SchemaVersion: 1,
		Mode:          ModeOff,
		CSPMode:       CSPModeEnforce,
	})
	if err != nil || name != "" || val != "" {
		t.Fatalf("OFF mode must emit empty CSP, got name=%q val=%q err=%v", name, val, err)
	}

	// 2. CSPMode OFF -> no header.
	name, val, err = CompileCSP(&Policy{
		SchemaVersion: 1,
		Mode:          ModeProtect,
		CSPMode:       CSPModeOff,
	})
	if err != nil || name != "" || val != "" {
		t.Fatalf("CSPMode OFF must emit empty CSP, got name=%q val=%q err=%v", name, val, err)
	}

	// 3. REPORT_ONLY with origins & custom directives.
	name, val, err = CompileCSP(&Policy{
		SchemaVersion:         1,
		Mode:                  ModeObserve,
		CSPMode:               CSPModeReportOnly,
		AllowedScriptOrigins:  []string{"'self'", "https://cdn.example.com"},
		AllowedConnectOrigins: []string{"'self'", "https://api.example.com"},
		AllowedFormOrigins:    []string{"'self'"},
		CustomCSPDirectives:   "object-src 'none'; frame-ancestors 'none';",
	})
	if err != nil {
		t.Fatalf("CompileCSP REPORT_ONLY err: %v", err)
	}
	if name != HeaderCSPReportOnly {
		t.Fatalf("header name = %q, want %q", name, HeaderCSPReportOnly)
	}
	want := "script-src 'self' https://cdn.example.com; connect-src 'self' https://api.example.com; form-action 'self'; object-src 'none'; frame-ancestors 'none'; report-uri /_wdsp/csp/v1/report"
	if val != want {
		t.Fatalf("CSP value mismatch:\ngot:  %q\nwant: %q", val, want)
	}

	// 4. ENFORCE with probe_enabled=true ensures 'self' in script-src & connect-src and strips conflicting 'none'.
	name, val, err = CompileCSP(&Policy{
		SchemaVersion:         1,
		Mode:                  ModeProtect,
		CSPMode:               CSPModeEnforce,
		ProbeEnabled:          true,
		AllowedScriptOrigins:  []string{"https://cdn.example.com"},
		AllowedConnectOrigins: []string{"'none'"},
		AllowedFormOrigins:    nil,
	})
	if err != nil {
		t.Fatalf("CompileCSP ENFORCE err: %v", err)
	}
	if name != HeaderCSP {
		t.Fatalf("header name = %q, want %q", name, HeaderCSP)
	}
	if !strings.Contains(val, "script-src 'self' https://cdn.example.com;") {
		t.Fatalf("probe_enabled must inject 'self' into script-src: %q", val)
	}
	if !strings.Contains(val, "connect-src 'self';") || strings.Contains(val, "'none'") {
		t.Fatalf("probe_enabled must replace 'none' with 'self' in connect-src: %q", val)
	}
	if !strings.Contains(val, "form-action 'self';") {
		t.Fatalf("empty form-action must default to 'self': %q", val)
	}
	if !strings.HasSuffix(val, "report-uri /_wdsp/csp/v1/report") {
		t.Fatalf("CSP must end with report-uri: %q", val)
	}

	// 5. CR/LF in custom directives rejected.
	if _, _, err := CompileCSP(&Policy{
		SchemaVersion:       1,
		Mode:                ModeProtect,
		CSPMode:             CSPModeEnforce,
		CustomCSPDirectives: "object-src 'none'\r\nSet-Cookie: pwn=1",
	}); err == nil {
		t.Fatal("expected CR/LF in custom_csp_directives to be rejected")
	}
}

func TestValidateCSPSourceToken(t *testing.T) {
	valid := []string{
		"'self'",
		"'none'",
		"'unsafe-inline'",
		"'strict-dynamic'",
		"'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='",
		"'nonce-abc123XYZ=='",
		"*",
		"https:",
		"data:",
		"blob:",
		"wss:",
		"https://cdn.example.com",
		"https://*.example.com",
		"https://cdn.example.com:8443",
		"https://cdn.example.com:*",
		"https://cdn.example.com/static/",
		"cdn.example.com",
		"*.example.com",
	}
	for _, tok := range valid {
		if err := ValidateCSPSourceToken(tok); err != nil {
			t.Errorf("expected valid CSP token %q, got err: %v", tok, err)
		}
	}

	invalid := []string{
		"",
		"   ",
		"'invalid-keyword'",
		"'self",
		"https://cdn.example.com\r\nX-Inject: 1",
		"https://cdn.example.com; object-src *",
		"https://cdn.example.com https://other.com",
		"https://user:pass@cdn.example.com",
		"https://cdn.example.com?q=1",
		"https://cdn.example.com#frag",
		"https://cdn.example.com:99999",
		"123bad:",
	}
	for _, tok := range invalid {
		if err := ValidateCSPSourceToken(tok); err == nil {
			t.Errorf("expected invalid CSP token %q to fail validation", tok)
		}
	}
}

func TestOriginMatcher_SubdomainSchemePortPath(t *testing.T) {
	mustURL := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}

	mSub, ok := compileOriginMatcher("https://*.trusted.example")
	if !ok {
		t.Fatal("compile subdomain matcher failed")
	}
	if !mSub.matches(mustURL("https://cdn.trusted.example/a.js"), false, "https") {
		t.Error("expected subdomain match")
	}
	if mSub.matches(mustURL("https://trusted.example/a.js"), false, "https") {
		t.Error("wildcard subdomain must not match bare apex")
	}
	if mSub.matches(mustURL("https://evil-trusted.example/a.js"), false, "https") {
		t.Error("wildcard subdomain must not match suffix-spoofed domain")
	}
	if mSub.matches(mustURL("http://cdn.trusted.example/a.js"), false, "https") {
		t.Error("https matcher must not match http")
	}

	mPath, ok := compileOriginMatcher("https://cdn.example.com/libs/")
	if !ok {
		t.Fatal("compile path matcher failed")
	}
	if !mPath.matches(mustURL("https://cdn.example.com/libs/v1/app.js"), false, "https") {
		t.Error("expected directory prefix match")
	}
	if mPath.matches(mustURL("https://cdn.example.com/other/app.js"), false, "https") {
		t.Error("unexpected match outside allowed path prefix")
	}

	mHostOnly, ok := compileOriginMatcher("cdn.example.com")
	if !ok {
		t.Fatal("compile host-only matcher failed")
	}
	if mHostOnly.matches(mustURL("http://cdn.example.com/a.js"), false, "https") {
		t.Error("host-only matcher must not allow http downgrade on https page")
	}
	if !mHostOnly.matches(mustURL("https://cdn.example.com/a.js"), false, "https") {
		t.Error("host-only matcher should allow https on https page")
	}
}
