package clientside

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseAndValidatePolicy_ValidAndStrictRejections(t *testing.T) {
	validJSON := json.RawMessage(`{
		"schema_version": 1,
		"application_id": "11111111-1111-1111-1111-111111111111",
		"mode": "PROTECT",
		"version": 3,
		"csp_mode": "ENFORCE",
		"sensitive_paths": ["/login", "/checkout", "/pay"],
		"probe_enabled": true,
		"strip_unauthorized_scripts": true,
		"allowed_script_origins": ["'self'", "https://cdn.example.com"],
		"allowed_connect_origins": ["'self'", "https://api.example.com"],
		"allowed_form_origins": ["'self'"],
		"custom_csp_directives": "object-src 'none'; frame-ancestors 'self'",
		"authorized_scripts": [
			{
				"script_url": "https://cdn.example.com/app.js",
				"script_type": "EXTERNAL",
				"sri_hash": "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC",
				"status": "AUTHORIZED"
			},
			{
				"script_url": "https://evil.example.com/bad.js",
				"script_type": "EXTERNAL",
				"sri_hash": "",
				"status": "BLOCKED"
			},
			{
				"script_url": "inline:sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
				"script_type": "INLINE_HASH",
				"sri_hash": "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
				"status": "AUTHORIZED"
			}
		]
	}`)

	pol, err := ParseAndValidatePolicy(validJSON)
	if err != nil {
		t.Fatalf("expected valid policy, got err: %v", err)
	}
	if pol.Mode != ModeProtect || pol.CSPMode != CSPModeEnforce || pol.Version != 3 {
		t.Fatalf("unexpected parsed policy: %+v", pol)
	}

	cases := []struct {
		name string
		raw  string
	}{
		{"unknown_field", `{"schema_version":1,"mode":"OBSERVE","unknown_flag":true}`},
		{"trailing_json", `{"schema_version":1,"mode":"OBSERVE"}{"extra":1}`},
		{"bad_schema_version", `{"schema_version":2,"mode":"OBSERVE"}`},
		{"missing_mode", `{"schema_version":1}`},
		{"unknown_mode", `{"schema_version":1,"mode":"BLOCK"}`},
		{"unknown_csp_mode", `{"schema_version":1,"mode":"OBSERVE","csp_mode":"STRICT"}`},
		{"negative_version", `{"schema_version":1,"mode":"OBSERVE","version":-1}`},
		{"sensitive_path_no_slash", `{"schema_version":1,"mode":"OBSERVE","sensitive_paths":["checkout"]}`},
		{"sensitive_path_query", `{"schema_version":1,"mode":"OBSERVE","sensitive_paths":["/checkout?a=1"]}`},
		{"sensitive_path_fragment", `{"schema_version":1,"mode":"OBSERVE","sensitive_paths":["/checkout#top"]}`},
		{"sensitive_path_too_long", `{"schema_version":1,"mode":"OBSERVE","sensitive_paths":["/` + strings.Repeat("a", MaxPathLen) + `"]}`},
		{"origin_crlf", `{"schema_version":1,"mode":"OBSERVE","allowed_script_origins":["https://cdn.example.com\r\nX-Evil:1"]}`},
		{"origin_semicolon", `{"schema_version":1,"mode":"OBSERVE","allowed_script_origins":["https://cdn.example.com;script-src *"]}`},
		{"custom_csp_crlf", `{"schema_version":1,"mode":"OBSERVE","custom_csp_directives":"object-src 'none'\nX-Injected: true"}`},
		{"custom_csp_too_long", `{"schema_version":1,"mode":"OBSERVE","custom_csp_directives":"` + strings.Repeat("a", MaxCustomDirectivesLen+1) + `"}`},
		{"bad_script_type", `{"schema_version":1,"mode":"OBSERVE","authorized_scripts":[{"script_url":"https://a.com/x.js","script_type":"MODULE","status":"AUTHORIZED"}]}`},
		{"bad_script_status", `{"schema_version":1,"mode":"OBSERVE","authorized_scripts":[{"script_url":"https://a.com/x.js","script_type":"EXTERNAL","status":"DISCOVERED"}]}`},
		{"bad_script_sri", `{"schema_version":1,"mode":"OBSERVE","authorized_scripts":[{"script_url":"https://a.com/x.js","script_type":"EXTERNAL","sri_hash":"md5-abc123","status":"AUTHORIZED"}]}`},
		{"empty_script_url", `{"schema_version":1,"mode":"OBSERVE","authorized_scripts":[{"script_url":"","script_type":"EXTERNAL","status":"AUTHORIZED"}]}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseAndValidatePolicy(json.RawMessage(tc.raw)); err == nil {
				t.Fatalf("case %s: expected validation error, got nil", tc.name)
			}
		})
	}
}

func TestValidatePolicy_TooManySensitivePathsAndOrigins(t *testing.T) {
	paths := make([]string, MaxSensitivePaths+1)
	for i := range paths {
		paths[i] = "/p"
	}
	if err := ValidatePolicy(&Policy{SchemaVersion: 1, Mode: ModeObserve, CSPMode: CSPModeOff, SensitivePaths: paths}); err == nil {
		t.Fatal("expected error when sensitive_paths exceeds MaxSensitivePaths")
	}

	origins := make([]string, MaxOrigins+1)
	for i := range origins {
		origins[i] = "https://cdn.example.com"
	}
	if err := ValidatePolicy(&Policy{SchemaVersion: 1, Mode: ModeObserve, CSPMode: CSPModeOff, AllowedScriptOrigins: origins}); err == nil {
		t.Fatal("expected error when allowed_script_origins exceeds MaxOrigins")
	}
}

func TestEngine_MatchSensitivePathSegmentBoundary(t *testing.T) {
	eng, err := NewEngine(&Policy{
		SchemaVersion:  1,
		Mode:           ModeObserve,
		CSPMode:        CSPModeOff,
		ProbeEnabled:   true,
		SensitivePaths: []string{"/login", "/checkout", "/pay/"},
	}, EngineOptions{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	shouldMatch := []string{
		"/login",
		"/login/",
		"/login/mfa",
		"/checkout",
		"/checkout/step2",
		"/x/../checkout/confirm",
		"/checkout//confirm",
		"/pay",
		"/pay/card",
	}
	for _, p := range shouldMatch {
		if !eng.ShouldInjectProbe(p) {
			t.Errorf("expected path %q to match sensitive_paths", p)
		}
	}

	shouldNotMatch := []string{
		"/",
		"/login2",
		"/checkout-help",
		"/payment",
		"/about",
	}
	for _, p := range shouldNotMatch {
		if eng.ShouldInjectProbe(p) {
			t.Errorf("expected path %q NOT to match sensitive_paths", p)
		}
	}
}
