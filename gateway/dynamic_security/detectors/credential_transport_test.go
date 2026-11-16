package detectors

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func TestCheckCredentialTransport(t *testing.T) {
	ctx := dsctx.New("credential-1", dsctx.DefaultParseLimits())
	r := httptest.NewRequest("POST", "https://example.test/login?password=secret-value", nil)
	r.AddCookie(&http.Cookie{Name: "auth_token", Value: "cookie-secret"})
	p := &parser.Parsed{Query: map[string]string{"password": "secret-value"}}
	CheckCredentialTransport(ctx, r, p, decision.ModeProtect)
	var urlMatch, cookieMatch bool
	for _, match := range ctx.CopyMatches() {
		switch match.RuleID {
		case "credential.url_password":
			urlMatch = true
			if match.Category != "BLOCK" || match.Evidence["field"] != "password" {
				t.Fatalf("url match=%+v", match)
			}
		case "credential.cookie_sensitive":
			cookieMatch = true
			if match.Category != "OBSERVE" || match.Evidence["cookie_name"] != "auth_token" {
				t.Fatalf("cookie match=%+v", match)
			}
		}
	}
	if !urlMatch || !cookieMatch {
		t.Fatalf("url=%v cookie=%v matches=%+v", urlMatch, cookieMatch, ctx.CopyMatches())
	}
	for _, match := range ctx.CopyMatches() {
		for _, value := range match.Evidence {
			if strings.Contains(value, "secret") {
				t.Fatalf("sensitive value leaked: %+v", match.Evidence)
			}
		}
	}
}

func TestCheckCredentialTransportNormalRequest(t *testing.T) {
	ctx := dsctx.New("credential-normal", dsctx.DefaultParseLimits())
	r := httptest.NewRequest("GET", "https://example.test/profile?q=hello", nil)
	r.AddCookie(&http.Cookie{Name: "session_id", Value: "opaque-session"})
	p := &parser.Parsed{Query: map[string]string{"q": "hello"}}
	CheckCredentialTransport(ctx, r, p, decision.ModeObserve)
	if len(ctx.CopyMatches()) != 0 {
		t.Fatalf("normal request produced matches: %+v", ctx.CopyMatches())
	}
}
