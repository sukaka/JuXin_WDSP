package jiuzhang_guard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestServeNextCredentialURLPasswordProtect(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/login?password=secret-value", strings.NewReader(`{"username":"demo"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: "cookie-secret"})
	rr := httptest.NewRecorder()
	if err := g.serveNext(rr, req, next); err == nil {
		t.Fatal("expected blocked request error")
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"credential.url_password", "credential.cookie_sensitive"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing %s: %s", want, data)
		}
	}
	for _, forbidden := range []string{"secret-value", "cookie-secret"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("event leaked %s: %s", forbidden, data)
		}
	}
}

func TestServeNextServerDisclosureObserved(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Server", "Apache/2.4.49")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `Exception in thread "main" java.lang.RuntimeException`)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	if err := g.serveNext(rr, req, next); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("upstream status changed: %d", rr.Code)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"server.version_disclosure", "server.error_disclosure"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing %s: %s", want, data)
		}
	}
	for _, forbidden := range []string{"2.4.49", "RuntimeException"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("raw detail leaked: %s", data)
		}
	}
}
