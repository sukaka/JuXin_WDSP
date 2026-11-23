package urlwhitelists

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func withAdmin(r *http.Request) *http.Request {
	p := &authz.Principal{
		UserID:   uuid.New(),
		Username: "secops",
		Roles:    []string{"SECURITY_ADMIN"},
	}
	return r.WithContext(authz.WithPrincipal(context.Background(), p))
}

func TestHandlerValidationGuards(t *testing.T) {
	h := NewHandler(nil, nil)

	t.Run("create rejects malformed JSON", func(t *testing.T) {
		req := withAdmin(httptest.NewRequest(http.MethodPost, "/api/v1/url-whitelists", bytes.NewBufferString("{bad")))
		rec := httptest.NewRecorder()
		h.Create(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("create rejects query string in exact path", func(t *testing.T) {
		req := withAdmin(httptest.NewRequest(http.MethodPost, "/api/v1/url-whitelists", bytes.NewBufferString(`{
			"name":"bad","scope_type":"GLOBAL","match_type":"EXACT","uri_pattern":"/api?k=v","validity_type":"PERMANENT"
		}`)))
		rec := httptest.NewRecorder()
		h.Create(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("list rejects bad application_id", func(t *testing.T) {
		req := withAdmin(httptest.NewRequest(http.MethodGet, "/api/v1/url-whitelists?application_id=not-a-uuid", nil))
		rec := httptest.NewRecorder()
		h.List(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("get rejects invalid uuid", func(t *testing.T) {
		req := withAdmin(httptest.NewRequest(http.MethodGet, "/api/v1/url-whitelists/not-a-uuid", nil))
		req.SetPathValue("id", "not-a-uuid")
		rec := httptest.NewRecorder()
		h.Get(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})
}
