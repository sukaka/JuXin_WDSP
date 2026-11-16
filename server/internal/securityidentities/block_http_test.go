package securityidentities

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func identityRequest(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	principal := &authz.Principal{UserID: uuid.New(), Username: "tester"}
	return req.WithContext(authz.WithPrincipal(context.Background(), principal))
}

func TestBlockAndUnblockHTTPTransitions(t *testing.T) {
	id := uuid.New()
	publishes := 0
	handler := NewHandler(nil).SetPublishFunc(func(context.Context, uuid.UUID, string) { publishes++ })
	handler.blockFn = func(_ context.Context, gotID uuid.UUID, reason string, _ uuid.UUID) (*Identity, bool, error) {
		if gotID != id || reason != "confirmed abuse" {
			t.Fatalf("block input id=%s reason=%q", gotID, reason)
		}
		return &Identity{ID: id, Status: "BLOCKED"}, true, nil
	}
	handler.unblockFn = func(_ context.Context, gotID uuid.UUID, _ string, _ uuid.UUID) (*Identity, bool, error) {
		return &Identity{ID: gotID, Status: "NORMAL"}, true, nil
	}

	req := identityRequest(t, http.MethodPost, "/api/v1/security/identities/"+id.String()+"/block", `{"reason":"confirmed abuse"}`)
	req.SetPathValue("id", id.String())
	rr := httptest.NewRecorder()
	handler.Block(rr, req)
	if rr.Code != http.StatusOK || publishes != 1 {
		t.Fatalf("block status=%d publishes=%d", rr.Code, publishes)
	}

	handler.blockFn = func(context.Context, uuid.UUID, string, uuid.UUID) (*Identity, bool, error) {
		return &Identity{ID: id, Status: "BLOCKED"}, false, nil
	}
	req = identityRequest(t, http.MethodPost, "/api/v1/security/identities/"+id.String()+"/block", `{"reason":"confirmed abuse"}`)
	req.SetPathValue("id", id.String())
	rr = httptest.NewRecorder()
	handler.Block(rr, req)
	if rr.Code != http.StatusOK || publishes != 1 {
		t.Fatalf("idempotent block status=%d publishes=%d", rr.Code, publishes)
	}

	req = identityRequest(t, http.MethodPost, "/api/v1/security/identities/"+id.String()+"/unblock", "")
	req.SetPathValue("id", id.String())
	rr = httptest.NewRecorder()
	handler.Unblock(rr, req)
	if rr.Code != http.StatusOK || publishes != 2 {
		t.Fatalf("unblock status=%d publishes=%d", rr.Code, publishes)
	}
}

func TestBlockHTTPValidationAndNotFound(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "空 reason", body: `{"reason":" "}`},
		{name: "超长 reason", body: `{"reason":"` + strings.Repeat("x", 513) + `"}`},
		{name: "未知字段", body: `{"reason":"abuse","identity_key":"sensitive"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := NewHandler(nil)
			req := identityRequest(t, http.MethodPost, "/api/v1/security/identities/"+uuid.NewString()+"/block", tc.body)
			req.SetPathValue("id", uuid.NewString())
			rr := httptest.NewRecorder()
			handler.Block(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}

	handler := NewHandler(nil)
	handler.blockFn = func(context.Context, uuid.UUID, string, uuid.UUID) (*Identity, bool, error) {
		return nil, false, ErrNotFound
	}
	id := uuid.New()
	req := identityRequest(t, http.MethodPost, "/api/v1/security/identities/"+id.String()+"/block", `{"reason":"abuse"}`)
	req.SetPathValue("id", id.String())
	rr := httptest.NewRecorder()
	handler.Block(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("not found status=%d", rr.Code)
	}

	req = identityRequest(t, http.MethodPost, "/api/v1/security/identities/"+id.String()+"/unblock", `{}`)
	req.SetPathValue("id", id.String())
	rr = httptest.NewRecorder()
	handler.Unblock(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("non-empty unblock body status=%d", rr.Code)
	}
}
