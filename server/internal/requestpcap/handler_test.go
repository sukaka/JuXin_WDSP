package requestpcap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/users"
)

const handlerTestPassword = "Test-Only-Password-47!"

type requestUserStub struct{ user *users.User }

func (s *requestUserStub) GetByID(context.Context, uuid.UUID) (*users.User, error) {
	return s.user, nil
}

type requestAuditSpy struct {
	mu     sync.Mutex
	inputs []audits.RecordInput
}

func (s *requestAuditSpy) Record(_ context.Context, input audits.RecordInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inputs = append(s.inputs, input)
	return nil
}

func (s *requestAuditSpy) last() audits.RecordInput {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.inputs) == 0 {
		return audits.RecordInput{}
	}
	return s.inputs[len(s.inputs)-1]
}

type handlerFixture struct {
	service *Service
	store   *serviceStoreStub
	mux     *http.ServeMux
	audits  *requestAuditSpy
	userID  uuid.UUID
}

func newHandlerFixture(t *testing.T, permissions ...string) *handlerFixture {
	t.Helper()
	store, service, _ := newServiceFixture(t)
	hash, err := security.HashPassword(handlerTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	userID := uuid.New()
	spy := &requestAuditSpy{}
	handler := NewHandler(service, &requestUserStub{user: &users.User{ID: userID, Status: users.StatusActive, PasswordHash: hash}}, spy)
	mux := http.NewServeMux()
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			permissionSet := make(map[string]bool, len(permissions))
			for _, permission := range permissions {
				permissionSet[permission] = true
			}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), &authz.Principal{UserID: userID,
				Username: "auditor", SessionID: "session-handler", PermsSet: permissionSet})))
		})
	}
	passthrough := func(next http.Handler) http.Handler { return next }
	handler.RegisterRoutes(mux, auth, passthrough)
	return &handlerFixture{service: service, store: store, mux: mux, audits: spy, userID: userID}
}

func requestJSON(t *testing.T, handler http.Handler, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var payload bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&payload).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, &payload)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestHandlerPermissionsPasswordAndRealDownload(t *testing.T) {
	readOnly := newHandlerFixture(t, PermissionRead)
	lookup := "/api/v1/request-pcap/lookup?request_id=" + readOnly.store.link.RequestID
	response := requestJSON(t, readOnly.mux, http.MethodGet, lookup, nil)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "wrapped") || strings.Contains(response.Body.String(), "private") {
		t.Fatalf("safe lookup response: %d %s", response.Code, response.Body.String())
	}
	manifest := fmt.Sprintf("/api/v1/request-pcap/artifacts/%s/manifest?request_id=%s", readOnly.store.artifact.ID, readOnly.store.link.RequestID)
	if response := requestJSON(t, readOnly.mux, http.MethodGet, manifest, nil); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "UNVERIFIED") {
		t.Fatalf("manifest response: %d %s", response.Code, response.Body.String())
	}
	if response := requestJSON(t, readOnly.mux, http.MethodGet, lookup, nil); response.Code != http.StatusOK {
		t.Fatal("repeat read must remain safe")
	}
	if response := requestJSON(t, readOnly.mux, http.MethodPost, fmt.Sprintf("/api/v1/request-pcap/artifacts/%s/verify", readOnly.store.artifact.ID), map[string]string{"request_id": readOnly.store.link.RequestID, "reason": "完整性检查"}); response.Code != http.StatusForbidden {
		t.Fatalf("verify without permission status=%d", response.Code)
	}

	fixture := newHandlerFixture(t, PermissionRead, PermissionVerify, PermissionDownload)
	verifyPath := fmt.Sprintf("/api/v1/request-pcap/artifacts/%s/verify", fixture.store.artifact.ID)
	response = requestJSON(t, fixture.mux, http.MethodPost, verifyPath, map[string]string{"request_id": fixture.store.link.RequestID, "reason": "核验攻击证据"})
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"integrity_status":"PASS"`) {
		t.Fatalf("real verification response: %d %s", response.Code, response.Body.String())
	}
	grantPath := fmt.Sprintf("/api/v1/request-pcap/artifacts/%s/download-grants", fixture.store.artifact.ID)
	response = requestJSON(t, fixture.mux, http.MethodPost, grantPath, map[string]string{"request_id": fixture.store.link.RequestID, "reason": "调查事件", "password": "incorrect"})
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "incorrect") || fixture.audits.last().Result != audits.ResultFailure {
		t.Fatalf("wrong password response or audit: %d %s %+v", response.Code, response.Body.String(), fixture.audits.last())
	}
	response = requestJSON(t, fixture.mux, http.MethodPost, grantPath, map[string]string{"request_id": fixture.store.link.RequestID, "reason": "调查事件", "password": handlerTestPassword})
	if response.Code != http.StatusCreated {
		t.Fatalf("grant response: %d %s", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			GrantID uuid.UUID `json:"grant_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Data.GrantID == uuid.Nil {
		t.Fatalf("grant body invalid: %v %s", err, response.Body.String())
	}
	downloadPath := fmt.Sprintf("/api/v1/request-pcap/artifacts/%s/download?request_id=%s&grant_id=%s", fixture.store.artifact.ID, fixture.store.link.RequestID, body.Data.GrantID)
	response = requestJSON(t, fixture.mux, http.MethodGet, downloadPath, nil)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Body.Len() != 104 {
		t.Fatalf("derived download response: %d bytes=%d headers=%v", response.Code, response.Body.Len(), response.Header())
	}
	if fixture.audits.last().Result != audits.ResultSuccess || fixture.audits.last().RiskLevel != audits.RiskCritical {
		t.Fatalf("successful high-risk download not audited: %+v", fixture.audits.last())
	}
	if response := requestJSON(t, fixture.mux, http.MethodGet, downloadPath, nil); response.Code != http.StatusForbidden || fixture.audits.last().Result != audits.ResultFailure {
		t.Fatalf("replayed grant response: %d %s", response.Code, response.Body.String())
	}
}

func TestHandlerFailureAuditAndDisabledState(t *testing.T) {
	fixture := newHandlerFixture(t, PermissionVerify, PermissionDownload)
	if _, err := fixture.service.Verify(context.Background(), fixture.store.link.RequestID, fixture.store.artifact.ID, fixture.userID); err != nil {
		t.Fatal(err)
	}
	grant, err := fixture.service.CreateGrant(context.Background(), fixture.store.link.RequestID, fixture.store.artifact.ID, fixture.userID, "session-handler", "调查", "")
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/v1/request-pcap/artifacts/%s/download?request_id=%s&grant_id=%s", fixture.store.artifact.ID, fixture.store.link.RequestID, grant.ID)
	request := httptest.NewRequest(http.MethodGet, path, nil)
	writer := &failingPCAPWriter{header: make(http.Header)}
	fixture.mux.ServeHTTP(writer, request)
	if fixture.audits.last().Result != audits.ResultFailure || fixture.audits.last().Action != "request_pcap.download" {
		t.Fatalf("failed download audit missing: %+v", fixture.audits.last())
	}

	disabled := NewHandler(nil, nil, nil)
	mux := http.NewServeMux()
	disabled.RegisterRoutes(mux, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), &authz.Principal{UserID: uuid.New(), SessionID: "session", PermsSet: map[string]bool{PermissionRead: true}})))
		})
	}, func(next http.Handler) http.Handler { return next })
	if response := requestJSON(t, mux, http.MethodGet, "/api/v1/request-pcap/lookup?request_id=req-disabled", nil); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured PCAP service status=%d", response.Code)
	}
}

type failingPCAPWriter struct{ header http.Header }

func (w *failingPCAPWriter) Header() http.Header       { return w.header }
func (w *failingPCAPWriter) WriteHeader(int)           {}
func (w *failingPCAPWriter) Write([]byte) (int, error) { return 0, errors.New("client disconnected") }

func testActiveUser(t *testing.T) *users.User {
	t.Helper()
	hash, err := security.HashPassword(handlerTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	return &users.User{ID: uuid.New(), Status: users.StatusActive, PasswordHash: hash}
}

func authenticatedRequest(t *testing.T, method, path string, body interface{}, permission string) *http.Request {
	t.Helper()
	var payload bytes.Buffer
	if err := json.NewEncoder(&payload).Encode(body); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, &payload)
	principal := &authz.Principal{UserID: uuid.New(), Username: "key-admin", SessionID: "session-key", PermsSet: map[string]bool{permission: true}}
	return request.WithContext(authz.WithPrincipal(request.Context(), principal))
}

func newTestRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }
