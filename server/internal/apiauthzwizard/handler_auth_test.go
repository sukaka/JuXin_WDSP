// handler_auth_test.go 向导端点权限对照（D8：jiuzhang_admin（SYSTEM_ADMIN，无
// api_authorization.*）全部 403；只读主体可评估不签发；manage 方可签署）。
// 权限中间件先于 store 拦截——nil store 即可覆盖 403 分支。
package apiauthzwizard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiauthz"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func injectPerms(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "matrix", PermsSet: set}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
}

func doJSON(t *testing.T, mux http.Handler, method, url string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, url, reader)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// jiuzhang_admin 越权对照（D8：全部新端点 403，零新增权限点）。
func TestWizardEndpointsForbiddenForSysAdmin(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil)
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("system.read", "applications.edit"), h) // SYSTEM_ADMIN 形态（无 api_authorization.*）

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/api-security/authz/enforcement-readiness?application_id=" + uuid.NewString()},
		{http.MethodPost, "/api/v1/api-security/authz/enforcement-impact"},
		{http.MethodGet, "/api/v1/api-security/authz/enforcement-confirmations"},
		{http.MethodPost, "/api/v1/api-security/authz/enforcement-confirmations/" + uuid.NewString() + "/sign"},
		{http.MethodGet, "/api/v1/api-security/authz/conflicts"},
	} {
		rr := doJSON(t, mux, tc.method, tc.path, map[string]any{})
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s: 无 api_authorization 权限主体应 403, got %d", tc.method, tc.path, rr.Code)
		}
	}
}

// 分权边界：只读主体（api_authorization.read）不可签署（manage 才能）。
func TestWizardSignForbiddenForReadOnly(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil)
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms(apiauthz.PermAuthzRead), h)
	rr := doJSON(t, mux, http.MethodPost,
		"/api/v1/api-security/authz/enforcement-confirmations/"+uuid.NewString()+"/sign",
		map[string]any{"enforcement_owner": "a@b.c", "evidence_source": "MANUAL_CONFIRMED", "on_unknown": "ALLOW_UNKNOWN"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("只读主体签署应 403, got %d", rr.Code)
	}
}

func TestConflictItemMarshalsPrincipalsAsJSONArrayNotBase64(t *testing.T) {
	item := ConflictItem{
		ID:            uuid.New(),
		ApplicationID: uuid.New(),
		ObjectType:    "orders",
		ObjectRef:     "objref:123",
		Principals:    json.RawMessage(`["principal-a","principal-b"]`),
		Status:        "OPEN",
	}
	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("marshal ConflictItem: %v", err)
	}
	var decoded struct {
		Principals []string `json:"principals"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("principals must marshal as JSON array (not base64 string): %v raw=%s", err, string(raw))
	}
	if len(decoded.Principals) != 2 || decoded.Principals[0] != "principal-a" || decoded.Principals[1] != "principal-b" {
		t.Fatalf("unexpected decoded principals: %v", decoded.Principals)
	}
}

func TestImpactResultOmitsConfirmTokenWhenNil(t *testing.T) {
	res := ImpactResult{
		EndpointID:    uuid.New(),
		EndpointKey:   "GET /v1/orders/{id}",
		ObjectSegment: "path:2",
		WindowDays:    7,
		Readiness:     "READY",
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal ImpactResult: %v", err)
	}
	if strings.Contains(string(raw), "confirm_token") || strings.Contains(string(raw), "00000000-0000-0000-0000-000000000000") {
		t.Fatalf("nil ConfirmToken must be omitted from JSON, got %s", string(raw))
	}
	tok := uuid.New()
	res.ConfirmToken = &tok
	rawWithTok, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal ImpactResult with token: %v", err)
	}
	if !strings.Contains(string(rawWithTok), tok.String()) {
		t.Fatalf("non-nil ConfirmToken must serialize UUID, got %s", string(rawWithTok))
	}
}

func TestConfirmationMarshalsImpactSnapshotAsJSONObjectNotBase64(t *testing.T) {
	c := Confirmation{
		ID:             uuid.New(),
		ConfirmToken:   uuid.New(),
		ApplicationID:  uuid.New(),
		EndpointID:     uuid.New(),
		EndpointKey:    "GET /v1/orders/{id}",
		ObjectSegment:  "path:2",
		WindowDays:     7,
		ImpactSnapshot: json.RawMessage(`{"window_days":7,"observe_violation_count":3}`),
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal Confirmation: %v", err)
	}
	var decoded struct {
		ImpactSnapshot map[string]any `json:"impact_snapshot"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("impact_snapshot must marshal as JSON object (not base64 string): %v raw=%s", err, string(raw))
	}
	if decoded.ImpactSnapshot["window_days"] != float64(7) || decoded.ImpactSnapshot["observe_violation_count"] != float64(3) {
		t.Fatalf("unexpected decoded impact_snapshot: %v", decoded.ImpactSnapshot)
	}
}

func TestListReadinessQueryValidation(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil)
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms(apiauthz.PermAuthzRead), h)

	for _, url := range []string{
		"/api/v1/api-security/authz/enforcement-readiness",
		"/api/v1/api-security/authz/enforcement-readiness?application_id=bad",
		"/api/v1/api-security/authz/enforcement-readiness?endpoint_id=bad",
	} {
		rr := doJSON(t, mux, http.MethodGet, url, nil)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("GET %s: status=%d, want 400 (body=%s)", url, rr.Code, rr.Body.String())
		}
	}
}
