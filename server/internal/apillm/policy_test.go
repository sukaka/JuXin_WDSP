package apillm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func newSecurityPolicyTestMux(store *MemSecurityPolicyStore, authzFn func(http.Handler) http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterSecurityPolicyRoutes(mux, authzFn, NewSecurityPolicyHandler(store, nil))
	return mux
}

func doSecurityPolicyJSON(t *testing.T, mux http.Handler, method, url, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, url, reader)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func createSecurityPolicyForTest(t *testing.T, mux http.Handler, applicationID string) SecurityPolicy {
	t.Helper()
	body := `{"application_id":"` + applicationID + `","name":"客服助手输入保护","prompt_injection_enabled":true,"pii_detection_enabled":true,"blocked_topics":["违法融资"],"max_prompt_bytes":1024}`
	rr := doSecurityPolicyJSON(t, mux, http.MethodPost, "/api/v1/api-security/llm/security-policies", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	var result struct {
		Data SecurityPolicy `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result.Data
}

func TestSecurityPolicyPermissionMatrix(t *testing.T) {
	store := NewMemSecurityPolicyStore()
	body := `{"application_id":"` + uuid.NewString() + `","name":"AI助手"}`
	cases := []struct {
		method string
		url    string
		body   string
		perm   string
	}{
		{http.MethodGet, "/api/v1/api-security/llm/security-policies", "", PermSecurityRead},
		{http.MethodPost, "/api/v1/api-security/llm/security-policies", body, PermSecurityManage},
		{http.MethodPatch, "/api/v1/api-security/llm/security-policies/" + uuid.NewString(), `{"enabled":false}`, PermSecurityManage},
		{http.MethodDelete, "/api/v1/api-security/llm/security-policies/" + uuid.NewString(), "", PermSecurityManage},
		{http.MethodGet, "/api/v1/api-security/llm/security-policies/" + uuid.NewString() + "/versions", "", PermSecurityRead},
	}
	for _, tc := range cases {
		if rr := doSecurityPolicyJSON(t, newSecurityPolicyTestMux(store, noPrincipal), tc.method, tc.url, tc.body); rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s anonymous status=%d", tc.method, rr.Code)
		}
		if rr := doSecurityPolicyJSON(t, newSecurityPolicyTestMux(store, injectPrincipal("other.read")), tc.method, tc.url, tc.body); rr.Code != http.StatusForbidden {
			t.Fatalf("%s without permission status=%d", tc.method, rr.Code)
		}
		rr := doSecurityPolicyJSON(t, newSecurityPolicyTestMux(store, injectPrincipal(tc.perm)), tc.method, tc.url, tc.body)
		if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
			t.Fatalf("%s authorized status=%d body=%s", tc.method, rr.Code, rr.Body.String())
		}
	}
}

func TestSecurityPolicyCRUDVersionsAndGuardPayload(t *testing.T) {
	store := NewMemSecurityPolicyStore()
	mux := newSecurityPolicyTestMux(store, injectPrincipal(PermSecurityRead, PermSecurityManage))
	applicationID := uuid.NewString()
	created := createSecurityPolicyForTest(t, mux, applicationID)
	if created.Version != 1 || created.Mode != SecurityPolicyModeObserve || len(created.BlockedTopics) != 1 {
		t.Fatalf("created=%+v", created)
	}
	rr := doSecurityPolicyJSON(t, mux, http.MethodPatch, "/api/v1/api-security/llm/security-policies/"+created.ID.String(), `{"mode":"PROTECT","blocked_topics":["违法融资","恶意爬虫"],"max_prompt_bytes":2048}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", rr.Code, rr.Body.String())
	}
	var updated struct {
		Data SecurityPolicy `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Data.Version != 2 || updated.Data.Mode != SecurityPolicyModeProtect || updated.Data.MaxPromptBytes != 2048 {
		t.Fatalf("updated=%+v", updated.Data)
	}
	versions, err := store.ListSecurityPolicyVersions(t.Context(), created.ID)
	if err != nil || len(versions) != 2 || versions[0].Version != 2 {
		t.Fatalf("versions=%+v err=%v", versions, err)
	}
	payload, err := store.ListEnabledSecurityPolicies(t.Context())
	if err != nil || len(payload) != 1 {
		t.Fatalf("payload=%+v err=%v", payload, err)
	}
	if payload[0].ApplicationID != applicationID || payload[0].Version != 2 || len(payload[0].BlockedTopics) != 2 {
		t.Fatalf("guard payload=%+v", payload[0])
	}

	duplicate := `{"application_id":"` + applicationID + `","name":"重复策略"}`
	if rr := doSecurityPolicyJSON(t, mux, http.MethodPost, "/api/v1/api-security/llm/security-policies", duplicate); rr.Code != http.StatusConflict {
		t.Fatalf("duplicate status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr := doSecurityPolicyJSON(t, mux, http.MethodDelete, "/api/v1/api-security/llm/security-policies/"+created.ID.String(), ""); rr.Code != http.StatusOK {
		t.Fatalf("delete status=%d", rr.Code)
	}
}

func TestSecurityPolicyValidation(t *testing.T) {
	mux := newSecurityPolicyTestMux(NewMemSecurityPolicyStore(), injectPrincipal(PermSecurityManage))
	applicationID := uuid.NewString()
	bad := []string{
		`{"name":"缺少应用"}`,
		`{"application_id":"bad","name":"AI助手"}`,
		`{"application_id":"` + applicationID + `","name":"AI助手","mode":"BLOCK"}`,
		`{"application_id":"` + applicationID + `","name":"AI助手","blocked_topics":[""]}`,
		`{"application_id":"` + applicationID + `","name":"AI助手","max_prompt_bytes":100}`,
		`{"application_id":"` + applicationID + `","name":"AI助手","unknown":true}`,
	}
	for _, body := range bad {
		if rr := doSecurityPolicyJSON(t, mux, http.MethodPost, "/api/v1/api-security/llm/security-policies", body); rr.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d body=%s", body, rr.Code, rr.Body.String())
		}
	}
}
