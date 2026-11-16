package apillm

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestSecurityPolicyInputContentVersionAndPartialUpdate(t *testing.T) {
	store := NewMemSecurityPolicyStore()
	mux := newSecurityPolicyTestMux(store, injectPrincipal(PermSecurityRead, PermSecurityManage))
	applicationID := uuid.NewString()
	body := `{"application_id":"` + applicationID + `","name":"AI 输入内容防护"}`
	rr := doSecurityPolicyJSON(t, mux, http.MethodPost, "/api/v1/api-security/llm/security-policies", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	var created struct {
		Data SecurityPolicy `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !created.Data.InputContentEnabled {
		t.Fatal("new policy should enable input content inspection by default")
	}

	rr = doSecurityPolicyJSON(t, mux, http.MethodPatch, "/api/v1/api-security/llm/security-policies/"+created.Data.ID.String(), `{"input_content_enabled":false}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("partial update status=%d body=%s", rr.Code, rr.Body.String())
	}
	updated, err := store.GetSecurityPolicy(t.Context(), created.Data.ID)
	if err != nil || updated.InputContentEnabled || updated.MaxOutputTokens != 0 {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	versions, err := store.ListSecurityPolicyVersions(t.Context(), created.Data.ID)
	if err != nil || len(versions) != 2 {
		t.Fatalf("versions=%+v err=%v", versions, err)
	}
	var snapshot SecurityPolicy
	if err := json.Unmarshal(versions[0].PolicySnapshot, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.InputContentEnabled {
		t.Fatal("policy snapshot must preserve the disabled input content switch")
	}
	payload, err := store.ListEnabledSecurityPolicies(t.Context())
	if err != nil || len(payload) != 1 || payload[0].InputContentEnabled {
		t.Fatalf("guard payload=%+v err=%v", payload, err)
	}
}
