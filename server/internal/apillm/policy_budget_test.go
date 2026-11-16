package apillm

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestSecurityPolicyTokenBudgetVersionsAndPartialUpdate(t *testing.T) {
	store := NewMemSecurityPolicyStore()
	mux := newSecurityPolicyTestMux(store, injectPrincipal(PermSecurityRead, PermSecurityManage))
	applicationID := uuid.NewString()
	body := `{"application_id":"` + applicationID + `","name":"AI 资源防护","max_output_tokens":2048}`
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
	if created.Data.MaxOutputTokens != 2048 {
		t.Fatalf("created=%+v", created.Data)
	}

	rr = doSecurityPolicyJSON(t, mux, http.MethodPatch, "/api/v1/api-security/llm/security-policies/"+created.Data.ID.String(), `{"enabled":false}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("partial update status=%d body=%s", rr.Code, rr.Body.String())
	}
	updated, err := store.GetSecurityPolicy(t.Context(), created.Data.ID)
	if err != nil || updated.MaxOutputTokens != 2048 || updated.Enabled {
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
	if snapshot.MaxOutputTokens != 2048 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestSecurityPolicyTokenBudgetValidation(t *testing.T) {
	mux := newSecurityPolicyTestMux(NewMemSecurityPolicyStore(), injectPrincipal(PermSecurityManage))
	for _, value := range []string{"-1", "1000001"} {
		body := `{"application_id":"` + uuid.NewString() + `","name":"AI 资源防护","max_output_tokens":` + value + `}`
		rr := doSecurityPolicyJSON(t, mux, http.MethodPost, "/api/v1/api-security/llm/security-policies", body)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("value=%s status=%d body=%s", value, rr.Code, rr.Body.String())
		}
	}
}
