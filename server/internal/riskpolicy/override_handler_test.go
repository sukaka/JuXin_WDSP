package riskpolicy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type overrideTestRepository struct {
	items map[uuid.UUID]*Policy
}

func newOverrideTestRepository() *overrideTestRepository {
	return &overrideTestRepository{items: map[uuid.UUID]*Policy{}}
}

func (r *overrideTestRepository) GetApplicationOverride(_ context.Context, id uuid.UUID) (*Policy, error) {
	return r.items[id], nil
}

func (r *overrideTestRepository) PutApplicationOverride(_ context.Context, p *Policy, expected int, updatedBy string) (*Policy, error) {
	id := *p.ApplicationID
	current := r.items[id]
	if current == nil && expected != 0 || current != nil && current.Version != expected {
		return nil, ErrConflict
	}
	stored := *p
	stored.UpdatedBy = updatedBy
	stored.UpdatedAt = time.Now().UTC()
	if current == nil {
		stored.ID = uuid.New()
		stored.CreatedAt = stored.UpdatedAt
		stored.Version = 1
	} else {
		stored.ID = current.ID
		stored.CreatedAt = current.CreatedAt
		stored.Version = current.Version + 1
	}
	r.items[id] = &stored
	result := stored
	return &result, nil
}

func (r *overrideTestRepository) DeleteApplicationOverride(_ context.Context, id uuid.UUID, version int) error {
	current := r.items[id]
	if current == nil {
		return ErrNotFound
	}
	if current.Version != version {
		return ErrConflict
	}
	delete(r.items, id)
	return nil
}

func (r *overrideTestRepository) ListGuardRiskPolicyOverrides(context.Context) ([]gatewayconfig.GuardRiskPolicyOverride, error) {
	return []gatewayconfig.GuardRiskPolicyOverride{}, nil
}

func overrideRequest(t *testing.T, mux http.Handler, method, path, body string, permissions ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func newOverrideTestMux(store OverrideRepository, permissions ...string) *http.ServeMux {
	mux := http.NewServeMux()
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if permissions != nil {
				perms := map[string]bool{}
				for _, permission := range permissions {
					perms[permission] = true
				}
				principal := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: perms}
				next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), principal)))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	RegisterOverrideRoutes(mux, auth, NewOverrideHandler(store, nil))
	return mux
}

func TestApplicationOverrideHTTPCreateUpdateConflictDelete(t *testing.T) {
	store := newOverrideTestRepository()
	applicationID := uuid.New()
	path := "/api/v1/security/risk-policy/applications/" + applicationID.String()
	if rr := overrideRequest(t, newOverrideTestMux(store), http.MethodGet, path, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status=%d", rr.Code)
	}
	if rr := overrideRequest(t, newOverrideTestMux(store, "other.read"), http.MethodGet, path, ""); rr.Code != http.StatusForbidden {
		t.Fatalf("forbidden status=%d", rr.Code)
	}
	mux := newOverrideTestMux(store, "risk_policy.read", "risk_policy.edit")
	rr := overrideRequest(t, mux, http.MethodGet, path, "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"policy":null`) {
		t.Fatalf("missing override status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := `{"enabled":true,"mode":"OBSERVE","version":0,"block_threshold":80,"rate_limit_threshold":40,"rate_limit_rps":10,"signal_window_seconds":86400,"scores":{"WAF":50},"risk_levels":{"medium":20,"high":40,"critical":70}}`
	rr = overrideRequest(t, mux, http.MethodPut, path, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	var created struct {
		Data struct {
			Policy Policy `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Data.Policy.Version != 1 || created.Data.Policy.ApplicationID == nil || *created.Data.Policy.ApplicationID != applicationID {
		t.Fatalf("created=%+v", created.Data.Policy)
	}
	if rr := overrideRequest(t, mux, http.MethodPut, path, body); rr.Code != http.StatusConflict {
		t.Fatalf("stale create status=%d", rr.Code)
	}
	updatedBody := strings.Replace(body, `"version":0`, `"version":1`, 1)
	updatedBody = strings.Replace(updatedBody, `"mode":"OBSERVE"`, `"mode":"PROTECT"`, 1)
	rr = overrideRequest(t, mux, http.MethodPut, path, updatedBody)
	if rr.Code != http.StatusOK || store.items[applicationID].Version != 2 || store.items[applicationID].Mode != ModeProtect {
		t.Fatalf("update status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr := overrideRequest(t, mux, http.MethodDelete, path, ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("delete without version status=%d", rr.Code)
	}
	if rr := overrideRequest(t, mux, http.MethodDelete, path+"?version=1", ""); rr.Code != http.StatusConflict {
		t.Fatalf("stale delete status=%d", rr.Code)
	}
	if rr := overrideRequest(t, mux, http.MethodDelete, path+"?version=2", ""); rr.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", rr.Code, rr.Body.String())
	}
	if store.items[applicationID] != nil {
		t.Fatal("deleted override still exists")
	}
}

func TestApplicationOverrideValidation(t *testing.T) {
	mux := newOverrideTestMux(newOverrideTestRepository(), "risk_policy.edit")
	path := "/api/v1/security/risk-policy/applications/" + uuid.NewString()
	body := `{"enabled":true,"mode":"BLOCK","version":0,"block_threshold":80,"rate_limit_threshold":40,"rate_limit_rps":10,"signal_window_seconds":86400,"scores":{},"risk_levels":{"medium":20,"high":40,"critical":70}}`
	if rr := overrideRequest(t, mux, http.MethodPut, path, body); rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid mode status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr := overrideRequest(t, mux, http.MethodPut, "/api/v1/security/risk-policy/applications/not-a-uuid", body); rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid application status=%d", rr.Code)
	}
}

func TestApplicationOverrideRejectsGlobalScope(t *testing.T) {
	mux := newOverrideTestMux(newOverrideTestRepository(), "risk_policy.edit")
	path := "/api/v1/security/risk-policy/applications/" + uuid.NewString()
	body := `{"scope":"GLOBAL","enabled":true,"mode":"OBSERVE","version":0,"block_threshold":80,"rate_limit_threshold":40,"rate_limit_rps":10,"signal_window_seconds":86400,"scores":{},"risk_levels":{"medium":20,"high":40,"critical":70}}`
	if rr := overrideRequest(t, mux, http.MethodPut, path, body); rr.Code != http.StatusBadRequest {
		t.Fatalf("global scope in application override status=%d", rr.Code)
	}
}
