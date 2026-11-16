package apiassets

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

type applicationValueTestStore struct {
	*MemStore
	value *ApplicationAssetValue
	err   error
}

func (s *applicationValueTestStore) ApplicationAssetValue(context.Context, uuid.UUID) (*ApplicationAssetValue, error) {
	if s.value == nil {
		return nil, s.err
	}
	value := *s.value
	return &value, nil
}

func newApplicationValueTestMux(store Repository, permissions ...string) *http.ServeMux {
	mux := http.NewServeMux()
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if permissions != nil {
				perms := map[string]bool{}
				for _, permission := range permissions {
					perms[permission] = true
				}
				p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: perms}
				next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	RegisterRoutes(mux, auth, NewHandler(store, nil))
	return mux
}

func TestApplicationAssetValueHTTPContract(t *testing.T) {
	applicationID := uuid.New()
	store := &applicationValueTestStore{MemStore: NewMemStore(), value: &ApplicationAssetValue{
		ApplicationID: applicationID, Level: AssetValueHigh, AverageScore: 14.5, MaxScore: 20, MaxTotal: 26,
		EndpointCount: 3, ScoredCount: 2, UnscoredCount: 1,
		LevelDistribution: map[string]int64{AssetValueHigh: 1, AssetValueMedium: 1},
		Dimensions:        []ApplicationValueDimension{{Name: "data_sensitivity", AverageScore: 2.5, Max: 3}},
	}}
	path := "/api/v1/api-security/applications/" + applicationID.String() + "/asset-value"
	mux := newApplicationValueTestMux(store)
	if rr := doJSON(t, mux, http.MethodGet, path, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status=%d", rr.Code)
	}
	mux = newApplicationValueTestMux(store, "api_asset.read")
	rr := doJSON(t, mux, http.MethodGet, path, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("read status=%d body=%s", rr.Code, rr.Body.String())
	}
	var result struct {
		Data ApplicationAssetValue `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Data.ApplicationID != applicationID || result.Data.AverageScore != 14.5 || result.Data.UnscoredCount != 1 || result.Data.LevelDistribution[AssetValueHigh] != 1 {
		t.Fatalf("result=%+v", result.Data)
	}
	if len(result.Data.Dimensions) != 1 || result.Data.Dimensions[0].Name != "data_sensitivity" {
		t.Fatalf("dimensions=%+v", result.Data.Dimensions)
	}

	if rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/applications/not-a-uuid/asset-value", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid ID status=%d", rr.Code)
	}
	store.err = ErrNotFound
	store.value = nil
	if rr := doJSON(t, mux, http.MethodGet, path, nil); rr.Code != http.StatusNotFound {
		t.Fatalf("missing application status=%d", rr.Code)
	}
}

func TestApplicationAssetValuePermissionAndUnavailable(t *testing.T) {
	mux := newApplicationValueTestMux(&applicationValueTestStore{MemStore: NewMemStore()}, "other.read")
	path := "/api/v1/api-security/applications/" + uuid.NewString() + "/asset-value"
	if rr := doJSON(t, mux, http.MethodGet, path, nil); rr.Code != http.StatusForbidden {
		t.Fatalf("forbidden status=%d", rr.Code)
	}
	mux = newApplicationValueTestMux(NewMemStore(), "api_asset.read")
	if rr := doJSON(t, mux, http.MethodGet, path, nil); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable status=%d", rr.Code)
	}
}

func TestApplicationAssetValueFailure(t *testing.T) {
	store := &applicationValueTestStore{MemStore: NewMemStore(), err: errors.New("database unavailable")}
	mux := newApplicationValueTestMux(store, "api_asset.read")
	path := "/api/v1/api-security/applications/" + uuid.NewString() + "/asset-value"
	if rr := doJSON(t, mux, http.MethodGet, path, nil); rr.Code != http.StatusInternalServerError {
		t.Fatalf("failure status=%d", rr.Code)
	}
}
