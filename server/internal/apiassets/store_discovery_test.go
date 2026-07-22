package apiassets

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/server/internal/response"
)

// TestMemStoreUpsertListConfirm drives Repository UpsertDiscovery/List/Confirm
// with fixture path normalization (production Store shares the same contract).
func TestMemStoreUpsertListConfirm(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	tpl := normalizer.NormalizePath("/users/42")
	if tpl != "/users/{id}" {
		t.Fatalf("normalize=%s", tpl)
	}
	e1, err := store.UpsertDiscovery(ctx, "GET", tpl, 0.7, true)
	if err != nil {
		t.Fatal(err)
	}
	if e1.EndpointKey != "GET /users/{id}" || e1.Status != "DISCOVERED" || e1.HitCount != 1 {
		t.Fatalf("%+v", e1)
	}
	e2, err := store.UpsertDiscovery(ctx, "get", tpl, 0.95, true)
	if err != nil {
		t.Fatal(err)
	}
	if e2.ID != e1.ID || e2.HitCount != 2 || e2.Confidence < 0.9 {
		t.Fatalf("merge: %+v", e2)
	}
	list, total, err := store.List(ctx, "", 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(list) != 1 {
		t.Fatalf("list total=%d len=%d", total, len(list))
	}
	if list[0].PathTemplate != "/users/{id}" || list[0].Method != "GET" || list[0].EndpointKey == "" {
		t.Fatalf("structured empty/wrong: %+v", list[0])
	}
	conf, err := store.Confirm(ctx, e1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if conf.Status != "CONFIRMED" || conf.ConfirmedAt == nil {
		t.Fatalf("%+v", conf)
	}
}

// TestHandlerDiscoverListConfirmHTTP drives real Handler methods with fixture JSON.
func TestHandlerDiscoverListConfirmHTTP(t *testing.T) {
	store := NewMemStore()
	h := NewHandler(store)

	withRID := func(r *http.Request, id string) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), response.RequestIDKey, id))
	}

	// Discover fixture: POST /v1/orders/99 → template /v1/orders/{id}
	body := []byte(`{"method":"POST","path":"/v1/orders/99","confidence":0.8}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-endpoints/discover", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withRID(req, "disc-1")
	rr := httptest.NewRecorder()
	h.Discover(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("discover status=%d body=%s", rr.Code, rr.Body.String())
	}
	var env struct {
		Code string `json:"code"`
		Data struct {
			Endpoint Endpoint `json:"endpoint"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Code != "SUCCESS" {
		t.Fatalf("code=%s body=%s", env.Code, rr.Body.String())
	}
	ep := env.Data.Endpoint
	if ep.ID == uuid.Nil {
		t.Fatal("empty endpoint id")
	}
	if ep.PathTemplate != "/v1/orders/{id}" {
		t.Fatalf("path_template=%s", ep.PathTemplate)
	}
	if ep.EndpointKey != "POST /v1/orders/{id}" {
		t.Fatalf("endpoint_key=%s", ep.EndpointKey)
	}
	if ep.Status != "DISCOVERED" || ep.HitCount < 1 {
		t.Fatalf("%+v", ep)
	}

	// List must return non-empty structured results
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/api-endpoints?page=1&page_size=20", nil)
	req2 = withRID(req2, "list-1")
	rr2 := httptest.NewRecorder()
	h.List(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("list status=%d %s", rr2.Code, rr2.Body.String())
	}
	var listEnv struct {
		Data struct {
			Items []Endpoint `json:"items"`
			Total int64      `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &listEnv); err != nil {
		t.Fatal(err)
	}
	if listEnv.Data.Total < 1 || len(listEnv.Data.Items) < 1 {
		t.Fatalf("empty list: %+v body=%s", listEnv.Data, rr2.Body.String())
	}
	found := false
	for _, it := range listEnv.Data.Items {
		if it.EndpointKey == "POST /v1/orders/{id}" {
			found = true
			if it.Method != "POST" || it.PathTemplate != "/v1/orders/{id}" {
				t.Fatalf("list item: %+v", it)
			}
		}
	}
	if !found {
		t.Fatalf("fixture missing in list: %+v", listEnv.Data.Items)
	}

	// Confirm
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/api-endpoints/"+ep.ID.String()+"/confirm", nil)
	req3.SetPathValue("id", ep.ID.String())
	req3 = withRID(req3, "conf-1")
	rr3 := httptest.NewRecorder()
	h.Confirm(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("confirm status=%d %s", rr3.Code, rr3.Body.String())
	}
	var confEnv struct {
		Data struct {
			Endpoint Endpoint `json:"endpoint"`
			Message  string   `json:"message"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr3.Body.Bytes(), &confEnv); err != nil {
		t.Fatal(err)
	}
	if confEnv.Data.Endpoint.Status != "CONFIRMED" {
		t.Fatalf("confirm: %+v", confEnv.Data)
	}
}
