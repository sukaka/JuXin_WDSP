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
	e1, err := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: tpl, Confidence: 0.7, IsAPI: true})
	if err != nil {
		t.Fatal(err)
	}
	if e1.EndpointKey != "GET /users/{id}" || e1.AssetStatus != "DISCOVERED" || e1.HitCount != 1 {
		t.Fatalf("%+v", e1)
	}
	e2, err := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "get", PathTemplate: tpl, Confidence: 0.95, IsAPI: true})
	if err != nil {
		t.Fatal(err)
	}
	if e2.ID != e1.ID || e2.HitCount != 2 || e2.APIConfidence < 0.9 {
		t.Fatalf("merge: %+v", e2)
	}
	list, total, err := store.List(ctx, ListFilter{Page: 1, PageSize: 20})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(list) != 1 {
		t.Fatalf("list total=%d len=%d", total, len(list))
	}
	if list[0].NormalizedPath != "/users/{id}" || list[0].HTTPMethod != "GET" || list[0].EndpointKey == "" {
		t.Fatalf("structured empty/wrong: %+v", list[0])
	}
	conf, err := store.Confirm(ctx, e1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if conf.AssetStatus != "CONFIRMED" || conf.ConfirmedAt == nil {
		t.Fatalf("%+v", conf)
	}
}

// TestHandlerListConfirmBatchHTTP drives real Handler methods with fixture JSON
// （发现数据由网关采集链路 UpsertDiscovery 喂入，这里直接写存储层）。
func TestHandlerListConfirmBatchHTTP(t *testing.T) {
	store := NewMemStore()
	h := NewHandler(store, nil)

	withRID := func(r *http.Request, id string) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), response.RequestIDKey, id))
	}

	// 发现数据（等价于网关采集链路调用 UpsertDiscovery）
	ep, err := store.UpsertDiscovery(context.Background(), DiscoveryInput{Method: "POST", PathTemplate: normalizer.NormalizePath("/v1/orders/99"), Confidence: 0.8, IsAPI: true})
	if err != nil {
		t.Fatal(err)
	}
	if ep.ID == uuid.Nil {
		t.Fatal("empty endpoint id")
	}
	if ep.NormalizedPath != "/v1/orders/{id}" || ep.EndpointKey != "POST /v1/orders/{id}" {
		t.Fatalf("%+v", ep)
	}
	if ep.AssetStatus != "DISCOVERED" || ep.HitCount < 1 {
		t.Fatalf("%+v", ep)
	}

	// List must return non-empty structured results
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/api-security/endpoints?page=1&page_size=20", nil)
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
			if it.HTTPMethod != "POST" || it.NormalizedPath != "/v1/orders/{id}" {
				t.Fatalf("list item: %+v", it)
			}
		}
	}
	if !found {
		t.Fatalf("fixture missing in list: %+v", listEnv.Data.Items)
	}

	// 批量确认
	body := []byte(`{"ids":["` + ep.ID.String() + `"]}`)
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/api-security/endpoints/confirm", bytes.NewReader(body))
	req3.Header.Set("Content-Type", "application/json")
	req3 = withRID(req3, "conf-1")
	rr3 := httptest.NewRecorder()
	h.ConfirmBatch(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("confirm status=%d %s", rr3.Code, rr3.Body.String())
	}
	got, err := store.GetByID(context.Background(), ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AssetStatus != "CONFIRMED" || got.ConfirmedAt == nil {
		t.Fatalf("confirm: %+v", got)
	}
}
