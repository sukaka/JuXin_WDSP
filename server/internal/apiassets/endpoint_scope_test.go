package apiassets

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestMemStoreUpsertDiscoveryIsApplicationScoped(t *testing.T) {
	store := NewMemStore()
	appA, appB := uuid.New(), uuid.New()

	a, err := store.UpsertDiscovery(context.Background(), DiscoveryInput{
		Method: "GET", PathTemplate: "/orders/{id}", ApplicationID: &appA,
	})
	if err != nil {
		t.Fatalf("upsert app A: %v", err)
	}
	b, err := store.UpsertDiscovery(context.Background(), DiscoveryInput{
		Method: "GET", PathTemplate: "/orders/{id}", ApplicationID: &appB,
	})
	if err != nil {
		t.Fatalf("upsert app B: %v", err)
	}
	if a.ID == b.ID {
		t.Fatalf("same endpoint was merged across applications: %s", a.ID)
	}
	if a.EndpointKey != "GET /orders/{id}" || b.EndpointKey != a.EndpointKey {
		t.Fatalf("runtime endpoint key must remain METHOD path: a=%q b=%q", a.EndpointKey, b.EndpointKey)
	}

	aAgain, err := store.UpsertDiscovery(context.Background(), DiscoveryInput{
		Method: "GET", PathTemplate: "/orders/{id}", ApplicationID: &appA,
	})
	if err != nil {
		t.Fatalf("upsert app A again: %v", err)
	}
	if aAgain.ID != a.ID || aAgain.HitCount != 2 {
		t.Fatalf("same application did not hit existing endpoint: got id=%s hits=%d", aAgain.ID, aAgain.HitCount)
	}
}

func TestMemStoreUpsertDiscoveryIsBindingScoped(t *testing.T) {
	store := NewMemStore()
	bindingA, bindingB := uuid.New(), uuid.New()

	a, err := store.UpsertDiscovery(context.Background(), DiscoveryInput{
		Method: "GET", PathTemplate: "/orders/{id}", Host: "api.example.com", ApplicationBindingID: &bindingA,
	})
	if err != nil {
		t.Fatalf("upsert scope A: %v", err)
	}
	b, err := store.UpsertDiscovery(context.Background(), DiscoveryInput{
		Method: "GET", PathTemplate: "/orders/{id}", Host: "api.example.com", ApplicationBindingID: &bindingB,
	})
	if err != nil {
		t.Fatalf("upsert scope B: %v", err)
	}
	if a.ID == b.ID || a.EndpointKey != b.EndpointKey {
		t.Fatalf("binding scopes were merged or changed runtime key: a=%q b=%q", a.EndpointKey, b.EndpointKey)
	}
	if a.ApplicationBindingID == nil || b.ApplicationBindingID == nil || *a.ApplicationBindingID == *b.ApplicationBindingID {
		t.Fatalf("binding scope was not persisted on endpoint: %+v %+v", a.ApplicationBindingID, b.ApplicationBindingID)
	}
}

func TestMemStoreUpsertDiscoveryIsHostAndProtocolScoped(t *testing.T) {
	store := NewMemStore()
	inputs := []DiscoveryInput{
		{Method: "GET", PathTemplate: "/health", Host: "api-a.example", ProtocolType: "REST"},
		{Method: "GET", PathTemplate: "/health", Host: "api-b.example", ProtocolType: "REST"},
		{Method: "GET", PathTemplate: "/health", Host: "api-a.example", ProtocolType: "GRPC"},
	}
	endpoints := make([]*Endpoint, 0, len(inputs))
	for _, in := range inputs {
		ep, err := store.UpsertDiscovery(context.Background(), in)
		if err != nil {
			t.Fatalf("upsert scoped endpoint: %v", err)
		}
		endpoints = append(endpoints, ep)
	}
	if endpoints[0].ID == endpoints[1].ID || endpoints[0].ID == endpoints[2].ID || endpoints[1].ID == endpoints[2].ID {
		t.Fatalf("different host/protocol scopes were merged")
	}
	if endpoints[0].EndpointKey != endpoints[1].EndpointKey || endpoints[0].EndpointKey != endpoints[2].EndpointKey {
		t.Fatalf("host/protocol scope leaked into runtime endpoint key")
	}
}

func TestMemStoreUpsertDiscoveryLegacyAndScopedRowsDoNotMerge(t *testing.T) {
	store := NewMemStore()
	legacy, err := store.UpsertDiscovery(context.Background(), DiscoveryInput{Method: "GET", PathTemplate: "/health"})
	if err != nil {
		t.Fatalf("upsert legacy endpoint: %v", err)
	}
	app := uuid.New()
	scoped, err := store.UpsertDiscovery(context.Background(), DiscoveryInput{
		Method: "GET", PathTemplate: "/health", ApplicationID: &app, Host: "api.example.com",
	})
	if err != nil {
		t.Fatalf("upsert scoped endpoint: %v", err)
	}
	if legacy.ID == scoped.ID || legacy.EndpointKey != scoped.EndpointKey {
		t.Fatalf("legacy row merged with scoped row or runtime key changed: legacy=%+v scoped=%+v", legacy, scoped)
	}
}

func TestMemStoreUpsertDiscoveryKeepsLegacyUnassignedKey(t *testing.T) {
	ep, err := NewMemStore().UpsertDiscovery(context.Background(), DiscoveryInput{
		Method: "get", PathTemplate: "/health",
	})
	if err != nil {
		t.Fatalf("upsert legacy endpoint: %v", err)
	}
	if ep.EndpointKey != "GET /health" {
		t.Fatalf("legacy endpoint key changed: %q", ep.EndpointKey)
	}
}
