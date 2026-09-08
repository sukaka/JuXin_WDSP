package k8smeta

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolvePrefersDestinationAndCopiesMetadata(t *testing.T) {
	r := NewResolver()
	r.Replace(map[string]Metadata{
		"10.0.0.1": {Cluster: "prod", Namespace: "client", Pod: "client-1"},
		"10.0.0.2": {Cluster: "prod", Namespace: "payment", Pod: "payment-abc", Workload: "payment", Service: "payment-api"},
	})
	m := r.Resolve("10.0.0.1", "10.0.0.2")
	if m == nil || m.Pod != "payment-abc" || m.Side != "dst" {
		t.Fatalf("unexpected metadata: %#v", m)
	}
	m.Pod = "mutated"
	if got := r.Resolve("", "10.0.0.2"); got.Pod != "payment-abc" {
		t.Fatalf("snapshot was mutated: %#v", got)
	}
}

func TestTruncateReplicaSetName(t *testing.T) {
	if got := truncateReplicaSetName("payment-api-7d9f84c8bf"); got != "payment-api" {
		t.Fatalf("got %q", got)
	}
	if got := truncateReplicaSetName("redis"); got != "redis" {
		t.Fatalf("got %q", got)
	}
}

func TestSyncPaginatesAndJoinsService(t *testing.T) {
	var podRequests, endpointRequests, rsRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("limit") != "500" {
			t.Fatalf("limit = %q", q.Get("limit"))
		}
		switch r.URL.Path {
		case "/api/v1/pods":
			podRequests++
			if q.Get("fieldSelector") != "spec.nodeName=node-a,status.phase=Running" {
				t.Fatalf("fieldSelector = %q", q.Get("fieldSelector"))
			}
			if q.Get("continue") == "" {
				_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{"continue": "next"}, "items": []any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{}, "items": []any{map[string]any{
				"metadata": map[string]any{"name": "api-7d9f6c8b5d-x", "namespace": "prod", "ownerReferences": []any{map[string]string{"kind": "ReplicaSet", "name": "api-7d9f6c8b5d"}}},
				"status":   map[string]string{"podIP": "10.2.0.8"},
			}}})
		case "/apis/apps/v1/namespaces/prod/replicasets":
			rsRequests++
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{}, "items": []any{map[string]any{
				"metadata": map[string]any{"name": "api-7d9f6c8b5d", "ownerReferences": []any{map[string]string{"kind": "Deployment", "name": "api"}}},
			}}})
		case "/api/v1/namespaces/prod/endpoints":
			endpointRequests++
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{}, "items": []any{map[string]any{
				"metadata": map[string]any{"name": "api", "namespace": "prod"},
				"subsets":  []any{map[string]any{"addresses": []any{map[string]string{"ip": "10.2.0.8"}}}},
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c := &Client{baseURL: server.URL, token: "test", nodeName: "node-a", cluster: "cluster-a", http: server.Client()}
	items, err := c.sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if podRequests != 2 || endpointRequests != 1 || rsRequests != 1 {
		t.Fatalf("requests pods=%d endpoints=%d replicasets=%d", podRequests, endpointRequests, rsRequests)
	}
	got, ok := items["10.2.0.8"]
	if !ok {
		t.Fatalf("missing entry: %#v", items)
	}
	want := Metadata{Cluster: "cluster-a", Namespace: "prod", Pod: "api-7d9f6c8b5d-x", Workload: "api", Service: "api"}
	if got.meta != want {
		t.Fatalf("metadata = %#v, want %#v", got.meta, want)
	}
	if got.inferred {
		t.Fatal("经 ReplicaSet→Deployment 权威解析的 workload 不应标记为推断")
	}
}
