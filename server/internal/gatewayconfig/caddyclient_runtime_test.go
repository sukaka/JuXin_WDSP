package gatewayconfig

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetRuntimeSnapshot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jiuzhang/runtime" || r.Method != http.MethodGet {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"node":"gateway-1","resources":{"cpu_percent":81.5,"memory_percent":70},"connections":{"active":3,"accepted_total":9,"accepted_per_second":1.5},"http":{"sessions_active":2},"software_bypass":{"enabled":true,"active":true,"reason":"CPU_THRESHOLD"}}`))
	}))
	defer server.Close()
	client := &CaddyClient{baseURL: server.URL, httpClient: server.Client()}
	snapshot, err := client.GetRuntimeSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Node != "gateway-1" || snapshot.Resources.CPUPercent == nil || *snapshot.Resources.CPUPercent != 81.5 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if snapshot.Connections.Active != 3 || !snapshot.SoftwareBypass.Active {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}
