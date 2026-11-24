package gatewayconfig

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestGetRuntimeSnapshotExtendedFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"node": "gateway-prod-1",
			"taken_at": "2026-11-24T05:00:00Z",
			"resources": {
				"cpu_percent": 42.5,
				"memory_percent": 61.2,
				"memory_used_bytes": 4294967296,
				"memory_total_bytes": 8589934592,
				"load1": 1.25,
				"load5": 1.10,
				"load15": 0.95,
				"fd_open": 512,
				"fd_max": 65536,
				"fd_usage_percent": 0.78
			},
			"connections": {
				"active": 120,
				"accepted_total": 5000,
				"accepted_per_second": 25.5,
				"bytes_in_total": 1048576,
				"bytes_out_total": 2097152,
				"bytes_in_per_second": 10240.5,
				"bytes_out_per_second": 20480.25,
				"tcp_states": {
					"established": 95,
					"time_wait": 15,
					"close_wait": 2,
					"syn_recv": 1,
					"fin_wait": 3,
					"listen": 4,
					"other": 0
				}
			},
			"http": {
				"requests_in_flight": 14,
				"requests_total": 8800,
				"requests_per_second": 145.5,
				"sessions_active": 64,
				"sessions_new_total": 900,
				"sessions_new_per_second": 4.2,
				"sessions_overflow_total": 0,
				"status_2xx_total": 8000,
				"status_3xx_total": 300,
				"status_4xx_total": 450,
				"status_5xx_total": 50,
				"status_2xx_per_second": 130.0,
				"status_3xx_per_second": 5.5,
				"status_4xx_per_second": 8.0,
				"status_5xx_per_second": 2.0
			},
			"applications": [
				{
					"app_id": "app-1",
					"requests_in_flight": 10,
					"requests_total": 5000,
					"requests_per_second": 99.5,
					"bypassed_requests_total": 12,
					"bytes_in_total": 500000,
					"bytes_out_total": 1000000,
					"bytes_in_per_second": 6000.0,
					"bytes_out_per_second": 12000.0,
					"status_4xx_total": 20,
					"status_5xx_total": 3
				}
			]
		}`))
	}))
	defer server.Close()

	client := &CaddyClient{baseURL: server.URL, httpClient: server.Client()}
	snap, err := client.GetRuntimeSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Resources.MemoryUsedBytes == nil || *snap.Resources.MemoryUsedBytes != 4294967296 {
		t.Fatalf("memory_used_bytes = %v", snap.Resources.MemoryUsedBytes)
	}
	if snap.Resources.MemoryTotalBytes == nil || *snap.Resources.MemoryTotalBytes != 8589934592 {
		t.Fatalf("memory_total_bytes = %v", snap.Resources.MemoryTotalBytes)
	}
	if snap.Resources.Load1 == nil || *snap.Resources.Load1 != 1.25 ||
		snap.Resources.Load5 == nil || *snap.Resources.Load5 != 1.10 ||
		snap.Resources.Load15 == nil || *snap.Resources.Load15 != 0.95 {
		t.Fatalf("load = %v/%v/%v", snap.Resources.Load1, snap.Resources.Load5, snap.Resources.Load15)
	}
	if snap.Resources.FDOpen == nil || *snap.Resources.FDOpen != 512 ||
		snap.Resources.FDMax == nil || *snap.Resources.FDMax != 65536 ||
		snap.Resources.FDUsagePercent == nil || *snap.Resources.FDUsagePercent != 0.78 {
		t.Fatalf("fd = %v/%v/%v", snap.Resources.FDOpen, snap.Resources.FDMax, snap.Resources.FDUsagePercent)
	}
	if snap.Connections.BytesInTotal != 1048576 || snap.Connections.BytesOutTotal != 2097152 ||
		snap.Connections.BytesInPerSecond != 10240.5 || snap.Connections.BytesOutPerSecond != 20480.25 {
		t.Fatalf("connections bytes = %+v", snap.Connections)
	}
	if snap.Connections.TCPStates == nil || snap.Connections.TCPStates.Established != 95 ||
		snap.Connections.TCPStates.TimeWait != 15 || snap.Connections.TCPStates.Listen != 4 {
		t.Fatalf("tcp_states = %+v", snap.Connections.TCPStates)
	}
	if snap.HTTP.RequestsPerSecond != 145.5 || snap.HTTP.SessionsNewPerSecond != 4.2 ||
		snap.HTTP.Status2xxTotal != 8000 || snap.HTTP.Status5xxPerSecond != 2.0 {
		t.Fatalf("http = %+v", snap.HTTP)
	}
	if len(snap.Applications) != 1 || snap.Applications[0].AppID != "app-1" ||
		snap.Applications[0].RequestsPerSecond != 99.5 || snap.Applications[0].Status5xxTotal != 3 {
		t.Fatalf("applications = %+v", snap.Applications)
	}
}

func TestGetRuntimeHistory(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/jiuzhang/runtime/history" || r.Method != http.MethodGet {
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"node": "gateway-1",
				"interval_seconds": 2,
				"points": [
					{
						"taken_at": "2026-11-24T05:00:00Z",
						"cpu_percent": 32.5,
						"memory_percent": 55.0,
						"load1": 0.75,
						"fd_usage_percent": 1.2,
						"tcp_connections_active": 40,
						"tcp_connections_accepted_per_second": 12.5,
						"bytes_in_per_second": 2048.0,
						"bytes_out_per_second": 4096.0,
						"http_requests_in_flight": 5,
						"http_requests_per_second": 88.5,
						"http_sessions_active": 21,
						"http_sessions_new_per_second": 3.5,
						"status_2xx_per_second": 80.0,
						"status_3xx_per_second": 3.0,
						"status_4xx_per_second": 4.5,
						"status_5xx_per_second": 1.0,
						"software_bypass_active": false
					},
					{
						"taken_at": "2026-11-24T05:00:02Z",
						"cpu_percent": null,
						"memory_percent": null,
						"tcp_connections_active": 45,
						"software_bypass_active": true
					}
				]
			}`))
		}))
		defer server.Close()

		client := &CaddyClient{baseURL: server.URL, httpClient: server.Client()}
		hist, err := client.GetRuntimeHistory(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if hist.Node != "gateway-1" || hist.IntervalSeconds != 2 || len(hist.Points) != 2 {
			t.Fatalf("history = %+v", hist)
		}
		p0 := hist.Points[0]
		if p0.CPUPercent == nil || *p0.CPUPercent != 32.5 ||
			p0.MemoryPercent == nil || *p0.MemoryPercent != 55.0 ||
			p0.Load1 == nil || *p0.Load1 != 0.75 ||
			p0.FDUsagePercent == nil || *p0.FDUsagePercent != 1.2 ||
			p0.TCPConnectionsActive != 40 || p0.HTTPRequestsPerSecond != 88.5 ||
			p0.HTTPSessionsNewPerSecond != 3.5 || p0.Status5xxPerSecond != 1.0 ||
			p0.SoftwareBypassActive {
			t.Fatalf("point[0] = %+v", p0)
		}
		p1 := hist.Points[1]
		if p1.CPUPercent != nil || p1.MemoryPercent != nil || !p1.SoftwareBypassActive {
			t.Fatalf("point[1] = %+v", p1)
		}
	})

	t.Run("null points normalized to empty slice", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"node":"gw","interval_seconds":2,"points":null}`))
		}))
		defer server.Close()
		client := &CaddyClient{baseURL: server.URL, httpClient: server.Client()}
		hist, err := client.GetRuntimeHistory(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if hist.Points == nil || len(hist.Points) != 0 {
			t.Fatalf("points = %#v, want empty non-nil slice", hist.Points)
		}
	})

	t.Run("non-200 status returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		}))
		defer server.Close()
		client := &CaddyClient{baseURL: server.URL, httpClient: server.Client()}
		if _, err := client.GetRuntimeHistory(context.Background()); err == nil || !strings.Contains(err.Error(), "404") {
			t.Fatalf("err = %v, want 404 error", err)
		}
	})

	t.Run("oversized body truncated at 1MB fails decode", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"node":"` + strings.Repeat("a", (1<<20)+100) + `","points":[]}`))
		}))
		defer server.Close()
		client := &CaddyClient{baseURL: server.URL, httpClient: server.Client()}
		if _, err := client.GetRuntimeHistory(context.Background()); err == nil {
			t.Fatal("expected decode error for >1MB response")
		}
	})
}
