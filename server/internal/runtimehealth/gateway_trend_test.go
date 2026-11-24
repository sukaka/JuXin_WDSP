package runtimehealth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/response"
)

type fakeSnapshotStore struct {
	history     []Snapshot
	historyErr  error
	latest      *Snapshot
	latestErr   error
	gotComp     string
	gotSince    time.Time
	gotLimit    int
	historyHits int
	latestHits  int
}

func (f *fakeSnapshotStore) LatestAll(context.Context) ([]Snapshot, error) { return nil, nil }

func (f *fakeSnapshotStore) LatestByComponent(_ context.Context, component string) (*Snapshot, error) {
	f.latestHits++
	f.gotComp = component
	return f.latest, f.latestErr
}

func (f *fakeSnapshotStore) HistoryByComponent(_ context.Context, component string, since time.Time, limit int) ([]Snapshot, error) {
	f.historyHits++
	f.gotComp = component
	f.gotSince = since
	f.gotLimit = limit
	if f.historyErr != nil {
		return nil, f.historyErr
	}
	return f.history, nil
}

type fakeGatewayProvider struct {
	snap    *gatewayconfig.GatewayRuntimeSnapshot
	snapErr error
	hist    *gatewayconfig.GatewayRuntimeHistory
	histErr error
}

func (f *fakeGatewayProvider) GetRuntimeSnapshot(context.Context) (*gatewayconfig.GatewayRuntimeSnapshot, error) {
	return f.snap, f.snapErr
}

func (f *fakeGatewayProvider) GetRuntimeHistory(context.Context) (*gatewayconfig.GatewayRuntimeHistory, error) {
	return f.hist, f.histErr
}

type apiEnvelope struct {
	Code    string               `json:"code"`
	Message string               `json:"message"`
	Data    GatewayTrendResponse `json:"data"`
}

func floatPtr(v float64) *float64 { return &v }
func uint64Ptr(v uint64) *uint64  { return &v }
func intPtr(v int) *int           { return &v }

func doGatewayTrendRequest(t *testing.T, h *Handler, query string) (*httptest.ResponseRecorder, apiEnvelope, map[string]interface{}) {
	t.Helper()
	target := "/api/v1/system-health/gateway-trend"
	if query != "" {
		target += "?" + query
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	h.GatewayTrend(rec, req)

	var env apiEnvelope
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	var raw map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	return rec, env, raw
}

func TestGatewayTrendInvalidRange(t *testing.T) {
	h := NewHandler(nil, nil)
	for _, bad := range []string{"range=5m", "range=7d", "range=10M", "range=invalid", "range=24H"} {
		rec, env, _ := doGatewayTrendRequest(t, h, bad)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", bad, rec.Code)
		}
		if env.Code != response.CodeInvalidArgument {
			t.Errorf("%s: code = %q, want %q", bad, env.Code, response.CodeInvalidArgument)
		}
	}
}

func TestGatewayTrend10mLiveAndAppRanking(t *testing.T) {
	now := time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC)
	activatedAt := now.Add(-15 * time.Second)
	snap := &gatewayconfig.GatewayRuntimeSnapshot{
		Node:    "gw-live-01",
		TakenAt: now,
	}
	snap.Resources.CPUPercent = floatPtr(72.5)
	snap.Resources.MemoryPercent = floatPtr(64.0)
	snap.Resources.MemoryUsedBytes = uint64Ptr(4 << 30)
	snap.Resources.MemoryTotalBytes = uint64Ptr(8 << 30)
	snap.Resources.Load1 = floatPtr(1.5)
	snap.Resources.Load5 = floatPtr(1.2)
	snap.Resources.Load15 = floatPtr(1.0)
	snap.Resources.FDOpen = intPtr(320)
	snap.Resources.FDMax = uint64Ptr(65536)
	snap.Resources.FDUsagePercent = floatPtr(0.49)
	snap.Connections.Active = 88
	snap.Connections.AcceptedTotal = 12345
	snap.Connections.AcceptedPerSecond = 24.5
	snap.Connections.BytesInTotal = 500000
	snap.Connections.BytesOutTotal = 1500000
	snap.Connections.BytesInPerSecond = 12000
	snap.Connections.BytesOutPerSecond = 36000
	snap.Connections.TCPStates = &gatewayconfig.GatewayTCPStates{
		Established: 80, TimeWait: 5, CloseWait: 1, SynRecv: 1, FinWait: 0, Listen: 1, Other: 0,
	}
	snap.HTTP.RequestsInFlight = 9
	snap.HTTP.RequestsTotal = 9000
	snap.HTTP.RequestsPerSecond = 120.5
	snap.HTTP.SessionsActive = 42
	snap.HTTP.SessionsNewTotal = 600
	snap.HTTP.SessionsNewPerSecond = 3.5
	snap.HTTP.SessionsOverflowTotal = 1
	snap.HTTP.Status2xxTotal = 8500
	snap.HTTP.Status3xxTotal = 200
	snap.HTTP.Status4xxTotal = 250
	snap.HTTP.Status5xxTotal = 50
	snap.HTTP.Status2xxPerSecond = 110
	snap.HTTP.Status3xxPerSecond = 4
	snap.HTTP.Status4xxPerSecond = 5.5
	snap.HTTP.Status5xxPerSecond = 1
	snap.SoftwareBypass.Enabled = true
	snap.SoftwareBypass.Active = true
	snap.SoftwareBypass.Reason = "CPU_THRESHOLD"
	snap.SoftwareBypass.CPUThresholdPercent = 80
	snap.SoftwareBypass.MemoryThresholdPercent = 85
	snap.SoftwareBypass.RecoveryCPUPercent = 75
	snap.SoftwareBypass.RecoveryMemoryPercent = 80
	snap.SoftwareBypass.MinHoldSeconds = 10
	snap.SoftwareBypass.ActivatedAt = &activatedAt
	snap.SoftwareBypass.TransitionsTotal = 3
	snap.SoftwareBypass.BypassedRequestsTotal = 55

	// 构造 25 个应用以验证排序（RPS 降序、Total 降序）与 20 项截断。
	apps := make([]gatewayconfig.GatewayRuntimeApplication, 0, 25)
	for i := 1; i <= 25; i++ {
		apps = append(apps, gatewayconfig.GatewayRuntimeApplication{
			AppID:             fmt.Sprintf("app-%02d", i),
			RequestsPerSecond: float64(i),
			RequestsTotal:     uint64(i * 10),
		})
	}
	// 同 RPS 拼 RequestsTotal 降序：app-tie-high 应排在 app-tie-low 前面，两者均排第一梯队。
	apps[0] = gatewayconfig.GatewayRuntimeApplication{AppID: "app-tie-low", RequestsPerSecond: 100, RequestsTotal: 500}
	apps[1] = gatewayconfig.GatewayRuntimeApplication{AppID: "app-tie-high", RequestsPerSecond: 100, RequestsTotal: 900}
	snap.Applications = apps

	hist := &gatewayconfig.GatewayRuntimeHistory{
		Node:            "gw-live-01",
		IntervalSeconds: 2,
		Points: []gatewayconfig.GatewayRuntimeHistoryPoint{
			{
				TakenAt:                         now.Add(-4 * time.Second),
				CPUPercent:                      floatPtr(50.0),
				MemoryPercent:                   floatPtr(60.0),
				TCPConnectionsActive:            40,
				TCPConnectionsAcceptedPerSecond: 10,
				BytesInPerSecond:                5000,
				BytesOutPerSecond:               10000,
				HTTPRequestsPerSecond:           60,
				HTTPSessionsActive:              20,
				HTTPSessionsNewPerSecond:        2,
				SoftwareBypassActive:            false,
			},
			{
				TakenAt:                         now.Add(-2 * time.Second),
				CPUPercent:                      floatPtr(84.0),
				MemoryPercent:                   floatPtr(68.0),
				TCPConnectionsActive:            100,
				TCPConnectionsAcceptedPerSecond: 30,
				BytesInPerSecond:                15000,
				BytesOutPerSecond:               40000,
				HTTPRequestsPerSecond:           150,
				HTTPSessionsActive:              55,
				HTTPSessionsNewPerSecond:        6.5,
				SoftwareBypassActive:            true,
			},
		},
	}

	store := &fakeSnapshotStore{}
	h := NewHandler(nil, nil)
	h.store = store
	h.now = func() time.Time { return now }
	h.SetGatewayRuntimeProvider(&fakeGatewayProvider{snap: snap, hist: hist})
	h.SetAppNameLookup(func(_ context.Context, ids []string) (map[string]AppMeta, error) {
		if len(ids) > 20 {
			t.Errorf("lookup requested %d ids, expected <= 20", len(ids))
		}
		return map[string]AppMeta{
			"app-tie-high": {Code: "portal", Name: "门户网站"},
		}, nil
	})

	rec, env, _ := doGatewayTrendRequest(t, h, "range=10m")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	d := env.Data
	if d.Range != "10m" || d.Source != GatewayTrendSourceLive || d.IntervalSeconds != 2 || d.Node != "gw-live-01" {
		t.Fatalf("meta = %+v", d)
	}
	if store.historyHits != 0 {
		t.Fatalf("live path should not query DB history, got %d hits", store.historyHits)
	}
	if d.Current == nil || d.Current.Status != StatusUp || d.Current.HTTPSessionsCapacity != 10000 ||
		d.Current.TCPStates == nil || d.Current.TCPStates.Established != 80 ||
		!d.Current.SoftwareBypass.Active || d.Current.SoftwareBypass.RecoveryCPUPercent != 75 {
		t.Fatalf("current = %+v", d.Current)
	}
	if d.Summary.PeakTCPConnectionsActive != 100 || d.Summary.AvgTCPConnectionsActive != 70 ||
		d.Summary.PeakTCPConnectionsAcceptedPerSecond != 30 || d.Summary.PeakHTTPSessionsActive != 55 ||
		d.Summary.PeakHTTPSessionsNewPerSecond != 6.5 || d.Summary.PeakHTTPRequestsPerSecond != 150 ||
		d.Summary.PeakBytesInPerSecond != 15000 || d.Summary.PeakBytesOutPerSecond != 40000 ||
		d.Summary.PeakCPUPercent == nil || *d.Summary.PeakCPUPercent != 84.0 ||
		d.Summary.PeakMemoryPercent == nil || *d.Summary.PeakMemoryPercent != 68.0 ||
		d.Summary.BypassActivePoints != 1 {
		t.Fatalf("summary = %+v", d.Summary)
	}
	if len(d.Points) != 2 {
		t.Fatalf("len(points) = %d, want 2", len(d.Points))
	}
	if len(d.Applications) != 20 {
		t.Fatalf("len(applications) = %d, want 20", len(d.Applications))
	}
	if d.Applications[0].AppID != "app-tie-high" || d.Applications[0].AppCode != "portal" || d.Applications[0].AppName != "门户网站" {
		t.Fatalf("app[0] = %+v", d.Applications[0])
	}
	if d.Applications[1].AppID != "app-tie-low" || d.Applications[1].AppCode != "app-tie-low" || d.Applications[1].AppName != "app-tie-low" {
		t.Fatalf("app[1] = %+v, expected fallback to app_id", d.Applications[1])
	}
}

func TestGatewayTrend10mFallbackToDatabase(t *testing.T) {
	now := time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC)
	latency := 4
	// 模拟从 PostgreSQL JSONB 反序列化后的 map/slice 形态。
	store := &fakeSnapshotStore{
		history: []Snapshot{
			{
				TakenAt:   now.Add(-60 * time.Second),
				Component: ComponentGateway,
				Status:    StatusUp,
				LatencyMs: &latency,
				Metrics: map[string]interface{}{
					MetricCPUUsagePercent:                 float64(30),
					MetricMemoryUsagePercent:              float64(45),
					MetricTCPConnectionsActive:            float64(10),
					MetricTCPConnectionsAcceptedPerSecond: float64(4),
					MetricHTTPRequestsPerSecond:           float64(25),
					MetricHTTPSessionsActive:              float64(6),
					MetricHTTPSessionsNewPerSecond:        float64(1.5),
					MetricBytesInPerSecond:                float64(1024),
					MetricBytesOutPerSecond:               float64(2048),
				},
			},
			{
				TakenAt:   now.Add(-30 * time.Second),
				Component: ComponentGateway,
				Status:    StatusUp,
				LatencyMs: &latency,
				Metrics: map[string]interface{}{
					MetricCPUUsagePercent:                 float64(40),
					MetricMemoryUsagePercent:              float64(50),
					MetricTCPConnectionsActive:            float64(20),
					MetricTCPConnectionsAcceptedPerSecond: float64(8),
					MetricHTTPRequestsPerSecond:           float64(50),
					MetricHTTPSessionsActive:              float64(12),
					MetricHTTPSessionsNewPerSecond:        float64(2.5),
					MetricBytesInPerSecond:                float64(2048),
					MetricBytesOutPerSecond:               float64(4096),
					MetricTCPStates: map[string]interface{}{
						"established": float64(18),
						"time_wait":   float64(2),
					},
					MetricApplications: []interface{}{
						map[string]interface{}{
							"app_id":              "app-db-1",
							"requests_per_second": float64(40),
							"requests_total":      float64(1200),
						},
					},
				},
			},
		},
	}

	h := NewHandler(nil, nil)
	h.store = store
	h.now = func() time.Time { return now }
	h.SetGatewayRuntimeProvider(&fakeGatewayProvider{
		histErr: errors.New("404 not found"),
		snapErr: errors.New("connection refused"),
	})
	h.SetAppNameLookup(func(context.Context, []string) (map[string]AppMeta, error) {
		return nil, errors.New("db hiccup")
	})

	rec, env, _ := doGatewayTrendRequest(t, h, "range=10m")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	d := env.Data
	if d.Source != GatewayTrendSourceDatabaseFallback || d.IntervalSeconds != 30 {
		t.Fatalf("source/interval = %s/%d, want database_fallback/30", d.Source, d.IntervalSeconds)
	}
	if store.gotComp != ComponentGateway || !store.gotSince.Equal(now.Add(-10*time.Minute)) || store.gotLimit != maxHistorySnapshots {
		t.Fatalf("store query = comp=%s since=%v limit=%d", store.gotComp, store.gotSince, store.gotLimit)
	}
	if d.Current == nil || d.Current.TCPStates == nil || d.Current.TCPStates.Established != 18 ||
		d.Current.HTTPSessionsCapacity != 10000 {
		t.Fatalf("current = %+v", d.Current)
	}
	if len(d.Applications) != 1 || d.Applications[0].AppName != "app-db-1" || d.Applications[0].AppCode != "app-db-1" {
		t.Fatalf("applications = %+v", d.Applications)
	}
}

func TestGatewayTrendHistoricalRangesAndLegacyFallback(t *testing.T) {
	now := time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC)

	t.Run("range windows", func(t *testing.T) {
		cases := []struct {
			query  string
			want   string
			window time.Duration
		}{
			{"", "1h", time.Hour},
			{"range=1h", "1h", time.Hour},
			{"range=6h", "6h", 6 * time.Hour},
			{"range=24h", "24h", 24 * time.Hour},
		}
		for _, tc := range cases {
			store := &fakeSnapshotStore{}
			h := NewHandler(nil, nil)
			h.store = store
			h.now = func() time.Time { return now }

			rec, env, raw := doGatewayTrendRequest(t, h, tc.query)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: status = %d", tc.query, rec.Code)
			}
			if env.Data.Range != tc.want || env.Data.Source != GatewayTrendSourceDatabase || env.Data.IntervalSeconds != 30 {
				t.Fatalf("%s: meta = %+v", tc.query, env.Data)
			}
			if !store.gotSince.Equal(now.Add(-tc.window)) {
				t.Errorf("%s: since = %v, want %v", tc.query, store.gotSince, now.Add(-tc.window))
			}
			// 验证空态下 points 和 applications 在 JSON 中必须是 [] 而非 null。
			dataObj := raw["data"].(map[string]interface{})
			if pts, ok := dataObj["points"].([]interface{}); !ok || len(pts) != 0 {
				t.Errorf("%s: points raw JSON = %#v, want []", tc.query, dataObj["points"])
			}
			if apps, ok := dataObj["applications"].([]interface{}); !ok || len(apps) != 0 {
				t.Errorf("%s: applications raw JSON = %#v, want []", tc.query, dataObj["applications"])
			}
			if dataObj["current"] != nil {
				t.Errorf("%s: current = %#v, want nil", tc.query, dataObj["current"])
			}
		}
	})

	t.Run("legacy snapshots estimate missing rates and handle counter reset & zero dt", func(t *testing.T) {
		t0 := now.Add(-120 * time.Second)
		store := &fakeSnapshotStore{
			history: []Snapshot{
				{
					TakenAt:   t0,
					Component: ComponentGateway,
					Status:    StatusUp,
					Metrics: map[string]interface{}{
						MetricCPUUsagePercent:               float64(20),
						MetricMemoryUsagePercent:            float64(30),
						MetricTCPConnectionsActive:          float64(10),
						MetricTCPConnectionsAcceptedTotal:   float64(100),
						MetricHTTPRequestsTotal:             float64(1000),
						MetricHTTPSessionsActive:            float64(5),
						MetricHTTPSessionsNewTotal:          float64(50),
						MetricSoftwareBypassCPUThreshold:    float64(80),
						MetricSoftwareBypassMemoryThreshold: float64(85),
					},
				},
				{
					// +30s: +300 reqs -> 10 req/s, +30 sessions -> 1 sess/s, +60 conns -> 2 conn/s
					TakenAt:   t0.Add(30 * time.Second),
					Component: ComponentGateway,
					Status:    StatusUp,
					Metrics: map[string]interface{}{
						MetricCPUUsagePercent:               float64(35),
						MetricMemoryUsagePercent:            float64(40),
						MetricTCPConnectionsActive:          float64(25),
						MetricTCPConnectionsAcceptedTotal:   float64(160),
						MetricHTTPRequestsTotal:             float64(1300),
						MetricHTTPSessionsActive:            float64(10),
						MetricHTTPSessionsNewTotal:          float64(80),
						MetricSoftwareBypassActive:          true,
						MetricSoftwareBypassCPUThreshold:    float64(80),
						MetricSoftwareBypassMemoryThreshold: float64(85),
					},
				},
				{
					// 计数器回绕（网关重启）：currTotal < prevTotal -> 必须归 0，不得为负或溢出
					TakenAt:   t0.Add(60 * time.Second),
					Component: ComponentGateway,
					Status:    StatusUp,
					Metrics: map[string]interface{}{
						MetricTCPConnectionsActive: float64(5),
						MetricHTTPRequestsTotal:    float64(50),
						MetricHTTPSessionsNewTotal: float64(5),
					},
				},
				{
					// 相同时间戳（dt == 0）：防除零，必须为 0
					TakenAt:   t0.Add(60 * time.Second),
					Component: ComponentGateway,
					Status:    StatusUp,
					Metrics: map[string]interface{}{
						MetricTCPConnectionsActive:          float64(8),
						MetricHTTPRequestsTotal:             float64(200),
						MetricHTTPSessionsNewTotal:          float64(15),
						MetricSoftwareBypassCPUThreshold:    float64(80),
						MetricSoftwareBypassMemoryThreshold: float64(85),
					},
				},
			},
		}

		h := NewHandler(nil, nil)
		h.store = store
		h.now = func() time.Time { return now }

		rec, env, _ := doGatewayTrendRequest(t, h, "range=1h")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		pts := env.Data.Points
		if len(pts) != 4 {
			t.Fatalf("len(points) = %d, want 4", len(pts))
		}
		if math.Abs(pts[1].HTTPRequestsPerSecond-10) > 1e-6 ||
			math.Abs(pts[1].HTTPSessionsNewPerSecond-1) > 1e-6 ||
			math.Abs(pts[1].TCPConnectionsAcceptedPerSecond-2) > 1e-6 {
			t.Fatalf("estimated rates at pt[1] = %+v", pts[1])
		}
		if pts[2].HTTPRequestsPerSecond != 0 || pts[2].HTTPSessionsNewPerSecond != 0 {
			t.Fatalf("counter reset pt[2] should be 0, got %+v", pts[2])
		}
		if pts[3].HTTPRequestsPerSecond != 0 || pts[3].HTTPSessionsNewPerSecond != 0 {
			t.Fatalf("zero-dt pt[3] should be 0, got %+v", pts[3])
		}
		if env.Data.Summary.PeakTCPConnectionsActive != 25 ||
			math.Abs(env.Data.Summary.AvgTCPConnectionsActive-12) > 1e-6 ||
			env.Data.Summary.BypassActivePoints != 1 ||
			env.Data.Summary.PeakCPUPercent == nil || *env.Data.Summary.PeakCPUPercent != 35 {
			t.Fatalf("summary = %+v", env.Data.Summary)
		}
		if env.Data.Current == nil ||
			env.Data.Current.SoftwareBypass.RecoveryCPUPercent != 75 ||
			env.Data.Current.SoftwareBypass.RecoveryMemoryPercent != 80 {
			t.Fatalf("current = %+v", env.Data.Current)
		}
	})

	t.Run("store error returns 500", func(t *testing.T) {
		store := &fakeSnapshotStore{historyErr: errors.New("pg down")}
		h := NewHandler(nil, nil)
		h.store = store
		h.now = func() time.Time { return now }

		rec, env, _ := doGatewayTrendRequest(t, h, "range=6h")
		if rec.Code != http.StatusInternalServerError || env.Code != response.CodeInternalError {
			t.Fatalf("status=%d code=%s", rec.Code, env.Code)
		}
	})

	t.Run("1h combines DB history with live current snapshot", func(t *testing.T) {
		liveSnap := &gatewayconfig.GatewayRuntimeSnapshot{Node: "gw-hybrid", TakenAt: now}
		liveSnap.Connections.Active = 77
		liveSnap.HTTP.RequestsPerSecond = 210
		liveSnap.Applications = []gatewayconfig.GatewayRuntimeApplication{
			{AppID: "app-live", RequestsPerSecond: 210, RequestsTotal: 5000},
		}
		store := &fakeSnapshotStore{
			history: []Snapshot{
				{
					TakenAt:   now.Add(-5 * time.Minute),
					Component: ComponentGateway,
					Status:    StatusUp,
					Metrics: map[string]interface{}{
						MetricTCPConnectionsActive:  float64(33),
						MetricHTTPRequestsPerSecond: float64(100),
					},
				},
			},
		}
		h := NewHandler(nil, nil)
		h.store = store
		h.now = func() time.Time { return now }
		h.SetGatewayRuntimeProvider(&fakeGatewayProvider{snap: liveSnap})
		h.SetAppNameLookup(func(context.Context, []string) (map[string]AppMeta, error) {
			return map[string]AppMeta{"app-live": {Code: "api", Name: "核心 API"}}, nil
		})

		rec, env, _ := doGatewayTrendRequest(t, h, "range=1h")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		d := env.Data
		if d.Source != GatewayTrendSourceDatabase || d.Node != "gw-hybrid" || len(d.Points) != 1 {
			t.Fatalf("data = %+v", d)
		}
		if d.Current == nil || d.Current.TCPConnectionsActive != 77 || d.Current.HTTPRequestsPerSecond != 210 {
			t.Fatalf("current = %+v", d.Current)
		}
		if len(d.Applications) != 1 || d.Applications[0].AppCode != "api" || d.Applications[0].AppName != "核心 API" {
			t.Fatalf("applications = %+v", d.Applications)
		}
	})

	t.Run("10m history 404 keeps live current while falling back points to DB", func(t *testing.T) {
		liveSnap := &gatewayconfig.GatewayRuntimeSnapshot{Node: "gw-old", TakenAt: now}
		liveSnap.Connections.Active = 19
		store := &fakeSnapshotStore{
			history: []Snapshot{
				{
					TakenAt:   now.Add(-2 * time.Minute),
					Component: ComponentGateway,
					Status:    StatusUp,
					Metrics:   map[string]interface{}{MetricTCPConnectionsActive: float64(15)},
				},
			},
		}
		h := NewHandler(nil, nil)
		h.store = store
		h.now = func() time.Time { return now }
		h.SetGatewayRuntimeProvider(&fakeGatewayProvider{
			histErr: errors.New("gateway runtime history endpoint returned 404"),
			snap:    liveSnap,
		})

		rec, env, _ := doGatewayTrendRequest(t, h, "range=10m")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if env.Data.Source != GatewayTrendSourceDatabaseFallback || env.Data.Node != "gw-old" ||
			len(env.Data.Points) != 1 || env.Data.Current == nil || env.Data.Current.TCPConnectionsActive != 19 {
			t.Fatalf("data = %+v", env.Data)
		}
	})

	t.Run("empty window falls back current to LatestByComponent", func(t *testing.T) {
		store := &fakeSnapshotStore{
			history: nil,
			latest: &Snapshot{
				TakenAt:   now.Add(-2 * time.Hour),
				Component: ComponentGateway,
				Status:    StatusDegraded,
				Metrics:   map[string]interface{}{MetricTCPConnectionsActive: float64(9)},
			},
		}
		h := NewHandler(nil, nil)
		h.store = store
		h.now = func() time.Time { return now }

		rec, env, _ := doGatewayTrendRequest(t, h, "range=1h")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if len(env.Data.Points) != 0 || env.Data.Current == nil || env.Data.Current.Status != StatusDegraded ||
			env.Data.Current.TCPConnectionsActive != 9 || store.latestHits != 1 {
			t.Fatalf("data = %+v latestHits=%d", env.Data, store.latestHits)
		}
	})
}
