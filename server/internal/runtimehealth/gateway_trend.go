package runtimehealth

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/response"
)

const (
	GatewayTrendRange10m = "10m"
	GatewayTrendRange1h  = "1h"
	GatewayTrendRange6h  = "6h"
	GatewayTrendRange24h = "24h"

	GatewayTrendSourceLive             = "gateway_live"
	GatewayTrendSourceDatabase         = "database"
	GatewayTrendSourceDatabaseFallback = "database_fallback"

	DefaultGatewayLiveIntervalSeconds = 2
	DefaultGatewayDBIntervalSeconds   = 30
	DefaultHTTPSessionsCapacity       = 10000

	maxGatewayTrendApplications = 20
	gatewayLiveQueryTimeout     = 3 * time.Second
)

// GatewayTrendSoftwareBypass 描述网关软件旁路运行态。
type GatewayTrendSoftwareBypass struct {
	Enabled                bool       `json:"enabled"`
	Active                 bool       `json:"active"`
	Reason                 string     `json:"reason"`
	CPUThresholdPercent    int        `json:"cpu_threshold_percent"`
	MemoryThresholdPercent int        `json:"memory_threshold_percent"`
	RecoveryCPUPercent     int        `json:"recovery_cpu_percent"`
	RecoveryMemoryPercent  int        `json:"recovery_memory_percent"`
	MinHoldSeconds         int        `json:"min_hold_seconds"`
	ActivatedAt            *time.Time `json:"activated_at"`
	TransitionsTotal       uint64     `json:"transitions_total"`
	BypassedRequestsTotal  uint64     `json:"bypassed_requests_total"`
}

// GatewayTrendCurrent 描述网关当前瞬时运行态。
type GatewayTrendCurrent struct {
	Status                          string                          `json:"status"`
	LatencyMs                       *int                            `json:"latency_ms"`
	TakenAt                         time.Time                       `json:"taken_at"`
	CPUPercent                      *float64                        `json:"cpu_percent"`
	MemoryPercent                   *float64                        `json:"memory_percent"`
	MemoryUsedBytes                 *uint64                         `json:"memory_used_bytes"`
	MemoryTotalBytes                *uint64                         `json:"memory_total_bytes"`
	Load1                           *float64                        `json:"load1"`
	Load5                           *float64                        `json:"load5"`
	Load15                          *float64                        `json:"load15"`
	FDOpen                          *int                            `json:"fd_open"`
	FDMax                           *uint64                         `json:"fd_max"`
	FDUsagePercent                  *float64                        `json:"fd_usage_percent"`
	TCPConnectionsActive            int64                           `json:"tcp_connections_active"`
	TCPConnectionsAcceptedTotal     uint64                          `json:"tcp_connections_accepted_total"`
	TCPConnectionsAcceptedPerSecond float64                         `json:"tcp_connections_accepted_per_second"`
	BytesInTotal                    uint64                          `json:"bytes_in_total"`
	BytesOutTotal                   uint64                          `json:"bytes_out_total"`
	BytesInPerSecond                float64                         `json:"bytes_in_per_second"`
	BytesOutPerSecond               float64                         `json:"bytes_out_per_second"`
	HTTPRequestsInFlight            int64                           `json:"http_requests_in_flight"`
	HTTPRequestsTotal               uint64                          `json:"http_requests_total"`
	HTTPRequestsPerSecond           float64                         `json:"http_requests_per_second"`
	HTTPSessionsActive              int                             `json:"http_sessions_active"`
	HTTPSessionsNewTotal            uint64                          `json:"http_sessions_new_total"`
	HTTPSessionsNewPerSecond        float64                         `json:"http_sessions_new_per_second"`
	HTTPSessionsOverflowTotal       uint64                          `json:"http_sessions_overflow_total"`
	HTTPSessionsCapacity            int                             `json:"http_sessions_capacity"`
	Status2xxTotal                  uint64                          `json:"status_2xx_total"`
	Status3xxTotal                  uint64                          `json:"status_3xx_total"`
	Status4xxTotal                  uint64                          `json:"status_4xx_total"`
	Status5xxTotal                  uint64                          `json:"status_5xx_total"`
	Status2xxPerSecond              float64                         `json:"status_2xx_per_second"`
	Status3xxPerSecond              float64                         `json:"status_3xx_per_second"`
	Status4xxPerSecond              float64                         `json:"status_4xx_per_second"`
	Status5xxPerSecond              float64                         `json:"status_5xx_per_second"`
	SoftwareBypass                  GatewayTrendSoftwareBypass      `json:"software_bypass"`
	TCPStates                       *gatewayconfig.GatewayTCPStates `json:"tcp_states"`
	ResourceSampleError             string                          `json:"resource_sample_error"`
}

// GatewayTrendSummary 汇总时间窗口内的峰值、均值与旁路点数。
type GatewayTrendSummary struct {
	PeakTCPConnectionsActive            int64    `json:"peak_tcp_connections_active"`
	AvgTCPConnectionsActive             float64  `json:"avg_tcp_connections_active"`
	PeakTCPConnectionsAcceptedPerSecond float64  `json:"peak_tcp_connections_accepted_per_second"`
	PeakHTTPSessionsActive              int      `json:"peak_http_sessions_active"`
	PeakHTTPSessionsNewPerSecond        float64  `json:"peak_http_sessions_new_per_second"`
	PeakHTTPRequestsPerSecond           float64  `json:"peak_http_requests_per_second"`
	PeakBytesInPerSecond                float64  `json:"peak_bytes_in_per_second"`
	PeakBytesOutPerSecond               float64  `json:"peak_bytes_out_per_second"`
	PeakCPUPercent                      *float64 `json:"peak_cpu_percent"`
	PeakMemoryPercent                   *float64 `json:"peak_memory_percent"`
	BypassActivePoints                  int      `json:"bypass_active_points"`
}

// GatewayTrendPoint 描述单个时间点上的网关运行趋势指标。
type GatewayTrendPoint struct {
	TakenAt                         time.Time `json:"taken_at"`
	CPUPercent                      *float64  `json:"cpu_percent"`
	MemoryPercent                   *float64  `json:"memory_percent"`
	Load1                           *float64  `json:"load1"`
	FDUsagePercent                  *float64  `json:"fd_usage_percent"`
	TCPConnectionsActive            int64     `json:"tcp_connections_active"`
	TCPConnectionsAcceptedPerSecond float64   `json:"tcp_connections_accepted_per_second"`
	BytesInPerSecond                float64   `json:"bytes_in_per_second"`
	BytesOutPerSecond               float64   `json:"bytes_out_per_second"`
	HTTPRequestsInFlight            int64     `json:"http_requests_in_flight"`
	HTTPRequestsPerSecond           float64   `json:"http_requests_per_second"`
	HTTPSessionsActive              int       `json:"http_sessions_active"`
	HTTPSessionsNewPerSecond        float64   `json:"http_sessions_new_per_second"`
	Status2xxPerSecond              float64   `json:"status_2xx_per_second"`
	Status3xxPerSecond              float64   `json:"status_3xx_per_second"`
	Status4xxPerSecond              float64   `json:"status_4xx_per_second"`
	Status5xxPerSecond              float64   `json:"status_5xx_per_second"`
	SoftwareBypassActive            bool      `json:"software_bypass_active"`
}

// GatewayTrendApplication 描述单应用在网关侧的实时负载明细（附带应用编码与名称）。
type GatewayTrendApplication struct {
	AppID                 string  `json:"app_id"`
	AppCode               string  `json:"app_code"`
	AppName               string  `json:"app_name"`
	RequestsInFlight      int64   `json:"requests_in_flight"`
	RequestsTotal         uint64  `json:"requests_total"`
	RequestsPerSecond     float64 `json:"requests_per_second"`
	BypassedRequestsTotal uint64  `json:"bypassed_requests_total"`
	BytesInTotal          uint64  `json:"bytes_in_total"`
	BytesOutTotal         uint64  `json:"bytes_out_total"`
	BytesInPerSecond      float64 `json:"bytes_in_per_second"`
	BytesOutPerSecond     float64 `json:"bytes_out_per_second"`
	Status4xxTotal        uint64  `json:"status_4xx_total"`
	Status5xxTotal        uint64  `json:"status_5xx_total"`
}

// GatewayTrendResponse 是 GET /api/v1/system-health/gateway-trend 的响应载荷。
type GatewayTrendResponse struct {
	Range           string                    `json:"range"`
	Source          string                    `json:"source"`
	IntervalSeconds int                       `json:"interval_seconds"`
	GeneratedAt     time.Time                 `json:"generated_at"`
	Node            string                    `json:"node"`
	Current         *GatewayTrendCurrent      `json:"current"`
	Summary         GatewayTrendSummary       `json:"summary"`
	Points          []GatewayTrendPoint       `json:"points"`
	Applications    []GatewayTrendApplication `json:"applications"`
}

func parseGatewayTrendRange(raw string) (string, time.Duration, bool) {
	switch raw {
	case "", GatewayTrendRange1h:
		return GatewayTrendRange1h, time.Hour, true
	case GatewayTrendRange10m:
		return GatewayTrendRange10m, 10 * time.Minute, true
	case GatewayTrendRange6h:
		return GatewayTrendRange6h, 6 * time.Hour, true
	case GatewayTrendRange24h:
		return GatewayTrendRange24h, 24 * time.Hour, true
	default:
		return "", 0, false
	}
}

// GatewayTrend 网关连接/会话/吞吐实时与历史趋势（GET /system-health/gateway-trend）。
func (h *Handler) GatewayTrend(w http.ResponseWriter, r *http.Request) {
	rangeName, window, ok := parseGatewayTrendRange(r.URL.Query().Get("range"))
	if !ok {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "range 仅支持 10m、1h、6h、24h")
		return
	}

	now := h.now().UTC()
	resp := GatewayTrendResponse{
		Range:        rangeName,
		GeneratedAt:  now,
		Points:       []GatewayTrendPoint{},
		Applications: []GatewayTrendApplication{},
	}

	var rawApps []gatewayconfig.GatewayRuntimeApplication

	if rangeName == GatewayTrendRange10m {
		var (
			liveHistory *gatewayconfig.GatewayRuntimeHistory
			liveSnap    *gatewayconfig.GatewayRuntimeSnapshot
			liveLatency *int
		)
		if h.gatewayProvider != nil {
			gwCtx, cancel := context.WithTimeout(r.Context(), gatewayLiveQueryTimeout)
			hist, histErr := h.gatewayProvider.GetRuntimeHistory(gwCtx)
			if histErr == nil && hist != nil {
				liveHistory = hist
			} else if histErr != nil {
				slog.Debug("gateway runtime history unavailable, will fallback to database", "error", histErr)
			}
			// 复用同一时间预算尝试实时快照：旧版网关历史端点 404 时仍可拿到实时瞬时状态；
			// 若前面已超时，gwCtx 已过期会立即返回，不会叠加等待。
			if gwCtx.Err() == nil {
				liveSnap, liveLatency = h.fetchLiveSnapshot(gwCtx)
			}
			cancel()
		}

		if liveHistory != nil {
			resp.Source = GatewayTrendSourceLive
			resp.IntervalSeconds = liveHistory.IntervalSeconds
			if resp.IntervalSeconds <= 0 {
				resp.IntervalSeconds = DefaultGatewayLiveIntervalSeconds
			}
			resp.Node = liveHistory.Node
			resp.Points = trendPointsFromGatewayHistory(liveHistory.Points)
			if liveSnap != nil {
				if liveSnap.Node != "" {
					resp.Node = liveSnap.Node
				}
				resp.Current = trendCurrentFromGatewaySnapshot(liveSnap, liveLatency, now)
				rawApps = liveSnap.Applications
			} else if h.store != nil {
				latest, err := h.store.LatestByComponent(r.Context(), ComponentGateway)
				if err != nil {
					slog.Warn("load fallback latest gateway snapshot failed", "error", err)
				} else if latest != nil {
					resp.Current = trendCurrentFromDBSnapshot(latest, nil)
					rawApps = extractApplicationsFromMetrics(latest.Metrics)
				}
			}
		} else {
			resp.Source = GatewayTrendSourceDatabaseFallback
			resp.IntervalSeconds = DefaultGatewayDBIntervalSeconds
			snaps, err := h.queryGatewayHistory(r.Context(), now.Add(-window))
			if err != nil {
				response.InternalError(w, r, err)
				return
			}
			resp.Points = trendPointsFromDBSnapshots(snaps)
			if liveSnap != nil {
				resp.Node = liveSnap.Node
				resp.Current = trendCurrentFromGatewaySnapshot(liveSnap, liveLatency, now)
				rawApps = liveSnap.Applications
			} else {
				latest, lastPoint, err := h.resolveLatestDBSnapshot(r.Context(), snaps, resp.Points)
				if err != nil {
					response.InternalError(w, r, err)
					return
				}
				if latest != nil {
					resp.Current = trendCurrentFromDBSnapshot(latest, lastPoint)
					rawApps = extractApplicationsFromMetrics(latest.Metrics)
				}
			}
		}
	} else {
		resp.Source = GatewayTrendSourceDatabase
		resp.IntervalSeconds = DefaultGatewayDBIntervalSeconds
		snaps, err := h.queryGatewayHistory(r.Context(), now.Add(-window))
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		resp.Points = trendPointsFromDBSnapshots(snaps)

		var (
			liveSnap    *gatewayconfig.GatewayRuntimeSnapshot
			liveLatency *int
		)
		if h.gatewayProvider != nil {
			gwCtx, cancel := context.WithTimeout(r.Context(), gatewayLiveQueryTimeout)
			liveSnap, liveLatency = h.fetchLiveSnapshot(gwCtx)
			cancel()
		}
		if liveSnap != nil {
			resp.Node = liveSnap.Node
			resp.Current = trendCurrentFromGatewaySnapshot(liveSnap, liveLatency, now)
			rawApps = liveSnap.Applications
		} else {
			latest, lastPoint, err := h.resolveLatestDBSnapshot(r.Context(), snaps, resp.Points)
			if err != nil {
				response.InternalError(w, r, err)
				return
			}
			if latest != nil {
				resp.Current = trendCurrentFromDBSnapshot(latest, lastPoint)
				rawApps = extractApplicationsFromMetrics(latest.Metrics)
			}
		}
	}

	resp.Summary = computeGatewayTrendSummary(resp.Points)
	resp.Applications = h.buildGatewayTrendApplications(r.Context(), rawApps)
	response.JSON(w, r, http.StatusOK, resp)
}

func (h *Handler) fetchLiveSnapshot(ctx context.Context) (*gatewayconfig.GatewayRuntimeSnapshot, *int) {
	start := h.now()
	snap, err := h.gatewayProvider.GetRuntimeSnapshot(ctx)
	if err != nil || snap == nil {
		if err != nil {
			slog.Debug("gateway live runtime snapshot unavailable", "error", err)
		}
		return nil, nil
	}
	latency := int(h.now().Sub(start).Milliseconds())
	if latency < 0 {
		latency = 0
	}
	return snap, &latency
}

func (h *Handler) queryGatewayHistory(ctx context.Context, since time.Time) ([]Snapshot, error) {
	if h.store == nil {
		return nil, nil
	}
	return h.store.HistoryByComponent(ctx, ComponentGateway, since, maxHistorySnapshots)
}

func (h *Handler) resolveLatestDBSnapshot(ctx context.Context, snaps []Snapshot, points []GatewayTrendPoint) (*Snapshot, *GatewayTrendPoint, error) {
	if len(snaps) > 0 && len(snaps) < maxHistorySnapshots {
		var lastPt *GatewayTrendPoint
		if len(points) == len(snaps) {
			lastPt = &points[len(points)-1]
		}
		return &snaps[len(snaps)-1], lastPt, nil
	}
	if h.store == nil {
		if len(snaps) > 0 {
			var lastPt *GatewayTrendPoint
			if len(points) == len(snaps) {
				lastPt = &points[len(points)-1]
			}
			return &snaps[len(snaps)-1], lastPt, nil
		}
		return nil, nil, nil
	}
	latest, err := h.store.LatestByComponent(ctx, ComponentGateway)
	if err != nil {
		return nil, nil, err
	}
	return latest, nil, nil
}

func trendPointsFromGatewayHistory(in []gatewayconfig.GatewayRuntimeHistoryPoint) []GatewayTrendPoint {
	out := make([]GatewayTrendPoint, 0, len(in))
	for _, p := range in {
		out = append(out, GatewayTrendPoint{
			TakenAt:                         p.TakenAt,
			CPUPercent:                      cloneFloatPtr(p.CPUPercent),
			MemoryPercent:                   cloneFloatPtr(p.MemoryPercent),
			Load1:                           cloneFloatPtr(p.Load1),
			FDUsagePercent:                  cloneFloatPtr(p.FDUsagePercent),
			TCPConnectionsActive:            p.TCPConnectionsActive,
			TCPConnectionsAcceptedPerSecond: sanitizeFloat(p.TCPConnectionsAcceptedPerSecond),
			BytesInPerSecond:                sanitizeFloat(p.BytesInPerSecond),
			BytesOutPerSecond:               sanitizeFloat(p.BytesOutPerSecond),
			HTTPRequestsInFlight:            p.HTTPRequestsInFlight,
			HTTPRequestsPerSecond:           sanitizeFloat(p.HTTPRequestsPerSecond),
			HTTPSessionsActive:              p.HTTPSessionsActive,
			HTTPSessionsNewPerSecond:        sanitizeFloat(p.HTTPSessionsNewPerSecond),
			Status2xxPerSecond:              sanitizeFloat(p.Status2xxPerSecond),
			Status3xxPerSecond:              sanitizeFloat(p.Status3xxPerSecond),
			Status4xxPerSecond:              sanitizeFloat(p.Status4xxPerSecond),
			Status5xxPerSecond:              sanitizeFloat(p.Status5xxPerSecond),
			SoftwareBypassActive:            p.SoftwareBypassActive,
		})
	}
	return out
}

func trendPointsFromDBSnapshots(snaps []Snapshot) []GatewayTrendPoint {
	out := make([]GatewayTrendPoint, 0, len(snaps))
	for i := range snaps {
		curr := &snaps[i]
		var prev *Snapshot
		if i > 0 {
			prev = &snaps[i-1]
		}
		m := curr.Metrics
		out = append(out, GatewayTrendPoint{
			TakenAt:                         curr.TakenAt,
			CPUPercent:                      metricFloatPtrFallback(m, MetricCPUUsagePercent, "cpu_percent"),
			MemoryPercent:                   metricFloatPtrFallback(m, MetricMemoryUsagePercent, "memory_percent"),
			Load1:                           metricFloatPtr(m, MetricLoad1),
			FDUsagePercent:                  metricFloatPtr(m, MetricFDUsagePercent),
			TCPConnectionsActive:            metricInt64(m, MetricTCPConnectionsActive),
			TCPConnectionsAcceptedPerSecond: metricRateOrDelta(curr, prev, MetricTCPConnectionsAcceptedPerSecond, MetricTCPConnectionsAcceptedTotal),
			BytesInPerSecond:                metricRateOrDelta(curr, prev, MetricBytesInPerSecond, MetricBytesInTotal),
			BytesOutPerSecond:               metricRateOrDelta(curr, prev, MetricBytesOutPerSecond, MetricBytesOutTotal),
			HTTPRequestsInFlight:            metricInt64(m, MetricHTTPRequestsInFlight),
			HTTPRequestsPerSecond:           metricRateOrDelta(curr, prev, MetricHTTPRequestsPerSecond, MetricHTTPRequestsTotal),
			HTTPSessionsActive:              metricInt(m, MetricHTTPSessionsActive),
			HTTPSessionsNewPerSecond:        metricRateOrDelta(curr, prev, MetricHTTPSessionsNewPerSecond, MetricHTTPSessionsNewTotal),
			Status2xxPerSecond:              metricRateOrDelta(curr, prev, MetricStatus2xxPerSecond, MetricStatus2xxTotal),
			Status3xxPerSecond:              metricRateOrDelta(curr, prev, MetricStatus3xxPerSecond, MetricStatus3xxTotal),
			Status4xxPerSecond:              metricRateOrDelta(curr, prev, MetricStatus4xxPerSecond, MetricStatus4xxTotal),
			Status5xxPerSecond:              metricRateOrDelta(curr, prev, MetricStatus5xxPerSecond, MetricStatus5xxTotal),
			SoftwareBypassActive:            metricBool(m, MetricSoftwareBypassActive),
		})
	}
	return out
}

func trendCurrentFromGatewaySnapshot(snap *gatewayconfig.GatewayRuntimeSnapshot, latencyMs *int, fallbackNow time.Time) *GatewayTrendCurrent {
	if snap == nil {
		return nil
	}
	takenAt := snap.TakenAt
	if takenAt.IsZero() {
		takenAt = fallbackNow
	}
	var tcpStates *gatewayconfig.GatewayTCPStates
	if snap.Connections.TCPStates != nil {
		cp := *snap.Connections.TCPStates
		tcpStates = &cp
	}
	var activatedAt *time.Time
	if snap.SoftwareBypass.ActivatedAt != nil {
		cp := *snap.SoftwareBypass.ActivatedAt
		activatedAt = &cp
	}
	return &GatewayTrendCurrent{
		Status:                          StatusUp,
		LatencyMs:                       latencyMs,
		TakenAt:                         takenAt,
		CPUPercent:                      cloneFloatPtr(snap.Resources.CPUPercent),
		MemoryPercent:                   cloneFloatPtr(snap.Resources.MemoryPercent),
		MemoryUsedBytes:                 cloneUint64Ptr(snap.Resources.MemoryUsedBytes),
		MemoryTotalBytes:                cloneUint64Ptr(snap.Resources.MemoryTotalBytes),
		Load1:                           cloneFloatPtr(snap.Resources.Load1),
		Load5:                           cloneFloatPtr(snap.Resources.Load5),
		Load15:                          cloneFloatPtr(snap.Resources.Load15),
		FDOpen:                          cloneIntPtr(snap.Resources.FDOpen),
		FDMax:                           cloneUint64Ptr(snap.Resources.FDMax),
		FDUsagePercent:                  cloneFloatPtr(snap.Resources.FDUsagePercent),
		TCPConnectionsActive:            snap.Connections.Active,
		TCPConnectionsAcceptedTotal:     snap.Connections.AcceptedTotal,
		TCPConnectionsAcceptedPerSecond: sanitizeFloat(snap.Connections.AcceptedPerSecond),
		BytesInTotal:                    snap.Connections.BytesInTotal,
		BytesOutTotal:                   snap.Connections.BytesOutTotal,
		BytesInPerSecond:                sanitizeFloat(snap.Connections.BytesInPerSecond),
		BytesOutPerSecond:               sanitizeFloat(snap.Connections.BytesOutPerSecond),
		HTTPRequestsInFlight:            snap.HTTP.RequestsInFlight,
		HTTPRequestsTotal:               snap.HTTP.RequestsTotal,
		HTTPRequestsPerSecond:           sanitizeFloat(snap.HTTP.RequestsPerSecond),
		HTTPSessionsActive:              snap.HTTP.SessionsActive,
		HTTPSessionsNewTotal:            snap.HTTP.SessionsNewTotal,
		HTTPSessionsNewPerSecond:        sanitizeFloat(snap.HTTP.SessionsNewPerSecond),
		HTTPSessionsOverflowTotal:       snap.HTTP.SessionsOverflowTotal,
		HTTPSessionsCapacity:            DefaultHTTPSessionsCapacity,
		Status2xxTotal:                  snap.HTTP.Status2xxTotal,
		Status3xxTotal:                  snap.HTTP.Status3xxTotal,
		Status4xxTotal:                  snap.HTTP.Status4xxTotal,
		Status5xxTotal:                  snap.HTTP.Status5xxTotal,
		Status2xxPerSecond:              sanitizeFloat(snap.HTTP.Status2xxPerSecond),
		Status3xxPerSecond:              sanitizeFloat(snap.HTTP.Status3xxPerSecond),
		Status4xxPerSecond:              sanitizeFloat(snap.HTTP.Status4xxPerSecond),
		Status5xxPerSecond:              sanitizeFloat(snap.HTTP.Status5xxPerSecond),
		SoftwareBypass: GatewayTrendSoftwareBypass{
			Enabled:                snap.SoftwareBypass.Enabled,
			Active:                 snap.SoftwareBypass.Active,
			Reason:                 snap.SoftwareBypass.Reason,
			CPUThresholdPercent:    snap.SoftwareBypass.CPUThresholdPercent,
			MemoryThresholdPercent: snap.SoftwareBypass.MemoryThresholdPercent,
			RecoveryCPUPercent:     snap.SoftwareBypass.RecoveryCPUPercent,
			RecoveryMemoryPercent:  snap.SoftwareBypass.RecoveryMemoryPercent,
			MinHoldSeconds:         snap.SoftwareBypass.MinHoldSeconds,
			ActivatedAt:            activatedAt,
			TransitionsTotal:       snap.SoftwareBypass.TransitionsTotal,
			BypassedRequestsTotal:  snap.SoftwareBypass.BypassedRequestsTotal,
		},
		TCPStates:           tcpStates,
		ResourceSampleError: snap.Resources.Error,
	}
}

func trendCurrentFromDBSnapshot(snap *Snapshot, estimatedPoint *GatewayTrendPoint) *GatewayTrendCurrent {
	if snap == nil {
		return nil
	}
	m := snap.Metrics
	cpuThr := metricInt(m, MetricSoftwareBypassCPUThreshold)
	memThr := metricInt(m, MetricSoftwareBypassMemoryThreshold)
	recCPU := 0
	if cpuThr > 5 {
		recCPU = cpuThr - 5
	}
	recMem := 0
	if memThr > 5 {
		recMem = memThr - 5
	}
	cur := &GatewayTrendCurrent{
		Status:                          snap.Status,
		LatencyMs:                       snap.LatencyMs,
		TakenAt:                         snap.TakenAt,
		CPUPercent:                      metricFloatPtrFallback(m, MetricCPUUsagePercent, "cpu_percent"),
		MemoryPercent:                   metricFloatPtrFallback(m, MetricMemoryUsagePercent, "memory_percent"),
		MemoryUsedBytes:                 metricUint64Ptr(m, MetricMemoryUsedBytes),
		MemoryTotalBytes:                metricUint64Ptr(m, MetricMemoryTotalBytes),
		Load1:                           metricFloatPtr(m, MetricLoad1),
		Load5:                           metricFloatPtr(m, MetricLoad5),
		Load15:                          metricFloatPtr(m, MetricLoad15),
		FDOpen:                          metricIntPtr(m, MetricFDOpen),
		FDMax:                           metricUint64Ptr(m, MetricFDMax),
		FDUsagePercent:                  metricFloatPtr(m, MetricFDUsagePercent),
		TCPConnectionsActive:            metricInt64(m, MetricTCPConnectionsActive),
		TCPConnectionsAcceptedTotal:     metricUint64(m, MetricTCPConnectionsAcceptedTotal),
		TCPConnectionsAcceptedPerSecond: metricNonNegFloat(m, MetricTCPConnectionsAcceptedPerSecond),
		BytesInTotal:                    metricUint64(m, MetricBytesInTotal),
		BytesOutTotal:                   metricUint64(m, MetricBytesOutTotal),
		BytesInPerSecond:                metricNonNegFloat(m, MetricBytesInPerSecond),
		BytesOutPerSecond:               metricNonNegFloat(m, MetricBytesOutPerSecond),
		HTTPRequestsInFlight:            metricInt64(m, MetricHTTPRequestsInFlight),
		HTTPRequestsTotal:               metricUint64(m, MetricHTTPRequestsTotal),
		HTTPRequestsPerSecond:           metricNonNegFloat(m, MetricHTTPRequestsPerSecond),
		HTTPSessionsActive:              metricInt(m, MetricHTTPSessionsActive),
		HTTPSessionsNewTotal:            metricUint64(m, MetricHTTPSessionsNewTotal),
		HTTPSessionsNewPerSecond:        metricNonNegFloat(m, MetricHTTPSessionsNewPerSecond),
		HTTPSessionsOverflowTotal:       metricUint64(m, MetricHTTPSessionsOverflowTotal),
		HTTPSessionsCapacity:            DefaultHTTPSessionsCapacity,
		Status2xxTotal:                  metricUint64(m, MetricStatus2xxTotal),
		Status3xxTotal:                  metricUint64(m, MetricStatus3xxTotal),
		Status4xxTotal:                  metricUint64(m, MetricStatus4xxTotal),
		Status5xxTotal:                  metricUint64(m, MetricStatus5xxTotal),
		Status2xxPerSecond:              metricNonNegFloat(m, MetricStatus2xxPerSecond),
		Status3xxPerSecond:              metricNonNegFloat(m, MetricStatus3xxPerSecond),
		Status4xxPerSecond:              metricNonNegFloat(m, MetricStatus4xxPerSecond),
		Status5xxPerSecond:              metricNonNegFloat(m, MetricStatus5xxPerSecond),
		SoftwareBypass: GatewayTrendSoftwareBypass{
			Enabled:                metricBool(m, MetricSoftwareBypassEnabled),
			Active:                 metricBool(m, MetricSoftwareBypassActive),
			Reason:                 metricString(m, MetricSoftwareBypassReason),
			CPUThresholdPercent:    cpuThr,
			MemoryThresholdPercent: memThr,
			RecoveryCPUPercent:     recCPU,
			RecoveryMemoryPercent:  recMem,
			TransitionsTotal:       metricUint64(m, MetricSoftwareBypassTransitions),
			BypassedRequestsTotal:  metricUint64(m, MetricSoftwareBypassRequests),
		},
		TCPStates:           extractTCPStatesFromMetrics(m),
		ResourceSampleError: metricString(m, MetricResourceSampleError),
	}
	if estimatedPoint != nil {
		if _, ok := metricFloatSafe(m, MetricTCPConnectionsAcceptedPerSecond); !ok {
			cur.TCPConnectionsAcceptedPerSecond = estimatedPoint.TCPConnectionsAcceptedPerSecond
		}
		if _, ok := metricFloatSafe(m, MetricBytesInPerSecond); !ok {
			cur.BytesInPerSecond = estimatedPoint.BytesInPerSecond
		}
		if _, ok := metricFloatSafe(m, MetricBytesOutPerSecond); !ok {
			cur.BytesOutPerSecond = estimatedPoint.BytesOutPerSecond
		}
		if _, ok := metricFloatSafe(m, MetricHTTPRequestsPerSecond); !ok {
			cur.HTTPRequestsPerSecond = estimatedPoint.HTTPRequestsPerSecond
		}
		if _, ok := metricFloatSafe(m, MetricHTTPSessionsNewPerSecond); !ok {
			cur.HTTPSessionsNewPerSecond = estimatedPoint.HTTPSessionsNewPerSecond
		}
		if _, ok := metricFloatSafe(m, MetricStatus2xxPerSecond); !ok {
			cur.Status2xxPerSecond = estimatedPoint.Status2xxPerSecond
		}
		if _, ok := metricFloatSafe(m, MetricStatus3xxPerSecond); !ok {
			cur.Status3xxPerSecond = estimatedPoint.Status3xxPerSecond
		}
		if _, ok := metricFloatSafe(m, MetricStatus4xxPerSecond); !ok {
			cur.Status4xxPerSecond = estimatedPoint.Status4xxPerSecond
		}
		if _, ok := metricFloatSafe(m, MetricStatus5xxPerSecond); !ok {
			cur.Status5xxPerSecond = estimatedPoint.Status5xxPerSecond
		}
	}
	return cur
}

func computeGatewayTrendSummary(points []GatewayTrendPoint) GatewayTrendSummary {
	var summary GatewayTrendSummary
	if len(points) == 0 {
		return summary
	}
	var (
		activeSum int64
		hasCPU    bool
		peakCPU   float64
		hasMem    bool
		peakMem   float64
	)
	for _, p := range points {
		activeSum += p.TCPConnectionsActive
		if p.TCPConnectionsActive > summary.PeakTCPConnectionsActive {
			summary.PeakTCPConnectionsActive = p.TCPConnectionsActive
		}
		if p.TCPConnectionsAcceptedPerSecond > summary.PeakTCPConnectionsAcceptedPerSecond {
			summary.PeakTCPConnectionsAcceptedPerSecond = p.TCPConnectionsAcceptedPerSecond
		}
		if p.HTTPSessionsActive > summary.PeakHTTPSessionsActive {
			summary.PeakHTTPSessionsActive = p.HTTPSessionsActive
		}
		if p.HTTPSessionsNewPerSecond > summary.PeakHTTPSessionsNewPerSecond {
			summary.PeakHTTPSessionsNewPerSecond = p.HTTPSessionsNewPerSecond
		}
		if p.HTTPRequestsPerSecond > summary.PeakHTTPRequestsPerSecond {
			summary.PeakHTTPRequestsPerSecond = p.HTTPRequestsPerSecond
		}
		if p.BytesInPerSecond > summary.PeakBytesInPerSecond {
			summary.PeakBytesInPerSecond = p.BytesInPerSecond
		}
		if p.BytesOutPerSecond > summary.PeakBytesOutPerSecond {
			summary.PeakBytesOutPerSecond = p.BytesOutPerSecond
		}
		if p.CPUPercent != nil {
			v := sanitizeFloat(*p.CPUPercent)
			if !hasCPU || v > peakCPU {
				hasCPU = true
				peakCPU = v
			}
		}
		if p.MemoryPercent != nil {
			v := sanitizeFloat(*p.MemoryPercent)
			if !hasMem || v > peakMem {
				hasMem = true
				peakMem = v
			}
		}
		if p.SoftwareBypassActive {
			summary.BypassActivePoints++
		}
	}
	summary.AvgTCPConnectionsActive = float64(activeSum) / float64(len(points))
	if hasCPU {
		summary.PeakCPUPercent = &peakCPU
	}
	if hasMem {
		summary.PeakMemoryPercent = &peakMem
	}
	return summary
}

func (h *Handler) buildGatewayTrendApplications(ctx context.Context, raw []gatewayconfig.GatewayRuntimeApplication) []GatewayTrendApplication {
	if len(raw) == 0 {
		return []GatewayTrendApplication{}
	}
	sorted := make([]gatewayconfig.GatewayRuntimeApplication, len(raw))
	copy(sorted, raw)
	sort.Slice(sorted, func(i, j int) bool {
		ri, rj := sanitizeFloat(sorted[i].RequestsPerSecond), sanitizeFloat(sorted[j].RequestsPerSecond)
		if ri != rj {
			return ri > rj
		}
		if sorted[i].RequestsTotal != sorted[j].RequestsTotal {
			return sorted[i].RequestsTotal > sorted[j].RequestsTotal
		}
		return sorted[i].AppID < sorted[j].AppID
	})
	if len(sorted) > maxGatewayTrendApplications {
		sorted = sorted[:maxGatewayTrendApplications]
	}

	var metaMap map[string]AppMeta
	if h.appNameLookup != nil {
		ids := make([]string, 0, len(sorted))
		seen := make(map[string]struct{}, len(sorted))
		for _, a := range sorted {
			if a.AppID == "" {
				continue
			}
			if _, ok := seen[a.AppID]; !ok {
				seen[a.AppID] = struct{}{}
				ids = append(ids, a.AppID)
			}
		}
		if len(ids) > 0 {
			lookedUp, err := h.appNameLookup(ctx, ids)
			if err != nil {
				slog.Warn("gateway trend app name lookup failed, falling back to app_id", "error", err)
			} else {
				metaMap = lookedUp
			}
		}
	}

	out := make([]GatewayTrendApplication, 0, len(sorted))
	for _, a := range sorted {
		code, name := a.AppID, a.AppID
		if meta, ok := metaMap[a.AppID]; ok {
			if meta.Code != "" {
				code = meta.Code
			}
			if meta.Name != "" {
				name = meta.Name
			} else if meta.Code != "" {
				name = meta.Code
			}
		}
		out = append(out, GatewayTrendApplication{
			AppID:                 a.AppID,
			AppCode:               code,
			AppName:               name,
			RequestsInFlight:      a.RequestsInFlight,
			RequestsTotal:         a.RequestsTotal,
			RequestsPerSecond:     sanitizeFloat(a.RequestsPerSecond),
			BypassedRequestsTotal: a.BypassedRequestsTotal,
			BytesInTotal:          a.BytesInTotal,
			BytesOutTotal:         a.BytesOutTotal,
			BytesInPerSecond:      sanitizeFloat(a.BytesInPerSecond),
			BytesOutPerSecond:     sanitizeFloat(a.BytesOutPerSecond),
			Status4xxTotal:        a.Status4xxTotal,
			Status5xxTotal:        a.Status5xxTotal,
		})
	}
	return out
}

func metricFloatSafe(m map[string]interface{}, key string) (float64, bool) {
	if m == nil {
		return 0, false
	}
	v, ok := metricFloat(m, key)
	if !ok || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, false
	}
	return v, true
}

func metricRateOrDelta(curr, prev *Snapshot, rateKey, totalKey string) float64 {
	if v, ok := metricFloatSafe(curr.Metrics, rateKey); ok {
		if v < 0 {
			return 0
		}
		return v
	}
	if prev == nil {
		return 0
	}
	dt := curr.TakenAt.Sub(prev.TakenAt).Seconds()
	if dt <= 0 {
		return 0
	}
	currTotal, ok1 := metricFloatSafe(curr.Metrics, totalKey)
	prevTotal, ok2 := metricFloatSafe(prev.Metrics, totalKey)
	if !ok1 || !ok2 || currTotal < prevTotal {
		return 0
	}
	rate := (currTotal - prevTotal) / dt
	if math.IsNaN(rate) || math.IsInf(rate, 0) || rate < 0 {
		return 0
	}
	return rate
}

func metricNonNegFloat(m map[string]interface{}, key string) float64 {
	v, ok := metricFloatSafe(m, key)
	if !ok || v < 0 {
		return 0
	}
	return v
}

func metricFloatPtr(m map[string]interface{}, key string) *float64 {
	v, ok := metricFloatSafe(m, key)
	if !ok {
		return nil
	}
	return &v
}

func metricFloatPtrFallback(m map[string]interface{}, primary, fallback string) *float64 {
	if p := metricFloatPtr(m, primary); p != nil {
		return p
	}
	return metricFloatPtr(m, fallback)
}

func metricInt(m map[string]interface{}, key string) int {
	v, ok := metricFloatSafe(m, key)
	if !ok {
		return 0
	}
	return int(v)
}

func metricIntPtr(m map[string]interface{}, key string) *int {
	v, ok := metricFloatSafe(m, key)
	if !ok || v < 0 {
		return nil
	}
	n := int(v)
	return &n
}

func metricInt64(m map[string]interface{}, key string) int64 {
	v, ok := metricFloatSafe(m, key)
	if !ok {
		return 0
	}
	return int64(v)
}

func metricUint64(m map[string]interface{}, key string) uint64 {
	v, ok := metricFloatSafe(m, key)
	if !ok || v < 0 {
		return 0
	}
	return uint64(v)
}

func metricUint64Ptr(m map[string]interface{}, key string) *uint64 {
	v, ok := metricFloatSafe(m, key)
	if !ok || v < 0 {
		return nil
	}
	n := uint64(v)
	return &n
}

func metricBool(m map[string]interface{}, key string) bool {
	if m == nil {
		return false
	}
	v, ok := m[key].(bool)
	return ok && v
}

func metricString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key].(string)
	if !ok {
		return ""
	}
	return v
}

func extractTCPStatesFromMetrics(m map[string]interface{}) *gatewayconfig.GatewayTCPStates {
	if m == nil {
		return nil
	}
	raw, ok := m[MetricTCPStates]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case *gatewayconfig.GatewayTCPStates:
		if v == nil {
			return nil
		}
		cp := *v
		return &cp
	case gatewayconfig.GatewayTCPStates:
		cp := v
		return &cp
	default:
		buf, err := json.Marshal(raw)
		if err != nil {
			return nil
		}
		var out gatewayconfig.GatewayTCPStates
		if err := json.Unmarshal(buf, &out); err != nil {
			return nil
		}
		return &out
	}
}

func extractApplicationsFromMetrics(m map[string]interface{}) []gatewayconfig.GatewayRuntimeApplication {
	if m == nil {
		return nil
	}
	raw, ok := m[MetricApplications]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []gatewayconfig.GatewayRuntimeApplication:
		return v
	default:
		buf, err := json.Marshal(raw)
		if err != nil {
			return nil
		}
		var out []gatewayconfig.GatewayRuntimeApplication
		if err := json.Unmarshal(buf, &out); err != nil {
			return nil
		}
		return out
	}
}

func sanitizeFloat(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

func cloneFloatPtr(p *float64) *float64 {
	if p == nil || math.IsNaN(*p) || math.IsInf(*p, 0) {
		return nil
	}
	v := *p
	return &v
}

func cloneUint64Ptr(p *uint64) *uint64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneIntPtr(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
