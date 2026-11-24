package runtimehealth

import (
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func TestApplyGatewayRuntimeMetrics(t *testing.T) {
	cpu, memory := 81.5, 82.5
	memUsed, memTotal := uint64(4<<30), uint64(8<<30)
	load1, load5, load15 := 1.5, 1.2, 0.9
	fdOpen := 256
	fdMax := uint64(65536)
	fdUsage := 0.39

	runtime := &gatewayconfig.GatewayRuntimeSnapshot{}
	runtime.Resources.CPUPercent = &cpu
	runtime.Resources.MemoryPercent = &memory
	runtime.Resources.MemoryUsedBytes = &memUsed
	runtime.Resources.MemoryTotalBytes = &memTotal
	runtime.Resources.Load1 = &load1
	runtime.Resources.Load5 = &load5
	runtime.Resources.Load15 = &load15
	runtime.Resources.FDOpen = &fdOpen
	runtime.Resources.FDMax = &fdMax
	runtime.Resources.FDUsagePercent = &fdUsage
	runtime.Connections.Active = 12
	runtime.Connections.AcceptedTotal = 1200
	runtime.Connections.AcceptedPerSecond = 34.5
	runtime.Connections.BytesInTotal = 10000
	runtime.Connections.BytesOutTotal = 20000
	runtime.Connections.BytesInPerSecond = 512.5
	runtime.Connections.BytesOutPerSecond = 1024.5
	runtime.Connections.TCPStates = &gatewayconfig.GatewayTCPStates{
		Established: 10,
		TimeWait:    2,
		Listen:      1,
	}
	runtime.HTTP.RequestsInFlight = 4
	runtime.HTTP.RequestsTotal = 999
	runtime.HTTP.RequestsPerSecond = 55.5
	runtime.HTTP.SessionsActive = 8
	runtime.HTTP.SessionsNewTotal = 100
	runtime.HTTP.SessionsNewPerSecond = 2.5
	runtime.HTTP.Status2xxTotal = 900
	runtime.HTTP.Status3xxTotal = 40
	runtime.HTTP.Status4xxTotal = 50
	runtime.HTTP.Status5xxTotal = 9
	runtime.HTTP.Status2xxPerSecond = 50.0
	runtime.HTTP.Status3xxPerSecond = 2.0
	runtime.HTTP.Status4xxPerSecond = 3.0
	runtime.HTTP.Status5xxPerSecond = 0.5
	runtime.Applications = []gatewayconfig.GatewayRuntimeApplication{
		{AppID: "app-1", RequestsPerSecond: 30.0, RequestsTotal: 600},
	}
	runtime.SoftwareBypass.Enabled = true
	runtime.SoftwareBypass.Active = true
	runtime.SoftwareBypass.Reason = "CPU_THRESHOLD"

	snapshot := &Snapshot{Metrics: map[string]interface{}{}}
	applyGatewayRuntimeMetrics(snapshot, runtime)

	if snapshot.Metrics[MetricCPUUsagePercent] != cpu || snapshot.Metrics[MetricMemoryUsagePercent] != memory {
		t.Fatalf("resource metrics = %+v", snapshot.Metrics)
	}
	if snapshot.Metrics[MetricMemoryUsedBytes] != memUsed || snapshot.Metrics[MetricMemoryTotalBytes] != memTotal {
		t.Fatalf("memory bytes = %+v", snapshot.Metrics)
	}
	if snapshot.Metrics[MetricLoad1] != load1 || snapshot.Metrics[MetricLoad5] != load5 || snapshot.Metrics[MetricLoad15] != load15 {
		t.Fatalf("load metrics = %+v", snapshot.Metrics)
	}
	if snapshot.Metrics[MetricFDOpen] != fdOpen || snapshot.Metrics[MetricFDMax] != fdMax || snapshot.Metrics[MetricFDUsagePercent] != fdUsage {
		t.Fatalf("fd metrics = %+v", snapshot.Metrics)
	}
	if snapshot.Metrics[MetricTCPConnectionsActive] != int64(12) || snapshot.Metrics[MetricTCPConnectionsAcceptedPerSecond] != 34.5 {
		t.Fatalf("connection metrics = %+v", snapshot.Metrics)
	}
	if snapshot.Metrics[MetricBytesInTotal] != uint64(10000) || snapshot.Metrics[MetricBytesOutTotal] != uint64(20000) ||
		snapshot.Metrics[MetricBytesInPerSecond] != 512.5 || snapshot.Metrics[MetricBytesOutPerSecond] != 1024.5 {
		t.Fatalf("bandwidth metrics = %+v", snapshot.Metrics)
	}
	tcpStates, ok := snapshot.Metrics[MetricTCPStates].(gatewayconfig.GatewayTCPStates)
	if !ok || tcpStates.Established != 10 || tcpStates.TimeWait != 2 || tcpStates.Listen != 1 {
		t.Fatalf("tcp_states = %#v", snapshot.Metrics[MetricTCPStates])
	}
	if snapshot.Metrics[MetricHTTPRequestsPerSecond] != 55.5 ||
		snapshot.Metrics[MetricHTTPSessionsNewPerSecond] != 2.5 ||
		snapshot.Metrics[MetricStatus2xxTotal] != uint64(900) ||
		snapshot.Metrics[MetricStatus3xxTotal] != uint64(40) ||
		snapshot.Metrics[MetricStatus4xxTotal] != uint64(50) ||
		snapshot.Metrics[MetricStatus5xxTotal] != uint64(9) ||
		snapshot.Metrics[MetricStatus2xxPerSecond] != 50.0 ||
		snapshot.Metrics[MetricStatus3xxPerSecond] != 2.0 ||
		snapshot.Metrics[MetricStatus4xxPerSecond] != 3.0 ||
		snapshot.Metrics[MetricStatus5xxPerSecond] != 0.5 {
		t.Fatalf("http extended metrics = %+v", snapshot.Metrics)
	}
	apps, ok := snapshot.Metrics[MetricApplications].([]gatewayconfig.GatewayRuntimeApplication)
	if !ok || len(apps) != 1 || apps[0].AppID != "app-1" {
		t.Fatalf("applications = %#v", snapshot.Metrics[MetricApplications])
	}
	if snapshot.Metrics[MetricHTTPSessionsActive] != 8 || snapshot.Metrics[MetricSoftwareBypassActive] != true {
		t.Fatalf("HTTP/bypass metrics = %+v", snapshot.Metrics)
	}
}

func TestApplyGatewayRuntimeMetricsOmitsUnavailableOptionalFields(t *testing.T) {
	runtime := &gatewayconfig.GatewayRuntimeSnapshot{}
	runtime.Connections.Active = 2
	snapshot := &Snapshot{Metrics: map[string]interface{}{}}
	applyGatewayRuntimeMetrics(snapshot, runtime)

	for _, key := range []string{
		MetricCPUUsagePercent, MetricMemoryUsagePercent, MetricMemoryUsedBytes, MetricMemoryTotalBytes,
		MetricLoad1, MetricLoad5, MetricLoad15, MetricFDOpen, MetricFDMax, MetricFDUsagePercent,
		MetricTCPStates, MetricApplications, MetricResourceSampleError, MetricResourceSampledAt,
	} {
		if _, exists := snapshot.Metrics[key]; exists {
			t.Errorf("expected optional key %q to be omitted when nil/empty", key)
		}
	}
}
