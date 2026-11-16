package runtimehealth

import (
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func TestApplyGatewayRuntimeMetrics(t *testing.T) {
	cpu, memory := 81.5, 82.5
	runtime := &gatewayconfig.GatewayRuntimeSnapshot{}
	runtime.Resources.CPUPercent = &cpu
	runtime.Resources.MemoryPercent = &memory
	runtime.Connections.Active = 12
	runtime.Connections.AcceptedTotal = 1200
	runtime.Connections.AcceptedPerSecond = 34.5
	runtime.HTTP.SessionsActive = 8
	runtime.HTTP.SessionsNewTotal = 100
	runtime.SoftwareBypass.Enabled = true
	runtime.SoftwareBypass.Active = true
	runtime.SoftwareBypass.Reason = "CPU_THRESHOLD"
	snapshot := &Snapshot{Metrics: map[string]interface{}{}}
	applyGatewayRuntimeMetrics(snapshot, runtime)
	if snapshot.Metrics[MetricCPUUsagePercent] != cpu || snapshot.Metrics[MetricMemoryUsagePercent] != memory {
		t.Fatalf("resource metrics = %+v", snapshot.Metrics)
	}
	if snapshot.Metrics[MetricTCPConnectionsActive] != int64(12) || snapshot.Metrics[MetricTCPConnectionsAcceptedPerSecond] != 34.5 {
		t.Fatalf("connection metrics = %+v", snapshot.Metrics)
	}
	if snapshot.Metrics[MetricHTTPSessionsActive] != 8 || snapshot.Metrics[MetricSoftwareBypassActive] != true {
		t.Fatalf("HTTP/bypass metrics = %+v", snapshot.Metrics)
	}
}
