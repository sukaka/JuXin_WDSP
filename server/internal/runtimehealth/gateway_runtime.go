package runtimehealth

import "github.com/jiuzhang-waf/server/internal/gatewayconfig"

func applyGatewayRuntimeMetrics(snapshot *Snapshot, runtime *gatewayconfig.GatewayRuntimeSnapshot) {
	if runtime.Resources.CPUPercent != nil {
		snapshot.Metrics[MetricCPUUsagePercent] = *runtime.Resources.CPUPercent
	}
	if runtime.Resources.MemoryPercent != nil {
		snapshot.Metrics[MetricMemoryUsagePercent] = *runtime.Resources.MemoryPercent
	}
	if !runtime.Resources.SampledAt.IsZero() {
		snapshot.Metrics[MetricResourceSampledAt] = runtime.Resources.SampledAt
	}
	if runtime.Resources.Error != "" {
		snapshot.Metrics[MetricResourceSampleError] = runtime.Resources.Error
	}
	snapshot.Metrics[MetricTCPConnectionsActive] = runtime.Connections.Active
	snapshot.Metrics[MetricTCPConnectionsAcceptedTotal] = runtime.Connections.AcceptedTotal
	snapshot.Metrics[MetricTCPConnectionsAcceptedPerSecond] = runtime.Connections.AcceptedPerSecond
	snapshot.Metrics[MetricHTTPRequestsInFlight] = runtime.HTTP.RequestsInFlight
	snapshot.Metrics[MetricHTTPRequestsTotal] = runtime.HTTP.RequestsTotal
	snapshot.Metrics[MetricHTTPSessionsActive] = runtime.HTTP.SessionsActive
	snapshot.Metrics[MetricHTTPSessionsNewTotal] = runtime.HTTP.SessionsNewTotal
	snapshot.Metrics[MetricHTTPSessionsOverflowTotal] = runtime.HTTP.SessionsOverflowTotal
	snapshot.Metrics[MetricSoftwareBypassEnabled] = runtime.SoftwareBypass.Enabled
	snapshot.Metrics[MetricSoftwareBypassActive] = runtime.SoftwareBypass.Active
	snapshot.Metrics[MetricSoftwareBypassReason] = runtime.SoftwareBypass.Reason
	snapshot.Metrics[MetricSoftwareBypassCPUThreshold] = runtime.SoftwareBypass.CPUThresholdPercent
	snapshot.Metrics[MetricSoftwareBypassMemoryThreshold] = runtime.SoftwareBypass.MemoryThresholdPercent
	snapshot.Metrics[MetricSoftwareBypassTransitions] = runtime.SoftwareBypass.TransitionsTotal
	snapshot.Metrics[MetricSoftwareBypassRequests] = runtime.SoftwareBypass.BypassedRequestsTotal
}
