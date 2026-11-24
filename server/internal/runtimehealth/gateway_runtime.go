package runtimehealth

import "github.com/jiuzhang-waf/server/internal/gatewayconfig"

func applyGatewayRuntimeMetrics(snapshot *Snapshot, runtime *gatewayconfig.GatewayRuntimeSnapshot) {
	if runtime == nil || snapshot == nil {
		return
	}
	if snapshot.Metrics == nil {
		snapshot.Metrics = map[string]interface{}{}
	}
	if runtime.Resources.CPUPercent != nil {
		snapshot.Metrics[MetricCPUUsagePercent] = *runtime.Resources.CPUPercent
	}
	if runtime.Resources.MemoryPercent != nil {
		snapshot.Metrics[MetricMemoryUsagePercent] = *runtime.Resources.MemoryPercent
	}
	if runtime.Resources.MemoryUsedBytes != nil {
		snapshot.Metrics[MetricMemoryUsedBytes] = *runtime.Resources.MemoryUsedBytes
	}
	if runtime.Resources.MemoryTotalBytes != nil {
		snapshot.Metrics[MetricMemoryTotalBytes] = *runtime.Resources.MemoryTotalBytes
	}
	if runtime.Resources.Load1 != nil {
		snapshot.Metrics[MetricLoad1] = *runtime.Resources.Load1
	}
	if runtime.Resources.Load5 != nil {
		snapshot.Metrics[MetricLoad5] = *runtime.Resources.Load5
	}
	if runtime.Resources.Load15 != nil {
		snapshot.Metrics[MetricLoad15] = *runtime.Resources.Load15
	}
	if runtime.Resources.FDOpen != nil {
		snapshot.Metrics[MetricFDOpen] = *runtime.Resources.FDOpen
	}
	if runtime.Resources.FDMax != nil {
		snapshot.Metrics[MetricFDMax] = *runtime.Resources.FDMax
	}
	if runtime.Resources.FDUsagePercent != nil {
		snapshot.Metrics[MetricFDUsagePercent] = *runtime.Resources.FDUsagePercent
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
	snapshot.Metrics[MetricBytesInTotal] = runtime.Connections.BytesInTotal
	snapshot.Metrics[MetricBytesOutTotal] = runtime.Connections.BytesOutTotal
	snapshot.Metrics[MetricBytesInPerSecond] = runtime.Connections.BytesInPerSecond
	snapshot.Metrics[MetricBytesOutPerSecond] = runtime.Connections.BytesOutPerSecond
	if runtime.Connections.TCPStates != nil {
		snapshot.Metrics[MetricTCPStates] = *runtime.Connections.TCPStates
	}
	snapshot.Metrics[MetricHTTPRequestsInFlight] = runtime.HTTP.RequestsInFlight
	snapshot.Metrics[MetricHTTPRequestsTotal] = runtime.HTTP.RequestsTotal
	snapshot.Metrics[MetricHTTPRequestsPerSecond] = runtime.HTTP.RequestsPerSecond
	snapshot.Metrics[MetricHTTPSessionsActive] = runtime.HTTP.SessionsActive
	snapshot.Metrics[MetricHTTPSessionsNewTotal] = runtime.HTTP.SessionsNewTotal
	snapshot.Metrics[MetricHTTPSessionsNewPerSecond] = runtime.HTTP.SessionsNewPerSecond
	snapshot.Metrics[MetricHTTPSessionsOverflowTotal] = runtime.HTTP.SessionsOverflowTotal
	snapshot.Metrics[MetricStatus2xxTotal] = runtime.HTTP.Status2xxTotal
	snapshot.Metrics[MetricStatus3xxTotal] = runtime.HTTP.Status3xxTotal
	snapshot.Metrics[MetricStatus4xxTotal] = runtime.HTTP.Status4xxTotal
	snapshot.Metrics[MetricStatus5xxTotal] = runtime.HTTP.Status5xxTotal
	snapshot.Metrics[MetricStatus2xxPerSecond] = runtime.HTTP.Status2xxPerSecond
	snapshot.Metrics[MetricStatus3xxPerSecond] = runtime.HTTP.Status3xxPerSecond
	snapshot.Metrics[MetricStatus4xxPerSecond] = runtime.HTTP.Status4xxPerSecond
	snapshot.Metrics[MetricStatus5xxPerSecond] = runtime.HTTP.Status5xxPerSecond
	if len(runtime.Applications) > 0 {
		snapshot.Metrics[MetricApplications] = runtime.Applications
	}
	snapshot.Metrics[MetricSoftwareBypassEnabled] = runtime.SoftwareBypass.Enabled
	snapshot.Metrics[MetricSoftwareBypassActive] = runtime.SoftwareBypass.Active
	snapshot.Metrics[MetricSoftwareBypassReason] = runtime.SoftwareBypass.Reason
	snapshot.Metrics[MetricSoftwareBypassCPUThreshold] = runtime.SoftwareBypass.CPUThresholdPercent
	snapshot.Metrics[MetricSoftwareBypassMemoryThreshold] = runtime.SoftwareBypass.MemoryThresholdPercent
	snapshot.Metrics[MetricSoftwareBypassTransitions] = runtime.SoftwareBypass.TransitionsTotal
	snapshot.Metrics[MetricSoftwareBypassRequests] = runtime.SoftwareBypass.BypassedRequestsTotal
}
