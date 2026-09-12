package runtimehealth

import (
	"strconv"
	"strings"
)

// defaultFDUsageHighPercent 文件句柄使用率降级阈值（%）。
const defaultFDUsageHighPercent = 80.0

// fdUsagePercent 计算句柄使用率（%）；上限为 0 时返回 0。
func fdUsagePercent(open, max uint64) float64 {
	if max == 0 {
		return 0
	}
	return float64(open) / float64(max) * 100
}

// fdStatus 句柄状态：使用率达阈 DEGRADED（与 diskStatus 同档语义）。
func fdStatus(usagePercent, highThreshold float64) string {
	if usagePercent >= highThreshold {
		return StatusDegraded
	}
	return StatusUp
}

// parseMaxOpenFiles 从 /proc/self/limits 文本解析 "Max open files" soft limit；
// unlimited、缺失或格式非法返回 0（由调用方回退 getrlimit）。
func parseMaxOpenFiles(data string) uint64 {
	for _, line := range strings.Split(data, "\n") {
		if !strings.HasPrefix(line, "Max open files") {
			continue
		}
		// 格式：Max open files  <soft>  <hard>  files
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return 0
		}
		if fields[3] == "unlimited" {
			return 0
		}
		v, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			return 0
		}
		return v
	}
	return 0
}
