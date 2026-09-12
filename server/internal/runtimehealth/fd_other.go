//go:build !linux

// 文件句柄采集（非 Linux 回退）：无 /proc 实现，指标不可用。
package runtimehealth

// fdUsage 非 Linux 平台返回不可用（采集器跳过句柄指标，不判级）。
func fdUsage() (open, max uint64, ok bool) { return 0, 0, false }
