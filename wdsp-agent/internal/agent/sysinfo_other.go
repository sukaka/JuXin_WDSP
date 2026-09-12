//go:build !linux

// 主机信息采集（非 Linux 回退）。
package agent

import "runtime"

// OSRelease 非 Linux 回退为 GOOS。
func OSRelease() string { return runtime.GOOS }

// Kernel 非 Linux 无法读取内核版本。
func Kernel() string { return "unknown" }

// Arch GOARCH。
func Arch() string { return runtime.GOARCH }
