//go:build !linux && !darwin && !windows

// 主机信息采集（其他平台回退）。
package agent

import "runtime"

// OSRelease 其他平台回退为 GOOS。
func OSRelease() string { return runtime.GOOS }

// Kernel 其他平台无法读取内核版本。
func Kernel() string { return "unknown" }

// Arch GOARCH。
func Arch() string { return runtime.GOARCH }
