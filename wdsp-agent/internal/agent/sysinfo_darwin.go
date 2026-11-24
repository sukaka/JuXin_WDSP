//go:build darwin

// 主机信息采集（macOS）：SystemVersion.plist + sysctl（零 CGO）。
package agent

import (
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// OSRelease 返回 macOS 版本描述（如 "macOS 15.2 (24C101)"）。
func OSRelease() string {
	if data, err := os.ReadFile("/System/Library/CoreServices/SystemVersion.plist"); err == nil {
		if v := parseDarwinSystemVersionPlist(data); v != "" {
			return v
		}
	}
	if ver, err := unix.Sysctl("kern.osproductversion"); err == nil && strings.TrimSpace(ver) != "" {
		return "macOS " + strings.TrimSpace(ver)
	}
	return "macOS"
}

// Kernel 返回 Darwin 内核版本（sysctl kern.osrelease）。
func Kernel() string {
	if rel, err := unix.Sysctl("kern.osrelease"); err == nil && strings.TrimSpace(rel) != "" {
		return strings.TrimSpace(rel)
	}
	return "unknown"
}

// Arch GOARCH。
func Arch() string { return runtime.GOARCH }
