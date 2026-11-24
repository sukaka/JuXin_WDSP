//go:build windows

// 主机信息采集（Windows）：RtlGetNtVersionNumbers + 注册表 CurrentVersion（零 CGO）。
package agent

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// OSRelease 返回 Windows 版本描述（如 "Windows Server 2022 21H2 (Build 20348)" 或 "Windows 11 Pro 24H2 (Build 26100)"）。
func OSRelease() string {
	major, minor, build := windows.RtlGetNtVersionNumbers()
	var productName, displayVersion, currentBuild string
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		productName, _, _ = k.GetStringValue("ProductName")
		displayVersion, _, _ = k.GetStringValue("DisplayVersion")
		if displayVersion == "" {
			displayVersion, _, _ = k.GetStringValue("ReleaseId")
		}
		currentBuild, _, _ = k.GetStringValue("CurrentBuildNumber")
	}
	return formatWindowsOSRelease(productName, displayVersion, currentBuild, major, minor, build)
}

// Kernel 返回 Windows NT 内核版本（major.minor.build）。
func Kernel() string {
	major, minor, build := windows.RtlGetNtVersionNumbers()
	if major == 0 {
		return "unknown"
	}
	return fmt.Sprintf("%d.%d.%d", major, minor, build)
}

// Arch GOARCH。
func Arch() string { return runtime.GOARCH }
