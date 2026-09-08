//go:build linux

// 主机信息采集（Linux）：发行版与内核版本，用于注册上报（契约 §3.1）。
package agent

import (
	"os"
	"runtime"
	"strings"
	"syscall"
)

// OSRelease 读取 /etc/os-release 的 PRETTY_NAME（失败回退 "Linux"）。
func OSRelease() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "Linux"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			v := strings.TrimPrefix(line, "PRETTY_NAME=")
			v = strings.Trim(v, `"`)
			if v != "" {
				return v
			}
		}
	}
	return "Linux"
}

// Kernel 内核版本（uname -r）。
func Kernel() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return "unknown"
	}
	var b []byte
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	if len(b) == 0 {
		return "unknown"
	}
	return string(b)
}

// Arch GOARCH（如 x86_64 风格的 amd64）。
func Arch() string { return runtime.GOARCH }
