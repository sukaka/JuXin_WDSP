//go:build linux

// 文件句柄采集（Linux）：/proc/self/fd 计数与 /proc/self/limits 软上限。
package runtimehealth

import (
	"os"
	"syscall"
)

// fdUsage 返回当前进程已用句柄数与软上限；读取失败返回 ok=false（不判级）。
func fdUsage() (open, max uint64, ok bool) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, 0, false
	}
	max = fdSoftLimit()
	if max == 0 {
		return 0, 0, false
	}
	return uint64(len(entries)), max, true
}

// fdSoftLimit 读 /proc/self/limits 的 Max open files soft limit；
// unlimited 或读取失败回退 getrlimit(RLIMIT_NOFILE)。
func fdSoftLimit() uint64 {
	if data, err := os.ReadFile("/proc/self/limits"); err == nil {
		if v := parseMaxOpenFiles(string(data)); v > 0 {
			return v
		}
	}
	var r syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &r); err != nil {
		return 0
	}
	return r.Cur
}
