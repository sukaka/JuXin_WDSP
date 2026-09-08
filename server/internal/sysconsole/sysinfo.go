// sysinfo.go 只读系统信息：CPU / 内存 / 磁盘。Linux 读 /proc；macOS（开发机）走 sysctl 降级。
package sysconsole

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// SysInfo 组装系统信息文本（读取失败的分项标注「不可用」，不整体失败）。
func SysInfo() string {
	var b strings.Builder
	b.WriteString("== CPU ==\n" + cpuInfo() + "\n")
	b.WriteString("\n== 内存 ==\n" + memInfo() + "\n")
	b.WriteString("\n== 磁盘 ==\n" + diskInfo())
	return b.String()
}

// cpuInfo 型号 / 核数 / 负载。
func cpuInfo() string {
	model, cores, load := "", runtime.NumCPU(), ""
	if runtime.GOOS == "linux" {
		if raw, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			model = parseCPUModel(string(raw))
		}
		if raw, err := os.ReadFile("/proc/loadavg"); err == nil {
			load = strings.Join(strings.Fields(string(raw))[:3], " ")
		}
	} else {
		if raw, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output(); err == nil {
			model = string(raw)
		}
		if raw, err := exec.Command("sysctl", "-n", "vm.loadavg").Output(); err == nil {
			// 形如 "{ 1.23 1.45 1.67 }"
			load = strings.Trim(strings.TrimSpace(string(raw)), "{} ")
		}
	}
	model = strings.TrimSpace(model)
	if model == "" {
		model = "不可用"
	}
	if load == "" {
		load = "不可用"
	}
	return fmt.Sprintf("型号：%s\n逻辑核数：%d\n负载（1/5/15 分钟）：%s", model, cores, load)
}

// parseCPUModel 取 /proc/cpuinfo 首个 model name（便于单测）。
func parseCPUModel(cpuinfo string) string {
	for line := range strings.Lines(cpuinfo) {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "model name" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// memInfo 总量 / 已用 / 可用。
func memInfo() string {
	if runtime.GOOS == "linux" {
		raw, err := os.ReadFile("/proc/meminfo")
		if err != nil {
			return "不可用（读取 /proc/meminfo 失败）"
		}
		total, avail := parseMemInfo(string(raw))
		if total == 0 {
			return "不可用（/proc/meminfo 解析失败）"
		}
		used := total - avail
		return fmt.Sprintf("总量：%s\n已用：%s（%.1f%%）\n可用：%s",
			humanBytes(total), humanBytes(used), float64(used)/float64(total)*100, humanBytes(avail))
	}
	raw, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err != nil {
		return "不可用"
	}
	total, _ := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	return fmt.Sprintf("总量：%s\n（macOS 降级模式：已用/可用需 Linux 环境）", humanBytes(total))
}

// parseMemInfo 解析 /proc/meminfo 的 MemTotal/MemAvailable（字节；便于单测）。
func parseMemInfo(meminfo string) (total, avail uint64) {
	get := func(key string) uint64 {
		for line := range strings.Lines(meminfo) {
			k, v, ok := strings.Cut(line, ":")
			if !ok || strings.TrimSpace(k) != key {
				continue
			}
			f := strings.Fields(v)
			if len(f) == 0 {
				return 0
			}
			kb, _ := strconv.ParseUint(f[0], 10, 64)
			return kb * 1024
		}
		return 0
	}
	return get("MemTotal"), get("MemAvailable")
}

// diskInfo 各物理挂载点用量（Linux 读 /proc/mounts 的 /dev 项；其他系统仅根分区）。
func diskInfo() string {
	type mnt struct{ dev, dir string }
	var mounts []mnt
	if runtime.GOOS == "linux" {
		if raw, err := os.ReadFile("/proc/mounts"); err == nil {
			for line := range strings.Lines(string(raw)) {
				f := strings.Fields(line)
				if len(f) >= 2 && strings.HasPrefix(f[0], "/dev/") {
					mounts = append(mounts, mnt{f[0], f[1]})
				}
			}
		}
	}
	if len(mounts) == 0 {
		mounts = []mnt{{"/", "/"}}
	}
	var b strings.Builder
	seen := map[string]bool{}
	for _, m := range mounts {
		if seen[m.dir] {
			continue
		}
		seen[m.dir] = true
		var st syscall.Statfs_t
		if err := syscall.Statfs(m.dir, &st); err != nil {
			fmt.Fprintf(&b, "%s (%s)：不可用\n", m.dir, m.dev)
			continue
		}
		total := st.Blocks * uint64(st.Bsize)
		avail := st.Bavail * uint64(st.Bsize)
		used := total - avail
		pct := float64(0)
		if total > 0 {
			pct = float64(used) / float64(total) * 100
		}
		fmt.Fprintf(&b, "%s (%s)：总 %s，已用 %s（%.1f%%），可用 %s\n",
			m.dir, m.dev, humanBytes(total), humanBytes(used), pct, humanBytes(avail))
	}
	return strings.TrimRight(b.String(), "\n")
}

// humanBytes 人性化字节数。
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for x := n / unit; x >= unit && exp < 4; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
