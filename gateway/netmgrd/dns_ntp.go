// DNS/NTP 落地：network.json 可选字段 dns_servers / ntp_servers 的主机侧执行。
//
// 落地路径选择（按序探测，取第一条可用路径）：
//   - DNS：systemctl 可用且 systemd-resolved 活跃 → resolvectl（默认路由接口）；
//     否则 /etc/resolv.conf 可写、非 systemd stub 符号链接且非容器运行时挂载点
//     → 原子重写（每行 nameserver X）；都不行 → UNSUPPORTED；
//   - NTP：systemd-timesyncd 活跃 → 写 /etc/systemd/timesyncd.conf.d/99-jiuzhang.conf
//     并 restart；否则 chronyd 可用 → 写 /etc/chrony/conf.d/99-jiuzhang.conf
//     （server X iburst 每行）并 restart；都不行 → UNSUPPORTED。
//
// UNSUPPORTED 属预期情形（容器环境无 systemctl、resolv.conf 由运行时托管），
// 不计入整体失败；FAILED（存在落地路径但执行出错）计入整体失败，按周期重试自愈。
//
// 可测性：全部主机交互经 sysTools 注入（生产为真实实现，单测替换桩）。
package netmgrd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// resolvConfPath 主机 DNS 配置路径。
	resolvConfPath = "/etc/resolv.conf"
	// timesyncdConfDir systemd-timesyncd drop-in 目录。
	timesyncdConfDir = "/etc/systemd/timesyncd.conf.d"
	// chronyConfDir chrony drop-in 目录（发行版通用包含路径）。
	chronyConfDir = "/etc/chrony/conf.d"
	// procMountsPath 挂载表路径（判定容器运行时托管文件）。
	procMountsPath = "/proc/self/mounts"
)

// sysTools 主机交互抽象：DNS/NTP 落地所需的全部外部能力。
type sysTools struct {
	// lookPath 探测可执行文件是否存在（PATH 解析）。
	lookPath func(name string) bool
	// run 执行命令并返回 stdout（参数数组，不经 shell；含超时）。
	run func(ctx context.Context, name string, args ...string) (string, error)
	// writable 判定路径是否可写（以写方式打开探测，不产生变更）。
	writable func(path string) bool
	// resolveLink 解析符号链接最终目标（非符号链接返回自身）。
	resolveLink func(path string) (string, error)
	// mountPoint 判定路径是否为独立挂载点（容器运行时托管文件不可原子替换）。
	mountPoint func(path string) bool
	// mkdirAll 创建目录（含父目录，幂等）。
	mkdirAll func(path string, perm os.FileMode) error
	// writeAtomic 原子写文件（同目录临时文件 + rename）。
	writeAtomic func(path string, data []byte, perm os.FileMode) error
}

// hostTools 生产主机交互实现（包级变量，单测可整体替换；包内测试不并行）。
var hostTools = defaultSysTools()

func defaultSysTools() sysTools {
	return sysTools{
		lookPath: func(name string) bool {
			_, err := exec.LookPath(name)
			return err == nil
		},
		run: func(ctx context.Context, name string, args ...string) (string, error) {
			cctx, cancel := context.WithTimeout(ctx, DefaultCmdTimeout)
			defer cancel()
			cmd := exec.CommandContext(cctx, name, args...)
			out, err := cmd.Output()
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					return string(out), fmt.Errorf("%s: %w: %s", name, err,
						strings.TrimSpace(string(ee.Stderr)))
				}
				return string(out), fmt.Errorf("%s: %w", name, err)
			}
			return string(out), nil
		},
		writable: func(path string) bool {
			f, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				return false
			}
			f.Close()
			return true
		},
		resolveLink: filepath.EvalSymlinks,
		mountPoint:  isMountPoint,
		mkdirAll:    os.MkdirAll,
		writeAtomic: writeFileAtomic,
	}
}

// isMountPoint 判定路径是否在挂载表中独占一行（如 Docker 托管的
// /etc/resolv.conf——rename 原子替换对独立挂载点会失败，直接走 UNSUPPORTED）。
func isMountPoint(path string) bool {
	data, err := os.ReadFile(procMountsPath)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == path {
			return true
		}
	}
	return false
}

// writeFileAtomic 原子写文件：同目录临时文件 + rename（与 WriteStatusAtomic 同一约定）。
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".jiuzhang-*.tmp")
	if err != nil {
		return fmt.Errorf("创建临时文件（目录 %s 需可写）: %w", dir, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("写临时文件: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("设置文件权限: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("关闭临时文件: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("原子替换 %s: %w", path, err)
	}
	return nil
}

func appliedStatus(format string, args ...any) *ServiceStatus {
	return &ServiceStatus{State: StateApplied, Message: fmt.Sprintf(format, args...)}
}

func unsupportedStatus(format string, args ...any) *ServiceStatus {
	return &ServiceStatus{State: StateUnsupported, Message: fmt.Sprintf(format, args...)}
}

func failedStatus(format string, args ...any) *ServiceStatus {
	return &ServiceStatus{State: StateFailed, Message: fmt.Sprintf(format, args...)}
}

// systemctlActive 判定 systemd 单元是否活跃（无 systemctl 或单元不存在均为否）。
func systemctlActive(ctx context.Context, t sysTools, unit string) bool {
	if !t.lookPath("systemctl") {
		return false
	}
	out, err := t.run(ctx, "systemctl", "is-active", unit)
	return err == nil && strings.TrimSpace(out) == "active"
}

// defaultRouteIface 取默认路由出口接口（resolvectl 按接口下发 DNS 需要）。
func defaultRouteIface(ctx context.Context, t sysTools) (string, error) {
	out, err := t.run(ctx, "ip", "-j", "route", "show", "default")
	if err != nil {
		return "", fmt.Errorf("查询默认路由: %w", err)
	}
	var routes []struct {
		Dev string `json:"dev"`
	}
	if err := json.Unmarshal([]byte(out), &routes); err != nil {
		return "", fmt.Errorf("解析默认路由输出: %w", err)
	}
	for _, r := range routes {
		if r.Dev != "" {
			return r.Dev, nil
		}
	}
	return "", fmt.Errorf("主机无默认路由，无法确定 resolvectl 下发接口")
}

// applyDNS 落地期望 DNS 服务器。路径选择见文件头注释。
func applyDNS(ctx context.Context, servers []string, t sysTools) *ServiceStatus {
	// 路径一：systemd-resolved 活跃 → resolvectl（按默认路由接口下发）
	if systemctlActive(ctx, t, "systemd-resolved") {
		if !t.lookPath("resolvectl") {
			return failedStatus("systemd-resolved 活跃但 resolvectl 不存在（需 systemd 套件）")
		}
		dev, err := defaultRouteIface(ctx, t)
		if err != nil {
			return failedStatus("%v", err)
		}
		args := append([]string{"dns", dev}, servers...)
		if _, err := t.run(ctx, "resolvectl", args...); err != nil {
			return failedStatus("resolvectl 下发失败: %v", err)
		}
		return appliedStatus("resolvectl dns %s %s", dev, strings.Join(servers, " "))
	}

	// 路径二：直接管理 /etc/resolv.conf（先排除 systemd stub 符号链接与
	// 容器运行时托管挂载——两者都不具备安全原子重写条件）
	if link, err := t.resolveLink(resolvConfPath); err == nil &&
		strings.Contains(link, "systemd") {
		return unsupportedStatus("%s 是指向 systemd stub 的符号链接（%s）且 systemd-resolved 未活跃，拒绝改写",
			resolvConfPath, link)
	}
	if t.mountPoint(resolvConfPath) {
		return unsupportedStatus("%s 为容器运行时托管挂载，不可原子替换；无 systemd-resolved 可用", resolvConfPath)
	}
	if !t.writable(resolvConfPath) {
		return unsupportedStatus("无 systemd-resolved 且 %s 不可写", resolvConfPath)
	}
	var b strings.Builder
	b.WriteString("# managed by jiuzhang netmgrd（dns_servers 下发，原子重写）\n")
	for _, s := range servers {
		b.WriteString("nameserver " + s + "\n")
	}
	if err := t.writeAtomic(resolvConfPath, []byte(b.String()), 0o644); err != nil {
		return failedStatus("重写 %s 失败: %v", resolvConfPath, err)
	}
	return appliedStatus("已重写 %s（nameserver × %d）", resolvConfPath, len(servers))
}

// applyNTP 落地期望 NTP 服务器。路径选择见文件头注释。
func applyNTP(ctx context.Context, servers []string, t sysTools) *ServiceStatus {
	// 路径一：systemd-timesyncd 活跃 → drop-in 配置 + restart
	if systemctlActive(ctx, t, "systemd-timesyncd") {
		if err := t.mkdirAll(timesyncdConfDir, 0o755); err != nil {
			return failedStatus("创建 %s 失败: %v", timesyncdConfDir, err)
		}
		conf := "[Time]\nNTP=" + strings.Join(servers, " ") + "\n"
		path := filepath.Join(timesyncdConfDir, "99-jiuzhang.conf")
		if err := t.writeAtomic(path, []byte(conf), 0o644); err != nil {
			return failedStatus("写 %s 失败: %v", path, err)
		}
		if _, err := t.run(ctx, "systemctl", "restart", "systemd-timesyncd"); err != nil {
			return failedStatus("配置已写入 %s，但 restart systemd-timesyncd 失败: %v", path, err)
		}
		return appliedStatus("systemd-timesyncd drop-in %s（NTP=%s）", path, strings.Join(servers, " "))
	}

	// 路径二：chronyd 可用 → drop-in 配置 + restart
	if t.lookPath("chronyd") {
		if err := t.mkdirAll(chronyConfDir, 0o755); err != nil {
			return failedStatus("创建 %s 失败: %v", chronyConfDir, err)
		}
		var b strings.Builder
		b.WriteString("# managed by jiuzhang netmgrd（ntp_servers 下发）\n")
		for _, s := range servers {
			b.WriteString("server " + s + " iburst\n")
		}
		path := filepath.Join(chronyConfDir, "99-jiuzhang.conf")
		if err := t.writeAtomic(path, []byte(b.String()), 0o644); err != nil {
			return failedStatus("写 %s 失败: %v", path, err)
		}
		if t.lookPath("systemctl") {
			// 服务名发行版差异：RHEL 系 chronyd，Debian 系 chrony
			if _, err := t.run(ctx, "systemctl", "restart", "chronyd"); err != nil {
				if _, err2 := t.run(ctx, "systemctl", "restart", "chrony"); err2 != nil {
					return failedStatus("配置已写入 %s，但 restart chronyd/chrony 均失败: %v / %v", path, err, err2)
				}
			}
			return appliedStatus("chrony drop-in %s（server × %d）并已重启", path, len(servers))
		}
		return appliedStatus("chrony drop-in %s（server × %d）已写入；无 systemctl，需运维手动重载 chronyd",
			path, len(servers))
	}

	return unsupportedStatus("主机无 systemd-timesyncd / chronyd，无可用 NTP 落地路径")
}
