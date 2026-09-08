// network.go 网络查看与变更：查看走只读命令；变更统一经 sudo 调 root helper（netapply.sh），
// 参数已在 shell 层过白名单校验，此处只做参数化 exec（无 shell 拼接）。
package sysconsole

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// NetHelperPath root helper 路径（可用 JZ_CONSOLE_NETHELPER 覆盖，便于测试）。
func NetHelperPath() string {
	if p := os.Getenv("JZ_CONSOLE_NETHELPER"); p != "" {
		return p
	}
	return "/opt/jiuzhang/console/netapply.sh"
}

// Runner 外部命令执行器（可注入假实现用于单测）。
type Runner func(name string, args ...string) (string, error)

// defaultRunner 参数化执行（无 shell），截断过长输出。
func defaultRunner(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if len(s) > 4096 {
		s = s[:4096] + "\n…（输出截断）"
	}
	return s, err
}

// ShowNetwork 当前网口 / 地址 / 路由 / DNS。
func ShowNetwork(run Runner) string {
	var b strings.Builder
	if out, err := run("ip", "-brief", "address"); err == nil {
		b.WriteString("== 网口与地址 ==\n" + out + "\n\n")
	}
	if out, err := run("ip", "route", "show"); err == nil {
		b.WriteString("== 路由表 ==\n" + out + "\n\n")
	}
	if raw, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		var ns []string
		for line := range strings.Lines(string(raw)) {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == "nameserver" {
				ns = append(ns, f[1])
			}
		}
		b.WriteString("== DNS ==\n" + strings.Join(ns, "\n"))
	}
	s := strings.TrimSpace(b.String())
	if s == "" {
		return "不可用（当前系统不支持 ip 命令；仅 Linux 交付环境支持网络查看）"
	}
	return s
}

// NetApply 调用 root helper 执行网络变更，返回 helper 输出。
func NetApply(run Runner, args ...string) (string, error) {
	helper := NetHelperPath()
	out, err := run("sudo", append([]string{"-n", helper}, args...)...)
	if err != nil {
		return out, fmt.Errorf("网络变更失败：%v%s", err, wrapOutput(out))
	}
	return out, nil
}

// Ping 连通性诊断（固定 4 包）。
func Ping(run Runner, host string) (string, error) {
	out, err := run("ping", "-c", "4", host)
	if err != nil {
		return out, fmt.Errorf("ping 失败：%v%s", err, wrapOutput(out))
	}
	return out, nil
}

func wrapOutput(out string) string {
	if out == "" {
		return ""
	}
	return "：\n" + out
}
