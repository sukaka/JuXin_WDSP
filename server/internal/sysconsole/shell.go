// shell.go 受限命令 REPL：白名单解析 + 分发。输入绝不交给系统 shell 执行。
package sysconsole

import (
	"errors"
	"fmt"
	"strings"
)

// Prompter 交互输入抽象（passwd 用；真实终端不回显，测试可注入）。
type Prompter interface {
	PromptPassword(prompt string) (string, error)
}

// Shell 受限控制台。
type Shell struct {
	Cfg     *Config
	CfgPath string
	Audit   *AuditLogger
	Run     Runner   // 外部命令执行器（nil 用 defaultRunner）
	Prompt  Prompter // passwd 交互（nil 则 passwd 不可用并报提示）
}

var (
	// ErrQuit 用户请求退出。
	ErrQuit = errors.New("quit")
	// errUsage 用法错误（输出帮助而不算执行失败）。
	errUsage = errors.New("usage")
)

const helpText = `可用命令：
  help                                    显示本帮助
  show sysinfo                            查看 CPU / 内存 / 磁盘信息
  show network                            查看网口、地址、路由、DNS
  set mgmt-ip <网口> <IP/前缀> [网关]      设置管理地址（例：set mgmt-ip eth0 192.168.1.10/24 192.168.1.1）
  set route add <目的/前缀> via <网关> [dev <网口>]   添加静态路由
  set route del <目的/前缀>                删除静态路由
  set dns <IP1> [IP2]                     设置 DNS 服务器
  ping <主机>                             连通性诊断（4 包）
  passwd                                  重置控制台密码
  exit / logout                           退出控制台`

// Execute 解析并执行一行命令；返回输出文本。ErrQuit 表示退出；errUsage 表示用法错误。
func (s *Shell) Execute(user, line string) (string, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", nil
	}
	out, err := s.dispatch(fields)
	if s.Audit != nil {
		s.Audit.Log(user, "command", line, err == nil || errors.Is(err, ErrQuit))
	}
	return out, err
}

func (s *Shell) dispatch(f []string) (string, error) {
	run := s.Run
	if run == nil {
		run = defaultRunner
	}
	switch f[0] {
	case "help", "?":
		return helpText, nil
	case "exit", "logout", "quit":
		return "", ErrQuit
	case "show":
		if len(f) != 2 {
			return "", fmt.Errorf("%w: show sysinfo | show network", errUsage)
		}
		switch f[1] {
		case "sysinfo":
			return SysInfo(), nil
		case "network":
			return ShowNetwork(run), nil
		default:
			return "", fmt.Errorf("%w: 未知 show 子命令 %q", errUsage, f[1])
		}
	case "set":
		return s.setCmd(run, f[1:])
	case "ping":
		if len(f) != 2 || !ValidHost(f[1]) {
			return "", fmt.Errorf("%w: ping <主机>（IP 或合法主机名）", errUsage)
		}
		return Ping(run, f[1])
	case "passwd":
		return s.passwd()
	default:
		return "", fmt.Errorf("%w: 未知命令 %q，输入 help 查看可用命令", errUsage, f[0])
	}
}

// setCmd 网络变更子命令（全部经 root helper 落地）。
func (s *Shell) setCmd(run Runner, f []string) (string, error) {
	if len(f) == 0 {
		return "", fmt.Errorf("%w: set mgmt-ip | set route | set dns", errUsage)
	}
	switch f[0] {
	case "mgmt-ip":
		// set mgmt-ip <if> <ip/prefix> [gateway]
		if len(f) < 3 || len(f) > 4 || !ValidIfName(f[1]) {
			return "", fmt.Errorf("%w: set mgmt-ip <网口> <IP/前缀> [网关]", errUsage)
		}
		if _, err := ParsePrefix(f[2]); err != nil {
			return "", fmt.Errorf("无效的 IP/前缀 %q：%v", f[2], err)
		}
		args := []string{"mgmt-ip", f[1], f[2]}
		if len(f) == 4 {
			if _, err := ParseAddr(f[3]); err != nil {
				return "", fmt.Errorf("无效的网关地址 %q", f[3])
			}
			args = append(args, f[3])
		}
		out, err := NetApply(run, args...)
		return "管理地址已更新。" + wrapOutput(out), err
	case "route":
		return s.setRoute(run, f[1:])
	case "dns":
		// set dns <ip1> [ip2]
		if len(f) < 2 || len(f) > 3 {
			return "", fmt.Errorf("%w: set dns <IP1> [IP2]", errUsage)
		}
		for _, ip := range f[1:] {
			if _, err := ParseAddr(ip); err != nil {
				return "", fmt.Errorf("无效的 DNS 地址 %q", ip)
			}
		}
		out, err := NetApply(run, append([]string{"dns"}, f[1:]...)...)
		return "DNS 已更新。" + wrapOutput(out), err
	default:
		return "", fmt.Errorf("%w: 未知 set 子命令 %q", errUsage, f[0])
	}
}

// setRoute 静态路由增删。
func (s *Shell) setRoute(run Runner, f []string) (string, error) {
	if len(f) == 0 {
		return "", fmt.Errorf("%w: set route add|del ...", errUsage)
	}
	switch f[0] {
	case "add":
		// add <dest/prefix> via <gw> [dev <if>]
		if len(f) < 4 || f[2] != "via" {
			return "", fmt.Errorf("%w: set route add <目的/前缀> via <网关> [dev <网口>]", errUsage)
		}
		if _, err := ParsePrefix(f[1]); err != nil {
			return "", fmt.Errorf("无效的目的网段 %q：%v", f[1], err)
		}
		if _, err := ParseAddr(f[3]); err != nil {
			return "", fmt.Errorf("无效的网关地址 %q", f[3])
		}
		args := []string{"route-add", f[1], f[3]}
		if len(f) == 6 && f[4] == "dev" && ValidIfName(f[5]) {
			args = append(args, f[5])
		} else if len(f) != 4 {
			return "", fmt.Errorf("%w: set route add <目的/前缀> via <网关> [dev <网口>]", errUsage)
		}
		out, err := NetApply(run, args...)
		return "路由已添加。" + wrapOutput(out), err
	case "del":
		if len(f) != 2 {
			return "", fmt.Errorf("%w: set route del <目的/前缀>", errUsage)
		}
		if _, err := ParsePrefix(f[1]); err != nil {
			return "", fmt.Errorf("无效的目的网段 %q：%v", f[1], err)
		}
		out, err := NetApply(run, "route-del", f[1])
		return "路由已删除。" + wrapOutput(out), err
	default:
		return "", fmt.Errorf("%w: set route add|del ...", errUsage)
	}
}

// passwd 交互式重置控制台密码。
func (s *Shell) passwd() (string, error) {
	if s.Prompt == nil {
		return "", errors.New("当前环境不支持交互式改密（需 TTY）")
	}
	p1, err := s.Prompt.PromptPassword("新密码（至少 8 位）: ")
	if err != nil {
		return "", err
	}
	if len(p1) < 8 {
		return "", errors.New("密码至少 8 位")
	}
	p2, err := s.Prompt.PromptPassword("再次输入新密码: ")
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", errors.New("两次输入不一致")
	}
	hash, err := HashPassword(p1)
	if err != nil {
		return "", err
	}
	s.Cfg.PasswordHash = hash
	if err := SaveConfig(s.CfgPath, s.Cfg); err != nil {
		return "", fmt.Errorf("写回配置失败：%v", err)
	}
	return "密码已重置。", nil
}
