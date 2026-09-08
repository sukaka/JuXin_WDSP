// main.go jiuzhang-console —— 九章设备运维控制台（受限后台）。
// 作为 jiuzhang-ops 用户的登录 shell 运行：先账号口令认证，再进入白名单命令 REPL。
// 用法：
//
//	jiuzhang-console [-config /etc/jiuzhang/console.yaml] [-audit-log /var/log/jiuzhang-console.log]
//	jiuzhang-console -hash-password   从 stdin 读一行口令，输出 bcrypt 哈希（安装脚本用）
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/jiuzhang-waf/server/internal/sysconsole"
)

const maxLoginAttempts = 5

// ttyPrompter 终端不回显密码输入；非 TTY（管道/测试）降级为行读取。
type ttyPrompter struct {
	in *bufio.Reader
}

func (p ttyPrompter) PromptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if terminal.IsTerminal(fd) {
		raw, err := terminal.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(raw), err
	}
	line, err := p.in.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// readLine 读一行输入（账号、命令）。
func readLine(in *bufio.Reader) (string, error) {
	line, err := in.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

func main() {
	configPath := flag.String("config", "/etc/jiuzhang/console.yaml", "控制台配置文件路径")
	auditPath := flag.String("audit-log", "/var/log/jiuzhang-console.log", "审计日志路径")
	hashPassword := flag.Bool("hash-password", false, "从 stdin 读一行口令并输出 bcrypt 哈希（安装用）")
	flag.Parse()

	// 安装辅助：生成口令哈希（口令经管道传入，不出现在命令行参数/进程列表）
	if *hashPassword {
		in := bufio.NewReader(os.Stdin)
		pw, _ := in.ReadString('\n')
		pw = strings.TrimRight(pw, "\r\n")
		if len(pw) < 8 {
			fmt.Fprintln(os.Stderr, "口令至少 8 位")
			os.Exit(2)
		}
		hash, err := sysconsole.HashPassword(pw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "哈希失败:", err)
			os.Exit(1)
		}
		fmt.Println(hash)
		return
	}

	cfg, err := sysconsole.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法加载控制台配置：%v\n请先以 root 运行 ops/console/install-console.sh 完成初始化。\n", err)
		os.Exit(1)
	}
	audit := sysconsole.NewAuditLogger("jiuzhang-console", *auditPath)
	in := bufio.NewReader(os.Stdin)
	prompter := ttyPrompter{in: in}

	// 认证（账号 + 密码，失败 5 次退出）
	authed := false
	for attempt := 1; attempt <= maxLoginAttempts; attempt++ {
		fmt.Fprint(os.Stderr, "账号: ")
		user, err := readLine(in)
		if err != nil {
			os.Exit(1)
		}
		pw, err := prompter.PromptPassword("密码: ")
		if err != nil {
			os.Exit(1)
		}
		if user == cfg.Username && sysconsole.CheckPassword(cfg.PasswordHash, pw) {
			audit.Log(user, "login", "认证成功", true)
			authed = true
			break
		}
		audit.Log(user, "login", fmt.Sprintf("认证失败（第 %d 次）", attempt), false)
		fmt.Fprintf(os.Stderr, "账号或密码错误（%d/%d）\n", attempt, maxLoginAttempts)
	}
	if !authed {
		os.Exit(1)
	}

	fmt.Println("九章运维控制台（输入 help 查看可用命令，exit 退出）")
	shell := &sysconsole.Shell{Cfg: cfg, CfgPath: *configPath, Audit: audit, Prompt: prompter}
	for {
		fmt.Fprint(os.Stderr, "jiuzhang> ")
		line, err := readLine(in)
		if err != nil { // EOF / Ctrl-D
			fmt.Fprintln(os.Stderr)
			return
		}
		out, err := shell.Execute(cfg.Username, line)
		if errors.Is(err, sysconsole.ErrQuit) {
			return
		}
		if out != "" {
			fmt.Println(out)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "错误:", err)
		}
	}
}
