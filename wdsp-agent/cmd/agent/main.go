// wdsp-agent 九章 WDSP 分布式流量采集边缘 Agent（跨平台：Linux/macOS/Windows）。
//
// 设计依据：docs/agents/WDSP_DISTRIBUTED_AGENT_DESIGN.md
// 冻结契约：docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md、
//          docs/agents/WDSP_AGENT_CROSS_PLATFORM_INSTALL_CONTRACT.md
//
// 子命令：
//
//	wdsp-agent install --server <url> (--token-file <path> | --token <wdt_...> | WDSP_ENROLL_TOKEN) [flags]
//	wdsp-agent uninstall [--purge] [flags]
//	wdsp-agent status [--json] [flags]
//	wdsp-agent service <start|stop|restart|status>
//	wdsp-agent enroll --server <url> (--token-file <path> | --token <wdt_...> | WDSP_ENROLL_TOKEN) [flags]
//	wdsp-agent run [--config path] [--state-dir dir] [--log-file path] [--debug]
//	wdsp-agent version
//
// 红线：纯旁路只读，不存在任何向网卡写报文的能力；Agent 任何故障不影响业务。
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jiuzhang-waf/wdsp-agent/internal/agent"
	"github.com/jiuzhang-waf/wdsp-agent/internal/cert"
	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/netif"
	"github.com/jiuzhang-waf/wdsp-agent/internal/service"
	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

// 版本信息（发布构建用 -ldflags "-X main.version=x.y.z" 注入）。
var version = "2.4.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "wdsp-agent error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("缺少子命令")
	}
	switch args[0] {
	case "install":
		return cmdInstall(args[1:])
	case "uninstall":
		return cmdUninstall(args[1:])
	case "status":
		return cmdStatus(args[1:])
	case "service":
		return cmdService(args[1:])
	case "enroll":
		return cmdEnroll(args[1:])
	case "run":
		return cmdRun(args[1:])
	case "version":
		fmt.Printf("wdsp-agent %s\n", version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("未知子命令: %s", args[0])
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `wdsp-agent — 九章 WDSP 分布式流量采集边缘 Agent（Linux / macOS / Windows）

用法:
  wdsp-agent install --server <url> (--token-file <path> | --token <wdt_...> | WDSP_ENROLL_TOKEN) [--backend auto] [--insecure-skip-verify] [--force-reenroll] [--no-start] [--config path] [--state-dir dir]
  wdsp-agent uninstall [--purge] [--config path] [--state-dir dir]
  wdsp-agent status [--json] [--config path] [--state-dir dir]
  wdsp-agent service <start|stop|restart|status>
  wdsp-agent enroll --server <url> (--token-file <path> | --token <wdt_...> | WDSP_ENROLL_TOKEN) [--insecure-skip-verify] [--config path] [--state-dir dir]
  wdsp-agent run [--config path] [--state-dir dir] [--log-file path] [--debug]
  wdsp-agent version

说明:
  install    注册 Agent（生成机器身份证书）并安装/启动平台原生系统服务（systemd / launchd / Windows Service）
  uninstall  停止并注销系统服务（默认保留配置与证书，--purge 彻底清理）
  status     查看系统服务状态、身份配置与证书有效期
  service    直接启停或重启系统服务（start / stop / restart / status）
  enroll     仅执行一次性 Enrollment Token 注册并写入 agent.json（不注册系统服务）
  run        以 agent.json 凭据运行（Windows SCM 拉起时自动进入原生服务模式）
  version    打印版本
`)
}

// resolveEnrollToken 按优先级解析一次性注册令牌（--token-file > --token > WDSP_ENROLL_TOKEN）。
// 同时显式提供 --token 与 --token-file 时拒绝，避免歧义。
func resolveEnrollToken(flagToken, tokenFile, envToken string) (string, error) {
	flagToken = strings.TrimSpace(flagToken)
	tokenFile = strings.TrimSpace(tokenFile)
	envToken = strings.TrimSpace(envToken)
	if flagToken != "" && tokenFile != "" {
		return "", fmt.Errorf("--token 与 --token-file 不能同时指定")
	}
	if tokenFile != "" {
		data, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("读取 --token-file 失败: %w", err)
		}
		tok := strings.TrimSpace(string(data))
		if tok == "" {
			return "", fmt.Errorf("--token-file 内容为空")
		}
		return tok, nil
	}
	if flagToken != "" {
		return flagToken, nil
	}
	return envToken, nil
}

type enrollOptions struct {
	Server             string
	Token              string
	InsecureSkipVerify bool
	ConfigPath         string
	StateDir           string
	CaptureBackend     string
}

// doEnroll 注册（契约 §3.1 + Phase 2-B §7）：供 enroll 与 install 子命令共用。
func doEnroll(opts enrollOptions) (*config.Config, error) {
	if opts.Server == "" || opts.Token == "" {
		return nil, fmt.Errorf("enroll 需要 --server 与注册令牌（--token-file / WDSP_ENROLL_TOKEN / --token）")
	}

	// 机器身份密钥（契约 §12）：已存在且可用则复用；不可用仅降级告警，不阻断注册
	var csrPEM string
	keyPath := filepath.Join(opts.StateDir, cert.KeyFileName)
	key, err := cert.LoadOrGenerateKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "警告: 机器身份密钥不可用（%v），本次注册不带 CSR，退化为 Bearer 模式\n", err)
	} else if csr, err := cert.NewCSR(key); err != nil {
		fmt.Fprintf(os.Stderr, "警告: CSR 生成失败（%v），本次注册不带 CSR，退化为 Bearer 模式\n", err)
	} else {
		csrPEM = string(csr)
	}

	client, err := transport.New(opts.Server, opts.InsecureSkipVerify, version)
	if err != nil {
		return nil, err
	}
	ifaces, err := netif.Discover()
	if err != nil {
		return nil, fmt.Errorf("网卡发现失败: %w", err)
	}
	infos := make([]transport.InterfaceInfo, 0, len(ifaces))
	primaryIP := ""
	for _, i := range ifaces {
		infos = append(infos, transport.InterfaceInfo{
			Name: i.Name, MAC: i.MAC, IPv4: i.IPv4, IPv6: i.IPv6,
			MTU: i.MTU, SpeedMbps: i.SpeedMbps,
		})
		if primaryIP == "" && i.IPv4 != "" {
			primaryIP = i.IPv4
		}
	}
	if primaryIP == "" {
		primaryIP = "127.0.0.1"
	}
	hostname, _ := os.Hostname()
	if strings.TrimSpace(hostname) == "" {
		hostname = "unknown-host"
	}

	resp, err := client.Enroll(context.Background(), transport.EnrollRequest{
		EnrollmentToken: opts.Token,
		Hostname:        hostname,
		IP:              primaryIP,
		OS:              agent.OSRelease(),
		Kernel:          agent.Kernel(),
		Arch:            agent.Arch(),
		Version:         version,
		Interfaces:      infos,
		CSRPEM:          csrPEM,
		Capabilities:    transport.DeclaredCapabilities(), // v2 契约 §3：声明 http_event_schema_versions=[1,2]
	})
	if err != nil {
		return nil, err
	}
	if resp.Capabilities != nil {
		fmt.Printf("能力协商生效: http_event_schema_versions=%v\n", resp.Capabilities.HTTPEventSchemaVersions)
	}

	cfg := config.Default()
	cfg.Server = opts.Server
	cfg.AgentID = resp.AgentID
	cfg.Credential = resp.Credential
	cfg.InsecureSkipVerify = opts.InsecureSkipVerify
	if opts.CaptureBackend != "" {
		cfg.CaptureBackend = opts.CaptureBackend
	}
	if resp.HeartbeatIntervalSeconds > 0 {
		cfg.HeartbeatIntervalSeconds = resp.HeartbeatIntervalSeconds
	}
	if resp.AgentCertPEM != "" {
		if err := persistCerts(opts.StateDir, resp.AgentCertPEM, resp.CACertPEM); err != nil {
			// 服务端对缺失 PoP 头的请求回退 Bearer 校验（契约 §8），故仅降级告警
			fmt.Fprintf(os.Stderr, "警告: 机器身份证书保存失败（%v），按 Bearer 模式运行\n", err)
		} else {
			cfg.CertExpiresAt = resp.CertExpiresAt
			fmt.Printf("机器身份证书已保存: %s（到期 %s）\n",
				filepath.Join(opts.StateDir, cert.CertFileName), resp.CertExpiresAt)
		}
	} else {
		fmt.Println("服务端未签发机器身份证书（旧版服务端或未上送 CSR），按 Bearer 模式运行")
	}
	if err := cfg.Save(opts.ConfigPath); err != nil {
		return nil, err
	}
	fmt.Printf("注册成功: agent_id=%s config=%s\n", resp.AgentID, opts.ConfigPath)
	return cfg, nil
}

// cmdEnroll 注册（契约 §3.1）：成功后将 agent_id/credential/server 写入 agent.json。
func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	server := fs.String("server", "", "WDSP 地址（https://host[:port]，必填）")
	token := fs.String("token", "", "一次性 Enrollment Token（wdt_...；建议优先使用 --token-file 或 WDSP_ENROLL_TOKEN 避免命令行进程列表泄露）")
	tokenFile := fs.String("token-file", "", "包含一次性 Enrollment Token 的文件路径（优先于 WDSP_ENROLL_TOKEN）")
	insecure := fs.Bool("insecure-skip-verify", false, "跳过服务端证书校验（仅自签实验环境）")
	cfgPath := fs.String("config", config.DefaultConfigPath, "agent.json 路径")
	stateDir := fs.String("state-dir", config.DefaultStateDir, "状态目录（agent.key/agent.crt/ca.crt/buffer）")
	backend := fs.String("backend", "", "本地抓包后端覆盖（auto/ebpf/afpacket/bpf/npcap/rawsocket，默认 auto）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	enrollToken, err := resolveEnrollToken(*token, *tokenFile, os.Getenv("WDSP_ENROLL_TOKEN"))
	if err != nil {
		return err
	}
	_, err = doEnroll(enrollOptions{
		Server:             strings.TrimSpace(*server),
		Token:              enrollToken,
		InsecureSkipVerify: *insecure,
		ConfigPath:         *cfgPath,
		StateDir:           *stateDir,
		CaptureBackend:     strings.TrimSpace(*backend),
	})
	return err
}

// persistCerts 保存 enroll/rotate 下发的证书与 CA（0644，公钥材料）。
func persistCerts(stateDir, agentCertPEM, caCertPEM string) error {
	if err := cert.SaveCertificatePEM(filepath.Join(stateDir, cert.CertFileName), []byte(agentCertPEM)); err != nil {
		return err
	}
	if caCertPEM != "" {
		if err := cert.SaveCertificatePEM(filepath.Join(stateDir, cert.CAFileName), []byte(caCertPEM)); err != nil {
			return err
		}
	}
	return nil
}

// openLogWriter 构造日志输出；Windows 服务模式自动落盘到日志目录避免无控制台丢失日志。
func openLogWriter(logFile string) (io.Writer, func(), error) {
	path := strings.TrimSpace(logFile)
	if path == "" && service.IsRunningAsService() {
		path = filepath.Join(config.DefaultLogDir, "wdsp-agent.log")
	}
	if path == "" {
		return os.Stderr, func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return os.Stderr, func() {}, fmt.Errorf("创建日志目录失败: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return os.Stderr, func() {}, fmt.Errorf("打开日志文件失败: %w", err)
	}
	return f, func() { _ = f.Close() }, nil
}

// cmdRun 运行 Agent（契约 §6）：加载 agent.json → 控制/数据通道 → 优雅退出。
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath, "agent.json 路径")
	stateDir := fs.String("state-dir", config.DefaultStateDir, "状态目录（agent.key/agent.crt/ca.crt/buffer）")
	logFile := fs.String("log-file", "", "可选日志文件路径（Windows 服务模式默认写入日志目录）")
	debug := fs.Bool("debug", false, "DEBUG 日志级别（默认 INFO）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	writer, closeLog, logErr := openLogWriter(*logFile)
	if logErr != nil {
		fmt.Fprintf(os.Stderr, "警告: %v，回退输出至 stderr\n", logErr)
	}
	defer closeLog()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("加载配置失败（是否已执行 enroll / install？）: %w", err)
	}
	agent.Version = version
	a, err := agent.New(cfg, *cfgPath, *stateDir, log)
	if err != nil {
		return err
	}

	if handled, err := service.RunIfService(func(ctx context.Context) error {
		return a.Run(ctx)
	}); handled {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return a.Run(ctx)
}
