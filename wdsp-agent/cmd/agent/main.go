// wdsp-agent 九章 WDSP 分布式流量采集边缘 Agent（Phase 1-5）。
//
// 设计依据：docs/agents/WDSP_DISTRIBUTED_AGENT_DESIGN.md（§67 TASK-001~009）
// 冻结契约：docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md（§3 机器端点、§6 本地行为）
//
// 子命令：
//
//	wdsp-agent enroll --server <url> --token <wdt_...> [--insecure-skip-verify] [--config path]
//	wdsp-agent run [--config path]
//	wdsp-agent version
//
// 红线：纯旁路只读，不存在任何向网卡写报文的能力；Agent 任何故障不影响业务。
package main

import (
	"context"
	"flag"
	"fmt"
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
	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

// 版本信息（发布构建用 -ldflags "-X main.version=x.y.z" 注入）。
var version = "2.3.0"

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
	fmt.Fprintf(os.Stderr, `wdsp-agent — 九章 WDSP 分布式流量采集边缘 Agent（Phase 1-5）

用法:
  wdsp-agent enroll --server <url> (--token-file <path> | --token <wdt_...> | WDSP_ENROLL_TOKEN) [--insecure-skip-verify] [--config path] [--state-dir dir]
  wdsp-agent run [--config path] [--state-dir dir] [--debug]
  wdsp-agent version

说明:
  enroll  使用一次性 Enrollment Token 注册到 WDSP，成功后写入 agent.json（0600）；
          自动生成机器身份密钥并上送 CSR（契约 §7），服务端签发证书则保存
          agent.crt/ca.crt 进入 PoP 认证模式，否则按 Bearer 模式运行
  run     以 agent.json 中的凭据运行：心跳/配置/抓包/上报；
          持有证书时全部机器端点自动携带 PoP 签名头（契约 §8），存活期过半自动轮换（§9）
  version 打印版本
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

// cmdEnroll 注册（契约 §3.1）：成功后将 agent_id/credential/server 写入 agent.json。
// Phase 2-B（契约 §7/§12）：自动生成/复用机器身份密钥并随注册上送 CSR；
// 服务端签发证书则保存 agent.crt/ca.crt 并记录 cert_expires_at，否则 Bearer 模式。
func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	server := fs.String("server", "", "WDSP 地址（https://host[:port]，必填）")
	token := fs.String("token", "", "一次性 Enrollment Token（wdt_...；建议优先使用 --token-file 或 WDSP_ENROLL_TOKEN 避免命令行进程列表泄露）")
	tokenFile := fs.String("token-file", "", "包含一次性 Enrollment Token 的文件路径（优先于 WDSP_ENROLL_TOKEN）")
	insecure := fs.Bool("insecure-skip-verify", false, "跳过服务端证书校验（仅自签实验环境）")
	cfgPath := fs.String("config", config.DefaultConfigPath, "agent.json 路径")
	stateDir := fs.String("state-dir", config.DefaultStateDir, "状态目录（agent.key/agent.crt/ca.crt/buffer）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	enrollToken, err := resolveEnrollToken(*token, *tokenFile, os.Getenv("WDSP_ENROLL_TOKEN"))
	if err != nil {
		return err
	}
	if *server == "" || enrollToken == "" {
		return fmt.Errorf("enroll 需要 --server 与注册令牌（--token-file / WDSP_ENROLL_TOKEN / --token）")
	}

	// 机器身份密钥（契约 §12）：已存在且可用则复用；不可用仅降级告警，不阻断注册
	var csrPEM string
	keyPath := filepath.Join(*stateDir, cert.KeyFileName)
	key, err := cert.LoadOrGenerateKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "警告: 机器身份密钥不可用（%v），本次注册不带 CSR，退化为 Bearer 模式\n", err)
	} else if csr, err := cert.NewCSR(key); err != nil {
		fmt.Fprintf(os.Stderr, "警告: CSR 生成失败（%v），本次注册不带 CSR，退化为 Bearer 模式\n", err)
	} else {
		csrPEM = string(csr)
	}

	client, err := transport.New(*server, *insecure, version)
	if err != nil {
		return err
	}
	ifaces, err := netif.Discover()
	if err != nil {
		return fmt.Errorf("网卡发现失败: %w", err)
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
	hostname, _ := os.Hostname()

	resp, err := client.Enroll(context.Background(), transport.EnrollRequest{
		EnrollmentToken: enrollToken,
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
		return err
	}
	if resp.Capabilities != nil {
		fmt.Printf("能力协商生效: http_event_schema_versions=%v\n", resp.Capabilities.HTTPEventSchemaVersions)
	}

	cfg := config.Default()
	cfg.Server = *server
	cfg.AgentID = resp.AgentID
	cfg.Credential = resp.Credential
	cfg.InsecureSkipVerify = *insecure
	if resp.HeartbeatIntervalSeconds > 0 {
		cfg.HeartbeatIntervalSeconds = resp.HeartbeatIntervalSeconds
	}
	if resp.AgentCertPEM != "" {
		if err := persistCerts(*stateDir, resp.AgentCertPEM, resp.CACertPEM); err != nil {
			// 服务端对缺失 PoP 头的请求回退 Bearer 校验（契约 §8），故仅降级告警
			fmt.Fprintf(os.Stderr, "警告: 机器身份证书保存失败（%v），按 Bearer 模式运行\n", err)
		} else {
			cfg.CertExpiresAt = resp.CertExpiresAt
			fmt.Printf("机器身份证书已保存: %s（到期 %s）\n",
				filepath.Join(*stateDir, cert.CertFileName), resp.CertExpiresAt)
		}
	} else {
		fmt.Println("服务端未签发机器身份证书（旧版服务端或未上送 CSR），按 Bearer 模式运行")
	}
	if err := cfg.Save(*cfgPath); err != nil {
		return err
	}
	fmt.Printf("注册成功: agent_id=%s config=%s\n", resp.AgentID, *cfgPath)
	return nil
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

// cmdRun 运行 Agent（契约 §6）：加载 agent.json → 控制/数据通道 → 优雅退出。
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath, "agent.json 路径")
	stateDir := fs.String("state-dir", config.DefaultStateDir, "状态目录（agent.key/agent.crt/ca.crt/buffer）")
	debug := fs.Bool("debug", false, "DEBUG 日志级别（默认 INFO）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("加载配置失败（是否已执行 enroll？）: %w", err)
	}
	agent.Version = version
	a, err := agent.New(cfg, *cfgPath, *stateDir, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return a.Run(ctx)
}
