package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jiuzhang-waf/wdsp-agent/internal/agent"
	"github.com/jiuzhang-waf/wdsp-agent/internal/cert"
	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/fsperm"
	"github.com/jiuzhang-waf/wdsp-agent/internal/service"
)

// newServiceManager 供单测注入 fake 服务管理器。
var newServiceManager = service.NewManager

// resolveExecutable 供单测注入当前可执行文件路径。
var resolveExecutable = func() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if realPath, err := filepath.EvalSymlinks(exe); err == nil {
		return realPath, nil
	}
	return filepath.Abs(exe)
}

func validateBackendFlag(v string) error {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "auto", "ebpf", "afpacket", "bpf", "npcap", "rawsocket":
		return nil
	default:
		return fmt.Errorf("不支持的 --backend 取值 %q（合法值: auto/ebpf/afpacket/bpf/npcap/rawsocket）", v)
	}
}

func absPath(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", nil
	}
	return filepath.Abs(p)
}

// cmdInstall 注册 Agent 并安装/启动平台原生系统服务（跨平台契约 §2.1）。
func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	server := fs.String("server", "", "WDSP 地址（https://host[:port]）")
	token := fs.String("token", "", "一次性 Enrollment Token（建议使用 --token-file 或 WDSP_ENROLL_TOKEN）")
	tokenFile := fs.String("token-file", "", "包含一次性 Enrollment Token 的文件路径")
	insecure := fs.Bool("insecure-skip-verify", false, "跳过服务端证书校验（仅自签实验环境）")
	cfgPath := fs.String("config", config.DefaultConfigPath, "agent.json 路径")
	stateDir := fs.String("state-dir", config.DefaultStateDir, "状态目录（agent.key/agent.crt/ca.crt/buffer）")
	logDir := fs.String("log-dir", config.DefaultLogDir, "日志目录")
	backend := fs.String("backend", "", "本地抓包后端（auto/ebpf/afpacket/bpf/npcap/rawsocket）")
	forceReenroll := fs.Bool("force-reenroll", false, "已存在 agent.json 时强制使用新令牌重新注册")
	noStart := fs.Bool("no-start", false, "仅注册并写入服务配置，不立即启动服务")
	skipService := fs.Bool("skip-service", false, "仅完成注册与目录准备，跳过系统服务注册（适用于无 systemd 容器）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	backendVal := strings.ToLower(strings.TrimSpace(*backend))
	if err := validateBackendFlag(backendVal); err != nil {
		return err
	}

	absCfg, err := absPath(*cfgPath)
	if err != nil {
		return fmt.Errorf("解析 --config 路径失败: %w", err)
	}
	absState, err := absPath(*stateDir)
	if err != nil {
		return fmt.Errorf("解析 --state-dir 路径失败: %w", err)
	}
	absLog, err := absPath(*logDir)
	if err != nil {
		return fmt.Errorf("解析 --log-dir 路径失败: %w", err)
	}

	mgr := newServiceManager()
	// 先校验管理员/root 权限，避免权限不足却已消耗一次性 Enrollment Token
	if !*skipService {
		if err := mgr.CheckPrivileges(); err != nil {
			return fmt.Errorf("安装系统服务权限不足: %w", err)
		}
	}

	if err := fsperm.MkdirPrivate(filepath.Dir(absCfg)); err != nil {
		return err
	}
	if err := fsperm.MkdirPrivate(absState); err != nil {
		return err
	}

	enrollToken, err := resolveEnrollToken(*token, *tokenFile, os.Getenv("WDSP_ENROLL_TOKEN"))
	if err != nil {
		return err
	}

	existingCfg, loadErr := config.Load(absCfg)
	hasExisting := loadErr == nil && existingCfg.AgentID != "" && existingCfg.Credential != ""

	switch {
	case hasExisting && !*forceReenroll:
		if enrollToken != "" {
			return fmt.Errorf("检测到已存在有效配置 %s（agent_id=%s）；为防止误覆盖身份已中止。如需覆盖请附加 --force-reenroll，如需保留既有身份仅重装服务请勿传入注册令牌",
				absCfg, existingCfg.AgentID)
		}
		changed := false
		if backendVal != "" && existingCfg.CaptureBackend != backendVal {
			existingCfg.CaptureBackend = backendVal
			changed = true
		}
		if changed {
			if err := existingCfg.Save(absCfg); err != nil {
				return err
			}
		}
		fmt.Printf("复用既有 Agent 身份: agent_id=%s config=%s\n", existingCfg.AgentID, absCfg)
	default:
		if _, err := doEnroll(enrollOptions{
			Server:             strings.TrimSpace(*server),
			Token:              enrollToken,
			InsecureSkipVerify: *insecure,
			ConfigPath:         absCfg,
			StateDir:           absState,
			CaptureBackend:     backendVal,
		}); err != nil {
			return err
		}
	}

	if *skipService {
		fmt.Println("已跳过系统服务注册（--skip-service），可执行 wdsp-agent run 启动采集")
		return nil
	}

	exePath, err := resolveExecutable()
	if err != nil {
		return fmt.Errorf("定位当前二进制路径失败: %w", err)
	}
	svcCfg := service.Config{
		BinaryPath: exePath,
		ConfigPath: absCfg,
		StateDir:   absState,
		LogDir:     absLog,
	}
	if err := mgr.Install(svcCfg); err != nil {
		return err
	}
	fmt.Printf("系统服务已安装: %s (%s)\n", mgr.ServiceName(), mgr.UnitPath())

	if *noStart {
		fmt.Println("已按 --no-start 跳过服务启动")
		return nil
	}
	if err := mgr.Start(); err != nil {
		return fmt.Errorf("启动服务失败: %w", err)
	}
	st, _ := mgr.Status()
	fmt.Printf("服务已启动: %s state=%s\n", st.ServiceName, st.State)
	return nil
}

// isProtectedRoot 防止 --purge 误删系统根目录。
func isProtectedRoot(p string) bool {
	cleaned := filepath.Clean(p)
	if cleaned == "/" || cleaned == "." || cleaned == string(filepath.Separator) {
		return true
	}
	// Windows 盘符根（如 C:\）
	if len(cleaned) <= 3 && strings.HasSuffix(cleaned, `:\`) {
		return true
	}
	lower := strings.ToLower(cleaned)
	for _, sysDir := range []string{
		"/etc", "/var", "/var/lib", "/var/log", "/usr", "/usr/local", "/usr/local/bin",
		"/library", "/library/application support", "/library/logs",
		`c:\programdata`, `c:\program files`, `c:\windows`,
	} {
		if lower == sysDir {
			return true
		}
	}
	return false
}

// cmdUninstall 停止并卸载系统服务；--purge 时清理配置、状态与日志目录。
func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath, "agent.json 路径")
	stateDir := fs.String("state-dir", config.DefaultStateDir, "状态目录")
	logDir := fs.String("log-dir", config.DefaultLogDir, "日志目录")
	purge := fs.Bool("purge", false, "同时删除配置文件、私钥/证书、磁盘缓存与日志目录")
	skipService := fs.Bool("skip-service", false, "跳过系统服务卸载")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mgr := newServiceManager()
	if !*skipService {
		if err := mgr.CheckPrivileges(); err != nil {
			return fmt.Errorf("卸载系统服务权限不足: %w", err)
		}
		if err := mgr.Uninstall(); err != nil {
			return err
		}
		fmt.Printf("系统服务已卸载: %s\n", mgr.ServiceName())
	}

	if !*purge {
		fmt.Printf("已保留本地配置与状态（如需彻底清理请附加 --purge）: config=%s state=%s\n", *cfgPath, *stateDir)
		return nil
	}

	if err := os.Remove(*cfgPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("删除配置文件失败: %w", err)
	}
	cfgDir := filepath.Dir(*cfgPath)
	if !isProtectedRoot(cfgDir) {
		_ = os.Remove(cfgDir) // 仅在目录为空时移除
	}
	for _, dir := range []string{*stateDir, *logDir} {
		if strings.TrimSpace(dir) == "" || isProtectedRoot(dir) {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("清理目录 %s 失败: %w", dir, err)
		}
	}
	fmt.Println("已清理全部配置、证书与本地缓存")
	return nil
}

type statusReport struct {
	Version        string             `json:"version"`
	OS             string             `json:"os"`
	Kernel         string             `json:"kernel"`
	Arch           string             `json:"arch"`
	ConfigPath     string             `json:"config_path"`
	StateDir       string             `json:"state_dir"`
	Enrolled       bool               `json:"enrolled"`
	AgentID        string             `json:"agent_id,omitempty"`
	Server         string             `json:"server,omitempty"`
	AuthMode       string             `json:"auth_mode,omitempty"`
	CertExpiresAt  string             `json:"cert_expires_at,omitempty"`
	CaptureBackend string             `json:"capture_backend,omitempty"`
	Service        service.StatusInfo `json:"service"`
}

// cmdStatus 输出服务状态与本地身份摘要。
func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultConfigPath, "agent.json 路径")
	stateDir := fs.String("state-dir", config.DefaultStateDir, "状态目录")
	asJSON := fs.Bool("json", false, "以 JSON 格式输出")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mgr := newServiceManager()
	svcStatus, _ := mgr.Status()
	rep := statusReport{
		Version:    version,
		OS:         agent.OSRelease(),
		Kernel:     agent.Kernel(),
		Arch:       agent.Arch(),
		ConfigPath: *cfgPath,
		StateDir:   *stateDir,
		Service:    svcStatus,
	}

	if cfg, err := config.Load(*cfgPath); err == nil && cfg.AgentID != "" {
		rep.Enrolled = true
		rep.AgentID = cfg.AgentID
		rep.Server = cfg.Server
		rep.CaptureBackend = cfg.CaptureBackend
		if rep.CaptureBackend == "" {
			rep.CaptureBackend = "auto"
		}
		rep.AuthMode = "Bearer"
		if id, err := cert.LoadIdentity(
			filepath.Join(*stateDir, cert.KeyFileName),
			filepath.Join(*stateDir, cert.CertFileName),
		); err == nil && id != nil {
			rep.AuthMode = "PoP"
			rep.CertExpiresAt = id.Cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z")
		} else if cfg.CertExpiresAt != "" {
			rep.CertExpiresAt = cfg.CertExpiresAt
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}

	fmt.Printf("WDSP Agent %s (%s / %s / %s)\n", rep.Version, rep.OS, rep.Kernel, rep.Arch)
	fmt.Printf("  服务状态: %s (%s)\n", rep.Service.ServiceName, rep.Service.State)
	if rep.Service.Detail != "" {
		fmt.Printf("  服务详情: %s\n", rep.Service.Detail)
	}
	fmt.Printf("  配置路径: %s\n", rep.ConfigPath)
	fmt.Printf("  状态目录: %s\n", rep.StateDir)
	if rep.Enrolled {
		fmt.Printf("  Agent ID: %s\n", rep.AgentID)
		fmt.Printf("  管理面地址: %s\n", rep.Server)
		fmt.Printf("  认证模式: %s\n", rep.AuthMode)
		if rep.CertExpiresAt != "" {
			fmt.Printf("  证书到期: %s\n", rep.CertExpiresAt)
		}
		fmt.Printf("  本地后端: %s\n", rep.CaptureBackend)
	} else {
		fmt.Println("  注册状态: 未注册（请先执行 wdsp-agent install 或 enroll）")
	}
	return nil
}

// cmdService 服务启停控制子命令。
func cmdService(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("用法: wdsp-agent service <start|stop|restart|status>")
	}
	mgr := newServiceManager()
	switch args[0] {
	case "start":
		if err := mgr.Start(); err != nil {
			return err
		}
		fmt.Printf("服务已启动: %s\n", mgr.ServiceName())
		return nil
	case "stop":
		if err := mgr.Stop(); err != nil {
			return err
		}
		fmt.Printf("服务已停止: %s\n", mgr.ServiceName())
		return nil
	case "restart":
		if err := mgr.Restart(); err != nil {
			return err
		}
		fmt.Printf("服务已重启: %s\n", mgr.ServiceName())
		return nil
	case "status":
		st, err := mgr.Status()
		if err != nil {
			return err
		}
		fmt.Printf("%s: %s (%s)\n", st.ServiceName, st.State, st.Detail)
		return nil
	default:
		return fmt.Errorf("未知 service 动作 %q（支持 start/stop/restart/status）", args[0])
	}
}
