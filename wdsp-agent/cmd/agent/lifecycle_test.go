package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/service"
)

type fakeServiceManager struct {
	privErr     error
	installed   bool
	running     bool
	lastCfg     service.Config
	installs    int
	uninstalls  int
	starts      int
	stops       int
	restarts    int
}

func (f *fakeServiceManager) ServiceName() string    { return "wdsp-agent-test" }
func (f *fakeServiceManager) UnitPath() string       { return "/tmp/wdsp-agent-test.unit" }
func (f *fakeServiceManager) CheckPrivileges() error { return f.privErr }
func (f *fakeServiceManager) Install(cfg service.Config) error {
	if f.privErr != nil {
		return f.privErr
	}
	f.installed = true
	f.lastCfg = cfg
	f.installs++
	return nil
}
func (f *fakeServiceManager) Uninstall() error {
	if f.privErr != nil {
		return f.privErr
	}
	f.installed = false
	f.running = false
	f.uninstalls++
	return nil
}
func (f *fakeServiceManager) Start() error {
	f.running = true
	f.starts++
	return nil
}
func (f *fakeServiceManager) Stop() error {
	f.running = false
	f.stops++
	return nil
}
func (f *fakeServiceManager) Restart() error {
	f.running = true
	f.restarts++
	return nil
}
func (f *fakeServiceManager) Status() (service.StatusInfo, error) {
	st := service.StateNotInstalled
	if f.installed {
		st = service.StateStopped
		if f.running {
			st = service.StateRunning
		}
	}
	return service.StatusInfo{ServiceName: f.ServiceName(), State: st, UnitPath: f.UnitPath()}, nil
}

func withFakeService(t *testing.T, fake *fakeServiceManager) {
	t.Helper()
	origMgr := newServiceManager
	origExe := resolveExecutable
	newServiceManager = func() service.Manager { return fake }
	resolveExecutable = func() (string, error) { return "/usr/local/bin/wdsp-agent", nil }
	t.Cleanup(func() {
		newServiceManager = origMgr
		resolveExecutable = origExe
	})
}

func TestCmdInstallPermissionCheckBeforeEnroll(t *testing.T) {
	var enrollHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enrollHits.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"agent_id":"a1","credential":"wda_1","heartbeat_interval_seconds":15}`))
	}))
	defer srv.Close()

	fake := &fakeServiceManager{privErr: errors.New("root required")}
	withFakeService(t, fake)

	dir := t.TempDir()
	err := cmdInstall([]string{
		"--server", srv.URL, "--token", "wdt_secret",
		"--config", filepath.Join(dir, "agent.json"),
		"--state-dir", filepath.Join(dir, "state"),
	})
	if err == nil {
		t.Fatal("权限不足时 install 必须失败")
	}
	if enrollHits.Load() != 0 {
		t.Fatalf("权限不足时不得消耗一次性 Token，实际调用 enroll=%d 次", enrollHits.Load())
	}
}

func TestCmdInstallReuseForceReenrollAndUninstallPurge(t *testing.T) {
	certPEM := testCertPEM(t)
	var enrollHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := enrollHits.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agent_id":                   "agent-" + string(rune('0'+n)),
			"credential":                 "wda_cred",
			"heartbeat_interval_seconds": 15,
			"agent_cert_pem":             certPEM,
			"ca_cert_pem":                certPEM,
			"cert_expires_at":            "2027-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	fake := &fakeServiceManager{}
	withFakeService(t, fake)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg", "agent.json")
	stateDir := filepath.Join(dir, "state")
	logDir := filepath.Join(dir, "logs")

	// 1. 首次安装：注册 + 写 backend + 安装并启动服务
	t.Setenv("WDSP_ENROLL_TOKEN", "wdt_first")
	if err := cmdInstall([]string{
		"--server", srv.URL,
		"--config", cfgPath,
		"--state-dir", stateDir,
		"--log-dir", logDir,
		"--backend", "bpf",
	}); err != nil {
		t.Fatalf("首次 install 失败: %v", err)
	}
	if enrollHits.Load() != 1 || fake.installs != 1 || fake.starts != 1 || !fake.running {
		t.Fatalf("首次 install 状态异常: hits=%d fake=%+v", enrollHits.Load(), fake)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg.CaptureBackend != "bpf" || cfg.AgentID != "agent-1" {
		t.Fatalf("配置未保存正确: cfg=%+v err=%v", cfg, err)
	}

	// 2. 已有配置 + 又传了令牌但未指定 --force-reenroll：必须拒绝防止误覆盖
	if err := cmdInstall([]string{
		"--server", srv.URL, "--token", "wdt_second",
		"--config", cfgPath, "--state-dir", stateDir, "--log-dir", logDir,
	}); err == nil || !strings.Contains(err.Error(), "--force-reenroll") {
		t.Fatalf("已有配置传入新令牌应拒绝: %v", err)
	}

	// 3. 已有配置 + 不传令牌：复用身份、更新 backend 并重装服务
	t.Setenv("WDSP_ENROLL_TOKEN", "")
	if err := cmdInstall([]string{
		"--config", cfgPath, "--state-dir", stateDir, "--log-dir", logDir,
		"--backend", "auto", "--no-start",
	}); err != nil {
		t.Fatalf("复用身份重装失败: %v", err)
	}
	if enrollHits.Load() != 1 || fake.installs != 2 || fake.starts != 1 {
		t.Fatalf("复用身份不应重复 enroll 或启动: hits=%d fake=%+v", enrollHits.Load(), fake)
	}
	cfg, _ = config.Load(cfgPath)
	if cfg.CaptureBackend != "auto" {
		t.Fatalf("复用重装后 backend 应更新为 auto，got %q", cfg.CaptureBackend)
	}

	// 4. --force-reenroll：强制重新注册
	if err := cmdInstall([]string{
		"--server", srv.URL, "--token", "wdt_force", "--force-reenroll",
		"--config", cfgPath, "--state-dir", stateDir, "--log-dir", logDir,
	}); err != nil {
		t.Fatalf("force-reenroll 失败: %v", err)
	}
	if enrollHits.Load() != 2 {
		t.Fatalf("force-reenroll 应触发第 2 次 enroll，got %d", enrollHits.Load())
	}

	// 5. status 与 service 子命令
	if err := cmdStatus([]string{"--config", cfgPath, "--state-dir", stateDir, "--json"}); err != nil {
		t.Fatalf("cmdStatus 失败: %v", err)
	}
	for _, action := range []string{"stop", "start", "restart", "status"} {
		if err := cmdService([]string{action}); err != nil {
			t.Fatalf("cmdService %s 失败: %v", action, err)
		}
	}

	// 6. uninstall 默认保留配置与证书
	if err := cmdUninstall([]string{"--config", cfgPath, "--state-dir", stateDir, "--log-dir", logDir}); err != nil {
		t.Fatalf("uninstall 失败: %v", err)
	}
	if fake.installed || fake.running {
		t.Fatalf("uninstall 后服务应已移除: %+v", fake)
	}
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("非 --purge 应保留配置: %v", err)
	}

	// 7. uninstall --purge 彻底清理
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := cmdUninstall([]string{"--config", cfgPath, "--state-dir", stateDir, "--log-dir", logDir, "--purge"}); err != nil {
		t.Fatalf("uninstall --purge 失败: %v", err)
	}
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Fatal("--purge 应删除配置文件")
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatal("--purge 应删除状态目录")
	}
	if _, err := os.Stat(logDir); !os.IsNotExist(err) {
		t.Fatal("--purge 应删除日志目录")
	}
}
