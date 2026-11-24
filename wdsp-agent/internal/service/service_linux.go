//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

type linuxManager struct {
	unitPath string
}

// NewManager 返回 Linux systemd 服务管理器。
func NewManager() Manager {
	return &linuxManager{unitPath: LinuxUnitPath}
}

func (m *linuxManager) ServiceName() string { return LinuxServiceName }
func (m *linuxManager) UnitPath() string    { return m.unitPath }

func (m *linuxManager) CheckPrivileges() error {
	if os.Geteuid() != 0 {
		return errors.New("需要 root 权限（请使用 sudo 执行）")
	}
	return nil
}

func linuxKernelRelease() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	var b []byte
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func (m *linuxManager) Install(cfg Config) error {
	if err := m.CheckPrivileges(); err != nil {
		return err
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("未找到 systemctl（当前环境可能非 systemd 容器）；二进制已完成注册，可直接前台运行 wdsp-agent run")
	}
	unit := RenderSystemdUnit(cfg, SupportsCapBPF(linuxKernelRelease()))
	if err := os.MkdirAll(filepath.Dir(m.unitPath), 0o755); err != nil {
		return fmt.Errorf("创建 systemd 目录失败: %w", err)
	}
	tmp := m.unitPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("写入 systemd unit 失败: %w", err)
	}
	if err := os.Rename(tmp, m.unitPath); err != nil {
		return fmt.Errorf("替换 systemd unit 失败: %w", err)
	}
	if err := runCmd("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload 失败: %w", err)
	}
	if err := runCmd("systemctl", "enable", LinuxServiceName); err != nil {
		return fmt.Errorf("systemctl enable 失败: %w", err)
	}
	return nil
}

func (m *linuxManager) Uninstall() error {
	if err := m.CheckPrivileges(); err != nil {
		return err
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		_ = runCmd("systemctl", "stop", LinuxServiceName)
		_ = runCmd("systemctl", "disable", LinuxServiceName)
	}
	if err := os.Remove(m.unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("删除 unit 文件失败: %w", err)
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		_ = runCmd("systemctl", "daemon-reload")
	}
	return nil
}

func (m *linuxManager) Start() error {
	if err := m.CheckPrivileges(); err != nil {
		return err
	}
	return runCmd("systemctl", "start", LinuxServiceName)
}

func (m *linuxManager) Stop() error {
	if err := m.CheckPrivileges(); err != nil {
		return err
	}
	return runCmd("systemctl", "stop", LinuxServiceName)
}

func (m *linuxManager) Restart() error {
	if err := m.CheckPrivileges(); err != nil {
		return err
	}
	return runCmd("systemctl", "restart", LinuxServiceName)
}

func (m *linuxManager) Status() (StatusInfo, error) {
	info := StatusInfo{ServiceName: LinuxServiceName, UnitPath: m.unitPath}
	if _, err := os.Stat(m.unitPath); errors.Is(err, os.ErrNotExist) {
		info.State = StateNotInstalled
		info.Detail = "未安装 systemd 服务"
		return info, nil
	}
	out, err := exec.Command("systemctl", "is-active", LinuxServiceName).CombinedOutput()
	stateStr := strings.TrimSpace(string(out))
	info.Detail = stateStr
	if err == nil && stateStr == "active" {
		info.State = StateRunning
		return info, nil
	}
	if stateStr == "inactive" || stateStr == "failed" || stateStr == "deactivating" {
		info.State = StateStopped
		return info, nil
	}
	info.State = StateUnknown
	return info, nil
}

func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, msg)
		}
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

// IsRunningAsService Linux 下由 systemd 直接运行信号循环，无需额外 SCM 包装。
func IsRunningAsService() bool { return false }

// RunIfService Linux 下不拦截主流程。
func RunIfService(_ func(ctx context.Context) error) (bool, error) { return false, nil }
