//go:build darwin

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type darwinManager struct {
	plistPath string
}

// NewManager 返回 macOS launchd 服务管理器。
func NewManager() Manager {
	return &darwinManager{plistPath: DarwinPlistPath}
}

func (m *darwinManager) ServiceName() string { return DarwinServiceLabel }
func (m *darwinManager) UnitPath() string    { return m.plistPath }

func (m *darwinManager) CheckPrivileges() error {
	if os.Geteuid() != 0 {
		return errors.New("需要 root 权限（请使用 sudo 执行）")
	}
	return nil
}

func (m *darwinManager) Install(cfg Config) error {
	if err := m.CheckPrivileges(); err != nil {
		return err
	}
	if cfg.LogDir != "" {
		if err := os.MkdirAll(cfg.LogDir, 0o750); err != nil {
			return fmt.Errorf("创建日志目录失败: %w", err)
		}
	}
	plist, err := RenderLaunchdPlist(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.plistPath), 0o755); err != nil {
		return fmt.Errorf("创建 LaunchDaemons 目录失败: %w", err)
	}
	tmp := m.plistPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(plist), 0o644); err != nil {
		return fmt.Errorf("写入 plist 失败: %w", err)
	}
	if err := os.Rename(tmp, m.plistPath); err != nil {
		return fmt.Errorf("替换 plist 失败: %w", err)
	}
	_ = os.Chown(m.plistPath, 0, 0)
	_ = os.Chmod(m.plistPath, 0o644)
	return nil
}

func (m *darwinManager) Uninstall() error {
	if err := m.CheckPrivileges(); err != nil {
		return err
	}
	_ = m.Stop()
	if err := os.Remove(m.plistPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("删除 plist 失败: %w", err)
	}
	return nil
}

func (m *darwinManager) Start() error {
	if err := m.CheckPrivileges(); err != nil {
		return err
	}
	target := "system/" + DarwinServiceLabel
	// 若已 bootstrap 则直接 kickstart 重拉；否则 bootstrap 加载
	if err := exec.Command("launchctl", "print", target).Run(); err == nil {
		if err := runCmd("launchctl", "kickstart", "-k", target); err == nil {
			return nil
		}
	}
	if err := runCmd("launchctl", "bootstrap", "system", m.plistPath); err != nil {
		// 兼容旧版 macOS launchctl
		if err2 := runCmd("launchctl", "load", "-w", m.plistPath); err2 != nil {
			return err
		}
	}
	return nil
}

func (m *darwinManager) Stop() error {
	if err := m.CheckPrivileges(); err != nil {
		return err
	}
	target := "system/" + DarwinServiceLabel
	if err := runCmd("launchctl", "bootout", target); err != nil {
		// 若未加载或旧版 macOS，回退尝试 unload，忽略“未找到服务”状态
		if _, statErr := os.Stat(m.plistPath); statErr == nil {
			_ = runCmd("launchctl", "unload", "-w", m.plistPath)
		}
	}
	return nil
}

func (m *darwinManager) Restart() error {
	if err := m.CheckPrivileges(); err != nil {
		return err
	}
	target := "system/" + DarwinServiceLabel
	if err := exec.Command("launchctl", "print", target).Run(); err == nil {
		return runCmd("launchctl", "kickstart", "-k", target)
	}
	return m.Start()
}

func (m *darwinManager) Status() (StatusInfo, error) {
	info := StatusInfo{ServiceName: DarwinServiceLabel, UnitPath: m.plistPath}
	if _, err := os.Stat(m.plistPath); errors.Is(err, os.ErrNotExist) {
		info.State = StateNotInstalled
		info.Detail = "未安装 launchd LaunchDaemon"
		return info, nil
	}
	target := "system/" + DarwinServiceLabel
	out, err := exec.Command("launchctl", "print", target).CombinedOutput()
	text := string(out)
	if err != nil {
		info.State = StateStopped
		info.Detail = "未加载到 launchd"
		return info, nil
	}
	if strings.Contains(text, "state = running") {
		info.State = StateRunning
		info.Detail = "running"
		return info, nil
	}
	info.State = StateStopped
	info.Detail = "loaded (not running)"
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

// IsRunningAsService macOS LaunchDaemon 由 launchd 直接拉起，走标准信号循环。
func IsRunningAsService() bool { return false }

// RunIfService macOS 下不拦截主流程。
func RunIfService(_ func(ctx context.Context) error) (bool, error) { return false, nil }
