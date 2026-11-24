//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type windowsManager struct{}

// NewManager 返回 Windows SCM 原生服务管理器。
func NewManager() Manager {
	return &windowsManager{}
}

func (m *windowsManager) ServiceName() string { return WindowsServiceName }
func (m *windowsManager) UnitPath() string    { return `SCM:\` + WindowsServiceName }

func (m *windowsManager) CheckPrivileges() error {
	if windows.GetCurrentProcessToken().IsElevated() {
		return nil
	}
	return errors.New("需要管理员权限（请以“以管理员身份运行”打开 PowerShell）")
}

func (m *windowsManager) Install(cfg Config) error {
	if err := m.CheckPrivileges(); err != nil {
		return err
	}
	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连接 Windows 服务控制管理器失败: %w", err)
	}
	defer scm.Disconnect()

	svcCfg := mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        mgr.StartAutomatic,
		ErrorControl:     mgr.ErrorNormal,
		BinaryPathName:   cfg.BinaryPath,
		DisplayName:      WindowsDisplayName,
		Description:      WindowsDescription,
		DelayedAutoStart: false,
	}
	args := BuildWindowsServiceArgs(cfg)

	var s *mgr.Service
	if existing, openErr := scm.OpenService(WindowsServiceName); openErr == nil {
		// 服务已存在：先停止后重建，确保 BinaryPathName 与启动参数最新
		_ = stopAndWait(existing, 15*time.Second)
		if delErr := existing.Delete(); delErr != nil {
			_ = existing.Close()
			return fmt.Errorf("清理已有服务失败: %w", delErr)
		}
		_ = existing.Close()
		// 等待 SCM 标记删除释放
		waitServiceDeleted(scm, WindowsServiceName, 10*time.Second)
	}
	s, err = scm.CreateService(WindowsServiceName, cfg.BinaryPath, svcCfg, args...)
	if err != nil {
		return fmt.Errorf("创建 Windows 服务 %s 失败: %w", WindowsServiceName, err)
	}
	defer s.Close()

	// 配置异常退出自动重启恢复策略（5s / 15s / 30s，重置周期 24h）
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400)
	return nil
}

func waitServiceDeleted(scm *mgr.Mgr, name string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s, err := scm.OpenService(name)
		if err != nil {
			return
		}
		_ = s.Close()
		time.Sleep(250 * time.Millisecond)
	}
}

func (m *windowsManager) Uninstall() error {
	if err := m.CheckPrivileges(); err != nil {
		return err
	}
	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连接 Windows SCM 失败: %w", err)
	}
	defer scm.Disconnect()

	s, err := scm.OpenService(WindowsServiceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return fmt.Errorf("打开服务 %s 失败: %w", WindowsServiceName, err)
	}
	defer s.Close()

	_ = stopAndWait(s, 15*time.Second)
	if err := s.Delete(); err != nil {
		return fmt.Errorf("删除服务 %s 失败: %w", WindowsServiceName, err)
	}
	return nil
}

func (m *windowsManager) Start() error {
	if err := m.CheckPrivileges(); err != nil {
		return err
	}
	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连接 Windows SCM 失败: %w", err)
	}
	defer scm.Disconnect()
	s, err := scm.OpenService(WindowsServiceName)
	if err != nil {
		return fmt.Errorf("打开服务 %s 失败: %w", WindowsServiceName, err)
	}
	defer s.Close()

	if st, err := s.Query(); err == nil && st.State == svc.Running {
		return nil
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("启动服务 %s 失败: %w", WindowsServiceName, err)
	}
	return waitState(s, svc.Running, 15*time.Second)
}

func (m *windowsManager) Stop() error {
	if err := m.CheckPrivileges(); err != nil {
		return err
	}
	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连接 Windows SCM 失败: %w", err)
	}
	defer scm.Disconnect()
	s, err := scm.OpenService(WindowsServiceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return fmt.Errorf("打开服务 %s 失败: %w", WindowsServiceName, err)
	}
	defer s.Close()
	return stopAndWait(s, 15*time.Second)
}

func (m *windowsManager) Restart() error {
	if err := m.Stop(); err != nil {
		return err
	}
	return m.Start()
}

func (m *windowsManager) Status() (StatusInfo, error) {
	info := StatusInfo{ServiceName: WindowsServiceName, UnitPath: m.UnitPath()}
	scm, err := mgr.Connect()
	if err != nil {
		info.State = StateUnknown
		info.Detail = err.Error()
		return info, nil
	}
	defer scm.Disconnect()
	s, err := scm.OpenService(WindowsServiceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			info.State = StateNotInstalled
			info.Detail = "未安装 Windows 服务"
			return info, nil
		}
		info.State = StateUnknown
		info.Detail = err.Error()
		return info, nil
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		info.State = StateUnknown
		info.Detail = err.Error()
		return info, nil
	}
	switch st.State {
	case svc.Running:
		info.State = StateRunning
		info.Detail = "running"
	case svc.Stopped:
		info.State = StateStopped
		info.Detail = "stopped"
	case svc.StartPending:
		info.State = StateRunning
		info.Detail = "start_pending"
	case svc.StopPending:
		info.State = StateStopped
		info.Detail = "stop_pending"
	default:
		info.State = StateUnknown
		info.Detail = fmt.Sprintf("scm_state_%d", st.State)
	}
	return info, nil
}

func stopAndWait(s *mgr.Service, timeout time.Duration) error {
	st, err := s.Query()
	if err == nil && st.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return nil
		}
		return fmt.Errorf("停止服务失败: %w", err)
	}
	return waitState(s, svc.Stopped, timeout)
}

func waitState(s *mgr.Service, target svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == target {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("等待服务进入状态 %d 超时", target)
}

// IsRunningAsService 返回当前进程是否由 Windows SCM 作为服务拉起。
func IsRunningAsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

type winServiceHandler struct {
	runFn func(ctx context.Context) error
}

func (h *winServiceHandler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- h.runFn(ctx)
	}()

	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case err := <-done:
			status <- svc.Status{State: svc.Stopped}
			if err != nil {
				return false, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(12 * time.Second):
				}
				status <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		}
	}
}

// RunIfService 若由 Windows SCM 拉起，托管运行生命周期并返回 (true, err)；
// 命令行直接运行时返回 (false, nil)，交由标准 Ctrl+C 前台循环处理。
func RunIfService(runFn func(ctx context.Context) error) (bool, error) {
	if !IsRunningAsService() {
		return false, nil
	}
	err := svc.Run(WindowsServiceName, &winServiceHandler{runFn: runFn})
	return true, err
}
