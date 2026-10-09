package netmgrd

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSupervisorReadiness(t *testing.T) {
	dir := t.TempDir()
	f := &fakeRunner{dump: []byte(daemonDump)}
	s := NewSupervisor(filepath.Join(dir, "network.json"), filepath.Join(dir, "status.json"), time.Second, f)
	defer s.Close()
	check := func(want bool) {
		t.Helper()
		if err := s.Readiness(); (err == nil) != want {
			t.Fatalf("Readiness() = %v, want ready=%v", err, want)
		}
	}
	check(false) // 尚未执行首轮，不能沿用旧进程的成功状态。
	s.tick()
	check(true) // 未下发配置是合法空闲状态。
	writeNetmgrCfg(t, s.ConfigPath, `{"ip_forward":true}`)
	s.tick()
	check(true)
	execs := len(f.execLog())
	s.tick()
	check(true)
	if len(f.execLog()) != execs {
		t.Fatal("幂等轮询/健康查询不应新增变更命令")
	}
	writeNetmgrCfg(t, s.ConfigPath, `{broken`)
	s.tick()
	check(false)
	writeNetmgrCfg(t, s.ConfigPath, `{"ip_forward":true}`)
	s.tick()
	check(true)
	s.mu.Lock()
	if err := s.Readiness(); err == nil {
		t.Error("处理中不能报告就绪")
	}
	s.lastCheck = time.Now().Add(-time.Minute)
	s.mu.Unlock()
	check(false)
	s.tick()
	check(true)
	s.Close()
	check(false)
}

func TestReadinessRejectsApplyAndStatusFailures(t *testing.T) {
	for _, stage := range []string{"apply", "status"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			f := &fakeRunner{dump: []byte(daemonDump)}
			s := NewSupervisor(filepath.Join(dir, "network.json"), filepath.Join(dir, "status.json"), time.Second, f)
			defer s.Close()
			if stage == "apply" {
				f.failExec = map[string]string{"sysctl -w": "denied"}
			} else {
				// 用已存在目录模拟状态回写失败，不修改真实系统权限。
				s.StatusPath = dir
			}
			writeNetmgrCfg(t, s.ConfigPath, `{"ip_forward":true}`)
			s.tick()
			if err := s.Readiness(); err == nil {
				t.Fatal("执行/回写失败仍报告就绪")
			}
		})
	}
}

func TestHealthSocket(t *testing.T) {
	// Unix Socket 在 macOS 上有较短路径上限。
	dir, err := os.MkdirTemp("", "nm-health-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "h.sock")
	f := &fakeRunner{dump: []byte(daemonDump)}
	s := NewSupervisor(filepath.Join(dir, "network.json"), filepath.Join(dir, "status.json"), time.Second, f)
	defer s.Close()
	server, err := s.StartHealthServer(path)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := ProbeHealth(context.Background(), path); err == nil {
		t.Fatal("初始化未完成不应就绪")
	}
	s.tick()
	if err := ProbeHealth(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("健康 socket 必须仅本用户可访问: %v", err)
	}
	if second, err := s.StartHealthServer(path); err == nil {
		_ = second.Close()
		t.Fatal("不得替换仍活跃的健康 socket")
	}
	if len(f.execLog()) != 0 {
		t.Fatal("只读探测执行了网络配置命令")
	}
	s.Close()
	if err := ProbeHealth(context.Background(), path); err == nil {
		t.Fatal("关闭后仍报告就绪")
	}
	_ = server.Close()
	if err := ProbeHealth(context.Background(), path); err == nil {
		t.Fatal("socket 不可达必须失败")
	}
	writeNetmgrCfg(t, path, "preserve")
	if second, err := s.StartHealthServer(path); err == nil {
		_ = second.Close()
		t.Fatal("不得覆盖非 socket 文件")
	}
	if data, _ := os.ReadFile(path); string(data) != "preserve" {
		t.Fatal("非 socket 文件被修改")
	}

	stalePath := filepath.Join(dir, "stale.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: stalePath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	_ = listener.Close()
	restarted, err := s.StartHealthServer(stalePath)
	if err != nil {
		t.Fatalf("重启应允许清理已失效的 socket: %v", err)
	}
	_ = restarted.Close()
}
