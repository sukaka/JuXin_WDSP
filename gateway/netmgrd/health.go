package netmgrd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

// DefaultHealthSocket 位于容器私有文件系统，不随网关共享卷继承旧进程状态。
const DefaultHealthSocket = "/tmp/wdsp-netmgrd-health.sock"

// Readiness 仅检查监督循环状态，绝不执行网络变更或依赖可能过期的 status 文件。
func (s *Supervisor) Readiness() error {
	if !s.mu.TryLock() {
		return errors.New("配置处理尚未完成")
	}
	defer s.mu.Unlock()
	maxAge := max(3*s.Interval, 30*time.Second)
	if s.closed || !s.ready || s.lastCheck.IsZero() || time.Since(s.lastCheck) > maxAge {
		return errors.New("监督循环未就绪或最近配置处理失败")
	}
	return nil
}

// StartHealthServer 仅监听本地 Unix Socket；拒绝覆盖普通文件或仍活跃的监听器。
func (s *Supervisor) StartHealthServer(socketPath string) (*http.Server, error) {
	if st, err := os.Lstat(socketPath); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("健康 socket 路径已被非 socket 文件占用")
		}
		conn, err := net.DialTimeout("unix", socketPath, time.Second)
		if err == nil {
			_ = conn.Close()
			return nil, errors.New("健康 socket 已在监听")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("检查健康 socket: %w", err)
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("清理失效健康 socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("检查健康 socket 路径: %w", err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("监听健康 socket: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Readiness(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[netmgrd] 健康服务停止: %v", err)
		}
	}()
	return server, nil
}

// ProbeHealth 是 --healthcheck 的只读入口；连接失败、超时和非 200 均失败关闭。
func ProbeHealth(ctx context.Context, socketPath string) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("netmgrd 健康探测失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("netmgrd 未就绪: HTTP %d", resp.StatusCode)
	}
	return nil
}
