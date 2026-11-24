// 健康检查 HTTP 服务（/healthz）与 --healthcheck 探测客户端。
package tproxyd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// HealthStatus /healthz 返回的运行态快照。
type HealthStatus struct {
	OK        bool   `json:"ok"`
	Enabled   bool   `json:"enabled"`
	Listening bool   `json:"listening"`
	Listen    string `json:"listen"`
}

// HealthStatus 返回当前监督器与牵引监听器的即时运行态（goroutine 安全）。
func (s *Supervisor) HealthStatus() HealthStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return HealthStatus{OK: false}
	}
	listening := false
	listen := ""
	if s.srv != nil {
		alive := !s.drained
		if alive {
			select {
			case err := <-s.done:
				log.Printf("[tproxyd] 健康检查发现服务意外退出（%v）", err)
				alive = false
				s.drained = true
			default:
			}
		}
		if alive {
			listening = true
			listen = s.srv.Addr()
		}
	}
	return HealthStatus{
		OK:        true,
		Enabled:   s.enabled,
		Listening: listening,
		Listen:    listen,
	}
}

// StartHealthServer 在 addr 启动轻量 HTTP /healthz 服务（默认 127.0.0.1:15001）。
// 返回已启动的 *http.Server 及实际监听地址（支持 :0 动态端口测试）。
func (s *Supervisor) StartHealthServer(addr string) (*http.Server, string, error) {
	if err := checkAddr("TPROXY_HEALTH_ADDR", addr); err != nil {
		return nil, "", err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("监听健康端点 %s 失败: %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		st := s.HealthStatus()
		w.Header().Set("Content-Type", "application/json")
		if !st.OK {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(st)
	})
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      2 * time.Second,
		IdleTimeout:       5 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[tproxyd] 健康检查服务停止: %v", err)
		}
	}()
	return srv, ln.Addr().String(), nil
}

// ProbeHealth 探测 http://<healthAddr>/healthz（--healthcheck CLI 入口）；
// 仅在 HTTP 200 且响应 JSON 声明 ok=true 时返回 nil。
func ProbeHealth(ctx context.Context, healthAddr string) error {
	targetURL := normalizeHealthURL(healthAddr)
	if targetURL == "" {
		return fmt.Errorf("tproxyd 健康地址为空")
	}
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return fmt.Errorf("构造健康探测请求失败: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("tproxyd 健康探测失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("tproxyd 不健康: HTTP %d", resp.StatusCode)
	}
	var st HealthStatus
	if err := json.Unmarshal(body, &st); err != nil {
		return fmt.Errorf("tproxyd 健康响应 JSON 非法: %w", err)
	}
	if !st.OK {
		return fmt.Errorf("tproxyd 健康状态 ok=false")
	}
	return nil
}

func normalizeHealthURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		if strings.HasSuffix(s, "/healthz") {
			return s
		}
		return strings.TrimRight(s, "/") + "/healthz"
	}
	return "http://" + s + "/healthz"
}
