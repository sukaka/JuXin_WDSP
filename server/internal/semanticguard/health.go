// health.go 受控 Unix Domain Socket 边车 /healthz 实时探测（无 TCP/HTTP SSRF，绝不伪造在线）。
package semanticguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultProbeTimeout  = 2 * time.Second
	maxHealthzBodyBytes  = 16 * 1024
)

// StatusProber 边车实时健康探测接口（*UnixHealthProber 实现）。
type StatusProber interface {
	ValidateSocketPath(socketPath string) string
	Probe(ctx context.Context, socketPath string) SidecarStatus
}

// UnixHealthProber 通过 Unix Domain Socket 调用边车 GET http://unix/healthz。
// 生产构造始终只允许 /var/run/caddy/sidecars/ 与 /run/jiuzhang/ 两个受控目录；
// testAllowedPrefix 仅限包内单测注入临时目录使用，绝不经由 HTTP 参数或配置暴露。
type UnixHealthProber struct {
	timeout           time.Duration
	testAllowedPrefix string
}

// NewUnixHealthProber 创建生产环境边车探测器。
func NewUnixHealthProber(timeout time.Duration) *UnixHealthProber {
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	return &UnixHealthProber{timeout: timeout}
}

// ValidateSocketPath 校验探测目标路径是否位于受控目录内。
func (p *UnixHealthProber) ValidateSocketPath(socketPath string) string {
	if p.testAllowedPrefix != "" {
		return validateSocketPathWithPrefixes(socketPath, AllowedSocketPrefixCaddy, AllowedSocketPrefixRun, p.testAllowedPrefix)
	}
	return ValidateSocketPath(socketPath)
}

type sidecarHealthzResponse struct {
	Status      string `json:"status"`
	ModelID     string `json:"model_id"`
	ModelSHA256 string `json:"model_sha256"`
	Backend     string `json:"backend"`
	Error       string `json:"error"`
}

// Probe 实时探测本地 Unix Socket 边车状态；Socket 缺失、非 Socket、符号链接、超时、
// 非 200 或载荷异常均如实返回 available=false，绝不模拟在线。
func (p *UnixHealthProber) Probe(ctx context.Context, socketPath string) SidecarStatus {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	unavailable := func(status, errMsg string) SidecarStatus {
		return SidecarStatus{
			Available:  false,
			Status:     status,
			SocketPath: socketPath,
			Error:      sanitizeStatusString(errMsg, 256),
		}
	}
	if msg := p.ValidateSocketPath(socketPath); msg != "" {
		return unavailable("invalid_socket_path", msg)
	}

	fi, err := os.Lstat(socketPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return unavailable("unavailable", "边车未部署或 Unix Socket 文件不存在")
		}
		return unavailable("unavailable", fmt.Sprintf("无法检查 Socket 文件: %v", err))
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return unavailable("unavailable", "拒绝通过符号链接访问边车 Socket")
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return unavailable("unavailable", "目标路径不是合法的 Unix Domain Socket")
	}

	timeout := p.timeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(dctx, "unix", socketPath)
		},
		DisableKeepAlives: true,
		Proxy:             nil,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "http://unix/healthz", nil)
	if err != nil {
		return unavailable("unavailable", fmt.Sprintf("构造健康探测请求失败: %v", err))
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return unavailable("unavailable", fmt.Sprintf("边车连接失败: %v", err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHealthzBodyBytes+1))
	if err != nil {
		return unavailable("unavailable", fmt.Sprintf("读取边车响应失败: %v", err))
	}
	if len(body) > maxHealthzBodyBytes {
		return unavailable("invalid_response", "边车 /healthz 响应超过 16KiB 上限")
	}

	var payload sidecarHealthzResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		if resp.StatusCode != http.StatusOK {
			return unavailable("unhealthy", fmt.Sprintf("边车返回异常状态码 HTTP %d", resp.StatusCode))
		}
		return unavailable("invalid_response", fmt.Sprintf("边车 /healthz 返回非法 JSON: %v", err))
	}

	status := sanitizeStatusString(payload.Status, 64)
	modelID := sanitizeStatusString(payload.ModelID, 128)
	modelSHA := sanitizeStatusString(payload.ModelSHA256, 128)
	backend := sanitizeStatusString(payload.Backend, 64)
	errText := sanitizeStatusString(payload.Error, 256)

	if resp.StatusCode != http.StatusOK {
		if status == "" {
			status = "unhealthy"
		}
		if errText == "" {
			errText = fmt.Sprintf("边车返回 HTTP %d", resp.StatusCode)
		}
		return SidecarStatus{
			Available:   false,
			Status:      status,
			SocketPath:  socketPath,
			ModelID:     modelID,
			ModelSHA256: modelSHA,
			Backend:     backend,
			Error:       errText,
		}
	}

	okStatus := strings.EqualFold(status, "ok") ||
		strings.EqualFold(status, "healthy") ||
		strings.EqualFold(status, "ready")
	if !okStatus {
		if status == "" {
			status = "unhealthy"
		}
		if errText == "" {
			errText = fmt.Sprintf("边车报告非就绪状态: %s", status)
		}
		return SidecarStatus{
			Available:   false,
			Status:      status,
			SocketPath:  socketPath,
			ModelID:     modelID,
			ModelSHA256: modelSHA,
			Backend:     backend,
			Error:       errText,
		}
	}

	return SidecarStatus{
		Available:   true,
		Status:      status,
		SocketPath:  socketPath,
		ModelID:     modelID,
		ModelSHA256: modelSHA,
		Backend:     backend,
		Error:       errText,
	}
}

func sanitizeStatusString(s string, maxLen int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}
