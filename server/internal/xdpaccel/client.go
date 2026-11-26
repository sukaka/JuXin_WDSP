// client.go 受控 Unix Domain Socket xdpguard 守护进程客户端（镜像 semanticguard/health.go 安全纪律）：
// 绝不使用 TCP、拒绝符号链接与非 Socket 文件、禁用代理与重定向、有界响应读取，离线绝不伪造在线。
package xdpaccel

import (
	"bytes"
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
	defaultStatusTimeout = 2 * time.Second
	defaultSyncTimeout   = 5 * time.Second
	maxResponseBodyBytes = 64 * 1024
)

// 哨兵错误（供 handler 区分 400 非法路径与 503 守护进程不可达）。
var (
	ErrInvalidSocketPath = errors.New("invalid xdpguard unix socket path")
	ErrDaemonUnavailable = errors.New("xdpguard daemon unavailable")
)

// DaemonClient 抽象 xdpguard 本地 Unix Socket 控制面通信接口。
type DaemonClient interface {
	ValidateSocketPath(socketPath string) string
	ProbeStatus(ctx context.Context, socketPath string) Status
	PushSync(ctx context.Context, socketPath string, req SyncRequest) (SyncResponse, error)
}

// UnixClient 通过本地 Unix Domain Socket 调用 xdpguard GET /v1/stats（404 回退 /healthz）与 POST /v1/sync。
// 生产构造始终只允许 /var/run/caddy/sidecars/ 与 /run/jiuzhang/ 两个受控目录；
// testAllowedPrefix 仅限包内单测注入临时目录使用，绝不经由 HTTP 参数或配置暴露。
type UnixClient struct {
	statusTimeout     time.Duration
	syncTimeout       time.Duration
	testAllowedPrefix string
}

// NewUnixClient 创建生产环境 xdpguard Unix Socket 客户端。
func NewUnixClient(statusTimeout, syncTimeout time.Duration) *UnixClient {
	if statusTimeout <= 0 {
		statusTimeout = defaultStatusTimeout
	}
	if syncTimeout <= 0 {
		syncTimeout = defaultSyncTimeout
	}
	return &UnixClient{
		statusTimeout: statusTimeout,
		syncTimeout:   syncTimeout,
	}
}

// ValidateSocketPath 校验目标 Socket 路径是否位于受控目录内。
func (c *UnixClient) ValidateSocketPath(socketPath string) string {
	if c.testAllowedPrefix != "" {
		return validateSocketPathWithPrefixes(socketPath, AllowedSocketPrefixCaddy, AllowedSocketPrefixRun, c.testAllowedPrefix)
	}
	return ValidateSocketPath(socketPath)
}

type daemonStatsPayload struct {
	Status                 string            `json:"status"`
	Mode                   string            `json:"mode"`
	KernelAttached         bool              `json:"kernel_attached"`
	AttachModeRequested    string            `json:"attach_mode_requested"`
	Interfaces             []InterfaceStatus `json:"interfaces"`
	DroppedV4Packets       uint64            `json:"dropped_v4_packets"`
	DroppedV6Packets       uint64            `json:"dropped_v6_packets"`
	PassedPackets          uint64            `json:"passed_packets"`
	SyncedV4CIDRs          int               `json:"synced_v4_cidrs"`
	SyncedV6CIDRs          int               `json:"synced_v6_cidrs"`
	ExcludedProtectedCount int               `json:"excluded_protected_count"`
	LastSyncAt             string            `json:"last_sync_at"`
	Error                  string            `json:"error"`
}

type daemonHealthzPayload struct {
	Status                 string   `json:"status"`
	Mode                   string   `json:"mode"`
	KernelAttached         bool     `json:"kernel_attached"`
	AttachedInterfaces     []string `json:"attached_interfaces"`
	DroppedV4Packets       uint64   `json:"dropped_v4_packets"`
	DroppedV6Packets       uint64   `json:"dropped_v6_packets"`
	SyncedV4CIDRs          int      `json:"synced_v4_cidrs"`
	SyncedV6CIDRs          int      `json:"synced_v6_cidrs"`
	ExcludedProtectedCount int      `json:"excluded_protected_count"`
	LastSyncAt             string   `json:"last_sync_at"`
	Error                  string   `json:"error"`
}

type daemonErrorPayload struct {
	Error string `json:"error"`
}

// ProbeStatus 实时探测本地 xdpguard 守护进程状态；
// 优先调用 GET http://unix/v1/stats，若返回 404 则自动回退 GET http://unix/healthz。
// 任何路径非法、Socket 缺失、符号链接、非 Socket、连接失败或非法响应均如实返回 available=false。
func (c *UnixClient) ProbeStatus(ctx context.Context, socketPath string) Status {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	unavailable := func(status, errMsg string) Status {
		return Status{
			Available:      false,
			Status:         status,
			Mode:           ModeFallbackUserspace,
			KernelAttached: false,
			SocketPath:     socketPath,
			Interfaces:     []InterfaceStatus{},
			Error:          sanitizeStatusString(errMsg, 256),
		}
	}

	if msg := c.ValidateSocketPath(socketPath); msg != "" {
		return unavailable(StatusInvalidSocketPath, msg)
	}
	if err := checkSocketFile(socketPath); err != nil {
		return unavailable(StatusUnavailable, err.Error())
	}

	timeout := c.statusTimeout
	if timeout <= 0 {
		timeout = defaultStatusTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpClient, closeFn := newUnixHTTPClient(socketPath, timeout)
	defer closeFn()

	statusCode, body, err := doUnixRequest(probeCtx, httpClient, http.MethodGet, "http://unix/v1/stats", nil)
	if err != nil {
		return unavailable(StatusUnavailable, fmt.Sprintf("连接 xdpguard 失败: %v", err))
	}
	if statusCode == http.StatusNotFound {
		return c.probeHealthzFallback(probeCtx, httpClient, socketPath, unavailable)
	}
	if statusCode != http.StatusOK {
		return unavailable(StatusUnavailable, extractDaemonError(statusCode, body))
	}

	var payload daemonStatsPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return unavailable(StatusUnavailable, fmt.Sprintf("xdpguard /v1/stats 返回非法 JSON: %v", err))
	}

	st := normalizeDaemonStatus(payload.Status)
	if st != StatusOK && st != StatusDegraded {
		errMsg := sanitizeStatusString(payload.Error, 256)
		if errMsg == "" {
			errMsg = fmt.Sprintf("xdpguard 报告异常状态: %s", sanitizeStatusString(payload.Status, 64))
		}
		return unavailable(StatusUnavailable, errMsg)
	}

	ifaces := make([]InterfaceStatus, 0, len(payload.Interfaces))
	for _, it := range payload.Interfaces {
		ifaces = append(ifaces, InterfaceStatus{
			Name:     sanitizeStatusString(it.Name, 32),
			Attached: it.Attached,
			Mode:     normalizeRuntimeMode(it.Mode),
			Error:    sanitizeStatusString(it.Error, 256),
		})
	}
	return Status{
		Available:              true,
		Status:                 st,
		Mode:                   normalizeRuntimeMode(payload.Mode),
		KernelAttached:         payload.KernelAttached,
		SocketPath:             socketPath,
		AttachModeRequested:    sanitizeStatusString(payload.AttachModeRequested, 32),
		Interfaces:             ifaces,
		DroppedV4Packets:       payload.DroppedV4Packets,
		DroppedV6Packets:       payload.DroppedV6Packets,
		PassedPackets:          payload.PassedPackets,
		SyncedV4CIDRs:          payload.SyncedV4CIDRs,
		SyncedV6CIDRs:          payload.SyncedV6CIDRs,
		ExcludedProtectedCount: payload.ExcludedProtectedCount,
		LastSyncAt:             sanitizeStatusString(payload.LastSyncAt, 64),
		Error:                  sanitizeStatusString(payload.Error, 256),
	}
}

func (c *UnixClient) probeHealthzFallback(ctx context.Context, httpClient *http.Client, socketPath string, unavailable func(string, string) Status) Status {
	statusCode, body, err := doUnixRequest(ctx, httpClient, http.MethodGet, "http://unix/healthz", nil)
	if err != nil {
		return unavailable(StatusUnavailable, fmt.Sprintf("连接 xdpguard /healthz 失败: %v", err))
	}
	if statusCode != http.StatusOK {
		return unavailable(StatusUnavailable, extractDaemonError(statusCode, body))
	}
	var payload daemonHealthzPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return unavailable(StatusUnavailable, fmt.Sprintf("xdpguard /healthz 返回非法 JSON: %v", err))
	}
	st := normalizeDaemonStatus(payload.Status)
	if st != StatusOK && st != StatusDegraded {
		errMsg := sanitizeStatusString(payload.Error, 256)
		if errMsg == "" {
			errMsg = fmt.Sprintf("xdpguard /healthz 报告异常状态: %s", sanitizeStatusString(payload.Status, 64))
		}
		return unavailable(StatusUnavailable, errMsg)
	}
	mode := normalizeRuntimeMode(payload.Mode)
	ifaces := make([]InterfaceStatus, 0, len(payload.AttachedInterfaces))
	for _, name := range payload.AttachedInterfaces {
		ifaces = append(ifaces, InterfaceStatus{
			Name:     sanitizeStatusString(name, 32),
			Attached: payload.KernelAttached,
			Mode:     mode,
		})
	}
	return Status{
		Available:              true,
		Status:                 st,
		Mode:                   mode,
		KernelAttached:         payload.KernelAttached,
		SocketPath:             socketPath,
		Interfaces:             ifaces,
		DroppedV4Packets:       payload.DroppedV4Packets,
		DroppedV6Packets:       payload.DroppedV6Packets,
		SyncedV4CIDRs:          payload.SyncedV4CIDRs,
		SyncedV6CIDRs:          payload.SyncedV6CIDRs,
		ExcludedProtectedCount: payload.ExcludedProtectedCount,
		LastSyncAt:             sanitizeStatusString(payload.LastSyncAt, 64),
		Error:                  sanitizeStatusString(payload.Error, 256),
	}
}

// PushSync 向本地 xdpguard 发送 POST http://unix/v1/sync 同步全局黑名单与保护地址列表。
func (c *UnixClient) PushSync(ctx context.Context, socketPath string, req SyncRequest) (SyncResponse, error) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	if msg := c.ValidateSocketPath(socketPath); msg != "" {
		return SyncResponse{}, fmt.Errorf("%w: %s", ErrInvalidSocketPath, msg)
	}
	if err := checkSocketFile(socketPath); err != nil {
		return SyncResponse{}, fmt.Errorf("%w: %v", ErrDaemonUnavailable, err)
	}

	req.SchemaVersion = SchemaVersion
	req.Interfaces = nonNilStrings(req.Interfaces)
	req.BlockedCIDRs = nonNilStrings(req.BlockedCIDRs)
	req.ProtectedCIDRs = nonNilStrings(req.ProtectedCIDRs)

	rawReq, err := json.Marshal(req)
	if err != nil {
		return SyncResponse{}, fmt.Errorf("marshal xdp sync request: %w", err)
	}

	timeout := c.syncTimeout
	if timeout <= 0 {
		timeout = defaultSyncTimeout
	}
	syncCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpClient, closeFn := newUnixHTTPClient(socketPath, timeout)
	defer closeFn()

	statusCode, body, err := doUnixRequest(syncCtx, httpClient, http.MethodPost, "http://unix/v1/sync", rawReq)
	if err != nil {
		return SyncResponse{}, fmt.Errorf("%w: 调用 xdpguard /v1/sync 失败: %v", ErrDaemonUnavailable, err)
	}
	if statusCode != http.StatusOK {
		return SyncResponse{}, fmt.Errorf("%w: %s", ErrDaemonUnavailable, extractDaemonError(statusCode, body))
	}

	var resp SyncResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return SyncResponse{}, fmt.Errorf("%w: 解析 xdpguard /v1/sync 响应失败: %v", ErrDaemonUnavailable, err)
	}
	resp.Mode = normalizeRuntimeMode(resp.Mode)
	resp.AttachedInterfaces = sanitizeStringSlice(resp.AttachedInterfaces, 32)
	resp.LastSyncAt = sanitizeStatusString(resp.LastSyncAt, 64)
	resp.Error = sanitizeStatusString(resp.Error, 256)
	return resp, nil
}

func checkSocketFile(socketPath string) error {
	fi, err := os.Lstat(socketPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("xdpguard 守护进程未部署或 Unix Socket 文件不存在")
		}
		return fmt.Errorf("无法检查 Socket 文件: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("拒绝通过符号链接访问 xdpguard Socket")
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return errors.New("目标路径不是合法的 Unix Domain Socket")
	}
	return nil
}

func newUnixHTTPClient(socketPath string, timeout time.Duration) (*http.Client, func()) {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(dctx, "unix", socketPath)
		},
		DisableKeepAlives: true,
		Proxy:             nil,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, transport.CloseIdleConnections
}

func doUnixRequest(ctx context.Context, client *http.Client, method, url string, payload []byte) (int, []byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if len(body) > maxResponseBodyBytes {
		return resp.StatusCode, nil, fmt.Errorf("xdpguard 响应超过 %d 字节上限", maxResponseBodyBytes)
	}
	return resp.StatusCode, body, nil
}

func extractDaemonError(statusCode int, body []byte) string {
	var ep daemonErrorPayload
	if len(body) > 0 && json.Unmarshal(body, &ep) == nil {
		if msg := sanitizeStatusString(ep.Error, 256); msg != "" {
			return msg
		}
	}
	return fmt.Sprintf("xdpguard 返回异常状态码 HTTP %d", statusCode)
}

func normalizeDaemonStatus(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case StatusOK, "healthy", "ready":
		return StatusOK
	case StatusDegraded:
		return StatusDegraded
	default:
		return ""
	}
}

func normalizeRuntimeMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case ModeXDPNative:
		return ModeXDPNative
	case ModeXDPGeneric:
		return ModeXDPGeneric
	default:
		return ModeFallbackUserspace
	}
}

func sanitizeStringSlice(in []string, maxItemLen int) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if clean := sanitizeStatusString(s, maxItemLen); clean != "" {
			out = append(out, clean)
		}
	}
	return out
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
