package gatewayconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// CaddyClient 通过 Unix Socket 与 Caddy Admin API 通信。
type CaddyClient struct {
	socketPath string
	httpClient *http.Client
}

// NewCaddyClient 创建 Caddy Admin 客户端。
func NewCaddyClient(socketPath string) *CaddyClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
	return &CaddyClient{
		socketPath: socketPath,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}
}

// SocketPath 返回 Socket 路径。
func (c *CaddyClient) SocketPath() string {
	return c.socketPath
}

// Ping 检查 Admin API 是否可用（GET /config/）。
func (c *CaddyClient) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/config/", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("admin socket unreachable: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("admin api returned %d", resp.StatusCode)
	}
	return nil
}

// LoadConfig 发布配置到 Caddy（POST /load）。
// 返回错误信息（Caddy 返回的错误详情，已截断）。
func (c *CaddyClient) LoadConfig(ctx context.Context, configJSON string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/load",
		strings.NewReader(configJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("load config request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode != http.StatusOK {
		return &LoadError{
			StatusCode: resp.StatusCode,
			Message:    truncateString(string(body), 2000),
		}
	}
	return nil
}

// LoadError 是 Caddy 配置加载失败错误。
type LoadError struct {
	StatusCode int
	Message    string
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("caddy load failed (status %d): %s", e.StatusCode, e.Message)
}

// GetCurrentConfig 获取当前生效配置（GET /config/）。
func (c *CaddyClient) GetCurrentConfig(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/config/", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("get config failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4MB 上限
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("get config returned %d", resp.StatusCode)
	}
	return string(body), nil
}

// GetConfigHash 获取当前配置的哈希（用于发布前后一致性验证）。
// 注意：Caddy 会规范化配置，该哈希与生成器的确定性哈希不保证一致，
// 仅用于发布前后状态比对（发布后哈希应变化为预期新配置的语义）。
func (c *CaddyClient) GetConfigHash(ctx context.Context) (string, error) {
	cfg, err := c.GetCurrentConfig(ctx)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(cfg))
	return hex.EncodeToString(sum[:]), nil
}

// ValidateConfig 校验配置（POST /load 前先 adapt+validate）。
// Caddy Admin API 无独立 validate 端点，用 /load 的原子特性（失败不影响当前配置）。
// 此处通过 adapt 接口验证结构（如可用）。
func (c *CaddyClient) ValidateConfig(ctx context.Context, configJSON string) error {
	// Caddy Admin API 的 /load 是原子的：新配置无效时返回错误且不替换当前配置。
	// 我们用 "adapting" 预检：尝试 POST 到 /load 前，先用 JSON 结构校验（本地）。
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return fmt.Errorf("invalid config json structure: %w", err)
	}
	if _, ok := cfg["apps"]; !ok {
		return fmt.Errorf("config missing apps section")
	}
	return nil
}

func truncateString(s string, n int) string {
	if len(s) > n {
		return s[:n] + "...(truncated)"
	}
	return s
}
