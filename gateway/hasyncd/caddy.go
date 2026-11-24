package hasyncd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

type localCaddyClient struct {
	socketPath string
	httpClient *http.Client
}

func newLocalCaddyClient(socketPath string) *localCaddyClient {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &localCaddyClient{
		socketPath: socketPath,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *localCaddyClient) Ping(ctx context.Context) bool {
	if strings.TrimSpace(c.socketPath) == "" {
		return false
	}
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(pingCtx, http.MethodGet, "http://localhost/config/", nil)
	if err != nil {
		return false
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode == http.StatusOK
}

func (c *localCaddyClient) GetConfig(ctx context.Context) ([]byte, error) {
	if strings.TrimSpace(c.socketPath) == "" {
		return nil, errors.New("caddy socket not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/config/", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("caddy admin unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxCaddyLoadBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read caddy config: %w", err)
	}
	if int64(len(body)) > MaxCaddyLoadBytes {
		return nil, errors.New("caddy config exceeds size limit")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("caddy /config/ returned status %d", resp.StatusCode)
	}
	return body, nil
}

func (c *localCaddyClient) LoadConfig(ctx context.Context, configJSON []byte) (int, string, error) {
	if strings.TrimSpace(c.socketPath) == "" {
		return 0, "", errors.New("caddy socket not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/load", bytes.NewReader(configJSON))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("caddy admin unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return resp.StatusCode, "", fmt.Errorf("read caddy /load response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, sanitizeCaddyError(body), nil
	}
	return resp.StatusCode, "", nil
}

// CanonicalBusinessConfigHash computes the SHA-256 hex digest of canonicalized Caddy JSON
// with the top-level "admin" key stripped so nodes with different admin listeners yield
// identical hashes for identical business configs.
func CanonicalBusinessConfigHash(configJSON []byte) (string, error) {
	var root map[string]any
	if err := json.Unmarshal(configJSON, &root); err != nil {
		return "", fmt.Errorf("parse config json: %w", err)
	}
	if root == nil {
		return "", errors.New("config json must be an object")
	}
	delete(root, "admin")
	canonical, err := json.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("canonicalize config json: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// ExtractPolicyVersion finds the first non-empty api_policy_version inside a Caddy config JSON.
// Searches jiuzhang_guard handlers deterministically in sorted map key order, falling back to
// a top-level api_policy_version field if present.
func ExtractPolicyVersion(configJSON []byte) string {
	var root map[string]any
	if err := json.Unmarshal(configJSON, &root); err != nil || root == nil {
		return ""
	}
	if v := findPolicyVersionRecursive(root); v != "" {
		return v
	}
	if v, ok := root["api_policy_version"].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func findPolicyVersionRecursive(node any) string {
	switch val := node.(type) {
	case map[string]any:
		if handler, _ := val["handler"].(string); handler == "jiuzhang_guard" {
			if pv, ok := val["api_policy_version"].(string); ok && strings.TrimSpace(pv) != "" {
				return strings.TrimSpace(pv)
			}
		}
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if pv := findPolicyVersionRecursive(val[k]); pv != "" {
				return pv
			}
		}
	case []any:
		for _, item := range val {
			if pv := findPolicyVersionRecursive(item); pv != "" {
				return pv
			}
		}
	}
	return ""
}

var pemPrivateKeyRE = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

func sanitizeCaddyError(body []byte) string {
	s := string(body)
	s = pemPrivateKeyRE.ReplaceAllString(s, "[REDACTED_PRIVATE_KEY]")
	// Strip ASCII control chars except space/tab.
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\r' || c == '\n' {
			b.WriteByte(' ')
			continue
		}
		if c < 0x20 || c == 0x7f {
			continue
		}
		b.WriteByte(c)
	}
	out := strings.TrimSpace(b.String())
	const maxLen = 2000
	if len(out) > maxLen {
		out = out[:maxLen] + "...(truncated)"
	}
	return out
}
