package gatewayconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"
)

// CaddyClient 通过 Unix Socket 或内网 HTTP(S) 与 Caddy Admin API 通信。
type CaddyClient struct {
	socketPath string
	// baseURL 请求基址（unix socket 目标为 http://localhost 占位；
	// http(s) 目标为登记的管理面地址，见 NewCaddyClientForAdminAddr）
	baseURL      string
	isHTTPTarget bool
	httpClient   *http.Client
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
		baseURL:    "http://localhost",
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// SocketPath 返回 Socket 路径。
func (c *CaddyClient) SocketPath() string {
	return c.socketPath
}

// IsHTTP 返回该客户端是否指向 HTTP(S) TCP 管理通道（而非本地 Unix Socket）。
func (c *CaddyClient) IsHTTP() bool {
	return c.isHTTPTarget
}

// ErrAdminAddrDenied 节点管理通道地址非法（格式错误或非内网管理面地址）。
var ErrAdminAddrDenied = errors.New("invalid node admin address")

// ValidateNodeAdminAddr 登记时校验节点 Caddy Admin 通道地址（W18-SYNC，任务书 §200）。
// 支持两种形态：
//   - unix socket：绝对路径（/run/caddy-admin.sock）或 unix:///path 形式
//   - http(s)://host[:port]：仅内网管理面地址（回环/RFC1918/链路本地；主机名
//     须可解析且全部解析结果为内网地址，任一公网/保留地址即拒绝）
//
// 安全纪律（仿 apisecurity URL 导入的 SSRF 防护，方向相反——那里只许公网、
// 这里只许内网）：Caddy Admin API 无鉴权，登记公网或任意地址等于把配置面写入
// 能力交给网络可达者；http(s) 目标在拨号时还会重解析复检（防 DNS 重绑定，
// 见 NewCaddyClientForAdminAddr）。
func ValidateNodeAdminAddr(addr string) error {
	_, err := parseAdminAddr(addr)
	return err
}

// adminAddrTarget 解析后的管理通道目标。
type adminAddrTarget struct {
	socketPath string   // unix socket 路径（httpURL 为空时有效）
	httpURL    *url.URL // http(s) 目标（socketPath 为空时有效）
}

// allowedAdminSocketDirs 允许作为次要节点 Caddy Admin Unix Socket 的目录白名单。
var allowedAdminSocketDirs = []string{
	"/var/run/caddy/",
	"/run/caddy/",
}

// deniedAdminPrefixes 次要节点管理地址永久禁止网段（云元数据与链路本地，先于 IsPrivate 判定）。
var deniedAdminPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.169.254/32"),
	netip.MustParsePrefix("169.254.170.2/32"),
	netip.MustParsePrefix("100.100.100.200/32"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
}

// validateAdminSocketPath 校验 unix socket 路径：仅允许位于 /var/run/caddy/ 或 /run/caddy/
// 下的绝对路径，拒绝控制字符与 .. 路径穿越。
func validateAdminSocketPath(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("%w: unix socket 路径为空", ErrAdminAddrDenied)
	}
	for _, c := range raw {
		if c < 0x20 || c == 0x7f {
			return "", fmt.Errorf("%w: unix socket 路径包含控制字符", ErrAdminAddrDenied)
		}
	}
	if !strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("%w: unix socket 路径须为绝对路径", ErrAdminAddrDenied)
	}
	for _, seg := range strings.Split(raw, "/") {
		if seg == ".." {
			return "", fmt.Errorf("%w: unix socket 路径不允许包含 ..", ErrAdminAddrDenied)
		}
	}
	clean := path.Clean(raw)
	for _, dir := range allowedAdminSocketDirs {
		if strings.HasPrefix(clean, dir) && len(clean) > len(dir) {
			return clean, nil
		}
	}
	return "", fmt.Errorf("%w: unix socket 路径必须在 /var/run/caddy/ 或 /run/caddy/ 目录下", ErrAdminAddrDenied)
}

// parseAdminAddr 解析并校验管理通道地址。
func parseAdminAddr(addr string) (*adminAddrTarget, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, fmt.Errorf("%w: 地址为空", ErrAdminAddrDenied)
	}
	if len(addr) > 255 {
		return nil, fmt.Errorf("%w: 地址过长", ErrAdminAddrDenied)
	}
	// unix socket：绝对路径或 unix:// 形式，仅允许白名单 Caddy socket 目录
	if strings.HasPrefix(addr, "/") {
		clean, err := validateAdminSocketPath(addr)
		if err != nil {
			return nil, err
		}
		return &adminAddrTarget{socketPath: clean}, nil
	}
	if strings.HasPrefix(addr, "unix://") {
		p := strings.TrimPrefix(addr, "unix://")
		clean, err := validateAdminSocketPath(p)
		if err != nil {
			return nil, err
		}
		return &adminAddrTarget{socketPath: clean}, nil
	}
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: URL 解析失败", ErrAdminAddrDenied)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: 仅支持 unix socket 路径或 http(s)://host[:port]", ErrAdminAddrDenied)
	}
	// 拒绝 userinfo（凭据不入库）与非根路径/查询/片段（Admin API 在根路径，避免歧义）
	if u.User != nil {
		return nil, fmt.Errorf("%w: 不允许携带用户信息", ErrAdminAddrDenied)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("%w: 不允许携带路径", ErrAdminAddrDenied)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: 不允许携带查询或片段", ErrAdminAddrDenied)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: 缺少主机名", ErrAdminAddrDenied)
	}
	if ip := net.ParseIP(host); ip != nil {
		if err := checkInternalAdminIP(ip); err != nil {
			return nil, err
		}
		warnPlaintextAdminScheme(u)
		return &adminAddrTarget{httpURL: u}, nil
	}
	// 主机名：解析全部 A/AAAA 逐一校验（任一公网/保留地址即拒绝）
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("%w: 主机名解析失败", ErrAdminAddrDenied)
	}
	for _, ip := range ips {
		if err := checkInternalAdminIP(ip); err != nil {
			return nil, err
		}
	}
	warnPlaintextAdminScheme(u)
	return &adminAddrTarget{httpURL: u}, nil
}

// warnPlaintextAdminScheme http 明文管理通道风险提示：Caddy Admin API 无鉴权，
// 推送配置携带密钥材料（valkey 密码、签名密钥等），明文 http 传输存在链路旁路
// 读取与篡改风险，生产环境应使用 unix socket 或 https（仅提示，不改变地址校验逻辑；
// 登记路径 ValidateNodeAdminAddr 与推送路径 NewCaddyClientForAdminAddr 同经此处）。
func warnPlaintextAdminScheme(u *url.URL) {
	if u.Scheme != "http" {
		return
	}
	slog.Warn("node admin address uses plaintext http: Caddy Admin API is unauthenticated and pushed config carries secret material; prefer unix socket or https",
		"admin_addr", u.Host)
}

// checkInternalAdminIP 校验目标 IP 属于内网管理面（仅允许回环与 RFC1918/ULA 私网，
// 显式拒绝云元数据与链路本地地址，防止 SSRF 探测云元数据或链路本地服务）。
func checkInternalAdminIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("%w: 空地址", ErrAdminAddrDenied)
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("%w: 非法地址 %s", ErrAdminAddrDenied, ip)
	}
	addr = addr.Unmap()
	for _, prefix := range deniedAdminPrefixes {
		if prefix.Contains(addr) {
			return fmt.Errorf("%w: 禁止访问元数据或链路本地地址 %s", ErrAdminAddrDenied, addr)
		}
	}
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return fmt.Errorf("%w: 禁止访问链路本地地址 %s", ErrAdminAddrDenied, addr)
	}
	if addr.IsLoopback() || addr.IsPrivate() {
		return nil
	}
	return fmt.Errorf("%w: 非内网管理面地址 %s", ErrAdminAddrDenied, addr)
}

// NewCaddyClientForAdminAddr 按节点登记的管理通道地址构建 Caddy Admin 客户端
// （发布扇出到次要节点用）。unix 目标与 NewCaddyClient 等价；http(s) 目标走
// 普通 TCP，拨号时重解析并复检内网地址（防校验与连接之间的 DNS 重绑定，
// 与 apisecurity specFetchTransport 同一纪律），并禁用重定向以防 307 泄露推送配置中的密钥材料。
func NewCaddyClientForAdminAddr(addr string) (*CaddyClient, error) {
	target, err := parseAdminAddr(addr)
	if err != nil {
		return nil, err
	}
	if target.httpURL == nil {
		return NewCaddyClient(target.socketPath), nil
	}
	base := "http://" + target.httpURL.Host
	if target.httpURL.Scheme == "https" {
		base = "https://" + target.httpURL.Host
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		DisableKeepAlives: true,
		IdleConnTimeout:   30 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("%w: 地址解析失败", ErrAdminAddrDenied)
			}
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("%w: 主机名解析失败", ErrAdminAddrDenied)
			}
			for _, ip := range ips {
				if err := checkInternalAdminIP(ip); err != nil {
					return nil, err
				}
			}
			first, ok := netip.AddrFromSlice(ips[0])
			if !ok {
				return nil, fmt.Errorf("%w: 地址解析失败", ErrAdminAddrDenied)
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(first.Unmap().String(), port))
		},
	}
	return &CaddyClient{
		baseURL:      base,
		isHTTPTarget: true,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Ping 检查 Admin API 是否可用（GET /config/）。
func (c *CaddyClient) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/config/", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("admin socket unreachable: %w", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)); err != nil {
		return fmt.Errorf("admin api response body failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("admin api returned %d", resp.StatusCode)
	}
	return nil
}

// LoadConfig 发布配置到 Caddy（POST /load）。
// 返回错误信息（Caddy 返回的错误详情，已截断）。
func (c *CaddyClient) LoadConfig(ctx context.Context, configJSON string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/load",
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return fmt.Errorf("load config response body failed: %w", err)
	}
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

// maxCurrentConfigBytes 限制单次读取 Caddy /config/ 响应体的最大体积（32 MiB），
// 超限时显式报错（fail-closed）而非静默截断为半截 JSON 破坏回滚基线。
const maxCurrentConfigBytes = 32 << 20

// GetCurrentConfig 获取当前生效配置（GET /config/）。
func (c *CaddyClient) GetCurrentConfig(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/config/", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("get config failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCurrentConfigBytes+1))
	if err != nil {
		return "", fmt.Errorf("get config response body failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("get config returned %d", resp.StatusCode)
	}
	if len(body) > maxCurrentConfigBytes {
		return "", fmt.Errorf("get config response body exceeds %d bytes limit", maxCurrentConfigBytes)
	}
	return string(body), nil
}

// GetAdminConfig 获取当前生效的 admin 配置段（GET /config/admin）。
// 用于跨机 HTTP(S) 扇出前读取次要节点自身的 admin.listen，防止推送主节点的 unix socket 配置
// 覆盖次要节点的 TCP 管理监听导致节点永久失联。远端返回非 200、非对象或空/null 均报错（fail-closed）。
func (c *CaddyClient) GetAdminConfig(ctx context.Context) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/config/admin", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get admin config failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("get admin config response body failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get admin config failed (status %d): %s", resp.StatusCode, truncateString(string(body), 200))
	}
	var admin map[string]interface{}
	if err := json.Unmarshal(body, &admin); err != nil {
		return nil, fmt.Errorf("decode admin config failed: %w", err)
	}
	if len(admin) == 0 {
		return nil, fmt.Errorf("admin config is empty")
	}
	return admin, nil
}

// GetRuntimeSnapshot reads metrics from the admin-only gateway runtime endpoint.
func (c *CaddyClient) GetRuntimeSnapshot(ctx context.Context) (*GatewayRuntimeSnapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/jiuzhang/runtime", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get gateway runtime snapshot: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read gateway runtime snapshot: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway runtime endpoint returned %d: %s", resp.StatusCode, truncateString(string(body), 200))
	}
	var snapshot GatewayRuntimeSnapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return nil, fmt.Errorf("decode gateway runtime snapshot: %w", err)
	}
	return &snapshot, nil
}

// GetRuntimeHistory reads high-resolution runtime trend points from the admin-only gateway history endpoint.
func (c *CaddyClient) GetRuntimeHistory(ctx context.Context) (*GatewayRuntimeHistory, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/jiuzhang/runtime/history", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get gateway runtime history: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read gateway runtime history: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway runtime history endpoint returned %d: %s", resp.StatusCode, truncateString(string(body), 200))
	}
	var history GatewayRuntimeHistory
	if err := json.Unmarshal(body, &history); err != nil {
		return nil, fmt.Errorf("decode gateway runtime history: %w", err)
	}
	if history.Points == nil {
		history.Points = []GatewayRuntimeHistoryPoint{}
	}
	return &history, nil
}

// GetConfigHash 获取当前配置的规范化哈希（发布内容一致性验证与健康指标共用）。
// 规范化指键序/空白不敏感（Go encoding/json 对 map 键排序），容忍 Caddy /config/
// 返回与 /load 原文之间的格式差异；语义不一致（内容真实不同）才会得到不同哈希。
func (c *CaddyClient) GetConfigHash(ctx context.Context) (string, error) {
	cfg, err := c.GetCurrentConfig(ctx)
	if err != nil {
		return "", err
	}
	return CanonicalConfigHash(cfg)
}

// GetBusinessConfigHash 获取当前生效业务配置（剔除顶层 admin 段）的规范化哈希。
// 跨节点扇出验证使用本方法，确保各节点保留各自 admin.listen 时仍严格校验业务配置语义一致。
func (c *CaddyClient) GetBusinessConfigHash(ctx context.Context) (string, error) {
	cfg, err := c.GetCurrentConfig(ctx)
	if err != nil {
		return "", err
	}
	return CanonicalBusinessConfigHash(cfg)
}

// CanonicalConfigHash 规范化 JSON 的 sha256 hex：先解析再重新序列化（map 键排序、
// 空白归一），用于「发布内容 vs 网关实际加载配置」的生效比对（P0-21）。
func CanonicalConfigHash(configJSON string) (string, error) {
	var v interface{}
	if err := json.Unmarshal([]byte(configJSON), &v); err != nil {
		return "", fmt.Errorf("parse config json: %w", err)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("canonicalize config json: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// CanonicalBusinessConfigHash 计算剔除顶层 "admin" 键后的规范化 JSON SHA-256 hex。
// 跨节点配置一致性比对忽略各节点独立的 admin.listen，仅严格验证业务配置（apps、logging 等）逐字节等价。
func CanonicalBusinessConfigHash(configJSON string) (string, error) {
	var root map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &root); err != nil {
		return "", fmt.Errorf("parse config json: %w", err)
	}
	if root == nil {
		return "", fmt.Errorf("parse config json: expected JSON object")
	}
	delete(root, "admin")
	raw, err := json.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("canonicalize business config json: %w", err)
	}
	sum := sha256.Sum256(raw)
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
