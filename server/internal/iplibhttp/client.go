// client.go 基于 outboundhttp 构建的 IP 库专用受控出站下载器：
//   - OFFLINE_ONLY：彻底禁止出站请求；
//   - OFFICIAL：仅允许硬编码官方域名白名单、强制 HTTPS、最多 5 跳重定向且每跳复检、跨源剥离敏感头；
//   - CUSTOM_URL：默认公网 HTTPS；命中 outbound_allowlist 允许访问指定内网镜像；
//     仅当 allow_insecure_http_mirror=true 且目标命中 outbound_allowlist 时放宽 HTTP；
//     云元数据地址在任何模式和允许列表下均硬阻断；
//   - 可选正向代理：校验代理地址并阻断元数据，先校验目标 URL 方案与主机后再拨号代理，
//     代理认证凭据与 Basic Auth 凭据绝不写入 URL 或日志。
package iplibhttp

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/outboundhttp"
)

const (
	defaultMaxRedirects = 5
	defaultUserAgent    = "JiuZhang-WDSP-IPLib/2.0"
)

// 哨兵错误。
var (
	ErrOfflineOnly      = errors.New("当前来源模式为纯离线（OFFLINE_ONLY），禁止发起出站下载")
	ErrResponseTooLarge = errors.New("上游响应体积超过允许上限")
)

// HTTPStatusError 表示上游返回了非预期 HTTP 状态码（如 DB-IP 月初 404 回退判断用）。
type HTTPStatusError struct {
	StatusCode int
	URL        string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("上游返回 HTTP %d（%s）", e.StatusCode, e.URL)
}

// OfficialHosts 是 OFFICIAL 模式硬编码允许的官方主机白名单（不可通过设置扩大）。
var OfficialHosts = map[string]bool{
	"download.db-ip.com":        true,
	"download.maxmind.com":      true,
	"raw.githubusercontent.com": true,
	"github.com":                true,
	"feodotracker.abuse.ch":     true,
	"www.spamhaus.org":          true,
	"rules.emergingthreats.net": true,
}

// OfficialHostPathPrefixes 限定特定官方主机在 OFFICIAL 模式下允许访问的路径前缀（防同域非清单路径滥用）。
var OfficialHostPathPrefixes = map[string][]string{
	"www.spamhaus.org":          {"/drop/"},
	"rules.emergingthreats.net": {"/blockrules/"},
}

// IsOfficialHost 判断主机名是否命中官方硬编码白名单（大小写不敏感，容忍末尾根点）。
func IsOfficialHost(host string) bool {
	return OfficialHosts[normalizeHost(host)]
}

// IsOfficialURLAllowed 判断主机与路径是否满足 OFFICIAL 模式硬编码主机及路径前缀白名单。
func IsOfficialURLAllowed(host, urlPath string) bool {
	norm := normalizeHost(host)
	if !OfficialHosts[norm] {
		return false
	}
	prefixes, restricted := OfficialHostPathPrefixes[norm]
	if !restricted {
		return true
	}
	if strings.Contains(urlPath, "\\") {
		return false
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(urlPath, "/"))
	for _, p := range prefixes {
		if strings.HasPrefix(cleaned, p) {
			return true
		}
	}
	return false
}

var (
	cloudMetadataCIDRs = mustParseCIDRs([]string{
		"169.254.169.254/32", // AWS/GCP/Azure IPv4 元数据
		"169.254.170.2/32",   // AWS ECS 任务元数据
		"100.100.100.200/32", // 阿里云元数据
		"fd00:ec2::254/128",  // AWS IPv6 元数据
	})
	cloudMetadataHosts = map[string]bool{
		"metadata.google.internal": true,
		"metadata.goog":            true,
		"metadata.azure.internal":  true,
	}
	crossHostStripHeaders = []string{
		"Authorization",
		"Proxy-Authorization",
		"Cookie",
		"X-App-Key",
		"X-Sign",
	}
)

func mustParseCIDRs(list []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(list))
	for _, s := range list {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic("invalid CIDR: " + s)
		}
		out = append(out, n)
	}
	return out
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func isCloudMetadataIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range cloudMetadataCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isCloudMetadataHost(host string) bool {
	return cloudMetadataHosts[normalizeHost(host)]
}

func isLocalhostName(host string) bool {
	h := normalizeHost(host)
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}

// FetchRequest 描述一次受控出站下载请求。
type FetchRequest struct {
	SourceMode   string // OFFLINE_ONLY | OFFICIAL | CUSTOM_URL
	URL          string
	ETag         string // 可选 If-None-Match
	LastModified string // 可选 If-Modified-Since
	BasicUser    string // 可选 HTTP Basic Auth 用户名（如 MaxMind Account ID）
	BasicPass    string // 可选 HTTP Basic Auth 密码（绝不写日志）
	MaxBytes     int64  // 可选响应体硬上限（<=0 不额外限流）
	UserAgent    string // 可选，缺省 defaultUserAgent
}

// FetchResult 描述一次受控出站下载结果。
// NotModified 为 false 且 Body 非空时，调用方必须关闭 Body。
type FetchResult struct {
	StatusCode    int
	NotModified   bool
	Body          io.ReadCloser
	ContentLength int64
	ETag          string
	LastModified  string
	Filename      string
	FinalURL      string
}

// Downloader 是可复用的 IP 库受控出站下载器（并发安全，每次请求热读最新 system_settings）。
type Downloader struct {
	settings SettingsReader
	cipher   SecretCipher
	resolver outboundhttp.Resolver

	// 仅供本包单元测试覆盖（生产默认 nil/空，保持公网严格策略与系统根证书）。
	tlsConfig         *tls.Config
	officialAllowlist string
}

// NewDownloader 创建 IP 库受控出站下载器。
func NewDownloader(settings SettingsReader, cipher SecretCipher) *Downloader {
	return &Downloader{
		settings: settings,
		cipher:   cipher,
	}
}

// SetResolver 注入自定义 DNS 解析器（生产默认 net.DefaultResolver）。
func (d *Downloader) SetResolver(r outboundhttp.Resolver) *Downloader {
	d.resolver = r
	return d
}

func (d *Downloader) effectiveResolver() outboundhttp.Resolver {
	if d != nil && d.resolver != nil {
		return d.resolver
	}
	return net.DefaultResolver
}

// ValidateTargetURL 执行保存期/运行期目标 URL SSRF 与策略校验。
func (d *Downloader) ValidateTargetURL(ctx context.Context, sourceMode, rawURL string) error {
	cfg := LoadSettings(ctx, d.settings)
	_, err := d.validateTargetWithSettings(ctx, cfg, sourceMode, rawURL, true)
	return err
}

func (d *Downloader) validateTargetWithSettings(
	ctx context.Context,
	cfg OutboundSettings,
	sourceMode, rawURL string,
	isInitialHop bool,
) (*url.URL, error) {
	mode := strings.ToUpper(strings.TrimSpace(sourceMode))
	switch mode {
	case SourceModeOfflineOnly:
		return nil, ErrOfflineOnly
	case SourceModeOfficial, SourceModeCustomURL:
	default:
		return nil, fmt.Errorf("%w: 不支持的来源模式 %q", outboundhttp.ErrDenied, sourceMode)
	}

	u, err := outboundhttp.ParseURL(rawURL)
	if err != nil {
		return nil, err
	}
	host := normalizeHost(u.Hostname())
	if isCloudMetadataHost(host) {
		return nil, fmt.Errorf("%w: 禁止访问云元数据主机 %s", outboundhttp.ErrDenied, host)
	}

	if mode == SourceModeOfficial {
		if u.Scheme != "https" {
			return nil, fmt.Errorf("%w: 官方源仅允许 https 协议", outboundhttp.ErrDenied)
		}
		if isInitialHop {
			if !IsOfficialHost(host) {
				return nil, fmt.Errorf("%w: 官方源主机 %s 不在硬编码白名单内", outboundhttp.ErrDenied, host)
			}
			if !IsOfficialURLAllowed(host, u.Path) {
				return nil, fmt.Errorf("%w: 官方源路径 %s 不在主机 %s 允许的路径前缀白名单内", outboundhttp.ErrDenied, u.Path, host)
			}
		}
		if isLocalhostName(host) {
			return nil, fmt.Errorf("%w: 官方源禁止访问本地回环主机", outboundhttp.ErrDenied)
		}
	}

	resolver := d.effectiveResolver()
	allowHosts, allowCIDRs, err := parseAllowlistEntries(cfg.OutboundAllowlist)
	if err != nil {
		return nil, fmt.Errorf("%w: outbound_allowlist 配置非法: %v", outboundhttp.ErrDenied, err)
	}

	// 若配置了正向代理，先校验代理自身，再对目标做方案/主机/IP 安全校验（允许目标外网域名交由代理解析）。
	if strings.TrimSpace(cfg.ProxyURL) != "" {
		if _, err := ValidateProxyURL(ctx, cfg.ProxyURL, resolver, false); err != nil {
			return nil, err
		}
		if err := d.validateProxyTarget(ctx, cfg, mode, u, allowHosts, allowCIDRs, resolver); err != nil {
			return nil, err
		}
		return u, nil
	}

	// 直连模式：构造 outboundhttp.Policy 完整校验公网/允许列表与 DNS 解析结果。
	policyAllowlist := ""
	if mode == SourceModeOfficial {
		policyAllowlist = d.officialAllowlist
	} else {
		policyAllowlist = cfg.OutboundAllowlist
	}
	policy, err := outboundhttp.NewPolicy(outboundhttp.Options{
		Timeout:      time.Duration(cfg.HTTPTimeoutSeconds) * time.Second,
		MaxRedirects: defaultMaxRedirects,
		Resolver:     resolver,
		Allowlist:    policyAllowlist,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: 构造出站策略失败: %v", outboundhttp.ErrDenied, err)
	}
	if _, err := policy.ValidateURL(ctx, u.String()); err != nil {
		return nil, err
	}

	if mode == SourceModeCustomURL && u.Scheme == "http" {
		if !cfg.AllowInsecureHTTPMirror {
			return nil, fmt.Errorf("%w: 自定义源默认强制 https；如需明文 http 内网镜像请先开启 allow_insecure_http_mirror 并登记白名单", outboundhttp.ErrDenied)
		}
		if err := ensureTargetMatchesAllowlist(ctx, host, allowHosts, allowCIDRs, resolver, true); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// validateProxyTarget 在正向代理模式下于拨号代理前对目标 URL 执行方案、主机与地址校验。
func (d *Downloader) validateProxyTarget(
	ctx context.Context,
	cfg OutboundSettings,
	mode string,
	u *url.URL,
	allowHosts map[string]bool,
	allowCIDRs []*net.IPNet,
	resolver outboundhttp.Resolver,
) error {
	host := normalizeHost(u.Hostname())

	if mode == SourceModeCustomURL && u.Scheme == "http" {
		if !cfg.AllowInsecureHTTPMirror {
			return fmt.Errorf("%w: 自定义源默认强制 https；如需明文 http 内网镜像请先开启 allow_insecure_http_mirror 并登记白名单", outboundhttp.ErrDenied)
		}
		if err := ensureTargetMatchesAllowlist(ctx, host, allowHosts, allowCIDRs, resolver, false); err != nil {
			return err
		}
	}

	policyAllowlist := ""
	if mode == SourceModeOfficial {
		policyAllowlist = d.officialAllowlist
	} else {
		policyAllowlist = cfg.OutboundAllowlist
	}
	policy, err := outboundhttp.NewPolicy(outboundhttp.Options{
		Resolver:  resolver,
		Allowlist: policyAllowlist,
	})
	if err != nil {
		return fmt.Errorf("%w: 构造出站策略失败: %v", outboundhttp.ErrDenied, err)
	}

	// 目标为字面量 IP 时无论是否走代理都必须严格本地校验。
	if ip := net.ParseIP(host); ip != nil {
		return policy.CheckIP(ip)
	}
	if isLocalhostName(host) && !(mode == SourceModeCustomURL && allowHosts[host]) {
		return fmt.Errorf("%w: 禁止通过代理访问本地回环主机 %s", outboundhttp.ErrDenied, host)
	}

	// 目标为域名时尝试短超时本地解析：若可解析则拦截任何云元数据或未放行的私网地址；
	// 若本地无外网 DNS（隔离网段依赖代理解析），放行合法公网域名交由代理解析。
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ips, err := resolver.LookupIP(lookupCtx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil
	}
	if mode == SourceModeCustomURL && allowHosts[host] {
		for _, ip := range ips {
			if isCloudMetadataIP(ip) {
				return fmt.Errorf("%w: 主机名 %s 解析到云元数据地址", outboundhttp.ErrDenied, host)
			}
		}
		return nil
	}
	for _, ip := range ips {
		if err := policy.CheckIP(ip); err != nil {
			return err
		}
	}
	return nil
}

// Fetch 发起一次受控出站 GET 请求（支持条件请求 ETag/Last-Modified 与可选 Basic Auth）。
func (d *Downloader) Fetch(ctx context.Context, req FetchRequest) (*FetchResult, error) {
	cfg := LoadSettings(ctx, d.settings)
	mode := strings.ToUpper(strings.TrimSpace(req.SourceMode))

	initialURL, err := d.validateTargetWithSettings(ctx, cfg, mode, req.URL, true)
	if err != nil {
		return nil, err
	}

	client, err := d.buildHTTPClient(ctx, cfg, mode)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, initialURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("构造下载请求失败: %w", err)
	}
	ua := strings.TrimSpace(req.UserAgent)
	if ua == "" {
		ua = defaultUserAgent
	}
	httpReq.Header.Set("User-Agent", ua)
	if etag := strings.TrimSpace(req.ETag); etag != "" {
		httpReq.Header.Set("If-None-Match", etag)
	}
	if lm := strings.TrimSpace(req.LastModified); lm != "" {
		httpReq.Header.Set("If-Modified-Since", lm)
	}
	if req.BasicUser != "" || req.BasicPass != "" {
		httpReq.SetBasicAuth(req.BasicUser, req.BasicPass)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, sanitizeSecretError(err, req.BasicPass)
	}

	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = redactURLForLog(resp.Request.URL)
	}
	etag := strings.TrimSpace(resp.Header.Get("ETag"))
	lastMod := strings.TrimSpace(resp.Header.Get("Last-Modified"))

	if resp.StatusCode == http.StatusNotModified {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
		return &FetchResult{
			StatusCode:   http.StatusNotModified,
			NotModified:  true,
			ETag:         etag,
			LastModified: lastMod,
			FinalURL:     finalURL,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
		return nil, &HTTPStatusError{
			StatusCode: resp.StatusCode,
			URL:        finalURL,
		}
	}

	if req.MaxBytes > 0 && resp.ContentLength > req.MaxBytes {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: Content-Length=%d 超过上限 %d", ErrResponseTooLarge, resp.ContentLength, req.MaxBytes)
	}

	body := resp.Body
	if req.MaxBytes > 0 {
		body = &limitReadCloser{rc: resp.Body, limit: req.MaxBytes}
	}

	filename := extractFilename(resp)
	return &FetchResult{
		StatusCode:    resp.StatusCode,
		NotModified:   false,
		Body:          body,
		ContentLength: resp.ContentLength,
		ETag:          etag,
		LastModified:  lastMod,
		Filename:      filename,
		FinalURL:      finalURL,
	}, nil
}

func (d *Downloader) buildHTTPClient(ctx context.Context, cfg OutboundSettings, mode string) (*http.Client, error) {
	timeout := time.Duration(cfg.HTTPTimeoutSeconds) * time.Second
	resolver := d.effectiveResolver()
	allowHosts, allowCIDRs, err := parseAllowlistEntries(cfg.OutboundAllowlist)
	if err != nil {
		return nil, fmt.Errorf("%w: outbound_allowlist 配置非法: %v", outboundhttp.ErrDenied, err)
	}

	var rt http.RoundTripper
	if strings.TrimSpace(cfg.ProxyURL) != "" {
		proxyRT, err := d.buildProxyRoundTripper(ctx, cfg, timeout, resolver)
		if err != nil {
			return nil, err
		}
		rt = proxyRT
	} else {
		directRT, err := d.buildDirectRoundTripper(cfg, mode, timeout, resolver, allowHosts, allowCIDRs)
		if err != nil {
			return nil, err
		}
		rt = directRT
	}

	return &http.Client{
		Transport: rt,
		Timeout:   timeout,
		CheckRedirect: func(nextReq *http.Request, via []*http.Request) error {
			if len(via) >= defaultMaxRedirects {
				return fmt.Errorf("%w: 重定向次数超过上限 %d", outboundhttp.ErrDenied, defaultMaxRedirects)
			}
			if _, err := d.validateTargetWithSettings(nextReq.Context(), cfg, mode, nextReq.URL.String(), false); err != nil {
				return err
			}
			// 跨源（协议/主机/端口任一变化）重定向时剥离全部认证与 Cookie 头（防止 MaxMind 302 泄露 Basic Auth 给 R2/S3，
			// 并防止多次跳转先跳至第三方再回跳时重附凭据）。
			crossedOrigin := !sameRedirectOrigin(nextReq.URL, via[0].URL)
			if !crossedOrigin {
				for _, prev := range via[1:] {
					if !sameRedirectOrigin(prev.URL, via[0].URL) {
						crossedOrigin = true
						break
					}
				}
			}
			if crossedOrigin {
				for _, h := range crossHostStripHeaders {
					nextReq.Header.Del(h)
				}
			}
			return nil
		},
	}, nil
}

func (d *Downloader) buildDirectRoundTripper(
	cfg OutboundSettings,
	mode string,
	timeout time.Duration,
	resolver outboundhttp.Resolver,
	allowHosts map[string]bool,
	allowCIDRs []*net.IPNet,
) (http.RoundTripper, error) {
	policyAllowlist := ""
	if mode == SourceModeOfficial {
		policyAllowlist = d.officialAllowlist
	} else {
		policyAllowlist = cfg.OutboundAllowlist
	}
	policy, err := outboundhttp.NewPolicy(outboundhttp.Options{
		Timeout:      timeout,
		MaxRedirects: defaultMaxRedirects,
		Resolver:     resolver,
		Allowlist:    policyAllowlist,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: 构造出站策略失败: %v", outboundhttp.ErrDenied, err)
	}

	httpsTr := policy.Transport()
	if d.tlsConfig != nil {
		httpsTr.TLSClientConfig = d.tlsConfig.Clone()
	}

	if mode != SourceModeCustomURL || !cfg.AllowInsecureHTTPMirror {
		return httpsTr, nil
	}

	// 对于 CUSTOM_URL 的明文 http:// 镜像请求，拨号阶段独立复检目标仍在 allowlist 内（防 DNS 重绑定回退到公网明文 HTTP）。
	dialer := &net.Dialer{Timeout: timeout}
	httpMirrorTr := &http.Transport{
		DisableKeepAlives:   true,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("%w: 地址解析失败", outboundhttp.ErrDenied)
			}
			normHost := normalizeHost(host)
			if isCloudMetadataHost(normHost) {
				return nil, fmt.Errorf("%w: 禁止访问云元数据主机", outboundhttp.ErrDenied)
			}
			if allowHosts[normHost] {
				ips, err := resolver.LookupIP(ctx, "ip", normHost)
				if err != nil || len(ips) == 0 {
					return nil, fmt.Errorf("%w: 主机名 %s 解析失败", outboundhttp.ErrDenied, normHost)
				}
				for _, ip := range ips {
					if isCloudMetadataIP(ip) {
						return nil, fmt.Errorf("%w: 主机名 %s 解析到云元数据地址", outboundhttp.ErrDenied, normHost)
					}
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
			}
			if ip := net.ParseIP(normHost); ip != nil {
				if isCloudMetadataIP(ip) || !ipInCIDRs(ip, allowCIDRs) {
					return nil, fmt.Errorf("%w: 明文 http 镜像目标 %s 不在 allowlist 内", outboundhttp.ErrDenied, ip)
				}
				return dialer.DialContext(ctx, network, addr)
			}
			ips, err := resolver.LookupIP(ctx, "ip", normHost)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("%w: 主机名 %s 解析失败", outboundhttp.ErrDenied, normHost)
			}
			for _, ip := range ips {
				if isCloudMetadataIP(ip) || !ipInCIDRs(ip, allowCIDRs) {
					return nil, fmt.Errorf("%w: 明文 http 镜像目标 %s(%s) 不在 allowlist 内", outboundhttp.ErrDenied, normHost, ip)
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		},
	}

	return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL != nil && strings.EqualFold(r.URL.Scheme, "http") {
			return httpMirrorTr.RoundTrip(r)
		}
		return httpsTr.RoundTrip(r)
	}), nil
}

func (d *Downloader) buildProxyRoundTripper(
	ctx context.Context,
	cfg OutboundSettings,
	timeout time.Duration,
	resolver outboundhttp.Resolver,
) (http.RoundTripper, error) {
	proxyURL, err := ValidateProxyURL(ctx, cfg.ProxyURL, resolver, true)
	if err != nil {
		return nil, err
	}

	var proxyAuthHeader string
	if cfg.ProxyAuthEncrypted != "" {
		if d.cipher == nil {
			return nil, ErrCipherUnavailable
		}
		plain, err := d.cipher.Decrypt(cfg.ProxyAuthEncrypted)
		if err != nil {
			return nil, fmt.Errorf("解密正向代理认证凭据失败: %w", err)
		}
		if err := ValidateProxyAuth(plain); err != nil {
			return nil, fmt.Errorf("已保存的正向代理认证凭据格式非法: %w", err)
		}
		proxyAuthHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(plain))
	}

	cleanProxyURL := *proxyURL
	cleanProxyURL.User = nil

	dialer := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		DisableKeepAlives:   true,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: timeout,
		Proxy: func(*http.Request) (*url.URL, error) {
			u := cleanProxyURL
			return &u, nil
		},
		DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("%w: 代理地址解析失败", outboundhttp.ErrDenied)
			}
			if isCloudMetadataHost(host) {
				return nil, fmt.Errorf("%w: 代理地址禁止指向云元数据主机", outboundhttp.ErrDenied)
			}
			if ip := net.ParseIP(host); ip != nil {
				if err := checkProxyIP(ip); err != nil {
					return nil, err
				}
				return dialer.DialContext(dialCtx, network, addr)
			}
			ips, err := resolver.LookupIP(dialCtx, "ip", host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("%w: 代理主机名 %s 解析失败", outboundhttp.ErrDenied, host)
			}
			for _, ip := range ips {
				if err := checkProxyIP(ip); err != nil {
					return nil, err
				}
			}
			return dialer.DialContext(dialCtx, network, net.JoinHostPort(ips[0].String(), port))
		},
	}
	if d.tlsConfig != nil {
		tr.TLSClientConfig = d.tlsConfig.Clone()
	}
	if proxyAuthHeader != "" {
		tr.ProxyConnectHeader = http.Header{
			"Proxy-Authorization": []string{proxyAuthHeader},
		}
	}

	return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if proxyAuthHeader != "" && r.URL != nil && strings.EqualFold(r.URL.Scheme, "http") {
			cloned := r.Clone(r.Context())
			cloned.Header.Set("Proxy-Authorization", proxyAuthHeader)
			return tr.RoundTrip(cloned)
		}
		return tr.RoundTrip(r)
	}), nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func parseAllowlistEntries(raw string) (map[string]bool, []*net.IPNet, error) {
	hosts := map[string]bool{}
	var cidrs []*net.IPNet
	for _, tok := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if _, n, err := net.ParseCIDR(tok); err == nil {
			cidrs = append(cidrs, n)
			continue
		}
		host := normalizeHost(tok)
		if strings.Contains(tok, "/") || net.ParseIP(host) != nil || host == "" || len(host) > 253 {
			return nil, nil, fmt.Errorf("allowlist 项非法（须为 CIDR 或主机名）: %q", tok)
		}
		hosts[host] = true
	}
	return hosts, cidrs, nil
}

func ipInCIDRs(ip net.IP, cidrs []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func ensureTargetMatchesAllowlist(
	ctx context.Context,
	host string,
	allowHosts map[string]bool,
	allowCIDRs []*net.IPNet,
	resolver outboundhttp.Resolver,
	requireDNS bool,
) error {
	norm := normalizeHost(host)
	if isCloudMetadataHost(norm) {
		return fmt.Errorf("%w: 禁止访问云元数据主机 %s", outboundhttp.ErrDenied, norm)
	}
	if allowHosts[norm] {
		return nil
	}
	if ip := net.ParseIP(norm); ip != nil {
		if isCloudMetadataIP(ip) {
			return fmt.Errorf("%w: 禁止访问云元数据地址 %s", outboundhttp.ErrDenied, ip)
		}
		if ipInCIDRs(ip, allowCIDRs) {
			return nil
		}
		return fmt.Errorf("%w: 明文 http 仅允许命中 outbound_allowlist 的内网镜像目标（%s 未命中）", outboundhttp.ErrDenied, ip)
	}
	if len(allowCIDRs) == 0 {
		return fmt.Errorf("%w: 明文 http 仅允许命中 outbound_allowlist 的内网镜像目标（%s 未命中）", outboundhttp.ErrDenied, norm)
	}
	lookupCtx := ctx
	var cancel context.CancelFunc
	if !requireDNS {
		lookupCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
	}
	ips, err := resolver.LookupIP(lookupCtx, "ip", norm)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("%w: 明文 http 目标 %s 未命中精确主机白名单且无法解析验证 CIDR 白名单", outboundhttp.ErrDenied, norm)
	}
	for _, ip := range ips {
		if isCloudMetadataIP(ip) {
			return fmt.Errorf("%w: 目标 %s 解析到云元数据地址", outboundhttp.ErrDenied, norm)
		}
		if !ipInCIDRs(ip, allowCIDRs) {
			return fmt.Errorf("%w: 明文 http 目标 %s(%s) 不在 outbound_allowlist 内", outboundhttp.ErrDenied, norm, ip)
		}
	}
	return nil
}

func sameRedirectOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		normalizedSchemePort(a) == normalizedSchemePort(b)
}

func normalizedSchemePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

func extractFilename(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	if cd := strings.TrimSpace(resp.Header.Get("Content-Disposition")); cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil {
			if fn := strings.TrimSpace(params["filename"]); fn != "" {
				base := filepath.Base(strings.ReplaceAll(fn, "\\", "/"))
				if base != "." && base != "/" && base != "" {
					return base
				}
			}
		}
	}
	if resp.Request != nil && resp.Request.URL != nil {
		base := path.Base(resp.Request.URL.Path)
		if base != "." && base != "/" && base != "" {
			return base
		}
	}
	return ""
}

func redactURLForLog(u *url.URL) string {
	if u == nil {
		return ""
	}
	cp := *u
	cp.User = nil
	cp.RawQuery = ""
	cp.Fragment = ""
	return cp.String()
}

func sanitizeSecretError(err error, secret string) error {
	if err == nil || secret == "" {
		return err
	}
	msg := err.Error()
	if !strings.Contains(msg, secret) {
		return err
	}
	return errors.New(strings.ReplaceAll(msg, secret, "********"))
}

type limitReadCloser struct {
	rc    io.ReadCloser
	read  int64
	limit int64
}

func (l *limitReadCloser) Read(p []byte) (int, error) {
	if l.read > l.limit {
		return 0, ErrResponseTooLarge
	}
	remaining := l.limit - l.read + 1
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := l.rc.Read(p)
	l.read += int64(n)
	if l.read > l.limit {
		return 0, ErrResponseTooLarge
	}
	return n, err
}

func (l *limitReadCloser) Close() error {
	return l.rc.Close()
}
