// Package iplibhttp 提供 IP 库（GeoIP 归属地库与威胁情报 IP 黑名单库）共用的
// 受控出站 HTTP 下载器、SSRF/代理防护策略与出站设置管理接口。
package iplibhttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/outboundhttp"
)

// system_settings 组 ip_library 的配置键与数值范围（对应迁移 000256）。
const (
	SettingsGroup              = "ip_library"
	KeyOutboundAllowlist       = "outbound_allowlist"
	KeyAllowInsecureHTTPMirror = "allow_insecure_http_mirror"
	KeyProxyURL                = "proxy_url"
	KeyProxyAuthEncrypted      = "proxy_auth_encrypted"
	KeyHTTPTimeoutSeconds      = "http_timeout_seconds"

	DefaultHTTPTimeoutSeconds = 120
	MinHTTPTimeoutSeconds     = 15
	MaxHTTPTimeoutSeconds     = 600

	maxAllowlistBytes = 2048
	maxProxyURLBytes  = 512
	maxProxyAuthBytes = 512
)

// 来源模式词表（与迁移 000256 geoip_slot_configs / threat_intel_feeds CHECK 约束一致）。
const (
	SourceModeOfflineOnly = "OFFLINE_ONLY"
	SourceModeOfficial    = "OFFICIAL"
	SourceModeCustomURL   = "CUSTOM_URL"
)

// ErrInvalidSettings 表示出站配置参数校验未通过。
var ErrInvalidSettings = errors.New("出站设置参数非法")

// ErrCipherUnavailable 表示未配置系统主密钥加密服务，无法安全保存或解密代理凭据。
var ErrCipherUnavailable = errors.New("系统主密钥加密服务未初始化，无法处理代理认证凭据")

// SettingsReader 是只读系统设置接口（*settings.Service 满足）。
type SettingsReader interface {
	GetString(ctx context.Context, group, key, def string) string
	GetBool(ctx context.Context, group, key string, def bool) bool
	GetInt(ctx context.Context, group, key string, def int) int
}

// SettingsStore 是可读写系统设置接口（*settings.Service 满足）。
type SettingsStore interface {
	SettingsReader
	UpsertString(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) error
	UpsertSensitiveString(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) error
	UpsertBool(ctx context.Context, group, key string, value bool, description string, operatorID uuid.UUID) error
}

// intSettingsUpserter 是可选的整数设置写入扩展接口。
type intSettingsUpserter interface {
	UpsertInt(ctx context.Context, group, key string, value int, description string, operatorID uuid.UUID) error
}

// SecretCipher 是对称加密接口（*encryption.Service 满足）。
type SecretCipher interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(encoded string) (string, error)
}

// OutboundSettings 表示 IP 库统一出站设置（敏感密文字段绝不序列化输出）。
type OutboundSettings struct {
	OutboundAllowlist       string `json:"outbound_allowlist"`
	AllowInsecureHTTPMirror bool   `json:"allow_insecure_http_mirror"`
	ProxyURL                string `json:"proxy_url"`
	HasProxyAuth            bool   `json:"has_proxy_auth"`
	HTTPTimeoutSeconds      int    `json:"http_timeout_seconds"`
	ProxyAuthEncrypted      string `json:"-"`
}

// UpdateOutboundSettingsRequest 是 PUT /api/v1/ip-libraries/outbound-settings 的请求体。
type UpdateOutboundSettingsRequest struct {
	OutboundAllowlist       string `json:"outbound_allowlist"`
	AllowInsecureHTTPMirror bool   `json:"allow_insecure_http_mirror"`
	ProxyURL                string `json:"proxy_url"`
	ProxyAuth               string `json:"proxy_auth,omitempty"`
	ClearProxyAuth          bool   `json:"clear_proxy_auth,omitempty"`
	HTTPTimeoutSeconds      *int   `json:"http_timeout_seconds,omitempty"`
}

// LoadSettings 从系统设置读取 ip_library 分组配置（缺失或越界回退默认值）。
func LoadSettings(ctx context.Context, r SettingsReader) OutboundSettings {
	out := OutboundSettings{
		HTTPTimeoutSeconds: DefaultHTTPTimeoutSeconds,
	}
	if r == nil {
		return out
	}
	out.OutboundAllowlist = strings.TrimSpace(r.GetString(ctx, SettingsGroup, KeyOutboundAllowlist, ""))
	out.AllowInsecureHTTPMirror = r.GetBool(ctx, SettingsGroup, KeyAllowInsecureHTTPMirror, false)
	out.ProxyURL = strings.TrimSpace(r.GetString(ctx, SettingsGroup, KeyProxyURL, ""))
	out.ProxyAuthEncrypted = strings.TrimSpace(r.GetString(ctx, SettingsGroup, KeyProxyAuthEncrypted, ""))
	out.HasProxyAuth = out.ProxyAuthEncrypted != ""

	timeout := DefaultHTTPTimeoutSeconds
	// 兼容迁移 000256 初始 JSON number 种子与运行期 UpsertString 写入的字符串整数。
	if raw := strings.TrimSpace(r.GetString(ctx, SettingsGroup, KeyHTTPTimeoutSeconds, "")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			timeout = n
		}
	} else {
		timeout = r.GetInt(ctx, SettingsGroup, KeyHTTPTimeoutSeconds, DefaultHTTPTimeoutSeconds)
	}
	if timeout < MinHTTPTimeoutSeconds || timeout > MaxHTTPTimeoutSeconds {
		timeout = DefaultHTTPTimeoutSeconds
	}
	out.HTTPTimeoutSeconds = timeout
	return out
}

// SaveSettings 校验并持久化 ip_library 分组配置，返回脱敏后的最新配置及代理凭据变更标记。
func SaveSettings(
	ctx context.Context,
	store SettingsStore,
	cipher SecretCipher,
	resolver outboundhttp.Resolver,
	req UpdateOutboundSettingsRequest,
	operatorID uuid.UUID,
) (saved OutboundSettings, authUpdated bool, authCleared bool, err error) {
	if store == nil {
		return OutboundSettings{}, false, false, errors.New("settings store 未初始化")
	}

	cur := LoadSettings(ctx, store)

	allowlist := strings.TrimSpace(req.OutboundAllowlist)
	if len(allowlist) > maxAllowlistBytes {
		return OutboundSettings{}, false, false, fmt.Errorf("%w: outbound_allowlist 长度不能超过 %d 字节", ErrInvalidSettings, maxAllowlistBytes)
	}
	if _, err := outboundhttp.NewPolicy(outboundhttp.Options{Allowlist: allowlist}); err != nil {
		return OutboundSettings{}, false, false, fmt.Errorf("%w: outbound_allowlist 非法: %v", ErrInvalidSettings, err)
	}

	proxyURL := strings.TrimSpace(req.ProxyURL)
	if proxyURL != "" {
		if _, err := ValidateProxyURL(ctx, proxyURL, resolver, false); err != nil {
			return OutboundSettings{}, false, false, fmt.Errorf("%w: proxy_url 非法: %v", ErrInvalidSettings, err)
		}
	}

	timeout := cur.HTTPTimeoutSeconds
	if req.HTTPTimeoutSeconds != nil {
		timeout = *req.HTTPTimeoutSeconds
		if timeout < MinHTTPTimeoutSeconds || timeout > MaxHTTPTimeoutSeconds {
			return OutboundSettings{}, false, false, fmt.Errorf("%w: http_timeout_seconds 须在 %d-%d 秒之间",
				ErrInvalidSettings, MinHTTPTimeoutSeconds, MaxHTTPTimeoutSeconds)
		}
	}

	if req.ClearProxyAuth && req.ProxyAuth != "" {
		return OutboundSettings{}, false, false, fmt.Errorf("%w: 不能同时设置 proxy_auth 与 clear_proxy_auth", ErrInvalidSettings)
	}

	var encryptedProxyAuth string
	if req.ProxyAuth != "" {
		if err := ValidateProxyAuth(req.ProxyAuth); err != nil {
			return OutboundSettings{}, false, false, err
		}
		if cipher == nil {
			return OutboundSettings{}, false, false, ErrCipherUnavailable
		}
		enc, err := cipher.Encrypt(req.ProxyAuth)
		if err != nil {
			return OutboundSettings{}, false, false, fmt.Errorf("加密代理认证凭据失败: %w", err)
		}
		encryptedProxyAuth = enc
		authUpdated = true
	} else if req.ClearProxyAuth {
		authCleared = true
	}

	if err := store.UpsertString(ctx, SettingsGroup, KeyOutboundAllowlist, allowlist,
		"IP 库在线更新允许访问的内网镜像 CIDR 或精确主机名白名单（逗号分隔）", operatorID); err != nil {
		return OutboundSettings{}, false, false, err
	}
	if err := store.UpsertBool(ctx, SettingsGroup, KeyAllowInsecureHTTPMirror, req.AllowInsecureHTTPMirror,
		"是否允许已登记白名单的内网镜像源使用明文 HTTP（公网目标始终强制 HTTPS）", operatorID); err != nil {
		return OutboundSettings{}, false, false, err
	}
	if err := store.UpsertString(ctx, SettingsGroup, KeyProxyURL, proxyURL,
		"IP 库在线更新可选正向代理地址（如 http://proxy.corp.local:3128）", operatorID); err != nil {
		return OutboundSettings{}, false, false, err
	}
	if authUpdated {
		if err := store.UpsertSensitiveString(ctx, SettingsGroup, KeyProxyAuthEncrypted, encryptedProxyAuth,
			"IP 库在线更新正向代理认证凭据密文（user:pass 经系统主密钥加密）", operatorID); err != nil {
			return OutboundSettings{}, false, false, err
		}
	} else if authCleared {
		if err := store.UpsertSensitiveString(ctx, SettingsGroup, KeyProxyAuthEncrypted, "",
			"IP 库在线更新正向代理认证凭据密文（user:pass 经系统主密钥加密）", operatorID); err != nil {
			return OutboundSettings{}, false, false, err
		}
	}
	if err := upsertTimeoutSetting(ctx, store, timeout, operatorID); err != nil {
		return OutboundSettings{}, false, false, err
	}

	return LoadSettings(ctx, store), authUpdated, authCleared, nil
}

func upsertTimeoutSetting(ctx context.Context, store SettingsStore, timeout int, operatorID uuid.UUID) error {
	const desc = "IP 库在线下载单次请求超时时间（秒，范围 15–600）"
	if iu, ok := store.(intSettingsUpserter); ok {
		return iu.UpsertInt(ctx, SettingsGroup, KeyHTTPTimeoutSeconds, timeout, desc, operatorID)
	}
	return store.UpsertString(ctx, SettingsGroup, KeyHTTPTimeoutSeconds, strconv.Itoa(timeout), desc, operatorID)
}

// ValidateProxyAuth 校验正向代理认证串格式（须为 user:pass，禁止控制字符与换行）。
func ValidateProxyAuth(raw string) error {
	if len(raw) > maxProxyAuthBytes {
		return fmt.Errorf("%w: proxy_auth 长度不能超过 %d 字节", ErrInvalidSettings, maxProxyAuthBytes)
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return fmt.Errorf("%w: proxy_auth 不允许包含控制字符或换行符", ErrInvalidSettings)
		}
	}
	idx := strings.IndexByte(raw, ':')
	if idx <= 0 {
		return fmt.Errorf("%w: proxy_auth 须采用 user:pass 格式且用户名不能为空", ErrInvalidSettings)
	}
	return nil
}

// ValidateProxyURL 校验正向代理地址：
// 仅允许 http/https、无内嵌凭据、无 query/fragment/非根路径、硬拒绝云元数据地址。
// strictDNS=true 时要求域名必须成功解析且全部 IP 非云元数据/未指定/组播（拨号前使用）；
// strictDNS=false 时若解析成功同样拦截云元数据 IP，解析超时/失败允许延后至拨号期拦截（适配离线预配置）。
func ValidateProxyURL(ctx context.Context, raw string, resolver outboundhttp.Resolver, strictDNS bool) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	if len(trimmed) > maxProxyURLBytes {
		return nil, fmt.Errorf("%w: 代理地址长度超过 %d 字节", outboundhttp.ErrDenied, maxProxyURLBytes)
	}
	u, err := outboundhttp.ParseURL(trimmed)
	if err != nil {
		return nil, err
	}
	if u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("%w: 代理地址不允许包含路径、查询参数或片段", outboundhttp.ErrDenied)
	}
	host := u.Hostname()
	if isCloudMetadataHost(host) {
		return nil, fmt.Errorf("%w: 代理地址禁止指向云元数据主机 %s", outboundhttp.ErrDenied, host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if err := checkProxyIP(ip); err != nil {
			return nil, err
		}
		return u, nil
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	lookupCtx := ctx
	var cancel context.CancelFunc
	if !strictDNS {
		lookupCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
	}
	ips, err := resolver.LookupIP(lookupCtx, "ip", host)
	if err != nil || len(ips) == 0 {
		if strictDNS {
			return nil, fmt.Errorf("%w: 代理主机名 %s 解析失败", outboundhttp.ErrDenied, host)
		}
		return u, nil
	}
	for _, ip := range ips {
		if err := checkProxyIP(ip); err != nil {
			return nil, fmt.Errorf("%w: 代理主机名 %s 解析到禁止地址: %v", outboundhttp.ErrDenied, host, err)
		}
	}
	return u, nil
}

func checkProxyIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("%w: 代理地址为空", outboundhttp.ErrDenied)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if isCloudMetadataIP(ip) {
		return fmt.Errorf("%w: 代理地址禁止指向云元数据地址 %s", outboundhttp.ErrDenied, ip)
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("%w: 代理地址为保留/组播地址 %s", outboundhttp.ErrDenied, ip)
	}
	return nil
}
