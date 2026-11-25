// tls_config.go 应用级国密/国际协议自识别、TLS/HTTP 协议降级与 SSL 加密会话分析策略模型。
package gatewayconfig

import (
	"fmt"
	"strings"
)

// TLS 协议模式（站点级）
const (
	TLSProtocolModeAutoDetect        = "AUTO_DETECT"        // 同端口自动识别通用 TLS 与国密 TLCP
	TLSProtocolModeInternationalOnly = "INTERNATIONAL_ONLY" // 仅通用国际 TLS
	TLSProtocolModeGMOnly            = "GM_ONLY"            // 仅国密 TLCP 1.1
)

// 支持的可协商 TLS/TLCP 协议版本
const (
	TLSVersionTLCP11 = "TLCP1.1"
	TLSVersion10     = "TLS1.0"
	TLSVersion11     = "TLS1.1"
	TLSVersion12     = "TLS1.2"
	TLSVersion13     = "TLS1.3"
)

// 弱协议会话分析/阻断识别目标（ClientHello 预读层识别并记录/阻断）
const (
	LegacySSLv2   = "SSLv2"
	LegacySSLv2v3 = "SSLv2_v3"
	LegacySSLv3   = "SSLv3"
)

// 支持的接入/回源 HTTP 协议版本
const (
	HTTPVersion10   = "HTTP/1.0"
	HTTPVersion11   = "HTTP/1.1"
	HTTPVersion2    = "HTTP/2"
	UpstreamHTTPAuto = "AUTO"
)

// AppTLSConfig 是单个应用的 TLS/国密、HTTP 协议降级、回源 SSL 加载与会话分析策略。
type AppTLSConfig struct {
	TLSProtocolMode           string   `json:"tls_protocol_mode"`
	AllowedTLSVersions        []string `json:"allowed_tls_versions"`
	LegacySSLAnalysisVersions []string `json:"legacy_ssl_analysis_versions"`
	HTTPVersions              []string `json:"http_versions"`
	UpstreamHTTPVersion       string   `json:"upstream_http_version"`
	UpstreamTLSMinVersion     string   `json:"upstream_tls_min_version"`
	SessionAnalysisEnabled    bool     `json:"session_analysis_enabled"`
}

// DefaultAppTLSConfig 返回默认站点 TLS/HTTP 协议策略（安全缺省：自识别开启、默认 TLS 1.2/1.3、
// 弱协议 SSLv2/SSLv2_v3/SSLv3 识别阻断全开、HTTP 1.0/1.1/2 全开、回源自动协商 + TLS 1.2）。
func DefaultAppTLSConfig() *AppTLSConfig {
	return &AppTLSConfig{
		TLSProtocolMode:           TLSProtocolModeAutoDetect,
		AllowedTLSVersions:        []string{TLSVersion12, TLSVersion13},
		LegacySSLAnalysisVersions: []string{LegacySSLv2, LegacySSLv2v3, LegacySSLv3},
		HTTPVersions:              []string{HTTPVersion10, HTTPVersion11, HTTPVersion2},
		UpstreamHTTPVersion:       UpstreamHTTPAuto,
		UpstreamTLSMinVersion:     TLSVersion12,
		SessionAnalysisEnabled:    true,
	}
}

// CloneAppTLSConfig 深拷贝 AppTLSConfig。
func CloneAppTLSConfig(cfg *AppTLSConfig) *AppTLSConfig {
	if cfg == nil {
		return nil
	}
	out := *cfg
	out.AllowedTLSVersions = append([]string(nil), cfg.AllowedTLSVersions...)
	out.LegacySSLAnalysisVersions = append([]string(nil), cfg.LegacySSLAnalysisVersions...)
	out.HTTPVersions = append([]string(nil), cfg.HTTPVersions...)
	return &out
}

var (
	validTLSProtocolModes = map[string]bool{
		TLSProtocolModeAutoDetect:        true,
		TLSProtocolModeInternationalOnly: true,
		TLSProtocolModeGMOnly:            true,
	}
	validAllowedTLSVersions = map[string]bool{
		TLSVersionTLCP11: true,
		TLSVersion10:     true,
		TLSVersion11:     true,
		TLSVersion12:     true,
		TLSVersion13:     true,
	}
	validLegacySSLVersions = map[string]bool{
		LegacySSLv2:   true,
		LegacySSLv2v3: true,
		LegacySSLv3:   true,
	}
	validHTTPVersions = map[string]bool{
		HTTPVersion10: true,
		HTTPVersion11: true,
		HTTPVersion2:  true,
	}
	validUpstreamHTTPVersions = map[string]bool{
		UpstreamHTTPAuto: true,
		HTTPVersion10:    true,
		HTTPVersion11:    true,
		HTTPVersion2:     true,
	}
	validUpstreamTLSMinVersions = map[string]bool{
		TLSVersion10: true,
		TLSVersion11: true,
		TLSVersion12: true,
		TLSVersion13: true,
	}
)

// NormalizeAndValidateAppTLSConfig 规范化并严格校验站点协议配置。
func NormalizeAndValidateAppTLSConfig(cfg *AppTLSConfig) error {
	if cfg == nil {
		return fmt.Errorf("TLS 协议配置不能为空")
	}
	cfg.TLSProtocolMode = strings.ToUpper(strings.TrimSpace(cfg.TLSProtocolMode))
	if cfg.TLSProtocolMode == "" {
		cfg.TLSProtocolMode = TLSProtocolModeAutoDetect
	}
	if !validTLSProtocolModes[cfg.TLSProtocolMode] {
		return fmt.Errorf("无效的 TLS 协议模式: %s", cfg.TLSProtocolMode)
	}

	var err error
	cfg.AllowedTLSVersions, err = dedupeAndValidate(cfg.AllowedTLSVersions, validAllowedTLSVersions, "allowed_tls_versions")
	if err != nil {
		return err
	}
	if len(cfg.AllowedTLSVersions) == 0 {
		return fmt.Errorf("allowed_tls_versions 至少启用一个 TLS/TLCP 版本")
	}

	hasGM := false
	hasIntl := false
	for _, v := range cfg.AllowedTLSVersions {
		if v == TLSVersionTLCP11 {
			hasGM = true
		} else {
			hasIntl = true
		}
	}
	switch cfg.TLSProtocolMode {
	case TLSProtocolModeGMOnly:
		if !hasGM {
			return fmt.Errorf("仅国密模式（GM_ONLY）必须在 allowed_tls_versions 中启用 TLCP1.1")
		}
	case TLSProtocolModeInternationalOnly:
		if !hasIntl {
			return fmt.Errorf("仅国际模式（INTERNATIONAL_ONLY）必须至少启用一个国际 TLS 版本")
		}
	}

	cfg.LegacySSLAnalysisVersions, err = dedupeAndValidate(cfg.LegacySSLAnalysisVersions, validLegacySSLVersions, "legacy_ssl_analysis_versions")
	if err != nil {
		return err
	}

	cfg.HTTPVersions, err = dedupeAndValidate(cfg.HTTPVersions, validHTTPVersions, "http_versions")
	if err != nil {
		return err
	}
	if len(cfg.HTTPVersions) == 0 {
		return fmt.Errorf("http_versions 至少启用一个 HTTP 协议版本")
	}

	cfg.UpstreamHTTPVersion = strings.ToUpper(strings.TrimSpace(cfg.UpstreamHTTPVersion))
	if cfg.UpstreamHTTPVersion == "" {
		cfg.UpstreamHTTPVersion = UpstreamHTTPAuto
	}
	if !validUpstreamHTTPVersions[cfg.UpstreamHTTPVersion] {
		return fmt.Errorf("无效的回源 HTTP 协议版本: %s", cfg.UpstreamHTTPVersion)
	}

	cfg.UpstreamTLSMinVersion = strings.ToUpper(strings.TrimSpace(cfg.UpstreamTLSMinVersion))
	if cfg.UpstreamTLSMinVersion == "" {
		cfg.UpstreamTLSMinVersion = TLSVersion12
	}
	if !validUpstreamTLSMinVersions[cfg.UpstreamTLSMinVersion] {
		return fmt.Errorf("无效的回源 TLS 最低版本: %s", cfg.UpstreamTLSMinVersion)
	}
	return nil
}

func dedupeAndValidate(items []string, allow map[string]bool, field string) ([]string, error) {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, raw := range items {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if !allow[v] {
			return nil, fmt.Errorf("%s 包含不支持的值: %s", field, v)
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out, nil
}
