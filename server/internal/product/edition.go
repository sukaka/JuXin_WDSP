// Package product 产品 edition 与 WDSP/API 能力开关（管理面与打包语义）。
// WAF 默认 edition=waf 且 API 动态防护关闭，保证与既有交付行为一致。
package product

import (
	"os"
	"strconv"
	"strings"
)

// Edition 产品形态。
type Edition string

const (
	// EditionWAF 纯 Web 应用防火墙（默认可发版形态）。
	EditionWAF Edition = "waf"
	// EditionWDSP Web 动态安全防护 = WAF + API 动态防护。
	EditionWDSP Edition = "wdsp"
	// EditionAPI 九章 API 安全系统 = 共享底座 + API 能力域（不含 Web 防护交付）。
	EditionAPI Edition = "api"
)

// Settings 运行时产品设置（从环境变量加载）。
type Settings struct {
	Edition Edition
	// APIDynamicProtection 是否启用 API 动态防护（阶段8）；false 时不得加载 API 检测器。
	APIDynamicProtection bool
	// WebWAFEnabled 是否交付 Web 防护专属能力（策略/CC/访问控制面板）；API 包默认 false。
	WebWAFEnabled bool
	// APIProtectionMode 网关侧 API 动态防护模式：OFF | OBSERVE | PROTECT（缺省 OBSERVE，fail-safe）
	APIProtectionMode string
	// APIProtectionModeFromEnv 模式是否显式来自环境变量 API_PROTECTION_MODE（策略接口 mode_source 判定用）
	APIProtectionModeFromEnv bool
	// 解析限制（与 gateway/dynamic_security 约定一致，供管理面展示/下发）
	MaxBodyParseBytes  int
	MaxBodySampleBytes int
	MaxJSONDepth       int
	MaxFieldCount      int
}

// Load 从环境变量加载；缺省为 WAF 安全默认值。
func Load() Settings {
	ed := Edition(strings.ToLower(strings.TrimSpace(os.Getenv("PRODUCT_EDITION"))))
	switch ed {
	case EditionWAF, EditionWDSP, EditionAPI:
	default:
		ed = EditionWAF
	}

	// API 动态防护：显式 env 优先且无效值失败关闭；否则 wdsp/api 默认开、waf 默认关
	apiOn := false
	if v, ok := os.LookupEnv("API_DYNAMIC_PROTECTION_ENABLED"); ok && v != "" {
		apiOn = parseBool(v, false)
	} else {
		apiOn = ed == EditionWDSP || ed == EditionAPI
	}

	// Web 防护专属交付：显式 env 优先；否则 waf/wdsp 默认开、api 默认关
	webWAF := true
	if v, ok := os.LookupEnv("WEB_WAF_ENABLED"); ok && v != "" {
		webWAF = parseBool(v, true)
	} else {
		webWAF = ed != EditionAPI
	}

	// 防护模式：仅识别 OFF/OBSERVE/PROTECT；非法值回退 OBSERVE（fail-safe）
	mode := strings.ToUpper(strings.TrimSpace(os.Getenv("API_PROTECTION_MODE")))
	modeFromEnv := false
	switch mode {
	case "OFF", "OBSERVE", "PROTECT":
		modeFromEnv = true
	default:
		mode = "OBSERVE"
	}

	return Settings{
		Edition:                  ed,
		APIDynamicProtection:     apiOn,
		WebWAFEnabled:            webWAF,
		APIProtectionMode:        mode,
		APIProtectionModeFromEnv: modeFromEnv,
		MaxBodyParseBytes:        envInt("API_MAX_BODY_PARSE_BYTES", 1<<20),
		MaxBodySampleBytes:       envInt("API_MAX_BODY_SAMPLE_BYTES", 64<<10),
		MaxJSONDepth:             envInt("API_MAX_JSON_DEPTH", 32),
		MaxFieldCount:            envInt("API_MAX_FIELD_COUNT", 2048),
	}
}

// IsWDSP 是否 WDSP 产品形态。
func (s Settings) IsWDSP() bool { return s.Edition == EditionWDSP }

// IsWAF 是否纯 WAF 产品形态。
func (s Settings) IsWAF() bool { return s.Edition == EditionWAF }

// IsAPI 是否 API 安全系统产品形态。
func (s Settings) IsAPI() bool { return s.Edition == EditionAPI }

// APIDynamicProtectionEnabled 是否允许对外暴露 API 动态防护能力。
// WAF edition 即使显式打开检测开关，管理面与 API 路由也不得暴露 API 能力（防半成品外泄）。
// WDSP / API edition 以 APIDynamicProtection 标志为准。
func (s Settings) APIDynamicProtectionEnabled() bool {
	if s.IsWAF() {
		return false
	}
	return (s.IsWDSP() || s.IsAPI()) && s.APIDynamicProtection
}

// WebWAFProtectionEnabled 是否交付 Web 防护专属能力（策略/CC/访问控制菜单）。
// API 包默认关闭；统一流量引擎基础能力不受影响。
func (s Settings) WebWAFProtectionEnabled() bool {
	return s.WebWAFEnabled
}

// EffectiveAPIProtectionMode 下发网关的防护模式；能力关闭时恒为 OFF（网关零行为变化）。
func (s Settings) EffectiveAPIProtectionMode() string {
	if !s.APIDynamicProtectionEnabled() {
		return "OFF"
	}
	return s.APIProtectionMode
}

// ProductDisplayName 交付包/界面用产品中文名。
func ProductDisplayName(ed Edition) string {
	switch ed {
	case EditionWDSP:
		return "九章Web动态防护系统"
	case EditionAPI:
		return "九章API安全系统"
	default:
		return "九章WEB应用智能防护系统"
	}
}

func parseBool(s string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
