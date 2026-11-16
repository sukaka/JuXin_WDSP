// config.go 暴露面判定引擎配置：从 system_settings 组 exposure_engine 读取，
// 带默认值与夹取（防误配）；设置键白名单与校验登记见 settings/settings.go。
package apiexposure

import (
	"context"
	"net/netip"
	"sort"
	"strings"
)

// 设置键（system_settings 组 exposure_engine；种子见迁移 000190）。
const (
	SettingsGroup         = "exposure_engine"
	KeyObservationDays    = "observation_days"
	KeyPartnerEgressCIDRs = "partner_egress_cidrs"
	KeyPublicDNSServers   = "public_dns_servers"
	KeyMinRequests        = "min_requests"
	KeyMinDays            = "min_days"
)

// 默认值与夹取区间（与 settings.settingValueRanges 同口径，消费侧双重防御）。
const (
	DefaultObservationDays = 7
	DefaultMinRequests     = 50
	DefaultMinDays         = 2
	DefaultPublicDNS       = "223.5.5.5"

	minObservationDays = 1
	maxObservationDays = 30
	minMinRequests     = 1
	maxMinRequests     = 100000
	minMinDays         = 1
	maxMinDays         = 30
)

// Config 引擎配置（每轮评估重读设置，变更即时生效）。
type Config struct {
	ObservationDays  int      // 观察窗天数
	PartnerCIDRs     []string // 合作方出口网段（CIDR 原文，已归一排序去重）
	PublicDNSServers []string // 公网视角 DNS 服务器
	MinRequests      int64    // 流量证据请求数阈值
	MinDays          int      // 流量证据覆盖自然日阈值
}

// SettingsReader 设置读取窄接口（*settings.Service 满足；测试注入假实现）。
type SettingsReader interface {
	GetString(ctx context.Context, group, key, def string) string
	GetInt(ctx context.Context, group, key string, def int) int
}

// LoadConfig 读取引擎配置（settings 为 nil 时全用默认值）。
func LoadConfig(ctx context.Context, settings SettingsReader) Config {
	cfg := Config{
		ObservationDays:  DefaultObservationDays,
		PublicDNSServers: []string{DefaultPublicDNS},
		MinRequests:      DefaultMinRequests,
		MinDays:          DefaultMinDays,
	}
	if settings == nil {
		return cfg
	}
	cfg.ObservationDays = clampInt(settings.GetInt(ctx, SettingsGroup, KeyObservationDays, DefaultObservationDays), minObservationDays, maxObservationDays)
	cfg.MinRequests = int64(clampInt(settings.GetInt(ctx, SettingsGroup, KeyMinRequests, DefaultMinRequests), minMinRequests, maxMinRequests))
	cfg.MinDays = clampInt(settings.GetInt(ctx, SettingsGroup, KeyMinDays, DefaultMinDays), minMinDays, maxMinDays)
	cfg.PartnerCIDRs = ParseCIDRList(settings.GetString(ctx, SettingsGroup, KeyPartnerEgressCIDRs, ""))
	if servers := ParseServerList(settings.GetString(ctx, SettingsGroup, KeyPublicDNSServers, DefaultPublicDNS)); len(servers) > 0 {
		cfg.PublicDNSServers = servers
	}
	return cfg
}

// clampInt 整数夹取 [lo, hi]。
func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ParseCIDRList 解析逗号分隔 CIDR 列表：逐项 trim、去重、按原文排序（结果确定）；
// 非法项忽略（消费侧宽松归一；写入侧已由 settings 校验拦截，此处为兜底）。
func ParseCIDRList(raw string) []string {
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if _, err := netip.ParsePrefix(p); err != nil {
			continue // 非法项忽略
		}
		seen[p] = true
	}
	return sortedKeys(seen)
}

// ParseServerList 解析逗号分隔服务器列表：逐项 trim、丢弃空项、去重排序。
// 项形态校验（合法 IP 或主机名、项数上限）由 settings.validateServerList 在写入侧完成，
// 消费侧仅做空白归一（与 netconfig 消费 network:dns_servers 同口径）。
func ParseServerList(raw string) []string {
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		p := strings.TrimSpace(part)
		if p != "" {
			seen[p] = true
		}
	}
	return sortedKeys(seen)
}

// sortedKeys map 键排序输出（结果确定）。
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
