// resolver.go 出境判定：客户端 IP → 归属范围（本土/境外/内网/未知）纯函数判定。
// 归属数据源为 CountryLookup（生产为 *MMDB，测试注入假实现）；本土地区集合由
// system_settings api_data.home_regions 提供（逗号分隔国家码，默认 CN）。
package apigeo

import (
	"net/netip"
	"strings"
)

// Scope 归属范围（判定矩阵：本土/境外/内网/未知/非法输入）。
type Scope string

const (
	ScopeHome     Scope = "HOME"     // 归属本土地区（home_regions 内）
	ScopeForeign  Scope = "FOREIGN"  // 归属境外（公网且国家码在 home_regions 外）
	ScopeInternal Scope = "INTERNAL" // 内网/保留地址（不出境语义）
	ScopeUnknown  Scope = "UNKNOWN"  // 公网但 GeoIP 未收录 / 数据源未启用
	ScopeInvalid  Scope = "INVALID"  // 输入不是合法 IP（脏数据，不判定）
)

// 设置键（system_settings 组 api_data）。
const (
	SettingsGroup          = "api_data"
	SettingsKeyHomeRegions = "home_regions"
	DefaultHomeRegions     = "CN"
)

// CountryLookup 国家码查询能力（*MMDB 实现；测试注入假实现）。
type CountryLookup interface {
	// LookupCountry 返回 ISO 3166-1 alpha-2 国家码；未收录返回 ("", nil)；
	// 数据损坏返回错误（调用方不静默吞错）。
	LookupCountry(ip netip.Addr) (string, error)
}

// GeoResolver 出境判定器（无状态，并发安全；lookup 为 nil 表示 GeoIP 未启用）。
type GeoResolver struct {
	lookup CountryLookup
	home   map[string]bool
}

// NewGeoResolver 构造判定器（homeRegions 已归一；lookup 为 nil 时 Enabled()=false）。
func NewGeoResolver(lookup CountryLookup, homeRegions []string) *GeoResolver {
	home := make(map[string]bool, len(homeRegions))
	for _, r := range homeRegions {
		home[r] = true
	}
	return &GeoResolver{lookup: lookup, home: home}
}

// Enabled GeoIP 数据源是否可用（不可用时一切判定为 UNKNOWN，由调用方先行检查）。
func (r *GeoResolver) Enabled() bool { return r != nil && r.lookup != nil }

// HomeRegions 本土地区集合（排序输出，结果确定）。
func (r *GeoResolver) HomeRegions() []string {
	if r == nil {
		return nil
	}
	return sortedKeys(r.home)
}

// ParseHomeRegions 解析 home_regions 设置值：逗号分隔，逐项 trim + 大写 + 去重；
// 仅保留两位字母的 ISO 3166-1 alpha-2 国家码，非法项忽略（设置为运维侧受控输入，
// 宽松归一避免单项脏数据拖垮整体判定）；空值回退默认 CN。
func ParseHomeRegions(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = DefaultHomeRegions
	}
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		code := strings.ToUpper(strings.TrimSpace(part))
		if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
			continue // 非法项忽略
		}
		seen[code] = true
	}
	if len(seen) == 0 {
		seen[DefaultHomeRegions] = true
	}
	return sortedKeys(seen)
}

// Classify 判定客户端 IP 归属范围。
//
// 返回（范围, 国家码, 错误）：内网/非法/未知国家码为空串；
// error 仅来自底层数据损坏（系统性故障，调用方应中止并上抛，不逐条吞掉）。
// 判定矩阵见 resolver_test.go。
func (r *GeoResolver) Classify(ipRaw string) (Scope, string, error) {
	if r == nil || r.lookup == nil {
		return ScopeUnknown, "", nil
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ipRaw))
	if err != nil {
		return ScopeInvalid, "", nil
	}
	if isInternalAddr(addr) {
		return ScopeInternal, "", nil
	}
	country, err := r.lookup.LookupCountry(addr)
	if err != nil {
		return "", "", err
	}
	if country == "" {
		return ScopeUnknown, "", nil
	}
	if r.home[country] {
		return ScopeHome, country, nil
	}
	return ScopeForeign, country, nil
}

// IPScope IP 网络范围三分词表（暴露面来源聚合用；与 api_endpoint_source_buckets.scope
// 的 INTERNAL/PUBLIC 取值对齐，合作方 PARTNER 由引擎侧叠加出口 CIDR 判定）。
const (
	IPScopeInternal = "INTERNAL" // 内网/保留地址
	IPScopePublic   = "PUBLIC"   // 公网地址
	IPScopeInvalid  = "INVALID"  // 输入不是合法 IP（脏数据，不聚合）
)

// ClassifyIPScope IP 网络范围三分判定（暴露面判定引擎来源聚合用）。
// 包装 isInternalAddr + netip 解析：内网/保留 → INTERNAL，公网 → PUBLIC，
// 非法输入 → INVALID；不依赖 GeoIP 数据源（MMDB 缺失时同样可用）。
func ClassifyIPScope(ip string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return IPScopeInvalid
	}
	if isInternalAddr(addr) {
		return IPScopeInternal
	}
	return IPScopePublic
}

// isInternalAddr 内网/保留地址判定（不参与出境语义）。
// 覆盖：RFC1918、环回、链路本地、ULA、组播、未指定、CGNAT（100.64/10）、
// 0.0.0.0/8 与 240.0.0.0/4 保留段（与前端 isPublicIp 口径对齐，见 web/src/utils/ipgeo.ts）。
func isInternalAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	if addr.Is4() {
		b := addr.As4()
		if b[0] == 0 { // 0.0.0.0/8 本网络
			return true
		}
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 { // CGNAT 100.64.0.0/10
			return true
		}
		if b[0] >= 240 { // 240.0.0.0/4 保留（含广播 255.255.255.255）
			return true
		}
	}
	return false
}
