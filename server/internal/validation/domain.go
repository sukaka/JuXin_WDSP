// Package validation 提供阶段3业务字段校验（域名、应用编码、源站地址等）。
package validation

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

// 应用编码规则：3-64位小写字母、数字、短横线
var appCodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$`)

// ValidateAppCode 校验应用编码。
func ValidateAppCode(code string) error {
	if len(code) < 3 || len(code) > 64 {
		return fmt.Errorf("应用编码长度须为3至64位")
	}
	if !appCodePattern.MatchString(code) {
		return fmt.Errorf("应用编码仅允许小写字母、数字和短横线，且不能以短横线开头结尾")
	}
	if strings.Contains(code, "--") {
		return fmt.Errorf("应用编码不允许连续短横线")
	}
	return nil
}

// 域名校验错误
var domainLabelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeHostname 规范化域名：小写、去尾部点、去空白。
func NormalizeHostname(hostname string) string {
	h := strings.ToLower(strings.TrimSpace(hostname))
	h = strings.TrimSuffix(h, ".")
	return h
}

// ValidateHostname 校验域名（精确或泛域名）。
// 返回规范化后的域名与类型（EXACT/WILDCARD）。
func ValidateHostname(hostname string) (normalized, domainType string, err error) {
	if hostname == "" {
		return "", "", fmt.Errorf("域名不能为空")
	}
	if len(hostname) > 255 {
		return "", "", fmt.Errorf("域名过长")
	}
	// 禁止协议、路径、查询、端口、控制字符
	if strings.ContainsAny(hostname, "/:?#@\\ \t\n\r") {
		return "", "", fmt.Errorf("域名不得包含协议、路径、端口、查询参数或控制字符")
	}
	normalized = NormalizeHostname(hostname)
	domainType = "EXACT"

	host := normalized
	if strings.HasPrefix(host, "*.") {
		domainType = "WILDCARD"
		host = host[2:]
		// 泛域名后必须是有效域名且至少两标签
		if host == "" || !strings.Contains(host, ".") {
			return "", "", fmt.Errorf("泛域名格式错误，仅允许 *.example.com 形式")
		}
	} else if strings.Contains(host, "*") {
		return "", "", fmt.Errorf("泛域名仅允许前缀 *. 形式")
	}

	// 校验各标签
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", "", fmt.Errorf("域名至少包含两个标签")
	}
	for _, label := range labels {
		if len(label) == 0 {
			return "", "", fmt.Errorf("域名包含空标签")
		}
		if len(label) > 63 {
			return "", "", fmt.Errorf("域名单标签长度不能超过63")
		}
		if !domainLabelPattern.MatchString(label) {
			return "", "", fmt.Errorf("域名标签格式错误: %s", label)
		}
	}
	return normalized, domainType, nil
}

// MatchHostnamePattern 判断域名是否匹配证书域名（支持泛域名）。
// pattern 可为精确域名或 *.example.com 泛域名。
func MatchHostnamePattern(pattern, hostname string) bool {
	pattern = NormalizeHostname(pattern)
	hostname = NormalizeHostname(hostname)
	if pattern == hostname {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		// 泛域名只匹配一级子域名，不匹配根域名
		if strings.HasSuffix(hostname, suffix) {
			sub := strings.TrimSuffix(hostname, suffix)
			return sub != "" && !strings.Contains(sub, ".")
		}
	}
	return false
}

// ValidatePort 校验端口号。
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("端口号必须在1至65535之间")
	}
	return nil
}

// IsIPAddress 判断是否为合法 IP（v4/v6）。
func IsIPAddress(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

// IsValidUpstreamHost 校验源站地址（IP 或域名）。
func IsValidUpstreamHost(host string) error {
	if host == "" {
		return fmt.Errorf("源站地址不能为空")
	}
	if len(host) > 255 {
		return fmt.Errorf("源站地址过长")
	}
	// 优先识别 IP 地址（含 IPv6，其本身含冒号）
	if IsIPAddress(host) {
		return nil
	}
	// 域名形式：禁止协议、路径、用户信息、控制字符
	if strings.ContainsAny(host, "/:?#@\\ \t\n\r") {
		return fmt.Errorf("源站地址不得包含协议、路径、用户信息或控制字符")
	}
	if strings.Contains(host, "*") {
		return fmt.Errorf("源站地址不允许泛域名")
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("源站域名标签格式错误")
		}
		if !domainLabelPattern.MatchString(label) {
			return fmt.Errorf("源站域名标签格式错误: %s", label)
		}
	}
	return nil
}

// 私网/特殊地址段（SSRF 防护）
var privateNetworks = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
	"0.0.0.0/8", "::/128", "100.64.0.0/10", "198.18.0.0/15",
	"224.0.0.0/4", "ff00::/8",
}

// 云元数据与高危地址
var blockedNetworks = []string{
	"169.254.169.254/32", // 云元数据（AWS/GCP/Azure/OpenStack）
	"169.254.170.2/32",   // AWS ECS 任务元数据
	"100.100.100.200/32", // 阿里云元数据
	"fd00:ec2::254/128",  // AWS IPv6 元数据
}

// 源站连通性测试私网白名单永远不允许重叠的保留网段（回环/链路本地/未指定/组播）
var alwaysDeniedOverlapNetworks = []string{
	"127.0.0.0/8", "::1/128",
	"169.254.0.0/16", "fe80::/10",
	"0.0.0.0/8", "::/128",
	"224.0.0.0/4", "ff00::/8",
}

var parsedPrivate, parsedBlocked, parsedAlwaysDeniedOverlap []netip.Prefix

func init() {
	for _, cidr := range privateNetworks {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			parsedPrivate = append(parsedPrivate, p)
		}
	}
	for _, cidr := range blockedNetworks {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			parsedBlocked = append(parsedBlocked, p)
		}
	}
	for _, cidr := range alwaysDeniedOverlapNetworks {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			parsedAlwaysDeniedOverlap = append(parsedAlwaysDeniedOverlap, p)
		}
	}
}

// ValidateAllowedPrivateUpstreamPrefix 校验“允许测试的内网源站 CIDR 白名单”单条前缀：
// 拒绝全网通配（0.0.0.0/0、::/0）、IPv4 映射 IPv6、回环/链路本地/未指定/组播网段重叠及显式云元数据地址。
func ValidateAllowedPrivateUpstreamPrefix(p netip.Prefix) error {
	if !p.IsValid() {
		return fmt.Errorf("无效的 CIDR 前缀")
	}
	if p.Addr().Is4In6() || p.Addr().Zone() != "" {
		return fmt.Errorf("不支持 IPv4 映射 IPv6 或带作用域的 CIDR: %s", p)
	}
	masked := p.Masked()
	if masked.Bits() == 0 {
		return fmt.Errorf("禁止配置全网通配 CIDR: %s", p)
	}
	if IsBlockedAddress(masked.Addr()) {
		return fmt.Errorf("禁止配置云元数据地址: %s", p)
	}
	for _, denied := range parsedAlwaysDeniedOverlap {
		if masked.Overlaps(denied) {
			return fmt.Errorf("禁止包含回环/链路本地/未指定/组播保留网段: %s", p)
		}
	}
	return nil
}

// ParseAllowedPrivateUpstreamCIDRs 解析并校验逗号分隔的源站测试私网白名单 CIDR 列表。
func ParseAllowedPrivateUpstreamCIDRs(raw string, maxItems int) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(raw, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		p, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("非法 CIDR %q", item)
		}
		if err := ValidateAllowedPrivateUpstreamPrefix(p); err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
		if maxItems > 0 && len(out) > maxItems {
			return nil, fmt.Errorf("CIDR 项数不能超过 %d", maxItems)
		}
	}
	return out, nil
}

// IsBlockedAddress 判断是否为云元数据等绝对禁止地址。
// 先解映射 IPv4-in-IPv6 并剥离 Zone 再比对，防止 ::ffff:169.254.169.254 或带 Zone 地址绕过。
func IsBlockedAddress(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	ip = ip.Unmap().WithZone("")
	for _, p := range parsedBlocked {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// IsPrivateOrSpecialAddress 判断是否为私网/回环/链路本地等特殊地址。
// 带接口 Zone 的 IPv6 地址一律视为特殊地址；IPv4-in-IPv6 先 Unmap 再比对。
func IsPrivateOrSpecialAddress(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return true
	}
	ip = ip.Unmap()
	for _, p := range parsedPrivate {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ResolveAndValidate 解析域名并校验所有解析 IP（SSRF 防 DNS 重绑定）。
// allowPrivate 为 false 时拒绝私网/特殊地址。
func ResolveAndValidate(host string, allowPrivate bool) ([]netip.Addr, error) {
	// 云元数据主机名黑名单（去尾点防 FQDN 绕过）
	lower := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	blockedHosts := []string{
		"metadata.google.internal", "metadata",
		"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254",
	}
	for _, bh := range blockedHosts {
		if lower == bh {
			return nil, fmt.Errorf("禁止访问元数据地址")
		}
	}

	// 直接 IP
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return nil, fmt.Errorf("禁止包含网络接口作用域的IP地址")
		}
		addr = addr.Unmap()
		if IsBlockedAddress(addr) {
			return nil, fmt.Errorf("禁止访问元数据地址")
		}
		if !allowPrivate && IsPrivateOrSpecialAddress(addr) {
			return nil, fmt.Errorf("默认禁止访问回环/私网/链路本地地址")
		}
		return []netip.Addr{addr}, nil
	}

	// DNS 解析
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("DNS解析失败: %v", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("DNS解析无结果")
	}
	var out []netip.Addr
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		if addr.Zone() != "" {
			return nil, fmt.Errorf("禁止包含网络接口作用域的IP地址")
		}
		addr = addr.Unmap()
		if IsBlockedAddress(addr) {
			return nil, fmt.Errorf("禁止访问元数据地址")
		}
		if !allowPrivate && IsPrivateOrSpecialAddress(addr) {
			return nil, fmt.Errorf("默认禁止访问回环/私网/链路本地地址: %s", addr)
		}
		out = append(out, addr)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("无可用解析地址")
	}
	return out, nil
}

// ContainsControlChars 检测是否含控制字符（防注入）。
func ContainsControlChars(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}
