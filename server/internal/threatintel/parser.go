package threatintel

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// 解析限制
const (
	MaxContentBytes       = 1 << 20 // 离线导入内容 ≤ 1MB
	MaxOnlineContentBytes = 2 << 20 // 在线订阅源拉取内容 ≤ 2MB
	MaxEntries            = 5000    // 单批次有效条目上限（超出截断）
	MaxRowErrors          = 50      // 行级错误明细上限（错误总数仍完整计数）

	minAllowedCIDRPrefix = 16 // CIDR 前缀长度下限（硬拒绝 /0–/15，防止过宽网段自断网）
	maxAllowedCIDRPrefix = 32
)

// ParseOptions 控制威胁情报解析行为。
type ParseOptions struct {
	// AllowCIDR 允许公网 IPv4 CIDR（仅 /16–/32，规范化为网络地址前缀；
	// 硬拒绝 /0–/15 及与私网/回环/链路本地/CGNAT/组播/保留段重叠的网段）。
	AllowCIDR bool
}

// nonPublicIPv4Prefixes 是禁止导入黑名单的非公网/保留 IPv4 网段（防止误封内网/网关/云元数据导致自断网）。
// 不包含 RFC 5737 测试文档段（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24），兼容既有测试样本。
var nonPublicIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // 本网络 / 未指定地址
	netip.MustParsePrefix("10.0.0.0/8"),     // RFC 1918 私网
	netip.MustParsePrefix("100.64.0.0/10"),  // RFC 6598 运营商级 NAT（CGNAT）
	netip.MustParsePrefix("127.0.0.0/8"),    // RFC 1122 回环地址
	netip.MustParsePrefix("169.254.0.0/16"), // RFC 3927 链路本地 / 云元数据
	netip.MustParsePrefix("172.16.0.0/12"),  // RFC 1918 私网
	netip.MustParsePrefix("192.0.0.0/24"),   // RFC 6890 IETF 协议保留段
	netip.MustParsePrefix("192.168.0.0/16"), // RFC 1918 私网
	netip.MustParsePrefix("198.18.0.0/15"),  // RFC 2544 基准测试网段
	netip.MustParsePrefix("224.0.0.0/4"),    // RFC 5771 组播网段
	netip.MustParsePrefix("240.0.0.0/4"),    // RFC 1112 保留段（含 255.255.255.255/32 广播）
}

// Entry 是一条解析成功的情报条目。
type Entry struct {
	IP     string // 规范化 IPv4 或 IPv4 CIDR（netip 规范形式）
	Family string // 恶意家族（CSV malware/c2_family 列；纯文本无此信息为空）
	Line   int    // 源内容行号（从 1 计）
}

// RowError 是一条行级解析错误。
type RowError struct {
	Line    int    `json:"line"`
	Content string `json:"content"`
	Error   string `json:"error"`
}

// ParseResult 是解析结果：有效条目（按 IP 去重、保留首次出现顺序）+ 行级错误。
type ParseResult struct {
	Entries    []Entry
	Errors     []RowError // 明细最多前 MaxRowErrors 条
	ErrorTotal int        // 错误行总数（含明细被截断的部分）
	Truncated  bool       // 有效条目达 MaxEntries 上限被截断
}

// addEntry 追加有效条目（按 IP 去重，首次出现获胜）；达上限后到来的新条目
// 被丢弃并标记 Truncated（恰好收满上限不算截断）。
func (r *ParseResult) addEntry(ip, family string, line int, seen map[string]bool) {
	if seen[ip] {
		return
	}
	if len(r.Entries) >= MaxEntries {
		r.Truncated = true
		return
	}
	seen[ip] = true
	r.Entries = append(r.Entries, Entry{IP: ip, Family: family, Line: line})
}

// addError 记录行级错误：总数恒递增，明细只保留前 MaxRowErrors 条。
func (r *ParseResult) addError(line int, content, msg string) {
	r.ErrorTotal++
	if len(r.Errors) < MaxRowErrors {
		r.Errors = append(r.Errors, RowError{Line: line, Content: truncateRunes(content, 120), Error: msg})
	}
}

// ParseText 解析纯文本 IP 清单：一行一个 IPv4；# 与 ; 注释行、行尾注释与空行忽略；
// 兼容行内行尾空白；可选剥除 :port（如 192.0.2.1:8080）。默认不允许 CIDR。坏行跳过并计数。
func ParseText(content string) *ParseResult {
	return ParseTextWithOptions(content, ParseOptions{AllowCIDR: false})
}

// ParseTextWithOptions 按指定选项解析纯文本 IP/CIDR 清单。
// 忽略空行及以 # 或 ; 开头的注释行，并剥除行尾内联 ; 或 # 注释。
func ParseTextWithOptions(content string, opts ParseOptions) *ParseResult {
	content = strings.TrimPrefix(content, "\ufeff")
	res := &ParseResult{}
	seen := map[string]bool{}
	for i, line := range strings.Split(content, "\n") {
		if res.Truncated {
			break
		}
		s := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
			continue
		}
		if idx := strings.IndexAny(s, ";#"); idx >= 0 {
			s = strings.TrimSpace(s[:idx])
			if s == "" {
				continue
			}
		}
		ip, err := parseIPv4Entry(s, opts.AllowCIDR)
		if err != nil {
			res.addError(i+1, s, err.Error())
			continue
		}
		res.addEntry(ip, "", i+1, seen)
	}
	return res
}

// ipColumnNames / familyColumnNames 是 CSV 表头自适应候选列名（小写）。
// 实测 Feodo 表头：first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware。
var ipColumnNames = []string{"dst_ip", "ip", "ip_address", "address", "c2_ip"}
var familyColumnNames = []string{"malware", "c2_family", "family", "malware_family"}

// ParseCSV 解析 Feodo CSV（# 注释前导行 + 表头 + 数据行）。
// 表头自适应：IP 列取 dst_ip/ip/...（必需），家族列取 malware/c2_family/...（可选）。
// 缺 IP 列属结构性错误，整体失败；数据行坏行跳过并计数。默认不允许 CIDR。
func ParseCSV(content string) (*ParseResult, error) {
	return ParseCSVWithOptions(content, ParseOptions{AllowCIDR: false})
}

// ParseCSVWithOptions 按指定选项解析威胁情报 CSV。
func ParseCSVWithOptions(content string, opts ParseOptions) (*ParseResult, error) {
	content = strings.TrimPrefix(content, "\ufeff")
	r := csv.NewReader(strings.NewReader(content))
	r.Comment = '#'
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("CSV 表头解析失败: %v", err)
	}
	colIdx := map[string]int{}
	for i, h := range header {
		colIdx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	ipCol := findColumn(colIdx, ipColumnNames)
	if ipCol < 0 {
		return nil, fmt.Errorf("CSV 表头缺少 IP 列（支持列名: %s）", strings.Join(ipColumnNames, "/"))
	}
	familyCol := findColumn(colIdx, familyColumnNames)

	res := &ParseResult{}
	seen := map[string]bool{}
	lastLine := 1
	for {
		if res.Truncated {
			break
		}
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		line := lastLine + 1
		if len(rec) > 0 {
			l, _ := r.FieldPos(0)
			line = l
		}
		lastLine = line
		if err != nil {
			res.addError(line, strings.Join(rec, ","), "CSV 行解析失败: "+err.Error())
			continue
		}
		if len(rec) == 0 || (len(rec) == 1 && strings.TrimSpace(rec[0]) == "") {
			continue
		}
		get := func(col int) string {
			if col < 0 || col >= len(rec) {
				return ""
			}
			return strings.TrimSpace(rec[col])
		}
		raw := strings.Join(rec, ",")
		ip, perr := parseIPv4Entry(get(ipCol), opts.AllowCIDR)
		if perr != nil {
			res.addError(line, raw, perr.Error())
			continue
		}
		res.addEntry(ip, get(familyCol), line, seen)
	}
	return res, nil
}

// findColumn 按候选列名顺序查找表头列下标，未命中返回 -1。
func findColumn(colIdx map[string]int, names []string) int {
	for _, n := range names {
		if i, ok := colIdx[n]; ok {
			return i
		}
	}
	return -1
}

// parseIPv4 保持内部单 IP 解析入口兼容（不允许 CIDR）。
func parseIPv4(raw string) (string, error) {
	return parseIPv4Entry(raw, false)
}

// parseIPv4Entry 严格解析并规范化 IPv4 或（当 allowCIDR=true 时）公网 IPv4 CIDR：
// 拒绝 IPv6（含 4 映射 6）、域名、通配符、协议前缀与控制字符；
// 拒绝任何非公网（私网/回环/链路本地/CGNAT/组播/保留）地址或与之重叠的网段；
// CIDR 仅允许 /16–/32 前缀并归一化为网络地址前缀；单 IP 恰一个冒号时按 host:port 剥端口。
func parseIPv4Entry(raw string, allowCIDR bool) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("地址为空")
	}
	if len(s) > 64 {
		return "", fmt.Errorf("地址长度超过64字符: %s", s)
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return "", fmt.Errorf("地址包含控制字符")
		}
	}
	if strings.Contains(s, "://") {
		return "", fmt.Errorf("非法 IPv4 地址: %s", s)
	}

	if strings.Contains(s, "/") {
		if !allowCIDR {
			return "", fmt.Errorf("当前订阅源未启用 CIDR（仅允许单 IPv4）: %s", s)
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", fmt.Errorf("非法 IPv4 CIDR: %s", s)
		}
		if !p.Addr().Is4() {
			return "", fmt.Errorf("仅支持 IPv4 CIDR: %s", s)
		}
		if p.Bits() < minAllowedCIDRPrefix || p.Bits() > maxAllowedCIDRPrefix {
			return "", fmt.Errorf("CIDR 前缀长度仅允许 /%d 至 /%d（拒绝过宽网段）: %s",
				minAllowedCIDRPrefix, maxAllowedCIDRPrefix, s)
		}
		p = p.Masked()
		if overlapsRestrictedIPv4(p) {
			return "", fmt.Errorf("禁止导入非公网或保留网段: %s", p.String())
		}
		return p.String(), nil
	}

	// 剥端口：仅当恰有一个冒号（多冒号按 IPv6 处理，随后被拒绝）
	if strings.Count(s, ":") == 1 {
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			return "", fmt.Errorf("非法地址: %s", s)
		}
		p, perr := strconv.Atoi(port)
		if perr != nil || p <= 0 || p > 65535 {
			return "", fmt.Errorf("非法端口: %s", s)
		}
		s = host
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("非法 IPv4 地址: %s", s)
	}
	if !addr.Is4() {
		return "", fmt.Errorf("仅支持 IPv4 地址: %s", s)
	}
	if addr.IsUnspecified() {
		return "", fmt.Errorf("不允许未指定地址 0.0.0.0")
	}
	if overlapsRestrictedIPv4(netip.PrefixFrom(addr, 32)) {
		return "", fmt.Errorf("禁止导入非公网或保留地址: %s", addr.String())
	}
	return addr.String(), nil
}

// overlapsRestrictedIPv4 判断 IPv4 前缀（含 /32 单 IP）是否与任一私网/回环/链路本地/CGNAT/组播/保留网段重叠。
func overlapsRestrictedIPv4(p netip.Prefix) bool {
	for _, r := range nonPublicIPv4Prefixes {
		if p.Overlaps(r) {
			return true
		}
	}
	return false
}

// truncateRunes 按字符数截断（防超长行内容进入错误明细）。
func truncateRunes(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		return string(runes[:n])
	}
	return s
}
