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
	MaxContentBytes = 1 << 20 // 导入内容 ≤ 1MB
	MaxEntries      = 5000    // 单批次有效 IP 上限（超出截断）
	MaxRowErrors    = 50      // 行级错误明细上限（错误总数仍完整计数）
)

// Entry 是一条解析成功的情报条目。
type Entry struct {
	IP     string // 规范化 IPv4（netip 规范形式）
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

// ParseText 解析纯文本 IP 清单：一行一个 IPv4；# 注释行与空行忽略；
// 兼容行内行尾空白；可选剥除 :port（如 192.0.2.1:8080）。坏行跳过并计数。
func ParseText(content string) *ParseResult {
	res := &ParseResult{}
	seen := map[string]bool{}
	for i, line := range strings.Split(content, "\n") {
		if res.Truncated {
			break
		}
		s := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		ip, err := parseIPv4(s)
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
// 缺 IP 列属结构性错误，整体失败；数据行坏行跳过并计数。
func ParseCSV(content string) (*ParseResult, error) {
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
		ip, perr := parseIPv4(get(ipCol))
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

// parseIPv4 严格解析并规范化 IPv4：拒绝 IPv6（含 4 映射 6）、CIDR、域名、
// 通配符、协议前缀与控制字符；恰一个冒号时按 host:port 剥端口（端口须为
// 1-65535 的数字）。0.0.0.0 不具封禁意义，同样拒绝。
func parseIPv4(raw string) (string, error) {
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
	return addr.String(), nil
}

// truncateRunes 按字符数截断（防超长行内容进入错误明细）。
func truncateRunes(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		return string(runes[:n])
	}
	return s
}
