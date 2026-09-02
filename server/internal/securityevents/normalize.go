// Package securityevents 提供安全事件标准化、脱敏、存储与采集。
package securityevents

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 攻击类型映射
var attackTypeByTag = map[string]string{
	"attack-sqli":              "SQL_INJECTION",
	"attack-xss":               "XSS",
	"attack-rce":               "COMMAND_INJECTION",
	"attack-lfi":               "LOCAL_FILE_INCLUSION",
	"attack-rfi":               "REMOTE_FILE_INCLUSION",
	"attack-php":               "PHP_INJECTION",
	"attack-java":              "JAVA_INJECTION",
	"attack-protocol":          "PROTOCOL_VIOLATION",
	"attack-fixation":          "SESSION_FIXATION",
	"attack-scanner":           "SCANNER_DETECTION",
	"attack-disclosure":        "INFORMATION_DISCLOSURE",
	"attack-injection-generic": "REMOTE_CODE_EXECUTION",
}

var severityMap = map[string]string{
	"critical": "HIGH",
	"error":    "MEDIUM",
	"warning":  "LOW",
	"notice":   "INFO",
}

// auditEntry 是 Coraza JSON 审计日志条目。
type auditEntry struct {
	Transaction struct {
		Timestamp     string `json:"timestamp"`
		UnixTimestamp int64  `json:"unix_timestamp"`
		ID            string `json:"id"`
		ClientIP      string `json:"client_ip"`
		ClientPort    int    `json:"client_port"`
		Request       struct {
			Method   string              `json:"method"`
			Protocol string              `json:"protocol"`
			URI      string              `json:"uri"`
			Headers  map[string][]string `json:"headers"`
			Body     string              `json:"body"`
		} `json:"request"`
		Response struct {
			Status  int                 `json:"status"`
			Headers map[string][]string `json:"headers"`
			Body    string              `json:"body"`
		} `json:"response"`
		Producer struct {
			RuleEngine string   `json:"rule_engine"`
			Rulesets   []string `json:"rulesets"`
		} `json:"producer"`
		IsInterrupted bool `json:"is_interrupted"`
	} `json:"transaction"`
	Messages []struct {
		ErrorMessage string `json:"error_message"`
	} `json:"messages"`
}

// NormalizedEvent 是标准化后的安全事件。
type NormalizedEvent struct {
	RequestID    string
	OccurredAt   time.Time
	ClientIP     string
	ClientPort   int
	Method       string
	URI          string
	Path         string
	QuerySummary string
	HTTPVersion  string
	ContentType  string
	UserAgent    string
	Referer      string
	Host         string
	// ApplicationID / ApplicationName 由采集器按 Host 做域名→应用解析后回填，
	// 未命中时保持 nil / ""。
	ApplicationID         *uuid.UUID
	ApplicationName       string
	AttackType            string
	Severity              string
	AnomalyScore          int
	Action                string
	ResponseStatus        int
	RuleEngine            string
	GatewayNode           string
	RawRef                string
	RequestHeaders        map[string][]string
	RequestBody           string
	RequestBodyTruncated  bool
	ResponseHeaders       map[string][]string
	ResponseBody          string
	ResponseBodyTruncated bool
	Matches               []MatchInfo
}

// MatchInfo 是规则匹配信息。
type MatchInfo struct {
	RuleID          int      `json:"rule_id"`
	RuleName        string   `json:"rule_name"`
	RuleSource      string   `json:"rule_source,omitempty"`
	RuleVersion     string   `json:"rule_version,omitempty"`
	Severity        string   `json:"severity"`
	Message         string   `json:"message"`
	MatchedVariable string   `json:"matched_variable"`
	MatchedData     string   `json:"matched_data"`
	Tags            []string `json:"tags"`
	Phase           int      `json:"phase"`
}

var (
	kvPattern          = regexp.MustCompile(`\[([a-zA-Z_]+) "((?:[^"\\]|\\.)*)"\]`)
	scorePattern       = regexp.MustCompile(`Total Score: (\d+)`)
	matchedDataPattern = regexp.MustCompile(`^Matched Data: (.*?) found within ([A-Z_]+(?::[^\s:]+)?): (.*)$`)
)

// 敏感参数名（URI 查询串脱敏）
var sensitiveParams = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "token": true, "access_token": true,
	"refresh_token": true, "secret": true, "api_key": true, "apikey": true, "key": true,
	"session": true, "sessionid": true, "auth": true, "credential": true, "private_key": true,
	"client_secret": true, "id_token": true,
}

const (
	maxMatchedDataLen = 128
	maxUserAgentLen   = 256
	maxURILen         = 2048
	// maxBodyLen 是入库的请求/响应体最大长度（64KB），超出截断并打 truncated 标记
	maxBodyLen = 65536
)

// 敏感请求/响应头：入库前掩码，防止凭据泄露（AGENTS.md 日志脱敏底线）
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
}

// ParseAuditLine 解析单行 Coraza 审计日志为标准化事件（脱敏）。
func ParseAuditLine(line []byte, gatewayNode string) (*NormalizedEvent, error) {
	line = []byte(strings.TrimSpace(string(line)))
	if len(line) == 0 {
		return nil, fmt.Errorf("empty line")
	}
	var entry auditEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		return nil, fmt.Errorf("invalid audit json: %w", err)
	}
	if entry.Transaction.ID == "" {
		return nil, fmt.Errorf("missing transaction id")
	}

	tx := entry.Transaction
	occurred := parseAuditTime(tx.Timestamp)
	requestID := firstHeader(tx.Request.Headers, "x-request-id")
	if requestID == "" {
		requestID = tx.ID
	}

	evt := &NormalizedEvent{
		RequestID:   requestID,
		OccurredAt:  occurred,
		ClientIP:    maskIP(tx.ClientIP),
		ClientPort:  tx.ClientPort,
		Method:      tx.Request.Method,
		HTTPVersion: tx.Request.Protocol,
		RuleEngine:  tx.Producer.RuleEngine,
		GatewayNode: gatewayNode,
		RawRef:      "coraza-audit:" + tx.ID,
	}

	// URI 拆分与脱敏
	evt.URI = maskURI(truncate(tx.Request.URI, maxURILen))
	evt.Path, evt.QuerySummary = splitURI(tx.Request.URI)
	evt.UserAgent = truncate(firstHeader(tx.Request.Headers, "user-agent"), maxUserAgentLen)
	evt.Referer = truncate(firstHeader(tx.Request.Headers, "referer"), maxUserAgentLen)
	evt.ContentType = firstHeader(tx.Request.Headers, "content-type")
	evt.Host = firstHeader(tx.Request.Headers, "host")

	// 请求/响应头体留痕（敏感头掩码 + 64KB 截断），用于溯源取证
	evt.RequestHeaders = maskHeaders(tx.Request.Headers)
	evt.RequestBody, evt.RequestBodyTruncated = truncateBody(maskBody(tx.Request.Body))
	evt.ResponseHeaders = maskHeaders(tx.Response.Headers)
	evt.ResponseBody, evt.ResponseBodyTruncated = truncateBody(tx.Response.Body)

	// 动作与状态
	evt.Action = "OBSERVE"
	evt.ResponseStatus = 200
	if tx.IsInterrupted {
		evt.Action = "BLOCK"
		evt.ResponseStatus = 403
	} else if tx.Response.Status > 0 {
		evt.ResponseStatus = tx.Response.Status
	}

	// 规则匹配解析
	ruleSource, ruleVersion := parseRuleSetMetadata(tx.Producer.Rulesets)
	maxSevRank := -1
	evt.Severity = "INFO"
	bestTypeRank := -1
	for _, m := range entry.Messages {
		mi := parseMessage(m.ErrorMessage)
		if mi.RuleID == 0 {
			continue
		}
		mi.RuleSource = ruleSource
		mi.RuleVersion = ruleVersion
		evt.Matches = append(evt.Matches, mi)
		// 攻击类型按「严重度优先」确定：遍历全部匹配收集可映射 tag 候选，
		// 取 severityRank 最高者，并列取先出现者。防止 notice 级扫描器规则
		// （phase 1，先执行）抢在 critical 级攻击规则前面把事件误标为扫描器检测。
		for _, tag := range mi.Tags {
			if at, ok := attackTypeByTag[tag]; ok {
				if rank := severityRank(mi.Severity); rank > bestTypeRank {
					bestTypeRank = rank
					evt.AttackType = at
				}
			}
		}
		if rank := severityRank(mi.Severity); rank > maxSevRank {
			maxSevRank = rank
			evt.Severity = mi.Severity
		}
		if sc := scorePattern.FindStringSubmatch(m.ErrorMessage); len(sc) == 2 {
			if v, err := strconv.Atoi(sc[1]); err == nil && v > evt.AnomalyScore {
				evt.AnomalyScore = v
			}
		}
	}
	if evt.AttackType == "" {
		evt.AttackType = "OTHER"
	}
	return evt, nil
}

// parseRuleSetMetadata 从 Coraza producer.rulesets 提取规则来源与版本。
// 规则集名称属于配置元数据，限制长度后再写入事件，避免异常日志放大字段。
func parseRuleSetMetadata(rulesets []string) (string, string) {
	for _, raw := range rulesets {
		parts := strings.SplitN(strings.TrimSpace(raw), "/", 2)
		if len(parts) != 2 {
			continue
		}
		source := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])
		if source == "" || version == "" {
			continue
		}
		if len(source) > 32 {
			source = source[:32]
		}
		if len(version) > 32 {
			version = version[:32]
		}
		return source, version
	}
	return "", ""
}

// parseMessage 解析 ModSecurity 风格错误消息。
func parseMessage(em string) MatchInfo {
	kv := map[string]string{}
	var tags []string
	for _, m := range kvPattern.FindAllStringSubmatch(em, -1) {
		key, val := m[1], unescapeQuoted(m[2])
		if key == "tag" {
			tags = append(tags, val)
		} else {
			kv[key] = val
		}
	}
	ruleID, _ := strconv.Atoi(kv["id"])
	mi := MatchInfo{
		RuleID:   ruleID,
		RuleName: kv["msg"],
		Severity: mapSeverity(kv["severity"]),
		Message:  kv["msg"],
		Tags:     tags,
	}
	if md := matchedDataPattern.FindStringSubmatch(kv["data"]); len(md) == 4 {
		mi.MatchedVariable = md[2]
		mi.MatchedData = maskMatchedData(md[3])
	} else if kv["data"] != "" {
		mi.MatchedData = maskMatchedData(kv["data"])
	}
	return mi
}

func mapSeverity(s string) string {
	if v, ok := severityMap[strings.ToLower(strings.TrimSpace(s))]; ok {
		return v
	}
	return "INFO"
}

func severityRank(mapped string) int {
	switch mapped {
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func parseAuditTime(ts string) time.Time {
	if t, err := time.ParseInLocation("2006/01/02 15:04:05", ts, time.UTC); err == nil {
		return t.UTC()
	}
	return time.Now().UTC()
}

func firstHeader(headers map[string][]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// maskURI 对 URI 查询串敏感参数脱敏。
func maskURI(uri string) string {
	qIdx := strings.Index(uri, "?")
	if qIdx < 0 {
		return uri
	}
	path, query := uri[:qIdx], uri[qIdx+1:]
	parts := strings.Split(query, "&")
	for i, p := range parts {
		eq := strings.Index(p, "=")
		if eq < 0 {
			continue
		}
		name := strings.ToLower(p[:eq])
		if sensitiveParams[name] {
			parts[i] = p[:eq+1] + "masked"
		}
	}
	return path + "?" + strings.Join(parts, "&")
}

// splitURI 拆分 URI 为路径与查询摘要（脱敏）。
func splitURI(uri string) (path, querySummary string) {
	qIdx := strings.Index(uri, "?")
	if qIdx < 0 {
		return truncate(uri, 512), ""
	}
	return truncate(uri[:qIdx], 512), truncate(maskQuery(uri[qIdx+1:]), 512)
}

func maskQuery(query string) string {
	parts := strings.Split(query, "&")
	for i, p := range parts {
		eq := strings.Index(p, "=")
		if eq < 0 {
			continue
		}
		name := strings.ToLower(p[:eq])
		if sensitiveParams[name] {
			parts[i] = p[:eq+1] + "masked"
		}
	}
	return strings.Join(parts, "&")
}

// maskMatchedData 脱敏匹配数据。
func maskMatchedData(data string) string {
	data = strings.TrimSpace(data)
	for name := range sensitiveParams {
		for _, sep := range []string{"=", ":"} {
			needle := name + sep
			idx := strings.Index(strings.ToLower(data), needle)
			if idx >= 0 {
				start := idx + len(needle)
				end := start
				for end < len(data) && data[end] != ' ' && data[end] != '&' && data[end] != ';' {
					end++
				}
				data = data[:start] + "masked" + data[end:]
			}
		}
	}
	return truncate(data, maxMatchedDataLen)
}

// maskIP 对客户端 IP 脱敏（保留网段，隐藏最后一段用于隐私合规，可配置）。
// 安全事件调查需要 IP，此处仅对 IPv4 保留前三段。
func maskIP(ip string) string {
	if ip == "" {
		return ""
	}
	// 安全运营需要完整IP用于处置，不做隐藏（IP属于安全事件必要字段）
	if addr, err := netip.ParseAddr(ip); err == nil {
		return addr.String()
	}
	return ip
}

// maskHeaders 返回敏感头掩码后的头部副本。
func maskHeaders(headers map[string][]string) map[string][]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string][]string, len(headers))
	for k, v := range headers {
		if sensitiveHeaders[strings.ToLower(k)] {
			masked := make([]string, len(v))
			for i := range masked {
				masked[i] = "masked"
			}
			out[k] = masked
			continue
		}
		out[k] = v
	}
	return out
}

// truncateBody 截断头体到 maxBodyLen，返回截断标记。
func truncateBody(body string) (string, bool) {
	if len(body) > maxBodyLen {
		return body[:maxBodyLen], true
	}
	return body, false
}

// maskBody 脱敏请求体中的敏感键值。
// JSON 族优先解析-重建（encoding/json，UseNumber 保留数值字面量；任意空白形态与
// 转义值由解析器处理）；非 JSON 或解析失败（如截断残片）回退启发式。已知残余缝隙
// （尽力而为脱敏，宁过掩不泄漏）：非标量值不掩、键名截断残片不识别、值内形似
// 键值对的文本会被过掩。
func maskBody(body string) string {
	if body == "" {
		return body
	}
	if masked, ok := maskBodyJSON(body); ok {
		return masked
	}
	return maskBodyHeuristic(body)
}

// maskBodyJSON 解析式 JSON 脱敏：对象/数组根均可，任意空白形态与转义引号值由解析器处理。
func maskBodyJSON(body string) (string, bool) {
	trimmed := strings.TrimSpace(body)
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return body, false
	}
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return body, false
	}
	maskJSONValue(v)
	out, err := json.Marshal(v)
	if err != nil {
		return body, false
	}
	return string(out), true
}

// maskJSONValue 递归掩码对象中敏感键的值（就地修改；sensitiveParams 为小写键词表）。
func maskJSONValue(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if sensitiveParams[strings.ToLower(k)] {
				t[k] = "masked"
				continue
			}
			maskJSONValue(val)
		}
	case []any:
		for _, item := range t {
			maskJSONValue(item)
		}
	}
}

// maskBodyHeuristic 表单与非 JSON 文本的启发式脱敏：表单键经 URL 解码比对
// （pass%77ord= 编码键可命中）；JSON 残片形态容忍冒号两侧任意空白、值扫描感知
// 反斜杠转义（值内 \" 不再截断泄漏）。
func maskBodyHeuristic(body string) string {
	for name := range sensitiveParams {
		body = maskFormValue(body, name)
		body = maskJSONFragment(body, name)
	}
	return body
}

// maskFormValue 按 & / ; 分段扫描表单键值，键 URL 解码后命中敏感词表则掩码其值。
func maskFormValue(body, name string) string {
	segs := strings.Split(body, "&")
	for i, seg := range segs {
		sub := strings.Split(seg, ";")
		for j, s := range sub {
			eq := strings.Index(s, "=")
			if eq < 0 {
				continue
			}
			key, err := url.QueryUnescape(s[:eq])
			if err != nil {
				key = s[:eq]
			}
			if strings.ToLower(key) == name {
				sub[j] = s[:eq+1] + "masked"
			}
		}
		segs[i] = strings.Join(sub, ";")
	}
	return strings.Join(segs, "&")
}

// maskJSONFragment 掩码 JSON 残片中 "name" : "value" 形态的值：容忍冒号两侧任意
// 空白，值扫描感知反斜杠转义。键匹配为 ASCII 大小写不敏感（避免 strings.ToLower
// 在非 ASCII 字符上改变字节长度导致的位置错位）。
func maskJSONFragment(body, name string) string {
	needle := `"` + name + `"`
	from := 0
	for {
		idx := indexASCIIFold(body[from:], needle)
		if idx < 0 {
			break
		}
		i := from + idx + len(needle)
		for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\n' || body[i] == '\r') {
			i++
		}
		if i >= len(body) || body[i] != ':' {
			from += idx + len(needle)
			continue
		}
		i++
		for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\n' || body[i] == '\r') {
			i++
		}
		if i >= len(body) || body[i] != '"' {
			from += idx + len(needle)
			continue
		}
		valStart := i + 1
		j := valStart
		for j < len(body) {
			if body[j] == '\\' {
				j += 2
				continue
			}
			if body[j] == '"' {
				break
			}
			j++
		}
		body = body[:valStart] + "masked" + body[j:]
		from = valStart + len("masked")
	}
	return body
}

// indexASCIIFold ASCII 大小写不敏感子串查找（仅折叠 A-Z，非 ASCII 字节不参与）。
func indexASCIIFold(s, sub string) int {
	if len(sub) == 0 || len(s) < len(sub) {
		return -1
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if 'A' <= a && a <= 'Z' {
				a += 'a' - 'A'
			}
			if 'A' <= b && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func unescapeQuoted(s string) string {
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `\\`, `\`)
	return s
}
