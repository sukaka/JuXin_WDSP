// Package securityevents 提供安全事件标准化、脱敏、存储与采集。
package securityevents

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
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
		} `json:"request"`
		Response struct {
			Status int `json:"status"`
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
	RequestID      string
	OccurredAt     time.Time
	ClientIP       string
	ClientPort     int
	Method         string
	URI            string
	Path           string
	QuerySummary   string
	HTTPVersion    string
	ContentType    string
	UserAgent      string
	Referer        string
	Host           string
	AttackType     string
	Severity       string
	AnomalyScore   int
	Action         string
	ResponseStatus int
	RuleEngine     string
	GatewayNode    string
	RawRef         string
	Matches        []MatchInfo
}

// MatchInfo 是规则匹配信息。
type MatchInfo struct {
	RuleID          int      `json:"rule_id"`
	RuleName        string   `json:"rule_name"`
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
)

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
	maxSevRank := -1
	evt.Severity = "INFO"
	for _, m := range entry.Messages {
		mi := parseMessage(m.ErrorMessage)
		if mi.RuleID == 0 {
			continue
		}
		evt.Matches = append(evt.Matches, mi)
		for _, tag := range mi.Tags {
			if at, ok := attackTypeByTag[tag]; ok && evt.AttackType == "" {
				evt.AttackType = at
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
