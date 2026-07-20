// Package eventparser 将 Coraza JSON 审计日志解析为九章标准安全事件。
// 阶段1 POC：输出到 JSON 文件；后续阶段将对接 PostgreSQL 事件表。
package eventparser

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---------- 输入结构（Coraza JSON 审计日志） ----------

// AuditEntry 对应 Coraza SecAuditLogFormat JSON 的一行记录。
type AuditEntry struct {
	Transaction AuditTransaction `json:"transaction"`
	Messages    []AuditMessage   `json:"messages"`
}

// AuditTransaction 是审计日志的事务部分。
type AuditTransaction struct {
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
}

// AuditMessage 是命中规则的文本消息（ModSecurity 风格）。
type AuditMessage struct {
	ErrorMessage string `json:"error_message"`
}

// ---------- 输出结构（九章标准安全事件） ----------

// StandardEvent 是九章标准安全事件结构。
type StandardEvent struct {
	EventID     string         `json:"event_id"`
	RequestID   string         `json:"request_id"`
	OccurredAt  string         `json:"occurred_at"`
	Application ApplicationRef `json:"application"`
	Client      ClientInfo     `json:"client"`
	Request     RequestInfo    `json:"request"`
	Security    SecurityInfo   `json:"security"`
	Gateway     GatewayInfo    `json:"gateway"`
	RawRef      string         `json:"raw_log_reference"`
}

// ApplicationRef 引用产生事件的应用。
type ApplicationRef struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

// ClientInfo 是客户端信息。
type ClientInfo struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// RequestInfo 是请求概要（已脱敏）。
type RequestInfo struct {
	Method      string `json:"method"`
	URI         string `json:"uri"`
	HTTPVersion string `json:"http_version"`
	UserAgent   string `json:"user_agent"`
}

// SecurityInfo 是检测与动作信息。
type SecurityInfo struct {
	AttackType   string      `json:"attack_type"`
	Severity     string      `json:"severity"`
	AnomalyScore int         `json:"anomaly_score"`
	Action       string      `json:"action"`
	StatusCode   int         `json:"status_code"`
	RuleEngine   string      `json:"rule_engine"`
	Matches      []MatchInfo `json:"matches"`
}

// MatchInfo 是单条规则命中信息（已脱敏）。
type MatchInfo struct {
	RuleID          string   `json:"rule_id"`
	Message         string   `json:"message"`
	MatchedVariable string   `json:"matched_variable"`
	MatchedData     string   `json:"matched_data"`
	Severity        string   `json:"severity"`
	Tags            []string `json:"tags"`
}

// GatewayInfo 是网关节点信息。
type GatewayInfo struct {
	Node string `json:"node"`
}

// ---------- 脱敏配置 ----------

// sensitiveHeaderNames 是不会进入事件的请求头。
var sensitiveHeaderNames = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
}

// sensitiveParamNames 是 URI 查询串中需要脱敏的参数名。
var sensitiveParamNames = map[string]bool{
	"password": true, "passwd": true, "pwd": true,
	"token": true, "access_token": true, "refresh_token": true, "id_token": true,
	"secret": true, "api_key": true, "apikey": true, "key": true,
	"session": true, "sessionid": true, "session_id": true,
	"auth": true, "credential": true, "credentials": true,
	"private_key": true, "client_secret": true,
}

const (
	maxMatchedDataLen = 128
	maxUserAgentLen   = 256
	maxURILen         = 2048
)

// ---------- 解析 ----------

// 提取 ModSecurity 风格 [key "value"] 对。
var kvPattern = regexp.MustCompile(`\[([a-zA-Z_]+) "((?:[^"\\]|\\.)*)"\]`)

var scorePattern = regexp.MustCompile(`Total Score: (\d+)`)

// matchedDataPattern 解析 "Matched Data: <sample> found within <VAR>:<param>: <value>"，
// 其中变量部分形如 ARGS:q / REQUEST_HEADERS:User-Agent，参数名不可省略。
var matchedDataPattern = regexp.MustCompile(`^Matched Data: (.*?) found within ([A-Z_]+(?::[^\s:]+)?): (.*)$`)

// attackTypeByTag 将 CRS 攻击标签映射为九章攻击类型。
var attackTypeByTag = map[string]string{
	"attack-sqli":              "SQL_INJECTION",
	"attack-xss":               "XSS",
	"attack-rce":               "COMMAND_INJECTION",
	"attack-lfi":               "LOCAL_FILE_INCLUSION",
	"attack-rfi":               "REMOTE_FILE_INCLUSION",
	"attack-php":               "PHP_CODE_INJECTION",
	"attack-java":              "JAVA_CODE_INJECTION",
	"attack-protocol":          "PROTOCOL_VIOLATION",
	"attack-fixation":          "SESSION_FIXATION",
	"attack-scanner":           "SCANNER",
	"attack-disclosure":        "DATA_DISCLOSURE",
	"attack-injection-generic": "GENERIC_INJECTION",
}

// severityMap 将 CRS severity 映射为九章风险等级。
var severityMap = map[string]string{
	"critical": "HIGH",
	"error":    "MEDIUM",
	"warning":  "LOW",
	"notice":   "INFO",
}

// newUUID 生成 RFC 4122 v4 UUID（避免外部依赖）。
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand 失败属于极端情况，退化为时间戳拼接
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]), hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]))
}

// ParseLine 解析单行审计日志为标准事件。
// 解析失败返回 error，调用方必须将失败记录到错误文件，不得静默丢弃。
func ParseLine(line []byte, gatewayNode string, app ApplicationRef) (*StandardEvent, error) {
	line = []byte(strings.TrimSpace(string(line)))
	if len(line) == 0 {
		return nil, fmt.Errorf("empty line")
	}
	var entry AuditEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		return nil, fmt.Errorf("invalid audit json: %w", err)
	}
	if entry.Transaction.ID == "" {
		return nil, fmt.Errorf("missing transaction id")
	}

	tx := entry.Transaction

	// 时间解析：Coraza 输出 "2006/01/02 15:04:05"（UTC）
	occurred := parseAuditTime(tx.Timestamp)

	// Request ID 关联键：网关注入的 x-request-id 头；
	// 缺失时退化为 Coraza 事务 ID，保证事件仍可检索。
	requestID := firstHeader(tx.Request.Headers, "x-request-id")
	if requestID == "" {
		requestID = tx.ID
	}

	matches := make([]MatchInfo, 0, len(entry.Messages))
	attackType := "UNKNOWN"
	maxSeverityRank := -1
	severity := "INFO"
	anomalyScore := 0

	for _, m := range entry.Messages {
		mi := parseMessage(m.ErrorMessage)
		if mi.RuleID == "" {
			continue
		}
		matches = append(matches, mi)

		// 攻击类型取第一个可识别的攻击标签
		for _, tag := range mi.Tags {
			if at, ok := attackTypeByTag[tag]; ok && attackType == "UNKNOWN" {
				attackType = at
			}
		}
		// 严重等级取最高
		rank := severityRank(mi.Severity)
		if rank > maxSeverityRank {
			maxSeverityRank = rank
			severity = mi.Severity
		}
		// 异常评分从阻断评估规则消息中提取
		if sc := scorePattern.FindStringSubmatch(m.ErrorMessage); len(sc) == 2 {
			if v, err := strconv.Atoi(sc[1]); err == nil && v > anomalyScore {
				anomalyScore = v
			}
		}
	}

	action := "DETECT"
	statusCode := 200
	if tx.IsInterrupted {
		action = "BLOCK"
		statusCode = 403
	}

	return &StandardEvent{
		EventID:     newUUID(),
		RequestID:   requestID,
		OccurredAt:  occurred,
		Application: app,
		Client: ClientInfo{
			IP:   tx.ClientIP,
			Port: tx.ClientPort,
		},
		Request: RequestInfo{
			Method:      tx.Request.Method,
			URI:         maskURI(tx.Request.URI),
			HTTPVersion: tx.Request.Protocol,
			UserAgent:   truncate(firstHeader(tx.Request.Headers, "user-agent"), maxUserAgentLen),
		},
		Security: SecurityInfo{
			AttackType:   attackType,
			Severity:     severity,
			AnomalyScore: anomalyScore,
			Action:       action,
			StatusCode:   statusCode,
			RuleEngine:   tx.Producer.RuleEngine,
			Matches:      matches,
		},
		Gateway: GatewayInfo{Node: gatewayNode},
		RawRef:  fmt.Sprintf("coraza-audit:%s", tx.ID),
	}, nil
}

// parseMessage 解析 ModSecurity 风格错误消息为结构化命中信息。
func parseMessage(em string) MatchInfo {
	kv := map[string]string{}
	var tags []string
	for _, m := range kvPattern.FindAllStringSubmatch(em, -1) {
		key, val := m[1], unescapeQuoted(m[2])
		switch key {
		case "tag":
			tags = append(tags, val)
		default:
			kv[key] = val
		}
	}

	mi := MatchInfo{
		RuleID:   kv["id"],
		Message:  kv["msg"],
		Severity: mapSeverity(kv["severity"]),
		Tags:     tags,
	}

	// 从 data 字段提取匹配变量与匹配数据（脱敏）
	if md := matchedDataPattern.FindStringSubmatch(kv["data"]); len(md) == 4 {
		mi.MatchedVariable = md[2]
		mi.MatchedData = maskMatchedData(md[3])
	} else if kv["data"] != "" {
		mi.MatchedData = maskMatchedData(kv["data"])
	}
	return mi
}

// mapSeverity 映射风险等级，未知值归一化为 INFO。
func mapSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if v, ok := severityMap[s]; ok {
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

func parseAuditTime(ts string) string {
	if t, err := time.ParseInLocation("2006/01/02 15:04:05", ts, time.UTC); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}

func firstHeader(headers map[string][]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// maskURI 对 URI 查询串中的敏感参数值脱敏，保留调查所需的结构信息。
func maskURI(uri string) string {
	uri = truncate(uri, maxURILen)
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
		if sensitiveParamNames[name] {
			parts[i] = p[:eq+1] + "masked"
		}
	}
	return path + "?" + strings.Join(parts, "&")
}

// maskMatchedData 脱敏匹配数据：遮蔽键值模式中的敏感值并限制长度。
func maskMatchedData(data string) string {
	data = strings.TrimSpace(data)
	// 键值模式 password=xxx / token: xxx 遮蔽
	for name := range sensitiveParamNames {
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

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "...(truncated)"
	}
	return s
}

func unescapeQuoted(s string) string {
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `\\`, `\`)
	return s
}

// FilterHeaders 返回剔除敏感头后的请求头副本（供需要输出头部的场景使用）。
func FilterHeaders(headers map[string][]string) map[string][]string {
	out := make(map[string][]string, len(headers))
	for k, v := range headers {
		if sensitiveHeaderNames[strings.ToLower(k)] {
			out[k] = []string{"masked"}
			continue
		}
		out[k] = v
	}
	return out
}
