// Package eventparser 将 Coraza JSON 审计日志解析为九章标准安全事件。
// 阶段1 POC：输出到 JSON 文件；后续阶段将对接 PostgreSQL 事件表。
package eventparser

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
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
	// FinalDecision 请求最终处置上下文的 WAF 侧重建（WDSP P0-04，final_decision
	// JSON schema_version=1）：从审计事务事实（中断标记/响应码/命中规则/例外 tag）
	// 构建，与 guard 内存态处置上下文经 request_id 关联；server 侧按「已确认拦截
	// 优先」合并去重（契约 S4_DESIGN_BASELINE §2/§7）
	FinalDecision *FinalDecisionInfo `json:"final_decision,omitempty"`
}

// FinalDecisionInfo final_decision 的 eventparser 重建视图（与网关 disposition.go
// 输出同构的子集：审计行可诚实提供的事实；identity_verification/effective_config
// 等仅 guard 内存态可知的维度留空，由 server 合并补齐）。
type FinalDecisionInfo struct {
	SchemaVersion     int                    `json:"schema_version"`
	RequestID         string                 `json:"request_id"`
	ApplicationID     string                 `json:"application_id,omitempty"`
	GatewayNode       string                 `json:"gateway_node"`
	CompletionStatus  string                 `json:"completion_status"`
	SecurityAction    string                 `json:"security_action"`
	ExecutorModule    string                 `json:"executor_module"`
	ResponseSource    string                 `json:"response_source"`
	HTTPStatus        int                    `json:"http_status,omitempty"`
	ResponseCommitted bool                   `json:"response_committed"`
	RuleRefs          []FinalDecisionRuleRef `json:"rule_refs,omitempty"`
	MatchedExceptions []MatchedExceptionInfo `json:"matched_exceptions,omitempty"`
	FinalizedAt       string                 `json:"finalized_at"`
}

// FinalDecisionRuleRef final_decision.rule_refs 条目。
type FinalDecisionRuleRef struct {
	Module string `json:"module"`
	RuleID string `json:"rule_id"`
}

// MatchedExceptionInfo final_decision.matched_exceptions 条目（WAF 侧经效果规则
// exc:/excv: tag 反查 exception_id/version；契约 §5 两规则标记法）。
type MatchedExceptionInfo struct {
	ExceptionID string   `json:"exception_id"`
	Version     int      `json:"version"`
	Target      string   `json:"target"` // WAF
	RuleRefs    []string `json:"rule_refs,omitempty"`
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
	// ConnectionIP 原始 TCP 对端地址（guard 注入的内部头回填；空 = 未上报）。
	// 审计事务的 client_ip 经真实 IP 改写后不再携带连接层事实，由此恢复。
	ConnectionIP string `json:"connection_ip,omitempty"`
}

// connectionAddrHeader 是 guard 注入的内部头（原始 TCP 对端 host:port；
// gateway/modules/jiuzhang_guard/module.go connectionAddrHeader）。值由
// ClientInfo.ConnectionIP 承接，头本身不进事件输出。
const connectionAddrHeader = "x-jiuzhang-connection-addr"

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

var scorePattern = regexp.MustCompile(`(?:Total Score:\s*|总分[：:]\s*)(\d+)`)

// matchedDataPattern 解析 "Matched Data: <sample> found within <VAR>:<param>: <value>"，
// 其中变量部分形如 ARGS:q / REQUEST_HEADERS:User-Agent，参数名不可省略。
var matchedDataPattern = regexp.MustCompile(`^Matched Data: (.*?) found within ([A-Z_]+(?::[^\s:]+)?): (.*)$`)

// attackTypeByTag 将 CRS 攻击标签映射为九章攻击类型。
var attackTypeByTag = map[string]string{
	"attack-sqli":                    "SQL_INJECTION",
	"attack-xss":                     "XSS",
	"attack-rce":                     "COMMAND_INJECTION",
	"attack-lfi":                     "LOCAL_FILE_INCLUSION",
	"attack-rfi":                     "REMOTE_FILE_INCLUSION",
	"attack-php":                     "PHP_CODE_INJECTION",
	"attack-injection-php":           "PHP_CODE_INJECTION",
	"attack-java":                    "JAVA_CODE_INJECTION",
	"attack-injection-java":          "JAVA_CODE_INJECTION",
	"attack-protocol":                "PROTOCOL_VIOLATION",
	"attack-multipart-header":        "PROTOCOL_VIOLATION",
	"attack-deprecated-header":       "PROTOCOL_VIOLATION",
	"attack-fixation":                "SESSION_FIXATION",
	"attack-scanner":                 "SCANNER",
	"attack-reputation-scanner":      "SCANNER",
	"attack-disclosure":              "DATA_DISCLOSURE",
	"attack-injection-generic":       "GENERIC_INJECTION",
	"OWASP_CRS/METHOD-ENFORCEMENT":   "PROTOCOL_VIOLATION",
	"OWASP_CRS/PROTOCOL-ENFORCEMENT": "PROTOCOL_VIOLATION",
	"OWASP_CRS/PROTOCOL-ATTACK":      "PROTOCOL_VIOLATION",
	"OWASP_CRS/MULTIPART-ATTACK":     "PROTOCOL_VIOLATION",
	"OWASP_CRS/SCANNER-DETECTION":    "SCANNER",
	"OWASP_CRS/WEB-SHELLS":           "WEBSHELL",
	// 以下与规则库同步侧（server/internal/wafrules）保持一致
	"attack-ssrf":            "SSRF",
	"attack-xxe":             "XXE_INJECTION",
	"attack-dos":             "DOS",
	"attack-mass-assignment": "MASS_ASSIGNMENT",
	"attack-deserialization": "DESERIALIZATION",
	"attack-ssti":            "SSTI",
	"attack-upload":          "FILE_UPLOAD",
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

	// 连接层事实回填：guard 内部头携带原始 TCP 对端 host:port（RemoteAddr 改写后
	// 审计事务不再携带）。头部非法时忽略，ConnectionIP 留空。
	connIP := ""
	clientPort := tx.ClientPort
	if raw := firstHeader(tx.Request.Headers, connectionAddrHeader); raw != "" {
		if host, port, err := net.SplitHostPort(strings.TrimSpace(raw)); err == nil {
			if addr, perr := netip.ParseAddr(host); perr == nil {
				connIP = addr.String()
			}
			if p, perr := strconv.Atoi(port); perr == nil && p >= 0 && p <= 65535 {
				clientPort = p
			}
		}
	}
	maxSeverityRank := -1
	severity := "INFO"
	anomalyScore := 0
	var matchedExceptions []MatchedExceptionInfo

	for _, m := range entry.Messages {
		mi := parseMessage(m.ErrorMessage)
		if mi.RuleID == "" {
			continue
		}
		// WDSP P0-04：受限例外效果规则命中（契约 §5 两规则标记法——规则 ID 落在
		// jiuzhang 例外段 8000001-8004000 且携带 exc:<uuid> tag，excv:<version> 配版）：
		// 转入 final_decision.matched_exceptions，不算攻击命中（不进 matches/
		// attackType/severity）——仅标记命中而无攻击的事件 matches 为空，采集端
		// 按无攻击命中过滤（例外命中不是攻击）
		if rid, err := strconv.Atoi(mi.RuleID); err == nil && rid >= exceptionRuleIDMin && rid <= exceptionRuleIDMax {
			if excID, excVer, ok := exceptionTagInfo(mi.Tags); ok {
				matchedExceptions = appendMatchedException(matchedExceptions, excID, excVer, mi.RuleID)
				continue
			}
		}
		matches = append(matches, mi)

		// 攻击类型取第一个可识别的攻击标签（webshell/ 前缀统一归为 WEBSHELL）；
		// 仅在尚未识别（UNKNOWN）时赋值，保持首个命中优先
		for _, tag := range mi.Tags {
			if attackType != "UNKNOWN" {
				continue
			}
			if at, ok := attackTypeByTag[tag]; ok {
				attackType = at
			} else if strings.HasPrefix(tag, "webshell/") {
				attackType = "WEBSHELL"
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
		// 响应相位（phase 4）中断码已先行写入——response.status 有效 4xx/5xx 取之
		if tx.Response.Status >= 400 && tx.Response.Status <= 599 {
			statusCode = tx.Response.Status
		}
	}

	return &StandardEvent{
		EventID:     newUUID(),
		RequestID:   requestID,
		OccurredAt:  occurred,
		Application: app,
		Client: ClientInfo{
			IP:           tx.ClientIP,
			Port:         clientPort,
			ConnectionIP: connIP,
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
		Gateway:       GatewayInfo{Node: gatewayNode},
		RawRef:        fmt.Sprintf("coraza-audit:%s", tx.ID),
		FinalDecision: buildFinalDecision(tx, requestID, app.ID, gatewayNode, occurred, matches, matchedExceptions),
	}, nil
}

// 例外规则 ID 段（契约 §5：marker=8000001+2i、effect=8000002+2i，容量 2000 条）。
const (
	exceptionRuleIDMin = 8000001
	exceptionRuleIDMax = 8004000
)

// exceptionTagInfo 从命中 tag 列表提取例外锚点（exc:<uuid> 必须，excv:<version> 配版）。
func exceptionTagInfo(tags []string) (id string, version int, ok bool) {
	for _, t := range tags {
		if strings.HasPrefix(t, "exc:") {
			id = strings.TrimPrefix(t, "exc:")
		} else if strings.HasPrefix(t, "excv:") {
			if v, err := strconv.Atoi(strings.TrimPrefix(t, "excv:")); err == nil {
				version = v
			}
		}
	}
	return id, version, id != ""
}

// appendMatchedException 追加例外命中（同 exception_id 合并 rule_refs，保持先入序）。
func appendMatchedException(list []MatchedExceptionInfo, id string, version int, ruleID string) []MatchedExceptionInfo {
	for i := range list {
		if list[i].ExceptionID == id {
			dup := false
			for _, r := range list[i].RuleRefs {
				if r == ruleID {
					dup = true
					break
				}
			}
			if !dup {
				list[i].RuleRefs = append(list[i].RuleRefs, ruleID)
			}
			return list
		}
	}
	return append(list, MatchedExceptionInfo{
		ExceptionID: id,
		Version:     version,
		Target:      "WAF",
		RuleRefs:    []string{ruleID},
	})
}

// buildFinalDecision 从审计事务事实构建 final_decision 的 WAF 侧视图（P0-04）：
// interrupted → ABORTED/BLOCK/WAF/GATEWAY；否则 COMPLETED/NONE/NONE/ORIGIN。
// 规则引用取真实攻击命中（例外命中已分流，不进 rule_refs 的关键执法证据——
// 它们体现在 matched_exceptions）。
func buildFinalDecision(tx AuditTransaction, requestID, appID, node, occurred string, matches []MatchInfo, matchedExceptions []MatchedExceptionInfo) *FinalDecisionInfo {
	fd := &FinalDecisionInfo{
		SchemaVersion: 1,
		RequestID:     requestID,
		ApplicationID: appID,
		GatewayNode:   node,
		FinalizedAt:   occurred,
	}
	if tx.IsInterrupted {
		fd.CompletionStatus = "ABORTED"
		fd.SecurityAction = "BLOCK"
		fd.ExecutorModule = "WAF"
		fd.ResponseSource = "GATEWAY"
		fd.HTTPStatus = 403
		if tx.Response.Status >= 400 && tx.Response.Status <= 599 {
			fd.HTTPStatus = tx.Response.Status
		}
		fd.ResponseCommitted = true
	} else {
		fd.CompletionStatus = "COMPLETED"
		fd.SecurityAction = "NONE"
		fd.ExecutorModule = "NONE"
		fd.ResponseSource = "ORIGIN"
		if tx.Response.Status > 0 {
			fd.HTTPStatus = tx.Response.Status
		}
		fd.ResponseCommitted = true
	}
	for _, m := range matches {
		fd.RuleRefs = append(fd.RuleRefs, FinalDecisionRuleRef{Module: "WAF", RuleID: m.RuleID})
	}
	fd.MatchedExceptions = matchedExceptions
	return fd
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
		mi.MatchedData = maskMatchedValue(md[2], md[3])
	} else if kv["data"] != "" {
		mi.MatchedData = maskMatchedData(kv["data"])
	}
	return mi
}

// maskMatchedValue 按命中变量脱敏匹配数据：命中敏感请求/响应头
// （REQUEST_HEADERS:Authorization / Cookie 等）时值段整段遮蔽——
// 键值模式遮蔽无法覆盖 "Bearer xxx" 这类无键值结构的头值。
func maskMatchedValue(variable, value string) string {
	if isSensitiveHeaderVariable(variable) {
		return "masked"
	}
	return maskMatchedData(value)
}

// isSensitiveHeaderVariable 命中变量是否指向敏感头（REQUEST_HEADERS:Authorization 等）。
func isSensitiveHeaderVariable(variable string) bool {
	parts := strings.SplitN(variable, ":", 2)
	if len(parts) != 2 {
		return false
	}
	if parts[0] != "REQUEST_HEADERS" && parts[0] != "RESPONSE_HEADERS" {
		return false
	}
	return sensitiveHeaderNames[strings.ToLower(parts[1])]
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
// 同名敏感参数重复出现时逐处循环遮蔽（strings.Index 只取首处会漏掉第二次起
// 的原样值）；替换后从遮蔽文本之后继续检索，避免死循环。
func maskMatchedData(data string) string {
	data = strings.TrimSpace(data)
	// 键值模式 password=xxx / token: xxx 遮蔽（全部出现位置）
	for name := range sensitiveParamNames {
		for _, sep := range []string{"=", ":"} {
			needle := name + sep
			from := 0
			for from < len(data) {
				idx := strings.Index(strings.ToLower(data[from:]), needle)
				if idx < 0 {
					break
				}
				start := from + idx + len(needle)
				// 跳过分隔符后空白（"token: xxx" 带空格形式）
				for start < len(data) && data[start] == ' ' {
					start++
				}
				end := start
				for end < len(data) && data[end] != ' ' && data[end] != '&' && data[end] != ';' {
					end++
				}
				if end == start {
					from = start // 空值不插入遮蔽标记，继续检索后续出现
					continue
				}
				data = data[:start] + "masked" + data[end:]
				from = start + len("masked")
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
// 网关注入的内部头（连接层事实已由 ClientInfo 承接）一并剔除。
func FilterHeaders(headers map[string][]string) map[string][]string {
	out := make(map[string][]string, len(headers))
	for k, v := range headers {
		if strings.EqualFold(k, connectionAddrHeader) {
			continue
		}
		if sensitiveHeaderNames[strings.ToLower(k)] {
			out[k] = []string{"masked"}
			continue
		}
		out[k] = v
	}
	return out
}
