// Package securityevents 提供安全事件标准化、脱敏、存储与采集。
package securityevents

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/customrules"
	"github.com/jiuzhang-waf/server/internal/wafrules"
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

// customRuleAttackTypes 自定义规则攻击类型词表（与前端 ATTACK_TYPE_META 一致；
// EXCLUSION/OTHER 不产生攻击语义，不入表）。GenerateSecLang 把 attack_type 原样写成
// tag:'<TYPE>'（customrules.GenerateSecLang），此处按同一词表做恒等映射回收攻击类型——
// 否则自定义规则命中在事件聚合里拿不到攻击类型，会被带 attack-* 标签的 CRS 规则
// （如扫描器探测）抢占主类型。
var customRuleAttackTypes = map[string]bool{
	"SQL_INJECTION": true, "XSS": true, "COMMAND_INJECTION": true,
	"LOCAL_FILE_INCLUSION": true, "REMOTE_FILE_INCLUSION": true,
	"PHP_INJECTION": true, "JAVA_INJECTION": true, "PROTOCOL_VIOLATION": true,
	"SESSION_FIXATION": true, "SCANNER_DETECTION": true, "INFORMATION_DISCLOSURE": true,
	"REMOTE_CODE_EXECUTION": true, "SSRF": true, "XXE_INJECTION": true,
	"WEBSHELL": true, "FILE_UPLOAD": true, "DESERIALIZATION": true,
	"SSTI": true, "DOS": true, "MASS_ASSIGNMENT": true,
}

// attackTypeFromTag 解析标签对应的攻击类型：OWASP attack-* 标签走映射表；
// 自定义规则的原始攻击类型标签按词表恒等命中。
func attackTypeFromTag(tag string) (string, bool) {
	if at, ok := attackTypeByTag[tag]; ok {
		return at, true
	}
	if customRuleAttackTypes[tag] {
		return tag, true
	}
	return "", false
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
	// ConnectionIP 原始 TCP 对端地址（guard 经内部头注入；空 = 旧版网关未上报，
	// 落库回退与 client_ip 同值）。审计事务的 client_ip 经真实 IP 改写后不再携带
	// 连接层事实，由此恢复。
	ConnectionIP string
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
	// JWTVerification JWT 信任链验证摘要（WDSP P0-03；可选）。
	// 当前唯一来源 Coraza 审计日志不携带 JWT 验证数据，本字段恒为 nil——
	// 预留给 JWT 感知的事件来源（JWT 处置事件走 access_control_events.details，
	// 见 accesscontrolevents；API 主事件走 api_runtime_events.jwt_verification，
	// 迁移 000127）。历史事件为空，不回填；不落原始 Token/payload/明文 sub/tenant。
	JWTVerification *dsevents.JWTVerification
	// FinalDecision 请求最终处置上下文的 WAF 侧重建（WDSP P0-04，final_decision
	// schema_version=1；迁移 000132 security_events.final_decision JSONB，可空，
	// 历史不回填）：从审计事务事实（中断标记/响应码/命中规则/例外 exc: tag）构建，
	// 与 guard 内存态处置上下文（access_control_events.details.final_decision）经
	// request_id 关联；去重命中时按「已确认拦截优先」条件补全（契约
	// S4_DESIGN_BASELINE §2：先到先得 + 终止动作优先，PENDING_CORRELATION 允许被
	// 真实证据幂等更新）
	FinalDecision *FinalDecision
}

// FinalDecision final_decision（WDSP P0-04，schema_version=1）的 server 侧视图。
// 与网关 disposition.go / gateway eventparser 输出同构的事实子集——审计行可诚实
// 提供的维度；identity_verification/effective_config/steps 等仅 guard 内存态可知
// 的维度缺省（omitempty 省略），由事件详情合并展示时按 request_id 关联补齐。
type FinalDecision struct {
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
	MatchedExceptions []FinalDecisionMatch   `json:"matched_exceptions,omitempty"`
	FinalizedAt       string                 `json:"finalized_at"`
}

// FinalDecisionRuleRef final_decision.rule_refs 条目。
type FinalDecisionRuleRef struct {
	Module string `json:"module"`
	RuleID string `json:"rule_id"`
}

// FinalDecisionMatch final_decision.matched_exceptions 条目（WAF 侧经效果规则
// exc:/excv: tag 反查 exception_id/version；契约 §5 两规则标记法）。
type FinalDecisionMatch struct {
	ExceptionID string   `json:"exception_id"`
	Version     int      `json:"version"`
	Target      string   `json:"target"` // WAF
	RuleRefs    []string `json:"rule_refs,omitempty"`
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
	// CNNVDIDs/CVEIDs 命中规则的漏洞编号标注（CNNVD 兼容性 P1）：详情查询时按
	// rule_id+rule_source 联查 custom_rules/waf_rules 取现值（设计 §7 决策4，
	// 非落库快照）；规则已删除/未标注/联查失败时为空数组 []（静默降级）。
	CNNVDIDs []string `json:"cnnvd_ids"`
	CVEIDs   []string `json:"cve_ids"`
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

// connectionAddrHeader 是 guard 注入的内部头（原始 TCP 对端 host:port；
// gateway/modules/jiuzhang_guard/module.go connectionAddrHeader）。值由
// connection_ip/client_port 字段承接，头本身不进事件留痕。
const connectionAddrHeader = "x-jiuzhang-connection-addr"

// internalHeaders 是网关注入的内部头：从入库头表中剔除（值已由专门字段承接）。
var internalHeaders = map[string]bool{
	connectionAddrHeader: true,
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

	// 连接层事实回填：guard 注入的内部头携带原始 TCP 对端 host:port（RemoteAddr
	// 改写后审计事务不再携带）。头部非法（非 host:port / IP 非法 / 端口越界）时
	// 忽略——ConnectionIP 留空，落库回退与 client_ip 同值。
	if raw := firstHeader(tx.Request.Headers, connectionAddrHeader); raw != "" {
		if host, port, err := net.SplitHostPort(strings.TrimSpace(raw)); err == nil {
			if addr, perr := netip.ParseAddr(host); perr == nil {
				evt.ConnectionIP = addr.String()
			}
			if p, perr := strconv.Atoi(port); perr == nil && p >= 0 && p <= 65535 {
				evt.ClientPort = p
			}
		}
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
	var matchedExceptions []FinalDecisionMatch
	for _, m := range entry.Messages {
		mi := parseMessage(m.ErrorMessage)
		if mi.RuleID == 0 {
			continue
		}
		// WDSP P0-04：受限例外效果规则命中（契约 §5 两规则标记法——规则 ID 落在
		// jiuzhang 例外段 8000001-8004000 且携带 exc:<uuid> tag，excv:<version> 配版）：
		// 转入 final_decision.matched_exceptions，不算攻击命中（不进 Matches/
		// AttackType/Severity）——仅标记命中无攻击的事件 Matches 为空，采集端
		// 按无攻击命中过滤（例外命中不是攻击）
		if mi.RuleID >= exceptionRuleIDMin && mi.RuleID <= exceptionRuleIDMax {
			if excID, excVer, ok := exceptionTagInfo(mi.Tags); ok {
				matchedExceptions = appendFinalDecisionMatch(matchedExceptions, excID, excVer, mi.RuleID)
				continue
			}
		}
		// 规则来源标注：九章内置/用户自定义规则按 ID 段识别（customrules 包常量），
		// 不随 CRS 规则集元数据误标为 OWASP_CRS；版本号仅对 CRS 目录有意义。
		switch {
		case mi.RuleID >= customrules.JiuzhangBuiltinMin && mi.RuleID <= customrules.JiuzhangBuiltinMax:
			mi.RuleSource = "JIUZHANG_BUILTIN"
			mi.RuleVersion = ""
		case mi.RuleID >= customrules.UserCustomMin && mi.RuleID <= customrules.UserCustomMax:
			mi.RuleSource = "USER_CUSTOM"
			mi.RuleVersion = ""
		default:
			mi.RuleSource = ruleSource
			mi.RuleVersion = ruleVersion
		}
		evt.Matches = append(evt.Matches, mi)
		// 攻击类型按「严重度优先」确定：遍历全部匹配收集可映射 tag 候选，
		// 取 severityRank 最高者，并列取先出现者。防止 notice 级扫描器规则
		// （phase 1，先执行）抢在 critical 级攻击规则前面把事件误标为扫描器检测。
		for _, tag := range mi.Tags {
			if at, ok := attackTypeFromTag(tag); ok {
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
	evt.FinalDecision = buildFinalDecision(tx.IsInterrupted, tx.Response.Status, requestID, gatewayNode, occurred, evt.Matches, matchedExceptions)
	return evt, nil
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

// appendFinalDecisionMatch 追加例外命中（同 exception_id 合并 rule_refs，保持先入序）。
func appendFinalDecisionMatch(list []FinalDecisionMatch, id string, version, ruleID int) []FinalDecisionMatch {
	ruleRef := strconv.Itoa(ruleID)
	for i := range list {
		if list[i].ExceptionID == id {
			dup := false
			for _, r := range list[i].RuleRefs {
				if r == ruleRef {
					dup = true
					break
				}
			}
			if !dup {
				list[i].RuleRefs = append(list[i].RuleRefs, ruleRef)
			}
			return list
		}
	}
	return append(list, FinalDecisionMatch{
		ExceptionID: id,
		Version:     version,
		Target:      "WAF",
		RuleRefs:    []string{ruleRef},
	})
}

// buildFinalDecision 从审计事务事实构建 final_decision 的 WAF 侧视图（P0-04）：
// interrupted → ABORTED/BLOCK/WAF/GATEWAY；否则 COMPLETED/NONE/NONE/ORIGIN。
// 规则引用取真实攻击命中（例外命中已分流至 matched_exceptions）。
// 与 gateway eventparser buildFinalDecision 同逻辑（两模块各自独立实现，现有
// parseMessage 等即如此重复——跨 Go module 边界不共享代码）。
func buildFinalDecision(isInterrupted bool, respStatus int, requestID, node string, occurred time.Time, matches []MatchInfo, matchedExceptions []FinalDecisionMatch) *FinalDecision {
	fd := &FinalDecision{
		SchemaVersion: 1,
		RequestID:     requestID,
		GatewayNode:   node,
		FinalizedAt:   occurred.UTC().Format(time.RFC3339),
	}
	if isInterrupted {
		fd.CompletionStatus = "ABORTED"
		fd.SecurityAction = "BLOCK"
		fd.ExecutorModule = "WAF"
		fd.ResponseSource = "GATEWAY"
		fd.HTTPStatus = 403
		// 响应相位（phase 4）中断码已先行写出——response.status 有效 4xx/5xx 取之
		if respStatus >= 400 && respStatus <= 599 {
			fd.HTTPStatus = respStatus
		}
		fd.ResponseCommitted = true
	} else {
		fd.CompletionStatus = "COMPLETED"
		fd.SecurityAction = "NONE"
		fd.ExecutorModule = "NONE"
		fd.ResponseSource = "ORIGIN"
		if respStatus > 0 {
			fd.HTTPStatus = respStatus
		}
		fd.ResponseCommitted = true
	}
	for _, m := range matches {
		fd.RuleRefs = append(fd.RuleRefs, FinalDecisionRuleRef{Module: "WAF", RuleID: strconv.Itoa(m.RuleID)})
	}
	fd.MatchedExceptions = matchedExceptions
	return fd
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
	rawMsg := kv["msg"]
	mi := MatchInfo{
		RuleID:   ruleID,
		RuleName: wafrules.LocalizeRule(ruleID, "", rawMsg),
		Severity: mapSeverity(kv["severity"]),
		Message:  wafrules.LocalizeMatchMessage(ruleID, rawMsg),
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

// maskURI 对 URI 查询串敏感参数脱敏：参数名先 URL 解码再比对敏感名单（pass%77ord=
// 等编码键亦可命中），命中以 "masked" 替换原始（未解码）值；解码失败（非法 % 转义）
// 保持原样不过掩（无法确证敏感）。
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
		name, err := url.QueryUnescape(p[:eq])
		if err != nil {
			continue
		}
		if sensitiveParams[strings.ToLower(name)] {
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

// maskQuery 对查询摘要脱敏（与 maskURI 同一口径）：参数名先 URL 解码再比对敏感名单，
// pass%77ord= 等编码键亦可命中；解码失败（非法 % 转义）保持原样不过掩（无法确证敏感）。
func maskQuery(query string) string {
	parts := strings.Split(query, "&")
	for i, p := range parts {
		eq := strings.Index(p, "=")
		if eq < 0 {
			continue
		}
		name, err := url.QueryUnescape(p[:eq])
		if err != nil {
			continue
		}
		if sensitiveParams[strings.ToLower(name)] {
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

// maskHeaders 返回敏感头掩码后的头部副本（网关注入的内部头整体剔除）。
func maskHeaders(headers map[string][]string) map[string][]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string][]string, len(headers))
	for k, v := range headers {
		if internalHeaders[strings.ToLower(k)] {
			continue
		}
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
