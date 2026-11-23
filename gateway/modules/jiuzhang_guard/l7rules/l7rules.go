// Package l7rules L7 访问控制规则引擎：按 URI/请求域名（Host）/请求方法/请求头/Cookie/Query 参数/来源IP/请求体
// 以及响应头/响应体组合条件（多条件 AND）分阶段匹配，各阶段按优先级升序首中即停。
//
// 配置契约（与管理面发布通道冻结契约一致）：
//
//	{"l7_rules":{"rules":[{"id":"uuid","name":"规则名","priority":100,"enabled":true,
//	  "conditions":[{"type":"uri","op":"prefix","value":"/admin"},
//	    {"type":"host","op":"eq","value":"jxdr.cn"},
//	    {"type":"method","values":["GET","POST"]},
//	    {"type":"header","name":"X-Env","op":"eq","value":"prod"},
//	    {"type":"cookie","name":"session","op":"exists"},
//	    {"type":"query","name":"debug","op":"ne","value":"1"},
//	    {"type":"client_ip","values":["10.0.0.0/8","192.168.1.5"]}],
//	  "action":"block",
//	  "action_config":{"status":403,"message":"访问被拦截","redirect_url":"",
//	    "redirect_status":302,"preserve_path_query":false,"content_type":"text/html; charset=utf-8","body":""}}]}}
//
// 语义约定：
//   - 请求阶段与响应阶段分别按 priority 升序，首个 enabled 且条件全中的规则生效；
//   - 条件 type ∈ uri|host|method|header|cookie|query|client_ip|request_body|response_header|response_body；
//     op ∈ eq|ne|prefix|contains|regex|exists|not_exists|in；
//   - method 与 client_ip 仅用 values（数组，等价 op=in）；uri/host 与正文无 name；
//     header/cookie/query/response_header 用 name+op+value（in 用 name+values）；
//   - exists/not_exists 不需要 value；键不存在时一切值比较（含 ne/in）均为不命中；
//   - 正则使用 RE2（线性时间，防正则拒绝服务），长度 ≤512；
//   - 大小写：method 不敏感（统一大写比较）；host 不敏感且自动忽略可选端口与尾点（小写归一比较）；
//     header 名不敏感（RFC 7230 规范形）；uri/header 值/cookie 名与值/query 名与值均大小写敏感；
//   - 编译失败的规则整条拒绝（由调用方记录加载日志），不影响其余规则。
package l7rules

import (
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/cidr"
)

// 输入上限（与管理面校验对齐，网关侧为第二道防线）。
const (
	maxRules             = 500       // 规则总数上限
	maxConditionsPerRule = 10        // 单规则条件数上限
	maxValuesPerCond     = 64        // 单条件 values 数组上限
	maxRuleIDLen         = 64        // 规则 ID 长度上限（uuid）
	maxRuleNameLen       = 128       // 规则名长度上限
	maxCondNameLen       = 128       // 条件参数名长度上限
	maxCondValueLen      = 1024      // 条件值长度上限
	maxRegexLen          = 512       // 正则长度上限
	maxRedirectURLLen    = 2048      // 重定向 URL 长度上限
	maxBlockMessageLen   = 2048      // 阻止文案长度上限
	maxContentTypeLen    = 128       // Content-Type 长度上限
	MaxPageBodyBytes     = 64 * 1024 // 自定义页面内容上限（64KB）
	maxMethodLen         = 16        // 请求方法名长度上限
	defaultBlockStatus   = http.StatusForbidden
	defaultBlockMessage  = "访问被拦截"
	defaultRedirectCode  = http.StatusFound
	defaultPageStatus    = http.StatusOK
	defaultContentType   = "text/html; charset=utf-8"
)

// Action 规则动作。
type Action string

const (
	ActionBlock      Action = "block"
	ActionAllow      Action = "allow"
	ActionRedirect   Action = "redirect"
	ActionCustomPage Action = "custom_page"
)

// 条件类型。
const (
	condURI            = "uri"
	condHost           = "host"
	condMethod         = "method"
	condHeader         = "header"
	condCookie         = "cookie"
	condQuery          = "query"
	condClientIP       = "client_ip"
	condRequestBody    = "request_body"
	condResponseHeader = "response_header"
	condResponseBody   = "response_body"
)

// 条件运算符。
const (
	opEq        = "eq"
	opNe        = "ne"
	opPrefix    = "prefix"
	opContains  = "contains"
	opRegex     = "regex"
	opExists    = "exists"
	opNotExists = "not_exists"
	opIn        = "in"
)

// ---------- 配置 JSON 结构（冻结契约一） ----------

// Config 发布通道下发的 L7 访问控制配置（guardconfig 载荷 l7_rules 键）。
type Config struct {
	Rules []RuleJSON `json:"rules"`
}

// RuleJSON 一条 L7 访问控制规则。
type RuleJSON struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Priority     int              `json:"priority"`
	Enabled      bool             `json:"enabled"`
	Conditions   []ConditionJSON  `json:"conditions"`
	Action       string           `json:"action"`
	ActionConfig ActionConfigJSON `json:"action_config"`
}

// ConditionJSON 一个匹配条件。
type ConditionJSON struct {
	Type   string   `json:"type"`             // uri|host|method|header|cookie|query|client_ip|request_body|response_header|response_body
	Op     string   `json:"op,omitempty"`     // eq|ne|prefix|contains|regex|exists|not_exists|in
	Name   string   `json:"name,omitempty"`   // header/cookie/query/response_header 参数名
	Value  string   `json:"value,omitempty"`  // 单值（exists/not_exists 不需要）
	Values []string `json:"values,omitempty"` // method/client_ip 或 op=in
}

// ActionConfigJSON 动作配置（按动作取对应字段）。
type ActionConfigJSON struct {
	Status            int    `json:"status,omitempty"`              // block/custom_page 状态码（block 默认 403，custom_page 默认 200）
	Message           string `json:"message,omitempty"`             // block 文案
	RedirectURL       string `json:"redirect_url,omitempty"`        // redirect 目标（仅 http/https）
	RedirectStatus    int    `json:"redirect_status,omitempty"`     // redirect 状态码（301/302，默认 302）
	PreservePathQuery bool   `json:"preserve_path_query,omitempty"` // redirect 是否保留原请求路径和查询参数
	ContentType       string `json:"content_type,omitempty"`        // custom_page 内容类型
	Body              string `json:"body,omitempty"`                // custom_page 内容（≤64KB）
}

// ---------- 编译结果 ----------

// RuleError 单条规则的编译错误（规则整条被拒绝，不影响其余规则）。
type RuleError struct {
	RuleID string
	Err    error
}

// ActionConfig 编译后的动作配置（默认值已填充、URL 已校验）。
type ActionConfig struct {
	Status            int      // block/custom_page 状态码
	Message           string   // block 文案
	RedirectURL       string   // redirect 目标（scheme 仅 http/https）
	RedirectStatus    int      // redirect 状态码（301/302）
	PreservePathQuery bool     // redirect 是否保留原请求路径和查询参数
	redirectBaseURL   *url.URL // compile 期预解析的 redirect 目标
	ContentType       string   // custom_page 内容类型
	Body              string   // custom_page 内容
}

// RedirectTarget 计算最终重定向 Location。
// 未开启 PreservePathQuery 时原样返回 RedirectURL；开启后将当前请求路径与查询参数拼接到目标 URL，
// 自动规避首尾斜杠重复（如 https://www.jxdr.cn/ + /news?id=1 → https://www.jxdr.cn/news?id=1），
// 并剥离查询串中的控制字符防响应头注入。
func (c ActionConfig) RedirectTarget(reqURL *url.URL) string {
	if !c.PreservePathQuery || reqURL == nil {
		return c.RedirectURL
	}
	base := c.redirectBaseURL
	if base == nil {
		parsed, err := url.Parse(c.RedirectURL)
		if err != nil {
			return c.RedirectURL
		}
		base = parsed
	}
	u := *base
	basePath := strings.TrimRight(base.Path, "/")
	baseEscaped := strings.TrimRight(base.EscapedPath(), "/")
	reqPath := normalizeRedirectPath(reqURL.Path)
	reqEscaped := normalizeRedirectPath(reqURL.EscapedPath())
	u.Path = basePath + reqPath
	joinedEscaped := baseEscaped + reqEscaped
	if joinedEscaped != u.Path {
		u.RawPath = joinedEscaped
	} else {
		u.RawPath = ""
	}
	reqQuery := stripControlChars(reqURL.RawQuery)
	if reqQuery != "" {
		if u.RawQuery == "" {
			u.RawQuery = reqQuery
		} else {
			u.RawQuery = u.RawQuery + "&" + reqQuery
		}
	}
	return u.String()
}

// Decision 一次命中评估结果。
type Decision struct {
	RuleID   string
	RuleName string
	Action   Action
	Config   ActionConfig
}

// Engine 编译后的规则引擎（各阶段内按优先级升序首中即停；并发只读安全）。
type Engine struct {
	rules        []*compiledRule
	requestBody  bool
	responseRule bool
}

// compiledRule 编译后的单条规则。
type compiledRule struct {
	id            string
	name          string
	priority      int
	enabled       bool
	conds         []condition
	action        Action
	cfg           ActionConfig
	requestBody   bool
	responsePhase bool
	responseBody  bool
}

// Compile 校验并编译配置：正则预编译、CIDR 预解析、动作配置默认值填充。
// 单条规则编译失败整条拒绝（记入返回错误列表），其余规则正常加载；
// 规则按 priority 升序稳定排序（同优先级保持下发顺序，管理面按 (priority, created_at) 排序后下发）。
func Compile(cfg *Config) (*Engine, []RuleError) {
	e := &Engine{}
	if cfg == nil {
		return e, nil
	}
	var errs []RuleError
	reject := func(r RuleJSON, format string, args ...any) {
		errs = append(errs, RuleError{RuleID: r.ID, Err: fmt.Errorf(format, args...)})
	}
	rules := cfg.Rules
	if len(rules) > maxRules {
		errs = append(errs, RuleError{Err: fmt.Errorf("rules count %d exceeds limit %d, extra rules rejected", len(rules), maxRules)})
		rules = rules[:maxRules]
	}
	for _, r := range rules {
		cr, err := compileRule(r)
		if err != nil {
			reject(r, "%v", err)
			continue
		}
		e.rules = append(e.rules, cr)
		if cr.enabled {
			e.requestBody = e.requestBody || cr.requestBody
			e.responseRule = e.responseRule || cr.responsePhase
		}
	}
	sort.SliceStable(e.rules, func(i, j int) bool { return e.rules[i].priority < e.rules[j].priority })
	return e, errs
}

// RulesCount 成功编译的规则数（含 disabled，评估时跳过）。
func (e *Engine) RulesCount() int {
	if e == nil {
		return 0
	}
	return len(e.rules)
}

// NeedsRequestBody 是否存在启用规则需要读取请求体。
func (e *Engine) NeedsRequestBody() bool { return e != nil && e.requestBody }

// HasResponseRules 是否存在启用规则需要在响应返回后评估。
func (e *Engine) HasResponseRules() bool { return e != nil && e.responseRule }

// compileRule 编译单条规则。
func compileRule(r RuleJSON) (*compiledRule, error) {
	if r.ID == "" {
		return nil, fmt.Errorf("rule id required")
	}
	if len(r.ID) > maxRuleIDLen {
		return nil, fmt.Errorf("rule %q: id too long", r.ID)
	}
	if len(r.Name) > maxRuleNameLen {
		return nil, fmt.Errorf("rule %q: name too long", r.ID)
	}
	if len(r.Conditions) == 0 {
		return nil, fmt.Errorf("rule %q: at least one condition required", r.ID)
	}
	if len(r.Conditions) > maxConditionsPerRule {
		return nil, fmt.Errorf("rule %q: conditions count %d exceeds limit %d", r.ID, len(r.Conditions), maxConditionsPerRule)
	}
	conds := make([]condition, 0, len(r.Conditions))
	requestBody, responsePhase, responseBody := false, false, false
	for i, c := range r.Conditions {
		cc, err := compileCondition(r.ID, i, c)
		if err != nil {
			return nil, err
		}
		conds = append(conds, cc)
		requestBody = requestBody || c.Type == condRequestBody
		responseBody = responseBody || c.Type == condResponseBody
		responsePhase = responsePhase || c.Type == condResponseHeader || c.Type == condResponseBody
	}
	action, cfg, err := compileActionConfig(r)
	if err != nil {
		return nil, err
	}
	return &compiledRule{
		id: r.ID, name: r.Name, priority: r.Priority, enabled: r.Enabled,
		conds: conds, action: action, cfg: cfg,
		requestBody: requestBody, responsePhase: responsePhase, responseBody: responseBody,
	}, nil
}

// compileActionConfig 校验动作与 action_config 字段匹配并填充默认值。
func compileActionConfig(r RuleJSON) (Action, ActionConfig, error) {
	in := r.ActionConfig
	bad := func(format string, args ...any) (Action, ActionConfig, error) {
		return "", ActionConfig{}, fmt.Errorf("rule %q: %s", r.ID, fmt.Sprintf(format, args...))
	}
	switch Action(r.Action) {
	case ActionAllow:
		// allow 无需动作配置
		return ActionAllow, ActionConfig{}, nil
	case ActionBlock:
		status := in.Status
		if status == 0 {
			status = defaultBlockStatus
		}
		if status < 400 || status > 599 {
			return bad("block status must be 4xx/5xx, got %d", status)
		}
		msg := in.Message
		if msg == "" {
			msg = defaultBlockMessage
		}
		if len(msg) > maxBlockMessageLen {
			return bad("block message too long")
		}
		return ActionBlock, ActionConfig{Status: status, Message: msg}, nil
	case ActionRedirect:
		if in.RedirectURL == "" {
			return bad("redirect_url required")
		}
		if len(in.RedirectURL) > maxRedirectURLLen {
			return bad("redirect_url too long")
		}
		if hasControlChar(in.RedirectURL) {
			return bad("redirect_url contains control characters")
		}
		u, err := url.Parse(in.RedirectURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return bad("redirect_url must be an absolute http(s) URL")
		}
		code := in.RedirectStatus
		if code == 0 {
			code = defaultRedirectCode
		}
		if code != http.StatusMovedPermanently && code != http.StatusFound {
			return bad("redirect_status must be 301 or 302, got %d", code)
		}
		return ActionRedirect, ActionConfig{
			RedirectURL:       in.RedirectURL,
			RedirectStatus:    code,
			PreservePathQuery: in.PreservePathQuery,
			redirectBaseURL:   u,
		}, nil
	case ActionCustomPage:
		status := in.Status
		if status == 0 {
			status = defaultPageStatus
		}
		if status < 200 || status > 599 {
			return bad("custom_page status must be 2xx-5xx, got %d", status)
		}
		ct := in.ContentType
		if ct == "" {
			ct = defaultContentType
		}
		if len(ct) > maxContentTypeLen {
			return bad("content_type too long")
		}
		if _, _, err := mime.ParseMediaType(ct); err != nil {
			return bad("invalid content_type %q", ct)
		}
		if len(in.Body) > MaxPageBodyBytes {
			return bad("custom_page body exceeds 64KB")
		}
		return ActionCustomPage, ActionConfig{Status: status, ContentType: ct, Body: in.Body}, nil
	default:
		return bad("unknown action %q", r.Action)
	}
}

// ---------- 条件编译 ----------

// condition 编译后的匹配条件。
type condition interface {
	match(in *evalInput) bool
}

// stringCond 字符串条件（uri/header/response_header/cookie/query/request_body/response_body）。
// 多值目标（header/response_header/query/cookie）评估全部值：正向操作符（eq/prefix/contains/regex/in）
// 任一值命中即真；否定操作符（ne）要求全部值均不等于目标值（任一值等于目标即失败），防重复头/参数/Cookie 绕过。
type stringCond struct {
	target func(in *evalInput) (vals []string, present bool)
	op     string
	value  string
	values map[string]struct{} // op=in
	re     *regexp.Regexp      // op=regex（预编译）
}

func (c *stringCond) match(in *evalInput) bool {
	vals, present := c.target(in)
	switch c.op {
	case opExists:
		return present
	case opNotExists:
		return !present
	}
	// 键不存在时一切值比较（含 ne/in）均不命中
	if !present || len(vals) == 0 {
		return false
	}
	if c.op == opNe {
		for _, val := range vals {
			if val == c.value {
				return false
			}
		}
		return true
	}
	for _, val := range vals {
		switch c.op {
		case opEq:
			if val == c.value {
				return true
			}
		case opPrefix:
			if strings.HasPrefix(val, c.value) {
				return true
			}
		case opContains:
			if strings.Contains(val, c.value) {
				return true
			}
		case opRegex:
			if c.re.MatchString(val) {
				return true
			}
		case opIn:
			if _, ok := c.values[val]; ok {
				return true
			}
		}
	}
	return false
}

// methodCond 请求方法条件（values 集合，大小写不敏感）。
type methodCond struct {
	set map[string]struct{}
}

func (c *methodCond) match(in *evalInput) bool {
	_, ok := c.set[in.method]
	return ok
}

// ipCond 来源 IP 条件（values 为 IP/CIDR，预解析为前缀匹配器）。
type ipCond struct {
	matcher *cidr.Matcher
}

func (c *ipCond) match(in *evalInput) bool {
	return c.matcher.Contains(in.clientIP)
}

// compileCondition 编译单个条件。
func compileCondition(ruleID string, idx int, c ConditionJSON) (condition, error) {
	fail := func(format string, args ...any) (condition, error) {
		return nil, fmt.Errorf("rule %q: condition[%d]: %s", ruleID, idx, fmt.Sprintf(format, args...))
	}
	switch c.Type {
	case condURI, condHost, condHeader, condCookie, condQuery, condRequestBody, condResponseHeader, condResponseBody:
		return compileStringCond(fail, c)
	case condMethod:
		return compileMethodCond(fail, c)
	case condClientIP:
		return compileIPCond(fail, c)
	default:
		return fail("unknown condition type %q", c.Type)
	}
}

// compileStringCond 编译 URI、Host、头、Cookie、Query 与正文字符串条件。
func compileStringCond(fail func(string, ...any) (condition, error), c ConditionJSON) (condition, error) {
	switch c.Op {
	case opEq, opNe, opPrefix, opContains, opRegex, opIn, opExists, opNotExists:
	default:
		return fail("unknown op %q", c.Op)
	}
	isBody := c.Type == condRequestBody || c.Type == condResponseBody
	if (c.Type == condURI || c.Type == condHost || isBody) && (c.Op == opExists || c.Op == opNotExists) {
		return fail("%s does not support exists/not_exists", c.Type)
	}
	if isBody && c.Op == opIn {
		return fail("%s does not support in", c.Type)
	}
	if isBody && (c.Name != "" || c.Value == "") {
		return fail("body condition requires value and does not support name")
	}
	var target func(in *evalInput) ([]string, bool)
	switch c.Type {
	case condURI:
		if len(c.Value) > maxCondValueLen {
			return fail("value too long")
		}
		target = func(in *evalInput) ([]string, bool) { return []string{in.path}, true }
	case condHost:
		if c.Name != "" {
			return fail("host condition does not support name")
		}
		target = func(in *evalInput) ([]string, bool) {
			if in.host == "" {
				return nil, false
			}
			return []string{in.host}, true
		}
	case condHeader, condResponseHeader:
		if !validToken(c.Name) || len(c.Name) > maxCondNameLen {
			return fail("invalid header name %q", c.Name)
		}
		name := textproto.CanonicalMIMEHeaderKey(c.Name)
		target = func(in *evalInput) ([]string, bool) {
			headers := in.header
			if c.Type == condResponseHeader {
				headers = in.responseHeader
			}
			vals, ok := headers[name]
			if !ok || len(vals) == 0 {
				return nil, false
			}
			return vals, true
		}
	case condCookie:
		if !validToken(c.Name) || len(c.Name) > maxCondNameLen {
			return fail("invalid cookie name %q", c.Name)
		}
		name := c.Name
		target = func(in *evalInput) ([]string, bool) {
			vals, ok := in.cookies[name]
			if !ok || len(vals) == 0 {
				return nil, false
			}
			return vals, true
		}
	case condQuery:
		if c.Name == "" || len(c.Name) > maxCondNameLen || hasControl(c.Name) {
			return fail("invalid query name %q", c.Name)
		}
		name := c.Name
		target = func(in *evalInput) ([]string, bool) {
			vals, ok := in.query[name]
			if !ok || len(vals) == 0 {
				return nil, false
			}
			return vals, true
		}
	case condRequestBody:
		target = func(in *evalInput) ([]string, bool) {
			if !in.requestBodyReady {
				return nil, false
			}
			return []string{in.requestBody}, true
		}
	case condResponseBody:
		target = func(in *evalInput) ([]string, bool) {
			if !in.responseBodyReady {
				return nil, false
			}
			return []string{in.responseBody}, true
		}
	}
	out := &stringCond{target: target, op: c.Op, value: c.Value}
	switch c.Op {
	case opExists, opNotExists:
	case opRegex:
		if len(c.Value) == 0 || len(c.Value) > maxRegexLen {
			return fail("regex required and must be <= %d chars", maxRegexLen)
		}
		re, err := regexp.Compile(c.Value)
		if err != nil {
			return fail("bad regex: %v", err)
		}
		if c.Type == condHost {
			// Host 匹配大小写不敏感；请求侧已小写归一，正则包一层 (?i:...) 兼容大写字面量模式
			re, err = regexp.Compile("(?i:" + c.Value + ")")
			if err != nil {
				return fail("bad regex: %v", err)
			}
		}
		out.re = re
	case opIn:
		if len(c.Values) == 0 || len(c.Values) > maxValuesPerCond {
			return fail("values required and must be <= %d", maxValuesPerCond)
		}
		set := make(map[string]struct{}, len(c.Values))
		for _, v := range c.Values {
			if len(v) > maxCondValueLen {
				return fail("value too long")
			}
			if c.Type == condHost {
				v = NormalizeHost(v)
				if v == "" {
					return fail("host value required")
				}
			}
			set[v] = struct{}{}
		}
		out.values = set
	default:
		if len(c.Value) > maxCondValueLen {
			return fail("value too long")
		}
		if c.Type == condHost {
			if c.Op == opEq || c.Op == opNe {
				out.value = NormalizeHost(c.Value)
			} else {
				out.value = strings.ToLower(strings.TrimSpace(c.Value))
			}
			if out.value == "" {
				return fail("host value required")
			}
		}
	}
	return out, nil
}

// compileMethodCond 编译请求方法条件（仅用 values，大小写不敏感统一大写）。
func compileMethodCond(fail func(string, ...any) (condition, error), c ConditionJSON) (condition, error) {
	if c.Op != "" && c.Op != opIn {
		return fail("method only supports values (op=in)")
	}
	if len(c.Values) == 0 || len(c.Values) > maxValuesPerCond {
		return fail("method values required and must be <= %d", maxValuesPerCond)
	}
	set := make(map[string]struct{}, len(c.Values))
	for _, m := range c.Values {
		m = strings.ToUpper(m)
		if !validToken(m) || len(m) > maxMethodLen {
			return fail("invalid method %q", m)
		}
		set[m] = struct{}{}
	}
	return &methodCond{set: set}, nil
}

// compileIPCond 编译来源 IP 条件（values 为 IP/CIDR，预解析）。
func compileIPCond(fail func(string, ...any) (condition, error), c ConditionJSON) (condition, error) {
	if c.Op != "" && c.Op != opIn {
		return fail("client_ip only supports values (op=in)")
	}
	if len(c.Values) == 0 || len(c.Values) > maxValuesPerCond {
		return fail("client_ip values required and must be <= %d", maxValuesPerCond)
	}
	entries := make([]cidr.Entry, 0, len(c.Values))
	for _, v := range c.Values {
		pfx, err := cidr.ParseAddress(v)
		if err != nil {
			return fail("invalid client_ip value %q: %v", v, err)
		}
		entries = append(entries, cidr.Entry{Prefix: pfx, Meta: v})
	}
	return &ipCond{matcher: cidr.NewMatcher(entries)}, nil
}

// validToken 校验 RFC 7230 token（header/cookie 名、方法名）。
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", b) >= 0:
		default:
			return false
		}
	}
	return true
}

// hasControl 是否含控制字符或空白（防日志注入与畸形输入）。
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x21 || r == 0x7f {
			return true
		}
	}
	return false
}

// hasControlChar 是否含控制字符（含 DEL，不含普通空格）。
func hasControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// stripControlChars 剥离控制字符（用于构造安全的 Location 查询串）。
func stripControlChars(s string) string {
	if !hasControlChar(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// normalizeRedirectPath 规范化重定向追加路径：空路径补 "/"、非 "/" 开头补前缀、折叠前导 "//" 避免协议相对歧义。
func normalizeRedirectPath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	for strings.HasPrefix(p, "//") {
		p = p[1:]
	}
	return p
}

// NormalizeHost 规范化请求域名（Host）：去空白、剥离合法可选端口（含 [v6]:port）、
// 剥离 IPv6 字面量方括号、转小写并剥离单个 DNS 尾点（如 "JXDR.CN.:443" -> "jxdr.cn"）。
func NormalizeHost(raw string) string {
	h := strings.TrimSpace(raw)
	if h == "" {
		return ""
	}
	if host, port, err := net.SplitHostPort(h); err == nil && isOptionalPort(port) {
		h = host
	}
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	h = strings.ToLower(h)
	if len(h) > 1 && strings.HasSuffix(h, ".") && !strings.HasSuffix(h, "..") {
		h = h[:len(h)-1]
	}
	return h
}

func isOptionalPort(port string) bool {
	if port == "" {
		return true
	}
	if len(port) > 5 {
		return false
	}
	n := 0
	for i := 0; i < len(port); i++ {
		c := port[i]
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n >= 1 && n <= 65535
}

func extractRequestHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	if r.Host != "" {
		return r.Host
	}
	if h := r.Header.Get("Host"); h != "" {
		return h
	}
	if r.URL != nil {
		return r.URL.Host
	}
	return ""
}

// ---------- 评估 ----------

// evalInput 单请求预取的条件输入（一次解析，全条件复用）。
type evalInput struct {
	method            string              // 大写规范化
	path              string              // CanonicalPath(r.URL.Path)
	host              string              // NormalizeHost(r.Host)：小写且已忽略可选端口
	header            http.Header         // 规范形键
	cookies           map[string][]string // cookie 名 -> 全部值（防同名多 Cookie 绕过）
	query             url.Values
	clientIP          netip.Addr
	requestBody       string
	requestBodyReady  bool
	responseHeader    http.Header
	responseBody      string
	responseBodyReady bool
}

// newEvalInput 从请求构造评估输入。clientIP 为 guard 已识别的真实客户端 IP。
func newEvalInput(r *http.Request, clientIP netip.Addr) *evalInput {
	in := &evalInput{
		method:   strings.ToUpper(r.Method),
		path:     normalizer.CanonicalPath(r.URL.Path),
		host:     NormalizeHost(extractRequestHost(r)),
		header:   r.Header,
		query:    r.URL.Query(),
		clientIP: clientIP,
	}
	if len(r.Header.Values("Cookie")) > 0 {
		in.cookies = make(map[string][]string, 8)
		for _, ck := range r.Cookies() {
			in.cookies[ck.Name] = append(in.cookies[ck.Name], ck.Value)
		}
	}
	return in
}

// ResponseInput 是响应阶段的评估输入。正文只有完整读取或成功有界解压后才标记 Ready。
type ResponseInput struct {
	Header           http.Header
	Body             []byte
	BodyReady        bool
	RequestBody      []byte
	RequestBodyReady bool
}

// Eval 保持原请求前评估入口；正文按完整空体处理，旧规则行为不变。
func (e *Engine) Eval(r *http.Request, clientIP netip.Addr) (Decision, bool) {
	return e.EvalRequest(r, clientIP, nil, true)
}

// EvalRequest 评估请求阶段规则；含响应条件的规则在本阶段跳过。
func (e *Engine) EvalRequest(r *http.Request, clientIP netip.Addr, body []byte, bodyReady bool) (Decision, bool) {
	return e.eval(r, clientIP, ResponseInput{RequestBody: body, RequestBodyReady: bodyReady}, false, false)
}

// EvalResponse 评估含响应条件的规则，请求条件仍在同一规则内按 AND 参与匹配。
func (e *Engine) EvalResponse(r *http.Request, clientIP netip.Addr, in ResponseInput) (Decision, bool) {
	return e.eval(r, clientIP, in, true, false)
}

// EvalResponseHeaders 仅评估不含 response_body 条件的响应头规则（用于 WriteHeader/切直通前即时拦截，
// 防止超大响应体或流式/Flush 绕过 response_header 阻断规则，N-01）。
func (e *Engine) EvalResponseHeaders(r *http.Request, clientIP netip.Addr, in ResponseInput) (Decision, bool) {
	return e.eval(r, clientIP, in, true, true)
}

func (e *Engine) eval(r *http.Request, clientIP netip.Addr, response ResponseInput, responsePhase, headersOnly bool) (Decision, bool) {
	if e == nil || len(e.rules) == 0 {
		return Decision{}, false
	}
	in := newEvalInput(r, clientIP)
	in.requestBody = string(response.RequestBody)
	in.requestBodyReady = response.RequestBodyReady
	in.responseHeader = response.Header
	in.responseBody = string(response.Body)
	in.responseBodyReady = response.BodyReady
	for _, rule := range e.rules {
		if !rule.enabled || rule.responsePhase != responsePhase {
			continue
		}
		if headersOnly && rule.responseBody {
			continue
		}
		matched := true
		for _, c := range rule.conds {
			if !c.match(in) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		return Decision{RuleID: rule.id, RuleName: rule.name, Action: rule.action, Config: rule.cfg}, true
	}
	return Decision{}, false
}
