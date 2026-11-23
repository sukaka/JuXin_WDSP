package l7rules

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/jiuzhang-waf/server/internal/accessrules"
)

// 合法请求方法集合（method 条件 values 白名单，入库统一大写）。
var validMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true,
	"HEAD": true, "OPTIONS": true, "TRACE": true, "CONNECT": true,
}

// 命名条件（header/cookie/query）支持的运算符；
// in 仅由 method/client_ip 以 values 数组表达，命名条件用 regex 覆盖多值场景。
var namedValueOps = map[string]bool{
	OpEq: true, OpNe: true, OpPrefix: true, OpContains: true, OpRegex: true,
}

// ValidateInput 校验并规范化规则输入（原地修改：填默认值、method 大写、CIDR 掩码化等）。
// 校验失败返回包装 ErrInvalidInput 的中文错误。
func ValidateInput(in *RuleInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(in.Name); n == 0 || n > MaxNameRunes {
		return fmt.Errorf("%w: 规则名称必填且不超过%d字符", ErrInvalidInput, MaxNameRunes)
	}
	if in.Priority == 0 {
		in.Priority = 100 // 与 IP 黑白名单惯例一致：未显式设置时默认 100
	}
	if in.Priority < -1000000 || in.Priority > 1000000 {
		return fmt.Errorf("%w: 优先级必须在 -1000000~1000000 之间", ErrInvalidInput)
	}
	if len(in.Conditions) == 0 {
		return fmt.Errorf("%w: 至少需要一条匹配条件", ErrInvalidInput)
	}
	if len(in.Conditions) > MaxConditions {
		return fmt.Errorf("%w: 单规则条件数不能超过%d条", ErrInvalidInput, MaxConditions)
	}
	for i := range in.Conditions {
		if err := validateCondition(&in.Conditions[i]); err != nil {
			return fmt.Errorf("%w: 第%d条条件: %v", ErrInvalidInput, i+1, err)
		}
	}
	return validateActionConfig(in.Action, &in.ActionConfig)
}

// validateCondition 校验并规范化单条条件。
func validateCondition(c *Condition) error {
	c.Type = strings.TrimSpace(c.Type)
	switch c.Type {
	case CondTypeMethod:
		return validateValuesCondition(c, "请求方法")
	case CondTypeClientIP:
		return validateValuesCondition(c, "来源IP")
	case CondTypeURI:
		return validateURICondition(c)
	case CondTypeHost:
		return validateHostCondition(c)
	case CondTypeHeader, CondTypeCookie, CondTypeQuery, CondTypeResponseHeader:
		return validateNamedCondition(c)
	case CondTypeRequestBody, CondTypeResponseBody:
		return validateBodyCondition(c)
	default:
		return fmt.Errorf("条件类型必须为 uri/host/method/header/cookie/query/client_ip/request_body/response_header/response_body，收到: %s", c.Type)
	}
}

// validateBodyCondition 校验正文关键字/正则条件。正文不支持名称、多值和存在性运算。
func validateBodyCondition(c *Condition) error {
	if c.Name != "" || len(c.Values) > 0 {
		return fmt.Errorf("正文条件只支持 op+value，不支持 name/values 字段")
	}
	if !namedValueOps[c.Op] {
		return fmt.Errorf("正文条件运算符必须为 eq/ne/prefix/contains/regex，收到: %s", c.Op)
	}
	return validateCondValue(c)
}

// validateValuesCondition 校验 values 数组型条件（method/client_ip，等价 op=in）。
func validateValuesCondition(c *Condition, label string) error {
	if c.Name != "" || c.Value != "" {
		return fmt.Errorf("%s条件只支持 values 数组，不支持 name/value 字段", label)
	}
	if c.Op != "" && c.Op != OpIn {
		return fmt.Errorf("%s条件等价 op=in，不支持运算符: %s", label, c.Op)
	}
	c.Op = "" // 规范化：values 数组隐含 in 语义，下发不携带 op
	if len(c.Values) == 0 {
		return fmt.Errorf("%s条件的 values 不能为空", label)
	}
	if len(c.Values) > MaxValues {
		return fmt.Errorf("%s条件的 values 不能超过%d个", label, MaxValues)
	}
	for i, v := range c.Values {
		v = strings.TrimSpace(v)
		if v == "" {
			return fmt.Errorf("%s条件的 values 存在空值", label)
		}
		if c.Type == CondTypeMethod {
			v = strings.ToUpper(v)
			if !validMethods[v] {
				return fmt.Errorf("无效的请求方法: %s", v)
			}
		} else {
			// 来源IP：单 IP 或 CIDR，复用黑白名单的严格规范化（v4映射v6归一、CIDR掩码化）
			norm, _, err := accessrules.NormalizeAddress(v)
			if err != nil {
				return err
			}
			v = norm
		}
		c.Values[i] = v
	}
	return nil
}

// validateURICondition 校验 URI 条件（无 name；值 ops + regex）。
func validateURICondition(c *Condition) error {
	if c.Name != "" {
		return fmt.Errorf("URI条件不支持 name 字段")
	}
	if len(c.Values) > 0 {
		return fmt.Errorf("URI条件只支持单值 value，不支持 values 数组")
	}
	if !namedValueOps[c.Op] {
		return fmt.Errorf("URI条件运算符必须为 eq/ne/prefix/contains/regex，收到: %s", c.Op)
	}
	if err := validateCondValue(c); err != nil {
		return err
	}
	if c.Op != OpRegex && !strings.HasPrefix(c.Value, "/") {
		return fmt.Errorf("URI条件值必须以 / 开头: %s", c.Value)
	}
	return nil
}

// validateHostCondition 校验请求域名（Host）条件（无 name；支持 eq/ne/prefix/contains/regex）。
// 非正则条件下拒绝协议/路径/空白与显式端口（网关匹配自动兼容大小写和可选端口），并统一小写归一。
func validateHostCondition(c *Condition) error {
	if c.Name != "" {
		return fmt.Errorf("请求域名条件不支持 name 字段")
	}
	if len(c.Values) > 0 {
		return fmt.Errorf("请求域名条件只支持单值 value，不支持 values 数组")
	}
	if !namedValueOps[c.Op] {
		return fmt.Errorf("请求域名条件运算符必须为 eq/ne/prefix/contains/regex，收到: %s", c.Op)
	}
	if err := validateCondValue(c); err != nil {
		return err
	}
	if c.Op == OpRegex {
		return nil
	}
	v := strings.TrimSpace(c.Value)
	if v == "" {
		return fmt.Errorf("请求域名条件值不能为空")
	}
	if strings.Contains(v, "://") {
		return fmt.Errorf("请求域名不得包含协议（如 https://）: %s", v)
	}
	if strings.ContainsAny(v, "/?#") {
		return fmt.Errorf("请求域名不得包含路径或查询参数: %s", v)
	}
	if strings.ContainsAny(v, " \t\r\n") {
		return fmt.Errorf("请求域名不得包含空白字符: %s", v)
	}
	if host, port, err := net.SplitHostPort(v); err == nil && isOptionalPort(port) {
		if host == "" {
			return fmt.Errorf("无效的请求域名: %s", v)
		}
		return fmt.Errorf("请求域名条件值不得包含端口，匹配时已自动兼容可选端口: %s", v)
	}
	if c.Op == OpEq || c.Op == OpNe {
		if strings.Contains(v, ":") {
			bare := strings.TrimSuffix(strings.TrimPrefix(v, "["), "]")
			if _, err := netip.ParseAddr(bare); err != nil {
				return fmt.Errorf("无效的请求域名（匹配时自动兼容可选端口，无需填写端口）: %s", v)
			}
		}
		norm := NormalizeHost(v)
		if norm == "" {
			return fmt.Errorf("无效的请求域名: %s", v)
		}
		c.Value = norm
		return nil
	}
	c.Value = strings.ToLower(v)
	return nil
}

// NormalizeHost 规范化请求域名（Host）：去空白、剥离合法可选端口（含 [v6]:port）、
// 剥离 IPv6 字面量方括号、转小写并剥离单个 DNS 尾点（与网关 l7rules.NormalizeHost 一致）。
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

// validateNamedCondition 校验命名条件（请求头/Cookie/Query/响应头：name + op + value）。
func validateNamedCondition(c *Condition) error {
	if len(c.Values) > 0 {
		return fmt.Errorf("命名条件只支持单值 value，不支持 values 数组")
	}
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return fmt.Errorf("条件名称不能为空")
	}
	if len(c.Name) > MaxCondNameLen {
		return fmt.Errorf("条件名称长度不能超过%d字符", MaxCondNameLen)
	}
	if c.Type == CondTypeHeader || c.Type == CondTypeCookie || c.Type == CondTypeResponseHeader {
		if !isToken(c.Name) {
			return fmt.Errorf("条件名称含非法字符（须为HTTP token）: %s", c.Name)
		}
	} else if hasControlChar(c.Name) {
		return fmt.Errorf("条件名称含控制字符: %s", c.Name)
	}
	if c.Op == OpExists || c.Op == OpNotExists {
		if c.Value != "" {
			return fmt.Errorf("运算符 %s 不需要 value", c.Op)
		}
		return nil
	}
	if !namedValueOps[c.Op] {
		return fmt.Errorf("运算符必须为 eq/ne/prefix/contains/regex/exists/not_exists，收到: %s", c.Op)
	}
	return validateCondValue(c)
}

// validateCondValue 校验条件值（非空、长度、控制字符；regex 需可编译）。
func validateCondValue(c *Condition) error {
	if c.Value == "" {
		return fmt.Errorf("运算符 %s 需要非空 value", c.Op)
	}
	limit := MaxCondValueLen
	if c.Op == OpRegex {
		limit = MaxRegexLen
	}
	if len(c.Value) > limit {
		return fmt.Errorf("条件值长度不能超过%d字符", limit)
	}
	if hasControlChar(c.Value) {
		return fmt.Errorf("条件值含控制字符")
	}
	if c.Op == OpRegex {
		if _, err := regexp.Compile(c.Value); err != nil {
			return fmt.Errorf("正则表达式无法编译: %v", err)
		}
	}
	return nil
}

// validateActionConfig 校验动作与 action_config 字段匹配，并填充默认值（六键全量存储）。
func validateActionConfig(action string, cfg *ActionConfig) error {
	switch action {
	case ActionBlock, ActionAllow, ActionRedirect, ActionCustomPage:
	default:
		return fmt.Errorf("%w: 动作必须为 block/allow/redirect/custom_page，收到: %s", ErrInvalidInput, action)
	}
	// 默认值（与契约一示例一致：全部六键恒有值）
	if cfg.Status == 0 {
		if action == ActionCustomPage {
			cfg.Status = 200
		} else {
			cfg.Status = 403
		}
	}
	if cfg.RedirectStatus == 0 {
		cfg.RedirectStatus = 302
	}
	if cfg.ContentType == "" {
		cfg.ContentType = "text/html; charset=utf-8"
	}
	// 字段卫生校验（任何动作下只要字段非默认即校验，避免切换动作后脏数据生效）
	if utf8.RuneCountInString(cfg.Message) > MaxMessageRunes {
		return fmt.Errorf("%w: 阻止文案不超过%d字符", ErrInvalidInput, MaxMessageRunes)
	}
	if cfg.RedirectURL != "" {
		if err := validateRedirectURL(cfg.RedirectURL); err != nil {
			return err
		}
	}
	if cfg.RedirectStatus != 301 && cfg.RedirectStatus != 302 {
		return fmt.Errorf("%w: 重定向状态码必须为 301 或 302", ErrInvalidInput)
	}
	if len(cfg.ContentType) > MaxContentTypeLen || hasControlChar(cfg.ContentType) || !strings.Contains(cfg.ContentType, "/") {
		return fmt.Errorf("%w: 无效的 Content-Type: %s", ErrInvalidInput, cfg.ContentType)
	}
	if len(cfg.Body) > MaxBodyBytes {
		return fmt.Errorf("%w: 自定义页面内容不能超过%dKB", ErrInvalidInput, MaxBodyBytes/1024)
	}
	// 动作级强校验
	if action != ActionRedirect {
		cfg.PreservePathQuery = false
	}
	switch action {
	case ActionBlock:
		if cfg.Status < 400 || cfg.Status > 599 {
			return fmt.Errorf("%w: 阻止状态码必须在 400~599 之间", ErrInvalidInput)
		}
	case ActionRedirect:
		if cfg.RedirectURL == "" {
			return fmt.Errorf("%w: 重定向动作必须配置 redirect_url", ErrInvalidInput)
		}
	case ActionCustomPage:
		if cfg.Status < 200 || cfg.Status > 599 {
			return fmt.Errorf("%w: 自定义页面状态码必须在 200~599 之间", ErrInvalidInput)
		}
		if cfg.Body == "" {
			return fmt.Errorf("%w: 自定义页面内容不能为空", ErrInvalidInput)
		}
	}
	return nil
}

// validateRedirectURL 校验重定向 URL：仅 http/https scheme、含主机名、无控制字符。
func validateRedirectURL(raw string) error {
	if len(raw) > MaxRedirectURLLen {
		return fmt.Errorf("%w: 重定向URL长度不能超过%d字符", ErrInvalidInput, MaxRedirectURLLen)
	}
	if hasControlChar(raw) {
		return fmt.Errorf("%w: 重定向URL含控制字符", ErrInvalidInput)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: 无效的重定向URL: %s", ErrInvalidInput, raw)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%w: 重定向URL仅支持 http/https 绝对地址: %s", ErrInvalidInput, raw)
	}
	return nil
}

// isToken 判断是否为合法 HTTP token（RFC 7230 tchar）。
func isToken(s string) bool {
	for _, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", c)
		if !ok {
			return false
		}
	}
	return len(s) > 0
}

// hasControlChar 判断是否含控制字符（含 DEL）。
func hasControlChar(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}
