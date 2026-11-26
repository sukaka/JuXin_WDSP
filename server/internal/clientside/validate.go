// validate.go 客户端供应链安全策略、脚本授权与违规处置输入校验（纯函数，无网络 IO）。
package clientside

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// FieldError 字段级校验错误。
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError 校验错误集合（handler 映射为 400 details）。
type ValidationError struct {
	Errors []FieldError
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("client side validation failed: %d field(s)", len(e.Errors))
}

var (
	cspSchemeRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:$`)
	cspHostRe   = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:(\*|[0-9]{1,5}))?(/[A-Za-z0-9._~:/@!$&'()*+,;=%-]*)?$`)
	cspNonceRe  = regexp.MustCompile(`^'nonce-[A-Za-z0-9+/=_-]+'$`)
	cspHashRe   = regexp.MustCompile(`^'(sha256|sha384|sha512)-[A-Za-z0-9+/=_-]+'$`)
)

var allowedCSPKeywords = map[string]bool{
	"'self'":             true,
	"'none'":             true,
	"'strict-dynamic'":   true,
	"'unsafe-inline'":    true,
	"'unsafe-eval'":      true,
	"'unsafe-hashes'":    true,
	"'report-sample'":    true,
	"'wasm-unsafe-eval'": true,
}

func validMode(m string) bool {
	return m == ModeOff || m == ModeObserve || m == ModeProtect
}

func validCSPMode(m string) bool {
	return m == CSPModeOff || m == CSPModeReportOnly || m == CSPModeEnforce
}

func validScriptType(t string) bool {
	return t == ScriptTypeExternal || t == ScriptTypeInlineHash
}

func validScriptStatus(s string) bool {
	return s == ScriptStatusDiscovered || s == ScriptStatusAuthorized || s == ScriptStatusBlocked
}

func validViolationType(t string) bool {
	switch t {
	case ViolationUnauthorizedScript, ViolationScriptTampered, ViolationCSPViolation, ViolationProbeAlert:
		return true
	default:
		return false
	}
}

func validViolationStatus(s string) bool {
	switch s {
	case ViolationStatusOpen, ViolationStatusAcknowledged, ViolationStatusResolved, ViolationStatusFalsePositive:
		return true
	default:
		return false
	}
}

// NormalizePolicy 归一化策略字段（大小写、去空白、去重）。
func NormalizePolicy(p *Policy) {
	p.SchemaVersion = SchemaVersion
	p.Mode = strings.ToUpper(strings.TrimSpace(p.Mode))
	p.CSPMode = strings.ToUpper(strings.TrimSpace(p.CSPMode))
	if p.CSPMode == "" {
		p.CSPMode = CSPModeOff
	}
	p.SensitivePaths = normalizeStrings(p.SensitivePaths)
	p.AllowedScriptOrigins = normalizeStrings(p.AllowedScriptOrigins)
	p.AllowedConnectOrigins = normalizeStrings(p.AllowedConnectOrigins)
	p.AllowedFormOrigins = normalizeStrings(p.AllowedFormOrigins)
	p.CustomCSPDirectives = strings.TrimSpace(p.CustomCSPDirectives)
}

// ValidatePolicy 校验应用级客户端供应链安全策略全字段。
func ValidatePolicy(p *Policy) []FieldError {
	errs := []FieldError{}
	add := func(field, msg string) {
		errs = append(errs, FieldError{Field: field, Message: msg})
	}

	if !validMode(p.Mode) {
		add("mode", "仅支持 OFF / OBSERVE / PROTECT")
	}
	if !validCSPMode(p.CSPMode) {
		add("csp_mode", "仅支持 OFF / REPORT_ONLY / ENFORCE")
	}

	if len(p.SensitivePaths) > MaxSensitivePaths {
		add("sensitive_paths", fmt.Sprintf("敏感路径数量不能超过 %d 条", MaxSensitivePaths))
	}
	for i, path := range p.SensitivePaths {
		field := fmt.Sprintf("sensitive_paths[%d]", i)
		if !strings.HasPrefix(path, "/") {
			add(field, "敏感路径必须以 / 开头")
		} else if len(path) > MaxPathLen {
			add(field, fmt.Sprintf("单条敏感路径长度不能超过 %d 字符", MaxPathLen))
		} else if strings.ContainsAny(path, "?#") {
			add(field, "敏感路径不得包含查询参数（?）或锚点（#）")
		} else if hasControlChars(path) || strings.ContainsAny(path, " \t") {
			add(field, "敏感路径不得包含空白或控制字符")
		}
	}

	validateOriginList(p.AllowedScriptOrigins, "allowed_script_origins", add)
	validateOriginList(p.AllowedConnectOrigins, "allowed_connect_origins", add)
	validateOriginList(p.AllowedFormOrigins, "allowed_form_origins", add)

	if len(p.CustomCSPDirectives) > MaxCustomDirectivesLen {
		add("custom_csp_directives", fmt.Sprintf("自定义 CSP 指令长度不能超过 %d 字符", MaxCustomDirectivesLen))
	} else if hasControlChars(p.CustomCSPDirectives) {
		add("custom_csp_directives", "自定义 CSP 指令不得包含换行或控制字符")
	}

	return errs
}

func validateOriginList(origins []string, field string, add func(string, string)) {
	if len(origins) > MaxOrigins {
		add(field, fmt.Sprintf("允许源数量不能超过 %d 条", MaxOrigins))
	}
	for i, tok := range origins {
		itemField := fmt.Sprintf("%s[%d]", field, i)
		if err := ValidateCSPSourceToken(tok); err != nil {
			add(itemField, err.Error())
		}
	}
}

// ValidateCSPSourceToken 校验单条 CSP 源表达式（拒绝 CR/LF、分号、空白与控制字符）。
func ValidateCSPSourceToken(tok string) error {
	if tok == "" {
		return fmt.Errorf("CSP 源令牌不能为空")
	}
	if len(tok) > MaxOriginLen {
		return fmt.Errorf("单条 CSP 源令牌长度不能超过 %d 字符", MaxOriginLen)
	}
	if hasControlChars(tok) || strings.ContainsAny(tok, ";,\r\n\t ") {
		return fmt.Errorf("CSP 源令牌不得包含分号、逗号、空白或换行/控制字符")
	}
	if tok == "*" {
		return nil
	}
	// 单引号关键字、nonce 或哈希源
	if strings.HasPrefix(tok, "'") || strings.HasSuffix(tok, "'") {
		if allowedCSPKeywords[strings.ToLower(tok)] {
			return nil
		}
		if cspNonceRe.MatchString(tok) || cspHashRe.MatchString(tok) {
			return nil
		}
		return fmt.Errorf("不支持的 CSP 关键字令牌: %s", tok)
	}
	// 纯协议源（如 https:、data:、blob:、wss:）
	if strings.HasSuffix(tok, ":") && !strings.Contains(tok, "://") {
		if cspSchemeRe.MatchString(tok) {
			return nil
		}
		return fmt.Errorf("非法的 CSP 协议源: %s", tok)
	}
	// 带协议的 origin / host 源（如 https://cdn.example.com、https://*.example.com:8443）
	if strings.Contains(tok, "://") {
		if strings.ContainsAny(tok, "?#@") {
			return fmt.Errorf("CSP 源令牌不得包含凭据、查询参数或锚点")
		}
		u, err := url.Parse(tok)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("非法的 CSP 源地址: %s", tok)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" && scheme != "ws" && scheme != "wss" {
			return fmt.Errorf("CSP 源协议仅支持 http/https/ws/wss: %s", tok)
		}
		host := u.Hostname()
		if host == "" {
			return fmt.Errorf("CSP 源缺少主机名: %s", tok)
		}
		return nil
	}
	// 无协议主机源（如 cdn.example.com、*.example.com:443）
	if strings.ContainsAny(tok, "?#@") {
		return fmt.Errorf("CSP 主机源不得包含凭据、查询参数或锚点")
	}
	if !cspHostRe.MatchString(tok) {
		return fmt.Errorf("非法的 CSP 源令牌: %s", tok)
	}
	return nil
}

// ValidateSRIHash 校验 SRI 完整性哈希（空串允许；非空须为 sha256-/sha384-/sha512- + 合法 Base64）。
func ValidateSRIHash(sri string) error {
	sri = strings.TrimSpace(sri)
	if sri == "" {
		return nil
	}
	if len(sri) > MaxSRILen {
		return fmt.Errorf("SRI 哈希长度不能超过 %d 字符", MaxSRILen)
	}
	if hasControlChars(sri) || strings.ContainsAny(sri, " \t") {
		return fmt.Errorf("SRI 哈希不得包含空白或控制字符")
	}
	idx := strings.IndexByte(sri, '-')
	if idx <= 0 {
		return fmt.Errorf("SRI 哈希须以 sha256- / sha384- / sha512- 开头")
	}
	alg, b64 := sri[:idx], sri[idx+1:]
	if alg != "sha256" && alg != "sha384" && alg != "sha512" {
		return fmt.Errorf("SRI 哈希算法仅支持 sha256 / sha384 / sha512")
	}
	if b64 == "" {
		return fmt.Errorf("SRI 哈希摘要不能为空")
	}
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(decoded) == 0 {
		return fmt.Errorf("SRI 哈希摘要须为合法 Base64 编码")
	}
	return nil
}

// NormalizeScript 归一化脚本资产字段并派生 script_origin。
func NormalizeScript(s *Script) {
	s.ScriptURL = strings.TrimSpace(s.ScriptURL)
	s.ScriptType = strings.ToUpper(strings.TrimSpace(s.ScriptType))
	s.SRIHash = strings.TrimSpace(s.SRIHash)
	s.ObservedSRI = strings.TrimSpace(s.ObservedSRI)
	s.Status = strings.ToUpper(strings.TrimSpace(s.Status))
	s.Justification = strings.TrimSpace(s.Justification)
	s.SamplePagePath = strings.TrimSpace(s.SamplePagePath)
	if s.ScriptOrigin == "" {
		s.ScriptOrigin = ExtractScriptOrigin(s.ScriptURL, s.ScriptType)
	} else {
		s.ScriptOrigin = strings.TrimSpace(s.ScriptOrigin)
	}
}

// ExtractScriptOrigin 从脚本 URL 与类型派生源标识（EXTERNAL 取 scheme://host 或 'self'，INLINE_HASH 取 inline）。
func ExtractScriptOrigin(scriptURL, scriptType string) string {
	scriptURL = strings.TrimSpace(scriptURL)
	if strings.EqualFold(strings.TrimSpace(scriptType), ScriptTypeInlineHash) {
		return "inline"
	}
	if strings.HasPrefix(scriptURL, "/") {
		return "'self'"
	}
	if u, err := url.Parse(scriptURL); err == nil && u.Scheme != "" && u.Host != "" {
		return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	}
	return ""
}

// ValidateCreateScript 校验新增脚本资产输入（PCI DSS 4.0 6.4.3：AUTHORIZED 必填业务必要性说明）。
func ValidateCreateScript(s *Script) []FieldError {
	errs := []FieldError{}
	add := func(field, msg string) {
		errs = append(errs, FieldError{Field: field, Message: msg})
	}
	if !validScriptType(s.ScriptType) {
		add("script_type", "仅支持 EXTERNAL / INLINE_HASH")
	}
	if s.ScriptURL == "" {
		add("script_url", "脚本地址或内联哈希不能为空")
	} else if len(s.ScriptURL) > MaxScriptURLLen {
		add("script_url", fmt.Sprintf("脚本地址长度不能超过 %d 字符", MaxScriptURLLen))
	} else if hasControlChars(s.ScriptURL) || strings.ContainsAny(s.ScriptURL, " \t") {
		add("script_url", "脚本地址不得包含空白或控制字符")
	} else if s.ScriptType == ScriptTypeExternal {
		if !strings.HasPrefix(s.ScriptURL, "/") {
			u, err := url.Parse(s.ScriptURL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
				add("script_url", "外部脚本地址须为合法 http(s) URL 或以 / 开头的站内路径")
			}
		}
	}
	errs = append(errs, validateScriptMutableFields(s.SRIHash, s.Status, s.Justification)...)
	return errs
}

// ValidateUpdateScript 校验编辑/审批脚本资产输入（PCI DSS 4.0 6.4.3：AUTHORIZED 必填业务必要性说明）。
func ValidateUpdateScript(sriHash, status, justification string) []FieldError {
	return validateScriptMutableFields(sriHash, status, justification)
}

func validateScriptMutableFields(sriHash, status, justification string) []FieldError {
	errs := []FieldError{}
	add := func(field, msg string) {
		errs = append(errs, FieldError{Field: field, Message: msg})
	}
	if !validScriptStatus(status) {
		add("status", "仅支持 DISCOVERED / AUTHORIZED / BLOCKED")
	}
	if err := ValidateSRIHash(sriHash); err != nil {
		add("sri_hash", err.Error())
	}
	if len(justification) > MaxJustificationLen {
		add("justification", fmt.Sprintf("业务必要性说明不能超过 %d 字符", MaxJustificationLen))
	} else if hasDisallowedTextControlChars(justification) {
		add("justification", "业务必要性说明不得包含非法控制字符")
	}
	if status == ScriptStatusAuthorized && strings.TrimSpace(justification) == "" {
		add("justification", "根据 PCI DSS 4.0 6.4.3 要求，授权脚本必须填写业务必要性说明")
	}
	return errs
}

// ValidateViolationStatusUpdate 校验违规告警处置状态与备注。
func ValidateViolationStatusUpdate(status, note string) []FieldError {
	errs := []FieldError{}
	if !validViolationStatus(status) {
		errs = append(errs, FieldError{Field: "status", Message: "仅支持 OPEN / ACKNOWLEDGED / RESOLVED / FALSE_POSITIVE"})
	}
	if len(note) > MaxNoteLen {
		errs = append(errs, FieldError{Field: "note", Message: fmt.Sprintf("处置备注不能超过 %d 字符", MaxNoteLen)})
	} else if hasDisallowedTextControlChars(note) {
		errs = append(errs, FieldError{Field: "note", Message: "处置备注不得包含非法控制字符"})
	}
	return errs
}

func normalizeStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func hasControlChars(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

func hasDisallowedTextControlChars(s string) bool {
	for _, c := range s {
		if c == '\n' || c == '\t' {
			continue
		}
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}
