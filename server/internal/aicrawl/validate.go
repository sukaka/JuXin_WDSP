// validate.go AI 爬虫治理策略与爬虫公钥目录输入校验（纯函数结构校验 + SSRF URL 校验）。
package aicrawl

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/jiuzhang-waf/server/internal/outboundhttp"
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
	return fmt.Sprintf("ai crawl validation failed: %d field(s)", len(e.Errors))
}

var (
	slugPattern          = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	ruleIDPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	receiptHeaderPattern = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
)

func validMode(m string) bool {
	return m == ModeOff || m == ModeObserve || m == ModeProtect
}

func validAction(a string) bool {
	switch a {
	case ActionAllow, ActionRateLimit, ActionChallenge, ActionTarpit, ActionHTTP402, ActionBlock:
		return true
	default:
		return false
	}
}

func validCategory(c string) bool {
	switch c {
	case CategorySearchEngine, CategoryAITraining, CategoryAIAssistant, CategoryAIAgent, CategoryUnknownBot:
		return true
	default:
		return false
	}
}

// NormalizePolicy 归一化策略字段（大小写、去空白、去重）。
func NormalizePolicy(p *Policy) {
	p.SchemaVersion = SchemaVersion
	p.Mode = strings.ToUpper(strings.TrimSpace(p.Mode))
	p.DefaultAIAction = strings.ToUpper(strings.TrimSpace(p.DefaultAIAction))
	if p.DefaultAIAction == "" {
		p.DefaultAIAction = ActionAllow
	}
	p.ContentSignal = strings.TrimSpace(p.ContentSignal)
	p.HTTP402.Message = strings.TrimSpace(p.HTTP402.Message)
	p.HTTP402.PriceHint = strings.TrimSpace(p.HTTP402.PriceHint)
	p.HTTP402.ContactURL = strings.TrimSpace(p.HTTP402.ContactURL)
	p.HTTP402.ReceiptHeader = strings.TrimSpace(p.HTTP402.ReceiptHeader)
	if p.Rules == nil {
		p.Rules = []Rule{}
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		r.ID = strings.TrimSpace(r.ID)
		r.Name = strings.TrimSpace(r.Name)
		r.Category = strings.ToUpper(strings.TrimSpace(r.Category))
		r.AgentID = strings.TrimSpace(r.AgentID)
		r.Action = strings.ToUpper(strings.TrimSpace(r.Action))
		r.UAPatterns = normalizeStrings(r.UAPatterns)
	}
}

// ValidatePolicy 校验应用级 AI 爬虫治理策略全字段（纯结构，无网络 IO）。
func ValidatePolicy(p *Policy) []FieldError {
	errs := []FieldError{}
	add := func(field, msg string) {
		errs = append(errs, FieldError{Field: field, Message: msg})
	}

	if !validMode(p.Mode) {
		add("mode", "仅支持 OFF / OBSERVE / PROTECT")
	}
	if !validAction(p.DefaultAIAction) {
		add("default_ai_action", "仅支持 ALLOW / RATE_LIMIT / CHALLENGE / TARPIT / HTTP_402 / BLOCK")
	}
	if len(p.ContentSignal) > MaxContentSignalLen {
		add("content_signal", fmt.Sprintf("长度不能超过 %d", MaxContentSignalLen))
	} else if hasControlChars(p.ContentSignal) {
		add("content_signal", "不得包含换行或控制字符")
	}
	if p.LabyrinthMaxDepth < MinLabyrinthMaxDepth || p.LabyrinthMaxDepth > MaxLabyrinthMaxDepth {
		add("labyrinth_max_depth", fmt.Sprintf("必须在 %d~%d 之间", MinLabyrinthMaxDepth, MaxLabyrinthMaxDepth))
	}
	if p.LabyrinthMaxConcurrency < MinLabyrinthMaxConcurrency || p.LabyrinthMaxConcurrency > MaxLabyrinthMaxConcurrency {
		add("labyrinth_max_concurrency", fmt.Sprintf("必须在 %d~%d 之间", MinLabyrinthMaxConcurrency, MaxLabyrinthMaxConcurrency))
	}
	if p.LabyrinthDelayMs < MinLabyrinthDelayMs || p.LabyrinthDelayMs > MaxLabyrinthDelayMs {
		add("labyrinth_delay_ms", fmt.Sprintf("必须在 %d~%d 毫秒之间", MinLabyrinthDelayMs, MaxLabyrinthDelayMs))
	}

	if len(p.HTTP402.Message) > MaxHTTP402MessageLen || hasControlChars(p.HTTP402.Message) {
		add("http_402.message", fmt.Sprintf("长度不能超过 %d 且不得包含控制字符", MaxHTTP402MessageLen))
	}
	if len(p.HTTP402.PriceHint) > MaxHTTP402PriceLen || hasControlChars(p.HTTP402.PriceHint) {
		add("http_402.price_hint", fmt.Sprintf("长度不能超过 %d 且不得包含控制字符", MaxHTTP402PriceLen))
	}
	if p.HTTP402.ContactURL != "" {
		if len(p.HTTP402.ContactURL) > MaxHTTP402ContactLen || hasControlChars(p.HTTP402.ContactURL) {
			add("http_402.contact_url", fmt.Sprintf("长度不能超过 %d 且不得包含控制字符", MaxHTTP402ContactLen))
		} else {
			u, err := url.Parse(p.HTTP402.ContactURL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
				add("http_402.contact_url", "须为合法的 http/https 地址")
			}
		}
	}
	if p.HTTP402.ReceiptHeader != "" {
		if len(p.HTTP402.ReceiptHeader) > MaxHTTP402ReceiptLen || !receiptHeaderPattern.MatchString(p.HTTP402.ReceiptHeader) {
			add("http_402.receipt_header", "须为合法 HTTP 响应头名称（字母/数字/短横线，最长 64 字符）")
		}
	}

	if len(p.Rules) > MaxRules {
		add("rules", fmt.Sprintf("规则数量不能超过 %d", MaxRules))
	}
	seenID := map[string]bool{}
	for i, r := range p.Rules {
		prefix := fmt.Sprintf("rules[%d]", i)
		if r.ID == "" || !ruleIDPattern.MatchString(r.ID) {
			add(prefix+".id", "规则 ID 须为 1~64 字符的字母/数字/下划线/短横线/点")
		} else if seenID[r.ID] {
			add(prefix+".id", "规则 ID 不能重复: "+r.ID)
		} else {
			seenID[r.ID] = true
		}
		if r.Name == "" || len(r.Name) > MaxRuleNameLen || hasControlChars(r.Name) {
			add(prefix+".name", fmt.Sprintf("规则名称必填且不超过 %d 字符，不得包含控制字符", MaxRuleNameLen))
		}
		if r.Category != "" && !validCategory(r.Category) {
			add(prefix+".category", "仅支持 SEARCH_ENGINE / AI_TRAINING / AI_ASSISTANT / AI_AGENT / UNKNOWN_BOT")
		}
		if len(r.AgentID) > MaxRuleAgentIDLen || hasControlChars(r.AgentID) {
			add(prefix+".agent_id", fmt.Sprintf("agent_id 长度不能超过 %d 且不得包含控制字符", MaxRuleAgentIDLen))
		}
		if len(r.UAPatterns) > MaxRuleUAPatterns {
			add(prefix+".ua_patterns", fmt.Sprintf("UA 匹配模式不能超过 %d 条", MaxRuleUAPatterns))
		}
		for _, pat := range r.UAPatterns {
			if len(pat) > MaxUAPatternLen || hasControlChars(pat) {
				add(prefix+".ua_patterns", fmt.Sprintf("单条 UA 模式须为 1~%d 字符且不含控制字符", MaxUAPatternLen))
			}
		}
		if r.Category == "" && r.AgentID == "" && len(r.UAPatterns) == 0 {
			add(prefix, "category、agent_id、ua_patterns 至少须指定一项匹配条件")
		}
		if !validAction(r.Action) {
			add(prefix+".action", "仅支持 ALLOW / RATE_LIMIT / CHALLENGE / TARPIT / HTTP_402 / BLOCK")
		}
		if r.RateLimitRPM < 0 || r.RateLimitRPM > 1000000 {
			add(prefix+".rate_limit_rpm", "rate_limit_rpm 必须在 0~1000000 之间")
		}
		if r.Action == ActionRateLimit && r.RateLimitRPM <= 0 {
			add(prefix+".rate_limit_rpm", "action 为 RATE_LIMIT 时 rate_limit_rpm 必须大于 0")
		}
		if r.Priority < 0 || r.Priority > 10000 {
			add(prefix+".priority", "priority 必须在 0~10000 之间")
		}
	}
	return errs
}

// NormalizeDirectory 归一化目录字段。
func NormalizeDirectory(d *Directory) {
	d.Slug = strings.ToLower(strings.TrimSpace(d.Slug))
	d.Name = strings.TrimSpace(d.Name)
	d.Category = strings.ToUpper(strings.TrimSpace(d.Category))
	d.SignatureAgent = strings.TrimSpace(d.SignatureAgent)
	d.DirectoryURL = strings.TrimSpace(d.DirectoryURL)
	if d.Keys == nil {
		d.Keys = []CrawlerKey{}
	}
	for i := range d.Keys {
		d.Keys[i].KID = strings.TrimSpace(d.Keys[i].KID)
		d.Keys[i].Alg = strings.ToLower(strings.TrimSpace(d.Keys[i].Alg))
		d.Keys[i].PublicKeyPEM = strings.TrimSpace(d.Keys[i].PublicKeyPEM)
	}
}

// ValidateDirectory 校验爬虫公钥目录（纯结构 + 公钥 PEM 校验，拒绝私钥）。
func ValidateDirectory(d *Directory) []FieldError {
	errs := []FieldError{}
	add := func(field, msg string) {
		errs = append(errs, FieldError{Field: field, Message: msg})
	}
	if !slugPattern.MatchString(d.Slug) {
		add("slug", "slug 须为 1~64 位小写字母/数字/下划线/短横线，且以字母或数字开头")
	}
	if d.Name == "" || len(d.Name) > MaxDirectoryNameLen || hasControlChars(d.Name) {
		add("name", fmt.Sprintf("目录名称必填且不超过 %d 字符", MaxDirectoryNameLen))
	}
	if !validCategory(d.Category) {
		add("category", "仅支持 SEARCH_ENGINE / AI_TRAINING / AI_ASSISTANT / AI_AGENT / UNKNOWN_BOT")
	}
	if len(d.SignatureAgent) > MaxSignatureAgentLen || hasControlChars(d.SignatureAgent) {
		add("signature_agent", fmt.Sprintf("signature_agent 长度不能超过 %d 且不得包含控制字符", MaxSignatureAgentLen))
	}
	if d.DirectoryURL != "" {
		if len(d.DirectoryURL) > MaxDirectoryURLLen || hasControlChars(d.DirectoryURL) {
			add("directory_url", fmt.Sprintf("directory_url 长度不能超过 %d 且不得包含控制字符", MaxDirectoryURLLen))
		} else {
			u, err := outboundhttp.ParseURL(d.DirectoryURL)
			if err != nil {
				add("directory_url", err.Error())
			} else if !strings.EqualFold(u.Scheme, "https") {
				add("directory_url", "directory_url 仅允许 HTTPS 地址")
			}
		}
	}
	if len(d.Keys) > MaxDirectoryKeys {
		add("keys", fmt.Sprintf("公钥数量不能超过 %d", MaxDirectoryKeys))
	}
	seenKID := map[string]bool{}
	for i, k := range d.Keys {
		kPrefix := fmt.Sprintf("keys[%d]", i)
		if k.KID == "" || len(k.KID) > MaxKIDLen || hasControlChars(k.KID) {
			add(kPrefix+".kid", fmt.Sprintf("kid 必填且长度不超过 %d，不得包含控制字符", MaxKIDLen))
		} else if seenKID[k.KID] {
			add(kPrefix+".kid", "kid 不能重复: "+k.KID)
		} else {
			seenKID[k.KID] = true
		}
		if k.Alg != KeyAlgEd25519 && k.Alg != KeyAlgECDSAP256 {
			add(kPrefix+".alg", "仅支持 ed25519 / ecdsa-p256-sha256")
		} else if err := ValidatePublicKeyPEM(k.Alg, k.PublicKeyPEM); err != nil {
			add(kPrefix+".public_key_pem", err.Error())
		}
	}
	return errs
}

// ValidateDirectoryURLSSRF 对非空 directory_url 执行 SSRF 校验（仅 HTTPS + 公网/allowlist 检查）。
func ValidateDirectoryURLSSRF(ctx context.Context, rawURL string, policy *outboundhttp.Policy) *FieldError {
	if strings.TrimSpace(rawURL) == "" {
		return nil
	}
	u, err := policy.ValidateURL(ctx, rawURL)
	if err != nil {
		return &FieldError{Field: "directory_url", Message: "SSRF 校验未通过: " + err.Error()}
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return &FieldError{Field: "directory_url", Message: "directory_url 仅允许 HTTPS 地址"}
	}
	return nil
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
