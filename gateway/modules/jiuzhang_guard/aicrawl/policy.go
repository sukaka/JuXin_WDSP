// Package aicrawl 实现 Phase 9A-2 AI 爬虫治理、Web Bot Auth 目录快照（热路径零网络 IO）
// 与离线确定性 AI Labyrinth 迷宫陷阱。
package aicrawl

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/httpsig"
)

const (
	// SchemaVersion 本网关支持的 ai_crawl_policy 契约版本（不一致 fail-closed 拒载）。
	SchemaVersion = 1

	// 模式枚举。
	ModeOff     = "OFF"
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"

	// 动作枚举（冻结契约）。
	ActionAllow     = "ALLOW"
	ActionRateLimit = "RATE_LIMIT"
	ActionChallenge = "CHALLENGE"
	ActionTarpit    = "TARPIT"
	ActionHTTP402   = "HTTP_402"
	ActionBlock     = "BLOCK"

	// 爬虫分类枚举（冻结契约）。
	CategorySearchEngine = "SEARCH_ENGINE"
	CategoryAITraining   = "AI_TRAINING"
	CategoryAIAssistant  = "AI_ASSISTANT"
	CategoryAIAgent      = "AI_AGENT"
	CategoryUnknownBot   = "UNKNOWN_BOT"

	// Labyrinth 保留命名空间（本地处理，绝不反向代理）。
	LabyrinthReservedNamespace = "/_wdsp/labyrinth/v1/"

	// 默认值与边界。
	DefaultLabyrinthMaxDepth       = 5
	MaxLabyrinthDepth              = 32
	DefaultLabyrinthMaxConcurrency = 256
	MaxLabyrinthConcurrency        = 4096
	DefaultLabyrinthDelayMS        = 150
	MaxLabyrinthDelayMS            = 10000
	DefaultRateLimitRPM            = 60
	MaxRateLimitRPM                = 1_000_000
	DefaultHTTP402Message          = "Payment Required: automated AI access requires authorization or payment."

	maxRules           = 256
	maxDirectories     = 128
	maxKeysPerDir      = 64
	maxUAPatterns      = 64
	maxFieldLen        = 512
	maxShortFieldLen   = 128
	maxAgentIDLen      = 256
	maxKIDLen          = 256
	maxDirURLLen       = 1024
	maxUAPatternLen    = 256
	labyrinthKeyBytes  = 32
	defaultHTTP402Code = http.StatusPaymentRequired
)

// Policy 发布通道下发的 ai_crawl_policy 处理器段（严格解码，json tag 为跨分片冻结契约）。
type Policy struct {
	SchemaVersion           int             `json:"schema_version"`
	ApplicationID           string          `json:"application_id"`
	Mode                    string          `json:"mode"`
	Version                 int             `json:"version"`
	DefaultAIAction         string          `json:"default_ai_action"`
	ContentSignal           string          `json:"content_signal,omitempty"`
	VerifyWebBotAuth        bool            `json:"verify_web_bot_auth"`
	LabyrinthEnabled        bool            `json:"labyrinth_enabled"`
	LabyrinthInjectLinks    bool            `json:"labyrinth_inject_links"`
	LabyrinthMaxDepth       int             `json:"labyrinth_max_depth"`
	LabyrinthMaxConcurrency int             `json:"labyrinth_max_concurrency"`
	LabyrinthDelayMS        int             `json:"labyrinth_delay_ms"`
	LabyrinthKeyHex         string          `json:"labyrinth_key_hex,omitempty"`
	HTTP402                 HTTP402Config   `json:"http_402"`
	Rules                   []Rule          `json:"rules"`
	Directories             []DirectorySpec `json:"directories"`
}

// HTTP402Config HTTP 402 付费/授权提示配置。
type HTTP402Config struct {
	Message       string `json:"message"`
	PriceHint     string `json:"price_hint"`
	ContactURL    string `json:"contact_url"`
	ReceiptHeader string `json:"receipt_header"`
}

// Rule AI 爬虫分类与动作规则。
type Rule struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Category           string   `json:"category"`
	AgentID            string   `json:"agent_id"`
	UAPatterns         []string `json:"ua_patterns"`
	RequireVerifiedSig bool     `json:"require_verified_sig"`
	Action             string   `json:"action"`
	ExemptBotChallenge bool     `json:"exempt_bot_challenge"`
	RateLimitRPM       int      `json:"rate_limit_rpm"`
	Priority           int      `json:"priority"`
}

// DirectorySpec Web Bot Auth 爬虫公钥目录定义。
type DirectorySpec struct {
	ID             string    `json:"id"`
	Slug           string    `json:"slug"`
	Name           string    `json:"name"`
	Category       string    `json:"category"`
	SignatureAgent string    `json:"signature_agent"`
	DirectoryURL   string    `json:"directory_url"`
	Keys           []KeySpec `json:"keys"`
}

// KeySpec 单个目录公钥条目。
type KeySpec struct {
	Kid          string `json:"kid"`
	Alg          string `json:"alg"`
	PublicKeyPEM string `json:"public_key_pem"`
}

// ParseAndValidatePolicy 严格解码（DisallowUnknownFields）并全量校验 ai_crawl_policy。
// 任何未知字段、不支持的 schema_version、非法枚举/边界或 PROTECT+labyrinth 缺密钥均拒绝加载（fail-closed）。
func ParseAndValidatePolicy(raw json.RawMessage) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("ai_crawl_policy: 配置结构解析失败（拒绝加载）: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("ai_crawl_policy: 配置含多余内容（拒绝加载）")
	}
	applyPolicyDefaults(&p)
	if err := ValidatePolicy(&p); err != nil {
		return nil, fmt.Errorf("ai_crawl_policy: 配置校验未通过（拒绝加载）: %w", err)
	}
	return &p, nil
}

func applyPolicyDefaults(p *Policy) {
	if p.DefaultAIAction == "" {
		p.DefaultAIAction = ActionAllow
	}
	if p.LabyrinthMaxDepth == 0 {
		p.LabyrinthMaxDepth = DefaultLabyrinthMaxDepth
	}
	if p.LabyrinthMaxConcurrency == 0 {
		p.LabyrinthMaxConcurrency = DefaultLabyrinthMaxConcurrency
	}
}

// ValidatePolicy 校验解析后的 Policy（不含任何密钥明文到错误消息）。
func ValidatePolicy(p *Policy) error {
	if p == nil {
		return errors.New("policy is nil")
	}
	var errs []error
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if p.SchemaVersion != SchemaVersion {
		add("schema_version: 不支持的版本 %d（本网关支持 %d）", p.SchemaVersion, SchemaVersion)
	}
	switch p.Mode {
	case ModeOff, ModeObserve, ModeProtect:
	default:
		add("mode: 未知强制语义 %q（仅支持 OFF|OBSERVE|PROTECT）", p.Mode)
	}
	if !isValidAction(p.DefaultAIAction) {
		add("default_ai_action: 非法动作 %q", p.DefaultAIAction)
	}
	if len(p.ContentSignal) > maxFieldLen || hasControlChars(p.ContentSignal) {
		add("content_signal: 长度超过 %d 或含控制字符", maxFieldLen)
	}
	if p.LabyrinthMaxDepth < 1 || p.LabyrinthMaxDepth > MaxLabyrinthDepth {
		add("labyrinth_max_depth: 必须在 1..%d 之间，实际 %d", MaxLabyrinthDepth, p.LabyrinthMaxDepth)
	}
	if p.LabyrinthMaxConcurrency < 1 || p.LabyrinthMaxConcurrency > MaxLabyrinthConcurrency {
		add("labyrinth_max_concurrency: 必须在 1..%d 之间，实际 %d", MaxLabyrinthConcurrency, p.LabyrinthMaxConcurrency)
	}
	if p.LabyrinthDelayMS < 0 || p.LabyrinthDelayMS > MaxLabyrinthDelayMS {
		add("labyrinth_delay_ms: 必须在 0..%d 之间，实际 %d", MaxLabyrinthDelayMS, p.LabyrinthDelayMS)
	}

	keyHex := strings.TrimSpace(p.LabyrinthKeyHex)
	if keyHex != "" {
		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil || len(keyBytes) != labyrinthKeyBytes {
			add("labyrinth_key_hex: 必须为 32 字节（64 位十六进制）密钥")
		}
	} else if p.Mode == ModeProtect && p.LabyrinthEnabled {
		add("labyrinth_key_hex: PROTECT 模式启用 AI Labyrinth 时必须配置密钥")
	}

	// HTTP 402 配置校验
	if len(p.HTTP402.Message) > maxFieldLen || hasControlChars(p.HTTP402.Message) {
		add("http_402.message: 长度超过 %d 或含控制字符", maxFieldLen)
	}
	if len(p.HTTP402.PriceHint) > maxShortFieldLen || hasControlChars(p.HTTP402.PriceHint) {
		add("http_402.price_hint: 长度超过 %d 或含控制字符", maxShortFieldLen)
	}
	if p.HTTP402.ContactURL != "" {
		if len(p.HTTP402.ContactURL) > maxFieldLen || hasControlChars(p.HTTP402.ContactURL) {
			add("http_402.contact_url: 长度超过 %d 或含控制字符", maxFieldLen)
		} else if u, err := url.Parse(p.HTTP402.ContactURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			add("http_402.contact_url: 必须为合法 http/https URL")
		}
	}
	if p.HTTP402.ReceiptHeader != "" {
		if len(p.HTTP402.ReceiptHeader) > maxShortFieldLen || !isValidHeaderName(p.HTTP402.ReceiptHeader) {
			add("http_402.receipt_header: 非法 HTTP 头名 %q", p.HTTP402.ReceiptHeader)
		}
	}

	// 规则校验
	if len(p.Rules) > maxRules {
		add("rules: 数量不能超过 %d", maxRules)
	}
	seenRuleID := make(map[string]bool, len(p.Rules))
	for i, r := range p.Rules {
		if r.ID != "" {
			if len(r.ID) > maxShortFieldLen || hasControlChars(r.ID) {
				add("rules[%d].id: 非法 ID", i)
			} else if seenRuleID[r.ID] {
				add("rules[%d].id: 重复的规则 ID %q", i, r.ID)
			}
			seenRuleID[r.ID] = true
		}
		if len(r.Name) > maxShortFieldLen || hasControlChars(r.Name) {
			add("rules[%d].name: 长度超过 %d 或含控制字符", i, maxShortFieldLen)
		}
		if r.Category != "" && !isValidCategory(r.Category) {
			add("rules[%d].category: 非法分类 %q", i, r.Category)
		}
		if len(r.AgentID) > maxAgentIDLen || hasControlChars(r.AgentID) {
			add("rules[%d].agent_id: 非法 agent_id", i)
		}
		if !isValidAction(r.Action) {
			add("rules[%d].action: 非法动作 %q", i, r.Action)
		}
		if r.RateLimitRPM < 0 || r.RateLimitRPM > MaxRateLimitRPM {
			add("rules[%d].rate_limit_rpm: 必须在 0..%d 之间", i, MaxRateLimitRPM)
		}
		if len(r.UAPatterns) > maxUAPatterns {
			add("rules[%d].ua_patterns: 数量不能超过 %d", i, maxUAPatterns)
		}
		for j, pat := range r.UAPatterns {
			if strings.TrimSpace(pat) == "" || len(pat) > maxUAPatternLen || hasControlChars(pat) {
				add("rules[%d].ua_patterns[%d]: 非法 UA 模式", i, j)
			}
		}
	}

	// 目录校验
	if len(p.Directories) > maxDirectories {
		add("directories: 数量不能超过 %d", maxDirectories)
	}
	for i, d := range p.Directories {
		if strings.TrimSpace(d.ID) == "" && strings.TrimSpace(d.Slug) == "" {
			add("directories[%d]: id 与 slug 不能同时为空", i)
		}
		if len(d.ID) > maxShortFieldLen || len(d.Slug) > maxShortFieldLen || len(d.Name) > maxShortFieldLen {
			add("directories[%d]: 标识或名称超长", i)
		}
		if d.Category != "" && !isValidCategory(d.Category) {
			add("directories[%d].category: 非法分类 %q", i, d.Category)
		}
		if d.DirectoryURL != "" {
			if err := validateDirectoryURL(d.DirectoryURL, false); err != nil {
				add("directories[%d].directory_url: %v", i, err)
			}
		}
		if len(d.Keys) > maxKeysPerDir {
			add("directories[%d].keys: 数量不能超过 %d", i, maxKeysPerDir)
		}
		for j, k := range d.Keys {
			if strings.TrimSpace(k.Kid) == "" || len(k.Kid) > maxKIDLen || hasControlChars(k.Kid) {
				add("directories[%d].keys[%d].kid: 非法 kid", i, j)
			}
			alg := strings.ToLower(strings.TrimSpace(k.Alg))
			if alg != httpsig.AlgEd25519 && alg != httpsig.AlgECDSAP256SHA256 {
				add("directories[%d].keys[%d].alg: 仅支持 ed25519|ecdsa-p256-sha256，实际 %q", i, j, k.Alg)
			}
			if err := validatePublicKeyPEM([]byte(k.PublicKeyPEM), alg); err != nil {
				add("directories[%d].keys[%d].public_key_pem: %v", i, j, err)
			}
		}
	}

	return errors.Join(errs...)
}

func validatePublicKeyPEM(raw []byte, alg string) error {
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return errors.New("invalid PEM encoding")
	}
	if !strings.Contains(blk.Type, "PUBLIC KEY") {
		return errors.New("must be a PUBLIC KEY PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return fmt.Errorf("invalid PKIX public key: %w", err)
	}
	switch alg {
	case httpsig.AlgEd25519:
		if _, ok := pub.(ed25519.PublicKey); !ok {
			return errors.New("key type does not match ed25519")
		}
	case httpsig.AlgECDSAP256SHA256:
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok || ec.Curve != elliptic.P256() {
			return errors.New("key type does not match ecdsa-p256-sha256")
		}
	}
	return nil
}

// EngineOptions 引擎装配可选项（测试可注入时钟、Fetcher 与日志回调）。
type EngineOptions struct {
	Now     func() time.Time
	Fetcher *Fetcher
	OnWarn  func(msg string, err error)
}

// Engine AI 爬虫治理运行时引擎（Provision 后只读，热路径零网络 IO）。
type Engine struct {
	policy    *Policy
	rules     []compiledRule
	dirs      *DirectoryStore
	labyrinth *Labyrinth
	now       func() time.Time
}

type compiledRule struct {
	rule     Rule
	patterns []string // 小写归一化后的匹配模式
}

// NewEngine 从已校验的 Policy 构建运行时引擎。
func NewEngine(p *Policy, opts EngineOptions) (*Engine, error) {
	if p == nil {
		return nil, errors.New("aicrawl: nil policy")
	}
	cp := *p
	applyPolicyDefaults(&cp)
	if err := ValidatePolicy(&cp); err != nil {
		return nil, err
	}
	labyrinthKey, err := resolveLabyrinthKey(cp.LabyrinthKeyHex, cp.Mode == ModeProtect && cp.LabyrinthEnabled)
	if err != nil {
		return nil, err
	}
	dirStore, err := NewDirectoryStore(cp.Directories, DirectoryStoreOptions{
		Fetcher: opts.Fetcher,
		OnWarn:  opts.OnWarn,
	})
	if err != nil {
		return nil, err
	}
	labyrinth := NewLabyrinth(LabyrinthConfig{
		Key:            labyrinthKey,
		MaxDepth:       cp.LabyrinthMaxDepth,
		MaxConcurrency: cp.LabyrinthMaxConcurrency,
		Delay:          time.Duration(cp.LabyrinthDelayMS) * time.Millisecond,
	})

	// 按 Priority 升序稳定排序（数值小者优先，与 accesscontrol/l7rules 一致）。
	sortedRules := make([]Rule, len(cp.Rules))
	copy(sortedRules, cp.Rules)
	sort.SliceStable(sortedRules, func(i, j int) bool {
		return sortedRules[i].Priority < sortedRules[j].Priority
	})
	compiled := make([]compiledRule, len(sortedRules))
	for i, r := range sortedRules {
		pats := make([]string, 0, len(r.UAPatterns))
		for _, pat := range r.UAPatterns {
			pats = append(pats, strings.ToLower(strings.TrimSpace(pat)))
		}
		compiled[i] = compiledRule{rule: r, patterns: pats}
	}

	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Engine{
		policy:    &cp,
		rules:     compiled,
		dirs:      dirStore,
		labyrinth: labyrinth,
		now:       nowFn,
	}, nil
}

func resolveLabyrinthKey(keyHex string, required bool) ([]byte, error) {
	trimmed := strings.TrimSpace(keyHex)
	if trimmed != "" {
		b, err := hex.DecodeString(trimmed)
		if err != nil || len(b) != labyrinthKeyBytes {
			return nil, errors.New("aicrawl: invalid labyrinth_key_hex (must be 32-byte hex)")
		}
		return b, nil
	}
	if required {
		return nil, errors.New("aicrawl: labyrinth_key_hex is required when PROTECT mode enables labyrinth")
	}
	ephemeral := make([]byte, labyrinthKeyBytes)
	if _, err := rand.Read(ephemeral); err != nil {
		return nil, fmt.Errorf("aicrawl: generate ephemeral labyrinth key: %w", err)
	}
	return ephemeral, nil
}

// Policy 返回只读策略副本引用。
func (e *Engine) Policy() *Policy { return e.policy }

// Mode 返回策略模式（OFF|OBSERVE|PROTECT）。
func (e *Engine) Mode() string { return e.policy.Mode }

// ContentSignal 返回配置的 Content-Signal 头值（为空表示不下发）。
func (e *Engine) ContentSignal() string { return strings.TrimSpace(e.policy.ContentSignal) }

// HasRemoteDirectories 是否存在配置了 directory_url 的目录需要后台刷新。
func (e *Engine) HasRemoteDirectories() bool { return e.dirs.HasRemoteDirectories() }

// StartBackgroundRefresh 启动远程目录后台刷新（仅在有 directory_url 时启动 goroutine）。
func (e *Engine) StartBackgroundRefresh(ctx context.Context) { e.dirs.StartBackgroundRefresh(ctx) }

// WaitBackgroundRefresh 等待后台刷新 goroutine 退出。
func (e *Engine) WaitBackgroundRefresh() { e.dirs.WaitBackgroundRefresh() }

// Labyrinth 返回离线迷宫处理器。
func (e *Engine) Labyrinth() *Labyrinth { return e.labyrinth }

// Directories 返回目录快照存储。
func (e *Engine) Directories() *DirectoryStore { return e.dirs }

// EvalResult 单请求 AI 爬虫评估结果。
type EvalResult struct {
	Mode               string
	PolicyVersion      int
	Verified           bool
	SigStatus          string // "" | "VERIFIED" | "INVALID"
	SigReason          string
	KeyID              string
	SignatureAgent     string
	AgentID            string
	AgentSlug          string
	AgentName          string
	Category           string
	IsSuspectedBot     bool
	Matched            bool
	RuleID             string
	RuleName           string
	Action             string
	RateLimitRPM       int
	ExemptBotChallenge bool
	InjectTrapLink     bool
}

// Evaluate 对单个请求执行纯本地 AI 爬虫身份验证、分类与策略规则评估（热路径零网络 IO）。
func (e *Engine) Evaluate(r *http.Request) EvalResult {
	res := EvalResult{
		Mode:          e.policy.Mode,
		PolicyVersion: e.policy.Version,
	}
	if e == nil || r == nil || e.policy.Mode == ModeOff {
		return res
	}

	// 1. Web Bot Auth（RFC 9421）纯本地验签（从不可变原子目录快照查找公钥）。
	var matchedKey ResolvedKey
	if e.policy.VerifyWebBotAuth {
		lookup := func(keyID, sigAgent string) (httpsig.Key, bool) {
			rk, ok := e.dirs.Lookup(keyID, sigAgent)
			if !ok {
				return httpsig.Key{}, false
			}
			matchedKey = rk
			return rk.Key, true
		}
		wbaRes, err := httpsig.VerifyWebBotAuth(r, lookup, httpsig.WebBotAuthOptions{Now: e.now})
		switch {
		case err == nil && wbaRes != nil && wbaRes.Verified:
			res.Verified = true
			res.SigStatus = "VERIFIED"
			res.KeyID = wbaRes.KeyID
			res.SignatureAgent = wbaRes.SignatureAgent
			if res.SignatureAgent == "" {
				res.SignatureAgent = matchedKey.SignatureAgent
			}
			res.AgentID = matchedKey.DirectoryID
			res.AgentSlug = matchedKey.Slug
			res.AgentName = matchedKey.Name
			res.Category = matchedKey.Category
		case errors.Is(err, httpsig.ErrWebBotAuthNotPresent):
			// 未携带 web-bot-auth 签名，正常继续 UA/规则分类
		default:
			res.SigStatus = "INVALID"
			res.SigReason = classifyWebBotAuthErr(err)
			res.SignatureAgent = httpsig.ParseSignatureAgent(r.Header.Values("Signature-Agent"), "")
		}
	}

	// 2. 若未通过密码学目录验证，按内置轻量离线 UA 分类器辅助识别。
	ua := r.Header.Get("User-Agent")
	uaLower := strings.ToLower(ua)
	if res.Category == "" {
		res.Category = classifyCrawlerUA(uaLower)
	}
	if res.Category == "" && res.SigStatus == "INVALID" {
		res.Category = CategoryUnknownBot
	}

	// 未验证且属于任意爬虫分类（或携带非法 web-bot-auth 签名）标记为可疑未验证爬虫。
	if !res.Verified && (res.Category != "" || res.SigStatus == "INVALID") {
		res.IsSuspectedBot = true
	}

	// 3. 按优先级顺序匹配策略规则（首中即停）。
	for _, cr := range e.rules {
		if !matchRule(cr, uaLower, res) {
			continue
		}
		res.Matched = true
		res.RuleID = cr.rule.ID
		res.RuleName = cr.rule.Name
		res.Action = cr.rule.Action
		res.RateLimitRPM = cr.rule.RateLimitRPM
		if res.Action == ActionRateLimit && res.RateLimitRPM <= 0 {
			res.RateLimitRPM = DefaultRateLimitRPM
		}
		// 安全底线：仅密码学验签通过的 Web Bot Auth 才允许豁免 Bot JS 挑战。
		if res.Verified && cr.rule.ExemptBotChallenge {
			res.ExemptBotChallenge = true
		}
		break
	}

	// 4. 无显式规则命中时，对 AI 爬虫分类或伪造/无效 Web Bot Auth 签名应用 default_ai_action。
	if !res.Matched && (isAICategory(res.Category) || res.SigStatus == "INVALID") {
		res.Matched = true
		res.Action = e.policy.DefaultAIAction
		if res.Action == ActionRateLimit {
			res.RateLimitRPM = DefaultRateLimitRPM
		}
	}

	// 5. 陷阱链接注入资格：开启 labyrinth_enabled && labyrinth_inject_links，且为未验证可疑爬虫的 HTML GET 请求。
	if e.policy.LabyrinthEnabled && e.policy.LabyrinthInjectLinks && !res.Verified && res.IsSuspectedBot && r.Method == http.MethodGet {
		res.InjectTrapLink = true
	}

	return res
}

func matchRule(cr compiledRule, uaLower string, res EvalResult) bool {
	r := cr.rule
	if r.RequireVerifiedSig && !res.Verified {
		return false
	}
	if r.AgentID != "" {
		if !res.Verified {
			return false
		}
		if !strings.EqualFold(r.AgentID, res.AgentID) &&
			!strings.EqualFold(r.AgentID, res.AgentSlug) &&
			httpsig.NormalizeSignatureAgent(r.AgentID) != httpsig.NormalizeSignatureAgent(res.SignatureAgent) {
			return false
		}
	}
	if r.Category != "" {
		if !strings.EqualFold(r.Category, res.Category) {
			return false
		}
	}
	if len(cr.patterns) > 0 {
		matched := false
		for _, pat := range cr.patterns {
			if matchUAPattern(uaLower, pat) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	// 无任何筛选条件的规则仅对已识别爬虫生效，不误伤普通浏览器。
	if r.AgentID == "" && r.Category == "" && len(cr.patterns) == 0 {
		return res.Verified || res.Category != "" || res.SigStatus == "INVALID"
	}
	return true
}

// matchUAPattern 大小写不敏感子串或简单通配符（*）匹配（零回溯，免疫 ReDoS）。
func matchUAPattern(uaLower, patLower string) bool {
	if patLower == "" {
		return false
	}
	if !strings.Contains(patLower, "*") {
		return strings.Contains(uaLower, patLower)
	}
	parts := strings.Split(patLower, "*")
	idx := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		pos := strings.Index(uaLower[idx:], part)
		if pos < 0 {
			return false
		}
		if i == 0 && !strings.HasPrefix(patLower, "*") && pos != 0 {
			return false
		}
		idx += pos + len(part)
	}
	if !strings.HasSuffix(patLower, "*") {
		last := parts[len(parts)-1]
		if last != "" && !strings.HasSuffix(uaLower, last) {
			return false
		}
	}
	return true
}

type uaSignature struct {
	token    string
	category string
}

// 内置离线已知 AI 与搜索引擎爬虫特征表（顺序由更具体到更泛化）。
var knownCrawlerUAs = []uaSignature{
	// AI 训练爬虫
	{"gptbot", CategoryAITraining},
	{"claudebot", CategoryAITraining},
	{"anthropic-ai", CategoryAITraining},
	{"claude-web", CategoryAITraining},
	{"ccbot", CategoryAITraining},
	{"google-extended", CategoryAITraining},
	{"bytespider", CategoryAITraining},
	{"amazonbot", CategoryAITraining},
	{"meta-externalagent", CategoryAITraining},
	{"applebot-extended", CategoryAITraining},
	{"diffbot", CategoryAITraining},
	{"omgilibot", CategoryAITraining},
	{"cohere-training-data-crawler", CategoryAITraining},
	{"ai2bot", CategoryAITraining},
	{"imagesiftbot", CategoryAITraining},
	{"timpibot", CategoryAITraining},
	{"petalbot", CategoryAITraining},
	// AI 实时助手抓取
	{"chatgpt-user", CategoryAIAssistant},
	{"claude-user", CategoryAIAssistant},
	{"perplexity-user", CategoryAIAssistant},
	{"meta-externalfetcher", CategoryAIAssistant},
	{"duckassistbot", CategoryAIAssistant},
	{"mistralai-user", CategoryAIAssistant},
	// AI Agent / 搜索代理
	{"oai-searchbot", CategoryAIAgent},
	{"perplexitybot", CategoryAIAgent},
	{"claude-searchbot", CategoryAIAgent},
	{"cohere-ai", CategoryAIAgent},
	{"youbot", CategoryAIAgent},
	// 传统搜索引擎
	{"googlebot", CategorySearchEngine},
	{"bingbot", CategorySearchEngine},
	{"baiduspider", CategorySearchEngine},
	{"sogou", CategorySearchEngine},
	{"yandexbot", CategorySearchEngine},
	{"duckduckbot", CategorySearchEngine},
	{"applebot", CategorySearchEngine},
	{"360spider", CategorySearchEngine},
	{"yisouspider", CategorySearchEngine},
	// 未知自动化抓取工具 / 通用爬虫
	{"scrapy", CategoryUnknownBot},
	{"headlesschrome", CategoryUnknownBot},
	{"playwright", CategoryUnknownBot},
	{"puppeteer", CategoryUnknownBot},
	{"selenium", CategoryUnknownBot},
	{"python-requests", CategoryUnknownBot},
	{"python-urllib", CategoryUnknownBot},
	{"httpx", CategoryUnknownBot},
	{"aiohttp", CategoryUnknownBot},
	{"crawler", CategoryUnknownBot},
	{"spider", CategoryUnknownBot},
	{"scraper", CategoryUnknownBot},
	{"bot/", CategoryUnknownBot},
	{"bot;", CategoryUnknownBot},
}

func classifyCrawlerUA(uaLower string) string {
	if uaLower == "" {
		return ""
	}
	for _, sig := range knownCrawlerUAs {
		if strings.Contains(uaLower, sig.token) {
			return sig.category
		}
	}
	return ""
}

func classifyWebBotAuthErr(err error) string {
	switch {
	case errors.Is(err, httpsig.ErrWebBotAuthExpired):
		return "WEB_BOT_AUTH_EXPIRED"
	case errors.Is(err, httpsig.ErrWebBotAuthKeyNotFound):
		return "WEB_BOT_AUTH_KEY_NOT_FOUND"
	case errors.Is(err, httpsig.ErrBudget):
		return "WEB_BOT_AUTH_BUDGET_EXCEEDED"
	case errors.Is(err, httpsig.ErrMalformed):
		return "WEB_BOT_AUTH_MALFORMED"
	default:
		return "WEB_BOT_AUTH_INVALID"
	}
}

func isAICategory(cat string) bool {
	switch cat {
	case CategoryAITraining, CategoryAIAssistant, CategoryAIAgent:
		return true
	}
	return false
}

func isValidAction(a string) bool {
	switch a {
	case ActionAllow, ActionRateLimit, ActionChallenge, ActionTarpit, ActionHTTP402, ActionBlock:
		return true
	}
	return false
}

func isValidCategory(c string) bool {
	switch c {
	case CategorySearchEngine, CategoryAITraining, CategoryAIAssistant, CategoryAIAgent, CategoryUnknownBot:
		return true
	}
	return false
}

func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func isValidHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
