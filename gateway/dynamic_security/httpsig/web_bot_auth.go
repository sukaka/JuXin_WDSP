// web_bot_auth.go Web Bot Auth（RFC 9421 + IETF Web Bot Auth 签名认证）纯本地验证实现。
//
// 纪律与边界：
//   - 与 machine identity（ParseHeaders/VerifySignatureBase）共享同包 RFC 8941 SF
//     解析与 stdlib 密码学验签基础，零改动既有机器身份契约与测试；
//   - 仅处理带 tag="web-bot-auth" 的签名标签（同请求可并存其他签名标签，互不干扰）；
//   - 强制校验 created/expires 时效边界（默认最大有效期 300s，时钟漂移容忍 30s）；
//   - 强制要求覆盖成分包含 @authority；支持 Signature-Agent 请求头解析与绑定；
//   - 仅允许 Ed25519（ed25519）与 ECDSA P-256（ecdsa-p256-sha256）非对称验签，
//     拒绝弱算法/对称算法/未知算法；
//   - 纯函数、热路径零网络 IO：密钥通过调用方传入的本地目录快照回调按 (keyid, signature_agent) 查找。
package httpsig

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// WebBotAuthTag IETF Web Bot Auth 签名标签参数固定值。
	WebBotAuthTag = "web-bot-auth"
	// WebBotAuthMaxLifetime 签名有效期硬上限（expires - created ≤ 300s）。
	WebBotAuthMaxLifetime = 300 * time.Second
	// WebBotAuthMaxClockSkew 允许的时钟漂移（±30s）。
	WebBotAuthMaxClockSkew = 30 * time.Second
)

var (
	// ErrWebBotAuthNotPresent 请求未携带 tag="web-bot-auth" 的 RFC 9421 签名。
	ErrWebBotAuthNotPresent = errors.New("httpsig: web-bot-auth signature not present")
	// ErrWebBotAuthExpired 签名 created/expires 越界、已过期或有效期超过上限。
	ErrWebBotAuthExpired = errors.New("httpsig: web-bot-auth signature time bounds invalid")
	// ErrWebBotAuthKeyNotFound 目录快照中未找到匹配 keyid（及 Signature-Agent）的公钥。
	ErrWebBotAuthKeyNotFound = errors.New("httpsig: web-bot-auth key not found")
)

// WebBotAuthParams 解析后的 Web Bot Auth 签名参数。
type WebBotAuthParams struct {
	Label             string
	KeyID             string
	Alg               string // 可选；缺省时由目录密钥 Alg 决定
	Nonce             string // 可选
	Tag               string // 固定 "web-bot-auth"
	Created           int64
	Expires           int64
	SignatureAgent    string // 解析归一化前的逻辑 Signature-Agent（已去外层 SF 引号）
	CoveredComponents []string

	member   sfMember
	sigBytes []byte
}

// WebBotAuthOptions 验证选项（零值字段均采用规范默认值）。
type WebBotAuthOptions struct {
	Now         func() time.Time
	MaxLifetime time.Duration
	ClockSkew   time.Duration
	Budgets     Budgets
}

// WebBotAuthKeyLookup 按 keyid 与 Signature-Agent 在本地不可变目录快照中查找公钥。
type WebBotAuthKeyLookup func(keyID, signatureAgent string) (Key, bool)

// WebBotAuthResult Web Bot Auth 验证成功产物。
type WebBotAuthResult struct {
	Verified          bool
	Label             string
	KeyID             string
	Alg               string
	SignatureAgent    string
	Created           int64
	Expires           int64
	Nonce             string
	CoveredComponents []string
}

// ParseWebBotAuth 解析 HTTP 请求中的 Web Bot Auth（tag="web-bot-auth"）签名头。
// 若请求未携带 Signature-Input 或其中不含 tag="web-bot-auth" 的签名标签，
// 返回 ErrWebBotAuthNotPresent，不影响其他用途的 RFC 9421 签名（如机器身份）。
func ParseWebBotAuth(r *http.Request, b Budgets) (*WebBotAuthParams, error) {
	if r == nil {
		return nil, ErrWebBotAuthNotPresent
	}
	b = b.withDefaults()
	sigInput := strings.Join(r.Header.Values("Signature-Input"), ", ")
	sigHeader := strings.Join(r.Header.Values("Signature"), ", ")
	if strings.TrimSpace(sigInput) == "" {
		return nil, ErrWebBotAuthNotPresent
	}
	if len(sigInput)+len(sigHeader) > b.MaxHeaderBytes {
		return nil, &BudgetError{
			Rule:   "header_bytes_exceeded",
			Limit:  b.MaxHeaderBytes,
			Actual: len(sigInput) + len(sigHeader),
		}
	}
	inputMembers, err := parseSFDictionary(sigInput)
	if err != nil {
		return nil, malformed("Signature-Input: %v", err)
	}

	var matched []sfMember
	for _, m := range inputMembers {
		if !m.IsList {
			continue
		}
		if memberTag(m.ListParams) == WebBotAuthTag {
			matched = append(matched, m)
		}
	}
	if len(matched) == 0 {
		return nil, ErrWebBotAuthNotPresent
	}
	if len(matched) > 1 {
		return nil, malformed("Signature-Input: 存在多个 tag=%q 的签名标签（%d）", WebBotAuthTag, len(matched))
	}
	m := matched[0]
	if strings.TrimSpace(sigHeader) == "" {
		return nil, malformed("Signature 头缺失")
	}

	if len(m.Items) > b.MaxComponents {
		return nil, &BudgetError{
			Rule:   "component_count_exceeded",
			Limit:  b.MaxComponents,
			Actual: len(m.Items),
		}
	}

	p := &WebBotAuthParams{
		Label:  m.Key,
		Tag:    WebBotAuthTag,
		member: m,
	}
	seenComp := make(map[string]struct{}, len(m.Items))
	hasAuthority := false
	for _, item := range m.Items {
		var name string
		switch item.Value.Kind {
		case sfValueString, sfValueToken:
			name = item.Value.Str
		default:
			return nil, malformed("覆盖成分必须为字符串/令牌形态（kind=%d）", item.Value.Kind)
		}
		if len(name) > b.MaxComponentNameLen {
			return nil, &BudgetError{
				Rule:   "component_name_len_exceeded",
				Limit:  b.MaxComponentNameLen,
				Actual: len(name),
			}
		}
		if len(item.Params) > b.MaxParamsPerComponent {
			return nil, &BudgetError{
				Rule:   "component_params_exceeded",
				Limit:  b.MaxParamsPerComponent,
				Actual: len(item.Params),
			}
		}
		if !validComponentName(name) {
			return nil, malformed("覆盖成分名非法: %q", name)
		}
		compKey := name + renderSFParams(item.Params)
		if _, dup := seenComp[compKey]; dup {
			return nil, malformed("覆盖成分重复: %q", compKey)
		}
		seenComp[compKey] = struct{}{}
		if name == "@authority" {
			hasAuthority = true
		}
		p.CoveredComponents = append(p.CoveredComponents, name)
	}
	if !hasAuthority {
		return nil, malformed("web-bot-auth 覆盖成分必须包含 @authority")
	}

	var hasCreated, hasExpires bool
	for _, pr := range m.ListParams {
		switch pr.Name {
		case "created":
			if pr.Value.Kind != sfValueInteger {
				return nil, malformed("created 必须为整数")
			}
			p.Created = pr.Value.Int
			hasCreated = true
		case "expires":
			if pr.Value.Kind != sfValueInteger {
				return nil, malformed("expires 必须为整数")
			}
			p.Expires = pr.Value.Int
			hasExpires = true
		case "keyid":
			if pr.Value.Kind != sfValueString && pr.Value.Kind != sfValueToken {
				return nil, malformed("keyid 必须为字符串/令牌")
			}
			p.KeyID = pr.Value.Str
		case "alg":
			if pr.Value.Kind != sfValueString && pr.Value.Kind != sfValueToken {
				return nil, malformed("alg 必须为字符串/令牌")
			}
			p.Alg = strings.ToLower(strings.TrimSpace(pr.Value.Str))
		case "nonce":
			if pr.Value.Kind != sfValueString && pr.Value.Kind != sfValueToken {
				return nil, malformed("nonce 必须为字符串/令牌")
			}
			p.Nonce = pr.Value.Str
		case "tag":
			// 已在前文校验为 web-bot-auth
		}
	}
	if !hasCreated || !hasExpires || p.KeyID == "" {
		return nil, malformed("web-bot-auth 签名参数 created/expires/keyid 必填")
	}
	if p.Alg != "" && !isWebBotAuthAlg(p.Alg) {
		return nil, verifyErr("unsupported web-bot-auth alg %q", p.Alg)
	}

	sigMembers, err := parseSFDictionary(sigHeader)
	if err != nil {
		return nil, malformed("Signature: %v", err)
	}
	var foundSig []byte
	found := false
	for _, sm := range sigMembers {
		if sm.Key != m.Key {
			continue
		}
		if sm.IsList || sm.Item.Value.Kind != sfValueBytes {
			return nil, malformed("Signature[%s]: 值必须为 Byte Sequence", m.Key)
		}
		foundSig = sm.Item.Value.Bytes
		found = true
		break
	}
	if !found || len(foundSig) == 0 {
		return nil, malformed("Signature: 缺少与标签 %q 匹配的签名字节", m.Key)
	}
	p.sigBytes = foundSig
	p.SignatureAgent = ParseSignatureAgent(r.Header.Values("Signature-Agent"), m.Key)
	return p, nil
}

// VerifyWebBotAuth 执行完整的 Web Bot Auth（RFC 9421）解析、时效校验、目录公钥查找、
// 签名基线重构与密码学验签（Ed25519 / ECDSA P-256）。热路径零网络 IO。
func VerifyWebBotAuth(r *http.Request, lookup WebBotAuthKeyLookup, opts WebBotAuthOptions) (*WebBotAuthResult, error) {
	p, err := ParseWebBotAuth(r, opts.Budgets)
	if err != nil {
		return nil, err
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	maxLifetime := opts.MaxLifetime
	if maxLifetime <= 0 {
		maxLifetime = WebBotAuthMaxLifetime
	}
	clockSkew := opts.ClockSkew
	if clockSkew <= 0 {
		clockSkew = WebBotAuthMaxClockSkew
	}

	if err := validateWebBotAuthTimeBounds(p.Created, p.Expires, nowFn().Unix(), int64(maxLifetime/time.Second), int64(clockSkew/time.Second)); err != nil {
		return nil, err
	}
	if lookup == nil {
		return nil, ErrWebBotAuthKeyNotFound
	}
	key, ok := lookup(p.KeyID, p.SignatureAgent)
	if !ok {
		return nil, fmt.Errorf("%w: keyid=%q", ErrWebBotAuthKeyNotFound, p.KeyID)
	}

	keyAlg := strings.ToLower(strings.TrimSpace(key.Alg))
	effectiveAlg := p.Alg
	if effectiveAlg == "" {
		effectiveAlg = keyAlg
	}
	if keyAlg != "" && effectiveAlg != keyAlg {
		return nil, verifyErr("alg_mismatch")
	}
	if !isWebBotAuthAlg(effectiveAlg) {
		return nil, verifyErr("unsupported web-bot-auth alg %q", effectiveAlg)
	}

	base, err := BuildWebBotAuthSignatureBase(r, p)
	if err != nil {
		return nil, err
	}
	if err := verifyCrypto(key.PublicKeyPEM, effectiveAlg, base, p.sigBytes); err != nil {
		return nil, err
	}
	return &WebBotAuthResult{
		Verified:          true,
		Label:             p.Label,
		KeyID:             p.KeyID,
		Alg:               effectiveAlg,
		SignatureAgent:    p.SignatureAgent,
		Created:           p.Created,
		Expires:           p.Expires,
		Nonce:             p.Nonce,
		CoveredComponents: append([]string(nil), p.CoveredComponents...),
	}, nil
}

// BuildWebBotAuthSignatureBase 按 RFC 9421 §2.5 为 Web Bot Auth 重构签名基线，
// 忠实保留 Signature-Input 原文的覆盖成分序、成分参数与签名参数序。
func BuildWebBotAuthSignatureBase(r *http.Request, p *WebBotAuthParams) ([]byte, error) {
	if r == nil || p == nil {
		return nil, verifyErr("nil input")
	}
	in := p.member
	if !in.IsList {
		return nil, malformed("Signature-Input: 标签值必须为 Inner List")
	}
	var sb strings.Builder
	inner := make([]byte, 0, 256)
	for i, item := range in.Items {
		name := item.Value.Str
		val, err := deriveWebBotAuthComponentValue(r, name, item.Params)
		if err != nil {
			return nil, err
		}
		sb.WriteString(strconv.Quote(name))
		sb.WriteString(renderSFParams(item.Params))
		sb.WriteString(": ")
		sb.WriteString(val)
		sb.WriteString("\n")
		if i > 0 {
			inner = append(inner, ' ')
		}
		inner = append(inner, strconv.Quote(name)...)
		inner = append(inner, renderSFParams(item.Params)...)
	}
	sb.WriteString(strconv.Quote("@signature-params"))
	sb.WriteString(": (")
	sb.Write(inner)
	sb.WriteString(")")
	sb.WriteString(renderSFParams(in.ListParams))
	return []byte(sb.String()), nil
}

func validateWebBotAuthTimeBounds(created, expires, nowUnix, maxLifetimeSec, clockSkewSec int64) error {
	if created <= 0 || expires <= 0 {
		return fmt.Errorf("%w: created/expires must be positive", ErrWebBotAuthExpired)
	}
	if expires <= created {
		return fmt.Errorf("%w: expires must be greater than created", ErrWebBotAuthExpired)
	}
	if expires-created > maxLifetimeSec {
		return fmt.Errorf("%w: lifetime %ds exceeds max %ds", ErrWebBotAuthExpired, expires-created, maxLifetimeSec)
	}
	if created > nowUnix+clockSkewSec {
		return fmt.Errorf("%w: created is in the future", ErrWebBotAuthExpired)
	}
	if expires < nowUnix-clockSkewSec {
		return fmt.Errorf("%w: signature expired", ErrWebBotAuthExpired)
	}
	return nil
}

func deriveWebBotAuthComponentValue(r *http.Request, name string, params []sfParam) (string, error) {
	switch name {
	case "@method":
		if len(params) > 0 {
			return "", verifyErr("unsupported_component_param on @method")
		}
		return r.Method, nil
	case "@authority":
		if len(params) > 0 {
			return "", verifyErr("unsupported_component_param on @authority")
		}
		host := strings.TrimSpace(r.Host)
		if host == "" && r.URL != nil {
			host = strings.TrimSpace(r.URL.Host)
		}
		if host == "" {
			return "", verifyErr("empty @authority")
		}
		// RFC 9421 §2.2.3：@authority 小写归一。
		return strings.ToLower(host), nil
	case "@scheme":
		if len(params) > 0 {
			return "", verifyErr("unsupported_component_param on @scheme")
		}
		if r.TLS != nil {
			return "https", nil
		}
		if r.URL != nil && strings.EqualFold(r.URL.Scheme, "https") {
			return "https", nil
		}
		return "http", nil
	case "@path":
		if len(params) > 0 {
			return "", verifyErr("unsupported_component_param on @path")
		}
		return rawPathOf(r), nil
	case "@query":
		if len(params) > 0 {
			return "", verifyErr("unsupported_component_param on @query")
		}
		return "?" + rawQueryOf(r), nil
	case "@query-param":
		return queryParamValue(r, params)
	}
	if strings.HasPrefix(name, "@") {
		return "", verifyErr("unsupported derived component %s", name)
	}
	if len(params) > 0 {
		return "", verifyErr("unsupported_component_param on header %q", name)
	}
	vals := r.Header.Values(name)
	if len(vals) == 0 {
		return "", verifyErr("covered header %q not present", name)
	}
	return strings.Join(vals, ", "), nil
}

// ParseSignatureAgent 解析 Signature-Agent 请求头（支持 RFC 8941 String `"https://..."`、
// SF Dictionary `sig1="https://..."` 以及裸 URL/令牌形式）。
func ParseSignatureAgent(vals []string, label string) string {
	if len(vals) == 0 {
		return ""
	}
	raw := strings.TrimSpace(strings.Join(vals, ", "))
	if raw == "" {
		return ""
	}
	// 1. SF String 形态（如 "https://crawler.example.com"）
	if strings.HasPrefix(raw, `"`) {
		p := &sfParser{s: raw}
		if s, err := p.parseString(); err == nil {
			return stripControlChars(strings.TrimSpace(s))
		}
	}
	// 2. SF Dictionary 形态（如 sig1="https://crawler.example.com"）
	if members, err := parseSFDictionary(raw); err == nil && len(members) > 0 {
		if label != "" {
			for _, m := range members {
				if m.Key == label && !m.IsList && (m.Item.Value.Kind == sfValueString || m.Item.Value.Kind == sfValueToken) {
					return stripControlChars(strings.TrimSpace(m.Item.Value.Str))
				}
			}
		}
		if len(members) == 1 && !members[0].IsList && (members[0].Item.Value.Kind == sfValueString || members[0].Item.Value.Kind == sfValueToken) {
			return stripControlChars(strings.TrimSpace(members[0].Item.Value.Str))
		}
	}
	// 3. 裸字符串/URL 回退
	return stripControlChars(strings.Trim(raw, `"`))
}

// NormalizeSignatureAgent 归一化 Signature-Agent 标识用于目录匹配（去引号/空白、
// URL scheme/host 小写化、去除末尾斜杠）。
func NormalizeSignatureAgent(raw string) string {
	s := strings.TrimSpace(strings.Trim(raw, `"`))
	if s == "" {
		return ""
	}
	if u, err := url.Parse(s); err == nil && u.Scheme != "" && u.Host != "" {
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		out := u.String()
		return strings.TrimRight(out, "/")
	}
	return strings.TrimRight(strings.ToLower(s), "/")
}

func memberTag(params []sfParam) string {
	for _, pr := range params {
		if pr.Name == "tag" && (pr.Value.Kind == sfValueString || pr.Value.Kind == sfValueToken) {
			return pr.Value.Str
		}
	}
	return ""
}

func isWebBotAuthAlg(alg string) bool {
	return alg == AlgEd25519 || alg == AlgECDSAP256SHA256
}

func stripControlChars(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
