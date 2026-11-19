package identitybehavior

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// 身份类别（仅观测用途；AGENT 不由 User-Agent 单独推断）。
const (
	IdentityHuman       = "HUMAN"
	IdentityBot         = "BOT"
	IdentityApplication = "APPLICATION"
	IdentityService     = "SERVICE"
	IdentityAgent       = "AGENT"
	IdentityUnknown     = "UNKNOWN"
)

// CredentialType 凭据类型。
type CredentialType string

const (
	CredentialJWT     CredentialType = "JWT"
	CredentialAPIKey  CredentialType = "API_KEY"
	CredentialSession CredentialType = "SESSION"
	CredentialCookie  CredentialType = "COOKIE"
	CredentialOAuth   CredentialType = "OAUTH"
	CredentialCustom  CredentialType = "CUSTOM"
	CredentialMTLS    CredentialType = "MTLS"
)

// Credential 请求凭据观测（仅指纹与未验签关联字段；无明文）。
// JWTSubject/OAuthClientID 取自未验签 JWT claims——仅作身份关联，永不用于授权判定。
type Credential struct {
	Type          CredentialType `json:"type"`
	Hash          string         `json:"hash"`
	AccountID     string         `json:"account_id,omitempty"`
	JWTSubject    string         `json:"jwt_subject,omitempty"`
	OAuthClientID string         `json:"oauth_client_id,omitempty"`
	// raw 凭据原文：仅 identity_key 计算期间存活于引擎内，不导出、不落日志。
	raw string
}

// Identity 单请求身份解析结果（确定性 identity_key：同信号输入恒同键）。
type Identity struct {
	Key                string   // 确定性身份键（HMAC 指纹，优先级：凭据 > 浏览器指纹 > IP）
	Type               string   // HUMAN | BOT | APPLICATION | SERVICE | AGENT | UNKNOWN
	Confidence         uint8    // 0..100; explanation/policy signal only, never a standalone block reason
	Evidence           []string // signal types only; never credential values
	ClientIP           string
	UserAgent          string
	TLSFingerprint     string // TLS 版本+密码套件指纹（拿不到 ClientHello，不做 JA3/JA4；无 TLS 为空串）
	BrowserFingerprint string // UA/Accept 族指纹（UA 为空时为空串）
	Credentials        []Credential
	// VerifiedPrincipalID / VerifiedTenantID JWT 信任链（WDSP P0-03）VERIFIED 时
	// 由 jwt_trust 模块经请求上下文注入的独立可信信号（应用隔离 HMAC 主体指纹 /
	// 受信 tenant 声明值）。仅 JWT 验签通过后非空；与 identity_key/identity_type
	// 语义完全独立——不改写 Type（APPLICATION/SERVICE 不变 HUMAN），不与未验证
	// sub 相同的其他主体合并，不参与 identity_key 计算。
	VerifiedPrincipalID string
	VerifiedTenantID    string
}

// verifiedIdentityKey 请求上下文中的可信身份信号键（jwt_trust 验证点写入，Begin 消费）。
type verifiedIdentityKey struct{}

// VerifiedIdentity JWT 信任链 VERIFIED 结果的可信身份信号（验签通过后由
// 网关 jwt_trust 挂点注入请求上下文；观测层只消费，验证与执行不经过本模块）。
type VerifiedIdentity struct {
	PrincipalID    string // 应用隔离 HMAC 主体指纹（非明文 sub）
	TenantID       string // 受信 tenant 声明值（内存信号，不落事件明文）
	IssuerConfigID string // 命中的 issuer 配置 ID（溯源）
	PolicyVersion  string // 策略版本（溯源）
}

// WithVerifiedIdentity 把可信身份信号写入请求上下文（仅 VERIFIED 时调用）。
func WithVerifiedIdentity(ctx context.Context, v *VerifiedIdentity) context.Context {
	if v == nil {
		return ctx
	}
	return context.WithValue(ctx, verifiedIdentityKey{}, v)
}

// VerifiedIdentityFrom 取请求上下文中的可信身份信号（未注入为 nil）。
func VerifiedIdentityFrom(ctx context.Context) *VerifiedIdentity {
	v, _ := ctx.Value(verifiedIdentityKey{}).(*VerifiedIdentity)
	return v
}

// headlessUAMarker 无头浏览器 UA 标记（HEADLESS-001 信号与 bot 分类复用同一词表项）。
const headlessUAMarker = "headless"

// botUAMarkers bot 特征子串（小写匹配；先于浏览器特征判定——HeadlessChrome 归 BOT）。
// 含通用自动化客户端与常见渗透/扫描工具（OBSERVE 级分类，误标不阻断）。
var botUAMarkers = []string{
	"bot", "crawler", "spider", "scanner", "curl", "wget",
	"python-requests", "go-http-client", headlessUAMarker,
	"sqlmap", "nmap", "nikto", "nuclei", "masscan", "hydra",
	"metasploit", "gobuster", "dirbuster", "wpscan", "acunetix",
	"nessus", "openvas", "zgrab", "zmap",
}

// humanUAMarkers 浏览器特征子串（小写匹配）。
var humanUAMarkers = []string{"mozilla", "chrome", "safari"}

// sessionCookieNames 常见会话 Cookie 名（小写匹配）。
var sessionCookieNames = map[string]struct{}{
	"session": {}, "sessionid": {}, "sid": {}, "jsessionid": {},
	"phpsessid": {}, "asp.net_sessionid": {}, "connect.sid": {}, "_session": {},
}

// ResolveIdentity 解析请求身份：提取凭据 → 计算确定性 identity_key 与各类指纹。
// clientIP 为 guard 真实 IP 识别结果（已考虑可信代理）。
func ResolveIdentity(r *http.Request, salt, clientIP string) *Identity {
	ua := r.Header.Get("User-Agent")
	id := &Identity{
		Type:      classifyUA(ua),
		ClientIP:  clientIP,
		UserAgent: ua,
	}
	if ua != "" {
		id.BrowserFingerprint = fingerprintParts(salt, "br",
			ua, r.Header.Get("Accept-Language"), r.Header.Get("Accept-Encoding"), r.Header.Get("Accept"))
	}
	if r.TLS != nil {
		id.TLSFingerprint = fingerprintParts(salt, "tls",
			tls.VersionName(r.TLS.Version), tls.CipherSuiteName(r.TLS.CipherSuite))
	}
	id.Credentials = extractCredentials(r, salt)
	// A verified client certificate is the only strong credential evidence this
	// resolver can establish locally. Without an application-level mapping it is
	// conservatively classified as a service identity; the certificate digest is
	// still the deterministic identity key. API key/OAuth remain correlation signals.
	if len(id.Credentials) > 0 && id.Credentials[0].Type == CredentialMTLS {
		id.Type = IdentityService
	}
	// An API key/OAuth credential is a stable application correlation signal;
	// neither is verified by this observer, so neither receives high confidence.
	// Other credentials remain subject to the UA/session classification so that
	// an unverified JWT or cookie cannot silently become a stronger identity type.
	if len(id.Credentials) > 0 {
		switch id.Credentials[0].Type {
		case CredentialAPIKey, CredentialOAuth:
			id.Type = IdentityApplication
		}
	}
	switch {
	case len(id.Credentials) > 0:
		c := id.Credentials[0]
		id.Key = detectors.Fingerprint(salt, "cred:"+string(c.Type)+":"+c.raw)
	case ua != "":
		id.Key = detectors.Fingerprint(salt, "anon:"+id.BrowserFingerprint)
	default:
		id.Key = detectors.Fingerprint(salt, "ip:"+clientIP)
	}
	id.Confidence, id.Evidence = identityConfidence(id)
	// JWT 信任链可信信号（WDSP P0-03）：VERIFIED 时由 jwt_trust 验证点经请求
	// 上下文注入；只填充独立字段，不改 Key/Type/Confidence 语义（APPLICATION/
	// SERVICE 不改写为 HUMAN，未验证 sub 相同不合并可信主体）。
	if vi := VerifiedIdentityFrom(r.Context()); vi != nil {
		id.VerifiedPrincipalID = vi.PrincipalID
		id.VerifiedTenantID = vi.TenantID
	}
	return id
}

// CandidateKeys 返回本请求提取出的全部候选身份键（去重，主身份键 id.Key 在首位）。
// 请求携带多个凭据（如伪造 Authorization + 真实 X-API-Key/Cookie）时，所有提取出的
// 凭据键均参与封禁与风险评估，防止通过附加高优先级凭据头绕过既有封禁或风险累计（H-08）。
// 不改变 id.Key 与 id.Type 的既有语义。
func (id *Identity) CandidateKeys(salt string) []string {
	if id == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(id.Credentials)+1)
	out := make([]string, 0, len(id.Credentials)+1)
	add := func(k string) {
		if k == "" {
			return
		}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	add(id.Key)
	for _, c := range id.Credentials {
		if c.raw != "" {
			add(detectors.Fingerprint(salt, "cred:"+string(c.Type)+":"+c.raw))
		}
	}
	return out
}

// identityConfidence derives a bounded, explainable confidence score. Values
// are deliberately conservative because gateway credentials are observed, not
// verified here; confidence must not be used as a standalone block decision.
func identityConfidence(id *Identity) (uint8, []string) {
	if id == nil {
		return 0, nil
	}
	var evidence []string
	if len(id.Credentials) > 0 {
		switch id.Credentials[0].Type {
		case CredentialMTLS:
			return 95, []string{"credential:mtls_verified"}
		case CredentialAPIKey:
			// Header presence/fingerprint alone does not prove that the key was
			// accepted by an upstream authenticator.
			return 60, []string{"credential:api_key_observed"}
		case CredentialOAuth:
			// client_id comes from an unverified JWT payload. It is useful for
			// correlation, but must remain a weak signal until the gateway has
			// verified the token/signature against a trusted issuer.
			return 30, []string{"credential:oauth_unverified"}
		case CredentialJWT:
			return 65, []string{"credential:jwt", "credential:subject"}
		case CredentialSession:
			return 65, []string{"credential:session"}
		case CredentialCookie:
			return 40, []string{"credential:cookie"}
		case CredentialCustom:
			return 30, []string{"credential:custom"}
		}
	}
	if id.BrowserFingerprint != "" {
		evidence = append(evidence, "browser_fingerprint")
	}
	switch id.Type {
	case IdentityBot:
		evidence = append(evidence, "user_agent:bot")
	case IdentityHuman:
		evidence = append(evidence, "user_agent:browser")
	}
	if len(evidence) > 0 {
		return 50, evidence
	}
	if id.ClientIP != "" {
		return 20, []string{"client_ip"}
	}
	return 0, nil
}

// classifyUA 身份类别启发：bot 特征优先（自动化工具常伪装浏览器 UA 但带工具特征），
// 其次浏览器特征，其余 UNKNOWN（空 UA 亦 UNKNOWN）。
func classifyUA(ua string) string {
	l := strings.ToLower(ua)
	for _, m := range botUAMarkers {
		if strings.Contains(l, m) {
			return IdentityBot
		}
	}
	for _, m := range humanUAMarkers {
		if strings.Contains(l, m) {
			return IdentityHuman
		}
	}
	return IdentityUnknown
}

// ClassifyUA 导出 UA 分类启发（WDSP P1-02 B3：Bot 信号评估的 client_claim 组
// ua_class_match 指标复用同一口径）。注意：纯 UA 启发只会产出 BOT/HUMAN/UNKNOWN——
// APPLICATION/SERVICE/AGENT 需凭据佐证，UA 属可伪造弱信号，不能单独构成挑战依据。
func ClassifyUA(ua string) string { return classifyUA(ua) }

// extractCredentials 按优先级提取凭据：已验证 mTLS 客户端证书 → Authorization
// （Bearer JWT > opaque bearer > 其他方案）→ API Key 头 → 会话 Cookie → 其他 Cookie。
// 每项仅保留 HMAC 指纹与未验签关联字段。
func extractCredentials(r *http.Request, salt string) []Credential {
	var out []Credential
	// VerifiedChains is populated only after Go's TLS client certificate
	// verification succeeds. Never trust a forwarded certificate header here.
	if c, ok := verifiedMTLSCredential(r, salt); ok {
		out = append(out, c)
	}
	if v := strings.TrimSpace(r.Header.Get("Authorization")); v != "" {
		scheme, token := v, ""
		if i := strings.IndexByte(v, ' '); i > 0 {
			scheme, token = v[:i], strings.TrimSpace(v[i+1:])
		}
		switch {
		case strings.EqualFold(scheme, "bearer") && token != "":
			sub, clientID, isJWT := parseUnverifiedJWTClaims(token)
			switch {
			case isJWT && sub != "":
				out = append(out, Credential{
					Type: CredentialJWT, Hash: detectors.Fingerprint(salt, token),
					AccountID: sub, JWTSubject: sub, OAuthClientID: clientID, raw: token,
				})
			case isJWT:
				// client_credentials 形态（无 sub 仅 client_id）：OAUTH 关联
				out = append(out, Credential{
					Type: CredentialOAuth, Hash: detectors.Fingerprint(salt, token),
					OAuthClientID: clientID, raw: token,
				})
			default:
				// opaque bearer：非 JWT 形态，按自定义凭据关联
				raw := "bearer:" + token
				out = append(out, Credential{Type: CredentialCustom, Hash: detectors.Fingerprint(salt, raw), raw: raw})
			}
		default:
			// Basic/Digest 等其他方案：整值指纹关联（不解析内容）
			out = append(out, Credential{Type: CredentialCustom, Hash: detectors.Fingerprint(salt, v), raw: v})
		}
	}
	// X-API-Key / Api-Key（两个头名等价，取第一个非空）
	for _, h := range []string{"X-API-Key", "Api-Key"} {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			out = append(out, Credential{Type: CredentialAPIKey, Hash: detectors.Fingerprint(salt, v), raw: v})
			break
		}
	}
	// 常见会话 Cookie（名大小写不敏感，取首个命中）
	found := false
	for _, c := range r.Cookies() {
		if _, ok := sessionCookieNames[strings.ToLower(c.Name)]; ok {
			raw := c.Name + "=" + c.Value
			out = append(out, Credential{Type: CredentialSession, Hash: detectors.Fingerprint(salt, raw), raw: raw})
			found = true
			break
		}
	}
	// 无命中会话名但携带 Cookie：整体指纹作弱关联（COOKIE 类型）
	if !found {
		if v := strings.TrimSpace(r.Header.Get("Cookie")); v != "" {
			out = append(out, Credential{Type: CredentialCookie, Hash: detectors.Fingerprint(salt, v), raw: v})
		}
	}
	return out
}

// verifiedMTLSCredential returns a bounded, non-secret certificate digest only
// when the request carries a verified client certificate. The raw certificate
// bytes never leave this function and are not included in event records.
func verifiedMTLSCredential(r *http.Request, salt string) (Credential, bool) {
	if r == nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return Credential{}, false
	}
	chain := r.TLS.VerifiedChains[0]
	if len(chain) == 0 || chain[0] == nil || len(chain[0].Raw) == 0 {
		return Credential{}, false
	}
	digest := sha256.Sum256(chain[0].Raw)
	stable := "mtls:" + hex.EncodeToString(digest[:])
	return Credential{
		Type: CredentialMTLS,
		Hash: detectors.Fingerprint(salt, stable),
		raw:  stable,
	}, true
}

// parseUnverifiedJWTClaims 未验签解析 JWT claims 取 sub/client_id（结构三段 + payload 可解）。
// 纪律：仅作身份关联用途，永不用于授权判定；不验签、不解析其他 claim、不落 payload 明文。
func parseUnverifiedJWTClaims(token string) (sub, clientID string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return "", "", false
		}
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return "", "", false
	}
	sub, _ = claims["sub"].(string)
	clientID, _ = claims["client_id"].(string)
	return sub, clientID, true
}

// fingerprintParts 多段指纹：长度前缀编码后经 detectors.Fingerprint 统一 HMAC
// （盐语义与域分隔与 detectors.Fingerprint 完全一致：缺盐走固定域分隔前缀）。
func fingerprintParts(salt string, parts ...string) string {
	var sb strings.Builder
	for _, p := range parts {
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(p)))
		sb.Write(lb[:])
		sb.WriteString(p)
	}
	return detectors.Fingerprint(salt, sb.String())
}
