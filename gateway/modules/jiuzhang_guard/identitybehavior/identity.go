package identitybehavior

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
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
	IdentityMachine     = "MACHINE"
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
	Type               string   // HUMAN | BOT | APPLICATION | SERVICE | MACHINE | AGENT | UNKNOWN
	Confidence         uint8    // 0..100; explanation/policy signal only, never a standalone block reason
	Evidence           []string // signal types only; never credential values
	ClientIP           string
	UserAgent          string
	TLSFingerprint     string // TLS 版本+密码套件指纹（拿不到 ClientHello，不做 JA3/JA4；无 TLS 为空串）
	BrowserFingerprint string // UA/Accept 族指纹（UA 为空时为空串）
	Credentials        []Credential
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
	// An API key/OAuth credential is a stable application correlation signal;
	// OAuth claims are still unverified and therefore receive weak confidence.
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
	return id
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
		case CredentialAPIKey:
			return 75, []string{"credential:api_key"}
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

// extractCredentials 按优先级提取凭据：Authorization（Bearer JWT >  opaque bearer > 其他方案）
// → API Key 头 → 会话 Cookie → 其他 Cookie。每项仅保留 HMAC 指纹与未验签关联字段。
func extractCredentials(r *http.Request, salt string) []Credential {
	var out []Credential
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
