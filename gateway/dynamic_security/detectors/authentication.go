package detectors

import (
	"hash/fnv"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 认证有效性：Authorization scheme（Bearer/Basic/Digest）与格式校验、X-API-Key 强度。
// 数据最小化：凭据值永不写入 Evidence，仅记录 scheme 与长度档。
var (
	// reAuthScheme 受支持的 Authorization scheme（其余视为格式错误）。
	reAuthScheme = regexp.MustCompile(`(?i)^(bearer|basic|digest)$`)
	// reTokenBase64ish Bearer/Basic 凭据字符集（含 JWT 分段点与 URL-safe 变体）。
	reTokenBase64ish = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
)

// weakCredentialMinLen 弱凭据长度下限：token/API Key 短于该值判弱。
const weakCredentialMinLen = 8

// CheckAuthentication 认证有效性检测：无凭据 API / 弱凭据 / 格式错误（只 AddMatch，不定案）。
func CheckAuthentication(ctx *dsctx.RequestContext, r *http.Request, isAPI bool) {
	if ctx == nil || r == nil {
		return
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	apiKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if authz == "" && apiKey == "" {
		// 仅 API 流量关心匿名访问（静态资源无凭据属正常）
		if isAPI {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector:   "authentication",
				RuleID:     "auth.unauthenticated_api",
				Category:   "OBSERVE",
				Severity:   "MEDIUM",
				Message:    "api request without credential",
				Evidence:   map[string]string{"reason": "no_authorization_or_api_key"},
				ScoreDelta: 10,
			})
		}
		return
	}
	if authz != "" {
		// 传原始值："Bearer "（空 token）应判弱凭据而非格式错误
		checkAuthorization(ctx, r.Header.Get("Authorization"))
	}
	if apiKey != "" && len(apiKey) < weakCredentialMinLen {
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "authentication",
			RuleID:   "auth.weak_credential",
			Category: "OBSERVE",
			Severity: "LOW",
			Message:  "x-api-key too short",
			Evidence: map[string]string{
				"header":        "x-api-key",
				"length_bucket": lengthBucket(len(apiKey)),
				"reason":        "too_short",
			},
			ScoreDelta: 5,
		})
	}
}

// checkAuthorization 校验 Authorization 头：scheme 合法性 → 格式 → 凭据强度（每头至多一条 match）。
func checkAuthorization(ctx *dsctx.RequestContext, v string) {
	malformed := func(reason, scheme string) {
		ev := map[string]string{"header": "authorization", "reason": reason}
		if scheme != "" {
			ev["scheme"] = scheme
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "authentication",
			RuleID:     "auth.malformed_credential",
			Category:   "OBSERVE",
			Severity:   "MEDIUM",
			Message:    "malformed authorization header",
			Evidence:   ev,
			ScoreDelta: 10,
		})
	}
	weak := func(reason, scheme string, tokenLen int) {
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "authentication",
			RuleID:   "auth.weak_credential",
			Category: "OBSERVE",
			Severity: "LOW",
			Message:  "weak credential",
			Evidence: map[string]string{
				"header":        "authorization",
				"scheme":        scheme,
				"length_bucket": lengthBucket(tokenLen),
				"reason":        reason,
			},
			ScoreDelta: 5,
		})
	}
	parts := strings.SplitN(v, " ", 2)
	if len(parts) != 2 {
		malformed("missing_scheme_or_credentials", "")
		return
	}
	scheme := parts[0]
	token := strings.TrimSpace(parts[1])
	if !reAuthScheme.MatchString(scheme) {
		malformed("unsupported_scheme", clipScheme(scheme))
		return
	}
	scheme = strings.ToLower(scheme)
	if token == "" {
		weak("empty_token", scheme, 0)
		return
	}
	if len(token) < weakCredentialMinLen {
		weak("too_short", scheme, len(token))
		return
	}
	if scheme == "digest" {
		// Digest 凭据为 k=v 对列表，非 Base64；结构判据改为含等号
		if !strings.Contains(token, "=") {
			weak("not_key_value_pairs", scheme, len(token))
		}
		return
	}
	if !reTokenBase64ish.MatchString(token) {
		weak("not_base64ish", scheme, len(token))
	}
}

// clipScheme scheme 截断（异常输入可能极长，证据侧只留前缀）。
func clipScheme(s string) string {
	const max = 16
	if len(s) > max {
		return s[:max]
	}
	return s
}

// lengthBucket 长度分档（不记录精确长度，进一步去敏）。
func lengthBucket(n int) string {
	switch {
	case n <= 0:
		return "0"
	case n < 8:
		return "1-7"
	case n < 16:
		return "8-15"
	case n < 32:
		return "16-31"
	case n < 64:
		return "32-63"
	default:
		return "64+"
	}
}

// IdentityKey 身份维度键：凭据指纹（FNV-1a，非明文）优先，缺省回退客户端 IP。
// 供 behavior/ratelimit/resource 检测器做维度归并；指纹非可逆，不落明文。
func IdentityKey(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	if v := strings.TrimSpace(r.Header.Get("Authorization")); v != "" {
		return "auth:" + fingerprint(v)
	}
	if v := strings.TrimSpace(r.Header.Get("X-API-Key")); v != "" {
		return "key:" + fingerprint(v)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	if host == "" {
		return "unknown"
	}
	return "ip:" + host
}

// fingerprint 轻量指纹（FNV-1a 64，非加密用途，与 parser.BodyHash 同族）。
func fingerprint(v string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(v))
	return strconv.FormatUint(h.Sum64(), 16)
}
