package detectors

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

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
		return
	}
	// Bearer JWT 结构级识别（不验签、不落 payload 明文；仅 OBSERVE）
	if scheme == "bearer" {
		checkJWTStructure(ctx, token)
	}
}

// checkJWTStructure 对疑似 JWT（两段点分隔三部）做结构级安全信号。
// 纪律：只解 header/claims 的 alg/exp/kid 形态，不做签名校验、不把 sub/email 等写入证据。
func checkJWTStructure(ctx *dsctx.RequestContext, token string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return // 非 JWT 形态（opaque bearer）不处理
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		// 兼容带 padding
		hdrJSON, err = base64.URLEncoding.DecodeString(parts[0])
		if err != nil {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector:   "authentication",
				RuleID:     "auth.jwt_malformed_header",
				Category:   "OBSERVE",
				Severity:   "LOW",
				Message:    "jwt header not decodable",
				Evidence:   map[string]string{"reason": "header_b64"},
				ScoreDelta: 5,
			})
			return
		}
	}
	var hdr map[string]any
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "authentication",
			RuleID:     "auth.jwt_malformed_header",
			Category:   "OBSERVE",
			Severity:   "LOW",
			Message:    "jwt header json invalid",
			Evidence:   map[string]string{"reason": "header_json"},
			ScoreDelta: 5,
		})
		return
	}
	alg, _ := hdr["alg"].(string)
	algLower := strings.ToLower(strings.TrimSpace(alg))
	if algLower == "none" || algLower == "" {
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "authentication",
			RuleID:     "auth.jwt_alg_none",
			Category:   "OBSERVE",
			Severity:   "HIGH",
			Message:    "jwt alg none or empty",
			Evidence:   map[string]string{"alg": clipScheme(algLower)},
			ScoreDelta: 25,
		})
	}
	// kid 路径穿越形态（不输出 kid 全文，只记 reason）
	if kid, ok := hdr["kid"].(string); ok {
		lk := strings.ToLower(kid)
		if strings.Contains(lk, "../") || strings.HasPrefix(lk, "file:") || strings.Contains(lk, "/etc/") {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector:   "authentication",
				RuleID:     "auth.jwt_kid_traversal",
				Category:   "OBSERVE",
				Severity:   "HIGH",
				Message:    "jwt kid looks like path traversal",
				Evidence:   map[string]string{"reason": "kid_path_like"},
				ScoreDelta: 25,
			})
		}
	}
	// 空签名段
	if parts[2] == "" {
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "authentication",
			RuleID:     "auth.jwt_empty_signature",
			Category:   "OBSERVE",
			Severity:   "MEDIUM",
			Message:    "jwt empty signature segment",
			Evidence:   map[string]string{"reason": "empty_sig"},
			ScoreDelta: 15,
		})
	}
	// exp 过期（若 claims 可解；仅作信号，不验签）
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		claimsJSON, err = base64.URLEncoding.DecodeString(parts[1])
	}
	if err == nil {
		var claims map[string]any
		if json.Unmarshal(claimsJSON, &claims) == nil {
			if exp, ok := claimUnix(claims["exp"]); ok && exp < time.Now().Unix() {
				ctx.AddMatch(dsctx.DetectorMatch{
					Detector:   "authentication",
					RuleID:     "auth.jwt_expired",
					Category:   "OBSERVE",
					Severity:   "MEDIUM",
					Message:    "jwt exp in the past (unverified claims)",
					Evidence:   map[string]string{"reason": "exp_past"},
					ScoreDelta: 10,
				})
			}
		}
	}
}

func claimUnix(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	default:
		return 0, false
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

// CredentialKey 身份维度键：仅由凭据派生（auth:/key:/sess: 前缀 + 统一加盐指纹），
// 无凭据返回空串（匿名）。身份维度不得由 IP 冒充（边界规则见 docs/API_MICRO_MODELS.md §2.2：
// IP 属访问微模型的环境维度；NAT/出口代理会把大量用户折叠成一个“身份”）。
// 凭据明文不出本函数作用域。
func CredentialKey(r *http.Request, salt string) string {
	if r == nil {
		return ""
	}
	if v := strings.TrimSpace(r.Header.Get("Authorization")); v != "" {
		return "auth:" + Fingerprint(salt, v)
	}
	if v := strings.TrimSpace(r.Header.Get("X-API-Key")); v != "" {
		return "key:" + Fingerprint(salt, v)
	}
	if v := strings.TrimSpace(r.Header.Get("Cookie")); v != "" {
		return "sess:" + Fingerprint(salt, v)
	}
	return ""
}

// TrackingKey 追踪维度键：凭据指纹优先（见 CredentialKey），无凭据回退 ip:+客户端 IP。
// 仅供 behavior/ratelimit/resource 检测器的滑窗/游标计数使用（避免匿名流量全部并入同一桶）；
// 不得作为身份指纹输出到事件或画像。
func TrackingKey(r *http.Request, salt string) string {
	if key := CredentialKey(r, salt); key != "" {
		return key
	}
	if r == nil {
		return "unknown"
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
