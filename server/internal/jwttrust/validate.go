// validate.go JWT 信任策略输入校验（PUT 保存草稿与 store.SaveDraft 共用同一校验；
// 与 riskpolicy 同一模式：字段级错误列表，handler 转 400 details）。
// 结构校验为纯函数（无网络 IO）；REMOTE_JWKS 地址的 SSRF/解析校验见
// ValidateRemoteURLs（保存时与预检同一规则，复用 outboundhttp 防护策略）。
package jwttrust

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jiuzhang-waf/server/internal/outboundhttp"
)

// FieldError 字段级校验错误。
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError 校验错误集合（handler 转 400 响应 details）。
type ValidationError struct {
	Errors []FieldError
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("jwt trust policy validation failed: %d field(s)", len(e.Errors))
}

// HTTP 方法词形（大写 token；具体方法集合不限定，由网关按大写精确匹配）。
var methodPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,31}$`)

// tenant_claim 声明名词形（token 字符，防注入与歧义）。
var tenantClaimPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)

// Normalize 归一化输入（校验与落库前调用）：方法转大写去重；algorithms/audiences
// 去重去空白。clock_skew_seconds 缺省值（30）由 handler 在反序列化层应用
// （请求用 *int 区分「未提供」与显式 0——0 为合法值）。
func Normalize(p *Policy) {
	for i := range p.Selectors {
		p.Selectors[i].Methods = normalizeStrings(p.Selectors[i].Methods, true)
	}
	for i := range p.Issuers {
		p.Issuers[i].Audiences = normalizeStrings(p.Issuers[i].Audiences, false)
		p.Issuers[i].Algorithms = normalizeStrings(p.Issuers[i].Algorithms, true)
		p.Issuers[i].RoleClaims = normalizeStrings(p.Issuers[i].RoleClaims, false)
		if tb := p.Issuers[i].TokenBinding; tb != nil {
			tb.Mode = strings.ToUpper(strings.TrimSpace(tb.Mode))
			if tb.Mode == "" || tb.Mode == TokenBindingNone {
				p.Issuers[i].TokenBinding = nil
			} else {
				tb.AllowedDPoPAlgs = normalizeDPoPAlgs(tb.AllowedDPoPAlgs)
			}
		}
	}
}

// normalizeDPoPAlgs 归一化 DPoP 算法列表（保留 EdDSA 混合大小写，未知项原样保留供校验拒绝）。
func normalizeDPoPAlgs(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		switch strings.ToLower(s) {
		case "es256":
			s = DPoPAlgES256
		case "rs256":
			s = DPoPAlgRS256
		case "eddsa":
			s = DPoPAlgEdDSA
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// normalizeStrings 去空白、去重（keepOrder 稳定序）；upper 时转大写。
func normalizeStrings(in []string, upper bool) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if upper {
			s = strings.ToUpper(s)
		}
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ValidateStructure 校验策略全字段（纯结构，无网络 IO），返回字段级错误列表（空=通过）。
// 契约（任务书 §4.1）：mode OFF 时 selectors/issuers 可空；非 OFF 二者必填非空；
// selector path_exact/path_prefix 二选一且不含 query；issuer 精确值唯一；
// algorithms ⊆ {RS256,ES256} 非空；key_source 二选一；clock_skew 0~120。
func ValidateStructure(p *Policy) []FieldError {
	errs := []FieldError{}
	add := func(field, msg string) {
		errs = append(errs, FieldError{Field: field, Message: msg})
	}

	if p.Mode != ModeOff && p.Mode != ModeObserve && p.Mode != ModeProtect {
		add("mode", "仅支持 OFF / OBSERVE / PROTECT")
	}

	if len(p.Selectors) > MaxSelectors {
		add("selectors", fmt.Sprintf("选择器数量不能超过 %d", MaxSelectors))
	}
	if p.Mode != ModeOff && len(p.Selectors) == 0 {
		add("selectors", "非 OFF 模式必须配置至少一条选择器")
	}
	for i, s := range p.Selectors {
		prefix := fmt.Sprintf("selectors[%d]", i)
		if len(s.Methods) == 0 {
			add(prefix+".methods", "方法集合不能为空")
		}
		if len(s.Methods) > MaxSelectorMethods {
			add(prefix+".methods", fmt.Sprintf("方法数量不能超过 %d", MaxSelectorMethods))
		}
		for _, m := range s.Methods {
			if !methodPattern.MatchString(m) {
				add(prefix+".methods", "非法 HTTP 方法: "+m)
			}
		}
		hasExact := s.PathExact != ""
		hasPrefix := s.PathPrefix != ""
		if hasExact == hasPrefix {
			add(prefix, "path_exact 与 path_prefix 必须且仅须提供一个")
		}
		path := s.PathExact
		field := prefix + ".path_exact"
		if hasPrefix {
			path = s.PathPrefix
			field = prefix + ".path_prefix"
		}
		if path != "" {
			if !strings.HasPrefix(path, "/") {
				add(field, "路径必须以 / 开头")
			}
			if len(path) > MaxSelectorPathLen {
				add(field, fmt.Sprintf("路径长度不能超过 %d", MaxSelectorPathLen))
			}
			if strings.ContainsAny(path, "?#") {
				add(field, "路径不得包含 query 或 fragment")
			}
			if hasControlChars(path) {
				add(field, "路径不得包含控制字符")
			}
			if hasPrefix && strings.HasSuffix(path, "/") && path != "/" {
				add(field, "path_prefix 须按完整路径段给出，不应以 / 结尾")
			}
		}
	}

	if len(p.Issuers) > MaxIssuers {
		add("issuers", fmt.Sprintf("issuer 数量不能超过 %d", MaxIssuers))
	}
	if p.Mode != ModeOff && len(p.Issuers) == 0 {
		add("issuers", "非 OFF 模式必须配置至少一个 issuer")
	}
	seenIssuer := map[string]bool{}
	for i, is := range p.Issuers {
		prefix := fmt.Sprintf("issuers[%d]", i)
		if is.Issuer == "" {
			add(prefix+".issuer", "issuer 不能为空")
		} else {
			if len(is.Issuer) > MaxIssuerLen {
				add(prefix+".issuer", fmt.Sprintf("issuer 长度不能超过 %d", MaxIssuerLen))
			}
			if hasControlChars(is.Issuer) {
				add(prefix+".issuer", "issuer 不得包含控制字符")
			}
			if seenIssuer[is.Issuer] {
				add(prefix+".issuer", "issuer 精确值在策略内必须唯一: "+is.Issuer)
			}
			seenIssuer[is.Issuer] = true
		}
		if len(is.Audiences) == 0 {
			add(prefix+".audiences", "audiences 不能为空")
		}
		if len(is.Audiences) > MaxAudiences {
			add(prefix+".audiences", fmt.Sprintf("audiences 数量不能超过 %d", MaxAudiences))
		}
		for _, a := range is.Audiences {
			if a == "" || len(a) > MaxAudienceLen || hasControlChars(a) {
				add(prefix+".audiences", "audience 须为长度 1~256 的非空字符串")
			}
		}
		if len(is.Algorithms) == 0 {
			add(prefix+".algorithms", "algorithms 不能为空（RS256/ES256 的非空子集）")
		}
		for _, a := range is.Algorithms {
			if a != AlgRS256 && a != AlgES256 {
				add(prefix+".algorithms", "仅支持 RS256 / ES256，实际: "+a)
			}
		}
		if is.ClockSkewSeconds < 0 || is.ClockSkewSeconds > MaxClockSkew {
			add(prefix+".clock_skew_seconds", fmt.Sprintf("必须在 0~%d 秒之间", MaxClockSkew))
		}
		if is.TenantClaim != "" && !tenantClaimPattern.MatchString(is.TenantClaim) {
			add(prefix+".tenant_claim", "非法声明名（字母/数字/下划线/短横线，字母或下划线开头）")
		}
		if len(is.RoleClaims) > MaxRoleClaims {
			add(prefix+".role_claims", fmt.Sprintf("role_claims 数量不能超过 %d", MaxRoleClaims))
		}
		seenRoleClaim := map[string]bool{}
		for _, claim := range is.RoleClaims {
			if claim == "" || len(claim) > MaxRoleClaimLen || !tenantClaimPattern.MatchString(claim) {
				add(prefix+".role_claims", "非法角色声明名（字母/数字/下划线/短横线，字母或下划线开头）")
			}
			if seenRoleClaim[claim] {
				add(prefix+".role_claims", "角色声明名不得重复: "+claim)
			}
			seenRoleClaim[claim] = true
		}
		algSet := map[string]bool{}
		for _, a := range is.Algorithms {
			algSet[a] = true
		}
		switch is.KeySource.Type {
		case KeySourceStaticJWKS:
			if is.KeySource.JWKS == "" {
				add(prefix+".key_source.jwks", "STATIC_JWKS 必须提供公钥集")
			} else if _, err := ValidateJWKS(is.KeySource.JWKS, algSet); err != nil {
				add(prefix+".key_source.jwks", err.Error())
			}
			if is.KeySource.URL != "" {
				add(prefix+".key_source.url", "STATIC_JWKS 不接受 url 字段")
			}
		case KeySourceRemoteJWKS:
			if is.KeySource.URL == "" {
				add(prefix+".key_source.url", "REMOTE_JWKS 必须提供 url")
			} else if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(is.KeySource.URL)), "https://") {
				add(prefix+".key_source.url", "REMOTE_JWKS 仅允许 HTTPS 地址")
			}
			if is.KeySource.JWKS != "" {
				add(prefix+".key_source.jwks", "REMOTE_JWKS 不接受内联 jwks 字段")
			}
		default:
			add(prefix+".key_source.type", "仅支持 STATIC_JWKS / REMOTE_JWKS")
		}
		if tb := is.TokenBinding; tb != nil {
			tbPrefix := prefix + ".token_binding"
			switch tb.Mode {
			case "", TokenBindingNone:
				// 非激活绑定：不要求其他字段
			case TokenBindingDPoPOptional, TokenBindingDPoPRequired, TokenBindingMTLSRequired, TokenBindingDPoPOrMTLS:
				if tb.MaxProofAgeSeconds < MinDPoPMaxProofAgeSeconds || tb.MaxProofAgeSeconds > MaxDPoPMaxProofAgeSeconds {
					add(tbPrefix+".max_proof_age_seconds",
						fmt.Sprintf("必须在 %d~%d 秒之间", MinDPoPMaxProofAgeSeconds, MaxDPoPMaxProofAgeSeconds))
				}
				if tb.NonceTTLSeconds < MinDPoPNonceTTLSeconds || tb.NonceTTLSeconds > MaxDPoPNonceTTLSeconds {
					add(tbPrefix+".nonce_ttl_seconds",
						fmt.Sprintf("必须在 %d~%d 秒之间", MinDPoPNonceTTLSeconds, MaxDPoPNonceTTLSeconds))
				}
				for _, alg := range tb.AllowedDPoPAlgs {
					if alg != DPoPAlgES256 && alg != DPoPAlgRS256 && alg != DPoPAlgEdDSA {
						add(tbPrefix+".allowed_dpop_algs", "仅支持 ES256 / RS256 / EdDSA，实际: "+alg)
					}
				}
			default:
				add(tbPrefix+".mode", "仅支持 NONE / DPOP_OPTIONAL / DPOP_REQUIRED / MTLS_REQUIRED / DPOP_OR_MTLS")
			}
		}
	}
	return errs
}

// ValidateRemoteURLs REMOTE_JWKS 地址 SSRF 校验（保存时与预检同一规则）：
// 仅 HTTPS；默认拒绝回环/私网/链路本地/云元数据；企业内网 IdP 须经
// outbound 策略 allowlist（system_settings jwt_trust:remote_jwks_allowlist）显式登记。
// 域名解析全部 A/AAAA 记录逐一校验，任一内网地址即拒绝。
func ValidateRemoteURLs(ctx context.Context, p *Policy, outbound *outboundhttp.Policy) []FieldError {
	errs := []FieldError{}
	for i, is := range p.Issuers {
		if is.KeySource.Type != KeySourceRemoteJWKS || is.KeySource.URL == "" {
			continue
		}
		field := fmt.Sprintf("issuers[%d].key_source.url", i)
		u, err := outbound.ValidateURL(ctx, is.KeySource.URL)
		if err != nil {
			add := FieldError{Field: field, Message: "SSRF 校验未通过: " + err.Error()}
			errs = append(errs, add)
			continue
		}
		if u.Scheme != "https" {
			errs = append(errs, FieldError{Field: field, Message: "REMOTE_JWKS 仅允许 HTTPS 地址"})
		}
	}
	return errs
}

// hasControlChars 控制字符检测（防注入）。
func hasControlChars(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}
