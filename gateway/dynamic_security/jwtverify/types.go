package jwtverify

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Status 验证状态（冻结契约 §5）。
type Status string

const (
	StatusNotPresent  Status = "NOT_PRESENT" // 范围内未发现 Bearer
	StatusUnverified  Status = "UNVERIFIED"  // 策略关闭或不在范围
	StatusVerified    Status = "VERIFIED"
	StatusInvalid     Status = "INVALID"     // 依据可用信任配置明确不合法
	StatusUnavailable Status = "UNAVAILABLE" // 缺可用密钥或验证基础设施异常，不能推出有效/无效
)

// ReasonCode 固定枚举，不含原始 Token 或声明。
type ReasonCode string

const (
	ReasonPolicyOff         ReasonCode = "POLICY_OFF"
	ReasonOutOfScope        ReasonCode = "OUT_OF_SCOPE"
	ReasonMissingToken      ReasonCode = "MISSING_TOKEN"
	ReasonMalformedToken    ReasonCode = "MALFORMED_TOKEN"
	ReasonAlgorithmRejected ReasonCode = "ALGORITHM_REJECTED"
	ReasonUnknownIssuer     ReasonCode = "UNKNOWN_ISSUER"
	ReasonUnknownKid        ReasonCode = "UNKNOWN_KID"
	ReasonSignatureInvalid  ReasonCode = "SIGNATURE_INVALID"
	ReasonIssuerMismatch    ReasonCode = "ISSUER_MISMATCH"
	ReasonAudienceMismatch  ReasonCode = "AUDIENCE_MISMATCH"
	ReasonExpired           ReasonCode = "EXPIRED"
	ReasonNotYetValid       ReasonCode = "NOT_YET_VALID"
	ReasonClaimInvalid      ReasonCode = "CLAIM_INVALID"
	ReasonKeysetUnavailable ReasonCode = "KEYSET_UNAVAILABLE"
	ReasonVerifierError     ReasonCode = "VERIFIER_ERROR"
	ReasonValid             ReasonCode = "VALID"
)

// Mode 策略模式，默认 OFF。
type Mode string

const (
	ModeOff     Mode = "OFF"
	ModeObserve Mode = "OBSERVE"
	ModeProtect Mode = "PROTECT"
)

// EnforceAction 由模式决定：OFF→NONE，OBSERVE→OBSERVE，PROTECT→ENFORCE。
type EnforceAction string

const (
	EnforceNone    EnforceAction = "NONE"
	EnforceObserve EnforceAction = "OBSERVE"
	EnforceEnforce EnforceAction = "ENFORCE"
)

// KeySource 密钥来源，二选一。
type KeySource string

const (
	KeySourceStaticJWKS KeySource = "STATIC_JWKS"
	KeySourceRemoteJWKS KeySource = "REMOTE_JWKS"
)

// Algorithm 显式算法白名单取值。
type Algorithm string

const (
	AlgRS256 Algorithm = "RS256"
	AlgES256 Algorithm = "ES256"
)

// 产品限制（§5.2，可测试）。
const (
	MaxTokenBytes     = 16 * 1024  // Token 上限
	MaxKidBytes       = 256        // kid 上限
	MaxJWKSBytes      = 256 * 1024 // 单份 JWKS 上限
	MaxJWKSKeys       = 32         // 单份 JWKS 公钥数上限
	MaxSubjectBytes   = 256        // sub 上限
	MaxIssuerBytes    = 512        // issuer 精确值上限
	MaxIssuers        = 8          // 单策略 issuer 数上限
	MaxAudiences      = 16         // 单 issuer audience 数上限
	MaxAudienceBytes  = 256
	MaxTenantBytes    = 256
	MaxRoleClaims     = 8
	MaxRoleClaimBytes = 64
	MaxVerifiedRoles  = 32
	MaxRoleBytes      = 128

	DefaultClockSkewSeconds = 30
	MaxClockSkewSeconds     = 120

	minRSAKeyBits = 2048
)

// VerificationResult 不可变值类型（仅值字段，不产生共享引用）。
// VerifiedPrincipalID 仅 VERIFIED 非空；VerifiedTenantID 仅 VERIFIED 且
// 配置 tenant_claim 且声明验证成功时非空。
type VerificationResult struct {
	Status              Status
	ReasonCode          ReasonCode
	PolicyVersion       string
	IssuerConfigID      string
	KeysetVersion       string
	VerifiedPrincipalID string
	VerifiedTenantID    string
	// VerifiedRoles is populated only after the JWT signature and all claims
	// required by the trust policy have been verified.
	VerifiedRoles []string
	EvaluatedAt   string // RFC3339 UTC
	EnforceAction EnforceAction
}

// Selector 请求范围选择器；path_exact 与 path_prefix 二选一。
type Selector struct {
	Methods       []string // 大写去重；空表示任意方法
	PathExact     string
	PathPrefix    string
	TokenRequired bool
}

// IssuerConfig 单个受信发行方配置（只读快照，由配置链下发）。
type IssuerConfig struct {
	ID               string   // 服务端配置 ID；为空时按 issuer 值派生稳定 ID
	Issuer           string   // 精确值，大小写敏感，不去尾斜杠
	Audiences        []string // 非空
	Algorithms       []Algorithm
	KeySource        KeySource
	StaticJWKS       []byte   // STATIC_JWKS：公钥 JWKS JSON
	RemoteURL        string   // REMOTE_JWKS：预配置 HTTPS URL
	RemoteAllowCIDRs []string // REMOTE_JWKS：管理员显式登记的允许 CIDR（仍禁元数据/链路本地）
	ClockSkewSeconds int      // 0 表示默认 30；范围 0~120
	TenantClaim      string   // 可选，单一受信 tenant 声明名，仅在 VERIFIED 后读取
	RoleClaims       []string // 可选，显式受信 role 声明名，仅在 VERIFIED 后读取
}

// Policy JWT 信任策略（按应用）。
type Policy struct {
	ApplicationID string
	Version       string // 不可变策略版本
	Mode          Mode   // 默认 OFF
	Selectors     []Selector
	Issuers       []IssuerConfig
}

var errInvalidPolicy = errors.New("jwtverify: 策略配置无效")

func policyErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errInvalidPolicy, fmt.Sprintf(format, args...))
}

// Validate 校验并归一化策略（方法大写去重、prefix 去尾斜杠、算法去重、
// clock_skew 默认值回填）。校验失败返回包装 errInvalidPolicy 的错误。
func (p *Policy) Validate() error {
	if strings.TrimSpace(p.ApplicationID) == "" {
		return policyErr("application_id 不能为空")
	}
	switch p.Mode {
	case "":
		p.Mode = ModeOff
	case ModeOff, ModeObserve, ModeProtect:
	default:
		return policyErr("mode 取值非法: %q", p.Mode)
	}
	if p.Mode != ModeOff && len(p.Selectors) == 0 {
		return policyErr("非 OFF 模式 selectors 必填非空")
	}
	for i := range p.Selectors {
		if err := normalizeSelector(&p.Selectors[i]); err != nil {
			return err
		}
	}
	if len(p.Issuers) > MaxIssuers {
		return policyErr("issuers 最多 %d 项", MaxIssuers)
	}
	seenIssuer := make(map[string]struct{}, len(p.Issuers))
	for i := range p.Issuers {
		iss := &p.Issuers[i]
		if iss.Issuer == "" {
			return policyErr("issuer 精确值不能为空")
		}
		if len(iss.Issuer) > MaxIssuerBytes {
			return policyErr("issuer 长度超过 %d 字节", MaxIssuerBytes)
		}
		if _, dup := seenIssuer[iss.Issuer]; dup {
			return policyErr("issuer 精确值重复: %q", iss.Issuer)
		}
		seenIssuer[iss.Issuer] = struct{}{}
		if len(iss.Audiences) == 0 || len(iss.Audiences) > MaxAudiences {
			return policyErr("issuer %q 的 audiences 须为 1~%d 项", iss.Issuer, MaxAudiences)
		}
		for _, aud := range iss.Audiences {
			if aud == "" || len(aud) > MaxAudienceBytes {
				return policyErr("issuer %q 存在空或超长 audience", iss.Issuer)
			}
		}
		if len(iss.Algorithms) == 0 {
			return policyErr("issuer %q 的 algorithms 不能为空", iss.Issuer)
		}
		seenAlg := make(map[Algorithm]struct{}, len(iss.Algorithms))
		dedup := iss.Algorithms[:0]
		for _, alg := range iss.Algorithms {
			if alg != AlgRS256 && alg != AlgES256 {
				return policyErr("issuer %q 的算法不在白名单 {RS256,ES256}: %q", iss.Issuer, alg)
			}
			if _, dup := seenAlg[alg]; !dup {
				seenAlg[alg] = struct{}{}
				dedup = append(dedup, alg)
			}
		}
		iss.Algorithms = dedup
		switch iss.KeySource {
		case KeySourceStaticJWKS:
			if len(iss.StaticJWKS) == 0 {
				return policyErr("issuer %q STATIC_JWKS 缺静态公钥集", iss.Issuer)
			}
			if len(iss.StaticJWKS) > MaxJWKSBytes {
				return policyErr("issuer %q 静态 JWKS 超过 %d 字节", iss.Issuer, MaxJWKSBytes)
			}
			if iss.RemoteURL != "" {
				return policyErr("issuer %q STATIC_JWKS 不得配置 remote_url", iss.Issuer)
			}
		case KeySourceRemoteJWKS:
			if err := validateRemoteURL(iss.RemoteURL); err != nil {
				return policyErr("issuer %q remote_url 非法: %v", iss.Issuer, err)
			}
			if len(iss.StaticJWKS) != 0 {
				return policyErr("issuer %q REMOTE_JWKS 不得配置静态 JWKS", iss.Issuer)
			}
			for _, c := range iss.RemoteAllowCIDRs {
				if _, err := netip.ParsePrefix(c); err != nil {
					return policyErr("issuer %q 允许 CIDR 非法: %q", iss.Issuer, c)
				}
			}
		default:
			return policyErr("issuer %q key_source 取值非法: %q", iss.Issuer, iss.KeySource)
		}
		if iss.ClockSkewSeconds == 0 {
			iss.ClockSkewSeconds = DefaultClockSkewSeconds
		}
		if iss.ClockSkewSeconds < 0 || iss.ClockSkewSeconds > MaxClockSkewSeconds {
			return policyErr("issuer %q clock_skew_seconds 须在 0~%d", iss.Issuer, MaxClockSkewSeconds)
		}
		if iss.TenantClaim != "" {
			if len(iss.TenantClaim) > 64 || strings.ContainsAny(iss.TenantClaim, " \t\r\n\"\\.") {
				return policyErr("issuer %q tenant_claim 名称非法", iss.Issuer)
			}
		}
		if len(iss.RoleClaims) > MaxRoleClaims {
			return policyErr("issuer %q role_claims 最多 %d 项", iss.Issuer, MaxRoleClaims)
		}
		seenRoleClaim := make(map[string]struct{}, len(iss.RoleClaims))
		for _, claim := range iss.RoleClaims {
			if claim == "" || len(claim) > MaxRoleClaimBytes || strings.ContainsAny(claim, " \t\r\n\"\\.") {
				return policyErr("issuer %q role_claim 名称非法", iss.Issuer)
			}
			if _, dup := seenRoleClaim[claim]; dup {
				return policyErr("issuer %q role_claim 重复", iss.Issuer)
			}
			seenRoleClaim[claim] = struct{}{}
		}
		if iss.ID == "" {
			iss.ID = derivedIssuerConfigID(iss.Issuer)
		}
	}
	return nil
}

func normalizeSelector(s *Selector) error {
	if (s.PathExact == "") == (s.PathPrefix == "") {
		return policyErr("selector 的 path_exact 与 path_prefix 必须二选一")
	}
	path := s.PathExact
	if path == "" {
		path = s.PathPrefix
	}
	if !strings.HasPrefix(path, "/") {
		return policyErr("selector 路径必须以 / 开头: %q", path)
	}
	if strings.ContainsAny(path, "?#") {
		return policyErr("selector 路径不得包含 query/fragment: %q", path)
	}
	if len(path) > 1024 {
		return policyErr("selector 路径过长")
	}
	if s.PathPrefix != "" && len(s.PathPrefix) > 1 {
		s.PathPrefix = strings.TrimRight(s.PathPrefix, "/")
		if s.PathPrefix == "" {
			s.PathPrefix = "/"
		}
	}
	seen := make(map[string]struct{}, len(s.Methods))
	dedup := s.Methods[:0]
	for _, m := range s.Methods {
		mu := strings.ToUpper(strings.TrimSpace(m))
		if mu == "" {
			return policyErr("selector methods 含空方法")
		}
		if strings.ContainsAny(mu, " \t,") {
			return policyErr("selector method 非法: %q", m)
		}
		if _, ok := seen[mu]; !ok {
			seen[mu] = struct{}{}
			dedup = append(dedup, mu)
		}
	}
	s.Methods = dedup
	return nil
}

func validateRemoteURL(raw string) error {
	if raw == "" {
		return errors.New("remote_url 不能为空")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return errors.New("remote_url 仅允许 https")
	}
	if u.User != nil {
		return errors.New("remote_url 不得包含用户信息")
	}
	if u.Hostname() == "" {
		return errors.New("remote_url 缺少主机名")
	}
	if len(raw) > 2048 {
		return errors.New("remote_url 过长")
	}
	return nil
}

// derivedIssuerConfigID 在未下发配置 ID 时按 issuer 值派生稳定标识。
func derivedIssuerConfigID(issuer string) string {
	sum := sha256Hex16([]byte(issuer))
	return "iss-" + sum
}

// matchSelectors 返回是否命中任一 selector（OR 语义）及合并后的
// token_required（重叠时 true 优先）。path 须为已规范的请求路径（不含 query）。
func matchSelectors(selectors []Selector, method, path string) (matched, tokenRequired bool) {
	method = strings.ToUpper(method)
	for i := range selectors {
		s := &selectors[i]
		if len(s.Methods) > 0 {
			ok := false
			for _, m := range s.Methods {
				if m == method {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		if s.PathExact != "" {
			if path != s.PathExact {
				continue
			}
		} else if !prefixSegmentMatch(s.PathPrefix, path) {
			continue
		}
		matched = true
		if s.TokenRequired {
			tokenRequired = true
		}
	}
	return matched, tokenRequired
}

// prefixSegmentMatch 按完整路径段匹配："/api" 匹配 "/api" 与 "/api/orders"，
// 不匹配 "/apix"；根前缀 "/" 匹配所有以 / 开头的路径。
func prefixSegmentMatch(prefix, path string) bool {
	if prefix == "/" {
		return strings.HasPrefix(path, "/")
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || path[len(prefix)] == '/'
}
