package jwtverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// VerifierConfig 验证器构造配置。
type VerifierConfig struct {
	Policy Policy
	// IdentitySecret 可信身份指纹密钥（部署注入）。PROTECT 必须非空，否则
	// 构造失败（fail-closed，§5.1）；空密钥不得用固定默认盐代替。
	// OBSERVE 允许空密钥：签名校验与观测照常运行，但 VERIFIED 结果不携带
	// 可信主体指纹（无可信身份产出，不得冒充已建立身份信任链）。
	IdentitySecret []byte
	// Fetcher 远程 JWKS 获取器；存在 REMOTE_JWKS issuer 时必填。
	Fetcher *Fetcher
	// Clock 时钟（缓存年龄取单调读数，声明时间取墙钟）；nil = 真实时钟。
	Clock Clock
	// TrustTTL 密钥集信任期，默认 15 分钟；RefreshInterval 后台刷新间隔，
	// 默认 5 分钟；RefreshCooldown 异步刷新冷却，默认 30s。
	TrustTTL        time.Duration
	RefreshInterval time.Duration
	RefreshCooldown time.Duration
	// OnRefreshError 后台/异步刷新失败回调（日志用）；可为 nil。
	OnRefreshError func(issuerID string, err error)
	// DPoPReplay DPoP Proof 分布式原子防重放存储（可选；启用 DPoP 时为 nil 将返 UNAVAILABLE）。
	DPoPReplay DPoPReplayStore
}

// Verifier 纯本地 JWT 验证器。热路径零网络 IO：仅读取不可变快照。
type Verifier struct {
	policy          Policy
	issuers         map[string]*issuerRuntime
	secret          []byte
	clock           Clock
	refreshInterval time.Duration
	dpopReplay      DPoPReplayStore
	allowDPoPScheme bool
}

type issuerRuntime struct {
	cfg         IssuerConfig
	algs        map[Algorithm]struct{}
	auds        map[string]struct{}
	dpopAlgs    map[string]struct{}
	allowCIDRs  []netip.Prefix
	staticSnap  *KeysetSnapshot // STATIC_JWKS：随已发布策略生效，不按远程 TTL 失效
	remoteCache *keysetCache    // REMOTE_JWKS
}

func (ir *issuerRuntime) snapshot() (*KeysetSnapshot, SnapshotState) {
	if ir.staticSnap != nil {
		return ir.staticSnap, SnapshotValid
	}
	return ir.remoteCache.snapshot()
}

// NewVerifier 校验策略、解析静态 JWKS、建立远程缓存；任一环节失败即整体
// 构造失败（配置加载期 fail-closed，不静默降级）。
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	policy := clonePolicy(cfg.Policy)
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if policy.Mode == ModeProtect && len(cfg.IdentitySecret) == 0 {
		return nil, ErrIdentitySecretRequired
	}
	clock := cfg.Clock
	if clock == nil {
		clock = realClock{}
	}
	v := &Verifier{
		policy:          policy,
		issuers:         make(map[string]*issuerRuntime, len(policy.Issuers)),
		secret:          append([]byte(nil), cfg.IdentitySecret...),
		clock:           clock,
		refreshInterval: cfg.RefreshInterval,
		dpopReplay:      cfg.DPoPReplay,
	}
	if v.refreshInterval <= 0 {
		v.refreshInterval = DefaultRefreshInterval
	}
	for _, iss := range policy.Issuers {
		ir := &issuerRuntime{
			cfg:      iss,
			algs:     make(map[Algorithm]struct{}, len(iss.Algorithms)),
			auds:     make(map[string]struct{}, len(iss.Audiences)),
			dpopAlgs: make(map[string]struct{}),
		}
		if iss.TokenBinding != nil && iss.TokenBinding.Active() {
			switch iss.TokenBinding.Mode {
			case TokenBindingDPoPOptional, TokenBindingDPoPRequired, TokenBindingDPoPOrMTLS:
				v.allowDPoPScheme = true
			}
			for _, da := range iss.TokenBinding.AllowedDPoPAlgs {
				ir.dpopAlgs[da] = struct{}{}
			}
		}
		for _, a := range iss.Algorithms {
			ir.algs[a] = struct{}{}
		}
		for _, aud := range iss.Audiences {
			ir.auds[aud] = struct{}{}
		}
		switch iss.KeySource {
		case KeySourceStaticJWKS:
			ks, err := ParseJWKS(iss.StaticJWKS)
			if err != nil {
				return nil, fmt.Errorf("jwtverify: issuer %q 静态 JWKS 无效: %w", iss.ID, err)
			}
			ir.staticSnap = &KeysetSnapshot{Keyset: ks, LoadedAt: clock.Now()}
		case KeySourceRemoteJWKS:
			if cfg.Fetcher == nil {
				return nil, fmt.Errorf("jwtverify: issuer %q 为 REMOTE_JWKS 但未提供 Fetcher", iss.ID)
			}
			allow, err := parseAllowCIDRs(iss.RemoteAllowCIDRs)
			if err != nil {
				return nil, err
			}
			ir.allowCIDRs = allow
			target := RemoteTarget{URL: iss.RemoteURL, AllowCIDRs: allow}
			fetcher := cfg.Fetcher
			var onErr func(error)
			if cfg.OnRefreshError != nil {
				id := iss.ID
				onErr = func(err error) { cfg.OnRefreshError(id, err) }
			}
			ir.remoteCache = newKeysetCache(clock, cfg.TrustTTL, cfg.RefreshCooldown,
				func(ctx context.Context) (*Keyset, error) {
					body, err := fetcher.Fetch(ctx, target)
					if err != nil {
						return nil, err
					}
					return ParseJWKS(body)
				}, onErr)
		}
		v.issuers[iss.Issuer] = ir
	}
	return v, nil
}

// StartBackgroundRefresh 启动远程密钥集后台刷新：立即刷新一次，之后按
// RefreshInterval 周期刷新，直至 ctx 取消。失败不延长最后成功时间。
func (v *Verifier) StartBackgroundRefresh(ctx context.Context) {
	remotes := make([]*keysetCache, 0, len(v.issuers))
	for _, ir := range v.issuers {
		if ir.remoteCache != nil {
			remotes = append(remotes, ir.remoteCache)
		}
	}
	if len(remotes) == 0 {
		return
	}
	go func() {
		for _, c := range remotes {
			_ = c.RefreshSync(ctx)
		}
		ticker := time.NewTicker(v.refreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, c := range remotes {
					_ = c.RefreshSync(ctx)
				}
			}
		}
	}()
}

// Policy 返回归一化后的策略只读快照。
func (v *Verifier) Policy() Policy { return v.policy }

// Verify 对一次请求执行本地 JWT 验证。authValues 为全部 Authorization 头值；
// method/path 为网关已规范的方法与路径（path 不含 query）。任何内部异常
// 恢复为 UNAVAILABLE/VERIFIER_ERROR，绝不 panic 到调用方。
func (v *Verifier) Verify(authValues []string, method, path string) (res VerificationResult) {
	return v.VerifyRequest(RequestVerifyInput{
		AuthValues: authValues,
		Method:     method,
		Path:       path,
	})
}

// VerifyRequest 对一次完整 HTTP 请求执行本地 JWT + 持有证明（DPoP / mTLS）验证。
// 任何内部异常恢复为 UNAVAILABLE/VERIFIER_ERROR，绝不 panic 到调用方。
func (v *Verifier) VerifyRequest(in RequestVerifyInput) (res VerificationResult) {
	defer func() {
		if r := recover(); r != nil {
			res = v.result(StatusUnavailable, ReasonVerifierError, nil, "", "")
		}
	}()
	return v.verifyRequest(in)
}

func (v *Verifier) verifyRequest(in RequestVerifyInput) VerificationResult {
	if v.policy.Mode == ModeOff {
		return v.result(StatusUnverified, ReasonPolicyOff, nil, "", "")
	}
	matched, tokenRequired := matchSelectors(v.policy.Selectors, in.Method, in.Path)
	if !matched {
		return v.result(StatusUnverified, ReasonOutOfScope, nil, "", "")
	}
	token, scheme, present, err := extractAuthToken(in.AuthValues, v.allowDPoPScheme)
	if err != nil {
		return v.result(StatusInvalid, err.(*tokenError).reason, nil, "", "")
	}
	if !present {
		if tokenRequired {
			return v.result(StatusInvalid, ReasonMissingToken, nil, "", "")
		}
		return v.result(StatusNotPresent, ReasonMissingToken, nil, "", "")
	}
	parsed, perr := parseTokenStrict(token)
	if perr != nil {
		res := v.result(StatusInvalid, perr.(*tokenError).reason, nil, "", "")
		res.TokenScheme = scheme
		return res
	}
	// 全局算法白名单先行拒绝（none/HS 混淆等），与具体 issuer 无关。
	if parsed.alg != string(AlgRS256) && parsed.alg != string(AlgES256) {
		res := v.result(StatusInvalid, ReasonAlgorithmRejected, nil, "", "")
		res.TokenScheme = scheme
		return res
	}
	// 未验证 iss 仅可作有限配置集合的索引。
	ir, ok := v.issuers[parsed.claims.issuer]
	if !parsed.claims.hasIssuer || !ok {
		res := v.result(StatusInvalid, ReasonUnknownIssuer, nil, "", "")
		res.TokenScheme = scheme
		return res
	}
	if _, ok := ir.algs[Algorithm(parsed.alg)]; !ok {
		res := v.result(StatusInvalid, ReasonAlgorithmRejected, ir, "", "")
		res.TokenScheme = scheme
		return res
	}
	snap, state := ir.snapshot()
	if state != SnapshotValid {
		if ir.remoteCache != nil {
			ir.remoteCache.notifyRefreshNeeded()
		}
		res := v.result(StatusUnavailable, ReasonKeysetUnavailable, ir, "", "")
		res.TokenScheme = scheme
		return res
	}
	key, ok := snap.Keyset.KeyFor(parsed.kid)
	if !ok {
		if ir.remoteCache != nil {
			ir.remoteCache.NotifyUnknownKid(parsed.kid)
		}
		res := v.result(StatusInvalid, ReasonUnknownKid, ir, snap.Keyset.Version, "")
		res.TokenScheme = scheme
		return res
	}
	if r := verifySignature(parsed, key); r != "" {
		res := v.result(StatusInvalid, r, ir, snap.Keyset.Version, "")
		res.TokenScheme = scheme
		return res
	}
	res := v.validateClaims(parsed, ir, snap.Keyset.Version)
	res.TokenScheme = scheme
	if res.Status != StatusVerified {
		return res
	}
	return v.verifyTokenBinding(parsed, ir, snap.Keyset.Version, scheme, in, res)
}

// verifyTokenBinding 9A-1：在 JWT 签名与标准声明均通过后，按发行方配置校验 DPoP (RFC 9449) 或 mTLS (RFC 8705) 绑定。
func (v *Verifier) verifyTokenBinding(
	parsed *parsedToken,
	ir *issuerRuntime,
	keysetVersion string,
	scheme string,
	in RequestVerifyInput,
	verifiedRes VerificationResult,
) VerificationResult {
	tb := ir.cfg.TokenBinding
	if tb == nil || !tb.Active() {
		// 未启用绑定时若客户端以 DPoP 方案发送（因他 issuer 开启了 allowDPoPScheme），
		// 拒绝非 Bearer 方案保持该 issuer 既有严格语义。
		if scheme != "Bearer" {
			res := v.result(StatusInvalid, ReasonMalformedToken, ir, keysetVersion, "")
			res.TokenScheme = scheme
			return res
		}
		return verifiedRes
	}
	cnf, err := parseCnfClaim(parsed.claims.raw)
	if err != nil {
		res := v.result(StatusInvalid, ReasonClaimInvalid, ir, keysetVersion, "")
		res.TokenScheme = scheme
		return res
	}

	failRes := func(st Status, rc ReasonCode, nonce string) VerificationResult {
		r := v.result(st, rc, ir, keysetVersion, "")
		r.TokenScheme = scheme
		r.DPoPNonce = nonce
		return r
	}

	runDPoP := func() VerificationResult {
		if cnf.JKT == "" {
			return failRes(StatusInvalid, ReasonBindingMissing, "")
		}
		if scheme != "DPoP" {
			return failRes(StatusInvalid, ReasonDPoPMalformed, "")
		}
		st, rc, nonce := v.verifyDPoPProof(ir, parsed.raw, cnf.JKT, in)
		if st != StatusVerified {
			return failRes(st, rc, nonce)
		}
		verifiedRes.TokenBindingVerified = "DPOP"
		return verifiedRes
	}

	runMTLS := func() VerificationResult {
		if cnf.X5TS256 == "" {
			return failRes(StatusInvalid, ReasonBindingMissing, "")
		}
		st, rc := verifyMTLSBinding(in.PeerCertDER, cnf.X5TS256)
		if st != StatusVerified {
			return failRes(st, rc, "")
		}
		verifiedRes.TokenBindingVerified = "MTLS"
		return verifiedRes
	}

	switch tb.Mode {
	case TokenBindingDPoPOptional:
		if cnf.JKT != "" || scheme == "DPoP" || len(in.DPoPHeaders) > 0 {
			return runDPoP()
		}
		return verifiedRes
	case TokenBindingDPoPRequired:
		return runDPoP()
	case TokenBindingMTLSRequired:
		if scheme != "Bearer" {
			return failRes(StatusInvalid, ReasonMalformedToken, "")
		}
		return runMTLS()
	case TokenBindingDPoPOrMTLS:
		if cnf.JKT != "" || scheme == "DPoP" || len(in.DPoPHeaders) > 0 {
			return runDPoP()
		}
		if cnf.X5TS256 != "" {
			return runMTLS()
		}
		return failRes(StatusInvalid, ReasonBindingMissing, "")
	default:
		return verifiedRes
	}
}

// verifySignature 算法/密钥绑定 + 签名校验。返回空串表示通过，否则为
// INVALID 类 reason_code。使用锁定的 go-jose v4 验签（其自身不解引用
// jku/x5u），外层 parseTokenStrict 已补齐重复键/段数/尺寸等严格性。
func verifySignature(parsed *parsedToken, key jose.JSONWebKey) ReasonCode {
	alg := Algorithm(parsed.alg)
	switch alg {
	case AlgRS256:
		if _, ok := key.Key.(*rsa.PublicKey); !ok {
			return ReasonAlgorithmRejected
		}
	case AlgES256:
		pub, ok := key.Key.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return ReasonAlgorithmRejected
		}
	default:
		return ReasonAlgorithmRejected
	}
	// JWK 自带 alg 时须与 Token alg 一致（密钥用途绑定）。
	if key.Algorithm != "" && key.Algorithm != parsed.alg {
		return ReasonAlgorithmRejected
	}
	jws, err := jose.ParseSigned(parsed.raw, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(parsed.alg)})
	if err != nil || len(jws.Signatures) != 1 {
		return ReasonSignatureInvalid
	}
	if _, err := jws.Verify(key.Key); err != nil {
		return ReasonSignatureInvalid
	}
	return ""
}

// validateClaims 验签后的声明复核（§5.2）：issuer 精确复核、audience 交集、
// exp 必填与过期、nbf 未生效、sub 非空有界。
func (v *Verifier) validateClaims(parsed *parsedToken, ir *issuerRuntime, keysetVersion string) VerificationResult {
	claims := parsed.claims
	// 验签后必须复核 issuer 精确值（大小写敏感，不去尾斜杠）。
	if claims.issuer != ir.cfg.Issuer {
		return v.result(StatusInvalid, ReasonIssuerMismatch, ir, keysetVersion, "")
	}
	if !claims.hasAudiences {
		return v.result(StatusInvalid, ReasonAudienceMismatch, ir, keysetVersion, "")
	}
	audOK := false
	for _, aud := range claims.audiences {
		if _, ok := ir.auds[aud]; ok {
			audOK = true
			break
		}
	}
	if !audOK {
		return v.result(StatusInvalid, ReasonAudienceMismatch, ir, keysetVersion, "")
	}
	if !claims.hasExpiry {
		return v.result(StatusInvalid, ReasonClaimInvalid, ir, keysetVersion, "")
	}
	leeway := time.Duration(ir.cfg.ClockSkewSeconds) * time.Second
	now := v.clock.Now()
	if !now.Before(claims.expiry.Add(leeway)) { // now >= exp+leeway → 过期
		return v.result(StatusInvalid, ReasonExpired, ir, keysetVersion, "")
	}
	if claims.hasNotBefore && now.Add(leeway).Before(claims.notBefore) { // now+leeway < nbf → 未生效
		return v.result(StatusInvalid, ReasonNotYetValid, ir, keysetVersion, "")
	}
	if !claims.hasSubject || claims.subject == "" || len(claims.subject) > MaxSubjectBytes {
		return v.result(StatusInvalid, ReasonClaimInvalid, ir, keysetVersion, "")
	}
	// tenant：仅 VERIFIED 路径读取配置的受信声明；缺失/类型非法视为未携带，
	// 不影响验证结论，也不进入指纹。
	tenant, tenantPresent := "", false
	if ir.cfg.TenantClaim != "" {
		if raw, ok := claims.raw[ir.cfg.TenantClaim]; ok {
			var s string
			if err := jsonUnmarshalString(raw, &s); err == nil && s != "" && len(s) <= MaxTenantBytes {
				tenant, tenantPresent = s, true
			}
		}
	}
	// 角色、作用域与 RFC 8693 委派链只在签名及注册声明验证完成后读取；
	// 未验证 Token 绝不得产出任何 VerifiedScopes / DelegationChain / VerifiedAZP 信号。
	res := v.result(StatusVerified, ReasonValid, ir, keysetVersion, "")
	res.VerifiedRoles = verifiedRoles(claims.raw, ir.cfg.RoleClaims)
	res.VerifiedScopes = verifiedScopes(claims.raw)
	res.DelegationChain, res.DelegationScopes = verifiedDelegationChain(claims.raw)
	res.VerifiedAZP = verifiedAZP(claims.raw)
	// 空身份密钥（仅 OBSERVE 可达）：验签结论照常返回 VERIFIED，但不产出
	// 可信主体/tenant——无可信身份指纹密钥时禁止冒充已建立身份信任链（§5.1）。
	if len(v.secret) == 0 {
		// 角色基线只接受可信主体信号；没有主体指纹时，角色也不能进入
		// 后续授权决策，即使 JWT 本身已经通过签名校验。
		res.VerifiedRoles = nil
		return res
	}
	principal, err := PrincipalID(v.secret, v.policy.ApplicationID, claims.issuer, claims.subject, tenant, tenantPresent)
	if err != nil {
		return v.result(StatusUnavailable, ReasonVerifierError, ir, keysetVersion, "")
	}
	res.VerifiedPrincipalID = principal
	res.VerifiedTenantID = tenant
	if strings.TrimSpace(res.VerifiedPrincipalID) == "" {
		res.VerifiedRoles = nil
	}
	return res
}

// verifiedRoles reads only explicitly configured role claims, and is called
// after signature and registered claim validation has completed. Invalid or
// overlong role values are ignored so they cannot influence authorization.
func verifiedRoles(raw map[string]json.RawMessage, claimNames []string) []string {
	if len(raw) == 0 || len(claimNames) == 0 {
		return nil
	}
	roles := make([]string, 0, len(claimNames))
	seen := make(map[string]struct{})
	for _, name := range claimNames {
		value, ok := raw[name]
		if !ok {
			continue
		}
		var single string
		if json.Unmarshal(value, &single) == nil {
			appendVerifiedRole(&roles, seen, single)
			continue
		}
		var many []string
		if json.Unmarshal(value, &many) != nil {
			continue
		}
		for _, role := range many {
			appendVerifiedRole(&roles, seen, role)
			if len(roles) >= MaxVerifiedRoles {
				return roles
			}
		}
	}
	return roles
}

func appendVerifiedRole(roles *[]string, seen map[string]struct{}, role string) {
	role = strings.TrimSpace(role)
	if role == "" || len(role) > MaxRoleBytes {
		return
	}
	if _, ok := seen[role]; ok {
		return
	}
	seen[role] = struct{}{}
	*roles = append(*roles, role)
}

// verifiedScopes strictly parses "scope" (RFC 6749 space-delimited string or
// string array) and "scp" (string array or space-delimited string) ONLY after
// cryptographic signature and registered claim verification.
func verifiedScopes(raw map[string]json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var scopes []string
	seen := make(map[string]struct{})
	appendScope := func(s string) bool {
		if len(scopes) >= MaxVerifiedScopes {
			return false
		}
		s = strings.TrimSpace(s)
		if s == "" || len(s) > MaxScopeBytes || containsControlOrSpace(s) {
			return true
		}
		if _, dup := seen[s]; dup {
			return true
		}
		seen[s] = struct{}{}
		scopes = append(scopes, s)
		return len(scopes) < MaxVerifiedScopes
	}
	for _, claim := range []string{"scope", "scp"} {
		val, ok := raw[claim]
		if !ok || len(val) == 0 {
			continue
		}
		var single string
		if json.Unmarshal(val, &single) == nil {
			for _, f := range strings.Fields(single) {
				if !appendScope(f) {
					return scopes
				}
			}
			continue
		}
		var many []string
		if json.Unmarshal(val, &many) == nil {
			for _, item := range many {
				if !appendScope(item) {
					return scopes
				}
			}
		}
	}
	if len(scopes) == 0 {
		return nil
	}
	return scopes
}

// verifiedDelegationChain strictly parses the RFC 8693 nested "act" claim chain
// (outermost actor first) and any per-hop "scope"/"scp" claims ONLY after
// cryptographic signature and registered claim verification.
func verifiedDelegationChain(raw map[string]json.RawMessage) ([]string, [][]string) {
	if len(raw) == 0 {
		return nil, nil
	}
	actRaw, ok := raw["act"]
	if !ok || len(actRaw) == 0 {
		return nil, nil
	}
	var chain []string
	var allScopes [][]string
	hasAnyScopes := false
	for depth := 0; ok && len(actRaw) > 0 && depth < MaxDelegationChain; depth++ {
		var actObj map[string]json.RawMessage
		if err := json.Unmarshal(actRaw, &actObj); err != nil || len(actObj) == 0 {
			break
		}
		actor := firstValidClaimString(actObj, MaxDelegationSubBytes, "sub", "client_id", "azp")
		nextAct, hasNext := actObj["act"]
		if actor == "" {
			if !hasNext {
				break
			}
			actor = "unknown"
		}
		hopScopes := verifiedScopes(actObj)
		if len(hopScopes) > 0 {
			hasAnyScopes = true
		}
		chain = append(chain, actor)
		allScopes = append(allScopes, hopScopes)
		actRaw, ok = nextAct, hasNext
	}
	if len(chain) == 0 {
		return nil, nil
	}
	if !hasAnyScopes {
		return chain, nil
	}
	return chain, allScopes
}

// verifiedAZP extracts the authorized party ("azp" or fallback "client_id")
// strictly after cryptographic signature verification.
func verifiedAZP(raw map[string]json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	return firstValidClaimString(raw, MaxSubjectBytes, "azp", "client_id")
}

func firstValidClaimString(raw map[string]json.RawMessage, maxLen int, keys ...string) string {
	for _, k := range keys {
		v, ok := raw[k]
		if !ok || len(v) == 0 {
			continue
		}
		var s string
		if json.Unmarshal(v, &s) != nil {
			continue
		}
		s = strings.TrimSpace(s)
		if s == "" || len(s) > maxLen || containsControlChar(s) {
			continue
		}
		return s
	}
	return ""
}

func containsControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func containsControlOrSpace(s string) bool {
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// result 构造结果基座：填充策略/issuer/密钥版本、评估时间与模式处置动作。
func (v *Verifier) result(status Status, reason ReasonCode, ir *issuerRuntime, keysetVersion, _ string) VerificationResult {
	res := VerificationResult{
		Status:        status,
		ReasonCode:    reason,
		PolicyVersion: v.policy.Version,
		KeysetVersion: keysetVersion,
		EvaluatedAt:   v.clock.Now().UTC().Format(time.RFC3339),
	}
	if ir != nil {
		res.IssuerConfigID = ir.cfg.ID
	}
	switch v.policy.Mode {
	case ModeObserve:
		res.EnforceAction = EnforceObserve
	case ModeProtect:
		res.EnforceAction = EnforceEnforce
	default:
		res.EnforceAction = EnforceNone
	}
	if status == StatusUnverified { // OFF / 范围外不产生处置语义
		res.EnforceAction = EnforceNone
	}
	return res
}

func jsonUnmarshalString(raw json.RawMessage, out *string) error {
	return json.Unmarshal(raw, out)
}

func clonePolicy(p Policy) Policy {
	cp := p
	if len(p.Selectors) > 0 {
		cp.Selectors = make([]Selector, len(p.Selectors))
		for i, s := range p.Selectors {
			s.Methods = append([]string(nil), s.Methods...)
			cp.Selectors[i] = s
		}
	}
	if len(p.Issuers) > 0 {
		cp.Issuers = make([]IssuerConfig, len(p.Issuers))
		for i, iss := range p.Issuers {
			iss.Audiences = append([]string(nil), iss.Audiences...)
			iss.Algorithms = append([]Algorithm(nil), iss.Algorithms...)
			iss.StaticJWKS = append([]byte(nil), iss.StaticJWKS...)
			iss.RemoteAllowCIDRs = append([]string(nil), iss.RemoteAllowCIDRs...)
			iss.RoleClaims = append([]string(nil), iss.RoleClaims...)
			if iss.TokenBinding != nil {
				tb := *iss.TokenBinding
				tb.AllowedDPoPAlgs = append([]string(nil), iss.TokenBinding.AllowedDPoPAlgs...)
				iss.TokenBinding = &tb
			}
			cp.Issuers[i] = iss
		}
	}
	return cp
}
