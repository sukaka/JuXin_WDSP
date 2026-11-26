// JWT 信任链（WDSP P0-03，任务书 docs/tasks/wdsp-p0/P0-03_JWT_TRUST_CHAIN.md）：
// jiuzhang_guard 请求链上的配置消费、验证与强制处置挂点。
//
// 纪律：
//   - jwt_trust 处理器段（发布通道下发，仅 WDSP 开启时）是 guard 配置「容忍未知字段」
//     惯例的显式例外：严格解码——未知字段、不支持的 schema_version、未知 mode
//     强制语义一律拒绝加载该策略（fail-closed，任务书 JWT-14）；旧节点不得把
//     未知强制语义静默忽略当作安全回退。
//   - 真实 IP 处理后、身份观测前执行一次纯本地验证（仅计算，结果入请求上下文）；
//     强制处置在 API 动态管线阶段（serveNext 统一放行出口）执行——白名单/L7 allow
//     不绕过 JWT PROTECT（安全底线）；身份观测关闭或 panic recover 不跳过
//     JWT 验证与执行（验证/执行不经过观测模块的 fail-open 分支）。
//   - 身份指纹密钥复用发布通道 identity_salt（jwtverify 指纹带独立域分隔前缀，
//     与 identitybehavior 指纹互不混用）：空密钥时 OBSERVE 可运行但不产可信主体，
//     PROTECT 由 jwtverify.NewVerifier 拒绝构造（fail-closed）。
//   - 热路径零网络 IO；REMOTE_JWKS 后台刷新由 StartBackgroundRefresh 驱动，
//     随 Guard Cleanup 取消。
package jiuzhang_guard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
	"go.uber.org/zap"
)

// jwtTrustSchemaVersion / jwtTrustSchemaVersionV2 本网关支持的 jwt_trust 配置结构版本
// （1=基础 JWT 信任链，2=含 9A-1 token_binding DPoP/mTLS；不支持的版本与 v1 夹带 token_binding 均拒绝加载）。
const (
	jwtTrustSchemaVersion   = 1
	jwtTrustSchemaVersionV2 = 2
)

// jwtTrustJSON 发布通道下发 jwt_trust 处理器段（json tag 为跨分片契约，不得改动；
// 与 server/internal/gatewayconfig.GuardJWTTrustPolicy 同形）。
type jwtTrustJSON struct {
	SchemaVersion int               `json:"schema_version"`
	ApplicationID string            `json:"application_id"`
	Mode          string            `json:"mode"` // OFF | OBSERVE | PROTECT
	Version       int               `json:"version"`
	Selectors     []jwtSelectorJSON `json:"selectors"`
	Issuers       []jwtIssuerJSON   `json:"issuers"`
}

type jwtSelectorJSON struct {
	Methods       []string `json:"methods"`
	PathExact     string   `json:"path_exact,omitempty"`
	PathPrefix    string   `json:"path_prefix,omitempty"`
	TokenRequired bool     `json:"token_required"`
}

// jwtTokenBindingJSON 发行方级令牌持有证明绑定配置（9A-1 冻结契约，与 server/web 同形）。
type jwtTokenBindingJSON struct {
	Mode               string   `json:"mode,omitempty"`                  // NONE|DPOP_OPTIONAL|DPOP_REQUIRED|MTLS_REQUIRED|DPOP_OR_MTLS
	RequireNonce       bool     `json:"require_nonce,omitempty"`
	MaxProofAgeSeconds int      `json:"max_proof_age_seconds,omitempty"` // default 60, range 5..120
	NonceTTLSeconds    int      `json:"nonce_ttl_seconds,omitempty"`     // default 60, range 10..300
	AllowedDPoPAlgs    []string `json:"allowed_dpop_algs,omitempty"`     // subset of ES256|RS256|EdDSA
}

type jwtIssuerJSON struct {
	IssuerConfigID   string               `json:"issuer_config_id"`
	Issuer           string               `json:"issuer"`
	Audiences        []string             `json:"audiences"`
	Algorithms       []string             `json:"algorithms"`
	ClockSkewSeconds int                  `json:"clock_skew_seconds"`
	TenantClaim      string               `json:"tenant_claim,omitempty"`
	RoleClaims       []string             `json:"role_claims,omitempty"`
	KeySourceType    string               `json:"key_source_type"` // STATIC_JWKS | REMOTE_JWKS
	JWKS             json.RawMessage      `json:"jwks,omitempty"`  // STATIC_JWKS：公钥集（公钥非秘密）
	RemoteURL        string               `json:"remote_url,omitempty"`
	KeysetVersion    string               `json:"keyset_version,omitempty"` // 溯源标识；运行期版本由验证器按密钥材料派生
	TokenBinding     *jwtTokenBindingJSON `json:"token_binding,omitempty"`  // 9A-1：DPoP/mTLS 持有证明绑定（需 schema_version=2）
}

// parseJWTTrustSection 严格解码 jwt_trust 段并校验结构版本与强制语义。
// 任何不理解的内容都拒绝加载（fail-closed），绝不静默忽略。
func parseJWTTrustSection(raw json.RawMessage) (*jwtTrustJSON, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// 显式例外：guard 其他段容忍未知字段（前向兼容），jwt_trust 不行——
	// 未知字段可能携带本网关不理解的强制语义（任务书 JWT-14）
	dec.DisallowUnknownFields()
	var sec jwtTrustJSON
	if err := dec.Decode(&sec); err != nil {
		return nil, fmt.Errorf("jwt_trust: 配置结构解析失败（拒绝加载）: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("jwt_trust: 配置含多余内容（拒绝加载）")
	}
	if sec.SchemaVersion != jwtTrustSchemaVersion && sec.SchemaVersion != jwtTrustSchemaVersionV2 {
		return nil, fmt.Errorf("jwt_trust: 不支持的 schema_version %d（本网关支持 %d/%d；拒绝加载而非忽略强制语义）",
			sec.SchemaVersion, jwtTrustSchemaVersion, jwtTrustSchemaVersionV2)
	}
	if sec.SchemaVersion == jwtTrustSchemaVersion {
		for _, is := range sec.Issuers {
			if is.TokenBinding != nil {
				return nil, fmt.Errorf("jwt_trust: schema_version=%d 不允许携带 token_binding（须升级为 schema_version=%d；拒绝加载）",
					jwtTrustSchemaVersion, jwtTrustSchemaVersionV2)
			}
		}
	}
	switch jwtverify.Mode(sec.Mode) {
	case jwtverify.ModeOff, jwtverify.ModeObserve, jwtverify.ModeProtect:
	default:
		return nil, fmt.Errorf("jwt_trust: 未知强制语义 mode=%q（拒绝加载）", sec.Mode)
	}
	return &sec, nil
}

// assembleJWTTrust 装配 JWT 信任链验证器（Provision 调用）。
// 段缺失/Mode=OFF 时不装配（零行为变化——发布通道对 OFF 也下发以覆盖旧配置残留，
// 不建验证器即等价关闭校验）；装配失败拒绝整体配置加载（fail-closed，
// 已存在 PROTECT 策略不得被静默删除或降级）。
func (g *Guard) assembleJWTTrust() error {
	if len(g.JWTTrust) == 0 {
		return nil
	}
	sec, err := parseJWTTrustSection(g.JWTTrust)
	if err != nil {
		return err
	}
	if jwtverify.Mode(sec.Mode) == jwtverify.ModeOff {
		return nil
	}
	v, err := g.buildJWTVerifier(sec)
	if err != nil {
		return err
	}
	g.jwtVerifier = v
	if g.logger != nil {
		g.logger.Info("jwt trust policy loaded",
			zap.String("app_id", sec.ApplicationID),
			zap.String("mode", sec.Mode),
			zap.String("policy_version", strconv.Itoa(sec.Version)),
			zap.Int("selectors", len(sec.Selectors)),
			zap.Int("issuers", len(sec.Issuers)),
			zap.Bool("identity_secret", g.IdentitySalt != ""))
	}
	return nil
}

// buildJWTVerifier 把下发段转换为 jwtverify.Policy 并构造纯本地验证器。
// 策略校验/静态 JWKS 解析/密钥门禁全部由 jwtverify.NewVerifier 完成，
// 任一失败即整体构造失败（配置加载期 fail-closed）。
func (g *Guard) buildJWTVerifier(sec *jwtTrustJSON) (*jwtverify.Verifier, error) {
	pol := jwtverify.Policy{
		ApplicationID: sec.ApplicationID,
		Version:       strconv.Itoa(sec.Version),
		Mode:          jwtverify.Mode(sec.Mode),
	}
	for _, s := range sec.Selectors {
		pol.Selectors = append(pol.Selectors, jwtverify.Selector{
			Methods:       s.Methods,
			PathExact:     s.PathExact,
			PathPrefix:    s.PathPrefix,
			TokenRequired: s.TokenRequired,
		})
	}
	hasRemote := false
	for _, is := range sec.Issuers {
		ic := jwtverify.IssuerConfig{
			ID:               is.IssuerConfigID,
			Issuer:           is.Issuer,
			Audiences:        is.Audiences,
			ClockSkewSeconds: is.ClockSkewSeconds,
			TenantClaim:      is.TenantClaim,
			RoleClaims:       append([]string(nil), is.RoleClaims...),
			KeySource:        jwtverify.KeySource(is.KeySourceType), // 未知取值由 Validate 拒绝
		}
		for _, a := range is.Algorithms {
			ic.Algorithms = append(ic.Algorithms, jwtverify.Algorithm(a))
		}
		switch ic.KeySource {
		case jwtverify.KeySourceStaticJWKS:
			ic.StaticJWKS = append([]byte(nil), is.JWKS...)
		case jwtverify.KeySourceRemoteJWKS:
			ic.RemoteURL = is.RemoteURL
			hasRemote = true
		}
		if is.TokenBinding != nil {
			ic.TokenBinding = &jwtverify.TokenBindingConfig{
				Mode:               jwtverify.TokenBindingMode(is.TokenBinding.Mode),
				RequireNonce:       is.TokenBinding.RequireNonce,
				MaxProofAgeSeconds: is.TokenBinding.MaxProofAgeSeconds,
				NonceTTLSeconds:    is.TokenBinding.NonceTTLSeconds,
				AllowedDPoPAlgs:    append([]string(nil), is.TokenBinding.AllowedDPoPAlgs...),
			}
		}
		pol.Issuers = append(pol.Issuers, ic)
	}
	fetcher := g.jwtFetcher // 测试注入钩子；生产为 nil → 默认受限获取器
	if fetcher == nil && hasRemote {
		fetcher = jwtverify.NewFetcher(jwtverify.FetcherConfig{})
	}
	var dpopReplay jwtverify.DPoPReplayStore
	if g.engine != nil && g.engine.valkey != nil {
		dpopReplay = jwtverify.NewValkeyDPoPReplayStore(g.engine.valkey)
	}
	cfg := jwtverify.VerifierConfig{
		Policy: pol,
		// 身份指纹密钥复用发布通道 identity_salt（jwtverify 指纹域分隔，
		// 与 identitybehavior 身份键不混用）：空密钥 OBSERVE 可运行但不产
		// 可信主体；PROTECT 由 NewVerifier 返回 ErrIdentitySecretRequired（fail-closed）
		IdentitySecret: []byte(g.IdentitySalt),
		Fetcher:        fetcher,
		DPoPReplay:     dpopReplay,
	}
	if g.logger != nil {
		cfg.OnRefreshError = func(issuerID string, err error) {
			g.logger.Warn("jwt_trust: 远程 JWKS 刷新失败（沿用信任期内缓存/不可用按 UNAVAILABLE 处理）",
				zap.String("issuer_config_id", issuerID), zap.Error(err))
		}
	}
	v, err := jwtverify.NewVerifier(cfg)
	if err != nil {
		return nil, fmt.Errorf("jwt_trust: %w", err)
	}
	return v, nil
}

// jwtResultKey 请求上下文中的 JWT 验证结果键（serveGuard 验证点写入，
// serveNext 处置点与事件输出消费）。
type jwtResultKey struct{}

// jwtResultFrom 取请求上下文中的 JWT 验证结果（未验证/未装配为 ok=false）。
func jwtResultFrom(ctx context.Context) (jwtverify.VerificationResult, bool) {
	v, ok := ctx.Value(jwtResultKey{}).(jwtverify.VerificationResult)
	return v, ok
}

// verifyJWTTrust serveGuard 挂点：真实 IP 处理后、身份观测前执行一次本地验证
// （仅计算，结果入请求上下文供身份观测与 API 管线处置点消费；VERIFIED 时
// 把可信主体/tenant 作为独立可信信号注入身份观测上下文——不改 identity_key/
// identity_type 语义）。纯本地、热路径零网络 IO；Verifier.Verify 内部 recover，
// 任何异常落成 UNAVAILABLE/VERIFIER_ERROR，绝不 panic 到请求链。
func (g *Guard) verifyJWTTrust(r *http.Request) {
	scheme := "http"
	var peerCertDER []byte
	if r.TLS != nil {
		scheme = "https"
		// 安全底线：仅在 TLS 握手客户端证书链已通过 CA 验证后才透传叶证书 DER，
		// 绝不信任未经校验的 PeerCertificates（防自签名证书伪造 mTLS 绑定）。
		if len(r.TLS.VerifiedChains) > 0 && len(r.TLS.PeerCertificates) > 0 && r.TLS.PeerCertificates[0] != nil {
			peerCertDER = r.TLS.PeerCertificates[0].Raw
		}
	}
	res := g.jwtVerifier.VerifyRequest(jwtverify.RequestVerifyInput{
		AuthValues:  r.Header.Values("Authorization"),
		Method:      r.Method,
		Path:        normalizer.CanonicalPath(r.URL.Path),
		RawPath:     r.URL.Path,
		Scheme:      scheme,
		Host:        r.Host,
		DPoPHeaders: r.Header.Values("DPoP"),
		PeerCertDER: peerCertDER,
	})
	*r = *r.WithContext(context.WithValue(r.Context(), jwtResultKey{}, res))
	// P0-04：身份验证状态/主体指纹写入处置上下文（指纹为 HMAC 值，不落明文 sub）
	DispositionFrom(r.Context()).SetIdentityVerification(string(res.Status), res.VerifiedPrincipalID)
	if res.Status == jwtverify.StatusVerified {
		*r = *r.WithContext(identitybehavior.WithVerifiedIdentity(r.Context(), &identitybehavior.VerifiedIdentity{
			PrincipalID:    res.VerifiedPrincipalID,
			TenantID:       res.VerifiedTenantID,
			IssuerConfigID: res.IssuerConfigID,
			PolicyVersion:  res.PolicyVersion,
		}))
	}
}

// enforceJWTTrust serveNext 挂点：JWT 强制处置在 API 动态管线阶段执行——
// 所有放行出口（保护地址旁路/白名单/L7 allow/常规链路）统一经 serveNext，
// 白名单与 L7 allow 不绕过 JWT PROTECT（安全底线）；人工封禁/黑白名单/L7/
// 自动封禁/风险/配额/CC 既有顺序不变（均在 serveNext 之前完成）。
// 处置表（任务书 §7）：OFF/范围外/NOT_PRESENT/VERIFIED 原样继续（VERIFIED
// 不产生全局放行）；INVALID/缺必需 Bearer：OBSERVE 记录放行 / PROTECT 401；
// UNAVAILABLE：OBSERVE 记录放行 / PROTECT 503（不伪装成 Token 错误）。
// 返回 handled=true 表示已响应（401/503），err 恒为 nil（直接写响应，不经
// caddyhttp.Error——401 需携带规范 Bearer challenge）。
func (g *Guard) enforceJWTTrust(w http.ResponseWriter, r *http.Request) (bool, error) {
	if g.jwtVerifier == nil {
		return false, nil
	}
	res, ok := jwtResultFrom(r.Context())
	if !ok {
		return false, nil
	}
	switch res.Status {
	case jwtverify.StatusUnverified, jwtverify.StatusNotPresent, jwtverify.StatusVerified:
		// OFF/范围外、范围内可选未携带、验证通过：原行为，继续后续检测
		return false, nil
	}
	// INVALID / UNAVAILABLE：OBSERVE 记录放行；PROTECT 实断
	ev := g.jwtEventBase(r, res)
	dispo := DispositionFrom(r.Context())
	if res.EnforceAction != jwtverify.EnforceEnforce {
		// OBSERVE 记录放行（P0-04：观察命中进 steps，不进 security_action）
		dispo.RecordStep(ExecutorJWT, StepObserved,
			fmt.Sprintf("status=%s reason=%s", res.Status, res.ReasonCode))
		g.emit(ev, events.JWTObserved, "OBSERVE", 0)
		return false, nil
	}
	if res.Status == jwtverify.StatusUnavailable {
		g.writeJWTUnavailable(w, ev.RequestID)
		dispo.RecordTerminal(ExecutorJWT, DisActionBlock, http.StatusServiceUnavailable, true,
			[]string{"JWT_UNAVAILABLE"}, nil)
		ev.FinalDecision = dispo.JSON()
		g.emit(ev, events.JWTUnavailable, "REJECT", http.StatusServiceUnavailable)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return true, nil
	}
	g.writeJWTAuthFailed(w, ev.RequestID, res)
	dispo.RecordTerminal(ExecutorJWT, DisActionBlock, http.StatusUnauthorized, true,
		[]string{"JWT_AUTH_FAILED"}, nil)
	ev.FinalDecision = dispo.JSON()
	g.emit(ev, events.JWTAuthFailed, "REJECT", http.StatusUnauthorized)
	accessLogAnnotate(r.Context(), wafActionBlock)
	return true, nil
}

// jwtEventBase 构造 JWT 事件公共字段（真实 IP 识别结果由 serveGuard 先于
// 验证点写入请求上下文，此处直接复用；验证摘要嵌套 jwt_verification 对象）。
func (g *Guard) jwtEventBase(r *http.Request, res jwtverify.VerificationResult) events.Event {
	ev := events.Event{
		RequestID:     r.Header.Get("X-Request-Id"),
		OccurredAt:    time.Now().UTC(),
		ApplicationID: g.AppID,
		AppCode:       g.AppCode,
		Domain:        r.Host,
		Method:        r.Method,
		Path:          r.URL.RequestURI(),
		Proto:         r.Proto,
		GatewayNode:   g.GatewayNode,
		JWT:           g.jwtEventDetail(res),
	}
	if cres, ok := clientIPResultFrom(r.Context()); ok {
		ev.ClientIP = cres.ClientIP.String()
		ev.ConnectionIP = cres.ConnectionIP.String()
		// 阶段5 §6.5 三字段（与 eventBase 同口径）
		ev.ClientIPSource = string(cres.Source)
		ev.TrustedProxyUsed = cres.TrustedProxyUsed
		ev.ForwardedChainSummary = cres.ChainSummary
	}
	return ev
}

// jwtEventDetail 验证结果 → 事件 jwt_verification 对象（数据最小化：
// 不落原始 Token/payload/明文 sub；tenant 以 identity_salt 加盐指纹上报，
// 域分隔前缀区别于身份键指纹）。
func (g *Guard) jwtEventDetail(res jwtverify.VerificationResult) *dsevents.JWTVerification {
	d := &dsevents.JWTVerification{
		Status:               string(res.Status),
		ReasonCode:           string(res.ReasonCode),
		PolicyVersion:        res.PolicyVersion,
		IssuerConfigID:       res.IssuerConfigID,
		KeysetVersion:        res.KeysetVersion,
		VerifiedPrincipalID:  res.VerifiedPrincipalID,
		TokenBindingVerified: res.TokenBindingVerified,
		EvaluatedAt:          res.EvaluatedAt,
	}
	if res.VerifiedTenantID != "" {
		d.VerifiedTenantID = detectors.Fingerprint(g.IdentitySalt, "jwt-tenant:"+res.VerifiedTenantID)
	}
	return d
}

// writeJWTAuthFailed PROTECT 认证失败响应：401 + 规范 Bearer/DPoP challenge +
// 统一简短文案，不回显签名/发行方内部原因（详细 reason_code 仅事件与管理面可见）。
func (g *Guard) writeJWTAuthFailed(w http.ResponseWriter, requestID string, res jwtverify.VerificationResult) {
	switch {
	case res.DPoPNonce != "":
		w.Header().Set("DPoP-Nonce", res.DPoPNonce)
		w.Header().Set("WWW-Authenticate", `DPoP realm="jiuzhang-waf", error="use_dpop_nonce"`)
	case jwtverify.IsDPoPReason(res.ReasonCode):
		w.Header().Set("WWW-Authenticate", `DPoP realm="jiuzhang-waf", error="invalid_dpop_proof"`)
	case res.TokenScheme == "DPoP":
		w.Header().Set("WWW-Authenticate", `DPoP realm="jiuzhang-waf", error="invalid_token"`)
	default:
		w.Header().Set("WWW-Authenticate", `Bearer realm="jiuzhang-waf"`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Jiuzhang-Request-ID", requestID)
	w.WriteHeader(http.StatusUnauthorized)
	body, _ := json.Marshal(map[string]string{
		"error":      "authentication_failed",
		"message":    "认证失败",
		"request_id": requestID,
	})
	if _, err := w.Write(body); err != nil && g.logger != nil {
		g.logger.Warn("jwt auth failed response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}

// writeJWTUnavailable PROTECT 验证不可用响应：503 + 简短文案（不伪装成 Token
// 错误、不带 Bearer challenge，避免诱导用户反复登录）。
func (g *Guard) writeJWTUnavailable(w http.ResponseWriter, requestID string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Jiuzhang-Request-ID", requestID)
	w.WriteHeader(http.StatusServiceUnavailable)
	body, _ := json.Marshal(map[string]string{
		"error":      "authentication_unavailable",
		"message":    "认证服务暂不可用，请稍后重试",
		"request_id": requestID,
	})
	if _, err := w.Write(body); err != nil {
		g.logger.Warn("jwt unavailable response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}
