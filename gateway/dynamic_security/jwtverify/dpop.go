// dpop.go OAuth 2.0 DPoP（Demonstrating Proof-of-Possession, RFC 9449）纯本地验证与
// Valkey 原子防重放存储（Phase 9A-1）。
//
// 安全纪律：
//   - 热路径零外部网络 IO（仅 Valkey 单次原子 SET NX PX 防重放）；
//   - 严格 JSON 解析（拒绝重复键、拒绝 crit、拒绝 alg=none/HS*、拒绝 jwk 夹带私钥参数）；
//   - 所有密码学摘要/指纹比较均使用 subtle.ConstantTimeCompare；
//   - 防重放存储缺失或故障时返回 StatusUnavailable/ReasonDPoPReplayUnavailable，
//     绝不伪装为无效 Token，严禁回退进程本地内存去重冒充分布式防重放。
package jwtverify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// ReplayEvaluator Valkey 最小 Lua Eval 接口（counters.ValkeyClient.Eval 结构化满足）。
type ReplayEvaluator interface {
	Eval(ctx context.Context, script string, keys []string, args []string) ([]interface{}, error)
}

// DPoPReplayStore DPoP Proof jti 原子防重放存储接口。
type DPoPReplayStore interface {
	CheckAndSet(ctx context.Context, jkt, jtiDigestHex32 string, ttl time.Duration) (isReplay bool, err error)
}

const (
	dpopReplayKeyPrefix = "jwt:v1:dpop:"
	dpopReplayOpTimeout = 300 * time.Millisecond
)

// dpopReplaySetNXLua 单次原子往返 SET NX PX（数组返回 {1}=首次登记，{0}=重放）。
const dpopReplaySetNXLua = `
return {redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', tonumber(ARGV[2])) and 1 or 0}
`

var (
	errDPoPStoreUnconfigured = errors.New("jwtverify: dpop replay store unconfigured")
	errDPoPReplayProtocol    = errors.New("jwtverify: dpop replay eval protocol error")
)

// ValkeyDPoPReplayStore 基于 Valkey Lua 的分布式原子防重放存储。
type ValkeyDPoPReplayStore struct {
	cli ReplayEvaluator
}

// NewValkeyDPoPReplayStore 创建基于 Valkey 的 DPoP 防重放存储（cli 允许 nil，
// 运行期返回 errDPoPStoreUnconfigured → UNAVAILABLE，严禁本机去重兜底）。
func NewValkeyDPoPReplayStore(cli ReplayEvaluator) *ValkeyDPoPReplayStore {
	return &ValkeyDPoPReplayStore{cli: cli}
}

// CheckAndSet 原子登记 (jkt, jtiDigest)；首次返回 (false, nil)，重复返回 (true, nil)，
// 存储未配置或异常透传错误（上层映射为 UNAVAILABLE）。
func (s *ValkeyDPoPReplayStore) CheckAndSet(_ context.Context, jkt, jtiDigestHex32 string, ttl time.Duration) (bool, error) {
	if s == nil || s.cli == nil {
		return false, errDPoPStoreUnconfigured
	}
	if ttl < time.Second {
		ttl = time.Second
	}
	key := dpopReplayKeyPrefix + "{" + sha256Hex16([]byte(jkt)) + "}:" + jtiDigestHex32
	opCtx, cancel := context.WithTimeout(context.Background(), dpopReplayOpTimeout)
	defer cancel()
	out, err := s.cli.Eval(opCtx, dpopReplaySetNXLua, []string{key}, []string{"1", strconv.FormatInt(ttl.Milliseconds(), 10)})
	if err != nil {
		return false, err
	}
	if len(out) != 1 {
		return false, errDPoPReplayProtocol
	}
	switch v := out[0].(type) {
	case int64:
		return v == 0, nil
	case string:
		if v == "1" {
			return false, nil
		}
		if v == "0" {
			return true, nil
		}
		return false, errDPoPReplayProtocol
	default:
		return false, errDPoPReplayProtocol
	}
}

// cnfClaim JWT 确认声明（RFC 7800 / RFC 9449 / RFC 8705）。
type cnfClaim struct {
	JKT     string
	X5TS256 string
}

// parseCnfClaim 从已验签的 JWT claims 提取 cnf.jkt 与 cnf["x5t#S256"]。
// cnf 缺失返回零值；格式非法返回错误。
func parseCnfClaim(raw map[string]json.RawMessage) (cnfClaim, error) {
	v, ok := raw["cnf"]
	if !ok {
		return cnfClaim{}, nil
	}
	obj, err := strictJSONObject(v)
	if err != nil {
		return cnfClaim{}, err
	}
	var out cnfClaim
	if jktRaw, ok := obj["jkt"]; ok {
		var s string
		if err := json.Unmarshal(jktRaw, &s); err != nil {
			return cnfClaim{}, errors.New("cnf.jkt 类型非法")
		}
		out.JKT = strings.TrimSpace(s)
	}
	if x5tRaw, ok := obj["x5t#S256"]; ok {
		var s string
		if err := json.Unmarshal(x5tRaw, &s); err != nil {
			return cnfClaim{}, errors.New("cnf.x5t#S256 类型非法")
		}
		out.X5TS256 = strings.TrimSpace(s)
	}
	return out, nil
}

// jwkPrivateParams RFC 7517/7518 私钥参数黑名单（DPoP Proof header.jwk 严禁夹带私钥）。
var jwkPrivateParams = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// verifyDPoPProof 执行完整 RFC 9449 DPoP Proof 校验。
// 返回 (status, reason, issuedNonce)；status == StatusVerified 表示通过。
func (v *Verifier) verifyDPoPProof(
	ir *issuerRuntime,
	accessToken string,
	cnfJKT string,
	in RequestVerifyInput,
) (Status, ReasonCode, string) {
	if len(in.DPoPHeaders) == 0 {
		return StatusInvalid, ReasonDPoPMissing, ""
	}
	if len(in.DPoPHeaders) > 1 {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	proofRaw := strings.TrimSpace(in.DPoPHeaders[0])
	if proofRaw == "" {
		return StatusInvalid, ReasonDPoPMissing, ""
	}
	if len(proofRaw) > MaxTokenBytes {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	if strings.ContainsAny(proofRaw, ", \t\r\n") || strings.IndexFunc(proofRaw, func(r rune) bool {
		return !strings.ContainsRune(tokenCharset, r)
	}) >= 0 {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	parts := strings.Split(proofRaw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	headerRaw, err := decodeSegment(parts[0])
	if err != nil {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	if _, err := decodeSegment(parts[1]); err != nil {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	header, err := strictJSONObject(headerRaw)
	if err != nil {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	if _, hasCrit := header["crit"]; hasCrit {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	typ, err := requiredString(header, "typ")
	if err != nil || !strings.EqualFold(typ, "dpop+jwt") {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	alg, err := requiredString(header, "alg")
	if err != nil {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	if _, allowed := ir.dpopAlgs[alg]; !allowed {
		return StatusInvalid, ReasonDPoPAlgRejected, ""
	}

	jwkRaw, ok := header["jwk"]
	if !ok {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	jwkObj, err := strictJSONObject(jwkRaw)
	if err != nil {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	kty, err := requiredString(jwkObj, "kty")
	if err != nil || strings.EqualFold(kty, "oct") {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	for _, priv := range jwkPrivateParams {
		if _, found := jwkObj[priv]; found {
			return StatusInvalid, ReasonDPoPMalformed, ""
		}
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(jwkRaw, &jwk); err != nil || !jwk.Valid() || !jwk.IsPublic() {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	if jwk.Use != "" && jwk.Use != "sig" {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	if jwk.Algorithm != "" && jwk.Algorithm != alg {
		return StatusInvalid, ReasonDPoPAlgRejected, ""
	}
	if !dpopKeyMatchesAlg(jwk.Key, alg) {
		return StatusInvalid, ReasonDPoPAlgRejected, ""
	}

	jws, err := jose.ParseSigned(proofRaw, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(alg)})
	if err != nil || len(jws.Signatures) != 1 {
		return StatusInvalid, ReasonDPoPSigInvalid, ""
	}
	verifiedPayload, err := jws.Verify(jwk.Key)
	if err != nil {
		return StatusInvalid, ReasonDPoPSigInvalid, ""
	}

	// RFC 7638 JWK Thumbprint (SHA-256 base64url) 常量时间比对 cnf.jkt
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	gotJKT := base64.RawURLEncoding.EncodeToString(tp)
	if subtle.ConstantTimeCompare([]byte(gotJKT), []byte(cnfJKT)) != 1 {
		return StatusInvalid, ReasonDPoPJKTMismatch, ""
	}

	// 严格解析经签名校验后的 Proof Payload
	claims, err := strictJSONObject(verifiedPayload)
	if err != nil {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	jti, err := requiredString(claims, "jti")
	if err != nil || len(jti) > MaxDPoPJTIBenchBytes {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	htm, err := requiredString(claims, "htm")
	if err != nil {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	if !strings.EqualFold(htm, strings.TrimSpace(in.Method)) {
		return StatusInvalid, ReasonDPoPHTMMismatch, ""
	}
	htu, err := requiredString(claims, "htu")
	if err != nil {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	if !matchDPoPHTU(htu, in.Scheme, in.Host, in.RawPath, in.Path) {
		return StatusInvalid, ReasonDPoPHTUMismatch, ""
	}
	iatRaw, ok := claims["iat"]
	if !ok {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	iat, err := parseNumericDate(iatRaw)
	if err != nil {
		return StatusInvalid, ReasonDPoPMalformed, ""
	}
	tb := ir.cfg.TokenBinding
	leeway := time.Duration(ir.cfg.ClockSkewSeconds) * time.Second
	maxAge := time.Duration(tb.MaxProofAgeSeconds) * time.Second
	now := v.clock.Now()
	// 拒绝未来超 leeway 或已过期（now > iat + maxAge + leeway）
	if iat.After(now.Add(leeway)) || now.After(iat.Add(maxAge).Add(leeway)) {
		return StatusInvalid, ReasonDPoPExpired, ""
	}

	// ath（Access Token Hash, RFC 9449 §4.2）：资源服务器校验必填
	ath, err := requiredString(claims, "ath")
	if err != nil {
		return StatusInvalid, ReasonDPoPATHMismatch, ""
	}
	tokenSum := sha256.Sum256([]byte(accessToken))
	wantATH := base64.RawURLEncoding.EncodeToString(tokenSum[:])
	if subtle.ConstantTimeCompare([]byte(ath), []byte(wantATH)) != 1 {
		return StatusInvalid, ReasonDPoPATHMismatch, ""
	}

	// 可选 DPoP-Nonce（防客户端预计算 Proof；无状态 HMAC 时间桶，接受当前与上一桶）
	if tb.RequireNonce {
		if len(v.secret) == 0 {
			return StatusUnavailable, ReasonVerifierError, ""
		}
		ttlSec := int64(tb.NonceTTLSeconds)
		if ttlSec <= 0 {
			ttlSec = DefaultDPoPNonceTTLSeconds
		}
		bucket := now.Unix() / ttlSec
		curNonce := computeDPoPNonce(v.secret, v.policy.ApplicationID, ir.cfg.ID, cnfJKT, bucket)
		prevNonce := computeDPoPNonce(v.secret, v.policy.ApplicationID, ir.cfg.ID, cnfJKT, bucket-1)
		gotNonce, err := requiredString(claims, "nonce")
		if err != nil ||
			(subtle.ConstantTimeCompare([]byte(gotNonce), []byte(curNonce)) != 1 &&
				subtle.ConstantTimeCompare([]byte(gotNonce), []byte(prevNonce)) != 1) {
			return StatusInvalid, ReasonDPoPNonceRequired, curNonce
		}
	}

	// 分布式原子防重放（(jkt, jti)）：存储缺失或异常映射为 UNAVAILABLE，严禁本机兜底
	if v.dpopReplay == nil {
		return StatusUnavailable, ReasonDPoPReplayUnavailable, ""
	}
	// iat 最多可超前 now+leeway，故有效窗口可达 maxAge+2*leeway；加 1s 缓冲确保
	// 重放键不会早于 Proof 过期边界失效。
	replayTTL := iat.Add(maxAge).Add(leeway).Sub(now) + time.Second
	if replayTTL < time.Second {
		replayTTL = time.Second
	}
	maxTTL := time.Duration(MaxDPoPMaxProofAgeSeconds+2*MaxClockSkewSeconds+1) * time.Second
	if replayTTL > maxTTL {
		replayTTL = maxTTL
	}
	jtiSum := sha256.Sum256([]byte(jti))
	isReplay, err := v.dpopReplay.CheckAndSet(context.Background(), cnfJKT, hex.EncodeToString(jtiSum[:16]), replayTTL)
	if err != nil {
		return StatusUnavailable, ReasonDPoPReplayUnavailable, ""
	}
	if isReplay {
		return StatusInvalid, ReasonDPoPReplay, ""
	}
	return StatusVerified, ReasonValid, ""
}

const maxDPoPRSAKeyBits = 8192

func dpopKeyMatchesAlg(key any, alg string) bool {
	switch alg {
	case DPoPAlgES256:
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || pub == nil || pub.Curve != elliptic.P256() {
			return false
		}
		_, err := pub.ECDH()
		return err == nil
	case DPoPAlgRS256:
		pub, ok := key.(*rsa.PublicKey)
		return ok && pub != nil && pub.N != nil && pub.N.BitLen() >= minRSAKeyBits && pub.N.BitLen() <= maxDPoPRSAKeyBits && pub.E >= 3
	case DPoPAlgEdDSA:
		pub, ok := key.(ed25519.PublicKey)
		return ok && len(pub) == ed25519.PublicKeySize
	default:
		return false
	}
}

// matchDPoPHTU 按 RFC 9449 §4.2/§4.3 比对 Proof htu 与请求目标 URI（去除 query/fragment，
// scheme 与 host 忽略大小写，规范化默认端口 :443/:80）。
func matchDPoPHTU(proofHTU, reqScheme, reqHost, rawPath, canonPath string) bool {
	if proofHTU == "" || strings.TrimSpace(proofHTU) != proofHTU || strings.ContainsAny(proofHTU, "?#") {
		return false
	}
	pu, err := url.Parse(proofHTU)
	if err != nil || pu.RawQuery != "" || pu.ForceQuery || pu.Fragment != "" || pu.User != nil || pu.Opaque != "" {
		return false
	}
	pScheme := strings.ToLower(pu.Scheme)
	if pScheme != "http" && pScheme != "https" {
		return false
	}
	rScheme := strings.ToLower(strings.TrimSpace(reqScheme))
	if rScheme == "" {
		rScheme = "https"
	}
	if pScheme != rScheme {
		return false
	}
	pHost := normalizeHostDefaultPort(pu.Host, pScheme)
	rHost := normalizeHostDefaultPort(strings.TrimSpace(reqHost), rScheme)
	if pHost == "" || rHost == "" || pHost != rHost {
		return false
	}
	pPath := pu.EscapedPath()
	if pPath == "" {
		pPath = "/"
	}
	rPath := rawPath
	if rPath == "" {
		rPath = canonPath
	}
	if rPath == "" {
		rPath = "/"
	}
	return pPath == rPath
}

func normalizeHostDefaultPort(host, scheme string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		// 无端口（或裸 IPv6），去掉可能包裹的方括号保持稳定形态
		return host
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		if strings.Contains(h, ":") {
			return "[" + h + "]"
		}
		return h
	}
	return net.JoinHostPort(h, port)
}

func computeDPoPNonce(secret []byte, appID, issuerID, jkt string, bucket int64) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("dpop-nonce:v1:"))
	_, _ = mac.Write([]byte(appID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(issuerID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(jkt))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(strconv.FormatInt(bucket, 10)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// IsDPoPReason 判断原因码是否属于 DPoP 协议类错误（用于 401 WWW-Authenticate: DPoP 响应头选择）。
func IsDPoPReason(r ReasonCode) bool {
	switch r {
	case ReasonDPoPMissing, ReasonDPoPMalformed, ReasonDPoPAlgRejected, ReasonDPoPSigInvalid,
		ReasonDPoPJKTMismatch, ReasonDPoPHTMMismatch, ReasonDPoPHTUMismatch, ReasonDPoPATHMismatch,
		ReasonDPoPExpired, ReasonDPoPReplay, ReasonDPoPNonceRequired, ReasonDPoPReplayUnavailable:
		return true
	default:
		return false
	}
}

// ComputeJWKThumbprintSHA256 辅助函数：计算公钥的 RFC 7638 SHA-256 base64url Thumbprint（测试与工具复用）。
func ComputeJWKThumbprintSHA256(pub any) (string, error) {
	jwk := jose.JSONWebKey{Key: pub}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("jwtverify: compute jwk thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}
