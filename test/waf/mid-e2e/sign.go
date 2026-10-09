// sign.go HTTP Message Signatures（RFC 9421）签名构造（NG-ID G1 批次 C 参照
// 客户端）：Go stdlib crypto 三算法签名器（ed25519 / ecdsa-p256-sha256（R||S 64
// 字节拼接）/ rsa-pss-sha512（盐长 64=哈希长））+ 签名基线重构（与网关
// gateway/dynamic_security/httpsig verify.go 同一 RFC 文本——成分取值口径：
// @method 原文、@authority=Host 原文、@path raw 不归一、@query="?"+原文、
// content-digest 头原文、authorization 头原文（权限关键头存在必覆盖，
// §1.4 步 6 纪律））。
//
// 密钥持久化：私钥 PKCS8 PEM（<kid>.key.pem，0600）+ 公钥 PKIX PEM
// （<kid>.pub.pem——管理面静态离线导入形态）+ manifest.json（kid→alg）。
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// 算法词表（与网关 httpsig 冻结词表逐字一致；hmac-sha256 共享密钥形态排除、
// rsa-v1_5-sha256 排除（RFC 9421 标注不推荐））。AlgJWT 为 JWT 铸造专用
// （RS256——jwt_trust  issuer 静态 JWKS 对测用，不进入机器身份签名面）。
const (
	AlgEd25519 = "ed25519"
	AlgECDSA   = "ecdsa-p256-sha256"
	AlgRSAPSS  = "rsa-pss-sha512"
	AlgJWT     = "RS256"
)

// keySpec 密钥生成清单（keygen 固定集合——联调用例所需全部键）。
var keySpec = []struct {
	kid string
	alg string
}{
	{"k-ed", AlgEd25519},  // mid-svc-a 主键（I01 有效/I04 轮换旧键）
	{"k-ec", AlgECDSA},    // mid-svc-a（I01 有效）
	{"k-rsa", AlgRSAPSS},  // mid-svc-a（I01 有效/I04 撤销）
	{"k-ed2", AlgEd25519}, // mid-svc-a 轮换新键（I04）
	{"k-b", AlgEd25519},   // mid-svc-b（I02 他身份）
	{"k-dis", AlgEd25519}, // mid-svc-off（DISABLED 身份，I02）
	{"k-p", AlgEd25519},   // mid-svc-p（principal_binding 组合，I02）
	{"k-bot", AlgEd25519}, // mid-bot（I05 未豁免）
	{"k-bx", AlgEd25519},  // mid-bot-exempt（I05 豁免）
	{"jwt-k1", AlgJWT},    // JWT 铸造（I02 principal_binding 组合）
}

// midKey 签名密钥（kid+alg+私钥）。
type midKey struct {
	kid  string
	alg  string
	priv crypto.Signer
}

// keygen 生成固定集合全部密钥并写目录（幂等：已存在则跳过——重跑保持
// 登记公钥稳定，避免重复导入 409）。
func keygen(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	manifest := map[string]string{}
	for _, ks := range keySpec {
		manifest[ks.kid] = ks.alg
		privPath := filepath.Join(dir, ks.kid+".key.pem")
		if _, err := os.Stat(privPath); err == nil {
			continue // 幂等
		}
		priv, err := generatePriv(ks.alg)
		if err != nil {
			return fmt.Errorf("keygen %s: %w", ks.kid, err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return err
		}
		if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return err
		}
		pub, err := publicOf(priv)
		if err != nil {
			return err
		}
		pder, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, ks.kid+".pub.pem"),
			pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pder}), 0o644); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644)
}

func generatePriv(alg string) (crypto.Signer, error) {
	switch alg {
	case AlgEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	case AlgECDSA:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgRSAPSS, AlgJWT:
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	return nil, fmt.Errorf("未知算法 %q", alg)
}

func publicOf(priv crypto.Signer) (any, error) {
	switch k := priv.(type) {
	case ed25519.PrivateKey:
		return k.Public(), nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	}
	return nil, fmt.Errorf("未知键型 %T", priv)
}

// loadKey 读取私钥与算法（manifest 优先；缺 manifest 按 kid 推断失败即错）。
func loadKey(dir, kid string) (*midKey, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var manifest map[string]string
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	alg, ok := manifest[kid]
	if !ok {
		return nil, fmt.Errorf("manifest 无 kid %q（先 keygen）", kid)
	}
	pemRaw, err := os.ReadFile(filepath.Join(dir, kid+".key.pem"))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(pemRaw)
	if blk == nil {
		return nil, fmt.Errorf("私钥 PEM 解析失败 %s", kid)
	}
	privAny, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := privAny.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("私钥不可签名 %s", kid)
	}
	return &midKey{kid: kid, alg: alg, priv: priv}, nil
}

// pubPEM 读公钥 PEM（管理面导入用）。
func pubPEM(dir, kid string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, kid+".pub.pem"))
	return strings.TrimSpace(string(raw)), err
}

// sign 密码学签名（三算法 + RS256 铸造通道）：
//   - ed25519：纯签名（消息=基线原文）；
//   - ecdsa-p256-sha256：sha256 预哈希，签名值=R||S 各 32 字节大端拼接（非 ASN.1——
//     RFC 9421 §3.3.3 与网关 verify.go 同形）；
//   - rsa-pss-sha512：sha512 预哈希，PSS 盐长 64=哈希长（网关 VerifyPSS 同参）；
//   - RS256（仅 JWT 铸造）：PKCS1v15+sha256。
func (k *midKey) sign(base []byte) ([]byte, error) {
	switch k.alg {
	case AlgEd25519:
		return ed25519.Sign(k.priv.(ed25519.PrivateKey), base), nil
	case AlgECDSA:
		sum := sha256.Sum256(base)
		r, s, err := ecdsa.Sign(rand.Reader, k.priv.(*ecdsa.PrivateKey), sum[:])
		if err != nil {
			return nil, err
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out, nil
	case AlgRSAPSS:
		sum := sha512.Sum512(base)
		return rsa.SignPSS(rand.Reader, k.priv.(*rsa.PrivateKey), crypto.SHA512, sum[:], &rsa.PSSOptions{SaltLength: 64})
	case AlgJWT:
		sum := sha256.Sum256(base)
		return rsa.SignPKCS1v15(rand.Reader, k.priv.(*rsa.PrivateKey), crypto.SHA256, sum[:])
	}
	return nil, fmt.Errorf("未知算法 %q", k.alg)
}

// ---------- 签名基线（RFC 9421 §2.5） ----------

// coveredComponents 默认覆盖成分序（§1.4 步 6 必含集 + 条件成分）：
// @method/@authority/@path 恒含；有 query 必含 @query；有 body 必含
// content-digest；有 Authorization（权限关键头）必含 authorization。
func coveredComponents(req *http.Request, hasBody bool, omit map[string]bool) []string {
	out := []string{"@method", "@authority", "@path"}
	if req.URL.RawQuery != "" {
		out = append(out, "@query")
	}
	if hasBody {
		out = append(out, "content-digest")
	}
	if req.Header.Get("Authorization") != "" {
		out = append(out, "authorization")
	}
	if len(omit) > 0 {
		kept := out[:0]
		for _, c := range out {
			if !omit[c] {
				kept = append(kept, c)
			}
		}
		out = kept
	}
	return out
}

// componentValue 成分取值（与网关 deriveComponentValue 同一规范化口径——
// @authority=Host 原文、@path=EscapedPath 原文不归一、@query="?"+RawQuery 原文）。
func componentValue(req *http.Request, name string) (string, error) {
	switch name {
	case "@method":
		return req.Method, nil
	case "@authority":
		return req.Host, nil
	case "@path":
		return req.URL.EscapedPath(), nil
	case "@query":
		return "?" + req.URL.RawQuery, nil
	}
	if strings.HasPrefix(name, "@") {
		return "", fmt.Errorf("不支持的派生成分 %q", name)
	}
	vals := req.Header.Values(name)
	if len(vals) == 0 {
		return "", fmt.Errorf("覆盖头 %q 缺席", name)
	}
	return strings.Join(vals, ", "), nil
}

// buildSignatureBase 签名基线重构（逐行 "name": value，末行 "@signature-params"——
// 与网关 BuildSignatureBase 同一 RFC 文本；参数串与头发送串同串两用）。
func buildSignatureBase(req *http.Request, components []string, paramsStr string) ([]byte, error) {
	var sb strings.Builder
	for _, c := range components {
		v, err := componentValue(req, c)
		if err != nil {
			return nil, err
		}
		sb.WriteString(sfQuote(c))
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\n")
	}
	sb.WriteString(sfQuote("@signature-params"))
	sb.WriteString(": ")
	sb.WriteString(sfInnerList(components))
	sb.WriteString(paramsStr)
	return []byte(sb.String()), nil
}

// signOptions 签名构造选项（变体用例承载）。
type signOptions struct {
	unsigned bool            // 不携带签名头（proof_required 准入用例）
	nonce    string          // 固定 nonce（重放用例；空=随机 24 字节 base64url）
	created  int64           // 指定 created（时效变体；0=now）
	expires  int64           // 指定 expires（0=created+60）
	lifetime int64           // expires=created+lifetime（寿命超限用例；0 默认 60）
	kidClaim string          // keyid 参数覆盖（未登记 keyid 用例）
	algClaim string          // alg 参数覆盖（算法词表外/与登记不符用例）
	signWith string          // 用其他私钥签（签名无效用例；kid 参数不变）
	omit     map[string]bool // 省略覆盖成分（覆盖不足用例）
	rawInput string          // Signature-Input 全自定义（畸形/多标签用例）
	rawSig   string          // Signature 全自定义
	label    string          // 签名标签（默认 sig1——接入契约冻结）
}

// signRequest 对请求签名（设置 Content-Digest（有体时）/Signature-Input/Signature
// 三头）。体须已固定在 req（GetBody 可读）；created/expires 默认 now/now+60。
func signRequest(req *http.Request, body []byte, key *midKey, dir string, o signOptions) error {
	if o.unsigned {
		return nil
	}
	if o.rawInput != "" || o.rawSig != "" {
		req.Header.Set("Signature-Input", o.rawInput)
		req.Header.Set("Signature", o.rawSig)
		return nil
	}
	// Content-Digest（RFC 9530 sha-256——接入契约优先算法）
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		req.Header.Set("Content-Digest", "sha-256="+sfBytes(sum[:]))
	}
	created := o.created
	if created == 0 {
		created = nowUnix()
	}
	lifetime := o.lifetime
	if lifetime == 0 {
		lifetime = 60 // 窗口 ≤120s（接入契约冻结）
	}
	expires := o.expires
	if expires == 0 {
		expires = created + lifetime
	}
	nonce := o.nonce
	if nonce == "" {
		nonce = randomNonce()
	}
	kid := key.kid
	if o.kidClaim != "" {
		kid = o.kidClaim
	}
	alg := key.alg
	if o.algClaim != "" {
		alg = o.algClaim
	}
	label := o.label
	if label == "" {
		label = "sig1"
	}
	components := coveredComponents(req, len(body) > 0, o.omit)
	paramsStr := sfSigParams(created, expires, nonce, kid, alg)
	base, err := buildSignatureBase(req, components, paramsStr)
	if err != nil {
		return err
	}
	signer := key
	if o.signWith != "" {
		signer, err = loadKey(dir, o.signWith)
		if err != nil {
			return err
		}
	}
	sig, err := signer.sign(base)
	if err != nil {
		return err
	}
	req.Header.Set("Signature-Input", label+"="+sfInnerList(components)+paramsStr)
	req.Header.Set("Signature", label+"="+sfBytes(sig))
	return nil
}
