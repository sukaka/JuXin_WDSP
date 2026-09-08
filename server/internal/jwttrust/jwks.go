// jwks.go 静态 JWKS 公钥校验（纯 stdlib：encoding/json + base64url + crypto/rsa +
// crypto/elliptic，不引第三方 JOSE 库——服务端不验签，仅保证下发的密钥集只含合法公钥）。
// 校验规则（任务书 §5.2/§6）：仅 RSA（≥2048 位）/ EC P-256（ES256）；拒绝私钥参数
// （d/p/q/dp/dq/qi/oth）与对称密钥（kty=oct）；拒绝 x5u/jku（不从 Token/密钥自带
// 地址下载证书或密钥）；kid 非空且集内唯一；keys ≤ 32、整体 ≤ 256 KiB；拒绝重复 JSON 键。
package jwttrust

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/big"
	"sort"
	"strings"
)

// 私钥/对称参数（出现即拒绝）与自带 URL 参数（出现即拒绝，不下载）。
var (
	privateJWKParams = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
	urlJWKParams     = []string{"x5u", "jku"}
)

// JWKSummary 单个公钥的校验摘要（供管理面回显；仅公共字段）。
type JWKSummary struct {
	KID string `json:"kid"`
	Kty string `json:"kty"` // RSA | EC
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"` // EC 曲线（仅 P-256）
}

// keyMaterial 单个公钥的解析结果：校验摘要 + 规范化密钥材料（供 KeysetVersion
// 派生内容指纹；材料仅在本包内使用，不经 API 回显）。
type keyMaterial struct {
	sum  JWKSummary
	rsaN *big.Int
	rsaE int
	ecX  *big.Int
	ecY  *big.Int
}

// ValidateJWKS 校验静态 JWKS 文本（allowedAlgs 为该 issuer 的算法白名单，用于
// 交叉校验键 alg/kty 一致性；空集视为未声明）。返回每个公钥的摘要列表。
func ValidateJWKS(raw string, allowedAlgs map[string]bool) ([]JWKSummary, error) {
	keys, err := parseJWKSKeys(raw, allowedAlgs)
	if err != nil {
		return nil, err
	}
	out := make([]JWKSummary, 0, len(keys))
	for _, km := range keys {
		out = append(out, km.sum)
	}
	return out, nil
}

// parseJWKSKeys 校验静态 JWKS 文本并返回含密钥材料的解析结果（校验规则见文件头）。
func parseJWKSKeys(raw string, allowedAlgs map[string]bool) ([]keyMaterial, error) {
	data := []byte(strings.TrimSpace(raw))
	if len(data) == 0 {
		return nil, fmt.Errorf("JWKS 不能为空")
	}
	if len(data) > MaxJWKSBytes {
		return nil, fmt.Errorf("JWKS 超过 %d 字节上限", MaxJWKSBytes)
	}
	if err := checkDuplicateKeys(data); err != nil {
		return nil, err
	}
	var set struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("JWKS 不是合法 JSON: %v", err)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("JWKS keys 不能为空")
	}
	if len(set.Keys) > MaxJWKSKeys {
		return nil, fmt.Errorf("JWKS 公钥数量超过 %d 上限", MaxJWKSKeys)
	}
	out := make([]keyMaterial, 0, len(set.Keys))
	seenKID := map[string]bool{}
	for i, k := range set.Keys {
		km, err := parseJWK(k, allowedAlgs)
		if err != nil {
			return nil, fmt.Errorf("keys[%d]: %w", i, err)
		}
		if seenKID[km.sum.KID] {
			return nil, fmt.Errorf("keys[%d]: 重复 kid %q", i, km.sum.KID)
		}
		seenKID[km.sum.KID] = true
		out = append(out, km)
	}
	return out, nil
}

// parseJWK 校验并解析单个 JWK（map 形态保留原始字段以检测私钥参数）。
func parseJWK(k map[string]json.RawMessage, allowedAlgs map[string]bool) (keyMaterial, error) {
	var km keyMaterial
	str := func(name string) string {
		var s string
		if raw, ok := k[name]; ok {
			_ = json.Unmarshal(raw, &s)
		}
		return s
	}
	for _, p := range privateJWKParams {
		if _, ok := k[p]; ok {
			return km, fmt.Errorf("拒绝包含私钥/对称参数 %q 的密钥", p)
		}
	}
	for _, p := range urlJWKParams {
		if _, ok := k[p]; ok {
			return km, fmt.Errorf("拒绝自带密钥/证书地址参数 %q（不从外部地址拉取密钥）", p)
		}
	}
	km.sum.Kty = str("kty")
	km.sum.KID = str("kid")
	km.sum.Alg = str("alg")
	km.sum.Crv = str("crv")
	sum := km.sum
	if sum.KID == "" {
		return km, fmt.Errorf("kid 不能为空")
	}
	if len(sum.KID) > MaxKIDBytes {
		return km, fmt.Errorf("kid 超过 %d 字节上限", MaxKIDBytes)
	}
	if use := str("use"); use != "" && use != "sig" {
		return km, fmt.Errorf("use 仅允许 \"sig\"，实际 %q", use)
	}
	if sum.Alg != "" {
		if len(allowedAlgs) > 0 && !allowedAlgs[sum.Alg] {
			return km, fmt.Errorf("密钥 alg %q 不在 issuer 算法白名单内", sum.Alg)
		}
		if sum.Alg != AlgRS256 && sum.Alg != AlgES256 {
			return km, fmt.Errorf("密钥 alg 仅支持 %s/%s，实际 %q", AlgRS256, AlgES256, sum.Alg)
		}
	}
	switch sum.Kty {
	case "RSA":
		if sum.Alg != "" && sum.Alg != AlgRS256 {
			return km, fmt.Errorf("RSA 密钥 alg 必须为 %s，实际 %q", AlgRS256, sum.Alg)
		}
		pub, err := parseRSAPublicKey(str("n"), str("e"))
		if err != nil {
			return km, err
		}
		if pub.N.BitLen() < MinRSAKeyBits {
			return km, fmt.Errorf("RSA 公钥至少 %d 位，实际 %d 位", MinRSAKeyBits, pub.N.BitLen())
		}
		km.rsaN, km.rsaE = pub.N, pub.E
	case "EC":
		if sum.Crv != "P-256" {
			return km, fmt.Errorf("EC 密钥仅支持 P-256 曲线（ES256），实际 %q", sum.Crv)
		}
		if sum.Alg != "" && sum.Alg != AlgES256 {
			return km, fmt.Errorf("P-256 密钥 alg 必须为 %s，实际 %q", AlgES256, sum.Alg)
		}
		x, y, err := parseECPublicKey(str("x"), str("y"))
		if err != nil {
			return km, err
		}
		km.ecX, km.ecY = x, y
	case "oct":
		return km, fmt.Errorf("拒绝对称密钥（kty=oct）")
	default:
		return km, fmt.Errorf("不支持的 kty %q（仅 RSA/EC）", sum.Kty)
	}
	return km, nil
}

// parseRSAPublicKey 由 base64url 无填充 n/e 构造 RSA 公钥。
func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nb, err := b64url(nStr)
	if err != nil || len(nb) == 0 {
		return nil, fmt.Errorf("RSA 模数 n 非法")
	}
	eb, err := b64url(eStr)
	if err != nil || len(eb) == 0 {
		return nil, fmt.Errorf("RSA 指数 e 非法")
	}
	e := new(big.Int).SetBytes(eb).Int64()
	if e < 3 || e > 1<<31-1 || e%2 == 0 {
		return nil, fmt.Errorf("RSA 指数 e 取值非法")
	}
	n := new(big.Int).SetBytes(nb)
	if n.Sign() <= 0 {
		return nil, fmt.Errorf("RSA 模数 n 取值非法")
	}
	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

// parseECPublicKey 校验 P-256 公钥坐标在曲线上并返回坐标。
func parseECPublicKey(xStr, yStr string) (*big.Int, *big.Int, error) {
	xb, err := b64url(xStr)
	if err != nil || len(xb) == 0 {
		return nil, nil, fmt.Errorf("EC 坐标 x 非法")
	}
	yb, err := b64url(yStr)
	if err != nil || len(yb) == 0 {
		return nil, nil, fmt.Errorf("EC 坐标 y 非法")
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, nil, fmt.Errorf("EC 公钥坐标不在 P-256 曲线上")
	}
	return x, y, nil
}

// b64url 按 JWK 约定解码 base64url（无填充；容忍填充变体）。
func b64url(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// KeysetVersion 计算密钥集内容指纹（规范化密钥材料的 sha256 截断；供下发契约
// keyset_version、审计摘要与 VerificationResult 溯源；任何密钥材料轮换即变化，
// 含同 kid 换 key）。派生算法与网关 jwtverify.keysetVersion 逐字节一致
// （kid 排序；长度前缀字段；RSA=N 字节+8 字节指数；EC=P-256 压缩点 hex；
// 摘要截断前 16 字节），管理面审计指纹与网关事件溯源可直接比对。
func KeysetVersion(raw string) (string, error) {
	keys, err := parseJWKSKeys(raw, nil)
	if err != nil {
		return "", err
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].sum.KID < keys[j].sum.KID })
	h := sha256.New()
	for _, km := range keys {
		writeHashField(h, km.sum.KID)
		writeHashField(h, km.sum.Alg)
		switch {
		case km.rsaN != nil:
			writeHashField(h, "RSA")
			nb := km.rsaN.Bytes()
			var lb [8]byte
			binary.BigEndian.PutUint64(lb[:], uint64(len(nb)))
			_, _ = h.Write(lb[:])
			_, _ = h.Write(nb)
			var eb [8]byte
			binary.BigEndian.PutUint64(eb[:], uint64(km.rsaE))
			_, _ = h.Write(eb[:])
		case km.ecX != nil:
			writeHashField(h, "P-256")
			writeHashField(h, hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), km.ecX, km.ecY)))
		}
	}
	return hex.EncodeToString(h.Sum(nil)[:16]), nil
}

// writeHashField 写入长度前缀哈希字段（uint32 大端长度 + 原始字节），
// 与网关 jwtverify.writeHashField 逐字节一致，避免拼接歧义。
func writeHashField(h hash.Hash, s string) {
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(s)))
	_, _ = h.Write(lb[:])
	_, _ = h.Write([]byte(s))
}

// dupFrame 重复 JSON 键检测栈帧（json.Decoder 流式遍历；decoder 直接 Unmarshal
// 到 map 会静默覆盖重复键，必须显式检测——任务书 §5.2 拒绝解析歧义）。
type dupFrame struct {
	obj       bool
	keys      map[string]bool
	expectKey bool
}

func checkDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []dupFrame
	markValueDone := func() {
		if len(stack) > 0 && stack[len(stack)-1].obj {
			stack[len(stack)-1].expectKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("JWKS 不是合法 JSON: %v", err)
		}
		if len(stack) > 0 {
			top := &stack[len(stack)-1]
			if top.obj && top.expectKey {
				if key, ok := tok.(string); ok {
					if top.keys[key] {
						return fmt.Errorf("重复 JSON 键: %q", key)
					}
					top.keys[key] = true
					top.expectKey = false
					continue
				}
				// 对象结束（含空对象）合法；其余非字符串令牌非法
				if d, ok := tok.(json.Delim); !ok || d != '}' {
					return fmt.Errorf("非法 JSON 对象键")
				}
			}
		}
		switch d := tok.(type) {
		case json.Delim:
			switch d {
			case '{':
				stack = append(stack, dupFrame{obj: true, keys: map[string]bool{}, expectKey: true})
			case '[':
				stack = append(stack, dupFrame{})
			case '}', ']':
				stack = stack[:len(stack)-1]
				markValueDone()
			}
		default:
			markValueDone()
		}
	}
}
