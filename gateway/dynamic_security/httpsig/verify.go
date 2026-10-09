// verify.go 签名基线重构与验签（§1.4 步 6/7/8/9 纯函数——线契约冻结签名
// VerifySignatureBase + 黄金样本消费点 BuildSignatureBase）。
//
// 成分取值（§1.1 规范化口径逐字执行）：
//   - @method：请求方法原文；
//   - @authority：可信代理处理后的 Host 原文（只信任批准的转发信息——
//     不执行 RFC 9421 §2.2.3 的小写归一，以设计冻结文本为准）；
//   - @path：raw path 不做归一化（RequestURI origin-form 原文去 query；
//     非 origin-form 回退 r.URL.EscapedPath——G1 排除改写路由（管理面拒存））；
//   - @query：原文（"?" + RawQuery；无 query 时值为 "?"——RFC 9421 §2.2.7）；
//   - @query-param;name="x"：query 具名参数解码值（多值取首个；缺席即成分
//     不可得 → ErrVerify）；
//   - 普通头成分（小写名）：多头按 RFC 9110 §5.2 逗号+空格合并原文；
//     缺席即成分不可得 → ErrVerify；
//   - content-digest：头原文（SF Dictionary 形态——重算比对在步 8）。
//
// 目标绑定与验签的不可分割性（登记）：签名基线由网关视角成分重构——客户端
// 声明成分与网关视图的任何不一致都经密码学验签失败暴露（ErrVerify），
// MID-TARGET-MISMATCH/MID-SIGNATURE-INVALID 的细分映射属 B2 词表，本层
// 只承载错误分类（任务书明文：ErrVerify 不越界定义事件词表）。
package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// 算法词表（§1.2 冻结：ed25519/ecdsa-p256-sha256/rsa-pss-sha512；
// hmac-sha256 共享密钥形态排除，rsa-v1_5-sha256 排除（RFC 9421 标注不推荐））。
const (
	AlgEd25519         = "ed25519"
	AlgECDSAP256SHA256 = "ecdsa-p256-sha256"
	AlgRSAPSSSHA512    = "rsa-pss-sha512"
)

// privilegedHeaders 权限关键头词表（§1.4 步 6：存在必须被覆盖——未签名的
// 权限关键头不得进入可信上下文；词表=认证检测器消费面（authorization/
// x-api-key/cookie）+ proxy-authorization 同源形态）。
var privilegedHeaders = []string{"authorization", "proxy-authorization", "x-api-key", "cookie"}

// VerifySignatureBase 签名基线验证（线契约逐字冻结签名，§1.4 步 6/7/8/9）：
// 覆盖成分充分性 → 基线重构（成分取值+参数序忠实重现）→ content-digest 重算
// 比对 → 密码学验签。体预算用 DefaultBudgets（MaxBodyBytes 4MiB——签名无
// Budgets 入参的冻结形状承载）。
func VerifySignatureBase(r *http.Request, p *Params, body []byte, key Key) error {
	if r == nil || p == nil {
		return verifyErr("nil input")
	}
	b := DefaultBudgets()
	if len(body) > b.MaxBodyBytes {
		return &BudgetError{Rule: "body_bytes_exceeded", Limit: b.MaxBodyBytes, Actual: len(body)}
	}
	// 步 6：覆盖成分充分性
	if err := checkCoverage(r, p, len(body) > 0); err != nil {
		return err
	}
	// 步 7/9 前段：基线重构 + 签名提取（重读请求头原文——参数序忠实重现）
	base, sig, err := BuildSignatureBase(r, p)
	if err != nil {
		return err
	}
	// 步 8：content-digest 重算比对（覆盖才验——成分含 content-digest 时）
	if coveredContains(p, "content-digest") {
		if err := verifyContentDigest(r, body); err != nil {
			return err
		}
	}
	// 步 9：密码学验签（alg 与登记算法一致性双重核对——§1.4 步 3 纯函数侧承载）
	alg := p.Alg
	if alg == "" {
		alg = key.Alg // 黄金样本/直接调用路径：以登记算法为准
	}
	if key.Alg != "" && alg != key.Alg {
		return verifyErr("alg_mismatch")
	}
	return verifyCrypto(key.PublicKeyPEM, alg, base, sig)
}

// BuildSignatureBase 签名基线重构（黄金样本消费点——按 RFC 9421 §2.5 逐行
// 渲染：每成分 "name";params: value，末行 "@signature-params": (成分内列表)
// ;签名参数（Signature-Input 原文参数序与未知参数忠实重现——重读请求头经
// 同一 SF 解析引擎））。返回基线与签名 Byte Sequence 解码值。
func BuildSignatureBase(r *http.Request, p *Params) (base []byte, sig []byte, err error) {
	if r == nil || p == nil {
		return nil, nil, verifyErr("nil input")
	}
	// 重读 Signature-Input 原文（参数序+未知参数忠实重现的承载）
	inputMembers, err := parseSFDictionary(strings.Join(r.Header.Values("Signature-Input"), ", "))
	if err != nil {
		return nil, nil, malformed("Signature-Input: %v", err)
	}
	if len(inputMembers) != 1 || !inputMembers[0].IsList {
		return nil, nil, malformed("Signature-Input: 恰好一个签名标签且值为 Inner List")
	}
	in := inputMembers[0]
	// 成分数与 p 一致性交叉核对（ParseHeaders 与重读分歧 = 头在两次读取间
	// 不一致——如实拒绝不猜义）
	if len(in.Items) != len(p.CoveredComponents) {
		return nil, nil, verifyErr("covered_components_diverged")
	}
	var sb strings.Builder
	inner := make([]byte, 0, 256)
	for i, item := range in.Items {
		name := item.Value.Str
		if item.Value.Kind != sfValueString && item.Value.Kind != sfValueToken {
			return nil, nil, malformed("覆盖成分必须为字符串/令牌形态")
		}
		if p.CoveredComponents[i] != name {
			return nil, nil, verifyErr("covered_components_diverged")
		}
		value, err := deriveComponentValue(r, name, item.Params)
		if err != nil {
			return nil, nil, err
		}
		// 行："<name>";<成分参数>: <值>
		sb.WriteString(strconv.Quote(name))
		sb.WriteString(renderSFParams(item.Params))
		sb.WriteString(": ")
		sb.WriteString(value)
		sb.WriteString("\n")
		// 内列表项重现
		if i > 0 {
			inner = append(inner, ' ')
		}
		inner = append(inner, strconv.Quote(name)...)
		inner = append(inner, renderSFParams(item.Params)...)
	}
	// "@signature-params" 行：内列表 + 签名参数（原文序+未知参数忠实重现）
	sb.WriteString(strconv.Quote("@signature-params"))
	sb.WriteString(": (")
	sb.Write(inner)
	sb.WriteString(")")
	sb.WriteString(renderSFParams(in.ListParams))

	// 签名 Byte Sequence（重读 Signature 头；标签一致性交叉核对）
	sigMembers, err := parseSFDictionary(strings.Join(r.Header.Values("Signature"), ", "))
	if err != nil {
		return nil, nil, malformed("Signature: %v", err)
	}
	if len(sigMembers) != 1 || sigMembers[0].IsList || sigMembers[0].Item.Value.Kind != sfValueBytes {
		return nil, nil, malformed("Signature: 恰好一个签名标签且值为 Byte Sequence")
	}
	if sigMembers[0].Key != in.Key {
		return nil, nil, verifyErr("signature_label_mismatch")
	}
	return []byte(sb.String()), sigMembers[0].Item.Value.Bytes, nil
}

// checkCoverage 覆盖成分充分性（§1.4 步 6）。
func checkCoverage(r *http.Request, p *Params, hasBody bool) error {
	covered := make(map[string]bool, len(p.CoveredComponents))
	for _, c := range p.CoveredComponents {
		covered[c] = true
		// G1 排除 @target-uri 全形态（§3 冻结：以 @authority+@path+@query 分解
		// 覆盖；接入契约明示——拒收为覆盖不足语义，B2 映射 MID-COVERAGE-INSUFFICIENT）
		if c == "@target-uri" {
			return verifyErr("unsupported_component @target-uri")
		}
	}
	for _, must := range []string{"@method", "@authority", "@path"} {
		if !covered[must] {
			return verifyErr("coverage missing %s", must)
		}
	}
	if rawQueryOf(r) != "" && !covered["@query"] {
		return verifyErr("coverage missing @query（请求有 query 必含）")
	}
	if hasBody && !covered["content-digest"] {
		return verifyErr("coverage missing content-digest（请求有 body 必含，§12.2-3）")
	}
	// 权限关键头存在必被覆盖（§12.2-3 原文）
	for _, h := range privilegedHeaders {
		if len(r.Header.Values(h)) > 0 && !covered[h] {
			return verifyErr("coverage missing privileged header %q（未签名的权限关键头不得进入可信上下文）", h)
		}
	}
	return nil
}

// coveredContains 成分覆盖判定。
func coveredContains(p *Params, name string) bool {
	for _, c := range p.CoveredComponents {
		if c == name {
			return true
		}
	}
	return false
}

// deriveComponentValue 成分取值（§1.1 规范化口径逐字）。
func deriveComponentValue(r *http.Request, name string, params []sfParam) (string, error) {
	switch name {
	case "@method":
		return r.Method, nil
	case "@authority":
		return r.Host, nil // Host 原文（设计冻结口径）
	case "@path":
		return rawPathOf(r), nil
	case "@query":
		return "?" + rawQueryOf(r), nil // 无 query 值为 "?"（RFC 9421 §2.2.7）
	case "@query-param":
		return queryParamValue(r, params)
	case "@status", "@scheme", "@request-target", "@request-response", "@target-uri":
		return "", verifyErr("unsupported_component %s（G1 不做该形态）", name)
	}
	if strings.HasPrefix(name, "@") {
		return "", verifyErr("unknown derived component %s", name)
	}
	// 普通头成分：多头逗号+空格合并原文（RFC 9110 §5.2）；缺席即不可得
	vals := r.Header.Values(name)
	if len(vals) == 0 {
		return "", verifyErr("covered header %q not present（成分不可得）", name)
	}
	return strings.Join(vals, ", "), nil
}

// queryParamValue @query-param;name="x" 取值（解码后首个值；name 参数必填；
// 其余参数形态（sf/bs/tr/key/req）G1 不支持如实拒绝）。
func queryParamValue(r *http.Request, params []sfParam) (string, error) {
	var pname string
	for _, pr := range params {
		if pr.Name == "name" {
			if pr.Value.Kind != sfValueString && pr.Value.Kind != sfValueToken {
				return "", malformed("@query-param;name 必须为字符串/令牌")
			}
			pname = pr.Value.Str
			continue
		}
		return "", verifyErr("unsupported_component_param %q（G1 仅支持 @query-param;name）", pr.Name)
	}
	if pname == "" {
		return "", malformed("@query-param 缺 name 参数")
	}
	vals, err := url.ParseQuery(rawQueryOf(r))
	if err != nil {
		return "", verifyErr("query unparseable: %v", err)
	}
	v := vals[pname]
	if len(v) == 0 {
		return "", verifyErr("query-param %q not present（成分不可得）", pname)
	}
	return v[0], nil
}

// rawPathOf raw path 原文（RequestURI origin-form 去 query；非 origin-form
// 回退 r.URL.EscapedPath——不归一化）。
func rawPathOf(r *http.Request) string {
	if r.RequestURI != "" && strings.HasPrefix(r.RequestURI, "/") {
		if i := strings.IndexByte(r.RequestURI, '?'); i >= 0 {
			return r.RequestURI[:i]
		}
		return r.RequestURI
	}
	if r.URL != nil {
		return r.URL.EscapedPath()
	}
	return ""
}

// rawQueryOf query 原文（RequestURI 原文优先；回退 r.URL.RawQuery）。
func rawQueryOf(r *http.Request) string {
	if r.RequestURI != "" && strings.HasPrefix(r.RequestURI, "/") {
		if i := strings.IndexByte(r.RequestURI, '?'); i >= 0 {
			return r.RequestURI[i+1:]
		}
		return ""
	}
	if r.URL != nil {
		return r.URL.RawQuery
	}
	return ""
}

// verifyContentDigest content-digest 重算比对（RFC 9530：SF Dictionary，
// sha-256/sha-512 成员 Byte Sequence 值；逐呈现算法常量时间比对——
// 任一呈现算法不符即失败；两算法均缺席 = 成分不可得失败）。
func verifyContentDigest(r *http.Request, body []byte) error {
	raw := strings.Join(r.Header.Values("Content-Digest"), ", ")
	members, err := parseSFDictionary(raw)
	if err != nil {
		return malformed("Content-Digest: %v", err)
	}
	verified := false
	for _, m := range members {
		if m.IsList || m.Item.Value.Kind != sfValueBytes {
			return malformed("Content-Digest: 成员值必须为 Byte Sequence")
		}
		var sum []byte
		switch m.Key {
		case "sha-256":
			s := sha256.Sum256(body)
			sum = s[:]
		case "sha-512":
			s := sha512.Sum512(body)
			sum = s[:]
		default:
			continue // 未知算法成员跳过（G1 双算法词表）
		}
		if subtle.ConstantTimeCompare(sum, m.Item.Value.Bytes) != 1 {
			return verifyErr("digest_mismatch")
		}
		verified = true
	}
	if !verified {
		return verifyErr("digest_no_supported_alg（sha-256/sha-512 均缺席）")
	}
	return nil
}

// verifyCrypto 密码学验签（stdlib crypto；alg 词表外拒收）。
func verifyCrypto(publicKeyPEM []byte, alg string, base, sig []byte) error {
	pub, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return verifyErr("key_unparseable: %v", err)
	}
	switch alg {
	case AlgEd25519:
		pk, ok := pub.(ed25519.PublicKey)
		if !ok {
			return verifyErr("key_type_mismatch: 非 ed25519 公钥")
		}
		if !ed25519.Verify(pk, base, sig) {
			return verifyErr("signature_invalid")
		}
		return nil
	case AlgECDSAP256SHA256:
		pk, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return verifyErr("key_type_mismatch: 非 ECDSA 公钥")
		}
		if pk.Curve != elliptic.P256() {
			return verifyErr("key_curve_mismatch: 非 P-256")
		}
		if len(sig) != 64 {
			return verifyErr("signature_invalid")
		}
		sum := sha256.Sum256(base)
		if !ecdsa.Verify(pk, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return verifyErr("signature_invalid")
		}
		return nil
	case AlgRSAPSSSHA512:
		pk, ok := pub.(*rsa.PublicKey)
		if !ok {
			return verifyErr("key_type_mismatch: 非 RSA 公钥")
		}
		sum := sha512.Sum512(base)
		if err := rsa.VerifyPSS(pk, crypto.SHA512, sum[:], sig, &rsa.PSSOptions{SaltLength: 64}); err != nil {
			return verifyErr("signature_invalid")
		}
		return nil
	default:
		return verifyErr("unsupported_alg %q（词表 ed25519|ecdsa-p256-sha256|rsa-pss-sha512）", alg)
	}
}

// parsePublicKey PEM → PKIX 公钥（管理面静态离线导入形态；拒绝私钥形态误投）。
func parsePublicKey(raw []byte) (any, error) {
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, verifyErr("pem_decode_failed")
	}
	if !strings.Contains(blk.Type, "PUBLIC KEY") {
		return nil, verifyErr("not_a_public_key_pem")
	}
	return x509.ParsePKIXPublicKey(blk.Bytes)
}
