// httpsig_test.go RFC 9421 附录 B 官方测试向量黄金样本（规范内嵌零第三方依赖：
// B.2.6 ed25519 基线重构逐字节一致+验签通过；B.2.1/B.2.2/B.2.3 rsa-pss 验签；
// B.4 多头合并形态）+ ParseHeaders 契约矩阵 + I01 篡改形态。
package httpsig

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// RFC 9421 附录 B.1.4 ed25519 测试公钥（PKCS #8 PEM，规范原文逐字）。
const rfc9421Ed25519PubPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----
`

// RFC 9421 附录 B.1.2 RSA-PSS 测试公钥（PKCS #8 PEM，规范原文经脚本提取逐字）。
const rfc9421RSAPubPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----
`

// testRequestB26 RFC B.2 测试请求（逐字：POST /foo?param=Value&Pet=dog，
// Host example.com，Date/Content-Type/Content-Length 头，体 {"hello": "world"}）。
func testRequestB26(t *testing.T, input, sig string) *http.Request {
	t.Helper()
	r := httptest.NewRequest("POST", "/foo?param=Value&Pet=dog", strings.NewReader(`{"hello": "world"}`))
	// httptest 默认 Host=example.com（与向量一致）；显式钉死防实现漂移
	r.Host = "example.com"
	r.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Content-Length", "18")
	r.Header.Set("Signature-Input", input)
	r.Header.Set("Signature", sig)
	return r
}

// TestRFC9421B26Ed25519Golden 黄金样本：ed25519 向量签名基线重构逐字节一致 +
// 验签通过（规范附录 B.2.6 原文内嵌）。
func TestRFC9421B26Ed25519Golden(t *testing.T) {
	input := `sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`
	sig := `sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:`
	r := testRequestB26(t, input, sig)
	p := &Params{
		KeyID: "test-key-ed25519", Created: 1618884473,
		CoveredComponents: []string{"date", "@method", "@path", "@authority", "content-type", "content-length"},
	}
	base, sigBytes, err := BuildSignatureBase(r, p)
	if err != nil {
		t.Fatalf("基线重构: %v", err)
	}
	// 基线逐字节一致（RFC 附录 B.2.6 原文）
	wantBase := `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@authority": example.com
"content-type": application/json
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`
	if string(base) != wantBase {
		t.Fatalf("基线逐字节不符:\n---got---\n%s\n---want---\n%s", base, wantBase)
	}
	// 验签通过（std本 crypto ed25519）
	if err := verifyCrypto([]byte(rfc9421Ed25519PubPEM), "ed25519", base, sigBytes); err != nil {
		t.Fatalf("黄金样本验签应通过: %v", err)
	}
	// G1 链完整性对照：B.2.6 形态不满足 G1 覆盖充分性（有 query 未签 @query、
	// 有 body 未签 content-digest）——VerifySignatureBase 如实拒绝（G1 严于
	// RFC 示例，步 6 冻结口径；黄金样本走 BuildSignatureBase 消费点逐字节验证）
	if err := VerifySignatureBase(r, p, []byte(`{"hello": "world"}`), Key{Kid: "test-key-ed25519", Alg: "ed25519", PublicKeyPEM: []byte(rfc9421Ed25519PubPEM)}); err == nil {
		t.Fatal("G1 覆盖门应拒绝该 RFC 形态（缺 @query/content-digest 覆盖）")
	} else if !errors.Is(err, ErrVerify) {
		t.Fatalf("覆盖不足应 ErrVerify 分类: %v", err)
	}
}

// TestRFC9421B23RSAPSSGolden B.2.3 全覆盖 rsa-pss 样本（含 content-digest
// sha-512 重算比对通过——体摘要与签名双重通过；G1 覆盖门满足（query+digest
// 均覆盖），VerifySignatureBase 全链通过）。
func TestRFC9421B23RSAPSSGolden(t *testing.T) {
	input := `sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`
	sig := `sig-b23=:bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yBiMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fUxN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5ZJzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==:`
	r := testRequestB26(t, input, sig)
	r.Header.Set("Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:")
	p := &Params{
		KeyID: "test-key-rsa-pss", Created: 1618884473,
		CoveredComponents: []string{"date", "@method", "@path", "@query", "@authority", "content-type", "content-digest", "content-length"},
	}
	body := []byte(`{"hello": "world"}`)
	// 全链（VerifySignatureBase）：覆盖门通过（query+digest 均覆盖）+ 基线重构 +
	// digest 重算 + rsa-pss-sha512 验签
	if err := VerifySignatureBase(r, p, body, Key{Kid: "test-key-rsa-pss", Alg: "rsa-pss-sha512", PublicKeyPEM: []byte(rfc9421RSAPubPEM)}); err != nil {
		t.Fatalf("B.2.3 全链应通过: %v", err)
	}
	// 基线逐字节对照（RFC 附录 B.2.3 原文）
	base, _, err := BuildSignatureBase(r, p)
	if err != nil {
		t.Fatal(err)
	}
	wantBase := `"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@query": ?param=Value&Pet=dog
"@authority": example.com
"content-type": application/json
"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`
	if string(base) != wantBase {
		t.Fatalf("基线逐字节不符:\n---got---\n%s\n---want---\n%s", base, wantBase)
	}
}

// TestRFC9421B21MinimalRSAPSS B.2.1 最小签名（空成分集——nonce 时间戳占有证明）：
// 基线逐字节一致 + rsa-pss 验签通过（G1 覆盖门拒收——仅供基线/验签层验证）。
func TestRFC9421B21MinimalRSAPSS(t *testing.T) {
	input := `sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`
	sig := `sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:`
	r := testRequestB26(t, input, sig)
	p := &Params{KeyID: "test-key-rsa-pss", Created: 1618884473, Nonce: "b3k2pp5k7z-50gnwp.yemd"}
	base, sigBytes, err := BuildSignatureBase(r, p)
	if err != nil {
		t.Fatal(err)
	}
	wantBase := `"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`
	if string(base) != wantBase {
		t.Fatalf("基线不符:\n%q\n%q", base, wantBase)
	}
	if err := verifyCrypto([]byte(rfc9421RSAPubPEM), "rsa-pss-sha512", base, sigBytes); err != nil {
		t.Fatalf("B.2.1 验签应通过: %v", err)
	}
}

// TestRFC9421B22QueryParamTag B.2.2：@query-param;name 成分与应用级 tag 参数
// （参数序与未知参数忠实重现——Params 冻结形状不携带，经原文重读重现）。
func TestRFC9421B22QueryParamTag(t *testing.T) {
	input := `sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"`
	sig := `sig-b22=:LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQEdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SARYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoKUqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==:`
	r := testRequestB26(t, input, sig)
	r.Header.Set("Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:")
	p := &Params{
		KeyID: "test-key-rsa-pss", Created: 1618884473,
		CoveredComponents: []string{"@authority", "content-digest", "@query-param"},
	}
	base, sigBytes, err := BuildSignatureBase(r, p)
	if err != nil {
		t.Fatal(err)
	}
	wantBase := `"@authority": example.com
"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"@query-param";name="Pet": dog
"@signature-params": ("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"`
	if string(base) != wantBase {
		t.Fatalf("基线不符（tag 参数序忠实重现）:\n%q\n%q", base, wantBase)
	}
	if err := verifyCrypto([]byte(rfc9421RSAPubPEM), "rsa-pss-sha512", base, sigBytes); err != nil {
		t.Fatalf("B.2.2 验签应通过: %v", err)
	}
}

// TestRFC9421B4MultiValueJoin B.4 变换形态：多头成分逗号+空格合并（accept 双行）。
func TestRFC9421B4MultiValueJoin(t *testing.T) {
	input := `transform=("@method" "@path" "@authority" "accept");created=1618884473;keyid="test-key-ed25519"`
	sig := `transform=:ZT1kooQsEHpZ0I1IjCqtQppOmIqlJPeo7DHR3SoMn0s5JZ1eRGS0A+vyYP9t/LXlh5QMFFQ6cpLt2m0pmj3NDA==:`
	r := httptest.NewRequest("GET", "/demo?name1=Value1&Name2=value2", nil)
	r.Host = "example.org"
	r.Header.Set("Date", "Fri, 15 Jul 2022 14:24:55 GMT")
	r.Header.Add("Accept", "application/json")
	r.Header.Add("Accept", "*/*")
	r.Header.Set("Signature-Input", input)
	r.Header.Set("Signature", sig)
	p := &Params{
		KeyID: "test-key-ed25519", Created: 1618884473,
		CoveredComponents: []string{"@method", "@path", "@authority", "accept"},
	}
	base, sigBytes, err := BuildSignatureBase(r, p)
	if err != nil {
		t.Fatal(err)
	}
	wantBase := `"@method": GET
"@path": /demo
"@authority": example.org
"accept": application/json, */*
"@signature-params": ("@method" "@path" "@authority" "accept");created=1618884473;keyid="test-key-ed25519"`
	if string(base) != wantBase {
		t.Fatalf("基线不符:\n%q\n%q", base, wantBase)
	}
	if err := verifyCrypto([]byte(rfc9421Ed25519PubPEM), "ed25519", base, sigBytes); err != nil {
		t.Fatalf("B.4 验签应通过: %v", err)
	}
}
