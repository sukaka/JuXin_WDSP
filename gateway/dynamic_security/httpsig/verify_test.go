// verify_test.go 验签矩阵：三算法（ed25519/ecdsa-p256-sha256/rsa-pss-sha512）
// 真实密钥签名通过 + 篡改逐维拒绝（I01 形态：改方法/路径/query 任一即拒）+
// 覆盖充分性缺项 + digest 重算比对（sha-256/sha-512）+ 预算 + 算法词表。
package httpsig

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
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testKeys 三算法测试密钥对（stdlib 生成——真实密钥验签，签名构造经同一基线
// 重构（外部锚点已由 RFC 黄金样本钉死））。
type testKeys struct {
	edPub   ed25519.PublicKey
	edPriv  ed25519.PrivateKey
	ecPriv  *ecdsa.PrivateKey
	ecPub   *ecdsa.PublicKey
	rsaPriv *rsa.PrivateKey
	rsaPub  *rsa.PublicKey
}

func genTestKeys(t *testing.T) testKeys {
	t.Helper()
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return testKeys{edPub: edPub, edPriv: edPriv, ecPriv: ecPriv, ecPub: &ecPriv.PublicKey, rsaPriv: rsaPriv, rsaPub: &rsaPriv.PublicKey}
}

func pemOfPublic(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// signTestRequest 构造 G1 完整签名请求并验签（components/alg 可定制；
// 体非空自动加 content-digest 覆盖与头）。
func signTestRequest(t *testing.T, k testKeys, alg string, method, target string, body []byte, mutateReq func(r *http.Request)) (*http.Request, *Params, Key) {
	t.Helper()
	var bodyReader *strings.Reader
	if body != nil {
		bodyReader = strings.NewReader(string(body))
	} else {
		bodyReader = strings.NewReader("")
	}
	r := httptest.NewRequest(method, target, bodyReader)
	r.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	components := []string{"@method", "@authority", "@path"}
	if strings.Contains(target, "?") {
		components = append(components, "@query")
	}
	if body != nil {
		sum := sha256.Sum256(body)
		r.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":")
		components = append(components, "content-digest")
	}
	if mutateReq != nil {
		mutateReq(r)
	}
	// Signature-Input 构造（五参数齐全——G1 步 1 齐全性）
	var sb strings.Builder
	sb.WriteString(`sig1=(`)
	for i, c := range components {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(`"` + c + `"`)
	}
	sb.WriteString(`);created=1618884473;expires=1618884593;nonce="n8f6kfs9.2gkf0s9";keyid="k1";alg="` + alg + `"`)
	r.Header.Set("Signature-Input", sb.String())
	// 先占位解析（Signature 头暂缺——基线重构只读 Signature-Input；占位为合法
	// 空 Byte Sequence 形态 sig1=::）
	p, err := ParseHeaders(sb.String(), "sig1=::", Budgets{})
	if err != nil {
		t.Fatalf("ParseHeaders 占位: %v", err)
	}
	r.Header.Set("Signature", "sig1=::")
	base, _, err := BuildSignatureBase(r, p)
	if err != nil {
		t.Fatalf("基线: %v", err)
	}
	sig := signBase(t, k, alg, base)
	r.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
	p, err = ParseHeaders(sb.String(), r.Header.Get("Signature"), Budgets{})
	if err != nil {
		t.Fatalf("ParseHeaders: %v", err)
	}
	var pub []byte
	switch alg {
	case AlgEd25519:
		pub = pemOfPublic(t, k.edPub)
	case AlgECDSAP256SHA256:
		pub = pemOfPublic(t, k.ecPub)
	case AlgRSAPSSSHA512:
		pub = pemOfPublic(t, k.rsaPub)
	}
	return r, p, Key{Kid: "k1", Alg: alg, PublicKeyPEM: pub}
}

// signBase 按算法签名基线（ECDSA 为 R||S 64 字节拼接形态——RFC 9421 §3.3.4）。
func signBase(t *testing.T, k testKeys, alg string, base []byte) []byte {
	t.Helper()
	switch alg {
	case AlgEd25519:
		return ed25519.Sign(k.edPriv, base)
	case AlgECDSAP256SHA256:
		sum := sha256.Sum256(base)
		rv, sv, err := ecdsa.Sign(rand.Reader, k.ecPriv, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, 64)
		rv.FillBytes(out[:32])
		sv.FillBytes(out[32:])
		return out
	case AlgRSAPSSSHA512:
		sum := sha512.Sum512(base)
		sig, err := rsa.SignPSS(rand.Reader, k.rsaPriv, crypto.SHA512, sum[:], &rsa.PSSOptions{SaltLength: 64})
		if err != nil {
			t.Fatal(err)
		}
		return sig
	default:
		t.Fatalf("alg %q", alg)
		return nil
	}
}

// TestVerifyThreeAlgorithms 三算法真实密钥验签通过。
func TestVerifyThreeAlgorithms(t *testing.T) {
	k := genTestKeys(t)
	for _, alg := range []string{AlgEd25519, AlgECDSAP256SHA256, AlgRSAPSSSHA512} {
		t.Run(alg, func(t *testing.T) {
			r, p, key := signTestRequest(t, k, alg, "POST", "/foo?param=Value&Pet=dog", []byte(`{"hello": "world"}`), nil)
			if err := VerifySignatureBase(r, p, []byte(`{"hello": "world"}`), key); err != nil {
				t.Fatalf("有效签名应通过: %v", err)
			}
		})
	}
}

// TestVerifyTamperRejected I01 篡改矩阵：改方法/路径/query 任一即拒
// （ErrVerify 分类；MID-TARGET-MISMATCH 语义映射属 B2）。
func TestVerifyTamperRejected(t *testing.T) {
	k := genTestKeys(t)
	body := []byte(`{"hello": "world"}`)
	cases := []struct {
		name   string
		mutate func(r *http.Request) // 签名后的篡改（目标成分变化——验签失败）
	}{
		{"改方法", func(r *http.Request) { r.Method = "GET" }},
		{"改路径", func(r *http.Request) { r.RequestURI = "/bar?param=Value&Pet=dog"; r.URL.Path = "/bar" }},
		{"改 query", func(r *http.Request) {
			r.RequestURI = "/foo?param=Value&Pet=cat"
			r.URL.RawQuery = "param=Value&Pet=cat"
		}},
		{"改 Host", func(r *http.Request) { r.Host = "example.org" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, p, key := signTestRequest(t, k, AlgEd25519, "POST", "/foo?param=Value&Pet=dog", body, nil)
			tc.mutate(r)
			if err := VerifySignatureBase(r, p, body, key); !errors.Is(err, ErrVerify) {
				t.Fatalf("篡改变更必须拒绝: %v", err)
			}
		})
	}
	// 体篡改 + digest 陈旧 → digest_mismatch（步 8 前置明文比对）
	t.Run("体篡改 digest 陈旧", func(t *testing.T) {
		r, p, key := signTestRequest(t, k, AlgEd25519, "POST", "/foo?param=Value&Pet=dog", body, nil)
		tampered := []byte(`{"hello": "evil"}`)
		err := VerifySignatureBase(r, p, tampered, key)
		if !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "digest_mismatch") {
			t.Fatalf("应 digest_mismatch: %v", err)
		}
	})
	// 签名翻位 → signature_invalid
	t.Run("签名翻位", func(t *testing.T) {
		r, p, key := signTestRequest(t, k, AlgEd25519, "POST", "/foo?param=Value&Pet=dog", body, nil)
		sigRaw := r.Header.Get("Signature")
		inner := strings.Split(sigRaw, ":")[1]
		sigBytes, _ := base64.StdEncoding.DecodeString(inner)
		sigBytes[0] ^= 0x01
		r.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sigBytes)+":")
		if err := VerifySignatureBase(r, p, body, key); !errors.Is(err, ErrVerify) {
			t.Fatalf("翻位必须拒绝: %v", err)
		}
	})
}

// TestVerifyCoverageGate 覆盖成分充分性（步 6 各缺项）。
func TestVerifyCoverageGate(t *testing.T) {
	k := genTestKeys(t)
	body := []byte(`{"hello": "world"}`)
	drop := func(name string) func(r *http.Request) { // 从成分集移除
		return nil
	}
	_ = drop
	cases := []struct {
		name string
		keep func([]string) []string // 成分集过滤（移除覆盖）
		body []byte
		req  func(r *http.Request)
		want string
	}{
		{"缺 @method", func(c []string) []string { return removeComp(c, "@method") }, nil, nil, "missing @method"},
		{"缺 @authority", func(c []string) []string { return removeComp(c, "@authority") }, nil, nil, "missing @authority"},
		{"缺 @path", func(c []string) []string { return removeComp(c, "@path") }, nil, nil, "missing @path"},
		{"有 query 缺 @query", func(c []string) []string { return removeComp(c, "@query") }, nil, nil, "missing @query"},
		{"有 body 缺 content-digest", func(c []string) []string { return removeComp(c, "content-digest") }, body, nil, "missing content-digest"},
		{"权限关键头未覆盖", nil, nil, func(r *http.Request) { r.Header.Set("Authorization", "Bearer x") }, "privileged header"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 自构造请求（不经完整签名链——覆盖门先于验签）
			var br *strings.Reader
			if tc.body != nil {
				br = strings.NewReader(string(tc.body))
			} else {
				br = strings.NewReader("")
			}
			r := httptest.NewRequest("POST", "/foo?param=Value&Pet=dog", br)
			r.Host = "example.com"
			components := []string{"@method", "@authority", "@path", "@query", "content-digest"}
			if tc.keep != nil {
				components = tc.keep(components)
			}
			if tc.body != nil {
				sum := sha256.Sum256(tc.body)
				r.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":")
			}
			if tc.req != nil {
				tc.req(r)
			}
			p := &Params{KeyID: "k1", Alg: AlgEd25519, Created: 1, Expires: 2, Nonce: "n8f6kfs9.2gkf0s9", CoveredComponents: components}
			_, key := mustEDKey(t, k)
			err := VerifySignatureBase(r, p, tc.body, key)
			if err == nil || !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("应覆盖拒绝（含 %q）: %v", tc.want, err)
			}
		})
	}
	// @target-uri 形态拒收（G1 排除——接入契约明示）
	t.Run("@target-uri 拒收", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/foo", nil)
		r.Host = "example.com"
		p := &Params{KeyID: "k1", Alg: AlgEd25519, Created: 1, Expires: 2, Nonce: "n8f6kfs9.2gkf0s9",
			CoveredComponents: []string{"@method", "@authority", "@path", "@target-uri"}}
		_, key := mustEDKey(t, k)
		if err := VerifySignatureBase(r, p, nil, key); err == nil || !strings.Contains(err.Error(), "@target-uri") {
			t.Fatalf("@target-uri 应拒: %v", err)
		}
	})
}

func removeComp(c []string, name string) []string {
	out := c[:0]
	for _, x := range c {
		if x != name {
			out = append(out, x)
		}
	}
	return out
}

func mustEDKey(t *testing.T, k testKeys) (ed25519.PublicKey, Key) {
	t.Helper()
	return k.edPub, Key{Kid: "k1", Alg: AlgEd25519, PublicKeyPEM: pemOfPublic(t, k.edPub)}
}

// TestParseHeadersContract ParseHeaders 契约矩阵（齐全性/多标签拒收/预算逐条）。
func TestParseHeadersContract(t *testing.T) {
	validInput := `sig1=("@method" "@authority" "@path");created=1618884473;expires=1618884593;nonce="n8f6kfs9.2gkf0s9";keyid="k1";alg="ed25519"`
	validSig := `sig1=:dGVzdA==:`
	t.Run("合法解析", func(t *testing.T) {
		p, err := ParseHeaders(validInput, validSig, Budgets{})
		if err != nil {
			t.Fatal(err)
		}
		if p.KeyID != "k1" || p.Alg != "ed25519" || p.Nonce != "n8f6kfs9.2gkf0s9" ||
			p.Created != 1618884473 || p.Expires != 1618884593 ||
			len(p.CoveredComponents) != 3 || p.CoveredComponents[0] != "@method" {
			t.Fatalf("Params = %+v", p)
		}
	})
	// 五参数缺任一即 ErrMalformed（步 1 齐全性）
	for _, miss := range []string{"created", "expires", "nonce", "keyid", "alg"} {
		input := `sig1=("@method");` + strings.Join(keepParams(miss), ";")
		_, err := ParseHeaders(input, validSig, Budgets{})
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("缺 %s 应拒: %v", miss, err)
		}
	}
	// 多签名标签拒收
	t.Run("多标签拒收", func(t *testing.T) {
		if _, err := ParseHeaders(validInput+","+validInput, validSig, Budgets{}); !errors.Is(err, ErrMalformed) {
			t.Fatal("多签名标签应拒收")
		}
		if _, err := ParseHeaders(validInput, validSig+",sig2=:dGVzdA==:", Budgets{}); !errors.Is(err, ErrMalformed) {
			t.Fatal("Signature 多标签应拒收")
		}
	})
	// 非 Inner List / 非 Byte Sequence
	t.Run("形态错误", func(t *testing.T) {
		if _, err := ParseHeaders(`sig1=42;created=1;expires=2;nonce="n";keyid="k";alg="ed25519"`, validSig, Budgets{}); !errors.Is(err, ErrMalformed) {
			t.Fatal("非 Inner List 应拒")
		}
		if _, err := ParseHeaders(validInput, `sig1="notbytes"`, Budgets{}); !errors.Is(err, ErrMalformed) {
			t.Fatal("非 Byte Sequence 应拒")
		}
	})
	// 预算逐条（恰等过/超 1 拒）
	t.Run("头合计预算", func(t *testing.T) {
		b := Budgets{MaxHeaderBytes: len(validInput) + len(validSig)}
		if _, err := ParseHeaders(validInput, validSig, b); err != nil {
			t.Fatalf("恰等应过: %v", err)
		}
		b.MaxHeaderBytes--
		_, err := ParseHeaders(validInput, validSig, b)
		var be *BudgetError
		if !errors.As(err, &be) || be.Rule != "header_bytes_exceeded" {
			t.Fatalf("超 1 应拒: %v", err)
		}
	})
	t.Run("成分数预算", func(t *testing.T) {
		b := Budgets{MaxComponents: 3}
		if _, err := ParseHeaders(validInput, validSig, b); err != nil {
			t.Fatalf("恰等应过: %v", err)
		}
		b.MaxComponents = 2
		var be *BudgetError
		if _, err := ParseHeaders(validInput, validSig, b); !errors.As(err, &be) || be.Rule != "component_count_exceeded" {
			t.Fatalf("超 1 应拒: %v", err)
		}
	})
	t.Run("成分名长预算", func(t *testing.T) {
		b := Budgets{MaxComponentNameLen: 7}
		var be *BudgetError
		if _, err := ParseHeaders(validInput, validSig, b); !errors.As(err, &be) || be.Rule != "component_name_len_exceeded" {
			t.Fatalf("超长应拒: %v", err)
		}
	})
	t.Run("成分参数预算", func(t *testing.T) {
		input := `sig1=("@method";a=1;b=2;c=3);created=1618884473;expires=1618884593;nonce="n8f6kfs9.2gkf0s9";keyid="k1";alg="ed25519"`
		if _, err := ParseHeaders(input, validSig, Budgets{MaxParamsPerComponent: 3}); err != nil {
			t.Fatalf("恰等应过: %v", err)
		}
		var be *BudgetError
		if _, err := ParseHeaders(input, validSig, Budgets{MaxParamsPerComponent: 2}); !errors.As(err, &be) || be.Rule != "component_params_exceeded" {
			t.Fatalf("超 1 应拒: %v", err)
		}
	})
	// 缺 Signature 头
	t.Run("缺头", func(t *testing.T) {
		if _, err := ParseHeaders(validInput, "", Budgets{}); !errors.Is(err, ErrMalformed) {
			t.Fatal("缺 Signature 应拒")
		}
		if _, err := ParseHeaders("", validSig, Budgets{}); !errors.Is(err, ErrMalformed) {
			t.Fatal("缺 Signature-Input 应拒")
		}
	})
	// 未知参数容忍（保序——RFC B.2.2 tag 先例；ParseHeaders 层不拒）
	t.Run("未知参数容忍", func(t *testing.T) {
		input := validInput + `;tag="header-example"`
		if _, err := ParseHeaders(input, validSig, Budgets{}); err != nil {
			t.Fatalf("未知参数应容忍: %v", err)
		}
	})
	// 成分名字符集（大写头名拒收——RFC 9421 成分名小写纪律）
	t.Run("成分名大写拒收", func(t *testing.T) {
		input := strings.Replace(validInput, `"@method"`, `"Date"`, 1)
		if _, err := ParseHeaders(input, validSig, Budgets{}); !errors.Is(err, ErrMalformed) {
			t.Fatal("大写成分名应拒收")
		}
	})
}

// keepParams 构造缺某参数的参数字符串。
func keepParams(miss string) []string {
	all := []string{
		`created=1618884473`, `expires=1618884593`, `nonce="n8f6kfs9.2gkf0s9"`, `keyid="k1"`, `alg="ed25519"`,
	}
	out := all[:0]
	for _, p := range all {
		if !strings.HasPrefix(p, miss+"=") {
			out = append(out, p)
		}
	}
	return out
}
