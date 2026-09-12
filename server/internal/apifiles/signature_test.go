// signature_test.go 文件签名验证/密钥管理测试：token 复算正反/过期/未来/kid 轮换、
// 密钥加载（缺失/损坏/密文形态）、轮换递增、HTTP 权限矩阵与 503/404 语义。
package apifiles

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apidata"
	"github.com/jiuzhang-waf/server/internal/encryption"
)

// fakeSigKV 设置表替身（内存键值；实现 SignatureSettingsKV）。
type fakeSigKV struct {
	kv     map[string]string
	ints   map[string]int
	getErr error
}

func (f *fakeSigKV) GetString(_ context.Context, group, key, def string) string {
	if v, ok := f.kv[group+"/"+key]; ok {
		return v
	}
	return def
}

func (f *fakeSigKV) GetInt(_ context.Context, group, key string, def int) int {
	if v, ok := f.ints[group+"/"+key]; ok {
		return v
	}
	return def
}

func (f *fakeSigKV) UpsertString(_ context.Context, group, key, value, _ string, _ uuid.UUID) error {
	if f.kv == nil {
		f.kv = map[string]string{}
	}
	f.kv[group+"/"+key] = value
	return nil
}

// testEncryptor 固定主密钥的真实加密服务（与生产同算法）。
func testEncryptor(t *testing.T) *encryption.Service {
	t.Helper()
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 1)
	}
	enc, err := encryption.NewWithKey(master)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// testSigKey 生成随机 32 字节密钥。
func testSigKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, signatureKeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

const (
	testSHAHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testKid    = "7"
)

// TestSignVerifyRoundTrip 真实签名串复算：正例通过；改文件名/哈希/身份指纹/密钥任一则不通过。
func TestSignVerifyRoundTrip(t *testing.T) {
	key := testSigKey(t)
	now := time.Now().UTC()
	ts := now.Add(-time.Hour).Unix()
	token := SignFileToken(key, testKid, "report.pdf", testSHAHex, ts, "auth:user-1")

	res := VerifyFileToken(key, testKid, "report.pdf", testSHAHex, token, "auth:user-1", 30, now)
	if !res.Valid || res.Kid != testKid || res.SignedAt == "" {
		t.Fatalf("valid token rejected: %+v", res)
	}
	if res.IdentityFPPrefix != "auth:use" {
		t.Fatalf("identity_fp_prefix=%q, want %q", res.IdentityFPPrefix, "auth:use")
	}
	// 匿名口径（无 identity_fp）：以空串签名/复算
	anon := SignFileToken(key, testKid, "report.pdf", testSHAHex, ts, "")
	res = VerifyFileToken(key, testKid, "report.pdf", testSHAHex, anon, "", 30, now)
	if !res.Valid || res.IdentityFPPrefix != "" {
		t.Fatalf("anon token: %+v", res)
	}
	// 篡改任一绑定字段 → HMAC 不通过
	for name, mutate := range map[string]struct{ filename, sha, fp string }{
		"filename": {"evil.pdf", testSHAHex, "auth:user-1"},
		"sha":      {"report.pdf", strings.Repeat("0", 64), "auth:user-1"},
		"identity": {"report.pdf", testSHAHex, "auth:user-2"},
	} {
		res := VerifyFileToken(key, testKid, mutate.filename, mutate.sha, token, mutate.fp, 30, now)
		if res.Valid || !strings.Contains(res.Reason, "签名不匹配") {
			t.Fatalf("%s tampered: %+v", name, res)
		}
	}
	// 错误密钥
	if res := VerifyFileToken(testSigKey(t), testKid, "report.pdf", testSHAHex, token, "auth:user-1", 30, now); res.Valid {
		t.Fatal("wrong key accepted")
	}
	// kid 不匹配（轮换/伪造）
	res = VerifyFileToken(key, "8", "report.pdf", testSHAHex, token, "auth:user-1", 30, now)
	if res.Valid || !strings.Contains(res.Reason, "kid") {
		t.Fatalf("kid mismatch: %+v", res)
	}
}

// TestVerifyMalformedToken 非法形态 token 一律 invalid（不 panic）。
func TestVerifyMalformedToken(t *testing.T) {
	key := testSigKey(t)
	now := time.Now().UTC()
	for _, tok := range []string{
		"", "nope", "jzsig1.1", "v2.1.1700000000." + strings.Repeat("a", 64),
		"jzsig1..1700000000." + strings.Repeat("a", 64),
		"jzsig1.1.notanumber." + strings.Repeat("a", 64),
		"jzsig1.1.1700000000.tooshort",
		"jzsig1.1.1700000000." + strings.Repeat("zz", 32),
		"jzsig1.1.1700000000." + strings.Repeat("a", 64) + ".extra",
	} {
		if res := VerifyFileToken(key, "1", "a.pdf", testSHAHex, tok, "", 30, now); res.Valid {
			t.Fatalf("malformed %q accepted", tok)
		}
	}
}

// TestVerifyExpiry 过期/未来时间戳判定（maxAge 天界 + 钟差容忍 + 非法 maxAge 回退默认）。
func TestVerifyExpiry(t *testing.T) {
	key := testSigKey(t)
	now := time.Now().UTC()
	sign := func(ts int64) string { return SignFileToken(key, testKid, "a.pdf", testSHAHex, ts, "") }

	// 31 天前签名，有效期 30 天 → 过期
	old := sign(now.AddDate(0, 0, -31).Unix())
	res := VerifyFileToken(key, testKid, "a.pdf", testSHAHex, old, "", 30, now)
	if res.Valid || !strings.Contains(res.Reason, "已过期") {
		t.Fatalf("expired token: %+v", res)
	}
	// 29 天前 → 有效
	recent := sign(now.AddDate(0, 0, -29).Unix())
	if res := VerifyFileToken(key, testKid, "a.pdf", testSHAHex, recent, "", 30, now); !res.Valid {
		t.Fatalf("recent token rejected: %+v", res)
	}
	// 未来 1 小时 → 拒绝；未来 1 分钟（钟差内）→ 放行
	future := sign(now.Add(time.Hour).Unix())
	if res := VerifyFileToken(key, testKid, "a.pdf", testSHAHex, future, "", 30, now); res.Valid {
		t.Fatalf("future token accepted: %+v", res)
	}
	skew := sign(now.Add(time.Minute).Unix())
	if res := VerifyFileToken(key, testKid, "a.pdf", testSHAHex, skew, "", 30, now); !res.Valid {
		t.Fatalf("skew token rejected: %+v", res)
	}
	// maxAge 非法（0/负）回退默认 30 天：40 天前签名过期、20 天前有效
	if res := VerifyFileToken(key, testKid, "a.pdf", testSHAHex, sign(now.AddDate(0, 0, -40).Unix()), "", 0, now); res.Valid {
		t.Fatal("maxAge=0 should fall back to default 30d")
	}
	if res := VerifyFileToken(key, testKid, "a.pdf", testSHAHex, sign(now.AddDate(0, 0, -20).Unix()), "", -5, now); !res.Valid {
		t.Fatal("maxAge<0 should fall back to default 30d")
	}
}

// TestLoadFileSignatureKey 加载：未配置 ErrSignatureKeyNotConfigured / 损坏 ErrSignatureKeyInvalid / 正例。
func TestLoadFileSignatureKey(t *testing.T) {
	enc := testEncryptor(t)
	ctx := context.Background()
	// 未装配
	if _, _, err := LoadFileSignatureKey(ctx, nil, enc); err == nil {
		t.Fatal("nil kv should fail")
	}
	if _, _, err := LoadFileSignatureKey(ctx, &fakeSigKV{}, nil); err == nil {
		t.Fatal("nil enc should fail")
	}
	// 未配置
	if _, _, err := LoadFileSignatureKey(ctx, &fakeSigKV{}, enc); err != ErrSignatureKeyNotConfigured {
		t.Fatalf("empty kv: err=%v, want ErrSignatureKeyNotConfigured", err)
	}
	// 密文损坏
	bad := &fakeSigKV{kv: map[string]string{signatureSettingsGroup + "/" + signatureKeySetting: "!!!not-cipher!!!"}}
	if _, _, err := LoadFileSignatureKey(ctx, bad, enc); err == nil || err == ErrSignatureKeyNotConfigured {
		t.Fatalf("corrupt cipher: err=%v", err)
	}
	// 正例：先轮换生成，再加载
	kv := &fakeSigKV{}
	kid, err := RotateFileSignatureKey(ctx, kv, enc, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	key, gotKid, err := LoadFileSignatureKey(ctx, kv, enc)
	if err != nil || gotKid != kid || len(key) != signatureKeyBytes {
		t.Fatalf("load: key=%d kid=%q err=%v", len(key), gotKid, err)
	}
	// 密钥存在但 kid 缺失 → 状态不一致如实报错
	kv2 := &fakeSigKV{kv: map[string]string{signatureSettingsGroup + "/" + signatureKeySetting: kv.kv[signatureSettingsGroup+"/"+signatureKeySetting]}}
	if _, _, err := LoadFileSignatureKey(ctx, kv2, enc); err == nil {
		t.Fatal("key without kid should fail")
	}
}

// TestRotateFileSignatureKey 轮换：kid 递增、旧 token 失效（kid 不匹配）、密钥材料确实更换。
func TestRotateFileSignatureKey(t *testing.T) {
	enc := testEncryptor(t)
	ctx := context.Background()
	kv := &fakeSigKV{}
	kid1, err := RotateFileSignatureKey(ctx, kv, enc, uuid.Nil)
	if err != nil || kid1 != "1" {
		t.Fatalf("first rotate: kid=%q err=%v", kid1, err)
	}
	key1, _, err := LoadFileSignatureKey(ctx, kv, enc)
	if err != nil {
		t.Fatal(err)
	}
	// 落库值须为密文（不含密钥明文 hex）
	stored := kv.kv[signatureSettingsGroup+"/"+signatureKeySetting]
	if stored == "" || len(stored) == 64 {
		t.Fatalf("stored key looks like plaintext hex: %q", stored)
	}
	token := SignFileToken(key1, kid1, "a.pdf", testSHAHex, time.Now().Unix(), "")
	kid2, err := RotateFileSignatureKey(ctx, kv, enc, uuid.Nil)
	if err != nil || kid2 != "2" {
		t.Fatalf("second rotate: kid=%q err=%v", kid2, err)
	}
	key2, gotKid, err := LoadFileSignatureKey(ctx, kv, enc)
	if err != nil || gotKid != "2" {
		t.Fatalf("reload: kid=%q err=%v", gotKid, err)
	}
	if string(key1) == string(key2) {
		t.Fatal("key material not changed after rotate")
	}
	// 旧 kid token 失效（v1 仅保留当前密钥）
	if res := VerifyFileToken(key2, kid2, "a.pdf", testSHAHex, token, "", 30, time.Now().UTC()); res.Valid {
		t.Fatal("old kid token still valid after rotate")
	}
	// kid 损坏（非正整数）→ 轮换如实报错
	kv.kv[signatureSettingsGroup+"/"+signatureKidSetting] = "abc"
	if _, err := RotateFileSignatureKey(ctx, kv, enc, uuid.Nil); err == nil {
		t.Fatal("corrupt kid should fail rotate")
	}
}

// newSignatureMux 装配签名路由（内存设置 + 真实加密，无审计服务）。
func newSignatureMux(kv SignatureSettingsKV, enc SignatureEncryptor, authzFn func(http.Handler) http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterSignatureRoutes(mux, authzFn, NewSignatureHandler(kv, enc, nil))
	return mux
}

// decodeVerifyResp 解码验证响应 data 段。
func decodeVerifyResp(t *testing.T, rr *httptest.ResponseRecorder) VerifyResult {
	t.Helper()
	var resp struct {
		Data VerifyResult `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rr.Body.String())
	}
	return resp.Data
}

// 权限矩阵：verify/key 读权限、rotate 写权限；未登录 401 / 无权限 403。
func TestSignaturePermissionMatrix(t *testing.T) {
	kv := &fakeSigKV{}
	enc := testEncryptor(t)
	cases := []struct {
		name string
		url  string
		body string
		perm string
	}{
		{"verify", "/api/v1/api-security/file-signature/verify",
			`{"filename":"a.pdf","content_sha256_hex":"` + testSHAHex + `","token":"x"}`, apidata.PermDataRead},
		{"key", "/api/v1/api-security/file-signature/key", "", apidata.PermDataRead},
		{"rotate", "/api/v1/api-security/file-signature/key/rotate", "{}", apidata.PermDataManage},
	}
	for _, tc := range cases {
		method := http.MethodPost
		if tc.name == "key" {
			method = http.MethodGet
		}
		if rr := doJSON(t, newSignatureMux(kv, enc, noPrincipal), method, tc.url, tc.body); rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s anon: status=%d, want 401", tc.name, rr.Code)
		}
		if rr := doJSON(t, newSignatureMux(kv, enc, injectPrincipal("other.read")), method, tc.url, tc.body); rr.Code != http.StatusForbidden {
			t.Fatalf("%s noperm: status=%d, want 403", tc.name, rr.Code)
		}
		if tc.perm == apidata.PermDataManage {
			if rr := doJSON(t, newSignatureMux(kv, enc, injectPrincipal(apidata.PermDataRead)), method, tc.url, tc.body); rr.Code != http.StatusForbidden {
				t.Fatalf("%s with read perm: status=%d, want 403", tc.name, rr.Code)
			}
		}
		rr := doJSON(t, newSignatureMux(kv, enc, injectPrincipal(tc.perm)), method, tc.url, tc.body)
		if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
			t.Fatalf("%s authorized: status=%d body=%s", tc.name, rr.Code, rr.Body.String())
		}
	}
}

// TestSignatureVerifyHTTP 端到端（HTTP）：密钥缺失 503 → rotate → kid 查询 →
// 真实签名串正反面验证 → 输入校验 400。
func TestSignatureVerifyHTTP(t *testing.T) {
	kv := &fakeSigKV{}
	enc := testEncryptor(t)
	mux := newSignatureMux(kv, enc, injectPrincipal(apidata.PermDataRead, apidata.PermDataManage))
	verifyURL := "/api/v1/api-security/file-signature/verify"
	validBody := func(token string) string {
		return `{"filename":"report.pdf","content_sha256_hex":"` + testSHAHex + `","token":"` + token + `"}`
	}

	// 密钥未配置：verify 503、key 查询 404
	if rr := doJSON(t, mux, http.MethodPost, verifyURL, validBody("jzsig1.1.1700000000."+strings.Repeat("a", 64))); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("verify without key: status=%d, want 503 (%s)", rr.Code, rr.Body.String())
	}
	if rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/file-signature/key", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("key without rotate: status=%d, want 404", rr.Code)
	}

	// rotate → kid=1
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/file-signature/key/rotate", "{}")
	if rr.Code != http.StatusOK {
		t.Fatalf("rotate: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var kidResp struct {
		Data struct {
			Kid string `json:"kid"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &kidResp); err != nil || kidResp.Data.Kid != "1" {
		t.Fatalf("rotate resp: %v %+v", err, kidResp)
	}
	// GET key 返回 kid（不含密钥材料）
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/file-signature/key", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("get key: status=%d", rr.Code)
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &kidResp); err != nil || kidResp.Data.Kid != "1" {
		t.Fatalf("get key resp: %v body=%s", err, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), kv.kv[signatureSettingsGroup+"/"+signatureKeySetting]) {
		t.Fatal("key endpoint leaks key material")
	}

	// 真实签名串（用落库密钥复算）→ valid
	key, kid, err := LoadFileSignatureKey(context.Background(), kv, enc)
	if err != nil {
		t.Fatal(err)
	}
	token := SignFileToken(key, kid, "report.pdf", testSHAHex, time.Now().UTC().Unix(), "")
	rr = doJSON(t, mux, http.MethodPost, verifyURL, validBody(token))
	if rr.Code != http.StatusOK {
		t.Fatalf("verify: status=%d body=%s", rr.Code, rr.Body.String())
	}
	res := decodeVerifyResp(t, rr)
	if !res.Valid || res.Kid != "1" || res.SignedAt == "" {
		t.Fatalf("verify resp: %+v", res)
	}
	// 篡改 → valid=false（200 + 结论字段）
	tampered := SignFileToken(key, kid, "evil.pdf", testSHAHex, time.Now().UTC().Unix(), "")
	res = decodeVerifyResp(t, doJSON(t, mux, http.MethodPost, verifyURL, validBody(tampered)))
	if res.Valid || res.Reason == "" {
		t.Fatalf("tampered resp: %+v", res)
	}
	// 过期（有效期设置 1 天，签名 2 天前）
	kv.ints = map[string]int{SettingsGroup + "/" + SettingsKeySignatureMaxAgeDays: 1}
	old := SignFileToken(key, kid, "report.pdf", testSHAHex, time.Now().UTC().AddDate(0, 0, -2).Unix(), "")
	res = decodeVerifyResp(t, doJSON(t, mux, http.MethodPost, verifyURL, validBody(old)))
	if res.Valid || !strings.Contains(res.Reason, "已过期") {
		t.Fatalf("expired resp: %+v", res)
	}
	// 输入校验 400：缺 filename / 坏 sha / 空 token / 超长 identity_fp
	for _, body := range []string{
		`{"filename":"","content_sha256_hex":"` + testSHAHex + `","token":"x"}`,
		`{"filename":"a.pdf","content_sha256_hex":"xyz","token":"x"}`,
		`{"filename":"a.pdf","content_sha256_hex":"` + testSHAHex + `","token":""}`,
		`{"filename":"a.pdf","content_sha256_hex":"` + testSHAHex + `","token":"x","identity_fp":"` + strings.Repeat("f", 129) + `"}`,
	} {
		if rr := doJSON(t, mux, http.MethodPost, verifyURL, body); rr.Code != http.StatusBadRequest {
			t.Fatalf("body %s: status=%d, want 400", body, rr.Code)
		}
	}
	// 大写 sha 归一小写后验证通过
	upperBody := `{"filename":"report.pdf","content_sha256_hex":"` + strings.ToUpper(testSHAHex) + `","token":"` + token + `"}`
	if res := decodeVerifyResp(t, doJSON(t, mux, http.MethodPost, verifyURL, upperBody)); !res.Valid {
		t.Fatalf("upper-case sha rejected: %+v", res)
	}
}
