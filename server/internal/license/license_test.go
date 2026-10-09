// license_test.go .lic 解析/验签/字段校验/到期判定/指纹校验/公钥表加载单元测试。
// 样本 .lic 由测试内 ed25519.GenerateKey 生成密钥对签发；
// buildPayloadForTest 复刻签发侧 buildPayload/canonicalJSON 逻辑
// （事实来源：授权中心仓库 server/internal/licenses/payload.go，语义不得偏离）。
package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// testLicenseRec 测试样本授权参数。
type testLicenseRec struct {
	LicenseID          string
	LicenseType        string
	Product            string
	Customer           string
	Perpetual          bool
	ExpiresAt          *time.Time
	MachineFingerprint string
	Quotas             Quotas
	Features           []string
	Version            int
}

// buildPayloadForTest 复刻签发侧 buildPayload（expires_at YYYY-MM-DD 或 null、
// machine_fingerprint 字符串或 null、license_type 缺省 FORMAL、quotas 固定三键、
// features 排序非 nil）。
func buildPayloadForTest(rec testLicenseRec, issuedAt time.Time, keyID string) map[string]interface{} {
	var expires interface{}
	if !rec.Perpetual && rec.ExpiresAt != nil {
		expires = rec.ExpiresAt.Format("2006-01-02")
	}
	var fingerprint interface{}
	if rec.MachineFingerprint != "" {
		fingerprint = rec.MachineFingerprint
	}
	licenseType := rec.LicenseType
	if licenseType == "" {
		licenseType = TypeFormal
	}
	features := rec.Features
	if features == nil {
		features = []string{}
	}
	sort.Strings(features)
	return map[string]interface{}{
		"license_id":          rec.LicenseID,
		"license_type":        licenseType,
		"product":             rec.Product,
		"customer":            rec.Customer,
		"issued_at":           issuedAt.UTC().Format(time.RFC3339),
		"expires_at":          expires,
		"perpetual":           rec.Perpetual,
		"machine_fingerprint": fingerprint,
		"quotas": map[string]int64{
			"max_applications":  rec.Quotas.MaxApplications,
			"max_api_endpoints": rec.Quotas.MaxAPIEndpoints,
			"max_qps":           rec.Quotas.MaxQPS,
		},
		"features": features,
		"version":  rec.Version,
		"key_id":   keyID,
	}
}

// signTestLicense 用测试私钥签发样本 .lic 文件字节
// （签名输入 = json.Marshal(payload map)，与签发侧 canonicalJSON 逐字节一致）。
func signTestLicense(t *testing.T, priv ed25519.PrivateKey, payload map[string]interface{}) []byte {
	t.Helper()
	canonical, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("canonical payload: %v", err)
	}
	sig := ed25519.Sign(priv, canonical)
	out, err := json.Marshal(map[string]interface{}{
		"payload":   payload,
		"signature": hex.EncodeToString(sig),
	})
	if err != nil {
		t.Fatalf("marshal lic file: %v", err)
	}
	return out
}

// newTestKey 生成测试密钥对，返回公钥表条目与私钥。
func newTestKey(t *testing.T, keyID string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

// validSample 默认合法样本（wdsp、带配额与能力点、客户名含 HTML 特殊字符与中文字符，
// 锁定 json.Marshal 转义口径与签发侧逐字节一致）。
func validSample() testLicenseRec {
	expires := time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC)
	return testLicenseRec{
		LicenseID: "LIC-2026-0001",
		Product:   "wdsp",
		Customer:  "测试<>&客户",
		ExpiresAt: &expires,
		Quotas:    Quotas{MaxApplications: 10, MaxAPIEndpoints: 100, MaxQPS: 50},
		Features:  []string{"waf", "api"},
		Version:   1,
	}
}

const testKeyID = "key-20260827-test"

func TestVerifyAndParseOK(t *testing.T) {
	pub, priv := newTestKey(t, testKeyID)
	keys := map[string]ed25519.PublicKey{testKeyID: pub}
	issuedAt := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	fileBytes := signTestLicense(t, priv, buildPayloadForTest(validSample(), issuedAt, testKeyID))

	f, err := ParseFile(fileBytes)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	m, err := Verify(f.Payload, f.Signature, keys)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	p, err := ParsePayload(m)
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if p.LicenseID != "LIC-2026-0001" || p.Product != "wdsp" || p.Customer != "测试<>&客户" {
		t.Fatalf("unexpected payload: %+v", p)
	}
	if p.LicenseType != TypeFormal {
		t.Fatalf("license_type 缺省应为 FORMAL，got %q", p.LicenseType)
	}
	if p.Quotas != (Quotas{MaxApplications: 10, MaxAPIEndpoints: 100, MaxQPS: 50}) {
		t.Fatalf("quotas 解析错误: %+v", p.Quotas)
	}
	if len(p.Features) != 2 || p.Features[0] != "api" || p.Features[1] != "waf" {
		t.Fatalf("features 解析错误（签发侧排序口径）: %v", p.Features)
	}
	if p.ExpiresAt == nil || p.ExpiresAt.Format("2006-01-02") != "2099-12-31" {
		t.Fatalf("expires_at 解析错误: %v", p.ExpiresAt)
	}
	if p.KeyID != testKeyID || p.Version != 1 || p.Perpetual {
		t.Fatalf("payload 字段错误: %+v", p)
	}
	if p.Expired(time.Date(2099, 12, 31, 12, 0, 0, 0, time.UTC)) {
		t.Fatal("到期日当天不应判过期")
	}
}

func TestVerifyTamperedPayload(t *testing.T) {
	pub, priv := newTestKey(t, testKeyID)
	keys := map[string]ed25519.PublicKey{testKeyID: pub}
	fileBytes := signTestLicense(t, priv, buildPayloadForTest(validSample(), time.Now(), testKeyID))

	// 篡改 payload（改 customer），签名不变
	var file map[string]json.RawMessage
	if err := json.Unmarshal(fileBytes, &file); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(file["payload"], &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	payload["customer"] = "篡改客户"
	tampered, _ := json.Marshal(payload)
	if _, err := Verify(tampered, string(mustRawString(t, file["signature"])), keys); !errors.Is(err, ErrSignature) {
		t.Fatalf("篡改后应判验签失败，got %v", err)
	}
}

func TestVerifyUnknownKeyID(t *testing.T) {
	_, priv := newTestKey(t, testKeyID)
	otherPub, _ := newTestKey(t, "key-other")
	keys := map[string]ed25519.PublicKey{"key-other": otherPub}
	// 样本 key_id 为 testKeyID，但公钥表只有 key-other
	fileBytes := signTestLicense(t, priv, buildPayloadForTest(validSample(), time.Now(), testKeyID))
	f, _ := ParseFile(fileBytes)
	if _, err := Verify(f.Payload, f.Signature, keys); !errors.Is(err, ErrSignature) {
		t.Fatalf("未知 key_id 应判验签失败，got %v", err)
	}
}

func TestVerifyNoKeysFailClosed(t *testing.T) {
	_, priv := newTestKey(t, testKeyID)
	fileBytes := signTestLicense(t, priv, buildPayloadForTest(validSample(), time.Now(), testKeyID))
	f, _ := ParseFile(fileBytes)
	if _, err := Verify(f.Payload, f.Signature, nil); !errors.Is(err, ErrSignature) {
		t.Fatalf("无公钥配置应 fail-closed，got %v", err)
	}
	if _, err := Verify(f.Payload, f.Signature, map[string]ed25519.PublicKey{}); !errors.Is(err, ErrSignature) {
		t.Fatalf("空公钥表应 fail-closed，got %v", err)
	}
}

func TestParseFileMalformed(t *testing.T) {
	if _, err := ParseFile([]byte("not json")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("非 JSON 应判格式错误，got %v", err)
	}
	if _, err := ParseFile([]byte(`{"signature":"ab"}`)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("缺 payload 应判格式错误，got %v", err)
	}
	if _, err := ParseFile([]byte(`{"payload":{}}`)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("缺 signature 应判格式错误，got %v", err)
	}
}

func TestVerifySignatureFormat(t *testing.T) {
	if _, err := Verify(json.RawMessage(`{"key_id":"k1"}`), "zz", map[string]ed25519.PublicKey{"k1": {}}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("签名非 hex 应判格式错误，got %v", err)
	}
	if _, err := Verify(json.RawMessage(`{"key_id":"k1"}`), hex.EncodeToString([]byte("short")), map[string]ed25519.PublicKey{"k1": {}}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("签名长度非法应判格式错误，got %v", err)
	}
	if _, err := Verify(json.RawMessage(`[1,2]`), hex.EncodeToString(make([]byte, 64)), nil); !errors.Is(err, ErrMalformed) {
		t.Fatalf("payload 非对象应判格式错误，got %v", err)
	}
	if _, err := Verify(json.RawMessage(`{"a":1}`), hex.EncodeToString(make([]byte, 64)), nil); !errors.Is(err, ErrMalformed) {
		t.Fatalf("缺 key_id 应判格式错误，got %v", err)
	}
}

func TestExpiredBoundaries(t *testing.T) {
	expires := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	p := &Payload{ExpiresAt: &expires}
	cases := []struct {
		name    string
		now     time.Time
		expired bool
	}{
		{"到期日凌晨", time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), false},
		{"到期日中午", time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC), false},
		{"到期日 23:59:59（含当天边界）", time.Date(2026, 9, 1, 23, 59, 59, 0, time.UTC), false},
		{"次日 00:00:00", time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC), true},
		{"远未来", time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{"到期前一日", time.Date(2026, 8, 31, 23, 59, 59, 0, time.UTC), false},
	}
	for _, c := range cases {
		if got := p.Expired(c.now); got != c.expired {
			t.Fatalf("%s：Expired=%v，期望 %v", c.name, got, c.expired)
		}
	}
	// 永久授权永不过期
	pp := &Payload{Perpetual: true}
	if pp.Expired(time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("perpetual 授权不应过期")
	}
}

func TestCheckFingerprint(t *testing.T) {
	bound := &Payload{MachineFingerprint: "sha256:abc123"}
	if err := bound.CheckFingerprint("sha256:abc123"); err != nil {
		t.Fatalf("指纹匹配应通过，got %v", err)
	}
	if err := bound.CheckFingerprint("sha256:other"); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("指纹不匹配应判失败，got %v", err)
	}
	if err := bound.CheckFingerprint(""); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("宿主机无指纹材料应判失败（不绕过），got %v", err)
	}
	unbound := &Payload{}
	if err := unbound.CheckFingerprint(""); err != nil {
		t.Fatalf("未绑定指纹应跳过校验，got %v", err)
	}
	if err := unbound.CheckFingerprint("sha256:any"); err != nil {
		t.Fatalf("未绑定指纹不应受宿主材料影响，got %v", err)
	}
}

func TestParsePayloadValidation(t *testing.T) {
	base := buildPayloadForTest(validSample(), time.Now(), testKeyID)
	mutate := func(fn func(m map[string]interface{})) map[string]interface{} {
		raw, _ := json.Marshal(base)
		var m map[string]interface{}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		fn(m)
		return m
	}
	cases := []struct {
		name    string
		m       map[string]interface{}
		wantErr string
	}{
		{"product 非法", mutate(func(m map[string]interface{}) { m["product"] = "WAF" }), "product"},
		{"license_type 非法", mutate(func(m map[string]interface{}) { m["license_type"] = "X" }), "license_type"},
		{"license_type TRIAL 合法", mutate(func(m map[string]interface{}) { m["license_type"] = "TRIAL" }), ""},
		{"缺 license_id", mutate(func(m map[string]interface{}) { delete(m, "license_id") }), "license_id"},
		{"缺 key_id", mutate(func(m map[string]interface{}) { delete(m, "key_id") }), "key_id"},
		{"quotas 负数", mutate(func(m map[string]interface{}) {
			m["quotas"] = map[string]interface{}{"max_qps": -1}
		}), "max_qps"},
		{"quotas 非整数", mutate(func(m map[string]interface{}) {
			m["quotas"] = map[string]interface{}{"max_applications": 1.5}
		}), "max_applications"},
		{"quotas 缺省补 0", mutate(func(m map[string]interface{}) { delete(m, "quotas") }), ""},
		{"quotas 部分键", mutate(func(m map[string]interface{}) {
			m["quotas"] = map[string]interface{}{"max_qps": 5.0}
		}), ""},
		{"expires_at 格式非法", mutate(func(m map[string]interface{}) { m["expires_at"] = "2026/09/01" }), "expires_at"},
		{"非永久授权缺 expires_at", mutate(func(m map[string]interface{}) { m["expires_at"] = nil }), "expires_at"},
		{"features 元素非字符串", mutate(func(m map[string]interface{}) {
			m["features"] = []interface{}{1}
		}), "features"},
		{"perpetual 非布尔", mutate(func(m map[string]interface{}) { m["perpetual"] = "yes" }), "perpetual"},
		{"machine_fingerprint 类型非法", mutate(func(m map[string]interface{}) {
			m["machine_fingerprint"] = 123
		}), "machine_fingerprint"},
	}
	for _, c := range cases {
		_, err := ParsePayload(c.m)
		if c.wantErr == "" {
			if err != nil {
				t.Fatalf("%s：不应报错，got %v", c.name, err)
			}
			continue
		}
		if !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), c.wantErr) {
			t.Fatalf("%s：应报 %q 相关格式错误，got %v", c.name, c.wantErr, err)
		}
	}
	// 缺省值校验：quotas 删除后三键为 0；license_type 删除后 FORMAL
	p, err := ParsePayload(mutate(func(m map[string]interface{}) {
		delete(m, "quotas")
		delete(m, "license_type")
		delete(m, "features")
	}))
	if err != nil {
		t.Fatalf("缺省样本解析失败: %v", err)
	}
	if p.Quotas != (Quotas{}) || p.LicenseType != TypeFormal || len(p.Features) != 0 {
		t.Fatalf("缺省值错误: %+v", p)
	}
	// quotas 部分键：未给键为 0
	p2, err := ParsePayload(mutate(func(m map[string]interface{}) {
		m["quotas"] = map[string]interface{}{"max_qps": 5.0}
	}))
	if err != nil {
		t.Fatalf("quotas 部分键解析失败: %v", err)
	}
	if p2.Quotas != (Quotas{MaxQPS: 5}) {
		t.Fatalf("quotas 部分键缺省错误: %+v", p2.Quotas)
	}
}

func TestParseVendorKeys(t *testing.T) {
	pub1, _ := newTestKey(t, "k1")
	pub2, _ := newTestKey(t, "k2")
	src := "# 注释行\n\nk1:" + hex.EncodeToString(pub1) + "\n" +
		"bad-line-no-colon\n" +
		"k2:" + hex.EncodeToString(pub2) + ",\n" +
		"k3:nothex\n" +
		"k4:" + hex.EncodeToString([]byte("short")) + "\n"
	keys := parseVendorKeys(src)
	if len(keys) != 2 {
		t.Fatalf("应解析出 2 条有效公钥，got %d", len(keys))
	}
	if !keys["k1"].Equal(pub1) || !keys["k2"].Equal(pub2) {
		t.Fatal("公钥内容不一致")
	}
}

func TestLoadVendorKeysEmbedded(t *testing.T) {
	// 内嵌 vendor_pubkey.hex 已登记授权中心正式密钥与 TRIAL 专用密钥（含 2026-09-26
	// 轮换后的新 TRIAL 密钥，旧 TRIAL 密钥保留以支持存量未到期授权）；
	// 三条都必须解析为合法 Ed25519 公钥（key_id 与授权中心登记值一致）。
	keys := LoadVendorKeys()
	for _, keyID := range []string{"key-20260808-VX1H", "trial-9fc46ec2-c7f5-4ec0-ad88-b26a10ffb33f", "trial-67b3a728-4334-4606-9366-152a3d73d925"} {
		pub, ok := keys[keyID]
		if !ok {
			t.Fatalf("内嵌公钥表缺少已登记密钥 %s", keyID)
		}
		if len(pub) != ed25519.PublicKeySize {
			t.Fatalf("密钥 %s 公钥长度非法: %d", keyID, len(pub))
		}
	}
}

func TestReadHostFingerprint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host_fingerprint")
	if err := os.WriteFile(path, []byte("  sha256:host-fp\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	fp, err := ReadHostFingerprint(path)
	if err != nil || fp != "sha256:host-fp" {
		t.Fatalf("读取指纹失败: fp=%q err=%v", fp, err)
	}
	if _, err := ReadHostFingerprint(filepath.Join(dir, "missing")); !errors.Is(err, ErrNoFingerprintMaterial) {
		t.Fatalf("文件缺失应判无指纹材料，got %v", err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte(" \n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := ReadHostFingerprint(empty); !errors.Is(err, ErrNoFingerprintMaterial) {
		t.Fatalf("空文件应判无指纹材料，got %v", err)
	}
}

func TestHostFingerprintFileEnv(t *testing.T) {
	t.Setenv(HostFingerprintFileEnv, "/tmp/custom-fp")
	if got := HostFingerprintFile(); got != "/tmp/custom-fp" {
		t.Fatalf("env 覆盖应生效，got %q", got)
	}
}

// mustRawString 解析 JSON 字符串 RawMessage。
func mustRawString(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("unmarshal string: %v", err)
	}
	return []byte(s)
}
