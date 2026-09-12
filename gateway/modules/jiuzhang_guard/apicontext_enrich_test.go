// apicontext_enrich_test.go 统一上下文 §7 字段产出挂接测试：
// device_fingerprint 与 identitybehavior.BrowserFingerprint 同口径对拍，
// object_identifiers 经 enrichContextIdentifiers 进统一上下文（只记哈希）。
package jiuzhang_guard

import (
	"net/http/httptest"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
)

// 对拍：parser.DeriveDeviceFingerprint 与 identitybehavior BrowserFingerprint
// 同输入同盐输出逐字节一致（跨模块算法重复实现的一致性锁定）。
func TestDeviceFingerprintParityWithIdentityBehavior(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/users/42", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15")
	r.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	r.Header.Set("Accept-Encoding", "gzip, deflate, br")
	r.Header.Set("Accept", "text/html,application/xhtml+xml")

	id := identitybehavior.ResolveIdentity(r, "salt-parity", "203.0.113.7")
	got := parser.DeriveDeviceFingerprint("salt-parity", r.Header)
	if id.BrowserFingerprint == "" || got != id.BrowserFingerprint {
		t.Fatalf("parity broken: parser=%q identitybehavior=%q", got, id.BrowserFingerprint)
	}
	// 无 UA 两侧均不产出
	r2 := httptest.NewRequest("GET", "/v1/ping", nil)
	id2 := identitybehavior.ResolveIdentity(r2, "salt-parity", "203.0.113.7")
	if id2.BrowserFingerprint != "" || parser.DeriveDeviceFingerprint("salt-parity", r2.Header) != "" {
		t.Fatal("empty UA must yield empty fingerprint on both sides")
	}
}

// enrichContextIdentifiers：设备指纹与对象标识哈希写入统一上下文；重复调用不翻倍；
// parsed 为 nil 时仅头部设备指纹产出。
func TestEnrichContextIdentifiers(t *testing.T) {
	g := &Guard{IdentitySalt: "salt-enrich"}
	r := httptest.NewRequest("GET", "/v1/users/42", nil)
	r.Header.Set("User-Agent", "test-agent/1.0")

	rc := dsctx.New("req-enrich", dsctx.DefaultParseLimits())
	parsed := &parser.Parsed{
		RawPath:        "/v1/users/42",
		NormalizedPath: "/v1/users/{id}",
		JSONValues:     map[string]string{"id": "42", "note": "plain"},
	}
	g.enrichContextIdentifiers(r, rc, parsed)
	if rc.DeviceFingerprint == "" {
		t.Fatal("device fingerprint must be filled")
	}
	if len(rc.ObjectIdentifiers) != 2 { // path/id + body_json/id
		t.Fatalf("object identifiers = %+v, want 2 entries", rc.ObjectIdentifiers)
	}
	for _, oi := range rc.ObjectIdentifiers {
		if oi.ValueHash == "42" || len(oi.ValueHash) != 32 {
			t.Fatalf("plaintext or malformed hash leaked: %+v", oi)
		}
	}
	// 幂等：重复调用不重复追加
	g.enrichContextIdentifiers(r, rc, parsed)
	if len(rc.ObjectIdentifiers) != 2 {
		t.Fatalf("re-enrich must not duplicate: %+v", rc.ObjectIdentifiers)
	}
	// parsed 为 nil：仅设备指纹，不 panic
	rc2 := dsctx.New("req-enrich-2", dsctx.DefaultParseLimits())
	g.enrichContextIdentifiers(r, rc2, nil)
	if rc2.DeviceFingerprint == "" || len(rc2.ObjectIdentifiers) != 0 {
		t.Fatalf("nil parsed: fingerprint=%q identifiers=%v", rc2.DeviceFingerprint, rc2.ObjectIdentifiers)
	}
	// rc 为 nil 安全返回
	g.enrichContextIdentifiers(r, nil, parsed)
}
