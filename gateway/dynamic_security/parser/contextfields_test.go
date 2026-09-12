// contextfields_test.go 统一上下文 §7 字段产出测试：device_fingerprint 被动指纹与
// object_identifiers 对象标识哈希（口径/去重/封顶/不落明文）。
package parser

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// wantFingerprint 测试内独立复算指纹（HMAC-SHA256 截断 16 字节 hex），
// 与实现同源算法但独立书写，用于锁定构造口径不被意外改变。
func wantFingerprint(salt string, parts ...string) string {
	key := salt
	if key == "" {
		key = identityDomainPrefix
	}
	var sb strings.Builder
	for _, p := range parts {
		var lb [4]byte
		binary.BigEndian.PutUint32(lb[:], uint32(len(p)))
		sb.Write(lb[:])
		sb.WriteString(p)
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(sb.String()))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

func TestDeriveDeviceFingerprint(t *testing.T) {
	h := http.Header{
		"User-Agent":      {"Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"},
		"Accept-Language": {"zh-CN,zh;q=0.9"},
		"Accept-Encoding": {"gzip, br"},
		"Accept":          {"text/html"},
	}
	got := DeriveDeviceFingerprint("salt-1", h)
	want := wantFingerprint("salt-1", "br",
		"Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0", "zh-CN,zh;q=0.9", "gzip, br", "text/html")
	if got != want {
		t.Fatalf("device fingerprint = %q, want %q (br 域 + 四头长度前缀编码)", got, want)
	}
	// 确定性：同输入同输出；盐不同输出不同
	if got2 := DeriveDeviceFingerprint("salt-1", h); got2 != got {
		t.Fatal("device fingerprint must be deterministic")
	}
	if other := DeriveDeviceFingerprint("salt-2", h); other == got {
		t.Fatal("different salt must yield different fingerprint")
	}
	// UA 为空不产出（与 identitybehavior 一致）
	if v := DeriveDeviceFingerprint("salt-1", http.Header{"Accept": {"*/*"}}); v != "" {
		t.Fatalf("empty UA must yield empty fingerprint, got %q", v)
	}
	// 缺盐走固定域分隔前缀（与 detectors.Fingerprint 缺省口径一致）
	if v := DeriveDeviceFingerprint("", h); v != wantFingerprint("", "br",
		"Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0", "zh-CN,zh;q=0.9", "gzip, br", "text/html") {
		t.Fatalf("unsalted fingerprint must use fixed domain prefix, got %q", v)
	}
}

func TestExtractObjectIdentifiers(t *testing.T) {
	p := &Parsed{
		RawPath:        "/v1/users/42/orders/9f8b7c6d-1234-4abc-8def-0123456789ab",
		NormalizedPath: "/v1/users/{id}/orders/{uuid}",
		JSONValues:     map[string]string{"id": "42", "meta.user_id": "u-7", "note": "hello"},
		FormValues:     map[string]string{"order_id": "o-9", "memo": "x"},
	}
	got := ExtractObjectIdentifiers(p, "salt-1")
	// 路径 2 个 + body_json 2 个（id、meta.user_id）+ body_form 1 个（order_id）= 5
	if len(got) != 5 {
		t.Fatalf("object identifiers = %d, want 5: %+v", len(got), got)
	}
	byKey := map[string]dsctx.ObjectIdentifier{}
	for _, oi := range got {
		if len(oi.ValueHash) != 32 {
			t.Fatalf("value hash must be 32 hex chars, got %q", oi.ValueHash)
		}
		byKey[oi.Source+"/"+oi.Param] = oi
	}
	// 路径位置参数哈希与原始段值对应
	if oi := byKey["path/id"]; oi.ValueHash != wantFingerprint("salt-1", "obj", "42") {
		t.Fatalf("path id hash mismatch: %+v", oi)
	}
	if oi := byKey["path/uuid"]; oi.ValueHash != wantFingerprint("salt-1", "obj", "9f8b7c6d-1234-4abc-8def-0123456789ab") {
		t.Fatalf("path uuid hash mismatch: %+v", oi)
	}
	// body 主键字段（含 *_id 后缀与嵌套路径末段）
	if oi := byKey["body_json/meta.user_id"]; oi.ValueHash != wantFingerprint("salt-1", "obj", "u-7") {
		t.Fatalf("body_json user_id hash mismatch: %+v", oi)
	}
	if _, ok := byKey["body_form/order_id"]; !ok {
		t.Fatalf("body_form order_id missing: %+v", got)
	}
	// 非主键字段不收录；明文值绝不出现在输出中（哈希为定长 hex，逐字段比对原始值）
	if _, ok := byKey["body_json/note"]; ok {
		t.Fatal("non-primary-key field must not be collected")
	}
	rawValues := map[string]bool{"42": true, "9f8b7c6d-1234-4abc-8def-0123456789ab": true, "u-7": true, "o-9": true, "hello": true, "x": true}
	for _, oi := range got {
		if rawValues[oi.ValueHash] || rawValues[oi.Param] || rawValues[oi.Source] {
			t.Fatalf("plaintext value leaked into output: %+v", oi)
		}
	}
}

func TestExtractObjectIdentifiersBoundsAndDedup(t *testing.T) {
	if got := ExtractObjectIdentifiers(nil, "s"); got != nil {
		t.Fatalf("nil parsed must yield nil, got %v", got)
	}
	// 同值去重：路径 id 与 body id 同值同 param 不同 source 不去重；同 source 重复去重
	p := &Parsed{
		RawPath:        "/users/7",
		NormalizedPath: "/users/{id}",
		JSONValues:     map[string]string{"id": "7", "other.id": "7"},
	}
	got := ExtractObjectIdentifiers(p, "s")
	if len(got) != 3 { // path/id + body_json/id + body_json/other.id
		t.Fatalf("dedup mismatch: %+v", got)
	}
	// 超长值跳过（>128 非典型对象标识）
	long := strings.Repeat("a", 129)
	p2 := &Parsed{JSONValues: map[string]string{"id": long}}
	if got := ExtractObjectIdentifiers(p2, "s"); len(got) != 0 {
		t.Fatalf("oversized value must be skipped, got %+v", got)
	}
	// 条数封顶
	p3 := &Parsed{JSONValues: map[string]string{}}
	for i := 0; i < dsctx.MaxObjectIdentifiers+4; i++ {
		p3.JSONValues["id_"+strings.Repeat("x", i+1)+"_id"] = "v"
	}
	// 上一种命名不命中 *_id 规则时补精确名
	for i := 0; i < dsctx.MaxObjectIdentifiers+4; i++ {
		p3.JSONValues[strings.Repeat("k", i+1)+"_id"] = "v"
	}
	if got := ExtractObjectIdentifiers(p3, "s"); len(got) != dsctx.MaxObjectIdentifiers {
		t.Fatalf("object identifiers must cap at %d, got %d", dsctx.MaxObjectIdentifiers, len(got))
	}
	// 确定性：同输入两次输出顺序一致
	p4 := &Parsed{JSONValues: map[string]string{"b_id": "1", "a_id": "2", "id": "3"}}
	first := ExtractObjectIdentifiers(p4, "s")
	second := ExtractObjectIdentifiers(p4, "s")
	if len(first) != len(second) {
		t.Fatal("output length must be stable")
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("output order must be deterministic: %v vs %v", first, second)
		}
	}
	if first[0].Param != "a_id" || first[1].Param != "b_id" || first[2].Param != "id" {
		t.Fatalf("body keys must be sorted, got %+v", first)
	}
}
