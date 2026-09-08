package detectors

import (
	"strconv"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func TestCollectParamObservationsNoPlaintext(t *testing.T) {
	p := &parser.Parsed{
		Query:          map[string]string{"id": "12345", "q": "hello"},
		JSONFields:     map[string]string{"user.name": "string", "user.age": "number"},
		JSONValues:     map[string]string{"user.name": "alice", "user.age": "30"},
		RawPath:        "/api/users/42/orders",
		NormalizedPath: "/api/users/{id}/orders",
	}
	obs := CollectParamObservations(p)
	if len(obs) < 3 {
		t.Fatalf("want >=3 observations, got %d: %+v", len(obs), obs)
	}
	for _, o := range obs {
		if o.ValueHash == "" && o.Length > 0 {
			t.Errorf("missing hash for %+v", o)
		}
		// 明文不得出现在可序列化字段名之外的值字段——我们只有 hash/length
		if o.Name == "alice" || o.Path == "alice" {
			t.Fatal("plaintext leaked into name/path")
		}
	}
}

func TestCollectParamObservationsCap(t *testing.T) {
	q := map[string]string{}
	for i := 0; i < 100; i++ {
		q["k"+strconv.Itoa(i)] = "v"
	}
	obs := CollectParamObservations(&parser.Parsed{Query: q})
	if len(obs) != maxParamObservations {
		t.Fatalf("cap = %d, got %d", maxParamObservations, len(obs))
	}
}

// HMAC-SHA256 加盐哈希：同盐同值确定性一致，异盐不同；格式保持 16 hex；
// 缺盐走固定域分隔前缀（与 Fingerprint 同一实现，纪律同 fingerprint.go）。
func TestCollectParamObservationsSecureSaltedHash(t *testing.T) {
	p := &parser.Parsed{Query: map[string]string{"id": "12345"}}
	a := CollectParamObservationsSecure(p, "salt-a", nil, nil)
	b := CollectParamObservationsSecure(p, "salt-a", nil, nil)
	c := CollectParamObservationsSecure(p, "salt-b", nil, nil)
	legacy := CollectParamObservations(p)
	if len(a) != 1 || len(b) != 1 || len(c) != 1 || len(legacy) != 1 {
		t.Fatalf("want 1 observation each: %d/%d/%d/%d", len(a), len(b), len(c), len(legacy))
	}
	if a[0].ValueHash == "" || a[0].ValueHash != b[0].ValueHash {
		t.Fatal("same salt must produce deterministic hash")
	}
	if len(a[0].ValueHash) != 16 {
		t.Fatalf("hash format must stay 16 hex, got %q", a[0].ValueHash)
	}
	if a[0].ValueHash == c[0].ValueHash {
		t.Fatal("different salt must change hash")
	}
	// 缺盐 = 固定域分隔前缀（与 Fingerprint 同一取值）
	if legacy[0].ValueHash != Fingerprint("", "12345")[:16] {
		t.Fatal("missing salt must fall back to fixed domain prefix like Fingerprint")
	}
	if a[0].ValueHash != Fingerprint("salt-a", "12345")[:16] {
		t.Fatal("salted hash must match Fingerprint with identity_salt")
	}
}

// 敏感命中抑制：键名命中字段名词表或值命中值级规则的参数不上报 NumValue/ValueHash，
// 但保留长度/类型形态统计；未命中参数不受影响。
func TestCollectParamObservationsSecureSensitiveSuppressed(t *testing.T) {
	patterns, err := CompileSensitivePatterns(nil) // 默认表含 password 等
	if err != nil {
		t.Fatalf("compile patterns: %v", err)
	}
	rules, err := CompileSensitiveValueRules([]SensitiveValueRule{
		{DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"query", "json"}},
	})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	p := &parser.Parsed{
		Query: map[string]string{
			"password": "123456",      // 键名命中（数值形态值：抑制须同时去掉 NumValue）
			"contact":  "13800138000", // 键名未命中、值命中 phone 规则
			"page":     "2",           // 未命中：正常上报
		},
		JSONFields: map[string]string{"user.mobile": "string"},
		JSONValues: map[string]string{"user.mobile": "13912345678"}, // BODY 值命中
	}
	obs := CollectParamObservationsSecure(p, "salt", patterns, rules)
	byKey := map[string]ParamObservation{}
	for _, o := range obs {
		byKey[o.Location+":"+o.Name] = o
	}
	pw, ok := byKey["QUERY:password"]
	if !ok {
		t.Fatalf("missing password observation: %+v", obs)
	}
	if pw.ValueHash != "" || pw.NumValue != nil {
		t.Fatalf("name-hit param must suppress hash/num: %+v", pw)
	}
	if pw.Length != 6 || pw.BaseType != "number" {
		t.Fatalf("suppressed param keeps length/type stats: %+v", pw)
	}
	ct, ok := byKey["QUERY:contact"]
	if !ok || ct.ValueHash != "" || ct.NumValue != nil {
		t.Fatalf("value-hit param must suppress hash/num: %+v", ct)
	}
	mob, ok := byKey["BODY:mobile"]
	if !ok || mob.ValueHash != "" {
		t.Fatalf("BODY value-hit param must suppress hash: %+v", mob)
	}
	pg, ok := byKey["QUERY:page"]
	if !ok || pg.ValueHash == "" || pg.NumValue == nil || *pg.NumValue != 2 {
		t.Fatalf("non-sensitive param must keep hash/num: %+v", pg)
	}
	// 无词表/规则传入：不做抑制（兼容行为）
	plain := CollectParamObservationsSecure(p, "salt", nil, nil)
	for _, o := range plain {
		if o.Name == "password" && (o.ValueHash == "" || o.NumValue == nil) {
			t.Fatalf("nil word lists must not suppress: %+v", o)
		}
	}
	// 敏感值明文绝不出现在任何上报字段
	for _, o := range obs {
		if o.Name == "123456" || o.Path == "123456" {
			t.Fatalf("sensitive value leaked: %+v", o)
		}
	}
}
