// instancekey_test.go 实例键/提取器/摘要单测（与 server 侧 instancekey.go 同口径
// 对齐；含黄金向量跨侧漂移防线）。
package flowguard

import (
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// TestInstanceIDGoldenVector 黄金向量（key=0123456789abcdef×2，app-1|t-1|
// jwt:user-1|3|order-42）——与 server strongflow.InstanceRefHMAC 同算法同输入
// 的线契约锚点：任一侧算法/域常量/分量序漂移都会打破本断言。
func TestInstanceIDGoldenVector(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	got := InstanceID(key, "app-1", "t-1", "jwt:user-1", 3, "order-42")
	want := "sfref:5b72c4a23f5e09d64b2ecbe276ffde58cee5eb99d6c907e50a860e10c9006ed6"
	if got != want {
		t.Fatalf("实例键黄金向量漂移: got %q want %q", got, want)
	}
}

func TestInstanceIDProperties(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	base := InstanceID(key, "app-1", "t-1", "p", 1, "order-42")
	if !strings.HasPrefix(base, "sfref:") || len(base) != len("sfref:")+64 {
		t.Fatalf("形态应为 sfref:+64hex: %q", base)
	}
	// 分量敏感性：任一维度变化即异键（实例键五维度缺一不可互换）
	if InstanceID(key, "app-2", "t-1", "p", 1, "order-42") == base {
		t.Fatal("应用维度不敏感")
	}
	if InstanceID(key, "app-1", "t-2", "p", 1, "order-42") == base {
		t.Fatal("租户维度不敏感")
	}
	if InstanceID(key, "app-1", "t-1", "q", 1, "order-42") == base {
		t.Fatal("主体维度不敏感")
	}
	if InstanceID(key, "app-1", "t-1", "p", 2, "order-42") == base {
		t.Fatal("定义版本维度不敏感（存量实例按创建时版本隔离的承载）")
	}
	if InstanceID(key, "app-1", "t-1", "p", 1, "order-43") == base {
		t.Fatal("实例引用维度不敏感")
	}
	// 密钥缺席/非法 → 空串（调用方 UNKNOWN 放行+披露，不阻断）
	if InstanceID(nil, "app-1", "t-1", "p", 1, "order-42") != "" {
		t.Fatal("nil 密钥应空串")
	}
	if InstanceID([]byte("short"), "app-1", "t-1", "p", 1, "order-42") != "" {
		t.Fatal("非 32B 密钥应空串")
	}
	if InstanceID(key, "app-1", "t-1", "p", 1, "") != "" {
		t.Fatal("空实例引用应空串")
	}
}

func TestExtractInstanceRef(t *testing.T) {
	p := &parser.Parsed{
		RawPath: "/v1/orders/o-9/pay",
		Query:   map[string]string{"order_id": "o-7", "empty": ""},
	}
	// query 形态
	if got := ExtractInstanceRef("query:order_id", p); got != "o-7" {
		t.Fatalf("query 提取 = %q", got)
	}
	// path 形态：0 起段序（去一个前导斜杠；server derivePathSegments 同口径）
	if got := ExtractInstanceRef("path:2", p); got != "o-9" {
		t.Fatalf("path:2 提取 = %q，应 o-9", got)
	}
	if got := ExtractInstanceRef("path:0", p); got != "v1" {
		t.Fatalf("path:0 提取 = %q，应 v1", got)
	}
	// 失败形态：参数缺失/空值/段序越界/负序/非数/未知来源/nil parsed
	for _, bad := range []string{"query:absent", "query:empty", "path:9", "path:-1", "path:x", "header:x", ""} {
		if got := ExtractInstanceRef(bad, p); got != "" {
			t.Errorf("ExtractInstanceRef(%q) = %q，应空串", bad, got)
		}
	}
	if got := ExtractInstanceRef("query:order_id", nil); got != "" {
		t.Fatal("nil parsed 应空串")
	}
	if got := ExtractInstanceRef("path:0", &parser.Parsed{RawPath: "/"}); got != "" {
		t.Fatal("根路径无段应空串")
	}
	// C-08 回归：// 与 ./.. 路径段对齐
	for _, raw := range []string{"//v1//orders//o-9//pay", "/./v1/x/../orders/o-9/pay"} {
		if got := ExtractInstanceRef("path:2", &parser.Parsed{RawPath: raw}); got != "o-9" {
			t.Fatalf("ExtractInstanceRef(path:2, %q) = %q，应 o-9", raw, got)
		}
	}
}

func TestParamDigestDeterminism(t *testing.T) {
	a := &parser.Parsed{
		Query:      map[string]string{"x": "1", "y": "2"},
		JSONValues: map[string]string{"a.b": "v1", "a.c": "v2"},
	}
	b := &parser.Parsed{
		Query:      map[string]string{"y": "2", "x": "1"},
		JSONValues: map[string]string{"a.c": "v2", "a.b": "v1"},
	}
	if ParamDigest(a) != ParamDigest(b) {
		t.Fatal("同内容不同序必须同摘要（排序归一）")
	}
	c := &parser.Parsed{Query: map[string]string{"x": "1", "y": "3"}}
	if ParamDigest(a) == ParamDigest(c) {
		t.Fatal("异参数值必须异摘要")
	}
	if ParamDigest(nil) == ParamDigest(&parser.Parsed{}) {
		// nil 与空 parsed 同摘要（空集哈希）——合法，确定性即可
	}
	// 截断语义（与 parser 标值留存同界 256）：仅 256 前缀之后相异的值摘要相同——
	// 摘要精度上限如实固定，不夸大（同键同摘要幂等重放的判定输入即此前缀口径）
	long := strings.Repeat("v", 512)
	d1 := &parser.Parsed{Query: map[string]string{"x": long}}
	d2 := &parser.Parsed{Query: map[string]string{"x": long + "tail"}}
	if ParamDigest(d1) != ParamDigest(d2) {
		t.Fatal("256 截断同前缀值应同摘要（截断口径固定）")
	}
	d3 := &parser.Parsed{Query: map[string]string{"x": long[:255] + "w"}}
	if ParamDigest(d1) == ParamDigest(d3) {
		t.Fatal("256 前缀内相异必须异摘要")
	}
}

func TestIdempotencyKeyHash(t *testing.T) {
	hdr := map[string]string{"Idempotency-Key": "k-1"}
	get := func(k string) string { return hdr[k] }
	h := IdempotencyKeyHash(get)
	if h == "" || len(h) != 64 {
		t.Fatalf("幂等键哈希形态: %q", h)
	}
	// 优先级：Idempotency-Key 优先于 X-Idempotency-Key
	hdr["X-Idempotency-Key"] = "k-2"
	if IdempotencyKeyHash(get) != h {
		t.Fatal("优先级漂移")
	}
	delete(hdr, "Idempotency-Key")
	if IdempotencyKeyHash(get) == h {
		t.Fatal("回退键未生效")
	}
	delete(hdr, "X-Idempotency-Key")
	if IdempotencyKeyHash(get) != "" {
		t.Fatal("无幂等键应空串（不参与幂等语义）")
	}
}
