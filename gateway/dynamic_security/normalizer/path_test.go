package normalizer

import "testing"

func TestNormalizePathDynamicSegments(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/users/123", "/users/{id}"},
		{"/users/550e8400-e29b-41d4-a716-446655440000", "/users/{uuid}"},
		{"/v1/orders/99/items/7", "/v1/orders/{id}/items/{id}"},
		{"/static/app.js", "/static/app.js"},
		{"users/1?x=1", "/users/{id}"},
		{"//a//b//", "/a/b"},
	}
	for _, c := range cases {
		got := NormalizePath(c.in)
		if got != c.want {
			t.Fatalf("%q -> %q want %q", c.in, got, c.want)
		}
	}
}

func TestEndpointKey(t *testing.T) {
	k1 := EndpointKey("get", "/users/1")
	k2 := EndpointKey("GET", "/users/99")
	if k1 != k2 {
		t.Fatalf("keys differ: %q vs %q", k1, k2)
	}
	if k1 != "GET /users/{id}" {
		t.Fatal(k1)
	}
	if EndpointKey("POST", "/users/1") == k1 {
		t.Fatal("method must distinguish endpoints")
	}
}

func TestMergeCompatible(t *testing.T) {
	if !MergeCompatible("/users/1", "/users/2") {
		t.Fatal("should merge")
	}
	if MergeCompatible("/users/1", "/orders/1") {
		t.Fatal("should not merge")
	}
}

// IdentifierShape 与路径段归一化同一形态判据：UUID > 纯数字 > 长 hex；
// 只认形态不认语义，非对象形态返回空串。
func TestIdentifierShape(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"123", "numeric"},
		{"0", "numeric"},
		{"550e8400-e29b-41d4-a716-446655440000", "uuid"},
		{"550E8400-E29B-41D4-A716-446655440000", "uuid"}, // 大小写不敏感
		{"0123456789abcdef", "hex"},
		{"0123456789ABCDEF", "hex"},
		{"1234567890123456", "numeric"}, // 纯数字优先于 hex（与 NormalizePath 一致）
		{"abc", ""},                     // 短 hex（<16）不算对象标识
		{"hello world", ""},
		{"", ""},
		{"12a", ""}, // 混合短串非任一形态
	}
	for _, c := range cases {
		if got := IdentifierShape(c.in); got != c.want {
			t.Fatalf("IdentifierShape(%q)=%q want %q", c.in, got, c.want)
		}
	}
}
