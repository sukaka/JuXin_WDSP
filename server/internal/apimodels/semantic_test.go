package apimodels

import "testing"

// inferStringSemantic 词表与 statistics.go 1c 对齐：口令/令牌/邮箱/手机号/UUID 命中，
// 数值形态合理的语义（id/money）与普通参数名不命中。
func TestInferStringSemantic(t *testing.T) {
	cases := []struct {
		name, path, want string
	}{
		{"password", "password", "secret"},
		{"passwd", "passwd", "secret"},
		{"pwd", "pwd", "secret"},
		{"secret", "secret", "secret"},
		{"Password", "Password", "secret"}, // 大小写不敏感
		{"token", "token", "token"},
		{"access_token", "access_token", "token"},
		{"api_key", "api_key", "token"},
		{"apikey", "apikey", "token"},
		{"email", "email", "email"},
		{"user_email", "user_email", "email"},
		{"mobile", "mobile", "phone"},
		{"telephone", "telephone", "phone"},
		{"order_uuid", "order_uuid", "uuid"},
		{"id", "id", ""},         // id 允许数值形态，不在护栏范围
		{"amount", "amount", ""}, // money 语义允许数值
		{"username", "username", ""},
		{"page_size", "page_size", ""},
	}
	for _, tc := range cases {
		if got := inferStringSemantic(tc.name, tc.path); got != tc.want {
			t.Errorf("inferStringSemantic(%q,%q)=%q, want %q", tc.name, tc.path, got, tc.want)
		}
	}
}

// guardCandidateField 字符串语义字段强制 string 并弃置数值上下界，长度统计保留；
// 非字符串语义字段不受影响。
func TestGuardCandidateField(t *testing.T) {
	minV, maxV := 1111.0, 123456.0
	minL, maxL := 1, 12

	// 口令字段：纯数字样本学成 number → 归正 string，数值上下界清空，长度保留
	f := CandidateField{Path: "password", BaseType: "number",
		MinLength: &minL, MaxLength: &maxL, MinValue: &minV, MaxValue: &maxV}
	guardCandidateField("password", f.Path, &f)
	if f.BaseType != "string" {
		t.Fatalf("password base_type=%q, want string", f.BaseType)
	}
	if f.MinValue != nil || f.MaxValue != nil {
		t.Fatalf("password numeric bounds should be dropped, got %v/%v", f.MinValue, f.MaxValue)
	}
	if f.MinLength == nil || f.MaxLength == nil {
		t.Fatal("password length stats should be kept")
	}

	// 金额字段：数值形态合理，护栏不动
	g := CandidateField{Path: "amount", BaseType: "number", MinValue: &minV, MaxValue: &maxV}
	guardCandidateField("amount", g.Path, &g)
	if g.BaseType != "number" || g.MinValue == nil || g.MaxValue == nil {
		t.Fatalf("amount should be untouched: %+v", g)
	}
}

// isStringOnlySemantic 覆盖人工已确认语义值的判定。
func TestIsStringOnlySemantic(t *testing.T) {
	for _, sem := range []string{"secret", "token", "email", "phone", "uuid"} {
		if !isStringOnlySemantic(sem) {
			t.Errorf("%q should be string-only semantic", sem)
		}
	}
	for _, sem := range []string{"", "id", "money", "unknown"} {
		if isStringOnlySemantic(sem) {
			t.Errorf("%q should not be string-only semantic", sem)
		}
	}
}
