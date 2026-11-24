package apidata

import "testing"

func TestIsStandardProtocolHeader(t *testing.T) {
	for _, h := range []string{
		"sec-ch-ua-mobile",
		"Sec-CH-UA-Mobile",
		"sec-ch-ua-platform",
		"sec-fetch-mode",
		"sec-websocket-key",
		"user-agent",
		"x-forwarded-for",
		"accept-language",
	} {
		if !IsStandardProtocolHeader(h) {
			t.Errorf("IsStandardProtocolHeader(%q) = false, want true", h)
		}
	}
	for _, h := range []string{
		"",
		"x-user-phone",
		"x-mobile",
		"x-api-token",
		"authorization",
		"cookie",
	} {
		if IsStandardProtocolHeader(h) {
			t.Errorf("IsStandardProtocolHeader(%q) = true, want false", h)
		}
	}
}

func TestIsIgnoredProtocolHeaderFieldHit(t *testing.T) {
	if !IsIgnoredProtocolHeaderFieldHit("header", "sec-ch-ua-mobile", "sensitive.field") {
		t.Fatal("expected sec-ch-ua-mobile field hit to be ignored")
	}
	if !IsIgnoredProtocolHeaderFieldHit("HEADER", "Sec-CH-UA-Mobile", "SENSITIVE.FIELD") {
		t.Fatal("expected case-insensitive header field hit to be ignored")
	}
	// 值级命中绝不过滤（例如有人在 User-Agent 或 Sec-CH-UA 里塞了真实手机号）
	if IsIgnoredProtocolHeaderFieldHit("header", "sec-ch-ua-mobile", "sensitive.value") {
		t.Fatal("value-level match on header must NOT be ignored")
	}
	// 业务自定义头不过滤
	if IsIgnoredProtocolHeaderFieldHit("header", "x-user-mobile", "sensitive.field") {
		t.Fatal("custom business header must NOT be ignored")
	}
	// 非 header 位置不过滤
	if IsIgnoredProtocolHeaderFieldHit("query", "sec-ch-ua-mobile", "sensitive.field") {
		t.Fatal("non-header location must NOT be ignored")
	}
	if !IsIgnoredProtocolHeaderPath("header.sec-ch-ua-mobile", "sensitive.field") {
		t.Fatal("expected header.sec-ch-ua-mobile path to be ignored")
	}
	if IsIgnoredProtocolHeaderPath("header.sec-ch-ua-mobile", "sensitive.value") {
		t.Fatal("expected value-level header path not to be ignored")
	}
}

func TestIsIgnoredSensitiveFieldHitAndPath(t *testing.T) {
	// URL 路径字面段字段名误报（如 /mobile.zip、/mailer.zip、/remind_password.zip）应过滤
	if !IsIgnoredSensitiveFieldHit("path", "mobile.zip", "sensitive.field") {
		t.Fatal("expected path field-name hit to be ignored")
	}
	if !IsIgnoredSensitiveFieldPath("path.remind_password.zip", "sensitive.field") {
		t.Fatal("expected path.remind_password.zip structured path to be ignored")
	}
	// 路径值级命中（如 /user/13800138000）绝不过滤
	if IsIgnoredSensitiveFieldHit("path", "{id}", "sensitive.value") {
		t.Fatal("value-level path hit must NOT be ignored")
	}
	if IsIgnoredSensitiveFieldPath("path.{id}", "sensitive.value") {
		t.Fatal("value-level structured path must NOT be ignored")
	}
	// 响应体未完成检查诊断提示不是涉敏命中
	if !IsIgnoredSensitiveFieldHit("response_body", "response_body", "sensitive.response_body_unchecked") {
		t.Fatal("unchecked response body diagnostic must be ignored")
	}
	if !IsIgnoredSensitiveFieldPath("response_body.response_body", "sensitive.response_body_unchecked") {
		t.Fatal("unchecked response body path must be ignored")
	}
	// 标准协议头字段名误报继续过滤，常规载荷字段保留
	if !IsIgnoredSensitiveFieldHit("header", "sec-ch-ua-mobile", "sensitive.field") {
		t.Fatal("standard protocol header field hit must be ignored")
	}
	if IsIgnoredSensitiveFieldHit("json", "user.phone", "sensitive.field") {
		t.Fatal("json body field hit must NOT be ignored")
	}
	if IsIgnoredSensitiveFieldHit("query", "mobile", "sensitive.in_query") {
		t.Fatal("query sensitive hit must NOT be ignored")
	}
	// 值级规则判定
	for _, r := range []string{"sensitive.value", "sensitive.value_in_query", "sensitive.response_value"} {
		if !IsValueLevelSensitiveRule(r) {
			t.Errorf("IsValueLevelSensitiveRule(%q) = false, want true", r)
		}
	}
	for _, r := range []string{"sensitive.field", "sensitive.in_query", "sensitive.response_field", "sensitive.response_body_unchecked"} {
		if IsValueLevelSensitiveRule(r) {
			t.Errorf("IsValueLevelSensitiveRule(%q) = true, want false", r)
		}
	}
}
