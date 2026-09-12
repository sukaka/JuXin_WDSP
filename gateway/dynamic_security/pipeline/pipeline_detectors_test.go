package pipeline

import (
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func hasRule(res *Result, ruleID string) bool {
	for _, m := range res.Context.CopyMatches() {
		if m.RuleID == ruleID {
			return true
		}
	}
	return false
}

// 新检测器（认证/敏感/资源/生命周期）经管线真实产生 match；Query 敏感字段在 PROTECT 下定案 BLOCK。
func TestProcessNewDetectorsProduceMatches(t *testing.T) {
	body := `{"name":"n"}`
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/users/5?id_card=110101xxxx", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Request-Id", "pipe-new-detectors")
	res, err := Process(r, Config{
		Enabled:        true,
		Mode:           "PROTECT",
		KnownEndpoints: map[string]string{"GET /v1/known": "CONFIRMED"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{
		"auth.unauthenticated_api",
		"sensitive.in_query",
		"resource.unauthenticated_object_access",
		"lifecycle.new_endpoint",
	} {
		if !hasRule(res, rule) {
			t.Fatalf("expected match %s, got %+v", rule, res.Context.CopyMatches())
		}
	}
	// 对象标识类型扩展已写入
	if got := res.Context.Extensions["api.object_id_type"]; got != "numeric" {
		t.Fatalf("api.object_id_type=%v", got)
	}
	// SENSITIVE_IN_QUERY 为 BLOCK 类 → PROTECT 下阻断
	if res.FinalAction != dsctx.ActionBlock {
		t.Fatalf("final=%s", res.FinalAction)
	}
}

// 写方法 API 限速信号经管线定案 RATE_LIMIT。
func TestProcessAPIWriteRateLimit(t *testing.T) {
	cfg := Config{Enabled: true, Mode: "PROTECT", APIWriteRatePerMinute: 1}
	newReq := func() *http.Request {
		r, _ := http.NewRequest(http.MethodPost, "http://h/v1/write-rate-t1", strings.NewReader(`{"a":1}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "198.51.100.7:9000"
		return r
	}
	res1, err := Process(newReq(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res1.FinalAction == dsctx.ActionRateLimit {
		t.Fatal("first request under limit must not be rate limited")
	}
	res2, err := Process(newReq(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res2, "ratelimit.api_write_rate") {
		t.Fatalf("expected API_WRITE_RATE match, got %+v", res2.Context.CopyMatches())
	}
	if res2.FinalAction != dsctx.ActionRateLimit {
		t.Fatalf("final=%s, want RATE_LIMIT", res2.FinalAction)
	}
}

// 生命周期 DEPRECATED 调用经管线产生 match（携带合法凭据，隔离其它检测器）。
func TestProcessDeprecatedLifecycleMatch(t *testing.T) {
	body := `{"a":1}`
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/legacy", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer s3cr3t-token-0123456789abcdef")
	res, err := Process(r, Config{
		Enabled:        true,
		Mode:           "PROTECT",
		KnownEndpoints: map[string]string{"POST /v1/legacy": "DEPRECATED"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "lifecycle.deprecated_api_call") {
		t.Fatalf("expected DEPRECATED_API_CALL, got %+v", res.Context.CopyMatches())
	}
	if res.FinalAction != dsctx.ActionObserve {
		t.Fatalf("final=%s, want OBSERVE", res.FinalAction)
	}
}

// 自定义敏感字段模式编译失败必须返回错误（不静默吞错）。
func TestProcessBadSensitivePatternReturnsError(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "http://h/v1/x", nil)
	_, err := Process(r, Config{
		Enabled:           true,
		SensitivePatterns: []detectors.SensitivePattern{{DataType: "x", Pattern: "([bad"}},
	}, nil)
	if err == nil {
		t.Fatal("bad sensitive pattern must return error")
	}
}

// 已知端点在基线表中且非 DEPRECATED：不产生生命周期 match。
func TestProcessKnownEndpointNoLifecycleMatch(t *testing.T) {
	body := `{"a":1}`
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/known", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer s3cr3t-token-0123456789abcdef")
	res, err := Process(r, Config{
		Enabled:        true,
		Mode:           "PROTECT",
		KnownEndpoints: map[string]string{"POST /v1/known": "CONFIRMED"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(res, "lifecycle.new_endpoint") || hasRule(res, "lifecycle.deprecated_api_call") {
		t.Fatalf("known endpoint must not produce lifecycle match, got %+v", res.Context.CopyMatches())
	}
	if res.FinalAction != dsctx.ActionAllow {
		t.Fatalf("final=%s, want ALLOW", res.FinalAction)
	}
}

// 值级敏感规则经管线生效：QUERY 值命中（字段名不命中词表）在 PROTECT 下定案 BLOCK；
// FORM 值随规则开启留存并命中产 OBSERVE；证据不含明文值。
func TestProcessSensitiveValueRules(t *testing.T) {
	rules := []detectors.SensitiveValueRule{
		{DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"query", "form"}, Level: "SENSITIVE"},
	}
	r, _ := http.NewRequest(http.MethodGet, "http://h/v1/users?contact=13800138000", nil)
	r.Header.Set("Authorization", "Bearer s3cr3t-token-0123456789abcdef")
	res, err := Process(r, Config{Enabled: true, Mode: "PROTECT", SensitiveValueRules: rules}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "sensitive.value_in_query") {
		t.Fatalf("expected sensitive.value_in_query, got %+v", res.Context.CopyMatches())
	}
	if res.FinalAction != dsctx.ActionBlock {
		t.Fatalf("final=%s, want BLOCK", res.FinalAction)
	}
	for _, m := range res.Context.CopyMatches() {
		for _, v := range m.Evidence {
			if strings.Contains(v, "13800138000") {
				t.Fatalf("sensitive value leaked into evidence: %+v", m.Evidence)
			}
		}
	}

	// FORM 值命中（OBSERVE）：规则开启时表单标量值留存生效
	body := "nickname=abc&contact2=13912345678"
	r2, _ := http.NewRequest(http.MethodPost, "http://h/v1/form", strings.NewReader(body))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r2.Header.Set("Authorization", "Bearer s3cr3t-token-0123456789abcdef")
	res2, err := Process(r2, Config{Enabled: true, Mode: "OBSERVE", SensitiveValueRules: rules}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range res2.Context.CopyMatches() {
		if m.RuleID == "sensitive.value" && m.Evidence["location"] == "form" && m.Evidence["field"] == "contact2" {
			found = true
		}
		for _, v := range m.Evidence {
			if strings.Contains(v, "13912345678") {
				t.Fatalf("sensitive value leaked into evidence: %+v", m.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("expected form value hit, got %+v", res2.Context.CopyMatches())
	}
}

// 值级敏感规则编译失败必须返回错误（不静默吞错）。
func TestProcessBadSensitiveValueRuleReturnsError(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "http://h/v1/x", nil)
	_, err := Process(r, Config{
		Enabled:             true,
		SensitiveValueRules: []detectors.SensitiveValueRule{{DataType: "x", Regex: "([bad", Locations: []string{"query"}}},
	}, nil)
	if err == nil {
		t.Fatal("bad sensitive value rule must return error")
	}
}
