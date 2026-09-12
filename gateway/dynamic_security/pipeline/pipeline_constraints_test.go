package pipeline

import (
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// 参数约束经管线生效：BODY max_length 违规在 PROTECT 下定案 BLOCK；OBSERVE 下降级不阻断。
func TestProcessParamConstraints(t *testing.T) {
	constraints := []detectors.ParamConstraint{
		{Location: "BODY", Name: "name", Path: "name", BaseType: "string",
			Constraints: map[string]any{"max_length": float64(3)}},
		{Location: "QUERY", Name: "page", BaseType: "number",
			Constraints: map[string]any{"minimum": float64(1)}},
	}
	newReq := func() *http.Request {
		r, _ := http.NewRequest(http.MethodPost, "http://h/v1/things?page=0", strings.NewReader(`{"name":"abcde"}`))
		r.Header.Set("Content-Type", "application/json")
		return r
	}

	// PROTECT：两条 BLOCK 类命中（param_length + param_range）→ 定案 BLOCK
	res, err := Process(newReq(), Config{Enabled: true, Mode: "PROTECT", ParamConstraints: constraints}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "schema.param_length") || !hasRule(res, "schema.param_range") {
		t.Fatalf("expected param violations, got %+v", res.Context.CopyMatches())
	}
	if res.FinalAction != dsctx.ActionBlock {
		t.Fatalf("final=%s, want BLOCK", res.FinalAction)
	}
	// BODY 标量值随管线留存（仅请求内存活），证据不含值
	if res.Parsed == nil || res.Parsed.JSONValues["name"] != "abcde" {
		t.Fatalf("scalar value not retained in parsed: %+v", res.Parsed)
	}
	for _, m := range res.Context.CopyMatches() {
		for _, v := range m.Evidence {
			if v == "abcde" || v == "0" {
				t.Fatalf("raw value leaked into evidence: %+v", m.Evidence)
			}
		}
	}

	// OBSERVE：命中照常，动作降级不阻断
	res2, err := Process(newReq(), Config{Enabled: true, Mode: "OBSERVE", ParamConstraints: constraints}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res2, "schema.param_length") {
		t.Fatalf("expected param_length match in OBSERVE, got %+v", res2.Context.CopyMatches())
	}
	if res2.FinalAction == dsctx.ActionBlock {
		t.Fatalf("OBSERVE must not block, final=%s", res2.FinalAction)
	}
}

// API 管线开启时保留标量值（请求内存）供值观测与约束检测；值不入事件明文。
func TestProcessRetainsScalarValuesForObservation(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/x", strings.NewReader(`{"name":"abcde"}`))
	r.Header.Set("Content-Type", "application/json")
	res, err := Process(r, Config{Enabled: true, Mode: "PROTECT"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Parsed == nil || res.Parsed.JSONValues["name"] != "abcde" {
		t.Fatalf("want retained scalar value for observation, got %+v", res.Parsed)
	}
}
