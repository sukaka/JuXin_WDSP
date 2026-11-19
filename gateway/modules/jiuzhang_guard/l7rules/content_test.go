package l7rules

import (
	"net/http"
	"testing"
)

func TestContentConditionsAcrossPhases(t *testing.T) {
	rule := RuleJSON{
		ID: "response", Name: "响应内容", Priority: 10, Enabled: true,
		Conditions: []ConditionJSON{
			{Type: "uri", Op: "prefix", Value: "/api"},
			{Type: "request_body", Op: "contains", Value: "request-secret"},
			{Type: "response_header", Name: "X-Result", Op: "eq", Value: "ready"},
			{Type: "response_body", Op: "contains", Value: "response-secret"},
		},
		Action: "block",
	}
	eng := mustCompile(t, &Config{Rules: []RuleJSON{rule}})
	r := newReq(t, "POST", "/api/orders")
	if !eng.NeedsRequestBody() || !eng.HasResponseRules() {
		t.Fatal("内容检查能力标记缺失")
	}
	if _, ok := eng.EvalRequest(r, testIP, []byte("request-secret"), true); ok {
		t.Fatal("含响应条件的规则不得在请求阶段命中")
	}
	response := ResponseInput{
		Header: http.Header{"X-Result": []string{"ready"}},
		Body:   []byte("prefix response-secret suffix"), BodyReady: true,
		RequestBody: []byte("request-secret"), RequestBodyReady: true,
	}
	dec, ok := eng.EvalResponse(r, testIP, response)
	if !ok || dec.RuleID != "response" {
		t.Fatalf("完整请求和响应条件应命中: %+v ok=%v", dec, ok)
	}
	response.Header.Set("X-Result", "pending")
	if _, ok := eng.EvalResponse(r, testIP, response); ok {
		t.Fatal("响应头不匹配时不得命中")
	}
}

func TestBodyConditionRequiresCompleteBody(t *testing.T) {
	eng := mustCompile(t, &Config{Rules: []RuleJSON{
		allowRule("request", 1, ConditionJSON{Type: "request_body", Op: "contains", Value: "secret"}),
	}})
	r := newReq(t, "POST", "/")
	if _, ok := eng.EvalRequest(r, testIP, []byte("secret"), false); ok {
		t.Fatal("不完整请求体不得产生匹配")
	}
	if _, ok := eng.EvalRequest(r, testIP, []byte("secret"), true); !ok {
		t.Fatal("完整请求体关键字应命中")
	}
}

func TestContentConditionValidation(t *testing.T) {
	for _, cond := range []ConditionJSON{
		{Type: "request_body", Op: "exists"},
		{Type: "response_body", Name: "field", Op: "contains", Value: "secret"},
		{Type: "response_header", Name: "Bad Header", Op: "contains", Value: "x"},
	} {
		if _, errs := Compile(&Config{Rules: []RuleJSON{allowRule("bad", 1, cond)}}); len(errs) != 1 {
			t.Fatalf("非法内容条件应拒绝: %+v errs=%+v", cond, errs)
		}
	}
}

func TestServerStyleResponseHeaderNameIsCaseInsensitive(t *testing.T) {
	eng := mustCompile(t, &Config{Rules: []RuleJSON{
		allowRule("response", 1, ConditionJSON{Type: "response_header", Name: "x-secret-state", Op: "exists"}),
	}})
	r := newReq(t, "GET", "/")
	if _, ok := eng.EvalResponse(r, testIP, ResponseInput{Header: http.Header{"X-Secret-State": []string{""}}, BodyReady: true, RequestBodyReady: true}); !ok {
		t.Fatal("响应头名称应大小写不敏感")
	}
}
