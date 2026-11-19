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

// N-01 + M-G3 回归：header/response_header/query/cookie 多值评估（正向任一命中，ne 任一违规即不命中）
// 及 EvalResponseHeaders 独立评估。
func TestN01MultiValueAndEvalResponseHeaders(t *testing.T) {
	t.Run("多值 header/query/cookie 正向匹配第二值", func(t *testing.T) {
		eng := mustCompile(t, &Config{Rules: []RuleJSON{
			{
				ID: "hdr-eq", Priority: 1, Enabled: true,
				Conditions: []ConditionJSON{{Type: "header", Name: "X-Tag", Op: "eq", Value: "evil"}},
				Action:     "block",
			},
			{
				ID: "qry-eq", Priority: 2, Enabled: true,
				Conditions: []ConditionJSON{{Type: "query", Name: "role", Op: "eq", Value: "admin"}},
				Action:     "block",
			},
			{
				ID: "ck-eq", Priority: 3, Enabled: true,
				Conditions: []ConditionJSON{{Type: "cookie", Name: "sid", Op: "eq", Value: "hijack"}},
				Action:     "block",
			},
		}})

		rHdr := newReq(t, "GET", "/")
		rHdr.Header.Add("X-Tag", "benign")
		rHdr.Header.Add("X-Tag", "evil")
		if dec, ok := eng.Eval(rHdr, testIP); !ok || dec.RuleID != "hdr-eq" {
			t.Fatalf("多值请求头第二值应命中: %+v ok=%v", dec, ok)
		}

		rQry := newReq(t, "GET", "/?role=guest&role=admin")
		if dec, ok := eng.Eval(rQry, testIP); !ok || dec.RuleID != "qry-eq" {
			t.Fatalf("多值 query 第二值应命中: %+v ok=%v", dec, ok)
		}

		rCk := newReq(t, "GET", "/")
		rCk.Header.Add("Cookie", "sid=safe; sid=hijack")
		if dec, ok := eng.Eval(rCk, testIP); !ok || dec.RuleID != "ck-eq" {
			t.Fatalf("同名多 Cookie 第二值应命中: %+v ok=%v", dec, ok)
		}
	})

	t.Run("多值否定操作符 ne 任一值等于目标即失败", func(t *testing.T) {
		eng := mustCompile(t, &Config{Rules: []RuleJSON{
			{
				ID: "hdr-ne", Priority: 1, Enabled: true,
				Conditions: []ConditionJSON{{Type: "header", Name: "X-Env", Op: "ne", Value: "prod"}},
				Action:     "allow",
			},
		}})
		r := newReq(t, "GET", "/")
		r.Header.Add("X-Env", "staging")
		r.Header.Add("X-Env", "prod")
		if _, ok := eng.Eval(r, testIP); ok {
			t.Fatal("多值含 prod 时 ne=prod 不得命中")
		}
		r2 := newReq(t, "GET", "/")
		r2.Header.Add("X-Env", "staging")
		r2.Header.Add("X-Env", "dev")
		if _, ok := eng.Eval(r2, testIP); !ok {
			t.Fatal("全部值均非 prod 时 ne=prod 应命中")
		}
	})

	t.Run("多值 response_header 与 EvalResponseHeaders 跳过 response_body 规则", func(t *testing.T) {
		eng := mustCompile(t, &Config{Rules: []RuleJSON{
			{
				ID: "body-rule", Priority: 1, Enabled: true,
				Conditions: []ConditionJSON{
					{Type: "response_header", Name: "X-Flag", Op: "eq", Value: "secret"},
					{Type: "response_body", Op: "contains", Value: "needle"},
				},
				Action: "block",
			},
			{
				ID: "hdr-only", Priority: 2, Enabled: true,
				Conditions: []ConditionJSON{{Type: "response_header", Name: "X-Flag", Op: "eq", Value: "secret"}},
				Action:     "block",
			},
		}})
		r := newReq(t, "GET", "/")
		h := http.Header{}
		h.Add("X-Flag", "public")
		h.Add("X-Flag", "secret")
		dec, ok := eng.EvalResponseHeaders(r, testIP, ResponseInput{Header: h, RequestBodyReady: true})
		if !ok || dec.RuleID != "hdr-only" {
			t.Fatalf("EvalResponseHeaders 应跳过 response_body 规则并命中多值 response_header 规则: %+v ok=%v", dec, ok)
		}
	})
}
