package l7rules

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateAndEvaluateContentConditions(t *testing.T) {
	in := validInput()
	in.Conditions = []Condition{
		{Type: CondTypeRequestBody, Op: OpContains, Value: "request-secret"},
		{Type: CondTypeResponseHeader, Name: "X-Result", Op: OpEq, Value: "ready"},
		{Type: CondTypeResponseBody, Op: OpContains, Value: "response-secret"},
	}
	if err := ValidateInput(&in); err != nil {
		t.Fatalf("内容条件应通过校验: %v", err)
	}
	rule := Rule{ID: uuid.New(), Name: in.Name, Priority: 100, Enabled: true, Conditions: in.Conditions, CreatedAt: time.Now()}
	ev, err := NewEvaluator([]Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	input := baseInput()
	input.RequestBody = "request-secret"
	input.ResponseHeaders = map[string]string{"x-result": "ready"}
	input.ResponseBody = "response-secret"
	if !ev.Eval(input).Matched {
		t.Fatal("请求体、响应头和响应体条件应同时命中")
	}
	input.ResponseBody = "safe"
	if ev.Eval(input).Matched {
		t.Fatal("响应体关键字消失后不得命中")
	}
}
