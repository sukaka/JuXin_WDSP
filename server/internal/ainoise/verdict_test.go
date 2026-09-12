// verdict_test.go LLM 评分 JSON 解析与失败降级测试。
package ainoise

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aimodel"
)

func TestParseVerdict(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		conf    float64
		wantErr bool
	}{
		{"clean", `{"verdict":"LIKELY_FALSE_POSITIVE","confidence":0.87,"reason":"高频单一低风险规则"}`, VerdictLikelyFalsePositive, 0.87, false},
		{"fenced", "```json\n{\"verdict\":\"TRUE_POSITIVE\",\"confidence\":0.95,\"reason\":\"明确注入\"}\n```", VerdictTruePositive, 0.95, false},
		{"noisy", "评估结果如下：{\"verdict\":\"UNKNOWN\",\"confidence\":0.1,\"reason\":\"证据不足\"} 以上", VerdictUnknown, 0.1, false},
		{"clamp high", `{"verdict":"TRUE_POSITIVE","confidence":1.7,"reason":"x"}`, VerdictTruePositive, 1.0, false},
		{"clamp low", `{"verdict":"TRUE_POSITIVE","confidence":-0.5,"reason":"x"}`, VerdictTruePositive, 0.0, false},
		{"bad verdict", `{"verdict":"MAYBE","confidence":0.5,"reason":"x"}`, "", 0, true},
		{"no json", "这不是 JSON", "", 0, true},
		{"bad json", `{"verdict":}`, "", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseVerdict(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("want error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Verdict != c.want || got.Confidence != c.conf {
				t.Fatalf("got %+v want verdict=%s conf=%v", got, c.want, c.conf)
			}
		})
	}
}

// fakeGateway 假模型网关。
type fakeGateway struct {
	content string
	err     error
	calls   int
}

func (f *fakeGateway) Chat(_ context.Context, _ aimodel.TaskComplexity, _ aimodel.ChatRequest) (*aimodel.ChatResult, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &aimodel.ChatResult{Content: f.content, InputTokens: 10, OutputTokens: 5}, nil
}

func testEvidence() *Evidence {
	rid := 942100
	return &Evidence{
		Cluster: Cluster{
			ID: uuid.New(), Source: SourceWAF, Host: "a.com", NormalizedURI: "/users/{n}",
			RuleID: &rid, ClientIP: "1.2.3.4", EventCount: 30,
			FirstSeen: time.Now().Add(-10 * time.Minute), LastSeen: time.Now(),
		},
		AttackType: "SQLI", Severity: "HIGH", Action: "BLOCK",
		RuleHits:        []string{"rule 942100: SQL Injection"},
		EventsPerMinute: 3.0,
	}
}

func TestEvaluateSuccess(t *testing.T) {
	gw := &fakeGateway{content: `{"verdict":"LIKELY_FALSE_POSITIVE","confidence":0.8,"reason":"扫描器指纹"}`}
	ev := NewVerdictEvaluator(gw)
	got, tokens := ev.Evaluate(context.Background(), testEvidence())
	if got.Verdict != VerdictLikelyFalsePositive || got.Confidence != 0.8 {
		t.Fatalf("got %+v", got)
	}
	if tokens != 15 || gw.calls != 1 {
		t.Fatalf("tokens=%d calls=%d", tokens, gw.calls)
	}
}

func TestEvaluateLLMFailureDegrades(t *testing.T) {
	gw := &fakeGateway{err: errors.New("model down")}
	ev := NewVerdictEvaluator(gw)
	got, tokens := ev.Evaluate(context.Background(), testEvidence())
	if got.Verdict != VerdictUnknown || tokens != 0 {
		t.Fatalf("llm failure should degrade UNKNOWN, got %+v tokens=%d", got, tokens)
	}
}

func TestEvaluateParseFailureDegrades(t *testing.T) {
	gw := &fakeGateway{content: "无法判断"}
	ev := NewVerdictEvaluator(gw)
	got, tokens := ev.Evaluate(context.Background(), testEvidence())
	if got.Verdict != VerdictUnknown {
		t.Fatalf("parse failure should degrade UNKNOWN, got %+v", got)
	}
	if tokens != 15 {
		t.Fatalf("tokens should still be accounted, got %d", tokens)
	}
}

func TestEvaluateNilGateway(t *testing.T) {
	ev := NewVerdictEvaluator(nil)
	got, _ := ev.Evaluate(context.Background(), testEvidence())
	if got.Verdict != VerdictUnknown {
		t.Fatalf("nil gateway should degrade UNKNOWN, got %+v", got)
	}
}
