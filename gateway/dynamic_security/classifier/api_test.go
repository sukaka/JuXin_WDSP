package classifier

import (
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func TestClassifyNotOnlyAPIPrefix(t *testing.T) {
	// HTML page under /api-docs should not dominate alone if no other signals
	p := &parser.Parsed{Method: "GET", RawPath: "/docs", ContentType: "text/html"}
	r := Classify(p)
	if r.IsAPI {
		t.Fatalf("should not be API: %+v", r)
	}
	// JSON REST without /api/
	p2 := &parser.Parsed{
		Method: "POST", RawPath: "/v1/orders", ContentType: "application/json",
		IsJSON: true, JSONFields: map[string]string{"id": "number"},
		Headers: map[string]string{"accept": "application/json"},
	}
	r2 := Classify(p2)
	if !r2.IsAPI || r2.Confidence < 0.35 {
		t.Fatalf("expected API: %+v", r2)
	}
	// /api/ alone is weak but with GET may still be borderline
	p3 := &parser.Parsed{Method: "GET", RawPath: "/api/health"}
	r3 := Classify(p3)
	// may or may not pass threshold with only prefix; ensure prefix is not required for p2
	_ = r3
}

// §8.2 四级识别标签与 0-100 置信度：阈值边界与 IsAPI 兼容口径
// （IsAPI == Level 为 CONFIRMED_API/PROBABLE_API）。
func TestClassifyLevelAndConfidence100(t *testing.T) {
	tests := []struct {
		name        string
		p           *parser.Parsed
		wantLevel   string
		wantConf100 int
		wantIsAPI   bool
	}{
		{
			"多路强信号 → CONFIRMED_API/100",
			&parser.Parsed{
				Method: "POST", RawPath: "/v1/orders", ContentType: "application/json",
				IsJSON: true, JSONFields: map[string]string{"id": "number"},
				Headers: map[string]string{"accept": "application/json"},
			},
			LevelConfirmedAPI, 100, true,
		},
		{
			"恰好 0.35 判定线 → PROBABLE_API/35 且 IsAPI（兼容旧阈值）",
			&parser.Parsed{Method: "GET", RawPath: "/ping", ContentType: "application/json"},
			LevelProbableAPI, 35, true,
		},
		{
			"单路弱信号 api_prefix → POSSIBLE_API/15 非 IsAPI",
			&parser.Parsed{Method: "GET", RawPath: "/api/health"},
			LevelPossibleAPI, 15, false,
		},
		{
			"零信号 → NON_API/0",
			&parser.Parsed{Method: "GET", RawPath: "/docs", ContentType: "text/html"},
			LevelNonAPI, 0, false,
		},
		{
			"nil → NON_API/0",
			nil,
			LevelNonAPI, 0, false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := Classify(tc.p)
			if r.Level != tc.wantLevel || r.Confidence100 != tc.wantConf100 || r.IsAPI != tc.wantIsAPI {
				t.Fatalf("got level=%q conf100=%d isAPI=%v, want %q/%d/%v",
					r.Level, r.Confidence100, r.IsAPI, tc.wantLevel, tc.wantConf100, tc.wantIsAPI)
			}
			// 换算口径：Confidence100 == round(Confidence × 100)
			if r.Confidence100 != int(r.Confidence*100+0.5) {
				t.Fatalf("confidence100 %d inconsistent with confidence %f", r.Confidence100, r.Confidence)
			}
			// 兼容口径：IsAPI ⟺ Level ∈ {CONFIRMED_API, PROBABLE_API}
			if r.IsAPI != (r.Level == LevelConfirmedAPI || r.Level == LevelProbableAPI) {
				t.Fatalf("IsAPI=%v inconsistent with level %q", r.IsAPI, r.Level)
			}
		})
	}
}

// 响应证据参与资产识别：缺失/截断不作负向推断；结构性协议不被成功 HTML 响应误判。
func TestClassifyWithResponseEvidence(t *testing.T) {
	closeEnough := func(got, want float64) bool {
		const eps = 1e-9
		return got > want-eps && got < want+eps
	}

	t.Run("JSON 请求与响应提高置信度", func(t *testing.T) {
		p := &parser.Parsed{Method: "GET", RawPath: "/v1/orders", ContentType: "application/json"}
		got := ClassifyWithResponse(p, &ResponseEvidence{Status: 200, ContentType: "application/json"})
		if !got.IsAPI || !closeEnough(got.Confidence, 0.80) || got.Level != LevelConfirmedAPI {
			t.Fatalf("unexpected result: %+v", got)
		}
		if !containsSignal(got.Signals, "response_json") {
			t.Fatalf("response_json signal missing: %+v", got.Signals)
		}
	})

	t.Run("SOAP 请求与 XML 响应", func(t *testing.T) {
		p := &parser.Parsed{Method: "POST", RawPath: "/soap/orders", ContentType: "application/soap+xml"}
		got := ClassifyWithResponse(p, &ResponseEvidence{Status: 200, ContentType: "text/xml"})
		if !got.IsAPI || !closeEnough(got.Confidence, 0.45) || !containsSignal(got.Signals, "response_xml") {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("普通 HTML 页面和仅 API 前缀弱信号均被成功 HTML 响应压低", func(t *testing.T) {
		for _, p := range []*parser.Parsed{
			{Method: "GET", RawPath: "/docs", ContentType: "text/html"},
			{Method: "GET", RawPath: "/api/docs"},
		} {
			got := ClassifyWithResponse(p, &ResponseEvidence{Status: 200, ContentType: "text/html"})
			if got.IsAPI || got.Confidence != 0 || got.Level != LevelNonAPI {
				t.Fatalf("%s should not be API: %+v", p.RawPath, got)
			}
		}
	})

	t.Run("响应缺失不作负向推断", func(t *testing.T) {
		p := &parser.Parsed{Method: "GET", RawPath: "/v1/ping", ContentType: "application/json"}
		got := ClassifyWithResponse(p, nil)
		if !got.IsAPI || !closeEnough(got.Confidence, 0.55) {
			t.Fatalf("missing response changed request-only result: %+v", got)
		}
	})

	t.Run("截断 HTML 响应不作负向推断", func(t *testing.T) {
		p := &parser.Parsed{Method: "GET", RawPath: "/api/health"}
		got := ClassifyWithResponse(p, &ResponseEvidence{Status: 200, ContentType: "text/html", Truncated: true})
		if got.IsAPI || !closeEnough(got.Confidence, 0.15) || got.Level != LevelPossibleAPI {
			t.Fatalf("truncated response should keep request evidence: %+v", got)
		}
	})

	t.Run("GraphQL 结构协议不被成功 HTML 响应误判", func(t *testing.T) {
		p := &parser.Parsed{Method: "POST", RawPath: "/graphql", ContentType: "application/json", IsJSON: true}
		got := ClassifyWithResponse(p, &ResponseEvidence{Status: 200, ContentType: "text/html"})
		if !got.IsAPI || !closeEnough(got.Confidence, 0.85) || !containsSignal(got.Signals, "graphql_path") {
			t.Fatalf("structural protocol changed by response HTML: %+v", got)
		}
	})
}

func containsSignal(signals []string, want string) bool {
	for _, signal := range signals {
		if signal == want {
			return true
		}
	}
	return false
}
