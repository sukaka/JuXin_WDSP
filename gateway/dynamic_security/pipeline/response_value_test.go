package pipeline

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func responseBodySensitivePipelineRules() []detectors.SensitiveValueRule {
	return []detectors.SensitiveValueRule{{
		DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"response_body"}, Level: "CORE",
	}}
}

func TestProcessResponseResponseSensitiveValueNestedArrays(t *testing.T) {
	const firstPhone = "13800138000"
	const secondPhone = "13900139000"
	body := `{"groups":[{"members":[{"contact":"` + firstPhone + `"},{"contact":"` + secondPhone + `"}]}]}`
	rules := append(responseBodySensitivePipelineRules(), detectors.SensitiveValueRule{
		DataType: "request_side_only", Regex: `^1[3-9]\d{9}$`, Locations: []string{"json", "query"}, Level: "SENSITIVE",
	})
	ctx := dsctx.New("response-sensitive-nested", dsctx.DefaultParseLimits())
	act, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "application/json", Body: []byte(body), BodySize: int64(len(body)),
	}, ResponseConfig{Mode: decision.ModeProtect, SensitiveValueRules: rules})
	if err != nil {
		t.Fatal(err)
	}
	if act != dsctx.ActionObserve {
		t.Fatalf("response value observation must not block or transform, got %s", act)
	}

	var hits int
	for _, match := range ctx.CopyMatches() {
		if match.RuleID != "sensitive.response_value" {
			continue
		}
		hits++
		if match.Detector != "sensitive_data" || match.Category != "OBSERVE" || match.Severity != "MEDIUM" {
			t.Fatalf("unexpected response value match metadata: %+v", match)
		}
		if len(match.Evidence) != 6 {
			t.Fatalf("evidence must contain only field/data_type/level/location/direction/masked_sample: %+v", match.Evidence)
		}
		want := map[string]string{
			"field": "groups[].members[].contact", "data_type": "phone", "level": "CORE",
			"location": "response_body", "direction": "RESPONSE",
		}
		for key, value := range want {
			if match.Evidence[key] != value {
				t.Fatalf("evidence[%s] = %q, want %q: %+v", key, match.Evidence[key], value, match.Evidence)
			}
		}
		if ms := match.Evidence["masked_sample"]; ms != "138****8000" && ms != "139****9000" {
			t.Fatalf("unexpected masked_sample %q: %+v", ms, match.Evidence)
		}
		for key, value := range match.Evidence {
			if _, ok := want[key]; !ok && key != "masked_sample" {
				t.Fatalf("unexpected evidence key %q: %+v", key, match.Evidence)
			}
			if strings.Contains(value, firstPhone) || strings.Contains(value, secondPhone) {
				t.Fatalf("sensitive value leaked into evidence: %+v", match.Evidence)
			}
		}
	}
	if hits != 2 {
		t.Fatalf("nested array hits = %d, want 2; matches: %+v", hits, ctx.CopyMatches())
	}
}

func TestProcessResponseResponseSensitiveValueSkipsUnavailableBodies(t *testing.T) {
	const body = `{"contact":"13800138000"}`
	zeroSampleLimits := dsctx.DefaultParseLimits()
	zeroSampleLimits.ResponseSampleRatio = 0
	partialSampleLimits := dsctx.DefaultParseLimits()
	partialSampleLimits.MaxBodyParseBytes = 64
	partialSampleLimits.ResponseSampleRatio = 0.5

	tests := []struct {
		name   string
		in     ResponseInput
		rules  []detectors.SensitiveValueRule
		limits dsctx.ParseLimits
	}{
		{name: "no rules", in: ResponseInput{Status: 200, ContentType: "application/json", Body: []byte(body)}},
		{
			name:  "request locations only",
			in:    ResponseInput{Status: 200, ContentType: "application/json", Body: []byte(body)},
			rules: []detectors.SensitiveValueRule{{DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"json", "query"}}},
		},
		{
			name: "malformed JSON", in: ResponseInput{Status: 200, ContentType: "application/json", Body: []byte(`{"contact":`)},
			rules: responseBodySensitivePipelineRules(),
		},
		{
			name: "zero sample", in: ResponseInput{Status: 200, ContentType: "application/json", Body: []byte(body)},
			rules: responseBodySensitivePipelineRules(), limits: zeroSampleLimits,
		},
		{
			name:  "unparseable sampled prefix",
			in:    ResponseInput{Status: 200, ContentType: "application/json", Body: []byte(`{"padding":"` + strings.Repeat("x", 100) + `","contact":"13800138000"}`)},
			rules: responseBodySensitivePipelineRules(), limits: partialSampleLimits,
		},
		{
			name: "truncated", in: ResponseInput{Status: 200, ContentType: "application/json", Body: []byte(body), Truncated: true},
			rules: responseBodySensitivePipelineRules(),
		},
		{
			name: "streamed", in: ResponseInput{Status: 200, ContentType: "application/json", Body: []byte(body), Streamed: true},
			rules: responseBodySensitivePipelineRules(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			limits := tc.limits
			if limits.MaxBodyParseBytes <= 0 {
				limits = dsctx.DefaultParseLimits()
			}
			ctx := dsctx.New("response-sensitive-skip", limits)
			act, err := ProcessResponse(ctx, tc.in, ResponseConfig{
				Mode: decision.ModeProtect, Limits: limits, SensitiveValueRules: tc.rules,
			})
			if err != nil {
				t.Fatal(err)
			}
			if act == dsctx.ActionBlock {
				t.Fatalf("skipped response value scan must not block: %+v", ctx.CopyMatches())
			}
			for _, match := range ctx.CopyMatches() {
				if match.RuleID == "sensitive.response_value" {
					t.Fatalf("unexpected response value match: %+v", match)
				}
			}
		})
	}
}

func TestProcessResponseResponseSensitiveValueScansParseableSample(t *testing.T) {
	body := `{"contact":"13800138000"}` + strings.Repeat(" ", 100)
	limits := dsctx.DefaultParseLimits()
	limits.MaxBodyParseBytes = 64
	limits.ResponseSampleRatio = 0.5
	ctx := dsctx.New("response-sensitive-sample", limits)
	_, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "application/json", Body: []byte(body), BodySize: int64(len(body)),
	}, ResponseConfig{Mode: decision.ModeProtect, Limits: limits, SensitiveValueRules: responseBodySensitivePipelineRules()})
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range ctx.CopyMatches() {
		if match.RuleID == "sensitive.response_value" {
			return
		}
	}
	t.Fatalf("parseable sampled prefix must be scanned: %+v", ctx.CopyMatches())
}
