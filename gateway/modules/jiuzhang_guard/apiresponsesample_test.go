package jiuzhang_guard

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGuardConfigAPIResponseSampleRatioJSON(t *testing.T) {
	var legacy Guard
	if err := json.Unmarshal([]byte(`{"app_id":"a","events_log":"/tmp/e.log"}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy config: %v", err)
	}
	if legacy.APIResponseSampleRatio != nil {
		t.Fatalf("legacy config ratio = %v, want nil", *legacy.APIResponseSampleRatio)
	}
	if got := legacy.apiParseLimits().ResponseSampleRatio; got != 1 {
		t.Fatalf("legacy effective ratio = %v, want 1", got)
	}

	var zero Guard
	if err := json.Unmarshal([]byte(`{"api_response_sample_ratio":0}`), &zero); err != nil {
		t.Fatalf("unmarshal explicit zero: %v", err)
	}
	if zero.APIResponseSampleRatio == nil || *zero.APIResponseSampleRatio != 0 {
		t.Fatalf("explicit zero was not preserved: %v", zero.APIResponseSampleRatio)
	}
	if got := zero.apiParseLimits().ResponseSampleRatio; got != 0 {
		t.Fatalf("explicit zero effective ratio = %v, want 0", got)
	}
	encoded, err := json.Marshal(zero)
	if err != nil {
		t.Fatalf("marshal explicit zero: %v", err)
	}
	if !strings.Contains(string(encoded), `"api_response_sample_ratio":0`) {
		t.Fatalf("explicit zero must survive omitempty round trip: %s", encoded)
	}
	encoded, err = json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy config: %v", err)
	}
	if strings.Contains(string(encoded), `"api_response_sample_ratio"`) {
		t.Fatalf("unset ratio must remain omitted: %s", encoded)
	}

	var half Guard
	if err := json.Unmarshal([]byte(`{"api_response_sample_ratio":0.5}`), &half); err != nil {
		t.Fatalf("unmarshal half: %v", err)
	}
	if half.APIResponseSampleRatio == nil || *half.APIResponseSampleRatio != 0.5 {
		t.Fatalf("half ratio was not preserved: %v", half.APIResponseSampleRatio)
	}
	if got := half.apiParseLimits().ResponseSampleRatio; got != 0.5 {
		t.Fatalf("half effective ratio = %v, want 0.5", got)
	}
}

func TestGuardValidateAPIResponseSampleRatio(t *testing.T) {
	ratioPtr := func(v float64) *float64 { return &v }
	base := func() *Guard {
		return &Guard{EventsLog: "x", APIDynamicProtection: true}
	}
	for _, ratio := range []*float64{nil, ratioPtr(0), ratioPtr(0.5), ratioPtr(1)} {
		g := base()
		g.APIResponseSampleRatio = ratio
		if err := g.Validate(); err != nil {
			t.Fatalf("ratio %v must be valid: %v", ratio, err)
		}
	}
	for _, tc := range []struct {
		name  string
		ratio float64
	}{
		{name: "negative", ratio: -0.01},
		{name: "above one", ratio: 1.01},
		{name: "NaN", ratio: math.NaN()},
		{name: "positive infinity", ratio: math.Inf(1)},
		{name: "negative infinity", ratio: math.Inf(-1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := base()
			g.APIResponseSampleRatio = ratioPtr(tc.ratio)
			err := g.Validate()
			if err == nil {
				t.Fatalf("ratio %v must be rejected", tc.ratio)
			}
			if !strings.Contains(err.Error(), "api_response_sample_ratio") {
				t.Fatalf("validation error must identify field: %v", err)
			}
		})
	}

	disabled := &Guard{EventsLog: "x", APIResponseSampleRatio: ratioPtr(math.NaN())}
	if err := disabled.Validate(); err != nil {
		t.Fatalf("disabled API protection must skip ratio validation: %v", err)
	}
}

func TestServeNextAPIResponseSampleRatio(t *testing.T) {
	ratioPtr := func(v float64) *float64 { return &v }
	oversizedJSON := `{"pad":"` + strings.Repeat("x", 1<<20) + `"}`
	parseableSampledPrefix := `{"sampled":true}` + strings.Repeat(" ", 1<<20)
	tests := []struct {
		name          string
		ratio         *float64
		body          string
		wantRatio     float64
		wantJSON      bool
		wantField     string
		wantFieldType string
	}{
		{
			name: "legacy default fully parses oversized response", body: oversizedJSON,
			wantRatio: 1, wantJSON: true, wantField: "pad", wantFieldType: "string",
		},
		{
			name: "zero skips response body parsing", ratio: ratioPtr(0), body: `{"phone":"13800138000"}`,
			wantRatio: 0, wantJSON: false,
		},
		{
			name: "half parses deterministic complete prefix", ratio: ratioPtr(0.5), body: parseableSampledPrefix,
			wantRatio: 0.5, wantJSON: true, wantField: "sampled", wantFieldType: "bool",
		},
		{
			name: "half does not parse oversized body beyond sampled prefix", ratio: ratioPtr(0.5), body: oversizedJSON,
			wantRatio: 0.5, wantJSON: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, logPath := newAPITestGuard(t, "OBSERVE", nil)
			g.APIResponseSampleRatio = tc.ratio
			g.APIResponseCaptureMaxBytes = 2 << 20
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
				return nil
			})
			req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"name":"x"}`))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			if err := g.serveNext(recorder, req, next); err != nil {
				t.Fatalf("serveNext: %v", err)
			}
			if got := recorder.Body.String(); got != tc.body {
				t.Fatalf("response body changed: got %d bytes, want %d", len(got), len(tc.body))
			}

			requestCtx := RequestContextFrom(req)
			if requestCtx == nil {
				t.Fatal("request context not injected")
			}
			if got := requestCtx.Limits.ResponseSampleRatio; got != tc.wantRatio {
				t.Fatalf("request context ratio = %v, want %v", got, tc.wantRatio)
			}
			responseCtx := requestCtx.GetResponse()
			if responseCtx == nil {
				t.Fatal("response context not populated")
			}
			if responseCtx.IsJSON != tc.wantJSON {
				t.Fatalf("IsJSON = %v, want %v", responseCtx.IsJSON, tc.wantJSON)
			}
			if tc.wantJSON && responseCtx.ParsedBody[tc.wantField] != tc.wantFieldType {
				t.Fatalf("parsed field %s = %q, want %q", tc.wantField, responseCtx.ParsedBody[tc.wantField], tc.wantFieldType)
			}
			if !tc.wantJSON && responseCtx.ParsedBody != nil {
				t.Fatalf("unparsed response must not expose parsed fields: %+v", responseCtx.ParsedBody)
			}

			records := readAPIRecords(t, logPath)
			if len(records) != 1 {
				t.Fatalf("want 1 API event, got %d", len(records))
			}
			if tc.wantJSON {
				if len(records[0].ResponseObservations) != 1 || records[0].ResponseObservations[0].Fields[tc.wantField] != tc.wantFieldType {
					t.Fatalf("response observation missing sampled field: %+v", records[0].ResponseObservations)
				}
			} else if len(records[0].ResponseObservations) != 0 {
				t.Fatalf("unparsed response must not emit observations: %+v", records[0].ResponseObservations)
			}
		})
	}
}
