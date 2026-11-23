package jiuzhang_guard

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func responseBodySensitiveGuardRules() []detectors.SensitiveValueRule {
	return []detectors.SensitiveValueRule{{
		DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"response_body"}, Level: "CORE",
	}}
}

func TestServeNextResponseJSONSensitiveValueObservedWithoutBodyMutation(t *testing.T) {
	const sensitiveValue = "13800138000"
	const upstreamBody = `{"result":{"contacts":[{"phone":"` + sensitiveValue + `"}]},"ok":true}`
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.APISensitiveValueRules = append(responseBodySensitiveGuardRules(), detectors.SensitiveValueRule{
		DataType: "request_side_only", Regex: `^1[3-9]\d{9}$`, Locations: []string{"json"}, Level: "SENSITIVE",
	})
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(w, upstreamBody)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-response-sensitive-json")
	recorder := httptest.NewRecorder()
	if err := g.serveNext(recorder, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if recorder.Code != http.StatusOK || recorder.Body.String() != upstreamBody {
		t.Fatalf("ordinary JSON response changed: status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	records := readAPIRecords(t, logPath)
	if len(records) != 1 {
		t.Fatalf("want one main API event, got %d", len(records))
	}
	event := records[0]
	if event.FinalAction != "OBSERVE" || event.ResponseStatus != http.StatusOK {
		t.Fatalf("response value observation must not block: action=%s status=%d", event.FinalAction, event.ResponseStatus)
	}
	encodedEvent, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedEvent), sensitiveValue) {
		t.Fatalf("sensitive value leaked into main event: %s", encodedEvent)
	}

	var hits int
	for _, detail := range event.Details {
		if detail.RuleID != "sensitive.response_value" {
			continue
		}
		hits++
		if detail.Detector != "sensitive_data" || detail.Category != "OBSERVE" || detail.Severity != "MEDIUM" {
			t.Fatalf("unexpected response value detail metadata: %+v", detail)
		}
		if len(detail.Evidence) != 6 || detail.Evidence["field"] != "result.contacts[].phone" ||
			detail.Evidence["data_type"] != "phone" || detail.Evidence["level"] != "CORE" ||
			detail.Evidence["location"] != "response_body" || detail.Evidence["direction"] != "RESPONSE" ||
			detail.Evidence["masked_sample"] != "138****8000" {
			t.Fatalf("unexpected response value evidence: %+v", detail.Evidence)
		}
		for key, value := range detail.Evidence {
			switch key {
			case "field", "data_type", "level", "location", "direction", "masked_sample":
			default:
				t.Fatalf("unexpected evidence key %q: %+v", key, detail.Evidence)
			}
			if strings.Contains(value, sensitiveValue) {
				t.Fatalf("sensitive value leaked into evidence: %+v", detail.Evidence)
			}
		}
	}
	if hits != 1 {
		t.Fatalf("response value details = %d, want 1: %+v", hits, event.Details)
	}
}

func TestServeNextResponseSensitiveValueCaptureBoundaries(t *testing.T) {
	const body = `{"contact":"13800138000"}`
	zero := 0.0
	tests := []struct {
		name        string
		contentType string
		captureMax  int
		sampleRatio *float64
	}{
		{name: "zero sampling", contentType: "application/json", sampleRatio: &zero},
		{name: "capture spill", contentType: "application/json", captureMax: 16},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, logPath := newAPITestGuard(t, "PROTECT", nil)
			g.APISensitiveValueRules = responseBodySensitiveGuardRules()
			g.APIResponseCaptureMaxBytes = tc.captureMax
			g.APIResponseSampleRatio = tc.sampleRatio
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", tc.contentType)
				_, _ = io.WriteString(w, body)
				return nil
			})
			req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"name":"x"}`))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			if err := g.serveNext(recorder, req, next); err != nil {
				t.Fatalf("serveNext: %v", err)
			}
			if recorder.Code != http.StatusOK || recorder.Body.String() != body {
				t.Fatalf("boundary response changed: status=%d body=%q", recorder.Code, recorder.Body.String())
			}
			records := readAPIRecords(t, logPath)
			if len(records) != 1 {
				t.Fatalf("want one main API event, got %d", len(records))
			}
			for _, detail := range records[0].Details {
				if detail.RuleID == "sensitive.response_value" {
					t.Fatalf("boundary must skip response value scan: %+v", detail)
				}
			}
		})
	}
}

func TestServeNextStaticCSSWithClientHintProducesNoFalsePositiveOrEvent(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.APISensitiveValueRules = responseBodySensitiveGuardRules()
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = io.WriteString(w, "body{color:#333}")
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/astro/TheFooter.Cyh15Q7R.css", nil)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Sec-CH-UA-Platform", `"macOS"`)
	req.Header.Set("Sec-Fetch-Dest", "style")
	recorder := httptest.NewRecorder()
	if err := g.serveNext(recorder, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if recorder.Code != http.StatusOK || recorder.Body.String() != "body{color:#333}" {
		t.Fatalf("static CSS response changed: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 0 {
		t.Fatalf("static asset with Sec-CH-UA-Mobile must not emit API events, got %+v", records)
	}
}
