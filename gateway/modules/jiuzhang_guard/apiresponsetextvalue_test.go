package jiuzhang_guard

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeNextResponseXMLAndPlainTextValues(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contentType string
		body        string
		field       string
	}{
		{name: "XML", contentType: "application/xml", body: `<root><contact>13800138000</contact></root>`, field: "root.contact"},
		{name: "plain text", contentType: "text/plain; charset=utf-8", body: "ordinary\n13800138000", field: "text.line[2]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, logPath := newAPITestGuard(t, "PROTECT", nil)
			g.APISensitiveValueRules = responseBodySensitiveGuardRules()
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", tc.contentType)
				_, _ = io.WriteString(w, tc.body)
				return nil
			})
			recorder := httptest.NewRecorder()
			if err := g.serveNext(recorder, compressedResponseRequest("response-text-value-"+tc.name), next); err != nil {
				t.Fatalf("serveNext: %v", err)
			}
			if recorder.Code != http.StatusOK || recorder.Body.String() != tc.body {
				t.Fatalf("response body changed: status=%d body=%q", recorder.Code, recorder.Body.String())
			}
			records := readAPIRecords(t, logPath)
			if len(records) != 1 || records[0].FinalAction != "OBSERVE" {
				t.Fatalf("value observation must not block: %+v", records)
			}
			found := false
			for _, detail := range records[0].Details {
				if detail.RuleID != "sensitive.response_value" {
					continue
				}
				found = true
				if detail.Category != "OBSERVE" || detail.Evidence["field"] != tc.field || detail.Evidence["location"] != "response_body" {
					t.Fatalf("unexpected value evidence: %+v", detail)
				}
			}
			if !found {
				t.Fatalf("response value detail missing: %+v", records[0].Details)
			}
			assertCompressedResponseEventRedacted(t, records, "13800138000")
		})
	}
}

func TestServeNextResponseXMLUncheckedReasons(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   []byte
		reason string
	}{
		{name: "DTD", body: []byte(`<!DOCTYPE root><root><contact>13800138000</contact></root>`), reason: "DTD_FORBIDDEN"},
		{name: "invalid UTF8", body: []byte{0xff, '<', 'r', '>'}, reason: "INVALID_UTF8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, logPath := newAPITestGuard(t, "PROTECT", nil)
			g.APISensitiveValueRules = responseBodySensitiveGuardRules()
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", "application/xml")
				_, _ = w.Write(tc.body)
				return nil
			})
			recorder := httptest.NewRecorder()
			if err := g.serveNext(recorder, compressedResponseRequest("response-xml-unchecked-"+tc.name), next); err != nil {
				t.Fatalf("serveNext: %v", err)
			}
			if !bytes.Equal(recorder.Body.Bytes(), tc.body) {
				t.Fatal("unchecked XML must retain original bytes")
			}
			records := readAPIRecords(t, logPath)
			for _, detail := range records[0].Details {
				if detail.RuleID == "sensitive.response_value" {
					t.Fatalf("unchecked XML must not produce a value hit: %+v", detail)
				}
				if detail.RuleID == "sensitive.response_body_unchecked" {
					if detail.Evidence["completion"] != "partial" || detail.Evidence["skip_reason"] != tc.reason || detail.Evidence["format"] != "XML" {
						t.Fatalf("bad unchecked evidence: %+v", detail.Evidence)
					}
					return
				}
			}
			t.Fatalf("unchecked detail missing: %+v", records[0].Details)
		})
	}
}

func TestServeNextCompressedXMLAndPlainTextValues(t *testing.T) {
	for _, encoding := range []string{apiResponseEncodingGzip, apiResponseEncodingBr} {
		for _, tc := range []struct {
			name        string
			contentType string
			body        string
			field       string
		}{
			{name: "XML", contentType: "application/xml", body: `<root><contact>13800138000</contact></root>`, field: "root.contact"},
			{name: "plain text", contentType: "text/plain", body: "ordinary\n13800138000", field: "text.line[2]"},
		} {
			t.Run(encoding+"/"+tc.name, func(t *testing.T) {
				g, logPath := newAPITestGuard(t, "PROTECT", nil)
				g.APISensitiveValueRules = responseBodySensitiveGuardRules()
				raw := compressedResponseFixture(t, encoding, []byte(tc.body))
				next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
					w.Header().Set("Content-Type", tc.contentType)
					w.Header().Set("Content-Encoding", encoding)
					_, _ = w.Write(raw)
					return nil
				})
				recorder := httptest.NewRecorder()
				if err := g.serveNext(recorder, compressedResponseRequest("response-compressed-text-"+encoding), next); err != nil {
					t.Fatalf("serveNext: %v", err)
				}
				if !bytes.Equal(recorder.Body.Bytes(), raw) {
					t.Fatal("observation-only compressed response must retain original bytes")
				}
				if got := recorder.Header().Get("Content-Encoding"); got != encoding {
					t.Fatalf("Content-Encoding = %q, want %q", got, encoding)
				}
				records := readAPIRecords(t, logPath)
				found := false
				for _, detail := range records[0].Details {
					if detail.RuleID == "sensitive.response_value" && detail.Evidence["field"] == tc.field {
						found = true
					}
				}
				if !found {
					t.Fatalf("decoded %s %s value detail missing: %+v", encoding, tc.contentType, records[0].Details)
				}
				assertCompressedResponseEventRedacted(t, records, "13800138000")
			})
		}
	}
}

func TestServeNextPlainTextValueRequiresResponseBodyRule(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "13800138000")
		return nil
	})
	recorder := httptest.NewRecorder()
	if err := g.serveNext(recorder, compressedResponseRequest("response-text-no-rules"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if recorder.Body.String() != "13800138000" {
		t.Fatal("unconfigured text response changed")
	}
	for _, detail := range readAPIRecords(t, logPath)[0].Details {
		if detail.RuleID == "sensitive.response_value" {
			t.Fatalf("no response_body rule must not inspect text/plain: %+v", detail)
		}
	}
}
