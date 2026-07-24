package accesslogs

import (
	"strings"
	"testing"
	"time"
)

func TestParseLine(t *testing.T) {
	valid := `{"occurred_at":"2026-07-23T10:00:00Z","request_id":"req-1","application_id":"1b4e28ba-2fa1-11d2-883f-0016d3cca427",` +
		`"domain":"waf-s5.local","gateway_node_id":"gateway-stage5-01","client_ip":"203.0.113.10","client_port":4321,` +
		`"request_method":"POST","request_uri":"/login?token=masked","request_path":"/login","query_summary":"token=masked",` +
		`"http_version":"HTTP/1.1","content_type":"application/json","user_agent_summary":"curl/8.0","referer_summary":"",` +
		`"response_status":200,"bytes_in":42,"bytes_out":128,"duration_ms":15,"waf_action":"",` +
		`"request_headers":{"Cookie":["masked"],"Accept":["*/*"]},"request_body":"{\"password\":\"masked\"}","request_body_truncated":false,` +
		`"response_headers":{"Content-Type":["application/json"]},"response_body":"{\"ok\":true}","response_body_truncated":false}`

	cases := []struct {
		name    string
		line    string
		wantErr bool
		check   func(t *testing.T, e *LogEntry)
	}{
		{
			name: "valid full line",
			line: valid,
			check: func(t *testing.T, e *LogEntry) {
				if e.RequestID != "req-1" || e.ResponseStatus != 200 || e.BytesIn != 42 || e.BytesOut != 128 {
					t.Errorf("basic fields wrong: %+v", e)
				}
				if e.RequestHeaders["Cookie"][0] != "masked" {
					t.Errorf("headers wrong: %v", e.RequestHeaders)
				}
				if e.DurationMS != 15 || e.ClientPort != 4321 {
					t.Errorf("duration/port wrong: %+v", e)
				}
			},
		},
		{name: "empty line", line: "  \n", wantErr: true},
		{name: "bad json", line: "{not json", wantErr: true},
		{name: "missing occurred_at", line: `{"request_id":"req-2"}`, wantErr: true},
		{name: "oversize line", line: `{"occurred_at":"2026-07-23T10:00:00Z","request_body":"` + strings.Repeat("a", 1<<20) + `"}`, wantErr: true},
		{
			name: "oversize fields truncated",
			line: `{"occurred_at":"2026-07-23T10:00:00Z","request_id":"` + strings.Repeat("r", 200) +
				`","domain":"` + strings.Repeat("d", 300) + `"}`,
			check: func(t *testing.T, e *LogEntry) {
				if len(e.RequestID) != maxRequestIDLen {
					t.Errorf("request_id not truncated: %d", len(e.RequestID))
				}
				if len(e.Domain) != maxDomainLen {
					t.Errorf("domain not truncated: %d", len(e.Domain))
				}
			},
		},
		{
			name: "NUL stripped from body",
			line: `{"occurred_at":"2026-07-23T10:00:00Z","request_id":"req-3","request_body":"a\u0000b","response_body":"x\u0000y"}`,
			check: func(t *testing.T, e *LogEntry) {
				if strings.Contains(e.RequestBody, "\x00") || strings.Contains(e.ResponseBody, "\x00") {
					t.Errorf("NUL not stripped: %q %q", e.RequestBody, e.ResponseBody)
				}
			},
		},
		{
			name: "minimal line defaults",
			line: `{"occurred_at":"2026-07-23T10:00:00Z"}`,
			check: func(t *testing.T, e *LogEntry) {
				if e.RequestID != "" || e.ResponseStatus != 0 || e.WAFAction != "" {
					t.Errorf("defaults wrong: %+v", e)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := ParseLine([]byte(c.line))
			if c.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.check != nil {
				c.check(t, e)
			}
		})
	}
}

func TestParseLineOccurredAtPreserved(t *testing.T) {
	e, err := ParseLine([]byte(`{"occurred_at":"2026-07-23T10:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	if !e.OccurredAt.Equal(want) {
		t.Errorf("occurred_at = %v, want %v", e.OccurredAt, want)
	}
}
