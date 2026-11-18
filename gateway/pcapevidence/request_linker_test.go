package pcapevidence

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
)

func TestRequestLinkerExtractsTrustedEvidenceWithoutBody(t *testing.T) {
	var captured []RequestEvidence
	linker, err := NewRequestLinker("gw-1", "GATEWAY_EGRESS", func(evidence RequestEvidence) {
		captured = append(captured, evidence)
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.ReadRequest(newStringReader(`POST /v1/login?secret=not-recorded HTTP/1.1` + "\r\n" +
		"Host: shop.internal\r\n" +
		"X-Request-Id: req-evidence-1\r\n" +
		"Traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n" +
		"Content-Length: 10\r\n\r\npwd=masked"))
	if err != nil {
		t.Fatal(err)
	}
	defer request.Body.Close()
	linker.HandleRequest(request, FlowMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 8080}, false)
	if len(captured) != 1 {
		t.Fatalf("expected one request evidence, got %d", len(captured))
	}
	evidence := captured[0]
	if evidence.RequestID != "req-evidence-1" || evidence.TraceID != "0123456789abcdef0123456789abcdef" ||
		evidence.Path != "/v1/login" || evidence.Host != "shop.internal" || evidence.ConnectionID == "" {
		t.Fatalf("unexpected request evidence: %+v", evidence)
	}
	if strings.Contains(evidence.Path, "secret") {
		t.Fatal("query values leaked into request evidence")
	}
	linker.HandleRequest(request, FlowMeta{}, true)
	if len(captured) != 2 || !captured[1].BodyTruncated {
		t.Fatal("body truncation evidence was not retained")
	}
}

func TestRequestLinkerRejectsUntrustedOrInvalidEvidence(t *testing.T) {
	if _, err := NewRequestLinker("gw-1", "MIRROR", nil); err == nil {
		t.Fatal("untrusted mirror capture was accepted for request ID correlation")
	}
	linker, err := NewRequestLinker("gw-1", "GATEWAY_EGRESS", func(RequestEvidence) {
		t.Fatal("invalid request must not produce evidence")
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"GET / HTTP/1.1\r\nHost: example.internal\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: example.internal\r\nX-Request-Id: bad id\r\n\r\n",
	} {
		request, err := http.ReadRequest(newStringReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		linker.HandleRequest(request, FlowMeta{}, false)
		request.Body.Close()
	}
	if linker.Skipped() != 2 {
		t.Fatalf("skipped=%d want 2", linker.Skipped())
	}
}

func newStringReader(value string) *bufio.Reader { return bufio.NewReader(strings.NewReader(value)) }
