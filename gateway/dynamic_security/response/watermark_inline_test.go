package response

import "testing"

func TestInlineHTMLMediaTypeNormalization(t *testing.T) {
	for _, value := range []string{"text/html", " Text/HTML ", "text/html; charset=utf-8"} {
		if !IsHTMLMediaType(value) {
			t.Fatalf("HTML media type %q not recognized", value)
		}
	}
	for _, value := range []string{"text/plain", "application/xhtml+xml", "text/htmlx", ""} {
		if IsHTMLMediaType(value) {
			t.Fatalf("non-HTML media type %q accepted", value)
		}
	}
	cfg := wmTestConfig(t, "trace")
	if cfg.IncludeInlineHTML {
		t.Fatal("inline HTML must be opt-in")
	}
}
