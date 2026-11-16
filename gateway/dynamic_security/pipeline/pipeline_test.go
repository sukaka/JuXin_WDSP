package pipeline

import (
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestProcessUnifiedMultiMatchAndDecision(t *testing.T) {
	body := `{"id":1,"extra":"x"}`
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/orders/9", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Request-Id", "pipe-1")
	r.Header.Set("Authorization", "Bearer t")

	formal := map[string]string{"id": "number"} // no "extra"
	ext := []dsctx.DetectorMatch{
		{Detector: "waf", RuleID: "942100", Severity: "HIGH", Category: "BLOCK", ScoreDelta: 50, Message: "sqli"},
	}
	res, err := Process(r, Config{
		Enabled: true, Mode: "PROTECT",
		FormalSchema: formal,
	}, ext)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped {
		t.Fatal("should not skip")
	}
	if res.Context.RequestID != "pipe-1" {
		t.Fatal(res.Context.RequestID)
	}
	if res.EndpointKey != "POST /v1/orders/{id}" {
		t.Fatal(res.EndpointKey)
	}
	// waf + schema undefined field at least
	if res.Context.MatchCount() < 2 {
		t.Fatalf("matches=%d", res.Context.MatchCount())
	}
	if res.FinalAction != dsctx.ActionBlock {
		t.Fatalf("final=%s", res.FinalAction)
	}
	// detectors never left action unset then decided
	if res.Context.GetFinalAction() != dsctx.ActionBlock {
		t.Fatal("decision must set action")
	}
}

func TestProcessOptionalFormalFieldAbsenceAllows(t *testing.T) {
	body := `{"id":1}`
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/orders/1", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer s3cr3t-token-0123456789abcdef")
	res, err := Process(r, Config{
		Enabled: true, Mode: "PROTECT",
		FormalSchema: map[string]string{"id": "number", "note": "string"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.FinalAction != dsctx.ActionAllow {
		t.Fatalf("optional formal field absence must not produce OBSERVE, got %s matches=%+v",
			res.FinalAction, res.Context.CopyMatches())
	}
	for _, m := range res.Context.CopyMatches() {
		if m.RuleID == "schema.missing_field" {
			t.Fatalf("optional formal field absence emitted missing_field: %+v", res.Context.CopyMatches())
		}
	}
}

func TestProcessDisabledSkips(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "http://h/", nil)
	res, err := Process(r, Config{Enabled: false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped {
		t.Fatal("expected skip when API pipeline off")
	}
}

func TestProcessCleanAuthOnlyAllows(t *testing.T) {
	// 干净 API 请求仅带 Authorization：信息性 identity match 不得导致 OBSERVE
	// （凭据需为非弱强度——短凭据会被 authentication 检测器判 WEAK_CREDENTIAL）
	body := `{"id":1}`
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/orders/1", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer s3cr3t-token-0123456789abcdef")
	r.Header.Set("X-Request-Id", "clean-auth-1")
	res, err := Process(r, Config{Enabled: true, Mode: "PROTECT"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.FinalAction != dsctx.ActionAllow {
		t.Fatalf("expected ALLOW for clean auth-only request, got %s matches=%+v",
			res.FinalAction, res.Context.CopyMatches())
	}
	// identity match may still be recorded as INFO
	var hasInfo bool
	for _, m := range res.Context.CopyMatches() {
		if m.RuleID == "identity.token_present" && m.Category == "INFO" {
			hasInfo = true
		}
	}
	if !hasInfo {
		t.Fatal("expected informational identity match")
	}
}

func TestProcessFieldCapFlags(t *testing.T) {
	limits := dsctx.ParseLimits{
		MaxBodyParseBytes: 1 << 20, MaxBodySampleBytes: 1024,
		MaxJSONDepth: 8, MaxFieldCount: 2, MaxXMLDepth: 8, MaxFileMetaCount: 4,
	}
	body := `{"a":1,"b":2,"c":3}`
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/x", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	res, err := Process(r, Config{Enabled: true, Limits: limits}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Parsed.FieldCapped && !res.Context.FieldCountCapped {
		t.Fatal("expected field cap")
	}
}
