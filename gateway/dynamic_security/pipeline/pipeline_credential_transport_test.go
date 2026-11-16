package pipeline

import (
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestProcessCredentialTransport(t *testing.T) {
	body := `{"username":"demo"}`
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/login?password=secret-value", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "auth_token", Value: "cookie-secret"})
	res, err := Process(r, Config{Enabled: true, Mode: "PROTECT"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.FinalAction != "BLOCK" {
		t.Fatalf("final_action=%s matches=%+v", res.FinalAction, res.Context.CopyMatches())
	}
	for _, match := range res.Context.CopyMatches() {
		for _, value := range match.Evidence {
			if strings.Contains(value, "secret") {
				t.Fatalf("sensitive value leaked: %+v", match.Evidence)
			}
		}
	}
}

func TestProcessResponseServerDisclosure(t *testing.T) {
	ctx := dsctx.New("server-disclosure", dsctx.DefaultParseLimits())
	act, err := ProcessResponse(ctx, ResponseInput{
		Status: 500, ContentType: "application/json", Headers: map[string]string{"server": "Apache/2.4.49"},
		Body: []byte(`Exception in thread "main" java.lang.RuntimeException`), BodySize: 60,
	}, ResponseConfig{Mode: "OBSERVE"})
	if err != nil {
		t.Fatal(err)
	}
	if act != "OBSERVE" {
		t.Fatalf("action=%s", act)
	}
	for _, match := range ctx.CopyMatches() {
		for _, value := range match.Evidence {
			if strings.Contains(value, "2.4.49") || strings.Contains(value, "RuntimeException") {
				t.Fatalf("raw server detail leaked: %+v", match.Evidence)
			}
		}
	}
}
