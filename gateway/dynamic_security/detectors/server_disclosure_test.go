package detectors

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestCheckServerDisclosure(t *testing.T) {
	ctx := dsctx.New("server-disclosure", dsctx.DefaultParseLimits())
	headers := map[string]string{"server": "Apache/2.4.49", "x-powered-by": "PHP/8.2.1"}
	body := []byte(`Exception in thread "main" java.lang.RuntimeException: database failed`)
	CheckServerDisclosure(ctx, 500, headers, body)
	if len(ctx.CopyMatches()) != 3 {
		t.Fatalf("matches=%+v", ctx.CopyMatches())
	}
	for _, match := range ctx.CopyMatches() {
		for _, value := range match.Evidence {
			if strings.Contains(value, "2.4.49") || strings.Contains(value, "8.2.1") || strings.Contains(value, "database failed") {
				t.Fatalf("raw version or error leaked: %+v", match.Evidence)
			}
		}
	}
}

func TestCheckServerDisclosureNormalResponse(t *testing.T) {
	ctx := dsctx.New("server-normal", dsctx.DefaultParseLimits())
	CheckServerDisclosure(ctx, 200, map[string]string{"content-type": "application/json"}, []byte(`{"ok":true}`))
	if len(ctx.CopyMatches()) != 0 {
		t.Fatalf("normal response produced matches: %+v", ctx.CopyMatches())
	}
}
