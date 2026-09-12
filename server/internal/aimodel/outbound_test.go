package aimodel

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/outboundhttp"
)

func TestCanonicalOriginNormalizesSchemeHostAndPort(t *testing.T) {
	got, err := CanonicalOrigin("HTTPS://Example.COM/api/chat")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.com:443" {
		t.Fatalf("origin=%q", got)
	}
	got, err = CanonicalOrigin("http://Example.COM:8080/path")
	if err != nil || got != "http://example.com:8080" {
		t.Fatalf("origin=%q err=%v", got, err)
	}
}

func TestValidateProviderEndpointRequiresExplicitPrivateScope(t *testing.T) {
	p := &Provider{Type: ProviderOpenAICompatible, BaseURL: "http://127.0.0.1:18080"}
	if err := ValidateProviderEndpoint(context.Background(), p); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("private endpoint without scope should be denied, err=%v", err)
	}
	p.AllowedTargets = []string{"127.0.0.0/8"}
	if err := ValidateProviderEndpoint(context.Background(), p); err != nil {
		t.Fatalf("explicitly scoped private endpoint should be accepted: %v", err)
	}
}

func TestValidateProviderEndpointAlwaysRejectsSensitiveTargets(t *testing.T) {
	for _, baseURL := range []string{
		"http://169.254.169.254/latest/meta-data",
		"http://127.0.0.1:2019",
		"http://127.0.0.1:5432",
	} {
		p := &Provider{Type: ProviderOpenAICompatible, BaseURL: baseURL, AllowedTargets: []string{"127.0.0.0/8", "169.254.0.0/16"}}
		if err := ValidateProviderEndpoint(context.Background(), p); !errors.Is(err, outboundhttp.ErrDenied) {
			t.Errorf("sensitive endpoint %s should be denied, err=%v", baseURL, err)
		}
	}
}
