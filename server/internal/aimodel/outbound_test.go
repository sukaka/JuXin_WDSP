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
		"http://[::ffff:169.254.169.254]/latest/meta-data",
		"http://169.254.170.2/v2/credentials",
		"http://100.100.100.200/latest/meta-data",
		"http://[fd00:ec2::254]/latest/meta-data",
		"http://127.0.0.1:2019",
		"http://127.0.0.1:5432",
	} {
		p := &Provider{Type: ProviderOpenAICompatible, BaseURL: baseURL, AllowedTargets: []string{"127.0.0.0/8", "169.254.0.0/16"}}
		if err := ValidateProviderEndpoint(context.Background(), p); !errors.Is(err, outboundhttp.ErrDenied) {
			t.Errorf("sensitive endpoint %s should be denied, err=%v", baseURL, err)
		}
	}
}

func TestH20ValidateUserAllowedTargetsRejectsLoopbackAndMetadata(t *testing.T) {
	denied := [][]string{
		{"127.0.0.0/8"},
		{"127.0.0.1/32"},
		{"::1/128"},
		{"::ffff:127.0.0.1/128"},
		{"0.0.0.0/0"},
		{"::/0"},
		{"169.254.169.254/32"},
		{"169.254.170.2/32"},
		{"100.100.100.200/32"},
		{"fd00:ec2::254/128"},
		{"169.254.0.0/16"},
		{"fe80::/10"},
		{"localhost"},
		{"sub.localhost"},
		{"metadata.google.internal"},
	}
	for _, targets := range denied {
		if err := ValidateUserAllowedTargets(targets); !errors.Is(err, outboundhttp.ErrDenied) {
			t.Errorf("ValidateUserAllowedTargets(%v) = %v, want ErrDenied", targets, err)
		}
	}
	// 合法企业内网段/主机名放行
	for _, okTargets := range [][]string{
		{"10.10.0.0/16"},
		{"192.168.10.0/24"},
		{"vllm.internal.corp"},
	} {
		if err := ValidateUserAllowedTargets(okTargets); err != nil {
			t.Errorf("ValidateUserAllowedTargets(%v) unexpected err: %v", okTargets, err)
		}
	}
}
