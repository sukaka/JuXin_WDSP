package apiassets

import (
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
)

// TestEndpointIdentityUsesSharedNormalizer 管理面发现与网关共用归一化，保证 identity 一致。
func TestEndpointIdentityUsesSharedNormalizer(t *testing.T) {
	tpl := normalizer.NormalizePath("/users/123")
	if tpl != "/users/{id}" {
		t.Fatal(tpl)
	}
	k := normalizer.EndpointKey("post", "/users/99")
	if k != "POST /users/{id}" {
		t.Fatal(k)
	}
}
