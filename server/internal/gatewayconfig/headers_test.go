package gatewayconfig

import (
	"strings"
	"testing"
)

func TestVersionDisclosureResponseHeadersAlwaysHidden(t *testing.T) {
	cases := []struct {
		name string
		cfg  *AppHeaderConfig
	}{
		{name: "default"},
		{name: "legacy keep", cfg: &AppHeaderConfig{ServerAction: "keep", XPoweredByAction: "keep"}},
		{name: "legacy replace and custom readd", cfg: &AppHeaderConfig{
			ServerAction: "replace", ServerValue: "nginx/1.27.0",
			XPoweredByAction: "replace", XPoweredByValue: "PHP/8.4.0",
			CustomResponseRules: []HeaderRule{
				{Name: "Via", Method: "set", Value: "1.1 Caddy"},
				{Name: "x-postgresql-version", Method: "add", Value: "16.4"},
				{Name: "X-Safe", Method: "set", Value: "ok"},
			},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := buildHeaderHandler(tc.cfg)
			response := handler["response"].(mapT)
			if deferred, ok := response["deferred"].(bool); !ok || !deferred {
				t.Fatal("版本头清理必须在响应写出前执行")
			}
			deleted := make(map[string]bool)
			for _, name := range response["delete"].([]string) {
				deleted[strings.ToLower(name)] = true
			}
			for _, name := range versionDisclosureResponseHeaders {
				if !deleted[strings.ToLower(name)] {
					t.Errorf("缺少固定删除头 %s", name)
				}
			}
			for _, operation := range []string{"set", "add"} {
				values, ok := response[operation].(map[string][]string)
				if !ok {
					continue
				}
				for name := range values {
					if isVersionDisclosureResponseHeader(name) {
						t.Errorf("%s 不应重新设置版本头 %s", operation, name)
					}
				}
			}
		})
	}
}

func TestHeaderHandlerKeepsNonVersionCustomRules(t *testing.T) {
	cfg := &AppHeaderConfig{
		XAuthorAction: "replace", XAuthorValue: "security-team",
		CustomResponseRules: []HeaderRule{{Name: "X-Safe", Method: "set", Value: "ok"}},
	}
	response := buildHeaderHandler(cfg)["response"].(mapT)
	set := response["set"].(map[string][]string)
	if got := set["X-Author"]; len(got) != 1 || got[0] != "security-team" {
		t.Fatalf("X-Author 自定义行为被改变: %v", got)
	}
	if got := set["X-Safe"]; len(got) != 1 || got[0] != "ok" {
		t.Fatalf("普通自定义响应头被改变: %v", got)
	}
}
