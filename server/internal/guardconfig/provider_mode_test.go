package guardconfig

import "testing"

// TestResolveAPIProtectionMode settings 表覆盖优先于构造配置；非法覆盖回退（fail-safe）。
func TestResolveAPIProtectionMode(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		override   string
		found      bool
		want       string
	}{
		{name: "无覆盖用构造配置", configured: "OBSERVE", override: "", found: false, want: "OBSERVE"},
		{name: "合法覆盖优先", configured: "OBSERVE", override: "PROTECT", found: true, want: "PROTECT"},
		{name: "覆盖大小写归一", configured: "OBSERVE", override: "off", found: true, want: "OFF"},
		{name: "非法覆盖回退构造配置", configured: "PROTECT", override: "BLOCK", found: true, want: "PROTECT"},
		{name: "空白覆盖回退构造配置", configured: "OBSERVE", override: "  ", found: true, want: "OBSERVE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveAPIProtectionMode(tt.configured, tt.override, tt.found); got != tt.want {
				t.Fatalf("resolveAPIProtectionMode(%q,%q,%v)=%s want %s",
					tt.configured, tt.override, tt.found, got, tt.want)
			}
		})
	}
}
