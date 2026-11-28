package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateWithVersionedRulesBasePath(t *testing.T) {
	const versionedBase = "/etc/caddy/rules/releases/20261201.1"
	gen, err := Generate(GenerateInput{
		AdminSocket:   "/var/run/caddy/admin.sock",
		RulesBasePath: versionedBase,
		Apps:          sampleApps(),
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	wantIncludes := []string{
		"Include " + versionedBase + "/coraza.conf",
		"Include " + versionedBase + "/crs/crs-setup.conf",
		"Include " + versionedBase + "/crs/rules/*.conf",
		"Include " + versionedBase + "/contrib/*/*.conf",
		"Include " + versionedBase + "/jiuzhang/post-contrib-blocking.conf",
	}
	for _, inc := range wantIncludes {
		if !strings.Contains(gen.JSON, inc) {
			t.Errorf("expected generated JSON to contain %q", inc)
		}
	}
	// post-contrib-blocking.conf 必须仍是最后一条 Include
	lastInc := strings.LastIndex(gen.JSON, "Include "+versionedBase+"/")
	blockIdx := strings.Index(gen.JSON, "Include "+versionedBase+"/jiuzhang/post-contrib-blocking.conf")
	if lastInc != blockIdx || blockIdx < 0 {
		t.Fatalf("post-contrib-blocking.conf must be the final Include (blockIdx=%d, lastInc=%d)", blockIdx, lastInc)
	}
	// 不应再混入旧版扁平路径 Include /etc/caddy/rules/coraza.conf
	if strings.Contains(gen.JSON, "Include /etc/caddy/rules/coraza.conf") {
		t.Fatal("generated JSON leaked unversioned flat rules path")
	}
}

func TestBuildMinimalRuleValidationConfig(t *testing.T) {
	const versionedBase = "/etc/caddy/rules/releases/20261215.1"
	raw, err := BuildMinimalRuleValidationConfig("/var/run/caddy/admin.sock", versionedBase)
	if err != nil {
		t.Fatalf("BuildMinimalRuleValidationConfig failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("invalid minimal config JSON: %v", err)
	}
	if !strings.Contains(raw, "Include "+versionedBase+"/coraza.conf") ||
		!strings.Contains(raw, "Include "+versionedBase+"/jiuzhang/post-contrib-blocking.conf") {
		t.Fatalf("minimal config missing versioned Includes: %s", raw)
	}
}
