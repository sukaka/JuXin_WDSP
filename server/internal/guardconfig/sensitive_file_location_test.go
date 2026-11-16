package guardconfig

import (
	"context"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func TestLoadAPISensitiveValueRulesPreservesFileLocation(t *testing.T) {
	p := &Provider{sensitiveValueRules: &fakeSensitiveValueRuleLister{rules: []gatewayconfig.GuardSensitiveValueRule{{
		DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"file"}, Level: "SENSITIVE",
	}}}}
	rules := p.loadAPISensitiveValueRules(context.Background())
	if len(rules) != 1 || len(rules[0].Locations) != 1 || rules[0].Locations[0] != "file" {
		t.Fatalf("file location must survive publication: %+v", rules)
	}
}
