// Package detectors 运行时检测器：只写 Matches，不设置 FinalAction。
package detectors

import (
	"fmt"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// CheckSchemaDeviation 对比观测字段与冻结正式模型；偏离只产生 match，不修改 formal。
func CheckSchemaDeviation(ctx *dsctx.RequestContext, observed map[string]string, formal map[string]string) {
	if ctx == nil || formal == nil || len(formal) == 0 {
		return
	}
	for name, gotType := range observed {
		want, ok := formal[name]
		if !ok {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector:   "api_schema",
				RuleID:     "schema.undefined_field",
				Category:   "OBSERVE",
				Severity:   "MEDIUM",
				Message:    "undefined field vs formal model",
				Evidence:   map[string]string{"field": name, "type": gotType},
				ScoreDelta: 15,
			})
			continue
		}
		if want != "" && gotType != "" && want != gotType {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector:   "api_schema",
				RuleID:     "schema.type_mismatch",
				Category:   "BLOCK",
				Severity:   "HIGH",
				Message:    fmt.Sprintf("type mismatch for %s", name),
				Evidence:   map[string]string{"field": name, "want": want, "got": gotType},
				ScoreDelta: 40,
			})
		}
	}
	// missing required: formal keys with empty observed
	for name := range formal {
		if _, ok := observed[name]; !ok {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector:   "api_schema",
				RuleID:     "schema.missing_field",
				Category:   "OBSERVE",
				Severity:   "LOW",
				Message:    "missing formal field",
				Evidence:   map[string]string{"field": name},
				ScoreDelta: 5,
			})
		}
	}
}

// CheckIdentitySignals 身份/凭据存在性指纹（不存明文）。
func CheckIdentitySignals(ctx *dsctx.RequestContext, p *parser.Parsed) {
	if ctx == nil || p == nil {
		return
	}
	if v, ok := p.Headers["authorization"]; ok && v == "[redacted]" {
		ctx.AuthenticationType = "bearer_or_basic"
		ctx.TokenFingerprint = "present"
		// 信息性记录：不得抬高 FinalAction（决策引擎忽略 INFO）
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "identity",
			RuleID:   "identity.token_present",
			Category: "INFO",
			Severity: "INFO",
			Message:  "credential header present (redacted)",
			Evidence: map[string]string{"header": "authorization"},
		})
	}
	if v, ok := p.Headers["x-api-key"]; ok && v == "[redacted]" {
		ctx.APIKeyFingerprint = "present"
		ctx.AuthenticationType = "api_key"
	}
}
