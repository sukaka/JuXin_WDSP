package detectors

import (
	"net/http"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// CheckCredentialTransport 检查 URL 与 Cookie 中的凭据暴露风险。
// Cookie 仅检查名称，绝不读取 Cookie 值；Query 仅检查字段名，不记录参数值。
func CheckCredentialTransport(ctx *dsctx.RequestContext, r *http.Request, p *parser.Parsed, mode decision.Mode) {
	if ctx == nil || r == nil || p == nil {
		return
	}
	patterns, _ := CompileSensitivePatterns(nil)
	for name := range p.Query {
		typ, ok := matchSensitive(name, patterns)
		if !ok || typ != "credential" {
			continue
		}
		category, severity, score := "OBSERVE", "MEDIUM", 15
		if mode == decision.ModeProtect {
			category, severity, score = "BLOCK", "HIGH", 40
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "credential_transport", RuleID: "credential.url_password",
			Category: category, Severity: severity, Message: "credential exposed in url query",
			Evidence: map[string]string{"field": name, "location": "query"}, ScoreDelta: score,
		})
	}
	for _, cookie := range r.Cookies() {
		typ, ok := matchSensitive(cookie.Name, patterns)
		if !ok || typ != "credential" {
			continue
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "credential_transport", RuleID: "credential.cookie_sensitive",
			Category: "OBSERVE", Severity: "MEDIUM", Message: "sensitive cookie name observed",
			Evidence: map[string]string{"cookie_name": cookie.Name}, ScoreDelta: 10,
		})
	}
}
