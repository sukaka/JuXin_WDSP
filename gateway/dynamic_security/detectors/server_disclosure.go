package detectors

import (
	"strconv"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
)

var serverVersionHeaders = []string{
	"server", "x-powered-by", "x-aspnet-version", "x-runtime", "x-version",
	"x-generator", "via", "x-caddy", "x-nodejs", "x-php-version",
}

// CheckServerDisclosure 检查响应头中的服务器版本信息和错误堆栈泄露。
// 证据不记录版本原文、堆栈正文或响应体。
func CheckServerDisclosure(ctx *dsctx.RequestContext, status int, headers map[string]string, body []byte) {
	if ctx == nil {
		return
	}
	for _, header := range serverVersionHeaders {
		value := headers[header]
		if value == "" {
			continue
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "server_disclosure", RuleID: "server.version_disclosure",
			Category: "OBSERVE", Severity: "MEDIUM", Message: "server implementation header observed",
			Evidence: map[string]string{"header": header}, ScoreDelta: 10,
		})
	}
	signatures := response.ExtractErrorSignatures(status, body)
	for _, signature := range signatures {
		if !strings.HasPrefix(signature, "stack.") && !strings.HasPrefix(signature, "db.") {
			continue
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "server_disclosure", RuleID: "server.error_disclosure",
			Category: "OBSERVE", Severity: "MEDIUM", Message: "server error details observed in response",
			Evidence: map[string]string{"signature": signature, "status": strconv.Itoa(status)}, ScoreDelta: 10,
		})
	}
}
