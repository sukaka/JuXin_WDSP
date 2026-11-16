package jiuzhang_guard

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"go.uber.org/zap"
)

func (g *Guard) llmSecurityPolicyForApp() *detectors.LLMSecurityPolicy {
	if len(g.apiLLMSecurity) == 0 || g.AppID == "" {
		return nil
	}
	policy, ok := g.apiLLMSecurity[g.AppID]
	if !ok {
		return nil
	}
	return &policy
}

func hasLLMOutputBlock(matches []dsctx.DetectorMatch) bool {
	for _, match := range matches {
		if match.Category == "BLOCK" && strings.HasPrefix(match.RuleID, "llm.output_") {
			return true
		}
	}
	return false
}

func (g *Guard) writeLLMOutputBlockedResponse(w http.ResponseWriter, requestID string) {
	h := w.Header()
	h.Del("Content-Length")
	h.Del("Content-Encoding")
	h.Del("ETag")
	h.Del("Content-MD5")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	body, _ := json.Marshal(map[string]string{"error": "llm_output_protection", "request_id": requestID})
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write(body); err != nil {
		g.logger.Warn("llm output blocked response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}
