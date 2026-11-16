package jiuzhang_guard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/temporaryblock"
	"go.uber.org/zap"
)

const defaultAPITempBlockSeconds = 60

func normalizedAPIRateLimitAction(value string) string {
	action := strings.ToUpper(strings.TrimSpace(value))
	if action == "" {
		return "RATE_LIMIT"
	}
	return action
}

func normalizedAPITempBlockSeconds(value int) int {
	if value == 0 {
		return defaultAPITempBlockSeconds
	}
	return value
}

func validateAPIRateLimitDisposition(action string, seconds int) error {
	switch normalizedAPIRateLimitAction(action) {
	case "RATE_LIMIT", "BLOCK", "TEMP_BLOCK":
	default:
		return fmt.Errorf("api_rate_limit_action must be RATE_LIMIT, BLOCK or TEMP_BLOCK")
	}
	if seconds < 0 || seconds > 86400 {
		return fmt.Errorf("api_temp_block_seconds must be 0 or between 1 and 86400")
	}
	return nil
}

// createAPIRateLimitTempBlock 将 API 限速升级为真实自动临时封禁；缺真实 IP 或写入失败只告警，
// 不伪造 CC_TEMP_BLOCK_CREATED 记录，当前请求仍按原 ActionTempBlock 路径返回 403。
func (g *Guard) createAPIRateLimitTempBlock(r *http.Request, requestID string, finalDecision json.RawMessage) {
	ipResult, ok := clientIPResultFrom(r.Context())
	if !ok || !ipResult.ClientIP.IsValid() {
		g.logger.Warn("api rate limit temporary block skipped: real client IP unavailable", zap.String("request_id", requestID))
		return
	}
	if g.engine == nil || g.engine.blockCache == nil {
		g.logger.Warn("api rate limit temporary block skipped: block cache unavailable", zap.String("request_id", requestID))
		return
	}
	expiresAt := time.Now().UTC().Add(time.Duration(normalizedAPITempBlockSeconds(g.APITempBlockSeconds)) * time.Second)
	block := temporaryblock.Block{
		ClientIP:  ipResult.ClientIP.String(),
		AppID:     g.AppID,
		Reason:    "api_rate_limit",
		Auto:      true,
		ExpiresAt: expiresAt,
	}
	if err := g.engine.blockCache.PutLocal(r.Context(), block); err != nil {
		g.logger.Warn("api rate limit temporary block write failed", zap.String("request_id", requestID), zap.Error(err))
		return
	}
	ev := g.eventBase(r, requestID, ipResult)
	ev.Action = "TEMP_BLOCK"
	ev.BlockExpiresAt = &expiresAt
	ev.FinalDecision = finalDecision
	g.emit(ev, events.CCTempBlockCreated, "TEMP_BLOCK", 0)
}
