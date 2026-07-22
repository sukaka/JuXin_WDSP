// Package decision 统一决策：检测器只写 Matches，最终动作仅由此引擎设置。
package decision

import (
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// Mode 防护模式。
type Mode string

const (
	ModeOff     Mode = "OFF"
	ModeObserve Mode = "OBSERVE"
	ModeProtect Mode = "PROTECT"
)

// Input 决策输入。
type Input struct {
	Mode Mode // 默认 PROTECT
}

// Decide 根据上下文中的 Matches 设置 FinalAction（唯一允许 finalize 的路径）。
func Decide(ctx *dsctx.RequestContext, in Input) dsctx.FinalAction {
	if ctx == nil {
		return dsctx.ActionAllow
	}
	mode := in.Mode
	if mode == "" {
		mode = ModeProtect
	}
	if mode == ModeOff {
		ctx.SetFinalAction(dsctx.ActionAllow)
		return dsctx.ActionAllow
	}

	var (
		hasBlock     bool
		hasTempBlock bool
		hasRateLimit bool
		hasObserve   bool
	)
	// snapshot matches
	n := ctx.MatchCount()
	// re-read via AddMatch side effects already applied; walk Extensions not needed
	// Use risk score and match categories from matches by re-adding scan:
	// We need access to matches — add method on context
	matches := SnapshotMatches(ctx)
	for _, m := range matches {
		cat := strings.ToUpper(m.Category)
		sev := strings.ToUpper(m.Severity)
		// 纯信息性明细（如凭据存在）不参与动作决策
		if cat == "INFO" || sev == "INFO" {
			continue
		}
		switch {
		case cat == "TEMP_BLOCK" || strings.EqualFold(m.Detector, "temp_block"):
			hasTempBlock = true
		case cat == "RATE_LIMIT" || strings.EqualFold(m.Detector, "rate_limit"):
			hasRateLimit = true
		case cat == "BLOCK" || sev == "CRITICAL" || sev == "HIGH" || m.ScoreDelta >= 50:
			if strings.EqualFold(m.Detector, "waf") || strings.EqualFold(m.Detector, "api_schema") ||
				strings.EqualFold(m.Detector, "access_control") || cat == "BLOCK" {
				hasBlock = true
			} else if m.ScoreDelta >= 50 {
				hasBlock = true
			}
		case cat == "OBSERVE" || sev == "MEDIUM" || sev == "LOW" || m.ScoreDelta > 0:
			hasObserve = true
		}
	}
	_ = n

	var action dsctx.FinalAction
	switch {
	case hasTempBlock:
		action = dsctx.ActionTempBlock
	case hasRateLimit:
		action = dsctx.ActionRateLimit
	case hasBlock && mode == ModeProtect:
		action = dsctx.ActionBlock
	case hasBlock && mode == ModeObserve:
		action = dsctx.ActionObserve
	case hasObserve:
		action = dsctx.ActionObserve
	default:
		action = dsctx.ActionAllow
	}
	ctx.SetFinalAction(action)
	return action
}

// SnapshotMatches 导出当前匹配列表（决策/测试用）。
func SnapshotMatches(ctx *dsctx.RequestContext) []dsctx.DetectorMatch {
	if ctx == nil {
		return nil
	}
	return ctx.CopyMatches()
}
