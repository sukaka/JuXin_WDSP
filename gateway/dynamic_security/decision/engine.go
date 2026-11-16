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

// ExceptionRef 受限例外规则引用（WDSP P0-04，契约冻结 S4_DESIGN_BASELINE §10；
// 由 jiuzhang_guard FilterAPIExceptions 按请求范围筛选后展开传入）。
// 命中判定：DetectorID+RuleID 与 Finding 精确匹配；ModelVersion 非空（钉版）时
// 还要求等于 Finding.ModelVersion。ExceptionID/Version 用于 Finding 打标溯源。
type ExceptionRef struct {
	ExceptionID  string `json:"exception_id"`
	Version      int    `json:"version"`
	DetectorID   string `json:"detector_id"`
	RuleID       string `json:"rule_id"`
	ModelVersion string `json:"model_version,omitempty"`
}

// Input 决策输入。
type Input struct {
	Mode Mode // 默认 PROTECT
	// RateLimitAction RATE_LIMIT 类在 PROTECT 下的处置：空/RATE_LIMIT=429，
	// BLOCK=403，TEMP_BLOCK=403+真实临时封禁（由 Guard 执行）；OBSERVE 仍统一降级。
	RateLimitAction string
	// Exceptions 本请求适用的受限例外规则引用（装配层已按应用/域名/路径/方法/来源 IP/
	// 有效期完成范围筛选）：命中的 Finding 保留证据并打标 Excepted，其 ScoreDelta 与
	// 执法类别从本次定案排除后按既有优先级重算；nil 与空切片等价（零行为变化）。
	Exceptions []ExceptionRef
}

// exceptionRefMatches 例外引用命中判定：detector_id+rule_id 精确匹配；
// ref.ModelVersion 非空（钉版）时还要求等于 Finding.ModelVersion。
func exceptionRefMatches(ref ExceptionRef, m dsctx.DetectorMatch) bool {
	if ref.DetectorID != m.Detector || ref.RuleID != m.RuleID {
		return false
	}
	if ref.ModelVersion != "" && ref.ModelVersion != m.ModelVersion {
		return false
	}
	return true
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
	matches := SnapshotMatches(ctx)
	// 受限例外打标（WDSP P0-04）：每条 Finding 取第一条命中的例外引用（输入序即优先级，
	// 先入例外优先）；MarkMatchExcepted 幂等——重复 Decide 不重复打标、不覆盖既有标记；
	// 写回失败（快照过期/并发已标）时该 Finding 保持未豁免（fail-safe，防护不退化）。
	// 被豁免 Finding 保留于 Matches（证据不删），事件输出自然携带 exception_id/version。
	if len(in.Exceptions) > 0 {
		for i, m := range matches {
			if m.Excepted {
				continue
			}
			for _, ref := range in.Exceptions {
				if !exceptionRefMatches(ref, m) {
					continue
				}
				if ctx.MarkMatchExcepted(i, m.Detector, m.RuleID, ref.ExceptionID, ref.Version) {
					matches[i].Excepted = true
					matches[i].ExceptionID = ref.ExceptionID
					matches[i].ExceptionVersion = ref.Version
				}
				break
			}
		}
	}
	for _, m := range matches {
		// 被豁免 Finding 从定案排除：其 ScoreDelta/Category 不再贡献
		// hasBlock/hasTempBlock/hasRateLimit/hasObserve（证据仍保留于 Matches）。
		if m.Excepted {
			continue
		}
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
			// BLOCK 定案仅限可信阻断源（waf/api_schema/access_control 或显式 BLOCK 类）
			// 或高分（>=50）；其余 OBSERVE 类高严重度低分明细（如 auth.jwt_alg_none、
			// authz.bfla_anonymous、auth.env_anomaly_stack）不定案 BLOCK，但任何 OBSERVE
			// 类明细无论 severity 至少记 hasObserve，保证单独命中时至少定案 OBSERVE。
			if strings.EqualFold(m.Detector, "waf") || strings.EqualFold(m.Detector, "api_schema") ||
				strings.EqualFold(m.Detector, "access_control") || cat == "BLOCK" {
				hasBlock = true
			} else if m.ScoreDelta >= 50 {
				hasBlock = true
			} else {
				hasObserve = true
			}
		case cat == "OBSERVE" || sev == "MEDIUM" || sev == "LOW" || m.ScoreDelta > 0:
			hasObserve = true
		}
	}

	// 定案优先级：BLOCK > TEMP_BLOCK > RATE_LIMIT > MASK_RESPONSE > OBSERVE > ALLOW。
	// 阻断/限速类动作仅在 PROTECT 模式实断，非 PROTECT（OBSERVE）一律降级为 OBSERVE，
	// 与 BLOCK 分支同口径。核实结论：RATE_LIMIT/TEMP_BLOCK 明细仅可能来自 API 域
	// 检测器（detectors/ratelimit.go CheckAPIWriteRate，pipeline 装配；temp_block
	// 类别为预留分支）；WAF 域 CC 限速与临时封禁在 jiuzhang_guard module.go 更早
	// 环节独立实断（直接 403/429），不经本引擎，此处降级不影响 WAF 域防护语义。
	var action dsctx.FinalAction
	switch {
	case hasBlock && mode == ModeProtect:
		action = dsctx.ActionBlock
	case hasTempBlock && mode == ModeProtect:
		action = dsctx.ActionTempBlock
	case hasRateLimit && mode == ModeProtect:
		switch strings.ToUpper(strings.TrimSpace(in.RateLimitAction)) {
		case "BLOCK":
			action = dsctx.ActionBlock
		case "TEMP_BLOCK":
			action = dsctx.ActionTempBlock
		default:
			action = dsctx.ActionRateLimit
		}
	case ctx.HasTransformPlan() && mode == ModeProtect:
		// 响应脱敏计划非空且 PROTECT：放行但改写响应体（MASK_RESPONSE）。
		// 优先级低于一切阻断类动作（阻断请求无响应相位）；OBSERVE 模式仅记录计划，不执行。
		action = dsctx.ActionMaskResp
	case hasBlock || hasTempBlock || hasRateLimit:
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
