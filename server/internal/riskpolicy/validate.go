// validate.go 风险策略输入校验（PUT 全量更新前置；与 store.Update 共用同一校验）。
package riskpolicy

import (
	"fmt"
	"regexp"
)

// 校验边界
const (
	maxThreshold     = 100    // 风险分阈值上限（与表 CHECK 一致，1-100）
	maxRPS           = 100000 // 限速 RPS 上限
	maxWindowSeconds = 604800 // 信号汇总窗口上限（7 天）
	maxScore         = 100    // 单信号分值上限
)

// signalKeyPattern scores 键格式（信号类型标识：大写字母开头的 SNAKE_CASE，
// 如 URI_ENUMERATION / SQLI / HEADLESS；Risk Engine 汇总多类 Detector 信号，
// 键集合由网关侧定义，管理面仅约束格式不限定枚举）。
var signalKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// FieldError 字段级校验错误。
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError 校验错误集合（handler 转 400 响应 details）。
type ValidationError struct {
	Errors []FieldError
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("risk policy validation failed: %d field(s)", len(e.Errors))
}

// Validate 校验策略全字段，返回字段级错误列表（空 = 通过）：
// mode 限定 OBSERVE/PROTECT；block/rate_limit 阈值 1-100 且 rate_limit < block
// （限速应先于阻断触达）；rate_limit_rps 1-100000；signal_window_seconds 1-604800；
// scores 键为合法信号类型格式、值 0-100；risk_levels 恰为 medium/high/critical
// 三键、值 0-100 且严格递增（等级区间不得倒置/重叠）。
func Validate(p *Policy) []FieldError {
	errs := []FieldError{}
	add := func(field, msg string) {
		errs = append(errs, FieldError{Field: field, Message: msg})
	}

	if p.Mode != ModeObserve && p.Mode != ModeProtect {
		add("mode", "仅支持 OBSERVE / PROTECT")
	}

	blockOK := p.BlockThreshold >= 1 && p.BlockThreshold <= maxThreshold
	rateOK := p.RateLimitThreshold >= 1 && p.RateLimitThreshold <= maxThreshold
	if !blockOK {
		add("block_threshold", fmt.Sprintf("阈值必须在 1~%d 之间", maxThreshold))
	}
	if !rateOK {
		add("rate_limit_threshold", fmt.Sprintf("阈值必须在 1~%d 之间", maxThreshold))
	} else if blockOK && p.RateLimitThreshold >= p.BlockThreshold {
		add("rate_limit_threshold", "限速阈值必须小于阻断阈值")
	}

	if p.RateLimitRPS < 1 || p.RateLimitRPS > maxRPS {
		add("rate_limit_rps", fmt.Sprintf("必须在 1~%d 之间", maxRPS))
	}
	if p.SignalWindowSeconds < 1 || p.SignalWindowSeconds > maxWindowSeconds {
		add("signal_window_seconds", fmt.Sprintf("必须在 1~%d 秒之间", maxWindowSeconds))
	}

	// 信号分值覆盖：键为合法信号类型格式，值 0-100
	for sig, score := range p.Scores {
		if !signalKeyPattern.MatchString(sig) {
			add("scores", "非法的信号类型键: "+sig)
			continue
		}
		if score < 0 || score > maxScore {
			add("scores."+sig, fmt.Sprintf("分值必须在 0~%d 之间", maxScore))
		}
	}

	// 风险等级阈值：恰为 medium/high/critical 三键，值 0-100 且严格递增
	if len(p.RiskLevels) != len(ValidRiskLevels) {
		add("risk_levels", "必须且仅须包含 medium/high/critical 三个等级阈值")
	} else {
		prev := -1
		for _, level := range ValidRiskLevels {
			v, ok := p.RiskLevels[level]
			if !ok {
				add("risk_levels", "缺少等级阈值: "+level)
				continue
			}
			if v < 0 || v > maxThreshold {
				add("risk_levels."+level, fmt.Sprintf("阈值必须在 0~%d 之间", maxThreshold))
				continue
			}
			if v <= prev {
				add("risk_levels."+level, "等级阈值必须严格递增（medium < high < critical）")
			}
			prev = v
		}
	}
	return errs
}
