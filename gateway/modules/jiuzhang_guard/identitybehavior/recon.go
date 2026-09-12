package identitybehavior

import (
	"fmt"
	"math"
)

// 侦察信号名（事件 signal 字段 / scores 覆盖 key）。
const (
	SignalURIEnumeration      = "URI_ENUMERATION"
	SignalNotFoundEnumeration = "NOT_FOUND_ENUMERATION"
	SignalSensitivePathProbe  = "SENSITIVE_PATH_PROBE"
	SignalMethodEnumeration   = "METHOD_ENUMERATION"
	SignalParameterMutation   = "PARAMETER_MUTATION"
	SignalAuthFailProbe       = "AUTH_FAIL_PROBE"
	SignalLowSlowRecon        = "LOW_SLOW_RECON"
	SignalHeadless            = "HEADLESS"
	SignalAccountEnumeration  = "ACCOUNT_ENUMERATION"
	SignalObjectEnumeration   = "OBJECT_ENUMERATION"
)

// 侦察规则码（事件 rule_code 字段；规则集版本见 RuleVersion）。
const (
	RuleURIEnumeration      = "RECON-URI-001"
	RuleNotFoundEnumeration = "RECON-404-001"
	RuleSensitivePathProbe  = "RECON-PATH-001"
	RuleMethodEnumeration   = "RECON-METHOD-001"
	RuleParameterMutation   = "RECON-PARAM-001"
	RuleAuthFailProbe       = "AUTH-FAIL-001"
	RuleLowSlowRecon        = "RECON-LOWSLOW-001"
	RuleHeadless            = "HEADLESS-001"
	RuleAccountEnumeration  = "RECON-ACCOUNT-001"
	RuleObjectEnumeration   = "RECON-OBJECT-001"
)

// Signal 侦察信号（本阶段全部 OBSERVE，不拦截）。
type Signal struct {
	RuleCode    string
	RuleVersion string
	Signal      string
	ScoreDelta  int
	Mode        string
	Reason      string
	Window      string
	Metadata    map[string]any
}

// EvaluateRecon 纯函数式规则评估：配置 + 计数快照 → 命中信号集。
// sensitivePrefix 为当前请求命中的敏感路径前缀（空串 = 未命中，RECON-PATH-001 不评估）。
// 阈值/分值均来自配置（0 = 该规则关闭）；本阶段 Mode 恒 OBSERVE。
func EvaluateRecon(cfg *Config, snap *Snapshot, sensitivePrefix string) []Signal {
	if cfg == nil || snap == nil {
		return nil
	}
	var out []Signal
	emit := func(rule, signal, window, reason string, meta map[string]any) {
		out = append(out, Signal{
			RuleCode:    rule,
			RuleVersion: RuleVersion,
			Signal:      signal,
			ScoreDelta:  cfg.score(signal),
			Mode:        cfg.Mode,
			Reason:      reason,
			Window:      window,
			Metadata:    meta,
		})
	}

	w5 := snap.Windows[Window5m]

	// RECON-URI-001 URI 枚举：5m 窗 unique_uri 达阈值且 new_uri 占比达阈值
	if cfg.active(SignalURIEnumeration) && cfg.URIEnumUniqueThreshold > 0 && cfg.URIEnumNewRatioThreshold > 0 &&
		w5.UniqueURICount >= cfg.URIEnumUniqueThreshold && w5.RequestCount > 0 &&
		w5.NewURICount/w5.RequestCount >= cfg.URIEnumNewRatioThreshold {
		emit(RuleURIEnumeration, SignalURIEnumeration, Window5m.Name(),
			fmt.Sprintf("unique_uri_count %d >= %d and new_uri_ratio %.2f >= %.2f in 5m window",
				w5.UniqueURICount, cfg.URIEnumUniqueThreshold, w5.NewURICount/w5.RequestCount, cfg.URIEnumNewRatioThreshold),
			map[string]any{
				"unique_uri_count": w5.UniqueURICount,
				"new_uri_count":    round(w5.NewURICount),
				"request_count":    round(w5.RequestCount),
				"new_uri_ratio":    round4(w5.NewURICount / w5.RequestCount),
			})
	}

	// RECON-404-001 404 枚举：5m 窗请求量达下限且 404 占比达阈值
	if cfg.active(SignalNotFoundEnumeration) && cfg.NotFoundMinRequests > 0 && cfg.NotFoundRatioThreshold > 0 &&
		w5.RequestCount >= float64(cfg.NotFoundMinRequests) && w5.RequestCount > 0 &&
		w5.Status404Count/w5.RequestCount >= cfg.NotFoundRatioThreshold {
		emit(RuleNotFoundEnumeration, SignalNotFoundEnumeration, Window5m.Name(),
			fmt.Sprintf("request_count %d >= %d and not_found_ratio %.2f >= %.2f in 5m window",
				round(w5.RequestCount), cfg.NotFoundMinRequests, w5.Status404Count/w5.RequestCount, cfg.NotFoundRatioThreshold),
			map[string]any{
				"request_count":    round(w5.RequestCount),
				"status_404_count": round(w5.Status404Count),
				"not_found_ratio":  round4(w5.Status404Count / w5.RequestCount),
			})
	}

	// RECON-PATH-001 敏感路径探测：当前请求命中敏感路径前缀（按请求评估）
	if sensitivePrefix != "" && cfg.active(SignalSensitivePathProbe) {
		emit(RuleSensitivePathProbe, SignalSensitivePathProbe, "request",
			"request path matches sensitive path prefix",
			map[string]any{"matched_prefix": sensitivePrefix})
	}

	// RECON-METHOD-001 方法枚举：同 (identity,uri) 30m distinct method 数达阈值
	if cfg.active(SignalMethodEnumeration) && cfg.MethodEnumThreshold > 0 &&
		int64(snap.DistinctMethods) >= cfg.MethodEnumThreshold {
		emit(RuleMethodEnumeration, SignalMethodEnumeration, Window30m.Name(),
			fmt.Sprintf("distinct_methods %d >= %d for (identity,uri) in 30m",
				snap.DistinctMethods, cfg.MethodEnumThreshold),
			map[string]any{"distinct_methods": snap.DistinctMethods})
	}

	// RECON-PARAM-001 参数变异：5m 窗参数变异计数达阈值
	if cfg.active(SignalParameterMutation) && cfg.ParamMutationThreshold > 0 &&
		w5.ParameterMutationCount >= float64(cfg.ParamMutationThreshold) {
		emit(RuleParameterMutation, SignalParameterMutation, Window5m.Name(),
			fmt.Sprintf("parameter_mutation_count %d >= %d in 5m window",
				round(w5.ParameterMutationCount), cfg.ParamMutationThreshold),
			map[string]any{"parameter_mutation_count": round(w5.ParameterMutationCount)})
	}

	// AUTH-FAIL-001 认证失败探测：5m 窗认证失败计数达阈值
	if cfg.active(SignalAuthFailProbe) && cfg.AuthFailThreshold > 0 &&
		w5.AuthFailCount >= float64(cfg.AuthFailThreshold) {
		emit(RuleAuthFailProbe, SignalAuthFailProbe, Window5m.Name(),
			fmt.Sprintf("auth_fail_count %d >= %d in 5m window",
				round(w5.AuthFailCount), cfg.AuthFailThreshold),
			map[string]any{"auth_fail_count": round(w5.AuthFailCount)})
	}

	// 只有具备明确身份凭据时才评估枚举，避免匿名 IP 流量把公共查询参数误判为枚举。
	if cfg.active(SignalAccountEnumeration) && cfg.AccountEnumThreshold > 0 &&
		snap.IdentityConfidence >= 40 && w5.AccountEnumCount >= cfg.AccountEnumThreshold {
		emit(RuleAccountEnumeration, SignalAccountEnumeration, Window5m.Name(),
			fmt.Sprintf("unique_account_count %d >= %d in 5m window", w5.AccountEnumCount, cfg.AccountEnumThreshold),
			map[string]any{
				"unique_account_count": w5.AccountEnumCount,
				"identity_confidence":  snap.IdentityConfidence,
				"request_count":        round(w5.RequestCount),
				"status_401_count":     round(w5.Status401Count),
				"status_403_count":     round(w5.Status403Count),
				"status_404_count":     round(w5.Status404Count),
				"status_500_count":     round(w5.Status500Count),
				"identifier_fields":    append([]string(nil), cfg.AccountIdentifierFields...),
			})
	}
	if cfg.active(SignalObjectEnumeration) && cfg.ObjectEnumThreshold > 0 &&
		snap.IdentityConfidence >= 40 && w5.ObjectEnumCount >= cfg.ObjectEnumThreshold {
		emit(RuleObjectEnumeration, SignalObjectEnumeration, Window5m.Name(),
			fmt.Sprintf("unique_object_count %d >= %d in 5m window", w5.ObjectEnumCount, cfg.ObjectEnumThreshold),
			map[string]any{
				"unique_object_count": w5.ObjectEnumCount,
				"identity_confidence": snap.IdentityConfidence,
				"request_count":       round(w5.RequestCount),
				"status_401_count":    round(w5.Status401Count),
				"status_403_count":    round(w5.Status403Count),
				"status_404_count":    round(w5.Status404Count),
				"status_500_count":    round(w5.Status500Count),
				"identifier_fields":   append([]string(nil), cfg.ObjectIdentifierFields...),
			})
	}

	// RECON-LOWSLOW-001 低频慢速侦察：30m 或 24h 窗敏感路径命中达阈值（优先报 30m）
	if cfg.active(SignalLowSlowRecon) && cfg.LowSlowSensitiveMinHits > 0 {
		w30, w24 := snap.Windows[Window30m], snap.Windows[Window24h]
		switch {
		case w30.SensitivePathHits >= float64(cfg.LowSlowSensitiveMinHits):
			emit(RuleLowSlowRecon, SignalLowSlowRecon, Window30m.Name(),
				fmt.Sprintf("sensitive_path_hits %d >= %d in 30m window",
					round(w30.SensitivePathHits), cfg.LowSlowSensitiveMinHits),
				map[string]any{"sensitive_path_hits": round(w30.SensitivePathHits)})
		case w24.SensitivePathHits >= float64(cfg.LowSlowSensitiveMinHits):
			emit(RuleLowSlowRecon, SignalLowSlowRecon, Window24h.Name(),
				fmt.Sprintf("sensitive_path_hits %d >= %d in 24h window",
					round(w24.SensitivePathHits), cfg.LowSlowSensitiveMinHits),
				map[string]any{"sensitive_path_hits": round(w24.SensitivePathHits)})
		}
	}
	return out
}

// score 信号分值（0 = 规则关闭；配置表在 Compile 已合并默认值与下发覆盖）。
func (c *Config) score(signal string) int {
	if c == nil || c.Scores == nil {
		return 0
	}
	return c.Scores[signal]
}

// active 规则是否启用（分值 > 0；阈值条件由各规则自判）。
func (c *Config) active(signal string) bool { return c.score(signal) > 0 }

// round 浮点计数四舍五入为 int64（事件/证据整型呈现）。
func round(v float64) int64 { return int64(math.Round(v)) }

// round4 比率保留 4 位小数（事件证据呈现）。
func round4(v float64) float64 { return math.Round(v*10000) / 10000 }
