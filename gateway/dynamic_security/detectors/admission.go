// admission.go API 准入检测（WDSP P1，docs/API_ADMISSION_CONTROL_DESIGN.md §4.1）：
// 应用级准入策略（发布通道下发 api_admission 段）判定「这个 API 允不允许存在」——
// 与全局 api_protection_mode 的模型偏离防护正交：准入管端点存在性，模型管请求符合性。
//
// 判定口径（§3.2）：请求端点键（管线统一口径 ek = method + " " + normalized_path）
// 在该应用已确认集合（asset_status=CONFIRMED 子集，server 下发）中 → 放行无 finding；
// 不在确认集合时按基线（KnownEndpoints，endpoint_key → asset_status 全量映射）区分：
//   - 基线有此端点（DISCOVERED/IGNORED/DEPRECATED/ZOMBIE）→ admission.unconfirmed_endpoint；
//   - 基线完全无此端点（从未发现，含基线未下发 nil）→ admission.unknown_endpoint。
//
// 模式语义：OBSERVE → OBSERVE/LOW 仅记录；PROTECT → BLOCK/HIGH（决策引擎 cat==BLOCK
// 分支天然获得阻断资格，最终实断与否由统一决策按全局管线模式定案，检测器不擅自执行）。
// mode 词表外/缺失 fail-safe 视为 OFF（不启用不判定——不拦截优于误拦截），
// 装配层已在编译期归一，此处仍防御性跳过（检测器不对配置来源做信任假设）。
package detectors

import (
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 准入模式词表（应用级，与 decision.Mode 同词不同维度：准入策略按应用下发，
// 不读写全局管线模式）。词表外/缺失 fail-safe 视为 OFF。
const (
	AdmissionModeOff     = "OFF"
	AdmissionModeObserve = "OBSERVE"
	AdmissionModeProtect = "PROTECT"
)

// AdmissionPolicy 单个应用的准入策略（装配层按 application_id 解析后传入；
// Confirmed 为已确认端点键集合，只含 CONFIRMED，查找 O(1)）。
type AdmissionPolicy struct {
	Mode      string              // OFF | OBSERVE | PROTECT（词表外按 OFF）
	Confirmed map[string]struct{} // endpoint_key → 成员标记；nil/空 = 无确认端点
}

// AdmissionOutcome 准入判定结果（供装配层去重与短路，不携带请求状态）。
type AdmissionOutcome struct {
	// UnknownCovered 本次已产出 admission.unknown_endpoint（端点不在基线）。
	// 装配层据此跳过 lifecycle.new_endpoint：两者同语义（端点不在已知基线），
	// server 侧 OBSERVE 期同映射 SHADOW finding，并存会产生重复 finding——
	// 去重策略取「准入覆盖后 lifecycle 跳过」（deprecated_api_call 语义不同，不受影响）。
	UnknownCovered bool
	// ProtectDenied PROTECT 模式命中未确认/未知端点（BLOCK 类 finding 已写入上下文）。
	// 装配层据此短路后续重检测器（早退优化，集合查找已定案，schema/模型计算无意义）；
	// 不影响事件/finding/统一决策的正常产出。
	ProtectDenied bool
}

// CheckAdmission API 准入判定：endpointKey 为管线统一口径端点键；known 为已知端点
// 基线（发布通道下发，nil = 无基线——不在确认集合即按 unknown 处理）。policy 零值
// （Mode 空/OFF/词表外）不判定直接返回，与「应用无策略不判定」语义一致。
func CheckAdmission(ctx *dsctx.RequestContext, endpointKey string, policy AdmissionPolicy, known map[string]string) AdmissionOutcome {
	var out AdmissionOutcome
	if ctx == nil || endpointKey == "" {
		return out
	}
	if policy.Mode != AdmissionModeObserve && policy.Mode != AdmissionModeProtect {
		return out // OFF/缺失/词表外：fail-safe 不判定
	}
	if _, ok := policy.Confirmed[endpointKey]; ok {
		return out // 已确认端点：放行，无 finding
	}
	// 未确认：按基线区分 unknown（基线无此端点）与 unconfirmed（基线有但非 CONFIRMED）
	ruleID := "admission.unknown_endpoint"
	message := "endpoint not in admission baseline (never discovered)"
	evidence := map[string]string{
		"endpoint_key":   endpointKey,
		"admission_mode": policy.Mode,
	}
	if status, ok := known[endpointKey]; ok {
		ruleID = "admission.unconfirmed_endpoint"
		message = "endpoint in baseline but not confirmed for admission"
		evidence["asset_status"] = status
	} else {
		out.UnknownCovered = true
	}
	match := dsctx.DetectorMatch{
		Detector:   "admission",
		RuleID:     ruleID,
		Message:    message,
		Evidence:   evidence,
		ScoreDelta: 5,   // 与 lifecycle.new_endpoint 同分（OBSERVE 级基线成员判定）
		Confidence: 1.0, // 确定性集合成员判定
	}
	if policy.Mode == AdmissionModeProtect {
		match.Category = "BLOCK"
		match.Severity = "HIGH"
		match.ScoreDelta = 40 // 与确定性 BLOCK 规则同档（schema.type_mismatch/file 合规）
		out.ProtectDenied = true
	} else {
		match.Category = "OBSERVE"
		match.Severity = "LOW"
	}
	ctx.AddMatch(match)
	return out
}
