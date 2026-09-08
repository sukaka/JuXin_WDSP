// publisher_gate.go 安全回归发布门禁挂接（WDSP P1-04 R3；任务书 §7.2）。
//
// 挂接点：executePublish 中候选编译完成（Generate + Caddy 校验 + 不可变版本
// 保存）之后、发往节点（loadGatewayConfig → 主节点 Caddy，及其后的次要节点
// 扇出）之前。门禁评估以本次实际构建的不可变候选指纹为准——任务排队后才执行
// 评估，且评估对象即随后发送的同一份 gen.JSON（不存在检查后替换窗口：
// 指纹从 gen.Hash 派生，gen.JSON 原样进入 loadGatewayConfig）。
//
// 纪律：无 skip_gate 参数；ENFORCE 下证据缺失/过期/撤销/不完整/验证失败阻止
// 发布（REGRESSION_GATE_REJECTED），门禁依赖不可用明确失败不静默放行
// （REGRESSION_GATE_UNAVAILABLE）；OFF 不检查、OBSERVE 只记录不阻断（语义在
// regression 包实现，本处只看评估结论）。
package gatewayconfig

import (
	"context"

	"github.com/google/uuid"
)

// RegressionGateInput 发布门禁评估输入（跨包契约；regression.Gate 适配实现）。
type RegressionGateInput struct {
	// Fingerprint 候选配置指纹（cfgfpv1:<configuration_hash>，S0 契约 #6）。
	Fingerprint string
	TaskID      uuid.UUID
	VersionID   uuid.UUID
	// RestoreChannel 已知良好恢复通道（GuardOverride 历史快照重放，§7.3）。
	RestoreChannel bool
}

// RegressionGateOutcome 评估结论（无错误返回——依赖不可用显式建模，
// 避免调用方把 error 当放行）。
type RegressionGateOutcome struct {
	Allowed     bool
	Unavailable bool   // 门禁依赖不可用（ENFORCE 下也属失败，码不同）
	Message     string // 拒绝/不可用原因（不含敏感材料）
}

// RegressionGate 发布门禁评估接口（装配层以 regression.Gate 适配注入；
// nil = 门禁未装配，行为与历史一致——门禁策略默认 OFF，未装配不改变既有发布）。
type RegressionGate interface {
	EvaluatePublish(ctx context.Context, in RegressionGateInput) RegressionGateOutcome
}

// SetRegressionGate 注入安全回归发布门禁（可为 nil）。
func (p *Publisher) SetRegressionGate(g RegressionGate) {
	p.regressionGate = g
}

// evaluateRegressionGate 在候选版本保存后、发往节点前执行门禁评估。
// 返回 (是否继续发布, 失败码, 失败消息)；门禁未装配或评估放行时继续。
func (p *Publisher) evaluateRegressionGate(ctx context.Context, taskID, versionID uuid.UUID, fingerprint string, restoreChannel bool) (bool, string, string) {
	if p.regressionGate == nil {
		return true, "", ""
	}
	out := p.regressionGate.EvaluatePublish(ctx, RegressionGateInput{
		Fingerprint:    fingerprint,
		TaskID:         taskID,
		VersionID:      versionID,
		RestoreChannel: restoreChannel,
	})
	if out.Allowed {
		return true, "", ""
	}
	if out.Unavailable {
		return false, "REGRESSION_GATE_UNAVAILABLE",
			"安全回归门禁依赖不可用，发布已暂停（不静默放行）: " + out.Message
	}
	return false, "REGRESSION_GATE_REJECTED",
		"安全回归证据不满足发布门禁: " + out.Message
}
