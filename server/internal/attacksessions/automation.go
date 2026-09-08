// automation.go 疑似自动化攻击派生标注（WDSP AI 自动化渗透防护增强 阶段4 补充；
// 设计 #45「一个身份在一段时间内是否正在执行自动化攻击行为」的显式标注形态）。
//
// 判定规则（纯函数、全可解释）：
//
//	会话内有效阶段（非 UNKNOWN）≥ 3 且 命中至少一个自动化指示信号（无头/枚举/低慢类——
//	人工浏览不会产生的行为指纹）→ automation_suspected = true。
//
// 单调性：会话内证据只增不减，标注只 false→true 不回退；判定依据（阶段集+指示信号）
// 持久化在 automation_basis 列（跨 Sweep 增量状态的载体，同时供前端 tooltip 展示）。
package attacksessions

import (
	"sort"
	"strings"
)

// automationMinStages 疑似自动化攻击的最小有效阶段数（非 UNKNOWN）。
const automationMinStages = 3

// automationBasisMaxLen basis 列长度上限（迁移 000106 VARCHAR(256)）。
const automationBasisMaxLen = 256

// automationIndicatorSignals 自动化指示信号（网关 identitybehavior/recon.go 与
// attacksessions/businesssec.go 契约值；AUTH_FAIL_PROBE/LOGIN_ABUSE 刻意不收——
// 人工误触/多账号家庭共享可达，仅靠阶段数门槛不足以区分，防误标）。
var automationIndicatorSignals = map[string]bool{
	"HEADLESS":              true, // 无头浏览器框架特征
	"URI_ENUMERATION":       true, // URI 枚举
	"NOT_FOUND_ENUMERATION": true, // 404 枚举
	"SENSITIVE_PATH_PROBE":  true, // 敏感路径探测
	"METHOD_ENUMERATION":    true, // 方法枚举
	"PARAMETER_MUTATION":    true, // 参数变异
	"LOW_SLOW_RECON":        true, // 低慢侦察
	"OBJECT_ENUMERATION":    true, // 对象枚举（BOLA 自动化探测）
}

// automationState 会话自动化标注的增量状态。
type automationState struct {
	stages    map[string]bool // 已见有效阶段（非 UNKNOWN）
	indicator string          // 首个命中的自动化指示信号（空 = 未命中）
}

// parseAutomationBasis 从持久化 basis 恢复增量状态（格式 stages=A,B,C;indicator=X；
// 空串/坏数据按零状态容忍——历史会话自然从零累积，不追溯）。
func parseAutomationBasis(basis string) automationState {
	st := automationState{stages: map[string]bool{}}
	for _, part := range strings.Split(basis, ";") {
		if rest, ok := strings.CutPrefix(part, "stages="); ok {
			for _, s := range strings.Split(rest, ",") {
				if s != "" {
					st.stages[s] = true
				}
			}
		} else if rest, ok := strings.CutPrefix(part, "indicator="); ok {
			st.indicator = rest
		}
	}
	return st
}

// observe 吸收一个成员事件（阶段 + 行为信号；非行为源 Signal 为空自然不命中）。
func (st *automationState) observe(stage, signal string) {
	if stage != "" && stage != StageUnknown {
		st.stages[stage] = true
	}
	if st.indicator == "" && automationIndicatorSignals[signal] {
		st.indicator = signal
	}
}

// eval 输出（是否疑似自动化攻击，判定依据 basis；basis 无论是否命中都随状态增长）。
func (st automationState) eval() (bool, string) {
	stages := make([]string, 0, len(st.stages))
	for s := range st.stages {
		stages = append(stages, s)
	}
	sort.Strings(stages)
	basis := "stages=" + strings.Join(stages, ",")
	if st.indicator != "" {
		basis += ";indicator=" + st.indicator
	}
	if len(basis) > automationBasisMaxLen {
		basis = basis[:automationBasisMaxLen]
	}
	return st.indicator != "" && len(st.stages) >= automationMinStages, basis
}
