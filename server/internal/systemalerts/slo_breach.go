// slo_breach.go APM SLO 违约告警评估：周期读取 apm 包 SLO 评估结果（apm_slos 定义 +
// metric_hour_aggregates 窗口聚合；当前值/错误预算/状态机口径归 apm 包，
// 见 apm/slo_types.go），状态 BREACHED 的 SLO 触发 APM_SLO_BREACH；触发/合并/冷却/
// 抖动/自动恢复全部复用引擎既有机制（Raise/AutoRecover，与 endpoint_perf.go 同构）。
//
// 去重维度：component = service/SLO 名（超长截断 + 摘要后缀，见
// truncatedAlertComponent）——按服务+目标粒度告警，不按实例/端点放大（设计 §18.2）。
// 告警详情只含服务/SLO 名与指标口径数值，不含任何请求正文、参数或原始路径。
package systemalerts

import (
	"context"
	"errors"
	"fmt"
)

// SLOBreachState 单条 SLO 的本轮评估状态（供给方 apm.SLOStore 计算；
// Title/Message 仅在 Breached=true 时携带，文案含评估口径）。
type SLOBreachState struct {
	Service  string // SLO 服务（应用编码）
	Name     string // SLO 名称
	Breached bool   // 本轮状态是否为 BREACHED
	Title    string
	Message  string
}

// SLOBreachStatsStore 提供全部 SLO 的本轮评估状态（nil 时 EvaluateSLOBreach 空转——
// APM_ENABLED 关闭形态）。
type SLOBreachStatsStore interface {
	SLOBreachStates(ctx context.Context) ([]SLOBreachState, error)
}

// EvaluateSLOBreach 评估 SLO 违约告警（装配层按分钟周期调用）。本轮 BREACHED 的 SLO
// 逐组件 Raise（走合并/冷却/抖动；同组件重复评估自动合并，即"进入 BREACHED 才新建"），
// 仍有未关闭告警但本轮未 BREACHED 的组件 AutoRecover（含 SLO 已删除的组件——
// 定义消失视为恢复收口）。读数失败整体中止（不清动既有告警）；单条 Raise/恢复失败
// 不阻断其他 SLO，错误聚合返回。
func (e *Engine) EvaluateSLOBreach(ctx context.Context) error {
	if e.sloBreach == nil {
		return nil
	}
	// APM 总开关关闭：空转（运行期热生效；不清动既有告警）
	if !e.apmEnabledNow(ctx) {
		return nil
	}
	states, err := e.sloBreach.SLOBreachStates(ctx)
	if err != nil {
		return fmt.Errorf("slo breach states: %w", err)
	}

	triggered := map[string]bool{}
	var errs []error
	for _, st := range states {
		if !st.Breached {
			continue
		}
		comp := truncatedAlertComponent(st.Service + "/" + st.Name)
		triggered[comp] = true // 先标记再 Raise：Raise 失败不误恢复既有告警
		if _, err := e.Raise(ctx, RaiseRequest{
			AlertType: TypeAPMSLOBreach,
			Component: comp,
			Title:     st.Title,
			Message:   st.Message,
		}); err != nil {
			errs = append(errs, err)
		}
	}

	// 自动恢复：仍有未关闭告警但本轮未违约的组件（一次查询避免逐条扫库）。
	open, err := e.store.ListOpenByTypes(ctx, []string{TypeAPMSLOBreach})
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("list open slo alerts: %w", err))...)
	}
	for i := range open {
		a := &open[i]
		if triggered[a.Component] {
			continue
		}
		if _, err := e.AutoRecover(ctx, a.Component, a.AlertType); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
