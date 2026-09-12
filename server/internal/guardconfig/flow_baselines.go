// flow_baselines.go 业务流程基线下发（阶段8 §44 发布下发面）：
// api_flow_baselines 表 enabled 行 + api_flow_baseline_steps 步骤（endpoint_key 经
// api_endpoints 关联解析，与 api_role_baselines 同一先例）→ api_flow_baselines 段。
// 表由迁移 000155 建立，批量执行/取消语义五列由 000158 补齐；
// 缺失/查询失败 Warn 跳过，与 RoleBaselineStore 同一模式。
package guardconfig

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// FlowBaselineLister 流程基线读取接口（api_flow_baselines 表；包内单测可 fake 错误路径）。
type FlowBaselineLister interface {
	ListEnabledFlowBaselines(ctx context.Context) ([]gatewayconfig.GuardFlowBaseline, error)
}

// FlowBaselineStore api_flow_baselines 读取（表由迁移 000155 建立；按冻结列名读取；
// 仅取 enabled 行，步骤按 sequence/step_id 稳定排序——同内容恒得同序列化，版本戳确定）。
type FlowBaselineStore struct {
	db *pgxpool.Pool
}

// NewFlowBaselineStore 创建流程基线读取仓储。
func NewFlowBaselineStore(db *pgxpool.Pool) *FlowBaselineStore {
	return &FlowBaselineStore{db: db}
}

var _ FlowBaselineLister = (*FlowBaselineStore)(nil)

// ListEnabledFlowBaselines 读取启用流程基线（按 flow_id 稳定排序；步骤内嵌）。
func (s *FlowBaselineStore) ListEnabledFlowBaselines(ctx context.Context) ([]gatewayconfig.GuardFlowBaseline, error) {
	rows, err := s.db.Query(ctx, `
SELECT fb.flow_id, fb.max_per_window, fb.rate_window_seconds,
       s.step_id, ep.endpoint_key, s.sequence, s.predecessors,
       s.terminal, s.state_from, s.state_to, s.max_per_window, s.rate_window_seconds, s.cancels_flow
FROM api_flow_baseline_steps s
JOIN api_flow_baselines fb ON fb.id = s.flow_baseline_id
JOIN api_endpoints ep ON ep.id = s.endpoint_id
WHERE fb.enabled
ORDER BY fb.flow_id, s.sequence, s.step_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardFlowBaseline{}
	index := map[string]int{}
	for rows.Next() {
		var flowID string
		var flowMax, flowWindow int
		var st gatewayconfig.GuardFlowStep
		if err := rows.Scan(&flowID, &flowMax, &flowWindow,
			&st.StepID, &st.EndpointKey, &st.Sequence,
			&st.Predecessors, &st.Terminal, &st.StateFrom, &st.StateTo,
			&st.MaxPerWindow, &st.RateWindowSeconds, &st.CancelsFlow); err != nil {
			return nil, err
		}
		if st.Predecessors == nil {
			st.Predecessors = []string{}
		}
		i, ok := index[flowID]
		if !ok {
			out = append(out, gatewayconfig.GuardFlowBaseline{
				FlowID: flowID, MaxPerWindow: flowMax, RateWindowSeconds: flowWindow,
				Steps: []gatewayconfig.GuardFlowStep{},
			})
			i = len(out) - 1
			index[flowID] = i
		}
		out[i].Steps = append(out[i].Steps, st)
	}
	return out, rows.Err()
}

// SetFlowBaselineLister 注入流程基线读取（nil 时不下发 api_flow_baselines 段）。
func (p *Provider) SetFlowBaselineLister(l FlowBaselineLister) { p.flowBaselines = l }

// loadAPIFlowBaselines 读取启用流程基线；未注入或查询失败（如迁移 000155 表尚未建立）
// Warn 并跳过，不阻断发布主流程（纪律同 loadAPIRoleBaselines：增量能力，缺失时保持
// 发布通道既有行为，网关无基线下发时流程偏离检测零行为，行为与历史版本一致）。
func (p *Provider) loadAPIFlowBaselines(ctx context.Context) []gatewayconfig.GuardFlowBaseline {
	flows, err := p.loadAPIFlowBaselinesStrict(ctx)
	if err != nil {
		slog.Warn("list api flow baselines failed, skip api_flow_baselines", "error", err)
	}
	return flows
}

func (p *Provider) loadAPIFlowBaselinesStrict(ctx context.Context) ([]gatewayconfig.GuardFlowBaseline, error) {
	if p.flowBaselines == nil {
		return nil, nil
	}
	flows, err := p.flowBaselines.ListEnabledFlowBaselines(ctx)
	if err != nil {
		if isMissingLegacyTableError(err, "api_flow_baseline_steps") ||
			isMissingLegacyTableError(err, "api_flow_baselines") {
			slog.Warn("optional legacy table api_flow_baselines is unavailable", "error", err)
			return nil, nil
		}
		return nil, wrapLegacyLoaderError("api_flow_baselines", err)
	}
	if len(flows) == 0 {
		return nil, nil
	}
	return flows, nil
}
