// strongflow.go 强流程定义发布下发（NG-FLOW-01 §1.1/D1 + 联调裁决 §8.4-1 育龄窗）：
// api_strong_flow_definitions 表 ACTIVE 行 ∪ 存在非终态实例（ACTIVE/INDETERMINATE）
// 的 RETIRED 行 + api_strong_flow_steps 步骤 → api_strong_flows 段。表由迁移
// 000176 建立；缺失/查询失败 Warn 跳过（同 FlowBaselineStore 先例）。
// 育龄窗（F06 联调裁决闭环）：旧版本 RETIRED 后仍随发布面下发直至其非终态实例
// 全部走完——存量实例按创建时版本续跑（实例行冻结 definition_version，网关
// registry 按 (id,version) 多版本并存匹配），新实例只能按 ACTIVE 版本创建
// （网关侧 status 消费闸）；RETIRED 定义无非终态实例后自然掉出发布面。
// 稳定排序（应用,名称,版本 + 步骤 sequence——同内容恒得同序列化，版本戳确定）。
package guardconfig

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// StrongFlowLister 强流程定义读取接口（包内单测可 fake 错误路径）。
type StrongFlowLister interface {
	ListPublishableStrongFlows(ctx context.Context) ([]gatewayconfig.GuardStrongFlowDefinition, error)
}

// StrongFlowStore api_strong_flow_definitions 读取（迁移 000176 表；冻结列名）。
type StrongFlowStore struct {
	db *pgxpool.Pool
}

// NewStrongFlowStore 创建。
func NewStrongFlowStore(db *pgxpool.Pool) *StrongFlowStore { return &StrongFlowStore{db: db} }

var _ StrongFlowLister = (*StrongFlowStore)(nil)

// ListPublishableStrongFlows 读取发布面定义与步骤（ACTIVE ∪ 育龄窗 RETIRED；
// 稳定排序；success_rule 原文透传；status 透传——网关侧消费「ACTIVE 才可建实例」闸）。
func (s *StrongFlowStore) ListPublishableStrongFlows(ctx context.Context) ([]gatewayconfig.GuardStrongFlowDefinition, error) {
	rows, err := s.db.Query(ctx, `
SELECT d.id, d.application_id, d.name, d.version, d.status, d.binding_path_prefix, d.instance_key_param, d.mode,
       s.step_key, s.endpoint_key, s.sequence, s.success_rule, s.timeout_seconds,
       s.retry_semantics, s.parallel_group, s.lease_seconds, s.allows_202
FROM api_strong_flow_definitions d
JOIN api_strong_flow_steps s ON s.definition_id = d.id
WHERE d.status='ACTIVE'
   OR (d.status='RETIRED' AND EXISTS (
       SELECT 1 FROM api_strong_flow_instances i
       WHERE i.definition_id = d.id AND i.definition_version = d.version
         AND i.status IN ('ACTIVE','INDETERMINATE')))
ORDER BY d.application_id, d.name, d.version, s.sequence`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardStrongFlowDefinition{}
	index := map[string]int{}
	for rows.Next() {
		var defID string
		var st gatewayconfig.GuardStrongFlowStep
		var d gatewayconfig.GuardStrongFlowDefinition
		if err := rows.Scan(&defID, &d.ApplicationID, &d.Name, &d.Version, &d.Status,
			&d.BindingPathPrefix, &d.InstanceKeyParam, &d.Mode,
			&st.StepKey, &st.EndpointKey, &st.Sequence, &st.SuccessRule, &st.TimeoutSeconds,
			&st.RetrySemantics, &st.ParallelGroup, &st.LeaseSeconds, &st.Allows202); err != nil {
			return nil, err
		}
		i, ok := index[defID]
		if !ok {
			d.DefinitionID = defID
			d.Steps = []gatewayconfig.GuardStrongFlowStep{}
			out = append(out, d)
			i = len(out) - 1
			index[defID] = i
		}
		out[i].Steps = append(out[i].Steps, st)
	}
	return out, rows.Err()
}

// SetStrongFlowLister 注入强流程定义读取（nil 时不下发 api_strong_flows 段）。
func (p *Provider) SetStrongFlowLister(l StrongFlowLister) { p.strongFlows = l }

// loadAPIStrongFlows 读取发布面强流程定义（兼容旧调用方；BuildGuardConfig 统一走 loadAPIStrongFlowsStrict）。
func (p *Provider) loadAPIStrongFlows(ctx context.Context) []gatewayconfig.GuardStrongFlowDefinition {
	flows, err := p.loadAPIStrongFlowsStrict(ctx)
	if err != nil {
		slog.Warn("list api strong flows failed, skip api_strong_flows", "error", err)
	}
	return flows
}

// loadAPIStrongFlowsStrict 仅容忍旧库未建表（42P01）；真实数据库错误中止候选发布（fail-hard）。
func (p *Provider) loadAPIStrongFlowsStrict(ctx context.Context) ([]gatewayconfig.GuardStrongFlowDefinition, error) {
	if p.strongFlows == nil {
		return nil, nil
	}
	flows, err := p.strongFlows.ListPublishableStrongFlows(ctx)
	if err != nil {
		if isMissingLegacyTableError(err, "api_strong_flow_definitions") ||
			isMissingLegacyTableError(err, "api_strong_flow_steps") ||
			isMissingLegacyTableError(err, "api_strong_flow_instances") {
			slog.Warn("optional table api_strong_flow_definitions is unavailable", "error", err)
			return nil, nil
		}
		return nil, wrapLegacyLoaderError("api_strong_flow_definitions", err)
	}
	if len(flows) == 0 {
		return nil, nil
	}
	return flows, nil
}
