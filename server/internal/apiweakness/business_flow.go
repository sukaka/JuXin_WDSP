package apiweakness

import (
	"context"
	"time"
)

var flowSequenceRuleIDs = []string{
	"flow.step_skip",
	"flow.out_of_order",
	"flow.illegal_state_transition",
	"flow.post_cancel_operation",
	"flow.anonymous_late_entry",
	"flowguard.violation",
}

var flowReplayBurstRuleIDs = []string{"flow.duplicate_submit", "flow.rapid_batch"}

func (s *pgSignalSource) FlowSequence(ctx context.Context, since time.Time) ([]EndpointSignal, error) {
	return s.businessFlowSignals(ctx, since, flowSequenceRuleIDs)
}

func (s *pgSignalSource) FlowReplayBurst(ctx context.Context, since time.Time) ([]EndpointSignal, error) {
	return s.businessFlowSignals(ctx, since, flowReplayBurstRuleIDs)
}

// businessFlowSignals 仅聚合已发布流程定义的实际违规。flowguard.unknown、
// 未配置基线的零行为以及正常流程不产生任何匹配，均不会进入弱点中心。
func (s *pgSignalSource) businessFlowSignals(ctx context.Context, since time.Time, ruleIDs []string) ([]EndpointSignal, error) {
	if len(ruleIDs) == 0 {
		return []EndpointSignal{}, nil
	}
	rows, err := s.db.Query(ctx, `
SELECT ep.id, e.endpoint_key, count(*) AS hits, min(e.occurred_at), max(e.occurred_at)
FROM api_runtime_events e
JOIN api_endpoints ep ON ep.endpoint_key = e.endpoint_key
WHERE e.occurred_at >= $1
  AND EXISTS (
    SELECT 1 FROM jsonb_array_elements(e.details_json) m
    WHERE m->>'detector' IN ('api_flow', 'flowguard')
      AND m->>'rule_id' = ANY($2::text[])
  )
GROUP BY ep.id, e.endpoint_key`, since, ruleIDs)
	if err != nil {
		return nil, err
	}
	return scanSignals(rows)
}
