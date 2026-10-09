// instance_events.go 强流程事件消费与实例状态机（NG-FLOW-02 §1.2/D2/D8）：
//
// 事件链（gateway flowguard 执行侧发射，apievents `strong_flow` 对象，
// server apiruntime 采集器透传消费）：
//   - INSTANCE_*（实例状态推进）：upsert 实例行——按五态合法转换推进
//     （非法转换不静默：实例行不动 + step_events 落 REJECTED/FLOW-STATE-001）；
//   - RESERVE/COMMIT/RELEASE/EXPIRE（步骤事件）：落 step_events
//     （UNIQUE(instance_id,step_key,action,fencing_token) 幂等去重——采集重放安全）。
//
// 实例标识线契约（冻结注释）：事件的 instance_id 字段承载实例键（sfref: 前缀域隔离
// HMAC，strongflow.InstanceRefHMAC 域）——网关执行侧不知道 server 行 UUID，sfref
// 是双轨共用实例标识；server 实例行的 instance_key 列即其值，内部行 id 不出事件链。
package strongflow

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StrongFlowEvent 强流程事件（`strong_flow` JSON 对象逐键冻结；B 轨发射、A 轨消费）。
type StrongFlowEvent struct {
	DefinitionID      string `json:"definition_id"`
	DefinitionVersion int    `json:"definition_version"`
	// InstanceID 实例键（sfref: 前缀 HMAC 形态；线契约见包注释——非 server 行 UUID）
	InstanceID    string    `json:"instance_id"`
	StepKey       string    `json:"step_key"`
	Action        string    `json:"action"`
	FencingToken  int64     `json:"fencing_token"`
	LeaseSeconds  int       `json:"lease_seconds"`
	Result        string    `json:"result"`
	ReasonCode    string    `json:"reason_code"`
	RequestID     string    `json:"request_id"`
	ApplicationID string    `json:"application_id"` // 实例归属（建行用）
	TenantRef     string    `json:"tenant_ref"`     // 可信租户引用（脱敏形态；建行用）
	PrincipalRef  string    `json:"principal_ref"`  // 可信主体引用（脱敏形态；建行用）
	OccurredAt    time.Time `json:"occurred_at"`
}

// action 词表（冻结）。
const (
	ActionReserve               = "RESERVE"
	ActionCommit                = "COMMIT"
	ActionRelease               = "RELEASE"
	ActionExpire                = "EXPIRE"
	ActionInstanceNew           = "INSTANCE_NEW"
	ActionInstanceConfirmed     = "INSTANCE_CONFIRMED"
	ActionInstanceIndeterminate = "INSTANCE_INDETERMINATE"
	ActionInstanceCancelled     = "INSTANCE_CANCELLED"
	ActionInstanceFailed        = "INSTANCE_FAILED"
)

// result 词表（冻结）。
const (
	ResultOK       = "OK"
	ResultConflict = "CONFLICT"
	ResultRejected = "REJECTED"
	ResultUnknown  = "UNKNOWN"
)

// 状态机合法转换（冻结）：ACTIVE→CONFIRMED/INDETERMINATE/CANCELLED/FAILED；
// INDETERMINATE→CONFIRMED/FAILED（对账恢复）；CANCELLED/CONFIRMED/FAILED 终态。
var legalTransitions = map[string]map[string]bool{
	"ACTIVE":        {"CONFIRMED": true, "INDETERMINATE": true, "CANCELLED": true, "FAILED": true},
	"INDETERMINATE": {"CONFIRMED": true, "FAILED": true},
}

// instanceActionStatus INSTANCE_* 动作的目标状态。
var instanceActionStatus = map[string]string{
	ActionInstanceConfirmed:     "CONFIRMED",
	ActionInstanceIndeterminate: "INDETERMINATE",
	ActionInstanceCancelled:     "CANCELLED",
	ActionInstanceFailed:        "FAILED",
}

// validateStrongFlowEvent 事件边界校验（词表外/形态非法拒收不落库——
// 与 authz_decision 同一纪律：服务端边界不相信上游自觉）。
func validateStrongFlowEvent(ev *StrongFlowEvent) string {
	if _, err := uuid.Parse(strings.TrimSpace(ev.DefinitionID)); err != nil {
		return "definition_id 非法（UUID）"
	}
	if ev.DefinitionVersion < 1 {
		return "definition_version 必须 ≥1"
	}
	if !strings.HasPrefix(ev.InstanceID, InstanceRefPrefix) || len(ev.InstanceID) != len(InstanceRefPrefix)+64 {
		return "instance_id 非法（sfref: 前缀 + 64 位小写 hex 形态）"
	}
	switch ev.Action {
	case ActionReserve, ActionCommit, ActionRelease, ActionExpire:
		if strings.TrimSpace(ev.StepKey) == "" {
			return "步骤事件 step_key 必填"
		}
	case ActionInstanceNew, ActionInstanceConfirmed, ActionInstanceIndeterminate, ActionInstanceCancelled, ActionInstanceFailed:
	default:
		return "action 词表外"
	}
	switch ev.Result {
	case ResultOK, ResultConflict, ResultRejected, ResultUnknown:
	default:
		return "result 词表外"
	}
	if ev.OccurredAt.IsZero() {
		return "occurred_at 必填"
	}
	if len(ev.RequestID) > 64 {
		return "request_id 超 64 字符"
	}
	return ""
}

// StrongFlowEventStore 事件消费仓储（实例 upsert + 步骤事件幂等落库）。
type StrongFlowEventStore struct {
	db *pgxpool.Pool
}

// NewStrongFlowEventStore 创建。
func NewStrongFlowEventStore(db *pgxpool.Pool) *StrongFlowEventStore {
	return &StrongFlowEventStore{db: db}
}

// resolveInstance 按实例键解析/建实例行（INSTANCE_NEW 携带归属字段建行；
// 步骤事件先于创建事件到达（乱序/丢失）时按 ACTIVE 建行并如实披露 FLOW-ORDER-001——
// 事件链是仅有的证据，不静默丢弃）。
func (s *StrongFlowEventStore) resolveInstance(ctx context.Context, tx pgx.Tx, ev *StrongFlowEvent) (uuid.UUID, bool, error) {
	defID, _ := uuid.Parse(strings.TrimSpace(ev.DefinitionID))
	var id uuid.UUID
	err := tx.QueryRow(ctx, `INSERT INTO api_strong_flow_instances
		(application_id, definition_id, definition_version, instance_key, tenant_ref, principal_ref)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (definition_id, definition_version, instance_key) DO NOTHING
		RETURNING id`,
		ev.ApplicationID, defID, ev.DefinitionVersion, ev.InstanceID,
		strings.TrimSpace(ev.TenantRef), strings.TrimSpace(ev.PrincipalRef)).Scan(&id)
	if err == nil {
		return id, true, nil // 新建
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, fmt.Errorf("insert strong flow instance: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT id FROM api_strong_flow_instances
		WHERE definition_id=$1 AND definition_version=$2 AND instance_key=$3`,
		defID, ev.DefinitionVersion, ev.InstanceID).Scan(&id); err != nil {
		return uuid.Nil, false, fmt.Errorf("load strong flow instance: %w", err)
	}
	return id, false, nil
}

// appendStepEvent 步骤事件幂等落库（唯一键去重；返回 true=实际插入）。
func appendStepEvent(ctx context.Context, tx pgx.Tx, instanceID uuid.UUID, ev *StrongFlowEvent, result, reasonCode string) (bool, error) {
	ct, err := tx.Exec(ctx, `INSERT INTO api_strong_flow_step_events
		(instance_id, step_key, action, fencing_token, result, reason_code, request_id, occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (instance_id, step_key, action, fencing_token) DO NOTHING`,
		instanceID, ev.StepKey, ev.Action, ev.FencingToken, result, reasonCode, ev.RequestID, ev.OccurredAt)
	if err != nil {
		return false, fmt.Errorf("insert strong flow step event: %w", err)
	}
	return ct.RowsAffected() > 0, nil
}

// RecordStrongFlow 消费一条强流程事件（采集器副作用；单事件事务化——实例推进与
// 事件落行同事务，失败整体回滚不留半状态）。调用方纪律：错误仅记录不阻断采集主流程。
func (s *StrongFlowEventStore) RecordStrongFlow(ctx context.Context, ev *StrongFlowEvent) error {
	if ev == nil {
		return nil
	}
	if msg := validateStrongFlowEvent(ev); msg != "" {
		return fmt.Errorf("strong_flow event invalid: %s", msg)
	}
	if _, err := uuid.Parse(strings.TrimSpace(ev.ApplicationID)); err != nil {
		return fmt.Errorf("strong_flow event invalid: application_id 非法（UUID）")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	instanceID, _, err := s.resolveInstance(ctx, tx, ev)
	if err != nil {
		return err
	}

	if target, isInstanceAction := instanceActionStatus[ev.Action]; isInstanceAction {
		// 状态推进：合法转换才动实例行（version+1；终态置 terminated_at）；
		// 非法转换实例行不动，事件落 REJECTED/FLOW-STATE-001 如实留痕
		var current string
		if err := tx.QueryRow(ctx, `SELECT status FROM api_strong_flow_instances WHERE id=$1 FOR UPDATE`, instanceID).Scan(&current); err != nil {
			return fmt.Errorf("lock strong flow instance: %w", err)
		}
		if legalTransitions[current][target] {
			if _, err := tx.Exec(ctx, `UPDATE api_strong_flow_instances SET status=$2,
				version=version+1, updated_at=now(),
				terminated_at = CASE WHEN $2 IN ('CONFIRMED','CANCELLED','FAILED') THEN now() ELSE terminated_at END
				WHERE id=$1`, instanceID, target); err != nil {
				return fmt.Errorf("advance strong flow instance: %w", err)
			}
			if _, err := appendStepEvent(ctx, tx, instanceID, ev, ev.Result, ev.ReasonCode); err != nil {
				return err
			}
		} else {
			reason := ev.ReasonCode
			if reason == "" {
				reason = "FLOW-STATE-001"
			}
			if _, err := appendStepEvent(ctx, tx, instanceID, ev, ResultRejected, reason); err != nil {
				return err
			}
		}
	} else if ev.Action == ActionInstanceNew {
		// 实例创建事件：行已由 resolveInstance upsert；落事件行（重复到达去重）
		if _, err := appendStepEvent(ctx, tx, instanceID, ev, ev.Result, ev.ReasonCode); err != nil {
			return err
		}
	} else {
		// 步骤事件（RESERVE/COMMIT/RELEASE/EXPIRE）：幂等落行
		if _, err := appendStepEvent(ctx, tx, instanceID, ev, ev.Result, ev.ReasonCode); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
