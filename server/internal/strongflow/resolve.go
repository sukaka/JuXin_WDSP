// resolve.go 强流程实例管理恢复（NG-FLOW-03 §1.5/D5：未知恢复与管理对账）：
//
//	POST /api/v1/api-security/strong-flows/instances/{id}/resolve
//
// 语义冻结：
//   - action ∈ CONFIRM_SUCCEEDED / CONFIRM_NOT_EXECUTED / KEEP_UNKNOWN（词表外 400）；
//   - reason 必填非空（400）——对账决定必须留理由，不降级猜义；
//   - expected_version 乐观锁（不匹配 409 ErrVersionConflict）；
//   - 终态实例（CONFIRMED/CANCELLED/FAILED）拒绝重复恢复（409 ErrInstanceTerminal，
//     幂等不误伤——终态已定案，任何恢复动作不推进）；
//   - CONFIRM_SUCCEEDED → CONFIRMED / CONFIRM_NOT_EXECUTED → FAILED（五态合法转换表
//     内：ACTIVE/INDETERMINATE→CONFIRMED/FAILED；FAILED=「明确业务失败——仅由明确
//     证据进入」（§1.2），人工对账确认未执行即明确证据）；实例行 version+1、
//     终态置 terminated_at；落 step_events（action=INSTANCE_CONFIRMED/INSTANCE_FAILED、
//     reason_code=FLOW-RESOLVE-001、result=OK——与网关执行侧产出以 reason_code 区分）；
//   - KEEP_UNKNOWN 不推进状态（行不动，version 不消费），仅落 RESOLVE 留痕事件
//     （迁移 000178 词表；reason_code=FLOW-RESOLVE-001、result=UNKNOWN——未知不显示
//     安全通过，绝不美化）。重复 KEEP_UNKNOWN 命中事件唯一键去重（同实例同形态
//     重申=同一事实，审计仍逐条在册）。
//   - 全部写路径单事务（状态推进与事件落行同生共死，不留半状态）。
package strongflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ResolveInput 管理恢复载荷（handler 边界已完成词表/reason 校验后传入）。
type ResolveInput struct {
	Action          string `json:"action"`
	Reason          string `json:"reason"`
	ExpectedVersion int    `json:"expected_version"`
}

// ValidateResolveInput 载荷边界校验（词表外/reason 空 → ValidationError 400）。
func ValidateResolveInput(in ResolveInput) error {
	switch strings.ToUpper(strings.TrimSpace(in.Action)) {
	case ResolveConfirmSucceeded, ResolveConfirmNotExecuted, ResolveKeepUnknown:
	default:
		return &ValidationError{Msg: "action 词表外（CONFIRM_SUCCEEDED|CONFIRM_NOT_EXECUTED|KEEP_UNKNOWN）"}
	}
	if strings.TrimSpace(in.Reason) == "" {
		return &ValidationError{Msg: "reason 必填（对账决定必须留理由）"}
	}
	if len(strings.TrimSpace(in.Reason)) > 512 {
		return &ValidationError{Msg: "reason 超 512 字符"}
	}
	if in.ExpectedVersion < 1 {
		return &ValidationError{Msg: "expected_version 必须 ≥1（乐观锁与实例 version 比对）"}
	}
	return nil
}

// ResolveResult 恢复结果（审计摘要与响应共用）。
type ResolveResult struct {
	InstanceID    uuid.UUID
	BeforeStatus  string
	AfterStatus   string // KEEP_UNKNOWN 时等于 BeforeStatus
	BeforeVersion int
	AfterVersion  int // KEEP_UNKNOWN 时等于 BeforeVersion（不消费版本）
	Action        string
}

// resolveTargetStatus CONFIRM_* 动作的目标终态（KEEP_UNKNOWN 无目标——不推进）。
var resolveTargetStatus = map[string]string{
	ResolveConfirmSucceeded:   "CONFIRMED",
	ResolveConfirmNotExecuted: "FAILED",
}

// resolveEventAction CONFIRM_* 推进落行的状态事件动作（五态语义词表内；
// KEEP_UNKNOWN 落 ActionResolve 留痕——管理面专属词表，迁移 000178 放宽 CHECK）。
var resolveEventAction = map[string]string{
	ResolveConfirmSucceeded:   ActionInstanceConfirmed,
	ResolveConfirmNotExecuted: ActionInstanceFailed,
}

// ResolveInstance 管理恢复（单事务：行锁 → 终态/版本闸 → 推进或留痕 → 事件落行）。
// operatorName 仅用于审计摘要回读（本层不落审计——审计在 handler 层与 HTTP 请求上下文同链）。
func (s *Store) ResolveInstance(ctx context.Context, id uuid.UUID, in ResolveInput, requestID string) (*ResolveResult, error) {
	action := strings.ToUpper(strings.TrimSpace(in.Action))
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var current string
	var version int
	if err := tx.QueryRow(ctx, `SELECT status, version FROM api_strong_flow_instances
		WHERE id=$1 FOR UPDATE`, id).Scan(&current, &version); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInstanceNotFound
		}
		return nil, err
	}
	res := &ResolveResult{InstanceID: id, BeforeStatus: current, BeforeVersion: version, Action: action}
	// 终态闸：重复恢复一律 409（幂等不误伤——终态已定案不推进；先于版本闸，
	// 终态语义优先于乐观锁读数）
	if current == "CONFIRMED" || current == "CANCELLED" || current == "FAILED" {
		return nil, ErrInstanceTerminal
	}
	// 乐观锁闸
	if version != in.ExpectedVersion {
		return nil, ErrVersionConflict
	}

	if action == ResolveKeepUnknown {
		// 不推进状态：仅 RESOLVE 留痕（重复重申命中唯一键去重——同一事实不重复落行，
		// 审计仍在 handler 层逐条在册）
		if _, err := tx.Exec(ctx, `INSERT INTO api_strong_flow_step_events
			(instance_id, step_key, action, fencing_token, result, reason_code, request_id, occurred_at)
			VALUES ($1,'',$2,0,$3,$4,$5,now())
			ON CONFLICT (instance_id, step_key, action, fencing_token) DO NOTHING`,
			id, ActionResolve, ResultUnknown, ReasonResolve, requestID); err != nil {
			return nil, fmt.Errorf("record keep-unknown resolve event: %w", err)
		}
		res.AfterStatus, res.AfterVersion = current, version
		return res, tx.Commit(ctx)
	}

	// CONFIRM_*：五态合法转换表内推进（ACTIVE/INDETERMINATE→CONFIRMED/FAILED）
	target := resolveTargetStatus[action]
	if !legalTransitions[current][target] {
		// 状态机外转换（防御：当前版本五态下不可达——ACTIVE/INDETERMINATE 全覆盖；
		// 未来扩状态未同步时如实 409 不静默推进）
		return nil, ErrInvalidTransition
	}
	if _, err := tx.Exec(ctx, `UPDATE api_strong_flow_instances SET status=$2,
		version=version+1, updated_at=now(), terminated_at=now() WHERE id=$1`, id, target); err != nil {
		return nil, fmt.Errorf("advance instance to %s: %w", target, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO api_strong_flow_step_events
		(instance_id, step_key, action, fencing_token, result, reason_code, request_id, occurred_at)
		VALUES ($1,'',$2,0,$3,$4,$5,now())
		ON CONFLICT (instance_id, step_key, action, fencing_token) DO NOTHING`,
		id, resolveEventAction[action], ResultOK, ReasonResolve, requestID); err != nil {
		return nil, fmt.Errorf("record resolve event: %w", err)
	}
	res.AfterStatus, res.AfterVersion = target, version+1
	return res, tx.Commit(ctx)
}

// trimReasonLen reason 审计摘要截断（与既有审计摘要同量纲，防超长载荷灌入审计行）。
func trimReasonLen(s string) string {
	const maxReasonSummary = 256
	if len(s) > maxReasonSummary {
		return s[:maxReasonSummary] + "…"
	}
	return s
}

// resolveSummary 恢复审计摘要（after 含 action/reason/前后状态——D5 全值回读；
// JSON 形态：既有审计脱敏器 MaskSensitiveJSON 对非 JSON 摘要整段遮蔽，JSON 对象
// 仅遮敏感键白名单（action/reason/status/version 均非敏感键，全值保留可读）；
// reason 自由文本经 json.Marshal 转义安全）。
func resolveSummary(res *ResolveResult, reason string) string {
	out, err := json.Marshal(map[string]any{
		"action":         res.Action,
		"reason":         trimReasonLen(reason),
		"status_before":  res.BeforeStatus,
		"status_after":   res.AfterStatus,
		"version_before": res.BeforeVersion,
		"version_after":  res.AfterVersion,
	})
	if err != nil {
		return "action=" + res.Action + " status=" + res.BeforeStatus + "→" + res.AfterStatus
	}
	return string(out)
}
