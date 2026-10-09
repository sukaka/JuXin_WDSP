// instances.go 强流程实例只读查询（NG-FLOW-02 列表最小面；NG-FLOW-03 补详情：
// 实例行 + 步骤轨迹全链 + 证据按 evidence_read 裁剪 + INDETERMINATE「未知，不显示
// 安全通过」语义字段（§9.4 红线，不美化））。
package strongflow

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Instance 实例行（读模型；tenant_ref/principal_ref 为脱敏引用形态原文）。
type Instance struct {
	ID                uuid.UUID  `json:"id"`
	ApplicationID     uuid.UUID  `json:"application_id"`
	DefinitionID      uuid.UUID  `json:"definition_id"`
	DefinitionName    string     `json:"definition_name"` // LEFT JOIN 带出
	DefinitionVersion int        `json:"definition_version"`
	InstanceKey       string     `json:"instance_key"` // sfref: 前缀域隔离 HMAC
	TenantRef         string     `json:"tenant_ref"`
	PrincipalRef      string     `json:"principal_ref"`
	Status            string     `json:"status"`
	Version           int        `json:"version"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	TerminatedAt      *time.Time `json:"terminated_at"`
}

// StepEventView 步骤事件视图（详情步骤轨迹条目）。摘要档四字段（step_key/action/
// result/occurred_at）随 read 权限可见；明细档（fencing_token/reason_code/request_id）
// 仅 evidence_read 带出（omitempty——无权限时键缺席，不空串占位冒充无数据）。
type StepEventView struct {
	StepKey      string    `json:"step_key"`
	Action       string    `json:"action"`
	Result       string    `json:"result"`
	OccurredAt   time.Time `json:"occurred_at"`
	FencingToken *int64    `json:"fencing_token,omitempty"`
	ReasonCode   string    `json:"reason_code,omitempty"`
	RequestID    string    `json:"request_id,omitempty"`
}

// InstanceDetail 实例详情（实例行 + 步骤轨迹全链 + 状态语义字段）。
type InstanceDetail struct {
	Instance
	// StatusSemantics 状态语义冻结词表（§9.4 红线承载：INDETERMINATE=未知，不显示
	// 安全通过——机器可读，前端不得映射为成功态）：
	//   ACTIVE→IN_PROGRESS / CONFIRMED→SUCCEEDED / INDETERMINATE→UNKNOWN_NOT_CONFIRMED /
	//   CANCELLED→CANCELLED / FAILED→FAILED
	StatusSemantics string `json:"status_semantics"`
	// StatusMessage 状态语义中文文案（INDETERMINATE 固定「未知，不显示安全通过」，
	// 逐字不美化；其余状态如实描述）。
	StatusMessage string          `json:"status_message"`
	Steps         []StepEventView `json:"steps"`
}

// statusSemantics 五态→语义词表/文案映射（冻结；新增状态须同步——不美化未知）。
func statusSemantics(status string) (semantics, message string) {
	switch status {
	case "ACTIVE":
		return "IN_PROGRESS", "进行中"
	case "CONFIRMED":
		return "SUCCEEDED", "已确认完成"
	case "INDETERMINATE":
		return "UNKNOWN_NOT_CONFIRMED", "未知，不显示安全通过"
	case "CANCELLED":
		return "CANCELLED", "已取消"
	case "FAILED":
		return "FAILED", "明确业务失败"
	default:
		// 词表外（未来扩展未同步）——如实回显原值，不猜义
		return status, status
	}
}

// ListInstances 实例分页列表（application_id/status/created_since 过滤；created_at 倒序）。
func (s *Store) ListInstances(ctx context.Context, applicationID uuid.UUID, status string, createdSince *time.Time, page, pageSize int) ([]Instance, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	where, args := []string{}, []any{}
	if applicationID != uuid.Nil {
		args = append(args, applicationID)
		where = append(where, fmt.Sprintf("i.application_id = $%d", len(args)))
	}
	if status != "" {
		args = append(args, status)
		where = append(where, fmt.Sprintf("i.status = $%d", len(args)))
	}
	if createdSince != nil {
		args = append(args, *createdSince)
		where = append(where, fmt.Sprintf("i.created_at >= $%d", len(args)))
	}
	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}
	join := ` FROM api_strong_flow_instances i
	LEFT JOIN api_strong_flow_definitions d ON d.id = i.definition_id`
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*)"+join+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, `SELECT i.id, i.application_id, i.definition_id, COALESCE(d.name,''),
		i.definition_version, i.instance_key, i.tenant_ref, i.principal_ref, i.status, i.version,
		i.created_at, i.updated_at, i.terminated_at`+join+cond+
		fmt.Sprintf(" ORDER BY i.created_at DESC, i.id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Instance{}
	for rows.Next() {
		var it Instance
		if err := rows.Scan(&it.ID, &it.ApplicationID, &it.DefinitionID, &it.DefinitionName,
			&it.DefinitionVersion, &it.InstanceKey, &it.TenantRef, &it.PrincipalRef, &it.Status,
			&it.Version, &it.CreatedAt, &it.UpdatedAt, &it.TerminatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, it)
	}
	return out, total, rows.Err()
}

// GetInstance 实例详情（NG-FLOW-03 §1.9）：实例行 + 步骤轨迹（step_events 按
// occurred_at,id 全链升序）+ 状态语义字段。withEvidence=false 时明细档
// （fencing_token/reason_code/request_id）缺席（evidence_read 裁剪——摘要级轨迹
// 不携带请求关联与内部序号）。ErrInstanceNotFound 哨兵。
func (s *Store) GetInstance(ctx context.Context, id uuid.UUID, withEvidence bool) (*InstanceDetail, error) {
	var d InstanceDetail
	err := s.db.QueryRow(ctx, `SELECT i.id, i.application_id, i.definition_id, COALESCE(d.name,''),
		i.definition_version, i.instance_key, i.tenant_ref, i.principal_ref, i.status, i.version,
		i.created_at, i.updated_at, i.terminated_at
		FROM api_strong_flow_instances i
		LEFT JOIN api_strong_flow_definitions d ON d.id = i.definition_id
		WHERE i.id=$1`, id).Scan(
		&d.ID, &d.ApplicationID, &d.DefinitionID, &d.DefinitionName,
		&d.DefinitionVersion, &d.InstanceKey, &d.TenantRef, &d.PrincipalRef, &d.Status,
		&d.Version, &d.CreatedAt, &d.UpdatedAt, &d.TerminatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInstanceNotFound
	}
	if err != nil {
		return nil, err
	}
	d.StatusSemantics, d.StatusMessage = statusSemantics(d.Status)
	rows, err := s.db.Query(ctx, `SELECT step_key, action, fencing_token, result, reason_code, request_id, occurred_at
		FROM api_strong_flow_step_events WHERE instance_id=$1 ORDER BY occurred_at, id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	d.Steps = []StepEventView{}
	for rows.Next() {
		var (
			ev                StepEventView
			token             int64
			reason, requestID string
		)
		if err := rows.Scan(&ev.StepKey, &ev.Action, &token, &ev.Result, &reason, &requestID, &ev.OccurredAt); err != nil {
			return nil, err
		}
		if withEvidence {
			t := token
			ev.FencingToken = &t
			ev.ReasonCode = reason
			ev.RequestID = requestID
		}
		d.Steps = append(d.Steps, ev)
	}
	return &d, rows.Err()
}
