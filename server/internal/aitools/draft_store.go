// draft_store.go 草稿（AI 推荐）查询与废弃：ai_recommendations 的只读列表/详情与逻辑废弃。
// 草稿始终为 DRAFT 状态，任何"接受/发布"均不在此处生效，须走既有人工校验发布流程。
package aitools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 草稿查询错误。
var (
	ErrDraftNotFound = errors.New("draft not found")
	ErrDraftState    = errors.New("draft status does not allow this operation")
)

// Recommendation AI 推荐/草稿记录（ai_recommendations 视图）。
type Recommendation struct {
	ID                 uuid.UUID       `json:"id"`
	TaskID             *uuid.UUID      `json:"task_id"`
	RecommendationType string          `json:"recommendation_type"`
	TargetType         string          `json:"target_type"`
	TargetID           string          `json:"target_id"`
	Summary            string          `json:"summary"`
	EvidenceReferences json.RawMessage `json:"evidence_references"`
	RiskLevel          string          `json:"risk_level"`
	Status             string          `json:"status"`
	DraftReference     string          `json:"draft_reference"`
	CreatedByAI        bool            `json:"created_by_ai"`
	ReviewedBy         *uuid.UUID      `json:"reviewed_by"`
	ReviewedAt         *time.Time      `json:"reviewed_at"`
	CreatedAt          time.Time       `json:"created_at"`
}

// List 分页查询草稿（status/recommendation_type 可选过滤）。
func (s *DraftStore) List(ctx context.Context, recType, status string, page, pageSize int) ([]Recommendation, int64, error) {
	where := "1=1"
	args := []interface{}{}
	idx := 1
	if recType != "" {
		where += fmt.Sprintf(" AND recommendation_type = $%d", idx)
		args = append(args, recType)
		idx++
	}
	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, status)
		idx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM ai_recommendations WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	rows, err := s.db.Query(ctx, `
SELECT id, task_id, recommendation_type, target_type, target_id, summary, evidence_references,
  risk_level, status, draft_reference, created_by_ai, reviewed_by, reviewed_at, created_at
FROM ai_recommendations WHERE `+where+` ORDER BY created_at DESC LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Recommendation
	for rows.Next() {
		var rec Recommendation
		if err := rows.Scan(&rec.ID, &rec.TaskID, &rec.RecommendationType, &rec.TargetType, &rec.TargetID,
			&rec.Summary, &rec.EvidenceReferences, &rec.RiskLevel, &rec.Status, &rec.DraftReference,
			&rec.CreatedByAI, &rec.ReviewedBy, &rec.ReviewedAt, &rec.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, rec)
	}
	return out, total, rows.Err()
}

// Get 查询单条草稿。
func (s *DraftStore) Get(ctx context.Context, id uuid.UUID) (*Recommendation, error) {
	var rec Recommendation
	err := s.db.QueryRow(ctx, `
SELECT id, task_id, recommendation_type, target_type, target_id, summary, evidence_references,
  risk_level, status, draft_reference, created_by_ai, reviewed_by, reviewed_at, created_at
FROM ai_recommendations WHERE id = $1`, id).Scan(
		&rec.ID, &rec.TaskID, &rec.RecommendationType, &rec.TargetType, &rec.TargetID,
		&rec.Summary, &rec.EvidenceReferences, &rec.RiskLevel, &rec.Status, &rec.DraftReference,
		&rec.CreatedByAI, &rec.ReviewedBy, &rec.ReviewedAt, &rec.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDraftNotFound
		}
		return nil, err
	}
	return &rec, nil
}

// Discard 逻辑废弃草稿（DRAFT/PENDING_REVIEW → REJECTED，记录审核人；不删除记录）。
func (s *DraftStore) Discard(ctx context.Context, id, reviewedBy uuid.UUID) error {
	return s.transition(ctx, id, reviewedBy, "REJECTED")
}

// Accept 接受推荐进入人工草稿流程（DRAFT/PENDING_REVIEW → ACCEPTED；不自动发布业务配置）。
func (s *DraftStore) Accept(ctx context.Context, id, reviewedBy uuid.UUID) error {
	return s.transition(ctx, id, reviewedBy, "ACCEPTED")
}

// Reject 拒绝推荐（DRAFT/PENDING_REVIEW → REJECTED）。
func (s *DraftStore) Reject(ctx context.Context, id, reviewedBy uuid.UUID) error {
	return s.transition(ctx, id, reviewedBy, "REJECTED")
}

func (s *DraftStore) transition(ctx context.Context, id, reviewedBy uuid.UUID, to string) error {
	if to != "ACCEPTED" && to != "REJECTED" {
		return fmt.Errorf("invalid target status %s", to)
	}
	tag, err := s.db.Exec(ctx, `
UPDATE ai_recommendations SET status=$2, reviewed_by=$3, reviewed_at=now()
WHERE id=$1 AND status IN ('DRAFT','PENDING_REVIEW')`, id, to, reviewedBy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if _, err := s.Get(ctx, id); err != nil {
			return err
		}
		return ErrDraftState
	}
	return nil
}
