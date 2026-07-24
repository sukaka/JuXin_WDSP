// recommend.go 降噪推荐：对疑似误报且超阈值的簇写 ai_recommendations
// （recommendation_type=NOISE_REDUCTION，status=DRAFT，人工审核；绝不自动生效）。
// 同簇已有 DRAFT/PENDING_REVIEW 推荐时跳过，避免重复推荐。
package ainoise

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// RecommendationType 降噪推荐类型。
const RecommendationType = "NOISE_REDUCTION"

// RecommendationRecorder 推荐落库契约（*aitools.DraftStore 满足；
// 接口定义在本包以避免 ainoise → aitools 依赖反转成环）。
type RecommendationRecorder interface {
	RecordRecommendation(ctx context.Context, taskID *uuid.UUID, recType, targetType, targetID, summary, risk, draftRef string, evidence []string) (uuid.UUID, error)
}

// Recommender 降噪推荐生成器。
type Recommender struct {
	rec RecommendationRecorder
}

// NewRecommender 创建推荐生成器（rec 为 nil 时全部跳过）。
func NewRecommender(rec RecommendationRecorder) *Recommender {
	return &Recommender{rec: rec}
}

// MaybeRecommend 为疑似误报簇生成 DRAFT 推荐；返回是否实际写入。
// 已有未决推荐（DRAFT/PENDING_REVIEW）或证据不足时跳过；错误如实返回，不静默吞掉。
func (r *Recommender) MaybeRecommend(ctx context.Context, store Store, c *Cluster) (bool, error) {
	if r == nil || r.rec == nil || c == nil {
		return false, nil
	}
	if c.AIVerdict != VerdictLikelyFalsePositive {
		return false, nil
	}
	open, err := store.HasOpenRecommendation(ctx, c.ID)
	if err != nil {
		return false, fmt.Errorf("check open noise recommendation: %w", err)
	}
	if open {
		return false, nil
	}
	// 证据引用：簇 ID + 代表事件 ID
	evidence := []string{"cluster:" + c.ID.String()}
	if ev, err := store.Evidence(ctx, c.ID); err == nil && ev.RepresentativeID != nil {
		evidence = append(evidence, "event:"+ev.RepresentativeID.String())
	} else if err != nil {
		return false, fmt.Errorf("load noise cluster evidence: %w", err)
	}
	conf := 0.0
	if c.AIConfidence != nil {
		conf = *c.AIConfidence
	}
	summary := fmt.Sprintf("降噪簇 %s %s（%d 个事件）疑似误报（置信度 %.2f），建议人工审核后考虑例外或规则调优",
		c.Host, c.NormalizedURI, c.EventCount, conf)
	if c.AISummary != "" {
		summary += "：" + c.AISummary
	}
	if len([]rune(summary)) > 900 {
		summary = string([]rune(summary)[:900])
	}
	_, err = r.rec.RecordRecommendation(ctx, nil, RecommendationType, "NOISE_CLUSTER", c.ID.String(),
		summary, "LOW", "noise:"+c.ID.String(), evidence)
	if err != nil {
		return false, fmt.Errorf("record noise recommendation: %w", err)
	}
	return true, nil
}
