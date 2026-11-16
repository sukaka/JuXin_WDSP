// feedback_handler.go AI 反馈质量聚合查询（管理面只读）：
// 按 feedback_type × task_type 聚合窗口内反馈总量/负反馈量/负反馈率，
// 用于回答质量运营观测；不返回 comment（反馈原文可能含用户输入，聚合面不落明文）。
package aihandlers

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/response"
)

// feedbackSummaryDays days 查询参数口径：默认 7 天，夹取上限 90 天（queryInt 已归一非正数为默认）。
func feedbackSummaryDays(r *http.Request) int {
	n := queryInt(r, "days", 7)
	if n > 90 {
		n = 90
	}
	return n
}

// feedbackSummaryItem 聚合行（feedback_type × task_type）。
type feedbackSummaryItem struct {
	FeedbackType string  `json:"feedback_type"`
	TaskType     string  `json:"task_type"`
	Total        int64   `json:"total"`
	Negative     int64   `json:"negative"`
	NegativeRate float64 `json:"negative_rate"` // 负反馈占比（百分制，两位小数）
}

// FeedbackSummary GET /api/v1/ai/feedback/summary?days=7（权限 ai.usage.read）。
// task_type 关联口径：反馈经 session_id 挂到该会话内、反馈时刻之前最近一次 ai_tasks
// （LEFT JOIN LATERAL），无法关联（会话无任务记录）归 UNKNOWN。
func (d *Deps) FeedbackSummary(w http.ResponseWriter, r *http.Request) {
	days := feedbackSummaryDays(r)
	rows, err := d.DB.Query(r.Context(), `
SELECT f.feedback_type, COALESCE(t.task_type, 'UNKNOWN') AS task_type,
       count(*) AS total, count(*) FILTER (WHERE f.rating < 0) AS negative
FROM ai_feedback f
LEFT JOIN LATERAL (
    SELECT at.task_type FROM ai_tasks at
    WHERE at.session_id = f.session_id AND at.created_at <= f.created_at
    ORDER BY at.created_at DESC LIMIT 1
) t ON true
WHERE f.created_at >= now() - make_interval(days => $1)
GROUP BY f.feedback_type, COALESCE(t.task_type, 'UNKNOWN')
ORDER BY f.feedback_type, task_type`, days)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	defer rows.Close()
	items := make([]feedbackSummaryItem, 0, 16)
	var totalAll, negativeAll int64
	for rows.Next() {
		var it feedbackSummaryItem
		if err := rows.Scan(&it.FeedbackType, &it.TaskType, &it.Total, &it.Negative); err != nil {
			response.InternalError(w, r, err)
			return
		}
		if it.Total > 0 {
			rate := float64(it.Negative) * 100 / float64(it.Total)
			it.NegativeRate = float64(int(rate*100)) / 100
		}
		totalAll += it.Total
		negativeAll += it.Negative
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		response.InternalError(w, r, err)
		return
	}
	overallRate := 0.0
	if totalAll > 0 {
		overallRate = float64(int(float64(negativeAll)*100/float64(totalAll)*100)) / 100
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"days":  days,
		"items": items,
		"total": map[string]interface{}{
			"total": totalAll, "negative": negativeAll, "negative_rate": overallRate,
		},
	})
}
