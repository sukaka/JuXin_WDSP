// evaluations_handler.go AI 质量评估：评估集管理 + 真实回归运行 HTTP 入口。
// 运行核心已抽至 evaluation_runner.go（executeEvalSet），供本入口与 Prompt 版本
// 真实回归（PromptVersionTest）共用；计分口径：回答对 expected_contains 大小写不敏感包含匹配。
package aihandlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aiaudit"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// evalCase 评估用例。
type evalCase struct {
	Question         string `json:"question"`
	ExpectedContains string `json:"expected_contains"`
}

// errEvalSetEmpty 评估集没有有效用例（cases 为空或 JSON 非法）。
var errEvalSetEmpty = errors.New("评估集没有有效的测试用例")

// errEvalSetNotFound 评估集不存在。
var errEvalSetNotFound = errors.New("评估集不存在")

// evalRunTimeout 单次评估运行整体超时（逐条串行，防止长时间占用）。
const evalRunTimeout = 10 * time.Minute

// evalCaseLimit 单次运行用例上限。
const evalCaseLimit = 20

// EvalSetList 评估集列表。
func (d *Deps) EvalSetList(w http.ResponseWriter, r *http.Request) {
	rows, err := d.DB.Query(r.Context(), `
SELECT id, code, name, description, cases, created_at FROM ai_evaluation_sets ORDER BY code LIMIT 200`)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	defer rows.Close()
	type setDTO struct {
		ID          uuid.UUID       `json:"id"`
		Code        string          `json:"code"`
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Cases       json.RawMessage `json:"cases"`
		CreatedAt   time.Time       `json:"created_at"`
	}
	out := make([]setDTO, 0, 8)
	for rows.Next() {
		var s setDTO
		if err := rows.Scan(&s.ID, &s.Code, &s.Name, &s.Description, &s.Cases, &s.CreatedAt); err != nil {
			response.InternalError(w, r, err)
			return
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": out})
}

// EvalSetCreate 创建评估集。
func (d *Deps) EvalSetCreate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req struct {
		Code        string     `json:"code"`
		Name        string     `json:"name"`
		Description string     `json:"description"`
		Cases       []evalCase `json:"cases"`
	}
	if err := decodeJSON(w, r, &req, 131072); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	req.Code = strings.TrimSpace(req.Code)
	req.Name = strings.TrimSpace(req.Name)
	if req.Code == "" || len(req.Code) > 50 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "评估集编码必填且不超过 50 字符")
		return
	}
	if req.Name == "" || len(req.Name) > 100 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "评估集名称必填且不超过 100 字符")
		return
	}
	if len(req.Cases) == 0 || len(req.Cases) > 50 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "测试用例数量须为 1-50")
		return
	}
	for _, c := range req.Cases {
		if strings.TrimSpace(c.Question) == "" || len(c.Question) > 1000 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "用例问题必填且不超过 1000 字符")
			return
		}
	}
	casesJSON, _ := json.Marshal(req.Cases)
	tag, err := d.DB.Exec(r.Context(), `
INSERT INTO ai_evaluation_sets (code, name, description, cases) VALUES ($1,$2,$3,$4)
ON CONFLICT (code) DO NOTHING`,
		req.Code, req.Name, trunc(req.Description, 500), casesJSON)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if tag.RowsAffected() == 0 {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "评估集编码已存在")
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		Action: "evaluation_set_create", RequestSummary: "创建评估集 " + req.Code, ResultSummary: "SUCCESS",
	})
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "评估集已创建"})
}

// evalRunDTO 评估运行输出（列表项与详情共用同一字段口径）。
type evalRunDTO struct {
	ID              uuid.UUID       `json:"id"`
	EvaluationSetID uuid.UUID       `json:"evaluation_set_id"`
	SetCode         string          `json:"set_code"`
	Status          string          `json:"status"`
	Score           *float64        `json:"score"`
	Details         json.RawMessage `json:"details"`
	StartedAt       time.Time       `json:"started_at"`
	FinishedAt      *time.Time      `json:"finished_at"`
}

// EvalRunList 评估运行记录（分页）。
func (d *Deps) EvalRunList(w http.ResponseWriter, r *http.Request) {
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	if pageSize > 100 {
		pageSize = 100
	}
	var total int64
	if err := d.DB.QueryRow(r.Context(), `SELECT count(*) FROM ai_evaluation_runs`).Scan(&total); err != nil {
		response.InternalError(w, r, err)
		return
	}
	rows, err := d.DB.Query(r.Context(), `
SELECT r.id, r.evaluation_set_id, s.code, r.status, r.score, r.details, r.started_at, r.finished_at
FROM ai_evaluation_runs r JOIN ai_evaluation_sets s ON s.id = r.evaluation_set_id
ORDER BY r.started_at DESC LIMIT $1 OFFSET $2`, pageSize, (page-1)*pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	defer rows.Close()
	out := make([]evalRunDTO, 0, pageSize)
	for rows.Next() {
		var run evalRunDTO
		if err := rows.Scan(&run.ID, &run.EvaluationSetID, &run.SetCode, &run.Status,
			&run.Score, &run.Details, &run.StartedAt, &run.FinishedAt); err != nil {
			response.InternalError(w, r, err)
			return
		}
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, out, total, page, pageSize)
}

// EvalRun 执行评估：委托 executeEvalSet（真实回归共用运行器）逐条过编排器计分落库。
func (d *Deps) EvalRun(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req struct {
		EvaluationSetID string `json:"evaluation_set_id"`
	}
	if err := decodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	setID, err := uuid.Parse(req.EvaluationSetID)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的评估集ID")
		return
	}
	// 评估串行跑多个用例可能远超服务器 WriteTimeout（默认 30s），放宽本请求写期限
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetWriteDeadline(time.Now().Add(15 * time.Minute))
	}
	runCtx, cancel := context.WithTimeout(r.Context(), evalRunTimeout)
	defer cancel()
	outcome, err := d.executeEvalSet(runCtx, p, setID, nil, nil)
	if err != nil {
		switch {
		case errors.Is(err, errEvalSetNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, errEvalSetNotFound.Error())
		case errors.Is(err, errEvalSetEmpty):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, errEvalSetEmpty.Error())
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	d.recordAIAudit(p, aiaudit.Record{
		SessionID: &outcome.SessionID, Action: "evaluation_run",
		RequestSummary: "运行评估集 " + outcome.SetCode,
		ResultSummary:  fmt.Sprintf("score=%.2f passed=%d/%d", outcome.Score, outcome.Passed, outcome.Total),
		InputTokens:    outcome.InTokens, OutputTokens: outcome.OutTokens,
	})
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"run": map[string]interface{}{
			"id":                outcome.RunID,
			"evaluation_set_id": outcome.SetID,
			"status":            "SUCCESS",
			"score":             outcome.Score,
			"total":             outcome.Total,
			"passed":            outcome.Passed,
			"truncated":         outcome.Truncated,
		},
	})
}
