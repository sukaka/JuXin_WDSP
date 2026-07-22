// evaluations_handler.go AI 质量评估（最小落地）：
// 评估集内存测试用例（question + expected_contains），运行逐条过编排器，
// 按回答包含匹配计分并落库 ai_evaluation_runs。
package aihandlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aiaudit"
	"github.com/jiuzhang-waf/server/internal/aiorchestrator"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// evalCase 评估用例。
type evalCase struct {
	Question         string `json:"question"`
	ExpectedContains string `json:"expected_contains"`
}

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
	type runDTO struct {
		ID              uuid.UUID       `json:"id"`
		EvaluationSetID uuid.UUID       `json:"evaluation_set_id"`
		SetCode         string          `json:"set_code"`
		Status          string          `json:"status"`
		Score           *float64        `json:"score"`
		Details         json.RawMessage `json:"details"`
		StartedAt       time.Time       `json:"started_at"`
		FinishedAt      *time.Time      `json:"finished_at"`
	}
	out := make([]runDTO, 0, pageSize)
	for rows.Next() {
		var run runDTO
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

// EvalRun 执行评估：逐条用例过编排器，按 expected_contains 包含匹配计分落库。
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
	var setCode string
	var casesJSON json.RawMessage
	err = d.DB.QueryRow(r.Context(), `SELECT code, cases FROM ai_evaluation_sets WHERE id=$1`, setID).
		Scan(&setCode, &casesJSON)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "评估集不存在")
		return
	}
	var cases []evalCase
	if err := json.Unmarshal(casesJSON, &cases); err != nil || len(cases) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "评估集没有有效的测试用例")
		return
	}
	truncated := false
	if len(cases) > evalCaseLimit {
		cases = cases[:evalCaseLimit]
		truncated = true
	}
	// 一次性会话（评估过程不污染会话列表，用完即删）
	sess, err := d.Sessions.Create(r.Context(), p.UserID, "[评估运行] "+setCode)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	defer func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer dcancel()
		if err := d.Sessions.Delete(dctx, sess.ID); err != nil {
			slog.Warn("delete evaluation session failed", "session_id", sess.ID, "error", err)
		}
	}()
	// 评估串行跑多个用例可能远超服务器 WriteTimeout（默认 30s），放宽本请求写期限
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetWriteDeadline(time.Now().Add(15 * time.Minute))
	}
	runCtx, cancel := context.WithTimeout(r.Context(), evalRunTimeout)
	defer cancel()
	// 逐条执行（串行，最小实现）
	type caseResult struct {
		Question         string `json:"question"`
		ExpectedContains string `json:"expected_contains"`
		Passed           bool   `json:"passed"`
		AnswerExcerpt    string `json:"answer_excerpt,omitempty"`
		Error            string `json:"error,omitempty"`
	}
	details := make([]caseResult, 0, len(cases))
	passed := 0
	inTok, outTok := 0, 0
	for _, c := range cases {
		cr := caseResult{Question: c.Question, ExpectedContains: c.ExpectedContains}
		inTok += aiorchestrator.EstimateTokens(c.Question)
		result, err := d.Orch.Run(runCtx, aiorchestrator.RunInput{
			SessionID: sess.ID, UserID: p.UserID, Username: p.Username,
			RoleCodes: p.Roles, Permissions: p.PermsSet, Message: c.Question,
		}, nil)
		if err != nil {
			cr.Error = "执行失败"
			details = append(details, cr)
			continue
		}
		outTok += aiorchestrator.EstimateTokens(result.Answer)
		cr.Passed = true
		if c.ExpectedContains != "" {
			cr.Passed = strings.Contains(strings.ToLower(result.Answer), strings.ToLower(c.ExpectedContains))
		}
		if cr.Passed {
			passed++
		}
		cr.AnswerExcerpt = trunc(result.Answer, 300)
		details = append(details, cr)
	}
	score := float64(passed) * 100 / float64(len(cases))
	// 保留两位小数
	score = float64(int(score*100)) / 100
	detailsJSON, _ := json.Marshal(map[string]interface{}{
		"total": len(cases), "passed": passed, "truncated": truncated, "cases": details,
	})
	runID := uuid.New()
	if _, err := d.DB.Exec(r.Context(), `
INSERT INTO ai_evaluation_runs (id, evaluation_set_id, status, score, details, finished_at)
VALUES ($1,$2,'SUCCESS',$3,$4,now())`, runID, setID, score, detailsJSON); err != nil {
		response.InternalError(w, r, err)
		return
	}
	// 用量与审计（聚合记录一次）
	pctx, pcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pcancel()
	if uErr := d.Cost.RecordUsage(pctx, p.UserID, &sess.ID, nil, nil, inTok, outTok, 0, 0); uErr != nil {
		slog.Error("record evaluation usage failed", "error", uErr)
	}
	d.recordAIAudit(p, aiaudit.Record{
		SessionID: &sess.ID, Action: "evaluation_run",
		RequestSummary: "运行评估集 " + setCode,
		ResultSummary:  fmt.Sprintf("score=%.2f passed=%d/%d", score, passed, len(cases)),
		InputTokens: inTok, OutputTokens: outTok,
	})
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"run": map[string]interface{}{
			"id":                runID,
			"evaluation_set_id": setID,
			"status":            "SUCCESS",
			"score":             score,
			"total":             len(cases),
			"passed":            passed,
			"truncated":         truncated,
		},
	})
}
