// details_handler.go 详情 GET（阶段7 §30 接口路径对齐补齐）：
// 模型 / Agent / Tool / AI 审计 / 评估运行五个详情接口；返回字段口径与对应列表项一致，
// 不新造字段；只读操作不写 AI 审计（与邻近读接口一致）。路由在 app.go 注册。
package aihandlers

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jiuzhang-waf/server/internal/aiaudit"
	"github.com/jiuzhang-waf/server/internal/response"
)

// ModelGet 模型详情（字段口径同模型列表项，绝不含密钥材料）。
func (d *Deps) ModelGet(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模型ID")
		return
	}
	m, err := d.Models.GetModel(r.Context(), id)
	if err != nil {
		d.modelError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"model": toModelDTO(m)})
}

// AgentGet Agent 详情（字段口径同 Agent 列表项，含 in_registry 标记）。
func (d *Deps) AgentGet(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的Agent ID")
		return
	}
	var a agentDTO
	err = d.DB.QueryRow(r.Context(), `
SELECT id, code, name, description, allowed_tool_ids, status, version FROM ai_agents WHERE id=$1`, id).
		Scan(&a.ID, &a.Code, &a.Name, &a.Description, &a.AllowedToolIDs, &a.Status, &a.Version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Agent 不存在")
		} else {
			response.InternalError(w, r, err)
		}
		return
	}
	a.InRegistry = d.AgentCodes[a.Code] || a.Code == "dispatcher"
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"agent": a})
}

// ToolGet Tool 详情（字段口径同 Tool 列表项，含 in_registry 标记）。
func (d *Deps) ToolGet(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的Tool ID")
		return
	}
	var t toolDTO
	err = d.DB.QueryRow(r.Context(), `
SELECT id, code, name, description, version, risk_level, required_permission, input_schema,
  timeout_seconds, max_results, status FROM ai_tools WHERE id=$1`, id).
		Scan(&t.ID, &t.Code, &t.Name, &t.Description, &t.Version, &t.RiskLevel,
			&t.RequiredPermission, &t.InputSchema, &t.TimeoutSeconds, &t.MaxResults, &t.Status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Tool 不存在")
		} else {
			response.InternalError(w, r, err)
		}
		return
	}
	_, t.InRegistry = d.Tools.Get(t.Code)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"tool": t})
}

// auditDetailDTO 审计详情输出（列表项字段 + 记录 ID；详情补查 prompt_version/confirm_result 列）。
type auditDetailDTO struct {
	ID uuid.UUID `json:"id"`
	aiaudit.Record
}

// AuditGet AI 审计详情（字段口径同审计列表项；写入时已脱敏，此处原样返回）。
func (d *Deps) AuditGet(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的审计记录ID")
		return
	}
	rec := auditDetailDTO{ID: id}
	var uid, sid, tid *uuid.UUID
	err = d.DB.QueryRow(r.Context(), `
SELECT occurred_at, user_id, username, role_codes, session_id, task_id, action, task_type, agent_code, tool_code, model_code,
  prompt_version, input_tokens, output_tokens, duration_ms, estimated_cost, request_summary, result_summary, draft_reference, confirm_result
FROM ai_audit_records WHERE id=$1`, id).
		Scan(&rec.OccurredAt, &uid, &rec.Username, &rec.RoleCodes, &sid, &tid, &rec.Action, &rec.TaskType,
			&rec.AgentCode, &rec.ToolCode, &rec.ModelCode, &rec.PromptVersion,
			&rec.InputTokens, &rec.OutputTokens, &rec.DurationMs, &rec.EstimatedCost,
			&rec.RequestSummary, &rec.ResultSummary, &rec.DraftReference, &rec.ConfirmResult)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "审计记录不存在")
		} else {
			response.InternalError(w, r, err)
		}
		return
	}
	rec.UserID = uid
	rec.SessionID = sid
	rec.TaskID = tid
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"audit": rec})
}

// EvalRunGet 评估运行详情（字段口径同评估运行列表项，含评估集编码与运行明细）。
func (d *Deps) EvalRunGet(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的评估运行ID")
		return
	}
	var run evalRunDTO
	err = d.DB.QueryRow(r.Context(), `
SELECT r.id, r.evaluation_set_id, s.code, r.status, r.score, r.details, r.started_at, r.finished_at
FROM ai_evaluation_runs r JOIN ai_evaluation_sets s ON s.id = r.evaluation_set_id
WHERE r.id=$1`, id).
		Scan(&run.ID, &run.EvaluationSetID, &run.SetCode, &run.Status,
			&run.Score, &run.Details, &run.StartedAt, &run.FinishedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "评估运行记录不存在")
		} else {
			response.InternalError(w, r, err)
		}
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"run": run})
}
