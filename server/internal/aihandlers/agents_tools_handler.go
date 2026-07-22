// agents_tools_handler.go Agent / Tool 管理面：
// 代码 registry 是能力来源，ai_agents/ai_tools 表存启停与配置；列表 = DB 左联代码 registry。
// 启动时 SyncRegistry 把代码 registry 同步入库（code 唯一，保留既有启停状态）；
// Tool 执行经 Registry.EnabledChecker 强制尊重 DB 启停，Agent 调度经 Orchestrator 同款检查。
package aihandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aitools"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// AgentMeta Agent 目录元数据（代码 registry 中实现 + 编排器内置总调度）。
type AgentMeta struct {
	Code        string
	Name        string
	Description string
}

// AgentCatalog 8 个 Agent 目录（code 与 aiagents 注册及编排器 agentLabel 一致；
// dispatcher 为编排器内置总调度能力，非独立实现）。
var AgentCatalog = []AgentMeta{
	{"dispatcher", "总调度 Agent", "任务拆解、专业Agent调度、证据检查与结果合并（编排器内置，不可停用）"},
	{"security_event", "安全事件 Agent", "单事件分析、批量归纳、攻击画像与攻击链关联"},
	{"log_analysis", "日志分析 Agent", "访问/WAF/CC/访问控制/审计日志与 Request ID 链路追踪"},
	{"waf_policy", "WAF策略 Agent", "误报研判、规则解释、策略优化建议与 What-If 模拟"},
	{"asset", "资产 Agent", "应用、域名、证书、配置版本与发布状态盘点"},
	{"ops_diagnostic", "运维诊断 Agent", "组件健康、系统告警、发布与备份故障根因分析"},
	{"report", "报告 Agent", "日报/周报/月报与事件专题安全运营总结"},
	{"knowledge", "知识库 Agent", "OWASP CRS 与产品文档知识问答（非当前运行事实）"},
}

// SyncRegistry 启动同步：代码 registry → ai_agents/ai_tools（code 唯一 upsert，保留启停状态）。
func SyncRegistry(ctx context.Context, db *pgxpool.Pool, tools *aitools.Registry) error {
	for _, a := range AgentCatalog {
		if _, err := db.Exec(ctx, `
INSERT INTO ai_agents (code, name, description, status) VALUES ($1,$2,$3,'ENABLED')
ON CONFLICT (code) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, updated_at=now()`,
			a.Code, a.Name, a.Description); err != nil {
			return err
		}
	}
	for _, t := range tools.List() {
		schema, _ := json.Marshal(t["input_schema"])
		if _, err := db.Exec(ctx, `
INSERT INTO ai_tools (code, name, description, version, risk_level, required_permission, input_schema,
  timeout_seconds, max_results, status)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'ENABLED')
ON CONFLICT (code) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, version=EXCLUDED.version,
  risk_level=EXCLUDED.risk_level, required_permission=EXCLUDED.required_permission,
  input_schema=EXCLUDED.input_schema, timeout_seconds=EXCLUDED.timeout_seconds,
  max_results=EXCLUDED.max_results, updated_at=now()`,
			t["code"], t["name"], t["description"], t["version"], t["risk_level"],
			t["required_permission"], schema, t["timeout_seconds"], t["max_results"]); err != nil {
			return err
		}
	}
	return nil
}

// ToolEnabledChecker Tool 启停检查（未入库默认启用；执行路径每次实时查库保证即时生效）。
func ToolEnabledChecker(db *pgxpool.Pool) aitools.EnabledChecker {
	return func(ctx context.Context, code string) bool {
		var status string
		if err := db.QueryRow(ctx, `SELECT status FROM ai_tools WHERE code=$1`, code).Scan(&status); err != nil {
			return true
		}
		return status == "ENABLED"
	}
}

// AgentEnabledChecker Agent 启停检查（dispatcher 为编排器内置能力，恒启用）。
func AgentEnabledChecker(db *pgxpool.Pool) func(ctx context.Context, code string) bool {
	return func(ctx context.Context, code string) bool {
		if code == "dispatcher" {
			return true
		}
		var status string
		if err := db.QueryRow(ctx, `SELECT status FROM ai_agents WHERE code=$1`, code).Scan(&status); err != nil {
			return true
		}
		return status == "ENABLED"
	}
}

// agentDTO Agent 输出。
type agentDTO struct {
	ID             uuid.UUID       `json:"id"`
	Code           string          `json:"code"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	AllowedToolIDs json.RawMessage `json:"allowed_tool_ids"`
	Status         string          `json:"status"`
	Version        int             `json:"version"`
	InRegistry     bool            `json:"in_registry"`
}

// AgentList Agent 列表（DB 左联代码 registry）。
func (d *Deps) AgentList(w http.ResponseWriter, r *http.Request) {
	rows, err := d.DB.Query(r.Context(), `
SELECT id, code, name, description, allowed_tool_ids, status, version FROM ai_agents ORDER BY code`)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	defer rows.Close()
	out := make([]agentDTO, 0, 8)
	for rows.Next() {
		var a agentDTO
		if err := rows.Scan(&a.ID, &a.Code, &a.Name, &a.Description, &a.AllowedToolIDs, &a.Status, &a.Version); err != nil {
			response.InternalError(w, r, err)
			return
		}
		a.InRegistry = d.AgentCodes[a.Code] || a.Code == "dispatcher"
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": out})
}

// AgentPatch 配置 Agent（启停 / 允许 Tool 集；dispatcher 内置不可停用）。
func (d *Deps) AgentPatch(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的Agent ID")
		return
	}
	var req struct {
		Enabled        *bool    `json:"enabled"`
		AllowedToolIDs []string `json:"allowed_tool_ids"`
	}
	if err := decodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Enabled == nil && req.AllowedToolIDs == nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "未提供任何配置变更")
		return
	}
	// dispatcher 为编排器内置总调度，禁止停用
	var code string
	if err := d.DB.QueryRow(r.Context(), `SELECT code FROM ai_agents WHERE id=$1`, id).Scan(&code); err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Agent 不存在")
		return
	}
	if req.Enabled != nil && !*req.Enabled && code == "dispatcher" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "总调度 Agent 为编排器内置能力，不可停用")
		return
	}
	if req.Enabled != nil {
		status := "DISABLED"
		if *req.Enabled {
			status = "ENABLED"
		}
		if _, err := d.DB.Exec(r.Context(), `UPDATE ai_agents SET status=$2, updated_at=now() WHERE id=$1`, id, status); err != nil {
			response.InternalError(w, r, err)
			return
		}
	}
	if req.AllowedToolIDs != nil {
		for _, t := range req.AllowedToolIDs {
			if len(t) > 100 {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "Tool 编码过长")
				return
			}
		}
		toolIDs, _ := json.Marshal(req.AllowedToolIDs)
		if _, err := d.DB.Exec(r.Context(), `UPDATE ai_agents SET allowed_tool_ids=$2, updated_at=now() WHERE id=$1`, id, toolIDs); err != nil {
			response.InternalError(w, r, err)
			return
		}
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "Agent 配置已更新"})
}

// toolDTO Tool 输出。
type toolDTO struct {
	ID                 uuid.UUID       `json:"id"`
	Code               string          `json:"code"`
	Name               string          `json:"name"`
	Description        string          `json:"description"`
	Version            string          `json:"version"`
	RiskLevel          string          `json:"risk_level"`
	RequiredPermission string          `json:"required_permission"`
	InputSchema        json.RawMessage `json:"input_schema"`
	TimeoutSeconds     int             `json:"timeout_seconds"`
	MaxResults         int             `json:"max_results"`
	Status             string          `json:"status"`
	InRegistry         bool            `json:"in_registry"`
}

// ToolList Tool 列表（DB 左联代码 registry）。
func (d *Deps) ToolList(w http.ResponseWriter, r *http.Request) {
	rows, err := d.DB.Query(r.Context(), `
SELECT id, code, name, description, version, risk_level, required_permission, input_schema,
  timeout_seconds, max_results, status FROM ai_tools ORDER BY code`)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	defer rows.Close()
	out := make([]toolDTO, 0, 16)
	for rows.Next() {
		var t toolDTO
		if err := rows.Scan(&t.ID, &t.Code, &t.Name, &t.Description, &t.Version, &t.RiskLevel,
			&t.RequiredPermission, &t.InputSchema, &t.TimeoutSeconds, &t.MaxResults, &t.Status); err != nil {
			response.InternalError(w, r, err)
			return
		}
		_, t.InRegistry = d.Tools.Get(t.Code)
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": out})
}

// ToolPatch 配置 Tool（启停 / 超时 / 最大返回数）。
func (d *Deps) ToolPatch(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的Tool ID")
		return
	}
	var req struct {
		Enabled        *bool `json:"enabled"`
		TimeoutSeconds *int  `json:"timeout_seconds"`
		MaxResults     *int  `json:"max_results"`
	}
	if err := decodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Enabled == nil && req.TimeoutSeconds == nil && req.MaxResults == nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "未提供任何配置变更")
		return
	}
	if req.TimeoutSeconds != nil && (*req.TimeoutSeconds < 1 || *req.TimeoutSeconds > 300) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "超时时间须在 1-300 秒之间")
		return
	}
	if req.MaxResults != nil && (*req.MaxResults < 1 || *req.MaxResults > 1000) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "最大返回数须在 1-1000 之间")
		return
	}
	sets := []string{}
	args := []interface{}{id}
	if req.Enabled != nil {
		status := "DISABLED"
		if *req.Enabled {
			status = "ENABLED"
		}
		args = append(args, status)
		sets = append(sets, "status=$"+itoa(len(args)))
	}
	if req.TimeoutSeconds != nil {
		args = append(args, *req.TimeoutSeconds)
		sets = append(sets, "timeout_seconds=$"+itoa(len(args)))
	}
	if req.MaxResults != nil {
		args = append(args, *req.MaxResults)
		sets = append(sets, "max_results=$"+itoa(len(args)))
	}
	tag, err := d.DB.Exec(r.Context(),
		`UPDATE ai_tools SET `+strings.Join(sets, ", ")+`, updated_at=now() WHERE id=$1`, args...)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if tag.RowsAffected() == 0 {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Tool 不存在")
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "Tool 配置已更新"})
}

// AgentTest 连通性/可用性探测（不执行真实业务分析，仅校验注册与启停）。
func (d *Deps) AgentTest(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的Agent ID")
		return
	}
	var code, status string
	if err := d.DB.QueryRow(r.Context(), `SELECT code, status FROM ai_agents WHERE id=$1`, id).Scan(&code, &status); err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Agent 不存在")
		return
	}
	inRegistry := d.AgentCodes[code] || code == "dispatcher"
	ok := status == "ENABLED" && inRegistry
	msg := "Agent 可用"
	if status != "ENABLED" {
		msg = "Agent 已停用"
	} else if !inRegistry {
		msg = "Agent 未在代码 registry 中注册"
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"ok": ok, "code": code, "status": status, "in_registry": inRegistry, "message": msg,
	})
}

// ToolTest 对 READ_ONLY Tool 做空参数探测；DRAFT_ONLY 仅校验注册与启停。
func (d *Deps) ToolTest(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的Tool ID")
		return
	}
	var code, status, risk string
	if err := d.DB.QueryRow(r.Context(), `SELECT code, status, risk_level FROM ai_tools WHERE id=$1`, id).
		Scan(&code, &status, &risk); err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Tool 不存在")
		return
	}
	t, inReg := d.Tools.Get(code)
	if status != "ENABLED" {
		response.JSON(w, r, http.StatusOK, map[string]interface{}{
			"ok": false, "code": code, "status": status, "message": "Tool 已停用",
		})
		return
	}
	if !inReg {
		response.JSON(w, r, http.StatusOK, map[string]interface{}{
			"ok": false, "code": code, "message": "Tool 未在 registry 注册",
		})
		return
	}
	result := map[string]interface{}{
		"ok": true, "code": code, "risk_level": risk, "in_registry": true,
		"timeout_seconds": t.TimeoutSeconds(), "message": "Tool 已注册且启用",
	}
	// 对无必填参数的只读 Tool 尝试空执行（失败不视为故障，仅附错误）
	if risk == aitools.RiskReadOnly {
		p := authz.PrincipalFrom(r.Context())
		prin := &aitools.Principal{UserID: p.UserID, Username: p.Username, Permissions: p.PermsSet}
		if _, _, err := d.Tools.Execute(r.Context(), prin, uuid.New(), nil, code, []byte("{}"), nil); err != nil {
			result["probe"] = "error"
			result["probe_error"] = err.Error()
			result["message"] = "Tool 已注册；空参数探测返回错误（可能需业务参数）"
		} else {
			result["probe"] = "ok"
			result["message"] = "Tool 空参数探测成功"
		}
	}
	response.JSON(w, r, http.StatusOK, result)
}
