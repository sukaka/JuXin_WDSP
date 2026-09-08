// overrides_admin.go Phase 4 定向采集规则管理端点（契约 §2.3；会话 + RBAC，统一信封）：
//
//	GET    /api/v1/traffic/agents/{agent_id}/overrides                  规则列表（view；含派生 active）
//	POST   /api/v1/traffic/agents/{agent_id}/overrides                  新增规则（manage；201）
//	DELETE /api/v1/traffic/agents/{agent_id}/overrides/{override_id}    删除规则（manage；204）
//
// 创建/删除在同一事务内 agents.config_version+1 驱动 Agent 重拉配置；写操作 HIGH 级审计
// （module=traffic-agents，action=override_create/override_delete，before/after 含 match 与 level）。
package agents

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// ListOverrides GET /api/v1/traffic/agents/{agent_id}/overrides（view）。
// 列表含已过期规则（派生 active=未过期——契约 §2.3；过期规则保留 30 天后由 sweeper 清理）。
func (h *Handler) ListOverrides(w http.ResponseWriter, r *http.Request) {
	id, ok := parseAgentID(w, r)
	if !ok {
		return
	}
	if _, err := h.store.GetAgent(r.Context(), id); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	rows, err := h.store.ListCaptureOverrides(r.Context(), id)
	if err != nil {
		h.adminInternal(w, r, err)
		return
	}
	now := h.now().UTC()
	items := make([]CaptureOverrideItem, 0, len(rows))
	for i := range rows {
		items = append(items, CaptureOverrideItem{
			CaptureOverride: rows[i],
			Active:          rows[i].ExpiresAt.After(now),
		})
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

// createOverrideRequest 新增规则入参（契约 §2.3）。
type createOverrideRequest struct {
	Match        json.RawMessage `json:"match"`
	CaptureLevel string          `json:"capture_level"`
	TTLMinutes   int             `json:"ttl_minutes"`
	Note         string          `json:"note"`
}

// CreateOverride POST /api/v1/traffic/agents/{agent_id}/overrides（manage；201）。
// match 经 fail-closed 校验（未知字段拒绝 + §2.2 字段规则）后归一落库；
// ttl_minutes 缺省（0）取 30，范围 1-1440。
func (h *Handler) CreateOverride(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseAgentID(w, r)
	if !ok {
		return
	}
	var req createOverrideRequest
	if !decodeAdminJSON(w, r, &req) {
		return
	}
	if len(req.Match) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "match 缺失")
		return
	}
	var match CaptureOverrideMatch
	if err := decodeMachineJSON(req.Match, &match); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "match 不是合法的匹配条件 JSON")
		return
	}
	if err := match.validate(); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	switch req.CaptureLevel {
	case "L0", "L1", "L2", "L3":
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "capture_level 须为 L0/L1/L2/L3 之一")
		return
	}
	ttl := req.TTLMinutes
	if ttl == 0 {
		ttl = OverrideTTLDefaultMinutes
	}
	if ttl < OverrideTTLMinMinutes || ttl > OverrideTTLMaxMinutes {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "ttl_minutes 须在 1~1440（缺省 30）")
		return
	}
	req.Note = strings.TrimSpace(req.Note)
	if len(req.Note) > overrideNoteMaxLen {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "note 超过 512 字符")
		return
	}
	// Agent 404 前置（与既有端点同口径；仓储事务内仍有存在性兜底）
	before, err := h.store.GetAgent(r.Context(), id)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	// 校验后归一序列化（缺省键省略，JSONB 不存噪音）
	matchJSON, _ := json.Marshal(&match)
	now := h.now().UTC()
	created, err := h.store.CreateCaptureOverride(r.Context(), CaptureOverrideInput{
		AgentID:      id,
		Match:        matchJSON,
		CaptureLevel: req.CaptureLevel,
		Note:         req.Note,
		CreatedBy:    principalName(p),
		ExpiresAt:    now.Add(time.Duration(ttl) * time.Minute),
		Now:          now,
	})
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "override_create", "agent_capture_override", created.ID.String(), before.Hostname,
		"", overrideAuditSummary(&match, req.CaptureLevel, created.ExpiresAt, req.Note),
		audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusCreated, CaptureOverrideItem{
		CaptureOverride: *created,
		Active:          true,
	})
}

// DeleteOverride DELETE /api/v1/traffic/agents/{agent_id}/overrides/{override_id}（manage；204）。
func (h *Handler) DeleteOverride(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseAgentID(w, r)
	if !ok {
		return
	}
	overrideID, err := uuid.Parse(r.PathValue("override_id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "override_id 非法")
		return
	}
	before, err := h.store.GetAgent(r.Context(), id)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	deleted, err := h.store.DeleteCaptureOverride(r.Context(), id, overrideID, h.now().UTC())
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	var match CaptureOverrideMatch
	_ = json.Unmarshal(deleted.Match, &match)
	h.recordAudit(r, p, "override_delete", "agent_capture_override", overrideID.String(), before.Hostname,
		overrideAuditSummary(&match, deleted.CaptureLevel, deleted.ExpiresAt, deleted.Note), "",
		audits.ResultSuccess, audits.RiskHigh)
	w.WriteHeader(http.StatusNoContent)
}

// overrideAuditSummary 规则审计摘要（合法 JSON；含 match 与 level——契约 §2.3/任务口径）。
func overrideAuditSummary(match *CaptureOverrideMatch, level string, expiresAt time.Time, note string) string {
	raw, _ := json.Marshal(map[string]interface{}{
		"match":         match,
		"capture_level": level,
		"expires_at":    expiresAt.UTC().Format(time.RFC3339),
		"note":          note,
	})
	return string(raw)
}
