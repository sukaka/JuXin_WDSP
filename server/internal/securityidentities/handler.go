// handler.go client_identity 体系管理面接口（WDSP AI 自动化渗透防护增强 阶段1）。
// 路由（app.go 注册，权限点 security_identities.read）：
//
//	GET /api/v1/security/identities              身份分页列表（风险等级/类型/关键字/IP/时间窗筛选）
//	GET /api/v1/security/identities/{id}         身份详情（全字段 + IP历史 + 凭据 + 最近信号）
//	GET /api/v1/security/identities/{id}/behavior 行为窗口统计时间序列
//	GET /api/v1/security/identities/{id}/events  侦察信号事件分页
package securityidentities

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 是 client_identity 体系处理器。
type Handler struct {
	store *Store
}

// NewHandler 创建处理器。
func NewHandler(store *Store) *Handler {
	return &Handler{store: store}
}

// List 身份分页列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := ListFilter{
		RiskLevel:    q.Get("risk_level"),
		IdentityType: q.Get("identity_type"),
		Keyword:      q.Get("keyword"),
		IP:           q.Get("ip"),
		Sort:         q.Get("sort"),
		Order:        q.Get("order"),
		Page:         queryInt(r, "page", 1),
		PageSize:     queryInt(r, "page_size", 20),
	}
	if f.RiskLevel != "" && !validRiskLevels[f.RiskLevel] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的风险等级（LOW/MEDIUM/HIGH/CRITICAL）")
		return
	}
	if f.IdentityType != "" && !validTypes[f.IdentityType] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的身份类型（HUMAN/BOT/APPLICATION/SERVICE/AGENT/UNKNOWN）")
		return
	}
	if f.Sort != "" && validSortFields[f.Sort] == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的排序字段（last_seen_at/first_seen_at/risk_score/request_count）")
		return
	}
	from, to, ok := parseTimeRange(w, r)
	if !ok {
		return
	}
	f.From, f.To = from, to

	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Get 身份详情（全字段 + IP 历史 + 凭据 + 最近 20 条信号事件）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	identity, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		h.writeNotFound(w, r, err)
		return
	}
	ipHistory, err := h.store.ListIPHistory(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	credentials, err := h.store.ListCredentials(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	recentEvents, err := h.store.ListRecentEvents(r.Context(), id, 20)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"identity":      identity,
		"ip_history":    ipHistory,
		"credentials":   credentials,
		"recent_events": recentEvents,
	})
}

// Behavior 行为窗口统计时间序列（window 缺省全部窗口，时间范围缺省最近 24h）。
func (h *Handler) Behavior(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f := BehaviorFilter{
		Window:   q.Get("window"),
		Page:     queryInt(r, "page", 1),
		PageSize: queryInt(r, "page_size", 50),
	}
	if f.Window != "" && !validWindows[f.Window] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的行为窗口（1m/5m/30m/24h）")
		return
	}
	from, to, ok := parseTimeRange(w, r)
	if !ok {
		return
	}
	now := time.Now()
	f.To = now
	if to != nil {
		f.To = *to
	}
	f.From = f.To.Add(-24 * time.Hour)
	if from != nil {
		f.From = *from
	}

	// 身份不存在 → 404（与详情口径一致，避免对不存在身份返回空序列误导）
	if _, err := h.store.GetByID(r.Context(), id); err != nil {
		h.writeNotFound(w, r, err)
		return
	}
	list, total, err := h.store.ListBehavior(r.Context(), id, f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Events 侦察信号事件分页（signal/时间窗筛选，occurred_at DESC）。
func (h *Handler) Events(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	f := EventFilter{
		Signal:   r.URL.Query().Get("signal"),
		Page:     queryInt(r, "page", 1),
		PageSize: queryInt(r, "page_size", 20),
	}
	if f.Signal != "" && !validSignals[f.Signal] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的信号类型")
		return
	}
	from, to, ok := parseTimeRange(w, r)
	if !ok {
		return
	}
	f.From, f.To = from, to

	if _, err := h.store.GetByID(r.Context(), id); err != nil {
		h.writeNotFound(w, r, err)
		return
	}
	list, total, err := h.store.ListEvents(r.Context(), id, f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// parseID 解析路径参数身份 ID。
func parseID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的身份ID")
		return uuid.Nil, false
	}
	return id, true
}

// writeNotFound 统一处理身份不存在（其余错误按内部错误处理，不泄露 SQL 细节）。
func (h *Handler) writeNotFound(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "身份不存在")
		return
	}
	response.InternalError(w, r, err)
}

// parseTimeRange 解析 from/to 查询参数（RFC3339；非法值 400；均缺省时返回 nil, nil）。
func parseTimeRange(w http.ResponseWriter, r *http.Request) (*time.Time, *time.Time, bool) {
	q := r.URL.Query()
	var from, to *time.Time
	if v := q.Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 from 时间（RFC3339）")
			return nil, nil, false
		}
		from = &t
	}
	if v := q.Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 to 时间（RFC3339）")
			return nil, nil, false
		}
		to = &t
	}
	return from, to, true
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
