// handler.go 攻击活动会话管理面接口（WDSP AI 自动化渗透防护增强 阶段4；设计 #25.3）。
// 路由（app.go 注册，权限点 attack_sessions.read）：
//
//	GET /api/v1/security/attack-sessions       会话分页列表（阶段/风险等级/状态/时间窗筛选）
//	GET /api/v1/security/attack-sessions/{id}  会话详情（{session, events:[...时间序]}）
package attacksessions

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 风险等级/状态合法值（查询筛选校验用；写侧由聚合器产生）。
var (
	validRiskLevels = map[string]bool{"LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}
	validStatuses   = map[string]bool{"OPEN": true, "CLOSED": true}
)

// Handler 攻击活动会话处理器。
type Handler struct {
	store *Store
}

// NewHandler 创建处理器。
func NewHandler(store *Store) *Handler {
	return &Handler{store: store}
}

// List 会话分页列表（attack_stage/risk_level/status/from/to 筛选，end_time DESC）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := ListFilter{
		Stage:     q.Get("stage"),
		RiskLevel: q.Get("risk_level"),
		Status:    q.Get("status"),
		Page:      queryInt(r, "page", 1),
		PageSize:  queryInt(r, "page_size", 20),
	}
	if f.Stage != "" && !validStages[f.Stage] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"无效的攻击阶段（RECON/DISCOVERY/AUTH_PROBE/AUTHORIZATION_PROBE/EXPLOIT/DATA_ACCESS/PERSISTENCE/UNKNOWN）")
		return
	}
	if f.RiskLevel != "" && !validRiskLevels[f.RiskLevel] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的风险等级（LOW/MEDIUM/HIGH/CRITICAL）")
		return
	}
	if f.Status != "" && !validStatuses[f.Status] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的会话状态（OPEN/CLOSED）")
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

// Get 会话详情（{session, events:[...occurred_at 时间序]}）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的会话ID")
		return
	}
	sess, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "攻击活动会话不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	events, err := h.store.ListEvents(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"session": sess,
		"events":  events,
	})
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
