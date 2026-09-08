package temporaryblocks

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// ReleaseEventEmitter 人工解封事件回调（由 app 层注入，避免与 accesscontrolevents 包循环依赖）。
type ReleaseEventEmitter func(ctx context.Context, b *Block)

// Handler 是临时封禁处理器。
type Handler struct {
	store          *Store
	audits         *audits.Service
	onReleaseEvent ReleaseEventEmitter // 可选：人工解封写 CC_TEMP_BLOCK_RELEASED
}

// NewHandler 创建临时封禁处理器。
func NewHandler(store *Store, au *audits.Service) *Handler {
	return &Handler{store: store, audits: au}
}

// SetReleaseEventEmitter 注入人工解封事件回调（M-24）。
func (h *Handler) SetReleaseEventEmitter(fn ReleaseEventEmitter) {
	h.onReleaseEvent = fn
}

// List 封禁列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f := ListFilter{
		Status:   r.URL.Query().Get("status"),
		ClientIP: r.URL.Query().Get("client_ip"),
		Page:     queryInt(r, "page", 1),
		PageSize: queryInt(r, "page_size", 20),
	}
	if f.Status != "" && !validStatus(f.Status) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的封禁状态")
		return
	}
	if appID := r.URL.Query().Get("application_id"); appID != "" {
		id, err := uuid.Parse(appID)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
			return
		}
		f.ApplicationID = &id
	}
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if list == nil {
		list = []Block{}
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Get 封禁详情。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的封禁ID")
		return
	}
	b, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "封禁记录不存在")
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"block": b})
}

// Release 人工解封。
func (h *Handler) Release(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的封禁ID")
		return
	}
	// 解封前取详情供事件写入
	before, _ := h.store.GetByID(r.Context(), id)
	if err := h.store.Release(r.Context(), id, p.UserID); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	if h.onReleaseEvent != nil && before != nil {
		h.onReleaseEvent(r.Context(), before)
	}
	h.recordAudit(r, p, "release", id.String(), "", audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "封禁已解除"})
}

type extendRequest struct {
	NewExpiresAt string `json:"new_expires_at"`
}

// Extend 延长封禁。
func (h *Handler) Extend(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的封禁ID")
		return
	}
	var req extendRequest
	if err := response.DecodeJSON(w, r, &req, 2048); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	newExpiresAt, err := time.Parse(time.RFC3339, req.NewExpiresAt)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "new_expires_at 必须为 RFC3339 时间格式")
		return
	}
	if err := h.store.Extend(r.Context(), id, newExpiresAt); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "extend", id.String(), newExpiresAt.UTC().Format(time.RFC3339), audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "封禁已延长"})
}

// ConvertToPermanent 转永久封禁（DENY 规则）。
func (h *Handler) ConvertToPermanent(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的封禁ID")
		return
	}
	rule, err := h.store.ConvertToPermanent(r.Context(), id, p.UserID)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "convert_to_permanent", id.String(), rule.ID.String(), audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"rule_id": rule.ID,
		"message": "已转换为永久封禁规则",
	})
}

func (h *Handler) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "封禁记录不存在")
	case errors.Is(err, ErrNotActive):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "封禁不在生效状态，无法执行该操作")
	case errors.Is(err, ErrInvalidExpiry):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
	case errors.Is(err, ErrConvertUnsupported):
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "访问控制规则服务未配置")
	default:
		response.InternalError(w, r, err)
	}
}

func validStatus(s string) bool {
	switch s {
	case StatusActive, StatusExpired, StatusManuallyReleased, StatusCancelled:
		return true
	}
	return false
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, result, risk string) {
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "temporary_blocks",
		Action:       action,
		ObjectType:   "temporary_block",
		ObjectID:     objID,
		ObjectName:   objName,
		Result:       result,
		RiskLevel:    risk,
		RequestID:    response.RequestIDFrom(r),
	})
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
