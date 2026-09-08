package protectedaddresses

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 是保护地址处理器。
type Handler struct {
	store  *Store
	audits *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(store *Store, auditSvc *audits.Service) *Handler {
	return &Handler{store: store, audits: auditSvc}
}

// List 保护地址分页列表（启用中，可按 address_type 筛选；page_size 上限 100）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	addressType := r.URL.Query().Get("address_type")
	page, pageSize := queryInt(r, "page", 1), queryPageSize(r, 20)
	list, total, err := h.store.ListPaged(r.Context(), addressType, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if list == nil {
		list = []ProtectedAddress{}
	}
	response.Page(w, r, list, total, page, pageSize)
}

type createAddressRequest struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	CIDR        string `json:"cidr"`
	Description string `json:"description"`
}

// Create 创建自定义保护地址（source_type=MANUAL，address_type=CUSTOM）。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req createAddressRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	a := &ProtectedAddress{
		Name:        req.Name,
		Address:     req.Address,
		CIDR:        req.CIDR,
		Description: req.Description,
		Status:      StatusEnabled,
	}
	if err := h.store.Create(r.Context(), a); err != nil {
		if errors.Is(err, ErrConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "相同地址的保护地址已存在")
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "create", a.ID.String(), a.Name, "", addressSummary(a), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"address": a})
}

// Delete 删除保护地址（仅 MANUAL 可删；尝试删除系统地址记录高风险失败审计）。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的保护地址ID")
		return
	}
	a, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "保护地址不存在")
		return
	}
	if err := h.store.Delete(r.Context(), id); err != nil {
		if errors.Is(err, ErrSystemProtected) {
			// 尝试删除系统保护地址：高风险失败审计
			h.recordAudit(r, p, "delete", id.String(), a.Name, addressSummary(a), "",
				audits.ResultFailure, audits.RiskHigh)
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "系统自动登记的保护地址不可删除")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", id.String(), a.Name, addressSummary(a), "", audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "保护地址已删除"})
}

// Refresh 自动登记系统保护地址（幂等）。
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	added, skipped, err := h.store.Refresh(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "refresh", "", "protected_addresses", "",
		fmt.Sprintf(`{"added":%d,"skipped":%d}`, added, skipped), audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"added":   added,
		"skipped": skipped,
	})
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, before, after, result, risk string) {
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "access_control",
		Action:        action,
		ObjectType:    "protected_address",
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        result,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

// addressSummary 生成审计摘要（JSON，敏感字段由审计服务统一脱敏）。
func addressSummary(a *ProtectedAddress) string {
	data, err := json.Marshal(map[string]interface{}{
		"name":         a.Name,
		"address":      a.Address,
		"cidr":         a.CIDR,
		"address_type": a.AddressType,
		"source_type":  a.SourceType,
		"status":       a.Status,
	})
	if err != nil {
		return ""
	}
	return string(data)
}

// queryPageSize 分页大小（夹取 ≤100，非法回退默认值；与兄弟包上限口径一致）。
func queryPageSize(r *http.Request, def int) int {
	n := queryInt(r, "page_size", def)
	if n > 100 {
		n = 100
	}
	return n
}

// queryInt 查询参数整型（正数，非法回退默认值）。
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
