package vulnrefs

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/validation"
)

// Handler 是漏洞档案处理器。读权限沿用 waf_rules.read，写权限 waf_rule.vuln_ref.edit
// （路由层中间件约束，见 app.go）。
type Handler struct {
	store  *Store
	audits *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(store *Store, au *audits.Service) *Handler {
	return &Handler{store: store, audits: au}
}

// List 档案分页列表（含 rule_count/event_count_30d 交叉计数）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	keyword := strings.TrimSpace(r.URL.Query().Get("keyword"))
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	items, total, err := h.store.List(r.Context(), keyword, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, items, total, page, pageSize)
}

type refRequest struct {
	CNNVDID     string  `json:"cnnvd_id"`
	CVEID       string  `json:"cve_id"`
	Title       string  `json:"title"`
	Severity    string  `json:"severity"`
	PublishedAt *string `json:"published_at"`
	URL         string  `json:"url"`
}

// validateRefRequest 校验并归一档案字段（编号大写归一；published_at 仅接受 YYYY-MM-DD）。
func validateRefRequest(req *refRequest, requireCNNVD bool) (*Ref, string) {
	ref := &Ref{}
	var err error
	if requireCNNVD || strings.TrimSpace(req.CNNVDID) != "" {
		ref.CNNVDID, err = validation.ValidateCNNVDID(req.CNNVDID)
		if err != nil {
			return nil, err.Error()
		}
	}
	ref.CVEID, err = validation.ValidateCVEID(req.CVEID)
	if err != nil {
		return nil, err.Error()
	}
	ref.Title = strings.TrimSpace(req.Title)
	if len([]rune(ref.Title)) > 512 {
		return nil, "规范名称不超过 512 字符"
	}
	ref.Severity = strings.TrimSpace(req.Severity)
	if len([]rune(ref.Severity)) > 16 {
		return nil, "危害级别不超过 16 字符"
	}
	if req.PublishedAt != nil && strings.TrimSpace(*req.PublishedAt) != "" {
		d := strings.TrimSpace(*req.PublishedAt)
		if _, perr := time.Parse("2006-01-02", d); perr != nil {
			return nil, "发布日期必须是 YYYY-MM-DD 格式"
		}
		ref.PublishedAt = &d
	}
	ref.URL = strings.TrimSpace(req.URL)
	if len(ref.URL) > 1024 {
		return nil, "官方链接不超过 1024 字符"
	}
	if ref.URL != "" && !strings.HasPrefix(ref.URL, "https://") && !strings.HasPrefix(ref.URL, "http://") {
		return nil, "官方链接必须是 http/https 地址"
	}
	return ref, ""
}

// Create 录入档案。重复 cnnvd_id 返回 409，格式非法 400。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req refRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	ref, msg := validateRefRequest(&req, true)
	if ref == nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return
	}
	if err := h.store.Create(r.Context(), ref); err != nil {
		if err == ErrConflict {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "该 CNNVD 编号的档案已存在")
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "create", ref.ID.String(), ref.CNNVDID, audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, ref)
}

// Get 档案详情：条目 + 关联规则 + 近 30 天事件计数与样例（认证演示核心交叉查询）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	cnnvdID, err := validation.ValidateCNNVDID(r.PathValue("cnnvd_id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	d, err := h.store.Detail(r.Context(), cnnvdID)
	if err != nil {
		if err == ErrNotFound {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "漏洞档案不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, d)
}

// Update 更新档案（cnnvd_id 为路径键不可改；body 携带且不一致返回 400）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	cnnvdID, err := validation.ValidateCNNVDID(r.PathValue("cnnvd_id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	var req refRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	ref, msg := validateRefRequest(&req, false)
	if ref == nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return
	}
	if ref.CNNVDID != "" && ref.CNNVDID != cnnvdID {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "CNNVD 编号不可修改")
		return
	}
	ref.CNNVDID = cnnvdID
	if err := h.store.Update(r.Context(), ref); err != nil {
		if err == ErrNotFound {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "漏洞档案不存在")
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "update", cnnvdID, cnnvdID, audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "档案已更新"})
}

// Delete 删除档案。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	cnnvdID, err := validation.ValidateCNNVDID(r.PathValue("cnnvd_id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := h.store.Delete(r.Context(), cnnvdID); err != nil {
		if err == ErrNotFound {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "漏洞档案不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", cnnvdID, cnnvdID, audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "档案已删除"})
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName string, result, risk string) {
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "vuln_refs",
		Action:       action,
		ObjectType:   "vuln_ref",
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
