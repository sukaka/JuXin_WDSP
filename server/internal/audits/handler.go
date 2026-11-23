package audits

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/validation"
)

// Handler 是操作审计处理器。
type Handler struct {
	svc *Service
}

// NewHandler 创建处理器。
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func parseFilter(r *http.Request) ListFilter {
	f := ListFilter{
		Username:   r.URL.Query().Get("username"),
		SourceIP:   r.URL.Query().Get("source_ip"),
		Module:     r.URL.Query().Get("module"),
		Action:     r.URL.Query().Get("action"),
		ObjectType: r.URL.Query().Get("object_type"),
		Result:     r.URL.Query().Get("result"),
		RiskLevel:  r.URL.Query().Get("risk_level"),
		RequestID:  r.URL.Query().Get("request_id"),
		Page:       queryInt(r, "page", 1),
		PageSize:   queryInt(r, "page_size", 20),
	}
	if st := r.URL.Query().Get("start_time"); st != "" {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			f.StartTime = &t
		}
	}
	if et := r.URL.Query().Get("end_time"); et != "" {
		if t, err := time.Parse(time.RFC3339, et); err == nil {
			f.EndTime = &t
		}
	}
	return f
}

// List 查询操作审计。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f := parseFilter(r)
	list, total, err := h.svc.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Get 审计详情。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的审计ID")
		return
	}
	entry, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "审计记录不存在")
		return
	}
	response.JSON(w, r, http.StatusOK, entry)
}

// Export 导出审计（支持筛选导出与勾选 ids 导出）。
func (h *Handler) Export(w http.ResponseWriter, r *http.Request) {
	ids, err := validation.ParseExportUUIDs(r.URL.Query(), "ids")
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	f := parseFilter(r)
	f.IDs = ids
	csv, err := h.svc.Export(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="operation-audits.csv"`)
	_, _ = w.Write([]byte(csv))
}

// VerifyChain 校验审计哈希链完整性。
func (h *Handler) VerifyChain(w http.ResponseWriter, r *http.Request) {
	count, mismatches, err := h.svc.VerifyChain(r.Context(), 10000)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"valid":          count == 0,
		"mismatch_count": count,
		"mismatch_ids":   mismatches,
	})
}

// Modules 返回审计模块清单。
func (h *Handler) Modules(w http.ResponseWriter, r *http.Request) {
	mods, err := h.svc.DistinctModules(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": mods})
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if n <= 0 {
		return def
	}
	return n
}
