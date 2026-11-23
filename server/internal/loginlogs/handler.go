package loginlogs

import (
	"net/http"
	"time"

	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/validation"
)

// Handler 是登录日志处理器。
type Handler struct {
	svc *Service
}

// NewHandler 创建处理器。
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func parseFilter(r *http.Request) ListFilter {
	f := ListFilter{
		Username:  r.URL.Query().Get("username"),
		SourceIP:  r.URL.Query().Get("source_ip"),
		Result:    r.URL.Query().Get("result"),
		EventType: r.URL.Query().Get("event_type"),
		RequestID: r.URL.Query().Get("request_id"),
		Page:      queryInt(r, "page", 1),
		PageSize:  queryInt(r, "page_size", 20),
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

// List 查询登录日志（审计管理员全部 / 普通用户仅自己）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	f := parseFilter(r)
	f.Page, f.PageSize = normalizePage(f.Page, f.PageSize, 100)
	// 无 login_logs.read 权限的用户只能看自己的日志
	if !p.HasPermission("login_logs.read") {
		f.UserID = &p.UserID
	}
	list, total, err := h.svc.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Export 导出登录日志（需 login_logs.export 权限，由路由控制；支持筛选导出与勾选 ids 导出）。
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
	w.Header().Set("Content-Disposition", `attachment; filename="login-logs.csv"`)
	_, _ = w.Write([]byte(csv))
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
