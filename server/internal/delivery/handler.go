// handler.go 交付检查接口：List/Run/Get/Export。
package delivery

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 交付检查处理器。
type Handler struct {
	store   *Store
	service *Service
	audits  *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(store *Store, svc *Service, au *audits.Service) *Handler {
	return &Handler{store: store, service: svc, audits: au}
}

// RegisterRoutes 注册交付检查路由。authChain 为认证链（会话解析+认证+CSRF）。
func (h *Handler) RegisterRoutes(mux *http.ServeMux, authChain func(http.Handler) http.Handler) {
	read := middleware.RequirePermission("delivery_checks.read")
	mux.Handle("GET /api/v1/delivery-checks", authChain(read(http.HandlerFunc(h.List))))
	mux.Handle("POST /api/v1/delivery-checks/run", authChain(middleware.RequirePermission("delivery_checks.run")(http.HandlerFunc(h.Run))))
	mux.Handle("GET /api/v1/delivery-checks/{id}", authChain(read(http.HandlerFunc(h.Get))))
	mux.Handle("GET /api/v1/delivery-checks/{id}/export", authChain(read(http.HandlerFunc(h.Export))))
}

// List 检查执行记录列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListRuns(r.Context(), page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// Run 执行交付检查。
func (h *Handler) Run(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	run, items, err := h.service.Run(r.Context(), p.UserID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "run", run.ID.String(), run.Overall, audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"check":   run,
		"results": items,
	})
}

// Get 检查详情（含结果明细）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	run, items, ok := h.loadRun(w, r)
	if !ok {
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"check":   run,
		"results": items,
	})
}

// Export 导出检查结果（format=json|csv，默认 json）。
func (h *Handler) Export(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	run, items, ok := h.loadRun(w, r)
	if !ok {
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	h.recordAudit(r, p, "export", run.ID.String(), run.Overall, audits.ResultSuccess, audits.RiskLow)
	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="delivery-check-%s.json"`, run.ID))
		response.JSON(w, r, http.StatusOK, map[string]interface{}{
			"check":   run,
			"results": items,
		})
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="delivery-check-%s.csv"`, run.ID))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(exportCSV(items)))
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的导出格式（json/csv）")
	}
}

// loadRun 解析路径ID并加载检查与明细。
func (h *Handler) loadRun(w http.ResponseWriter, r *http.Request) (*CheckRun, []ItemResult, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的检查ID")
		return nil, nil, false
	}
	run, err := h.store.GetRun(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "交付检查记录不存在")
			return nil, nil, false
		}
		response.InternalError(w, r, err)
		return nil, nil, false
	}
	items, err := h.store.ListResults(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return nil, nil, false
	}
	return run, items, true
}

const exportCSVUTF8BOM = "\xef\xbb\xbf"

const exportCSVHeader = "检查项标识,检查项名称,分类,是否关键项,检查结果,说明\n"

// exportCSV 结果明细转 CSV（含 UTF-8 BOM、中文表头与枚举/布尔中文化、防公式注入）。
func exportCSV(items []ItemResult) string {
	var b strings.Builder
	b.WriteString(exportCSVUTF8BOM)
	b.WriteString(exportCSVHeader)
	for _, it := range items {
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s\n",
			csvEscape(it.Key), csvEscape(it.Name), csvEscape(it.Category),
			csvEscape(exportCriticalLabel(it.Critical)),
			csvEscape(exportResultLabel(it.Result)),
			csvEscape(it.Message))
	}
	return b.String()
}

func exportCriticalLabel(critical bool) string {
	if critical {
		return "是"
	}
	return "否"
}

func exportResultLabel(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "":
		return ""
	case ResultPass:
		return "通过"
	case ResultWarning:
		return "警告"
	case ResultFail:
		return "失败"
	case ResultNA:
		return "不适用"
	default:
		return v
	}
}

// csvEscape CSV 字段转义：=、+、-、@、\t、\r 开头前加 ' 防公式注入；
// 含逗号/引号/换行的字段加双引号并双写内部引号。
func csvEscape(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		s = "'" + s
	}
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

// recordAudit 写入操作审计。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, result, risk string) {
	if err := h.audits.Record(r.Context(), audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "delivery",
		Action:       action,
		ObjectType:   "delivery_check",
		ObjectID:     objID,
		ObjectName:   objName,
		Result:       result,
		RiskLevel:    risk,
		RequestID:    response.RequestIDFrom(r),
	}); err != nil {
		slog.Error("record delivery audit failed", "action", action, "object_id", objID, "error", err)
	}
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
