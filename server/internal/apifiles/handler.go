// handler.go 文件资产 HTTP 处理器：
//
//	GET /api/v1/api-security/file-assets        明细分页（过滤 direction/mime/extension/endpoint/时间窗）
//	GET /api/v1/api-security/file-assets/stats  §106 统计（上下行计数/敏感文件数/File/IP/Account/API TOP）
//
// 只读接口，权限点 api_data.read（种子迁移 000041，与 apigeo 同一权限域）。
package apifiles

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/jiuzhang-waf/server/internal/apidata"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 明细分页页大小上限（防过宽拉取）。
const assetPageSizeMax = 100

// Handler 文件资产处理器。
type Handler struct {
	store Repository
}

// NewHandler 创建处理器。
func NewHandler(store Repository) *Handler {
	return &Handler{store: store}
}

// RegisterRoutes 注册路由（统一 /api/v1/api-security 前缀；权限点 api_data.read）。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/file-assets",
		authz(middleware.RequirePermission(apidata.PermDataRead)(http.HandlerFunc(h.ListAssets))))
	mux.Handle("GET /api/v1/api-security/file-assets/stats",
		authz(middleware.RequirePermission(apidata.PermDataRead)(http.HandlerFunc(h.Stats))))
}

// ListAssets GET /api/v1/api-security/file-assets
// 查询参数：direction（UPLOAD/DOWNLOAD）/mime/extension/endpoint_key 精确过滤，
// sensitive_only=true 仅敏感文件；days（窗口，默认 7 上限 30，按 last_seen 口径）；
// page/page_size 分页。
func (h *Handler) ListAssets(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseAssetFilter(w, r)
	if !ok {
		return
	}
	assets, total, err := h.store.ListAssets(r.Context(), filter)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, response.PageData{
		Items:    assets,
		Page:     filter.Page,
		PageSize: filter.PageSize,
		Total:    total,
	})
}

// Stats GET /api/v1/api-security/file-assets/stats
// 查询参数：days（窗口，默认 7 上限 30）。
func (h *Handler) Stats(w http.ResponseWriter, r *http.Request) {
	days := clampDays(queryInt(r, "days", ListDefaultDays))
	stats, err := h.store.Stats(r.Context(), days)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, stats)
}

// parseAssetFilter 解析并校验列表查询参数（非法枚举/超长键 400，与白名单纪律一致）。
func parseAssetFilter(w http.ResponseWriter, r *http.Request) (AssetFilter, bool) {
	q := r.URL.Query()
	direction := strings.ToUpper(strings.TrimSpace(q.Get("direction")))
	if direction != "" && !validDirection(direction) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 direction 取值（UPLOAD/DOWNLOAD）")
		return AssetFilter{}, false
	}
	mimeType := strings.ToLower(strings.TrimSpace(q.Get("mime")))
	if len(mimeType) > 128 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "mime 长度不能超过 128")
		return AssetFilter{}, false
	}
	extension := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(q.Get("extension"), ".")))
	if len(extension) > 16 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "extension 长度不能超过 16")
		return AssetFilter{}, false
	}
	endpointKey := strings.TrimSpace(q.Get("endpoint_key"))
	if len(endpointKey) > 560 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "endpoint_key 长度不能超过 560")
		return AssetFilter{}, false
	}
	sensitiveOnly := false
	if v := strings.TrimSpace(q.Get("sensitive_only")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 sensitive_only 取值（true/false）")
			return AssetFilter{}, false
		}
		sensitiveOnly = b
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	if pageSize > assetPageSizeMax {
		pageSize = assetPageSizeMax
	}
	return AssetFilter{
		Days:          clampDays(queryInt(r, "days", ListDefaultDays)),
		Direction:     direction,
		MIME:          mimeType,
		Extension:     extension,
		EndpointKey:   endpointKey,
		SensitiveOnly: sensitiveOnly,
		Page:          page,
		PageSize:      pageSize,
	}, true
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
