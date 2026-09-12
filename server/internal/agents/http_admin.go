// http_admin.go HTTP 事件管理端点（Phase 3，契约 §6；会话 + RBAC view，统一信封）：
//
//	GET /api/v1/traffic/agents/{agent_id}/http-events       分页（page/page_size/host/method，ts 倒序）
//	GET /api/v1/traffic/agents/{agent_id}/http-events/{id}  单条全量（含 headers/body）
//
// 响应记录为契约 §3 嵌套结构（+顶层 id/agent_id——勘误 2026-09，见契约 §6 附注）：
// 列表项保持轻量（headers 置空对象、body 置空串，截断/原始长度标志如实保留），
// 详情给全量；response 未捕获时 "response": null 且 response_ts/latency_ms 为 null。
package agents

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/jiuzhang-waf/server/internal/response"
)

// ListHTTPEvents GET /api/v1/traffic/agents/{agent_id}/http-events（view）。
// host/method 为精确过滤（大小写不敏感）；分页参数非法回落默认（同其他列表端点）。
func (h *Handler) ListHTTPEvents(w http.ResponseWriter, r *http.Request) {
	id, ok := parseAgentID(w, r)
	if !ok {
		return
	}
	if _, err := h.store.GetAgent(r.Context(), id); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	f := HTTPEventFilter{
		Host:   strings.TrimSpace(r.URL.Query().Get("host")),
		Method: strings.TrimSpace(r.URL.Query().Get("method")),
		Page:   ParsePageParams(r.URL.Query().Get),
	}
	rows, total, err := h.store.ListHTTPEvents(r.Context(), id, f)
	if err != nil {
		h.adminInternal(w, r, err)
		return
	}
	items := make([]*HTTPEventJSON, 0, len(rows))
	for i := range rows {
		items = append(items, rows[i].ToNestedJSON(false))
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": items, "total": total})
}

// GetHTTPEvent GET /api/v1/traffic/agents/{agent_id}/http-events/{id}（view，全量）。
func (h *Handler) GetHTTPEvent(w http.ResponseWriter, r *http.Request) {
	id, ok := parseAgentID(w, r)
	if !ok {
		return
	}
	eventID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || eventID <= 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "id 非法")
		return
	}
	row, err := h.store.GetHTTPEvent(r.Context(), id, eventID)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, row.ToNestedJSON(true))
}
