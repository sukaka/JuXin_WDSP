// asset_sources_admin.go 资产来源关系管理端点（v2 契约 §5；任务书 P1-03 §4.2）：
//
//	GET /api/v1/traffic/agents/{agent_id}/http-asset-sources  分页（state 精确过滤，
//	    last_seen_at 倒序）——配额拒绝（QUOTA_REJECTED）/未绑定（UNASSIGNED）/
//	    关联失败（FAILED）均可查询，不只 Warn
//
// 会话 + RBAC traffic.agents.view，统一信封（同 http_admin.go 既有口径）。
package agents

import (
	"net/http"
	"strings"

	"github.com/jiuzhang-waf/server/internal/response"
)

// ListHTTPAssetSources GET /api/v1/traffic/agents/{agent_id}/http-asset-sources（view）。
func (h *Handler) ListHTTPAssetSources(w http.ResponseWriter, r *http.Request) {
	id, ok := parseAgentID(w, r)
	if !ok {
		return
	}
	if _, err := h.store.GetAgent(r.Context(), id); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	switch state {
	case "", AssetLinkLinked, AssetLinkUnassigned, AssetLinkQuotaRejected, AssetLinkFailed:
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"state 须为 LINKED/UNASSIGNED/QUOTA_REJECTED/FAILED 之一")
		return
	}
	rows, total, err := h.store.ListHTTPAssetSources(r.Context(), id, HTTPAssetSourceFilter{
		State: state,
		Page:  ParsePageParams(r.URL.Query().Get),
	})
	if err != nil {
		h.adminInternal(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": rows, "total": total})
}
