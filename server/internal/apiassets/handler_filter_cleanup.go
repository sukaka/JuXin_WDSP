// handler_filter_cleanup.go API 资产发现过滤规则、批量忽略与存量噪声清理管理接口。
package apiassets

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/classifier"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

func (h *Handler) effectiveDiscoveryFilter(r *http.Request) (DiscoveryFilterConfig, error) {
	if h.discoveryFilter == nil {
		return DefaultDiscoveryFilterConfig(), nil
	}
	return h.discoveryFilter.LoadStrict(r.Context())
}

// GetDiscoveryFilter GET /api/v1/api-security/discovery-filter
// 返回当前生效的静态资源与非 API 过滤规则，以及内置默认扩展名参考清单。
func (h *Handler) GetDiscoveryFilter(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.effectiveDiscoveryFilter(r)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"config":             cfg,
		"default_extensions": classifier.DefaultStaticAssetExtensions(),
	})
}

// UpdateDiscoveryFilter PUT /api/v1/api-security/discovery-filter
// 保存静态资源与非 API 过滤规则并立即刷新采集链路共享缓存。
func (h *Handler) UpdateDiscoveryFilter(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req DiscoveryFilterConfig
	if err := response.DecodeJSON(w, r, &req, 32768); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	before, err := h.effectiveDiscoveryFilter(r)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	var opID uuid.UUID
	if p != nil {
		opID = p.UserID
	}
	var saved DiscoveryFilterConfig
	if h.discoveryFilter != nil {
		saved, err = h.discoveryFilter.Save(r.Context(), req, opID)
	} else {
		saved, err = NormalizeAndValidateDiscoveryFilter(req)
	}
	if err != nil {
		// 校验错误按 400 返回，数据库错误按 500 返回
		if _, verr := NormalizeAndValidateDiscoveryFilter(req); verr != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, verr.Error())
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update_discovery_filter", DiscoveryFilterSettingGroup+":"+DiscoveryFilterSettingKey,
		"API发现过滤规则",
		summaryJSON(map[string]any{
			"exclude_static_assets": before.ExcludeStaticAssets,
			"filter_non_api":        before.FilterNonAPI,
			"exclude_extensions":    len(before.ExcludeExtensions),
			"exclude_path_prefixes": before.ExcludePathPrefixes,
			"include_path_prefixes": before.IncludePathPrefixes,
		}),
		summaryJSON(map[string]any{
			"exclude_static_assets": saved.ExcludeStaticAssets,
			"filter_non_api":        saved.FilterNonAPI,
			"exclude_extensions":    len(saved.ExcludeExtensions),
			"exclude_path_prefixes": saved.ExcludePathPrefixes,
			"include_path_prefixes": saved.IncludePathPrefixes,
		}),
		audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"config":  saved,
		"message": "发现过滤规则已保存并立即生效",
	})
}

// IgnoreBatch POST /api/v1/api-security/endpoints/ignore  {ids:[...]}
// 批量忽略 asset_status=IGNORED（单次最多 100 个，与 ConfirmBatch 对称）。
func (h *Handler) IgnoreBatch(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req struct {
		IDs []uuid.UUID `json:"ids"`
	}
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if len(req.IDs) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "ids 不能为空")
		return
	}
	if len(req.IDs) > 100 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "单次最多忽略 100 个接口")
		return
	}
	type failedItem struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	}
	ignored := []string{}
	failed := []failedItem{}
	actor := actorOf(p)
	for _, id := range req.IDs {
		_, err := h.store.SetAssetStatus(r.Context(), id, "IGNORED", actor)
		if errors.Is(err, ErrNotFound) {
			failed = append(failed, failedItem{ID: id.String(), Reason: "接口不存在"})
			continue
		}
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		ignored = append(ignored, id.String())
	}
	objID := req.IDs[0].String()
	h.recordAudit(r, p, "ignore_batch", objID, fmt.Sprintf("批量忽略 %d 个接口", len(req.IDs)),
		summaryJSON(map[string]any{"ids": req.IDs}),
		summaryJSON(map[string]any{"ignored": len(ignored), "failed": len(failed)}), audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"ignored":     len(ignored),
		"ignored_ids": ignored,
		"failed":      failed,
	})
}

type noiseCleanupRequest struct {
	ApplicationID  string      `json:"application_id"`
	IncludeIgnored *bool       `json:"include_ignored"`
	Limit          int         `json:"limit"`
	Action         string      `json:"action"`
	IDs            []uuid.UUID `json:"ids"`
}

func parseNoiseCleanupFilter(req noiseCleanupRequest) (NoiseCleanupFilter, error) {
	f := NoiseCleanupFilter{
		IncludeIgnored: true, // 默认一并纳入历史已忽略的静态垃圾以便彻底释放配额
		Limit:          req.Limit,
		IDs:            req.IDs,
	}
	if req.IncludeIgnored != nil {
		f.IncludeIgnored = *req.IncludeIgnored
	}
	if v := strings.TrimSpace(req.ApplicationID); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return NoiseCleanupFilter{}, fmt.Errorf("无效的 application_id")
		}
		f.ApplicationID = &id
	}
	if len(f.IDs) > 1000 {
		return NoiseCleanupFilter{}, fmt.Errorf("单次指定清理的 ids 不能超过 1000 个")
	}
	return f, nil
}

// PreviewNoiseCleanup POST /api/v1/api-security/endpoints/cleanup-noise/preview
// 扫描可安全清理的静态资源与非 API 噪声端点（严格跳过已确认/学习中/已建模/已绑定策略端点）。
func (h *Handler) PreviewNoiseCleanup(w http.ResponseWriter, r *http.Request) {
	var req noiseCleanupRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := response.DecodeJSON(w, r, &req, 65536); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
			return
		}
	}
	f, err := parseNoiseCleanupFilter(req)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	cfg, err := h.effectiveDiscoveryFilter(r)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	preview, err := h.store.PreviewNoiseCleanup(r.Context(), cfg, f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, preview)
}

// ExecuteNoiseCleanup POST /api/v1/api-security/endpoints/cleanup-noise
// 执行存量静态资源与非 API 噪声清理（DELETE 删除释放配额 或 IGNORE 批量忽略），全程审计。
func (h *Handler) ExecuteNoiseCleanup(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req noiseCleanupRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := response.DecodeJSON(w, r, &req, 65536); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
			return
		}
	}
	f, err := parseNoiseCleanupFilter(req)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	act, err := normalizeCleanupAction(req.Action)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	cfg, err := h.effectiveDiscoveryFilter(r)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	res, err := h.store.ExecuteNoiseCleanup(r.Context(), cfg, f, act, actorOf(p))
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	risk := audits.RiskMedium
	msg := fmt.Sprintf("已批量忽略 %d 条非 API / 静态噪声端点", res.Affected)
	if act == NoiseCleanupActionDelete {
		risk = audits.RiskHigh
		msg = fmt.Sprintf("已清理删除 %d 条非 API / 静态噪声端点", res.Affected)
	}
	h.recordAudit(r, p, "cleanup_noise", strings.TrimSpace(req.ApplicationID), msg,
		summaryJSON(map[string]any{
			"action":          act,
			"application_id":  req.ApplicationID,
			"include_ignored": f.IncludeIgnored,
			"ids_count":       len(f.IDs),
		}),
		summaryJSON(map[string]any{
			"affected":          res.Affected,
			"protected_skipped": res.ProtectedSkipped,
			"by_reason":         res.ByReason,
			"sample_keys":       res.SampleKeys,
		}),
		risk)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"result":  res,
		"message": msg,
	})
}
