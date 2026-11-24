// Package apiassets API 接口资产管理（阶段8/WDSP 任务书 51.1 接口组 + 学习启停）。
package apiassets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

const (
	// LearningSettingGroup API 学习系统设置分组名（system_settings）。
	LearningSettingGroup = "api_learning"
	// LearningSettingAutoStartOnConfirm 确认正式资产时默认自动启动学习开关（迁移 000235，默认 false）。
	LearningSettingAutoStartOnConfirm = "auto_start_on_confirm"
)

// LearningSettingsReader API 学习策略设置只读接口（*settings.Service 实现；nil 时回落默认）。
type LearningSettingsReader interface {
	GetBool(ctx context.Context, group, key string, def bool) bool
}

// Handler API 接口管理。
type Handler struct {
	store            Repository
	audits           *audits.Service
	exportModels     ExportModelReader
	exportExtras     ExportExtrasProvider
	discoveryFilter  *DiscoveryFilterProvider
	learningSettings LearningSettingsReader
}

// NewHandler 创建处理器（构造注入审计服务，语义同 customrules）。
func NewHandler(store Repository, audit *audits.Service) *Handler {
	return &Handler{store: store, audits: audit}
}

// SetDiscoveryFilterProvider 注入发现过滤规则提供者（读写 system_settings 并共享运行期缓存）。
func (h *Handler) SetDiscoveryFilterProvider(p *DiscoveryFilterProvider) *Handler {
	h.discoveryFilter = p
	return h
}

// SetLearningSettingsReader 注入 API 学习策略设置读取器（读取 api_learning:auto_start_on_confirm）。
func (h *Handler) SetLearningSettingsReader(r LearningSettingsReader) *Handler {
	h.learningSettings = r
	return h
}

func (h *Handler) autoStartOnConfirm(ctx context.Context) bool {
	if h.learningSettings == nil {
		return false
	}
	return h.learningSettings.GetBool(ctx, LearningSettingGroup, LearningSettingAutoStartOnConfirm, false)
}

// RegisterRoutes 注册任务书 51.1 / 51.2 接口组（统一 /api/v1/api-security 前缀，
// 权限点与任务书五十二章一致）。exportMiddleware 可选，仅包裹两个导出路由。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler, exportMiddleware ...func(http.Handler) http.Handler) {
	limiter := func(next http.Handler) http.Handler { return next }
	if len(exportMiddleware) > 0 && exportMiddleware[0] != nil {
		limiter = exportMiddleware[0]
	}
	exportRoute := func(handler http.Handler) http.Handler {
		return authz(limiter(middleware.RequirePermission("api_asset.export")(handler)))
	}
	mux.Handle("GET /api/v1/api-security/discovery-filter", authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.GetDiscoveryFilter))))
	mux.Handle("PUT /api/v1/api-security/discovery-filter", authz(middleware.RequirePermission("api_asset.edit")(http.HandlerFunc(h.UpdateDiscoveryFilter))))
	mux.Handle("GET /api/v1/api-security/endpoints", authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.List))))
	mux.Handle("GET /api/v1/api-security/endpoints/export", exportRoute(http.HandlerFunc(h.ExportList)))
	mux.Handle("GET /api/v1/api-security/endpoints/site-summary", authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.SiteSummary))))
	mux.Handle("GET /api/v1/api-security/endpoints/directory-tree", authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.DirectoryTree))))
	mux.Handle("POST /api/v1/api-security/endpoints/confirm", authz(middleware.RequirePermission("api_asset.confirm")(http.HandlerFunc(h.ConfirmBatch))))
	mux.Handle("POST /api/v1/api-security/endpoints/ignore", authz(middleware.RequirePermission("api_asset.ignore")(http.HandlerFunc(h.IgnoreBatch))))
	mux.Handle("POST /api/v1/api-security/endpoints/learning/start", authz(middleware.RequirePermission("api_learning.start")(http.HandlerFunc(h.LearningStartBatch))))
	mux.Handle("GET /api/v1/api-security/endpoints/learning/options", authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.LearningOptions))))
	mux.Handle("POST /api/v1/api-security/endpoints/cleanup-noise/preview", authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.PreviewNoiseCleanup))))
	mux.Handle("POST /api/v1/api-security/endpoints/cleanup-noise", authz(middleware.RequirePermission("api_asset.ignore")(http.HandlerFunc(h.ExecuteNoiseCleanup))))
	mux.Handle("GET /api/v1/api-security/endpoints/{id}", authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.Get))))
	mux.Handle("GET /api/v1/api-security/endpoints/{id}/export", exportRoute(http.HandlerFunc(h.ExportDetail)))
	mux.Handle("GET /api/v1/api-security/endpoints/{id}/traffic-trend", authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.TrafficTrend))))
	mux.Handle("PATCH /api/v1/api-security/endpoints/{id}", authz(middleware.RequirePermission("api_asset.edit")(http.HandlerFunc(h.Update))))
	mux.Handle("POST /api/v1/api-security/endpoints/{id}/merge", authz(middleware.RequirePermission("api_asset.merge")(http.HandlerFunc(h.Merge))))
	mux.Handle("POST /api/v1/api-security/endpoints/{id}/split", authz(middleware.RequirePermission("api_asset.split")(http.HandlerFunc(h.Split))))
	mux.Handle("POST /api/v1/api-security/endpoints/{id}/ignore", authz(middleware.RequirePermission("api_asset.ignore")(http.HandlerFunc(h.Ignore))))
	mux.Handle("POST /api/v1/api-security/endpoints/{id}/classify", authz(middleware.RequirePermission("api_asset.edit")(http.HandlerFunc(h.Classify))))
	mux.Handle("POST /api/v1/api-security/endpoints/{id}/deprecate", authz(middleware.RequirePermission("api_asset.edit")(http.HandlerFunc(h.Deprecate))))
	mux.Handle("POST /api/v1/api-security/endpoints/{id}/restore", authz(middleware.RequirePermission("api_asset.edit")(http.HandlerFunc(h.Restore))))
	mux.Handle("GET /api/v1/api-security/service-assets", authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.ServiceAssets))))
	mux.Handle("GET /api/v1/api-security/applications/{id}/asset-value", authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.ApplicationAssetValue))))
	mux.Handle("POST /api/v1/api-security/endpoints/{id}/learning/start", authz(middleware.RequirePermission("api_learning.start")(http.HandlerFunc(h.LearningStart))))
	mux.Handle("POST /api/v1/api-security/endpoints/{id}/learning/stop", authz(middleware.RequirePermission("api_learning.stop")(http.HandlerFunc(h.LearningStop))))
	mux.Handle("GET /api/v1/api-security/endpoints/{id}/learning/status", authz(middleware.RequirePermission("api_learning.read")(http.HandlerFunc(h.LearningStatus))))
	mux.Handle("GET /api/v1/api-security/endpoints/{id}/learning/samples", authz(middleware.RequirePermission("api_learning.read")(http.HandlerFunc(h.LearningSamples))))
	mux.Handle("GET /api/v1/api-security/endpoints/{id}/lifecycle-events", authz(middleware.RequirePermission("api_asset.read")(http.HandlerFunc(h.LifecycleEvents))))
}

// List GET /api/v1/api-security/endpoints
// 过滤：asset_status / learning_status / keyword / application_id / unassigned / directory_path / business_type。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := ListFilter{
		AssetStatus:     strings.ToUpper(strings.TrimSpace(q.Get("asset_status"))),
		LearningStatus:  strings.ToUpper(strings.TrimSpace(q.Get("learning_status"))),
		Keyword:         strings.TrimSpace(q.Get("keyword")),
		DirectoryPrefix: strings.TrimSpace(q.Get("directory_path")),
		Unassigned:      q.Get("unassigned") == "true",
		IncludeNonAPI:   q.Get("include_non_api") == "true",
		Page:            queryInt(r, "page", 1),
		PageSize:        queryInt(r, "page_size", 20),
	}
	if v := strings.TrimSpace(q.Get("application_id")); v != "" {
		appID, err := uuid.Parse(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的application_id")
			return
		}
		f.ApplicationID = &appID
	}
	if v := strings.TrimSpace(q.Get("business_type")); v != "" {
		bt := NormalizeBusinessType(v)
		if !validBusinessTypes[bt] {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				"无效的业务类型（LOGIN/REGISTER/PASSWORD_RESET/SMS/EMAIL/ORDER/PAYMENT/EXPORT/DOWNLOAD/SEARCH/QUERY_PERSONAL_DATA/AI_INFERENCE/OTHER）")
			return
		}
		f.BusinessType = bt
	}
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// SiteSummary GET /api/v1/api-security/endpoints/site-summary
// 各站点接口计数 + 未归属计数（站点列表数据源）。
func (h *Handler) SiteSummary(w http.ResponseWriter, r *http.Request) {
	items, unassigned, err := h.store.SiteSummary(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": items, "unassigned": unassigned})
}

// DirectoryTree GET /api/v1/api-security/endpoints/directory-tree
// 按目录聚合接口计数（扁平列表，前端组装层级）；application_id 指定站点，unassigned=true 查未归属。
func (h *Handler) DirectoryTree(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var appID *uuid.UUID
	if v := strings.TrimSpace(q.Get("application_id")); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的application_id")
			return
		}
		appID = &id
	}
	items, err := h.store.DirectoryTree(r.Context(), appID, q.Get("unassigned") == "true")
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": items})
}

// ConfirmBatch POST /api/v1/api-security/endpoints/confirm
// {ids:[...], auto_start_learning?: bool, sample_target?: int}
// 批量确认 asset_status=CONFIRMED；可选联动自动启动模型学习（需具备 api_learning.start 权限，
// 缺省遵循系统设置 api_learning:auto_start_on_confirm，学习中或已完成学习的接口自动跳过）。
func (h *Handler) ConfirmBatch(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req struct {
		IDs               []uuid.UUID `json:"ids"`
		AutoStartLearning *bool       `json:"auto_start_learning"`
		SampleTarget      *int        `json:"sample_target"`
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
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "单次最多确认 100 个接口")
		return
	}
	sampleTarget := 0
	if req.SampleTarget != nil {
		if *req.SampleTarget < MinSampleTarget || *req.SampleTarget > MaxSampleTarget {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				fmt.Sprintf("样本目标需在 %d~%d 之间", MinSampleTarget, MaxSampleTarget))
			return
		}
		sampleTarget = *req.SampleTarget
	}
	shouldAutoStart := false
	if req.AutoStartLearning != nil {
		if *req.AutoStartLearning {
			if p == nil || !p.HasPermission("api_learning.start") {
				response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied,
					"权限不足，无法在确认时自动启动学习（需要 api_learning.start）")
				return
			}
			shouldAutoStart = true
		}
	} else if h.autoStartOnConfirm(r.Context()) && p != nil && p.HasPermission("api_learning.start") {
		shouldAutoStart = true
	}

	ids := dedupUUIDs(req.IDs)
	var createdBy *uuid.UUID
	if p != nil {
		uid := p.UserID
		createdBy = &uid
	}
	type failedItem struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	}
	confirmed := []string{}
	failed := []failedItem{}
	learningStarted := []string{}
	learningSkipped := []string{}
	learningFailed := []failedItem{}
	for _, id := range ids {
		ep, err := h.store.Confirm(r.Context(), id)
		if errors.Is(err, ErrNotFound) {
			failed = append(failed, failedItem{ID: id.String(), Reason: "接口不存在"})
			continue
		}
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		confirmed = append(confirmed, id.String())
		if !shouldAutoStart {
			continue
		}
		// 学习中或已完成学习的接口自动跳过，避免覆盖/重复启动已有学习成果
		if ep != nil && (ep.LearningStatus == "LEARNING" || ep.LearningStatus == "LEARNED") {
			learningSkipped = append(learningSkipped, id.String())
			continue
		}
		_, startErr := h.store.StartLearning(r.Context(), id, sampleTarget, createdBy)
		if errors.Is(startErr, ErrLearningRunning) {
			learningSkipped = append(learningSkipped, id.String())
			continue
		}
		if startErr != nil {
			slog.Warn("auto start learning after confirm failed", "endpoint_id", id, "error", startErr)
			learningFailed = append(learningFailed, failedItem{ID: id.String(), Reason: "自动启动学习失败"})
			continue
		}
		learningStarted = append(learningStarted, id.String())
	}
	objID := ""
	if len(ids) > 0 {
		objID = ids[0].String()
	}
	afterMap := map[string]any{
		"confirmed":           len(confirmed),
		"failed":              len(failed),
		"auto_start_learning": shouldAutoStart,
		"learning_started":    len(learningStarted),
		"learning_skipped":    len(learningSkipped),
		"learning_failed":     len(learningFailed),
	}
	if shouldAutoStart {
		effectiveTarget := sampleTarget
		if effectiveTarget == 0 {
			effectiveTarget = DefaultSampleTarget
		}
		afterMap["sample_target"] = effectiveTarget
	}
	h.recordAudit(r, p, "confirm", objID, fmt.Sprintf("批量确认 %d 个接口", len(ids)),
		summaryJSON(map[string]any{"ids": ids, "auto_start_learning": shouldAutoStart}),
		summaryJSON(afterMap), audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"confirmed":            len(confirmed),
		"confirmed_ids":        confirmed,
		"failed":               failed,
		"learning_started":     len(learningStarted),
		"learning_started_ids": learningStarted,
		"learning_skipped":     len(learningSkipped),
		"learning_skipped_ids": learningSkipped,
		"learning_failed":      learningFailed,
	})
}

// LearningOptions GET /api/v1/api-security/endpoints/learning/options
// 返回前端确认弹窗与批量启动学习所需的非敏感学习默认选项（权限：api_asset.read）。
func (h *Handler) LearningOptions(w http.ResponseWriter, r *http.Request) {
	response.JSON(w, r, http.StatusOK, map[string]any{
		"auto_start_on_confirm": h.autoStartOnConfirm(r.Context()),
		"default_sample_target": DefaultSampleTarget,
		"min_sample_target":     MinSampleTarget,
		"max_sample_target":     MaxSampleTarget,
	})
}

const (
	// learningBatchMaxIDs 手工勾选 IDs 批量启动学习单次上限。
	learningBatchMaxIDs = 100
	// learningBatchMaxFiltered 按筛选条件批量启动学习单次最大处理数（防误操作引发超大任务风暴）。
	learningBatchMaxFiltered = 2000
	// learningBatchPageSize 后端分页拉取筛选命中的页大小（对齐 Store.List 上限 100）。
	learningBatchPageSize = 100
)

type learningBatchFilterRequest struct {
	AssetStatus     string `json:"asset_status"`
	LearningStatus  string `json:"learning_status"`
	Keyword         string `json:"keyword"`
	ApplicationID   string `json:"application_id"`
	Unassigned      bool   `json:"unassigned"`
	DirectoryPrefix string `json:"directory_path"`
	BusinessType    string `json:"business_type"`
}

func parseLearningBatchFilter(in *learningBatchFilterRequest) (ListFilter, error) {
	f := ListFilter{
		Page:     1,
		PageSize: learningBatchPageSize,
	}
	if in == nil {
		return f, nil
	}
	f.AssetStatus = strings.ToUpper(strings.TrimSpace(in.AssetStatus))
	f.LearningStatus = strings.ToUpper(strings.TrimSpace(in.LearningStatus))
	f.Keyword = strings.TrimSpace(in.Keyword)
	f.DirectoryPrefix = strings.TrimSpace(in.DirectoryPrefix)
	f.Unassigned = in.Unassigned
	if v := strings.TrimSpace(in.ApplicationID); v != "" {
		appID, err := uuid.Parse(v)
		if err != nil {
			return ListFilter{}, fmt.Errorf("无效的application_id")
		}
		f.ApplicationID = &appID
	}
	if v := strings.TrimSpace(in.BusinessType); v != "" {
		bt := NormalizeBusinessType(v)
		if !validBusinessTypes[bt] {
			return ListFilter{}, fmt.Errorf("无效的业务类型")
		}
		f.BusinessType = bt
	}
	return f, nil
}

// LearningStartBatch POST /api/v1/api-security/endpoints/learning/start
// 支持两种模式（权限：api_learning.start）：
//  1. 指定勾选 IDs：{ids:[...], sample_target?: int}（单次最多 100 个，已在学习中的自动跳过）；
//  2. 按当前筛选条件：{apply_to_filtered: true, filter?: {...}, sample_target?: int}
//     （后端分页收集全部命中接口，单次最多处理 2000 个；自动跳过学习中、非活跃资产及未显式筛选的已完成接口）。
func (h *Handler) LearningStartBatch(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req struct {
		IDs             []uuid.UUID                 `json:"ids"`
		ApplyToFiltered bool                        `json:"apply_to_filtered"`
		Filter          *learningBatchFilterRequest `json:"filter"`
		SampleTarget    *int                        `json:"sample_target"`
	}
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.ApplyToFiltered && len(req.IDs) > 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "ids 与 apply_to_filtered 不能同时指定")
		return
	}
	if !req.ApplyToFiltered {
		if len(req.IDs) == 0 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "ids 不能为空")
			return
		}
		if len(req.IDs) > learningBatchMaxIDs {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				fmt.Sprintf("单次最多启动 %d 个接口学习", learningBatchMaxIDs))
			return
		}
	}
	sampleTarget := 0
	if req.SampleTarget != nil {
		if *req.SampleTarget < MinSampleTarget || *req.SampleTarget > MaxSampleTarget {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				fmt.Sprintf("样本目标需在 %d~%d 之间", MinSampleTarget, MaxSampleTarget))
			return
		}
		sampleTarget = *req.SampleTarget
	}
	effectiveTarget := sampleTarget
	if effectiveTarget == 0 {
		effectiveTarget = DefaultSampleTarget
	}
	var createdBy *uuid.UUID
	if p != nil {
		uid := p.UserID
		createdBy = &uid
	}
	type failedItem struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	}
	started := []string{}
	skipped := []string{}
	failed := []failedItem{}

	if req.ApplyToFiltered {
		filter, err := parseLearningBatchFilter(req.Filter)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
		// 先完整分页收集命中快照再逐个启动，避免启动学习改变 learning_status 引发翻页偏移漏项。
		var candidates []Endpoint
		seen := make(map[uuid.UUID]struct{})
		var matchedTotal int64
		truncated := false
		for {
			list, total, listErr := h.store.List(r.Context(), filter)
			if listErr != nil {
				response.InternalError(w, r, listErr)
				return
			}
			if filter.Page == 1 {
				matchedTotal = total
			}
			for _, ep := range list {
				if _, dup := seen[ep.ID]; dup {
					continue
				}
				seen[ep.ID] = struct{}{}
				candidates = append(candidates, ep)
				if len(candidates) >= learningBatchMaxFiltered {
					break
				}
			}
			if len(candidates) >= learningBatchMaxFiltered {
				if matchedTotal > int64(learningBatchMaxFiltered) {
					truncated = true
				}
				break
			}
			if int64(filter.Page*filter.PageSize) >= total || len(list) == 0 {
				break
			}
			filter.Page++
		}
		for _, ep := range candidates {
			// 按筛选批量启动时，始终跳过非活跃资产（已忽略/已下线/僵尸）与学习中接口；
			// 已完成学习的接口仅在用户显式筛选 learning_status=LEARNED 时重新学习，否则自动跳过。
			if ep.AssetStatus == "IGNORED" || ep.AssetStatus == "DEPRECATED" || ep.AssetStatus == "ZOMBIE" {
				skipped = append(skipped, ep.ID.String())
				continue
			}
			if ep.LearningStatus == "LEARNING" {
				skipped = append(skipped, ep.ID.String())
				continue
			}
			if ep.LearningStatus == "LEARNED" && filter.LearningStatus != "LEARNED" {
				skipped = append(skipped, ep.ID.String())
				continue
			}
			_, startErr := h.store.StartLearning(r.Context(), ep.ID, sampleTarget, createdBy)
			if errors.Is(startErr, ErrNotFound) {
				failed = append(failed, failedItem{ID: ep.ID.String(), Reason: "接口不存在"})
				continue
			}
			if errors.Is(startErr, ErrLearningRunning) {
				skipped = append(skipped, ep.ID.String())
				continue
			}
			if startErr != nil {
				response.InternalError(w, r, startErr)
				return
			}
			started = append(started, ep.ID.String())
		}
		h.recordAudit(r, p, "learning_start_batch", "",
			fmt.Sprintf("按筛选批量启动学习（命中 %d 个接口）", matchedTotal),
			summaryJSON(map[string]any{
				"apply_to_filtered": true,
				"filter":            req.Filter,
				"sample_target":     effectiveTarget,
			}),
			summaryJSON(map[string]any{
				"matched_total": matchedTotal,
				"truncated":     truncated,
				"started":       len(started),
				"skipped":       len(skipped),
				"failed":        len(failed),
				"sample_target": effectiveTarget,
			}), audits.RiskLow)
		response.JSON(w, r, http.StatusOK, map[string]any{
			"started":       len(started),
			"started_ids":   started,
			"skipped":       len(skipped),
			"skipped_ids":   skipped,
			"failed":        failed,
			"matched_total": matchedTotal,
			"truncated":     truncated,
			"sample_target": effectiveTarget,
			"message":       formatFilteredLearningStartMessage(matchedTotal, len(started), len(skipped), len(failed), truncated),
		})
		return
	}

	ids := dedupUUIDs(req.IDs)
	for _, id := range ids {
		_, err := h.store.StartLearning(r.Context(), id, sampleTarget, createdBy)
		if errors.Is(err, ErrNotFound) {
			failed = append(failed, failedItem{ID: id.String(), Reason: "接口不存在"})
			continue
		}
		if errors.Is(err, ErrLearningRunning) {
			skipped = append(skipped, id.String())
			continue
		}
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		started = append(started, id.String())
	}
	objID := ""
	if len(ids) > 0 {
		objID = ids[0].String()
	}
	h.recordAudit(r, p, "learning_start_batch", objID, fmt.Sprintf("批量启动学习 %d 个接口", len(ids)),
		summaryJSON(map[string]any{"ids": ids, "sample_target": effectiveTarget}),
		summaryJSON(map[string]any{
			"started":       len(started),
			"skipped":       len(skipped),
			"failed":        len(failed),
			"sample_target": effectiveTarget,
		}), audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"started":       len(started),
		"started_ids":   started,
		"skipped":       len(skipped),
		"skipped_ids":   skipped,
		"failed":        failed,
		"matched_total": len(ids),
		"truncated":     false,
		"sample_target": effectiveTarget,
		"message":       formatBatchLearningStartMessage(len(started), len(skipped), len(failed)),
	})
}

func formatFilteredLearningStartMessage(matchedTotal int64, started, skipped, failed int, truncated bool) string {
	if matchedTotal == 0 {
		return "当前筛选条件下无可启动学习的接口"
	}
	if started == 0 && skipped > 0 && failed == 0 {
		return fmt.Sprintf("当前筛选命中的 %d 个接口均已在学习中、已完成或为非活跃资产，已自动跳过", skipped)
	}
	parts := make([]string, 0, 3)
	if started > 0 {
		parts = append(parts, fmt.Sprintf("已批量启动 %d 个接口学习", started))
	}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("跳过 %d 个（学习中/已完成/非活跃）", skipped))
	}
	if failed > 0 {
		parts = append(parts, fmt.Sprintf("%d 个失败", failed))
	}
	msg := strings.Join(parts, "，")
	if msg == "" {
		msg = "未启动任何学习任务"
	}
	if truncated {
		msg += fmt.Sprintf("（筛选共命中 %d 个，单次上限处理 %d 个）", matchedTotal, learningBatchMaxFiltered)
	}
	return msg
}

func dedupUUIDs(in []uuid.UUID) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(in))
	seen := make(map[uuid.UUID]struct{}, len(in))
	for _, id := range in {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func formatBatchLearningStartMessage(started, skipped, failed int) string {
	if started > 0 && skipped == 0 && failed == 0 {
		return fmt.Sprintf("已批量启动 %d 个接口学习", started)
	}
	if started == 0 && skipped > 0 && failed == 0 {
		return fmt.Sprintf("所选 %d 个接口均已在学习中，已自动跳过", skipped)
	}
	parts := make([]string, 0, 3)
	if started > 0 {
		parts = append(parts, fmt.Sprintf("已启动 %d 个", started))
	}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("跳过 %d 个（学习中）", skipped))
	}
	if failed > 0 {
		parts = append(parts, fmt.Sprintf("%d 个失败", failed))
	}
	if len(parts) == 0 {
		return "未启动任何学习任务"
	}
	return strings.Join(parts, "，")
}

// Get GET /api/v1/api-security/endpoints/{id}（含 api_assets 扩展字段与近 7 天日均调用量）
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	e, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	asset, err := h.store.GetAsset(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	e.Asset = asset
	if asset != nil {
		e.BusinessType = asset.BusinessType
		e.Tags = asset.Tags
	}
	now := time.Now().UTC()
	buckets, err := h.store.TrafficBuckets(r.Context(), id, now.Add(-valueTrafficWindowDays*24*time.Hour), now)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	var windowTotal int64
	for _, c := range buckets {
		windowTotal += c
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"endpoint": e, "daily_requests": windowTotal / valueTrafficWindowDays,
	})
}

// TrafficTrend GET /api/v1/api-security/endpoints/{id}/traffic-trend?range=1h|24h|7d
// 单接口访问趋势波形图数据源：5 分钟桶（UTC 对齐），服务端补零、时间升序；
// range 缺省 24h，非法值取默认；端点不存在 404。
func (h *Handler) TrafficTrend(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	if _, err := h.store.GetByID(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	rangeName, dur := ParseTrafficRange(r.URL.Query().Get("range"))
	now := time.Now().UTC()
	from := now.Add(-dur)
	counts, err := h.store.TrafficBuckets(r.Context(), id, from, TrafficBucketStart(now).Add(TrafficBucketSeconds*time.Second))
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	points, total := FillTrafficPoints(from, now, counts)
	response.JSON(w, r, http.StatusOK, &TrafficTrend{
		EndpointID:    id.String(),
		BucketSeconds: TrafficBucketSeconds,
		Range:         rangeName,
		Total:         total,
		Points:        points,
	})
}

// Update PATCH /api/v1/api-security/endpoints/{id}
// 编辑 api_assets 资产档案（AssetProfile 全量替换；枚举应用层校验，设计 #12.1 + 迁移 000191）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Purpose        string   `json:"purpose"`
		Exposure       string   `json:"exposure"`
		Owner          string   `json:"owner"`
		Tags           []string `json:"tags"`
		BusinessType   string   `json:"business_type"`
		Organization   string   `json:"organization"`
		BusinessSystem string   `json:"business_system"`
		TechnicalOwner string   `json:"technical_owner"`
		DataOwner      string   `json:"data_owner"`
		DataLevel      string   `json:"data_level"`
		APILevel       string   `json:"api_level"`
		AuthType       string   `json:"auth_type"`
	}
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	req.Purpose = strings.TrimSpace(req.Purpose)
	req.Owner = strings.TrimSpace(req.Owner)
	req.Organization = strings.TrimSpace(req.Organization)
	req.BusinessSystem = strings.TrimSpace(req.BusinessSystem)
	req.TechnicalOwner = strings.TrimSpace(req.TechnicalOwner)
	req.DataOwner = strings.TrimSpace(req.DataOwner)
	req.Exposure = strings.ToUpper(strings.TrimSpace(req.Exposure))
	req.BusinessType = NormalizeBusinessType(req.BusinessType)
	if req.Purpose == "" && req.Exposure == "" && req.Owner == "" && req.Tags == nil && req.BusinessType == "OTHER" &&
		req.Organization == "" && req.BusinessSystem == "" && req.TechnicalOwner == "" && req.DataOwner == "" &&
		req.DataLevel == "" && req.APILevel == "" && req.AuthType == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体不能为空")
		return
	}
	switch req.Exposure {
	case "", "INTERNAL", "PARTNER", "PUBLIC":
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的暴露面取值（INTERNAL/PARTNER/PUBLIC）")
		return
	}
	if !validBusinessTypes[req.BusinessType] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"无效的业务类型（LOGIN/REGISTER/PASSWORD_RESET/SMS/EMAIL/ORDER/PAYMENT/EXPORT/DOWNLOAD/SEARCH/QUERY_PERSONAL_DATA/AI_INFERENCE/OTHER）")
		return
	}
	for _, v := range []string{req.Purpose, req.Owner, req.Organization, req.BusinessSystem, req.TechnicalOwner, req.DataOwner} {
		if len(v) > 128 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "档案文本字段长度不能超过 128")
			return
		}
	}
	if len(req.Tags) > 32 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "标签数量不能超过 32")
		return
	}
	for _, t := range req.Tags {
		if len(strings.TrimSpace(t)) == 0 || len(t) > 64 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "标签不能为空且长度不能超过 64")
			return
		}
	}
	profile, err := normalizeAssetProfile(AssetProfile{
		Purpose: req.Purpose, Exposure: req.Exposure, Owner: req.Owner, Tags: req.Tags, BusinessType: req.BusinessType,
		Organization: req.Organization, BusinessSystem: req.BusinessSystem,
		TechnicalOwner: req.TechnicalOwner, DataOwner: req.DataOwner,
		DataLevel: req.DataLevel, APILevel: req.APILevel, AuthType: req.AuthType,
	})
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	e, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	before, err := h.store.GetAsset(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	asset, err := h.store.UpsertAsset(r.Context(), id, profile)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "edit", id.String(), truncateName(e.EndpointKey),
		assetSummary(before), assetSummary(asset), audits.RiskMedium)
	e.Asset = asset
	if asset != nil {
		e.BusinessType = asset.BusinessType
		e.Tags = asset.Tags
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"endpoint": e, "message": "资产信息已更新"})
}

// Merge POST /api/v1/api-security/endpoints/{id}/merge  {other_id}
func (h *Handler) Merge(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	var req struct {
		OtherID uuid.UUID `json:"other_id"`
	}
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.OtherID == uuid.Nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "other_id 不能为空")
		return
	}
	if req.OtherID == id {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "不能将接口合并到自身")
		return
	}
	other, err := h.store.GetByID(r.Context(), req.OtherID)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "待合并接口不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	before, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	merged, err := h.store.Merge(r.Context(), id, req.OtherID, actorOf(p))
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "merge", id.String(), truncateName(merged.EndpointKey),
		summaryJSON(map[string]any{"endpoint_key": before.EndpointKey, "hit_count": before.HitCount,
			"other_id": req.OtherID.String(), "other_key": other.EndpointKey}),
		summaryJSON(map[string]any{"endpoint_key": merged.EndpointKey, "hit_count": merged.HitCount}),
		audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]any{"endpoint": merged, "message": "接口已合并"})
}

// Split POST /api/v1/api-security/endpoints/{id}/split  {paths:[...]}
func (h *Handler) Split(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Paths []string `json:"paths"`
	}
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if len(req.Paths) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "拆分路径不能为空")
		return
	}
	if len(req.Paths) > 50 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "单次最多拆分 50 个路径")
		return
	}
	normed := make([]string, 0, len(req.Paths))
	for _, raw := range req.Paths {
		if strings.TrimSpace(raw) == "" {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "拆分路径不能为空")
			return
		}
		normed = append(normed, normalizer.NormalizePath(raw))
	}
	src, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	created, err := h.store.Split(r.Context(), id, normed, actorOf(p))
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if errors.Is(err, ErrEndpointConflict) {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
		return
	}
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "split", id.String(), truncateName(src.EndpointKey),
		summaryJSON(map[string]any{"endpoint_key": src.EndpointKey}),
		summaryJSON(map[string]any{"paths": normed, "created": len(created)}), audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"endpoints": created, "message": "接口已拆分"})
}

// Ignore POST /api/v1/api-security/endpoints/{id}/ignore（asset_status=IGNORED）
func (h *Handler) Ignore(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	e, err := h.store.SetAssetStatus(r.Context(), id, "IGNORED", actorOf(p))
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "ignore", id.String(), truncateName(e.EndpointKey),
		summaryJSON(map[string]any{"asset_status": before.AssetStatus}),
		summaryJSON(map[string]any{"asset_status": e.AssetStatus}), audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"endpoint": e, "message": "接口已忽略"})
}

// Deprecate POST /api/v1/api-security/endpoints/{id}/deprecate
// 人工下线（DISCOVERED/CONFIRMED→DEPRECATED，任务书 §11.3）；状态不允许 409。
func (h *Handler) Deprecate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	e, err := h.store.Deprecate(r.Context(), id, actorOf(p))
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if errors.Is(err, ErrInvalidTransition) {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "deprecate", id.String(), truncateName(e.EndpointKey),
		summaryJSON(map[string]any{"asset_status": before.AssetStatus}),
		summaryJSON(map[string]any{"asset_status": e.AssetStatus}), audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"endpoint": e, "message": "接口已标记下线"})
}

// Restore POST /api/v1/api-security/endpoints/{id}/restore
// 人工恢复（DEPRECATED/ZOMBIE→CONFIRMED）；状态不允许 409。
func (h *Handler) Restore(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	e, err := h.store.Restore(r.Context(), id, actorOf(p))
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if errors.Is(err, ErrInvalidTransition) {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "restore", id.String(), truncateName(e.EndpointKey),
		summaryJSON(map[string]any{"asset_status": before.AssetStatus}),
		summaryJSON(map[string]any{"asset_status": e.AssetStatus}), audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"endpoint": e, "message": "接口已恢复为已确认"})
}

// ServiceAssets GET /api/v1/api-security/service-assets
// 服务资产聚合（§14）：upstreams 主机:端口 视角反聚端点归属，分页返回。
func (h *Handler) ServiceAssets(w http.ResponseWriter, r *http.Request) {
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	items, total, err := h.store.ListServiceAssets(r.Context(), page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, items, total, page, pageSize)
}

// Classify POST /api/v1/api-security/endpoints/{id}/classify
// 按路径/方法启发式自动分类（含 §34 操作动作 ACTION 与业务领域 BUSINESS_DOMAIN 维度），
// 写 api_classification_dimensions（source=AUTO）。
func (h *Handler) Classify(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	e, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	dims, err := h.store.AutoClassify(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if errors.Is(err, ErrClassificationLocked) {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "分类已锁定，请先解锁后再执行自动分类")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "classify", id.String(), truncateName(e.EndpointKey), "",
		summaryJSON(map[string]any{"dimensions": dims}), audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{"dimensions": dims, "message": "自动分类完成"})
}

// LearningStart POST /api/v1/api-security/endpoints/{id}/learning/start
// 可选请求体 {"sample_target": N}：N∈[10,100000]，缺省 100；0 或越界 400。无请求体按缺省。
func (h *Handler) LearningStart(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	// 可选请求体：缺省（无体或无字段）由 store 归一为 DefaultSampleTarget
	sampleTarget := 0
	if r.Body != nil && r.ContentLength != 0 {
		var req struct {
			SampleTarget *int `json:"sample_target"`
		}
		if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
			return
		}
		if req.SampleTarget != nil {
			if *req.SampleTarget < MinSampleTarget || *req.SampleTarget > MaxSampleTarget {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
					fmt.Sprintf("样本目标需在 %d~%d 之间", MinSampleTarget, MaxSampleTarget))
				return
			}
			sampleTarget = *req.SampleTarget
		}
	}
	var createdBy *uuid.UUID
	if p != nil {
		uid := p.UserID
		createdBy = &uid
	}
	job, err := h.store.StartLearning(r.Context(), id, sampleTarget, createdBy)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if errors.Is(err, ErrLearningRunning) {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "该接口已有运行中的学习任务")
		return
	}
	if errors.Is(err, ErrInvalidSampleTarget) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("样本目标需在 %d~%d 之间", MinSampleTarget, MaxSampleTarget))
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "learning_start", id.String(), id.String(), "",
		summaryJSON(map[string]any{"job_id": job.ID.String(), "status": job.Status, "sample_target": job.SampleTarget}), audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{"job": job, "message": "学习任务已启动"})
}

// LearningStop POST /api/v1/api-security/endpoints/{id}/learning/stop
func (h *Handler) LearningStop(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	job, err := h.store.StopLearning(r.Context(), id, actorOf(p))
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if errors.Is(err, ErrLearningNotRunning) {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "当前没有运行中的学习任务")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "learning_stop", id.String(), id.String(), "",
		summaryJSON(map[string]any{"job_id": job.ID.String(), "status": job.Status}), audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]any{"job": job, "message": "学习任务已停止"})
}

// LearningStatus GET /api/v1/api-security/endpoints/{id}/learning/status
func (h *Handler) LearningStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	e, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	job, stats, err := h.store.LearningStatus(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"endpoint_id":     id,
		"learning_status": e.LearningStatus,
		"job":             job,
		"samples":         stats,
	})
}

// LifecycleEvents GET /api/v1/api-security/endpoints/{id}/lifecycle-events
// api_lifecycle_events 按 created_at DESC 分页。
func (h *Handler) LifecycleEvents(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	if _, err := h.store.GetByID(r.Context(), id); errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	} else if err != nil {
		response.InternalError(w, r, err)
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListLifecycleEvents(r.Context(), id, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// LearningSamples GET /api/v1/api-security/endpoints/{id}/learning/samples
// api_learning_samples 过滤 accepted（true/false，可空）+ 分页。
func (h *Handler) LearningSamples(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	if _, err := h.store.GetByID(r.Context(), id); errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	} else if err != nil {
		response.InternalError(w, r, err)
		return
	}
	var accepted *bool
	if v := strings.TrimSpace(r.URL.Query().Get("accepted")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 accepted 取值（true/false）")
			return
		}
		accepted = &b
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListLearningSamples(r.Context(), id, accepted, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// recordAudit 写操作审计（语义同 customrules：操作者/动作/对象/前后摘要/风险等级）。
// 审计服务未注入（旧接线）或无操作者上下文时跳过，不影响主流程。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, before, after, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_assets",
		Action:        action,
		ObjectType:    "api_endpoint",
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        audits.ResultSuccess,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

func parsePathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的接口ID")
		return uuid.Nil, false
	}
	return id, true
}

func actorOf(p *authz.Principal) string {
	if p == nil || p.Username == "" {
		return "system"
	}
	return p.Username
}

// summaryJSON 生成审计摘要（合法 JSON 对象，交给审计层脱敏）。
func summaryJSON(v map[string]any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// assetSummary 资产扩展摘要；无记录时返回空。
func assetSummary(a *Asset) string {
	if a == nil {
		return ""
	}
	return summaryJSON(map[string]any{
		"purpose": a.Purpose, "exposure": a.Exposure,
		"owner": a.Owner, "tags": a.Tags,
		"business_type": a.BusinessType,
		"organization":  a.Organization, "business_system": a.BusinessSystem,
		"technical_owner": a.TechnicalOwner, "data_owner": a.DataOwner,
		"data_level": a.DataLevel, "api_level": a.APILevel, "auth_type": a.AuthType,
	})
}

// truncateName 审计 object_name 列上限 255。
func truncateName(s string) string {
	if len(s) > 255 {
		return s[:255]
	}
	return s
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
