// handler.go 威胁情报导入 HTTP 接口（WDSP P2-C1）。
// 路由（app.go 注册）：
//
//	POST /api/v1/threat-intel/import  对账导入情报快照（权限 access_rules.import；
//	  CSRF 与审计同 accessrules 写接口规格；导入生效集变化时触发网关配置发布）
package threatintel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// PublishFunc 发布触发函数（app 装配注入 gatewayconfig.Publisher.Publish；nil = 发布通道不可用）。
type PublishFunc func(ctx context.Context, uid uuid.UUID, requestID string)

// Handler 是威胁情报导入处理器。
type Handler struct {
	svc        *Service
	reconciler Reconciler
	audits     *audits.Service
	publish    PublishFunc
	feedStore  FeedRepository
}

// NewHandler 创建处理器。
func NewHandler(svc *Service, au *audits.Service) *Handler {
	var rec Reconciler
	if svc != nil {
		rec = svc
	}
	return &Handler{svc: svc, reconciler: rec, audits: au}
}

// SetPublishFunc 注入发布触发函数（publisher 不可用时保持 nil：规则落库成功但不下发，
// 与装配层其他策略同一口径——发布通道恢复后任意发布动作即带上最新规则集）。
func (h *Handler) SetPublishFunc(fn PublishFunc) { h.publish = fn }

// SetFeedStore 注入可选的多源订阅仓储：非 nil 时离线快照导入自动记入
// threat_intel_sync_runs（OFFLINE_IMPORT）并在对应订阅源存在时刷新 active_rule_count。
func (h *Handler) SetFeedStore(repo FeedRepository) { h.feedStore = repo }

// importRequest 是对账导入请求体。
type importRequest struct {
	Format  string `json:"format"`   // text | csv（缺省 text）
	Content string `json:"content"`  // 情报快照内容（≤1MB）
	TTLDays *int   `json:"ttl_days"` // 有效期天数（缺省 30；0=永久）
	Feed    string `json:"feed"`     // 情报源名（缺省 feodo）
}

// Import 对账导入威胁情报（Feodo C2 → IP 黑名单）。
func (h *Handler) Import(w http.ResponseWriter, r *http.Request) {
	startedAt := time.Now().UTC()
	p := authz.PrincipalFrom(r.Context())
	var req importRequest
	if err := response.DecodeJSON(w, r, &req, MaxContentBytes+128*1024); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误或内容过大")
		return
	}
	if len(req.Content) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "导入内容不能为空")
		return
	}
	if len(req.Content) > MaxContentBytes {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "导入内容超过 1MB 上限")
		return
	}
	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format == "" {
		format = "text"
	}
	if format != "text" && format != "csv" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("无效的导入格式: %s（支持 text / csv）", req.Format))
		return
	}
	ttl := DefaultTTLDays
	if req.TTLDays != nil {
		ttl = *req.TTLDays
	}
	in := ImportInput{Feed: req.Feed, TTLDays: ttl, Operator: p.UserID}
	if err := ValidateInput(&in); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}

	var matchedFeed *Feed
	parseOpts := ParseOptions{AllowCIDR: false}
	if h.feedStore != nil {
		if f, ferr := h.feedStore.GetFeedByKey(r.Context(), in.Feed); ferr == nil && f != nil {
			matchedFeed = f
			parseOpts.AllowCIDR = f.AllowCIDR
		}
	}

	var parsed *ParseResult
	var perr error
	if format == "csv" {
		parsed, perr = ParseCSVWithOptions(req.Content, parseOpts)
	} else {
		parsed = ParseTextWithOptions(req.Content, parseOpts)
	}
	if perr != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, perr.Error())
		return
	}
	in.Entries = parsed.Entries

	result, err := h.reconciler.Import(r.Context(), in)
	if err != nil {
		if errors.Is(err, ErrInvalidInput) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
		response.InternalError(w, r, err)
		return
	}

	// 生效集有变化时触发网关配置发布（异步任务，触发失败仅记日志——规则已落库，
	// 与 behaviorpolicy/riskpolicy 策略变更同一口径）
	published := false
	if h.publish != nil && result.Added+result.Refreshed+result.Expired > 0 {
		h.publish(r.Context(), p.UserID, response.RequestIDFrom(r))
		published = true
	}

	h.recordOfflineImportRun(r.Context(), matchedFeed, p, result, parsed, published, startedAt)
	h.recordAudit(r, p, result, parsed)

	errs := parsed.Errors
	if errs == nil {
		errs = []RowError{}
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"batch_id":         result.BatchID,
		"feed":             result.Feed,
		"ttl_days":         result.TTLDays,
		"total_parsed":     len(parsed.Entries),
		"added":            result.Added,
		"refreshed":        result.Refreshed,
		"expired":          result.Expired,
		"skipped_conflict": result.SkippedConflict,
		"invalid":          parsed.ErrorTotal,
		"truncated":        parsed.Truncated,
		"conflicts":        result.Conflicts,
		"invalid_entries":  errs,
	})
}

func (h *Handler) recordOfflineImportRun(
	ctx context.Context,
	matchedFeed *Feed,
	p *authz.Principal,
	res *Result,
	parsed *ParseResult,
	published bool,
	startedAt time.Time,
) {
	if h.feedStore == nil || res == nil || parsed == nil {
		return
	}
	finishedAt := time.Now().UTC()
	var opID *uuid.UUID
	if p != nil && p.UserID != uuid.Nil {
		id := p.UserID
		opID = &id
	}
	if err := h.feedStore.InsertRun(ctx, &SyncRun{
		FeedKey:         res.Feed,
		TriggerType:     TriggerOfflineImport,
		BatchID:         res.BatchID,
		Status:          RunStatusSuccess,
		TotalParsed:     len(parsed.Entries),
		Added:           res.Added,
		Refreshed:       res.Refreshed,
		Expired:         res.Expired,
		SkippedConflict: res.SkippedConflict,
		InvalidCount:    parsed.ErrorTotal,
		Published:       published,
		OperatorID:      opID,
		StartedAt:       startedAt,
		FinishedAt:      finishedAt,
	}); err != nil {
		slog.Warn("record threat intel offline import run failed", "feed", res.Feed, "error", err)
	}
	if matchedFeed != nil {
		activeCount, cntErr := h.feedStore.CountActiveFeedRules(ctx, res.Feed)
		if cntErr != nil {
			activeCount = maxInt(0, matchedFeed.ActiveRuleCount+res.Added-res.Expired)
		}
		if err := h.feedStore.UpdateFeedSyncResult(ctx, FeedSyncUpdate{
			ID:                 matchedFeed.ID,
			UpdateCacheHeaders: false,
			ActiveRuleCount:    activeCount,
			UpdateActiveCount:  true,
			UpdateCircuit:      false,
			LastSyncAt:         finishedAt,
			LastStatus:         RunStatusSuccess,
			LastError:          "",
			UpdatedBy:          opID,
		}); err != nil {
			slog.Warn("refresh threat intel feed active_rule_count failed", "feed", res.Feed, "error", err)
		}
	}
}

// recordAudit 记录导入审计（成功口径；格式与 accessrules 导入一致：计数 JSON 摘要）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, res *Result, parsed *ParseResult) {
	if h.audits == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "access_control",
		Action:       "threat_intel_import",
		ObjectType:   "ip_access_rule",
		ObjectID:     res.BatchID,
		ObjectName:   "威胁情报导入（" + res.Feed + "）",
		AfterSummary: fmt.Sprintf(
			`{"batch_id":"%s","feed":"%s","ttl_days":%d,"parsed":%d,"added":%d,"refreshed":%d,"expired":%d,"skipped_conflict":%d,"invalid":%d}`,
			res.BatchID, res.Feed, res.TTLDays, len(parsed.Entries),
			res.Added, res.Refreshed, res.Expired, res.SkippedConflict, parsed.ErrorTotal),
		Result:    audits.ResultSuccess,
		RiskLevel: audits.RiskMedium,
		RequestID: response.RequestIDFrom(r),
	})
}
