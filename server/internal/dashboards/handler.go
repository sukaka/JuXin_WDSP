// handler.go 态势首页 HTTP 接口（只读）。
package dashboards

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/metrics"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 态势首页处理器。
type Handler struct {
	store *Store
}

// NewHandler 创建态势首页处理器。
func NewHandler(aggStore *aggregations.Store, db *pgxpool.Pool) *Handler {
	return &Handler{store: NewStore(db, aggStore)}
}

// SetCache 设置 Valkey 客户端（可选，用于运行态势存储采集）。
func (h *Handler) SetCache(c *cache.Client) { h.store.SetCache(c) }

// ---------- 安全态势 ----------

// SecurityTrendData 安全态势趋势（times 与各序列等长对齐）。
type SecurityTrendData struct {
	Start       time.Time            `json:"start"`
	End         time.Time            `json:"end"`
	StepSeconds int64                `json:"step_seconds"`
	Times       []time.Time          `json:"times"`
	Requests    []float64            `json:"requests"`
	Events      []float64            `json:"security_events"`
	Blocks      []float64            `json:"blocks"`
	Observes    []float64            `json:"observes"`
	CCExceeded  []float64            `json:"cc_exceeded"`
	IPDeny      []float64            `json:"ip_deny"`
	RiskLevels  map[string][]float64 `json:"risk_levels"`
	Disposition map[string][]float64 `json:"disposition"`
}

// TopData 排行区。
type TopData struct {
	AttackTypes  []KV           `json:"attack_types"`
	SourceIPs    []SourceIPStat `json:"source_ips"`
	Applications []KV           `json:"applications"`
	Rules        []KV           `json:"rules"`
	URIs         []URIStat      `json:"uris"`
}

// RiskData 风险区。
type RiskData struct {
	HighUnprocessedEvents []EventSummary       `json:"high_unprocessed_events"`
	FailedPublishTasks    []PublishTaskSummary `json:"failed_publish_tasks"`
	GatewayIssues         []ComponentIssue     `json:"gateway_issues"`
	CollectorLag          *CollectorLag        `json:"collector_lag"`
}

// SecurityOverviewData 安全态势首页数据。
type SecurityOverviewData struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Range       string             `json:"range"`
	Today       *TodayCounters     `json:"today"`
	Trends      *SecurityTrendData `json:"trends"`
	Top         *TopData           `json:"top"`
	Risks       *RiskData          `json:"risks"`
}

// SecurityOverview GET /api/v1/dashboard/security-overview
func (h *Handler) SecurityOverview(w http.ResponseWriter, r *http.Request) {
	rangeName := r.URL.Query().Get("range")
	if rangeName == "" {
		rangeName = "24h"
	}
	d, err := ParseTrendRange(rangeName)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	ctx := r.Context()
	now := time.Now().UTC()
	start := now.Add(-d)
	table := AggTableFor(d)
	step := TrendStep(d)
	buckets := BucketTimes(start, now, step)
	dayStart, _ := TodayWindowUTC(now)

	out := &SecurityOverviewData{GeneratedAt: now, Range: rangeName}

	// 今日计数
	today, err := h.store.TodayCounters(ctx, dayStart, now)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	out.Today = today

	// 趋势
	trends := &SecurityTrendData{
		Start: start, End: now, StepSeconds: int64(step / time.Second), Times: buckets,
		RiskLevels: map[string][]float64{}, Disposition: map[string][]float64{},
	}
	simple := []struct {
		metric string
		dst    *[]float64
	}{
		{metrics.HTTPRequestsTotal, &trends.Requests},
		{metrics.WAFEventsTotal, &trends.Events},
		{metrics.WAFBlocksTotal, &trends.Blocks},
		{metrics.WAFObserveTotal, &trends.Observes},
		{metrics.CCExceededTotal, &trends.CCExceeded},
		{metrics.IPDenyMatchesTotal, &trends.IPDeny},
	}
	for _, it := range simple {
		times, values, err := h.store.metricSeries(ctx, table, it.metric, start, now)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		*it.dst = SeriesInto(buckets, times, values, step)
	}
	sev, err := h.store.severitySeries(ctx, table, start, now)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	trends.RiskLevels = SeriesMapInto(buckets, sev, step)
	disp, err := h.store.dispositionSeries(ctx, start, now, StepTrunc(step))
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	trends.Disposition = SeriesMapInto(buckets, disp, step)
	out.Trends = trends

	// 排行
	attackTypes, err := h.store.TopAttackTypes(ctx, table, start, now, 5)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	sourceIPs, err := h.store.TopSourceIPs(ctx, start, now, 10)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	apps, err := h.store.TopApplications(ctx, table, start, now, 5)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	rules, err := h.store.TopRules(ctx, table, start, now, 10)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	uris, err := h.store.TopURIs(ctx, start, now, 10)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	out.Top = &TopData{
		AttackTypes: attackTypes, SourceIPs: sourceIPs,
		Applications: apps, Rules: rules, URIs: uris,
	}

	// 风险
	highEvents, err := h.store.RecentHighUnprocessed(ctx, 10)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	failedPublishes, err := h.store.RecentFailedPublishes(ctx, 5)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	issues, err := h.store.ComponentIssues(ctx)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	lag, err := h.store.CollectorLag(ctx)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	out.Risks = &RiskData{
		HighUnprocessedEvents: highEvents,
		FailedPublishTasks:    failedPublishes,
		GatewayIssues:         issues,
		CollectorLag:          lag,
	}
	response.JSON(w, r, http.StatusOK, out)
}

// ---------- 运行态势 ----------

// RuntimeOverviewData 运行态势首页数据。
type RuntimeOverviewData struct {
	GeneratedAt time.Time         `json:"generated_at"`
	Components  []ComponentStatus `json:"components"`
	Gateway     *GatewayRuntime   `json:"gateway"`
	Publish     *PublishStats     `json:"publish"`
	Reports     *ReportStats      `json:"reports"`
	Storage     *StorageStats     `json:"storage"`
}

// RuntimeOverview GET /api/v1/dashboard/runtime-overview
func (h *Handler) RuntimeOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	components, err := h.store.LatestComponentStatuses(ctx)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	gateway, err := h.store.GatewayRuntime(ctx)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	publish, err := h.store.PublishStats(ctx, 30)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	reports, err := h.store.ReportStats(ctx, 30)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	storage, err := h.store.StorageStats(ctx)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, &RuntimeOverviewData{
		GeneratedAt: time.Now().UTC(),
		Components:  components,
		Gateway:     gateway,
		Publish:     publish,
		Reports:     reports,
		Storage:     storage,
	})
}

// ---------- 审计态势 ----------

// AuditOverviewData 审计态势首页数据。
type AuditOverviewData struct {
	GeneratedAt             time.Time      `json:"generated_at"`
	TodayDispositions       int64          `json:"today_dispositions"`
	UnprocessedEvents       int64          `json:"unprocessed_events"`
	TodayAudits             int64          `json:"today_audits"`
	RecentAudits            []AuditSummary `json:"recent_audits"`
	DispositionDistribution []StatusCount  `json:"disposition_distribution"`
	ActionStats             []ActionCount  `json:"action_stats"`
}

// AuditOverview GET /api/v1/dashboard/audit-overview
func (h *Handler) AuditOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now().UTC()
	dayStart, _ := TodayWindowUTC(now)
	counters, err := h.store.AuditCounters(ctx, dayStart, now)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	recent, err := h.store.RecentAudits(ctx, 10)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	dist, err := h.store.DispositionDistribution(ctx)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	actions, err := h.store.AuditActionStats(ctx, dayStart, now, 10)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, &AuditOverviewData{
		GeneratedAt:             now,
		TodayDispositions:       counters.TodayDispositions,
		UnprocessedEvents:       counters.UnprocessedEvents,
		TodayAudits:             counters.TodayAudits,
		RecentAudits:            recent,
		DispositionDistribution: dist,
		ActionStats:             actions,
	})
}
