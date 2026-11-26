// handler.go 态势首页 HTTP 接口（只读）。
package dashboards

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/metrics"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/redis/go-redis/v9"
)

const (
	defaultOverviewCacheTTL = 20 * time.Second
	defaultCacheOpTimeout   = 500 * time.Millisecond
	defaultLoadTimeout      = 15 * time.Second

	cacheKeySecurityOverviewPrefix = "jiuzhang:dashboard:v1:security-overview:"
	cacheKeyRuntimeOverview        = "jiuzhang:dashboard:v1:runtime-overview"
	cacheKeyAuditOverview          = "jiuzhang:dashboard:v1:audit-overview"
)

type overviewCache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
}

type sfCall struct {
	done chan struct{}
	val  any
	err  error
}

type singleflightGroup struct {
	mu sync.Mutex
	m  map[string]*sfCall
}

func (g *singleflightGroup) do(ctx context.Context, key string, loadTimeout time.Duration, fn func(context.Context) (any, error)) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*sfCall)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		select {
		case <-c.done:
			return c.val, c.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c := &sfCall{done: make(chan struct{})}
	g.m[key] = c
	g.mu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.err = fmt.Errorf("dashboard singleflight panic: %v", r)
			}
			g.mu.Lock()
			delete(g.m, key)
			g.mu.Unlock()
			close(c.done)
		}()
		loadCtx := context.WithoutCancel(ctx)
		if loadTimeout > 0 {
			var cancel context.CancelFunc
			loadCtx, cancel = context.WithTimeout(loadCtx, loadTimeout)
			defer cancel()
		}
		c.val, c.err = fn(loadCtx)
	}()

	select {
	case <-c.done:
		return c.val, c.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func isCacheAvailable(c overviewCache) bool {
	if c == nil {
		return false
	}
	v := reflect.ValueOf(c)
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
		return !v.IsNil()
	default:
		return true
	}
}

// Handler 态势首页处理器。
type Handler struct {
	store          *Store
	ovCache        overviewCache
	cacheTTL       time.Duration
	cacheOpTimeout time.Duration
	loadTimeout    time.Duration
	sf             singleflightGroup

	loadSecurity func(ctx context.Context, rangeName string, d time.Duration) (*SecurityOverviewData, error)
	loadRuntime  func(ctx context.Context) (*RuntimeOverviewData, error)
	loadAudit    func(ctx context.Context) (*AuditOverviewData, error)
}

// NewHandler 创建态势首页处理器。
func NewHandler(aggStore *aggregations.Store, db *pgxpool.Pool) *Handler {
	h := &Handler{
		store:          NewStore(db, aggStore),
		cacheTTL:       defaultOverviewCacheTTL,
		cacheOpTimeout: defaultCacheOpTimeout,
		loadTimeout:    defaultLoadTimeout,
	}
	h.loadSecurity = h.loadSecurityOverview
	h.loadRuntime = h.loadRuntimeOverview
	h.loadAudit = h.loadAuditOverview
	return h
}

// SetCache 设置 Valkey 客户端（可选，用于态势短 TTL 缓存与运行态势存储采集）。
func (h *Handler) SetCache(c *cache.Client) {
	h.store.SetCache(c)
	if c != nil && c.Redis() != nil {
		h.ovCache = c
	} else {
		h.ovCache = nil
	}
}

type cacheGetResult struct {
	raw string
	err error
}

func boundedCacheGet(ctx context.Context, c overviewCache, key string, timeout time.Duration) (string, error) {
	gCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ch := make(chan cacheGetResult, 1)
	go func() {
		raw, err := c.Get(gCtx, key)
		ch <- cacheGetResult{raw: raw, err: err}
	}()
	select {
	case res := <-ch:
		return res.raw, res.err
	case <-gCtx.Done():
		return "", gCtx.Err()
	}
}

func boundedCacheSet(ctx context.Context, c overviewCache, key, value string, ttl, timeout time.Duration) error {
	sCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ch := make(chan error, 1)
	go func() {
		ch <- c.Set(sCtx, key, value, ttl)
	}()
	select {
	case err := <-ch:
		return err
	case <-sCtx.Done():
		return sCtx.Err()
	}
}

func getOrLoadCached[T any](
	ctx context.Context,
	h *Handler,
	key string,
	load func(context.Context) (*T, error),
) (*T, error) {
	c := h.ovCache
	ttl := h.cacheTTL
	opTimeout := h.cacheOpTimeout
	if opTimeout <= 0 {
		opTimeout = defaultCacheOpTimeout
	}
	cacheEnabled := isCacheAvailable(c) && ttl > 0

	if cacheEnabled {
		raw, err := boundedCacheGet(ctx, c, key, opTimeout)
		switch {
		case err == nil:
			var cached T
			if uErr := json.Unmarshal([]byte(raw), &cached); uErr == nil {
				return &cached, nil
			} else {
				slog.Warn("dashboard cache unmarshal failed, falling back to db", "key", key, "error", uErr)
			}
		case errors.Is(err, redis.Nil):
			// normal cache miss
		default:
			if ctx.Err() == nil {
				slog.Warn("dashboard cache get failed, falling back to db", "key", key, "error", err)
			}
		}
	}

	valAny, err := h.sf.do(ctx, key, h.loadTimeout, func(loadCtx context.Context) (any, error) {
		val, lErr := load(loadCtx)
		if lErr != nil {
			return nil, lErr
		}
		if cacheEnabled && loadCtx.Err() == nil {
			payload, mErr := json.Marshal(val)
			if mErr != nil {
				slog.Warn("dashboard cache marshal failed", "key", key, "error", mErr)
			} else {
				if sErr := boundedCacheSet(loadCtx, c, key, string(payload), ttl, opTimeout); sErr != nil && loadCtx.Err() == nil {
					slog.Warn("dashboard cache set failed", "key", key, "error", sErr)
				}
			}
		}
		return val, nil
	})
	if err != nil {
		return nil, err
	}
	val, ok := valAny.(*T)
	if !ok {
		return nil, fmt.Errorf("unexpected singleflight value type %T", valAny)
	}
	return val, nil
}

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
	key := cacheKeySecurityOverviewPrefix + rangeName
	out, err := getOrLoadCached(r.Context(), h, key, func(loadCtx context.Context) (*SecurityOverviewData, error) {
		return h.loadSecurity(loadCtx, rangeName, d)
	})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, out)
}

func (h *Handler) loadSecurityOverview(ctx context.Context, rangeName string, d time.Duration) (*SecurityOverviewData, error) {
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
		return nil, err
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
	simpleNames := make([]string, len(simple))
	for i, it := range simple {
		simpleNames[i] = it.metric
	}
	seriesTimes, seriesVals, err := h.store.metricSeriesBatch(ctx, table, simpleNames, start, now)
	if err != nil {
		return nil, err
	}
	for _, it := range simple {
		*it.dst = SeriesInto(buckets, seriesTimes[it.metric], seriesVals[it.metric], step)
	}
	sev, err := h.store.severitySeries(ctx, table, start, now)
	if err != nil {
		return nil, err
	}
	trends.RiskLevels = SeriesMapInto(buckets, sev, step)
	disp, err := h.store.dispositionSeries(ctx, start, now, StepTrunc(step))
	if err != nil {
		return nil, err
	}
	trends.Disposition = SeriesMapInto(buckets, disp, step)
	out.Trends = trends

	// 排行
	attackTypes, err := h.store.TopAttackTypes(ctx, table, start, now, 5)
	if err != nil {
		return nil, err
	}
	sourceIPs, err := h.store.TopSourceIPs(ctx, start, now, 10)
	if err != nil {
		return nil, err
	}
	apps, err := h.store.TopApplications(ctx, table, start, now, 5)
	if err != nil {
		return nil, err
	}
	rules, err := h.store.TopRules(ctx, table, start, now, 10)
	if err != nil {
		return nil, err
	}
	uris, err := h.store.TopURIs(ctx, start, now, 10)
	if err != nil {
		return nil, err
	}
	out.Top = &TopData{
		AttackTypes: attackTypes, SourceIPs: sourceIPs,
		Applications: apps, Rules: rules, URIs: uris,
	}

	// 风险
	highEvents, err := h.store.RecentHighUnprocessed(ctx, 10)
	if err != nil {
		return nil, err
	}
	failedPublishes, err := h.store.RecentFailedPublishes(ctx, 5)
	if err != nil {
		return nil, err
	}
	issues, err := h.store.ComponentIssues(ctx)
	if err != nil {
		return nil, err
	}
	lag, err := h.store.CollectorLag(ctx)
	if err != nil {
		return nil, err
	}
	out.Risks = &RiskData{
		HighUnprocessedEvents: highEvents,
		FailedPublishTasks:    failedPublishes,
		GatewayIssues:         issues,
		CollectorLag:          lag,
	}
	return out, nil
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
	out, err := getOrLoadCached(r.Context(), h, cacheKeyRuntimeOverview, h.loadRuntime)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, out)
}

func (h *Handler) loadRuntimeOverview(ctx context.Context) (*RuntimeOverviewData, error) {
	components, err := h.store.LatestComponentStatuses(ctx)
	if err != nil {
		return nil, err
	}
	gateway := deriveGatewayRuntime(components)
	publish, reports, storage, err := h.store.runtimeOverviewStats(ctx, 30)
	if err != nil {
		return nil, err
	}
	return &RuntimeOverviewData{
		GeneratedAt: time.Now().UTC(),
		Components:  components,
		Gateway:     gateway,
		Publish:     publish,
		Reports:     reports,
		Storage:     storage,
	}, nil
}

func deriveGatewayRuntime(components []ComponentStatus) *GatewayRuntime {
	out := &GatewayRuntime{Status: "UNKNOWN"}
	var latest *ComponentStatus
	for i := range components {
		c := &components[i]
		if !strings.Contains(strings.ToLower(c.Component), "gateway") {
			continue
		}
		if latest == nil || c.TakenAt.After(latest.TakenAt) {
			latest = c
		}
	}
	if latest == nil {
		return out
	}
	out.Status = latest.Status
	t := latest.TakenAt
	out.SnapshotAt = &t
	if latest.Metrics != nil {
		if v, ok := latest.Metrics["uptime_seconds"].(float64); ok {
			out.UptimeSeconds = &v
		}
	}
	return out
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
	out, err := getOrLoadCached(r.Context(), h, cacheKeyAuditOverview, h.loadAudit)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, out)
}

func (h *Handler) loadAuditOverview(ctx context.Context) (*AuditOverviewData, error) {
	now := time.Now().UTC()
	dayStart, _ := TodayWindowUTC(now)
	todayDispositions, unprocessedEvents, dist, err := h.store.auditSecurityOverviewStats(ctx, dayStart, now)
	if err != nil {
		return nil, err
	}
	recent, err := h.store.RecentAudits(ctx, 10)
	if err != nil {
		return nil, err
	}
	todayAudits, actions, err := h.store.auditOperationOverviewStats(ctx, dayStart, now, 10)
	if err != nil {
		return nil, err
	}
	return &AuditOverviewData{
		GeneratedAt:             now,
		TodayDispositions:       todayDispositions,
		UnprocessedEvents:       unprocessedEvents,
		TodayAudits:             todayAudits,
		RecentAudits:            recent,
		DispositionDistribution: dist,
		ActionStats:             actions,
	}, nil
}
