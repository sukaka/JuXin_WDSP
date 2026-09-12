package systemalerts

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/runtimehealth"
)

// 引擎默认参数
const (
	DefaultMaxOpen        = 500
	DefaultCooldown       = 5 * time.Minute
	DefaultFlapWindow     = 10 * time.Minute
	DefaultFlapThreshold  = 3
	DefaultDBCapacityHigh = 80.0 // 数据库容量占比阈值（%）

	defaultParseWindow  = 5 * time.Minute
	defaultParseMinFail = 5
	defaultParseRatePct = 10.0
)

// flapMark 抖动抑制标记（任务要求 message 含"抖动"）。
const flapMark = "（检测到抖动，已抑制频繁翻转）"

// capIgnorePrefix 最大未关闭保护自动忽略前缀。
const capIgnorePrefix = "未关闭告警超过上限，已自动忽略："

// 错误
var (
	ErrInvalidType     = errors.New("invalid alert type")
	ErrInvalidSeverity = errors.New("invalid alert severity")
)

// EngineStore 是评估引擎依赖的存储接口（单测用内存 fake 实现）。
type EngineStore interface {
	FindOpen(ctx context.Context, alertType, component string) (*Alert, error)
	Insert(ctx context.Context, a *Alert) error
	Merge(ctx context.Context, id uuid.UUID, message, severity string, updateMessage bool, now time.Time) error
	CountOpen(ctx context.Context) (int, error)
	ListOpenByComponent(ctx context.Context, component string, alertTypes []string) ([]Alert, error)
	// ListOpenByTypes 查询给定类型集合的全部未关闭告警（端点性能告警恢复扫描用）。
	ListOpenByTypes(ctx context.Context, alertTypes []string) ([]Alert, error)
	ResolveRecovered(ctx context.Context, id uuid.UUID, now time.Time) error
	// HasActiveSilence 同指纹静默判定（静默期内新建告警跳过通知但仍记录）。
	HasActiveSilence(ctx context.Context, alertType, component string) (bool, error)
}

// MaintenanceStore 是维护窗口源（阶段6 §11.5）：查询生效窗口并记录抑制事实。
type MaintenanceStore interface {
	FindActiveMaintenanceWindows(ctx context.Context, now time.Time, alertType, component string) ([]MaintenanceWindow, error)
	RecordMaintenanceSuppression(ctx context.Context, ids []uuid.UUID, now time.Time) error
}

// ParseStatsStore 提供解析失败率统计（EVENT_PARSE_FAILURE_RATE_HIGH 评估）。
type ParseStatsStore interface {
	ParseFailureRate(ctx context.Context, window time.Duration) (failures, processed int64, err error)
}

// RaiseRequest 是告警触发请求。
type RaiseRequest struct {
	AlertType string
	Component string
	Title     string
	Message   string
	// Severity 可空；空时按告警类型规则取默认等级（CERTIFICATE_EXPIRING 需调用方按天数给出）
	Severity string
}

// EngineOptions 是引擎选项。
type EngineOptions struct {
	Now                   func() time.Time
	MaxOpen               int           // OPEN 总数上限（默认 500）
	Cooldown              time.Duration // 重复告警 message 更新冷却（默认 5 分钟）
	FlapWindow            time.Duration // 抖动统计窗口（默认 10 分钟）
	FlapThreshold         int           // 窗口内翻转次数阈值（默认 3）
	DBCapacityHighPercent float64       // DATABASE_CAPACITY_HIGH 阈值（默认 80%）
	// ParseStats 解析失败率统计源；nil 时 EvaluateParseFailures 不执行
	ParseStats              ParseStatsStore
	ParseFailureWindow      time.Duration
	ParseFailureMinCount    int64
	ParseFailureRatePercent float64
	// APIFindings API 安全 findings 统计源；nil 时 EvaluateAPIFindings 不执行（W6-B）
	APIFindings APIFindingsStatsStore
	// SecuritySpikes 安全事件/CC 封禁统计源；nil 时 EvaluateSecuritySpikes 不执行（通知二期）
	SecuritySpikes SecuritySpikeStatsStore
	// EndpointPerf 端点级分钟聚合统计源（APM 阶段1 WP5）；nil 时 EvaluateEndpointPerf 不执行
	EndpointPerf EndpointPerfStatsStore
	// SLOBreach APM SLO 违约评估源（apm.SLOStore 实现）；nil 时 EvaluateSLOBreach 不执行
	SLOBreach SLOBreachStatsStore
	// IngestLag APM 数据面采集滞后读数源（apm.CHHealth 实现）；nil 时 EvaluateIngestLag 不执行
	IngestLag IngestLagStatsStore
	// APMEnabled APM 运行期总开关判定（界面设置热生效，生产为 apm.RuntimeConfig.Enabled）；
	// nil 视为恒 true（兼容既有测试与其他调用方）。返回 false 时 EndpointPerf/SLOBreach/
	// IngestLag 三个 APM 评估器空转，关闭期间不新建也不清动既有告警。
	APMEnabled func(ctx context.Context) bool
	// Settings 评估规则配置源（api_alert 组）；nil 时全部取默认值
	Settings SettingsReader
	// Maintenance 告警维护窗口源（阶段6 §11.5）；nil 时无维护窗口抑制。
	// Raise 命中生效窗口时跳过新建/合并，抑制事实计入窗口 suppressed_count 并写日志。
	Maintenance MaintenanceStore
}

// SyslogEnqueueFunc 是 syslog 外发投递函数（装配层闭包注入，本包不依赖 syslogfw，
// 避免循环导入；模式参考 backups.AlertFunc）。nil 时跳过外发。
type SyslogEnqueueFunc func(severityHint string, payload interface{})

// NotifyEnqueueFunc 是告警通知外发投递函数（装配层闭包注入 notify.Dispatcher，
// 本包不依赖 notify，避免循环导入）。nil 时跳过通知外发。
type NotifyEnqueueFunc func(a Alert)

// Engine 是告警评估引擎：触发、合并、冷却、抖动抑制、上限保护与自动恢复。
type Engine struct {
	store          EngineStore
	syslog         SyslogEnqueueFunc // nil 时跳过 syslog 外发
	notify         NotifyEnqueueFunc // nil 时跳过通知外发
	now            func() time.Time
	maxOpen        int
	cooldown       time.Duration
	flapWindow     time.Duration
	flapThreshold  int
	dbCapHighPct   float64
	parseStats     ParseStatsStore
	parseWindow    time.Duration
	parseMinFail   int64
	parseRatePct   float64
	apiFindings    APIFindingsStatsStore
	securitySpikes SecuritySpikeStatsStore
	endpointPerf   EndpointPerfStatsStore
	sloBreach      SLOBreachStatsStore
	ingestLag      IngestLagStatsStore
	apmEnabled     func(ctx context.Context) bool
	settings       SettingsReader
	maintenance    MaintenanceStore

	flaps *flapTracker
	// msgUpdated 记录各去重键最近一次 message 更新时间（冷却判定）
	mu         sync.Mutex
	msgUpdated map[string]time.Time
}

// NewEngine 创建评估引擎。
func NewEngine(store EngineStore, opts EngineOptions) *Engine {
	e := &Engine{
		store:          store,
		now:            opts.Now,
		maxOpen:        opts.MaxOpen,
		cooldown:       opts.Cooldown,
		flapWindow:     opts.FlapWindow,
		flapThreshold:  opts.FlapThreshold,
		dbCapHighPct:   opts.DBCapacityHighPercent,
		parseStats:     opts.ParseStats,
		parseWindow:    opts.ParseFailureWindow,
		parseMinFail:   opts.ParseFailureMinCount,
		parseRatePct:   opts.ParseFailureRatePercent,
		apiFindings:    opts.APIFindings,
		securitySpikes: opts.SecuritySpikes,
		endpointPerf:   opts.EndpointPerf,
		sloBreach:      opts.SLOBreach,
		ingestLag:      opts.IngestLag,
		apmEnabled:     opts.APMEnabled,
		settings:       opts.Settings,
		maintenance:    opts.Maintenance,
		msgUpdated:     map[string]time.Time{},
	}
	if e.now == nil {
		e.now = func() time.Time { return time.Now().UTC() }
	}
	if e.maxOpen <= 0 {
		e.maxOpen = DefaultMaxOpen
	}
	if e.cooldown <= 0 {
		e.cooldown = DefaultCooldown
	}
	if e.flapWindow <= 0 {
		e.flapWindow = DefaultFlapWindow
	}
	if e.flapThreshold <= 0 {
		e.flapThreshold = DefaultFlapThreshold
	}
	if e.dbCapHighPct <= 0 {
		e.dbCapHighPct = DefaultDBCapacityHigh
	}
	if e.parseWindow <= 0 {
		e.parseWindow = defaultParseWindow
	}
	if e.parseMinFail <= 0 {
		e.parseMinFail = defaultParseMinFail
	}
	if e.parseRatePct <= 0 {
		e.parseRatePct = defaultParseRatePct
	}
	e.flaps = newFlapTracker(e.flapWindow)
	return e
}

// SetSyslogForwarder 设置 syslog 外发投递函数（应用装配时使用，可为 nil）。
func (e *Engine) SetSyslogForwarder(fn SyslogEnqueueFunc) { e.syslog = fn }

// SetNotifyForwarder 设置告警通知外发投递函数（应用装配时使用，可为 nil）。
func (e *Engine) SetNotifyForwarder(fn NotifyEnqueueFunc) { e.notify = fn }

// SetIngestLag 注入/替换数据面采集滞后读数源（集成测试 fake CH 注入缝；
// 生产装配走 EngineOptions.IngestLag）。
func (e *Engine) SetIngestLag(src IngestLagStatsStore) { e.ingestLag = src }

// apmEnabledNow APM 运行期总开关判定（nil = 恒 true，兼容未注入的既有装配与测试）。
func (e *Engine) apmEnabledNow(ctx context.Context) bool {
	return e.apmEnabled == nil || e.apmEnabled(ctx)
}

// enqueueNotify 非阻塞投递告警通知外发（按值快照；投递函数 panic 只记日志，不扩散到告警主流程）。
func (e *Engine) enqueueNotify(a Alert) {
	if e.notify == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Error("notify enqueue panicked", "alert_type", a.AlertType, "panic", r)
		}
	}()
	e.notify(a)
}

// enqueueSyslog 非阻塞投递 syslog 外发（按值快照，避免调用方后续修改告警引入竞态）；
// 未注入投递函数时跳过，投递函数 panic 时记录错误日志而不扩散到告警主流程。
func (e *Engine) enqueueSyslog(a Alert) {
	if e.syslog == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Error("syslog enqueue panicked", "alert_type", a.AlertType, "panic", r)
		}
	}()
	e.syslog(a.Severity, a)
}

// dedupKey 是合并去重键（同 type+component）。
func dedupKey(alertType, component string) string {
	return alertType + "|" + component
}

// Raise 触发告警：存在同 type+component 未关闭告警时合并，否则新建。
func (e *Engine) Raise(ctx context.Context, req RaiseRequest) (*Alert, error) {
	if !IsValidType(req.AlertType) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidType, req.AlertType)
	}
	severity := req.Severity
	if severity == "" {
		severity = SeverityFor(req.AlertType)
	}
	if !IsValidSeverity(severity) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidSeverity, severity)
	}
	now := e.now()
	// 维护窗口抑制（阶段6 §11.5）：命中生效窗口时不新建也不合并告警，
	// 但抑制事实必须可观测——窗口 suppressed_count+1、刷新 last_suppressed_at 并写日志；
	// 查询/记账失败如实返回错误，不退化为放行（避免维护窗口失效时悄悄丢告警）。
	if e.maintenance != nil {
		wins, err := e.maintenance.FindActiveMaintenanceWindows(ctx, now, req.AlertType, req.Component)
		if err != nil {
			return nil, fmt.Errorf("check maintenance windows: %w", err)
		}
		if len(wins) > 0 {
			ids := make([]uuid.UUID, len(wins))
			for i, w := range wins {
				ids[i] = w.ID
			}
			if err := e.maintenance.RecordMaintenanceSuppression(ctx, ids, now); err != nil {
				return nil, fmt.Errorf("record maintenance suppression: %w", err)
			}
			slog.Info("alert suppressed by maintenance window",
				"alert_type", req.AlertType, "component", req.Component, "windows", len(wins))
			return nil, nil
		}
	}
	existing, err := e.store.FindOpen(ctx, req.AlertType, req.Component)
	if err != nil {
		return nil, err
	}
	key := dedupKey(req.AlertType, req.Component)
	openTotal := 0
	if existing == nil {
		openTotal, err = e.store.CountOpen(ctx)
		if err != nil {
			return nil, err
		}
	}
	d := decideRaise(raiseInput{
		Now:               now,
		Severity:          severity,
		HasExisting:       existing != nil,
		OpenTotal:         openTotal,
		MaxOpen:           e.maxOpen,
		FlapCount:         e.flaps.count(key, now),
		FlapThreshold:     e.flapThreshold,
		LastMessageUpdate: e.lastMsgUpdate(key),
		Cooldown:          e.cooldown,
	})
	message := req.Message
	if d.flapping {
		message = markFlapping(message)
	}
	switch d.action {
	case actionCreateIgnored:
		a := newAlert(req, severity, message, now)
		a.Status = StatusIgnored
		a.Message = capIgnorePrefix + a.Message
		if err := e.store.Insert(ctx, a); err != nil {
			return nil, err
		}
		return a, nil
	case actionCreate:
		a := newAlert(req, severity, message, now)
		if err := e.store.Insert(ctx, a); err != nil {
			return nil, err
		}
		e.flaps.record(key, now)
		e.setMsgUpdate(key, now)
		// syslog 外发：仅新建 OPEN 告警外发（合并与 IGNORED 不重复外发），非阻塞投递。
		// 防循环：forwarder 发送失败只写磁盘 spool 与 slog，不产生系统告警；
		// 即使未来新增 syslog 自身故障类告警，引擎对同 type+component 的 OPEN 告警
		// 去重合并（FindOpen→Merge），后续失败只合并不再外发，不会无限放大。
		//
		// 静默抑制（W6-B）：同指纹存在静默期内告警时跳过外发，告警照常落库
		// （「不重复通知但仍记录」）；静默判定失败如实返回错误，不退化为外发或吞错。
		silenced, err := e.store.HasActiveSilence(ctx, req.AlertType, req.Component)
		if err != nil {
			return a, fmt.Errorf("check active silence: %w", err)
		}
		if !silenced {
			e.enqueueSyslog(*a)
			// 通知外发（一期）：与 syslog 同挂点同静默语义；通知层内部再做
			// 渠道订阅过滤与风暴抑制，引擎只负责投递新建 OPEN 告警。
			e.enqueueNotify(*a)
		}
		return a, nil
	default: // actionMerge
		if err := e.store.Merge(ctx, existing.ID, message, severity, d.updateMessage, now); err != nil {
			return nil, err
		}
		if d.updateMessage {
			e.setMsgUpdate(key, now)
			existing.Message = message
			existing.Severity = severity
		}
		existing.LastSeenAt = now
		existing.OccurrenceCount++
		return existing, nil
	}
}

func newAlert(req RaiseRequest, severity, message string, now time.Time) *Alert {
	return &Alert{
		AlertType:       req.AlertType,
		Severity:        severity,
		Component:       req.Component,
		Title:           req.Title,
		Message:         message,
		Status:          StatusOpen,
		FirstSeenAt:     now,
		LastSeenAt:      now,
		OccurrenceCount: 1,
	}
}

// AutoRecover 组件恢复时将对应未关闭告警置为 RESOLVED(RECOVERED)。
// 抖动中的告警保持 OPEN 并补记抖动标记。返回恢复条数。
func (e *Engine) AutoRecover(ctx context.Context, component string, alertTypes ...string) (int, error) {
	open, err := e.store.ListOpenByComponent(ctx, component, alertTypes)
	if err != nil {
		return 0, err
	}
	now := e.now()
	resolved := 0
	for i := range open {
		a := &open[i]
		key := dedupKey(a.AlertType, a.Component)
		if decideRecover(e.flaps.count(key, now), e.flapThreshold) {
			if err := e.store.ResolveRecovered(ctx, a.ID, now); err != nil {
				return resolved, err
			}
			e.flaps.record(key, now)
			resolved++
			// 恢复通知（一期）：投递 RESOLVED 事件，通知层按 notify_resolved 开关决定
			// 是否外发；与引擎去重/冷却逻辑无关（仅追加投递，不改变状态机）。
			na := *a
			na.Status = StatusResolved
			na.ResolvedAt = &now
			rt := ResolveRecovered
			na.ResolveType = &rt
			e.enqueueNotify(na)
			continue
		}
		// 抖动抑制：保持 OPEN，message 补抖动标记
		if !strings.Contains(a.Message, "抖动") {
			if err := e.store.Merge(ctx, a.ID, markFlapping(a.Message), a.Severity, true, now); err != nil {
				return resolved, err
			}
			e.setMsgUpdate(key, now)
		}
	}
	return resolved, nil
}

// NotifyFailure 业务失败回调入口（备份/恢复验证/报告/升级/发布/哈希一致性/审计完整性）。
// component 建议使用业务组件名（如 BACKUP、REPORT、UPGRADE、GATEWAY、AUDIT）。
func (e *Engine) NotifyFailure(ctx context.Context, alertType, component, title, message string) (*Alert, error) {
	return e.Raise(ctx, RaiseRequest{
		AlertType: alertType,
		Component: component,
		Title:     title,
		Message:   message,
	})
}

// Evaluate 依据最新健康快照执行告警评估（触发与自动恢复）。
// 单组件评估失败不阻断其他组件，错误聚合返回。
func (e *Engine) Evaluate(ctx context.Context, snaps []runtimehealth.Snapshot) error {
	byComp := make(map[string]runtimehealth.Snapshot, len(snaps))
	for _, s := range snaps {
		byComp[s.Component] = s
	}
	var errs []error
	raise := func(req RaiseRequest) {
		if _, err := e.Raise(ctx, req); err != nil {
			errs = append(errs, err)
		}
	}
	recover := func(component string, types ...string) {
		if _, err := e.AutoRecover(ctx, component, types...); err != nil {
			errs = append(errs, err)
		}
	}

	// GATEWAY → GATEWAY_DOWN
	if s, ok := byComp[runtimehealth.ComponentGateway]; ok {
		switch s.Status {
		case runtimehealth.StatusDown:
			raise(RaiseRequest{TypeGatewayDown, s.Component, "防护网关不可用", msgOr(s.Message, "网关 Admin Socket 不可达"), ""})
		case runtimehealth.StatusUp:
			recover(s.Component, TypeGatewayDown)
		}
	}
	// API → MANAGEMENT_API_DOWN / FD_USAGE_HIGH（阶段6 §10.2 挂接：
	// 采集器 fd_usage_percent 达阈判 API 组件 DEGRADED，同 DISK_SPACE_LOW 模式）
	if s, ok := byComp[runtimehealth.ComponentAPI]; ok {
		switch s.Status {
		case runtimehealth.StatusDown:
			raise(RaiseRequest{TypeManagementAPIDown, s.Component, "管理 API 不可用", msgOr(s.Message, "管理 API 进程异常"), ""})
		case runtimehealth.StatusDegraded:
			// 降级且带句柄使用率指标 → FD_USAGE_HIGH；指标缺失（非 Linux/采集失败）不判级
			if pct, ok := metricFloat(s.Metrics, runtimehealth.MetricFDUsagePercent); ok {
				raise(RaiseRequest{TypeFDUsageHigh, s.Component, "文件句柄使用率过高",
					msgOr(s.Message, fmt.Sprintf("文件句柄使用率 %.1f%%", pct)), ""})
			}
		case runtimehealth.StatusUp:
			recover(s.Component, TypeManagementAPIDown)
			recover(s.Component, TypeFDUsageHigh)
		}
	}
	// POSTGRES → DATABASE_UNAVAILABLE / DATABASE_CAPACITY_HIGH
	if s, ok := byComp[runtimehealth.ComponentPostgres]; ok {
		switch s.Status {
		case runtimehealth.StatusDown:
			raise(RaiseRequest{TypeDatabaseUnavailable, s.Component, "数据库不可用", msgOr(s.Message, "PostgreSQL 不可达"), ""})
		case runtimehealth.StatusUp:
			recover(s.Component, TypeDatabaseUnavailable)
			if pct, ok := metricFloat(s.Metrics, runtimehealth.MetricDBCapacityPercent); ok {
				if pct >= e.dbCapHighPct {
					raise(RaiseRequest{TypeDatabaseCapacityHigh, s.Component, "数据库容量过高",
						fmt.Sprintf("数据库容量占磁盘 %.1f%%（阈值 %.0f%%）", pct, e.dbCapHighPct), ""})
				} else {
					recover(s.Component, TypeDatabaseCapacityHigh)
				}
			}
		}
	}
	// VALKEY → VALKEY_UNAVAILABLE
	if s, ok := byComp[runtimehealth.ComponentValkey]; ok {
		switch s.Status {
		case runtimehealth.StatusDown:
			raise(RaiseRequest{TypeValkeyUnavailable, s.Component, "Valkey 不可用", msgOr(s.Message, "Valkey 不可达"), ""})
		case runtimehealth.StatusUp:
			recover(s.Component, TypeValkeyUnavailable)
		}
	}
	// EVENT_COLLECTOR → EVENT_COLLECTOR_LAG
	if s, ok := byComp[runtimehealth.ComponentEventCollector]; ok {
		switch s.Status {
		case runtimehealth.StatusDegraded, runtimehealth.StatusDown:
			raise(RaiseRequest{TypeEventCollectorLag, s.Component, "事件采集滞后", msgOr(s.Message, "事件采集 checkpoint 滞后"), ""})
		case runtimehealth.StatusUp:
			recover(s.Component, TypeEventCollectorLag)
		}
	}
	// UPSTREAM → SOURCE_UNHEALTHY
	if s, ok := byComp[runtimehealth.ComponentUpstream]; ok {
		switch s.Status {
		case runtimehealth.StatusDegraded, runtimehealth.StatusDown:
			raise(RaiseRequest{TypeSourceUnhealthy, s.Component, "源站健康异常", msgOr(s.Message, "存在不健康源站"), ""})
		case runtimehealth.StatusUp:
			recover(s.Component, TypeSourceUnhealthy)
		}
	}
	// CERTIFICATE → CERTIFICATE_EXPIRED / CERTIFICATE_EXPIRING
	if s, ok := byComp[runtimehealth.ComponentCertificate]; ok && s.Status != runtimehealth.StatusUnknown {
		expired, _ := metricInt(s.Metrics, runtimehealth.MetricExpiredCount)
		minDays, hasDays := metricInt(s.Metrics, runtimehealth.MetricMinDaysRemaining)
		switch {
		case expired > 0:
			raise(RaiseRequest{TypeCertificateExpired, s.Component, "证书已过期",
				fmt.Sprintf("%d 张证书已过期", expired), ""})
			recover(s.Component, TypeCertificateExpiring)
		case hasDays && minDays <= 30:
			raise(RaiseRequest{TypeCertificateExpiring, s.Component, "证书即将到期",
				fmt.Sprintf("证书剩余 %d 天", minDays), SeverityForCertExpiring(int(minDays))})
			recover(s.Component, TypeCertificateExpired)
		default:
			recover(s.Component, TypeCertificateExpired, TypeCertificateExpiring)
		}
	}
	// DISK → DISK_SPACE_LOW
	if s, ok := byComp[runtimehealth.ComponentDisk]; ok {
		switch s.Status {
		case runtimehealth.StatusDegraded, runtimehealth.StatusDown:
			freePct, _ := metricFloat(s.Metrics, runtimehealth.MetricDiskFreePercent)
			raise(RaiseRequest{TypeDiskSpaceLow, s.Component, "磁盘空间不足",
				fmt.Sprintf("磁盘剩余 %.1f%%", freePct), ""})
		case runtimehealth.StatusUp:
			recover(s.Component, TypeDiskSpaceLow)
		}
	}
	return errors.Join(errs...)
}

// EvaluateParseFailures 评估事件解析失败率（需配置 ParseStats）。
// 窗口内失败数 ≥ 下限且失败率 ≥ 阈值时触发 EVENT_PARSE_FAILURE_RATE_HIGH，否则自动恢复。
func (e *Engine) EvaluateParseFailures(ctx context.Context) error {
	if e.parseStats == nil {
		return nil
	}
	failures, processed, err := e.parseStats.ParseFailureRate(ctx, e.parseWindow)
	if err != nil {
		return err
	}
	rate := parseFailureRate(failures, processed)
	if parseFailureRateHigh(failures, rate, e.parseMinFail, e.parseRatePct) {
		_, err = e.Raise(ctx, RaiseRequest{
			AlertType: TypeParseFailureRateHigh,
			Component: runtimehealth.ComponentEventCollector,
			Title:     "事件解析失败率过高",
			Message:   fmt.Sprintf("最近 %d 分钟解析失败 %d 条（失败率 %.1f%%）", int(e.parseWindow.Minutes()), failures, rate),
		})
		return err
	}
	_, err = e.AutoRecover(ctx, runtimehealth.ComponentEventCollector, TypeParseFailureRateHigh)
	return err
}

// ---------- 纯决策函数（单测直接覆盖） ----------

type raiseAction int

const (
	actionCreate raiseAction = iota
	actionMerge
	actionCreateIgnored
)

type raiseInput struct {
	Now               time.Time
	Severity          string
	HasExisting       bool // 存在同 type+component 未关闭告警
	OpenTotal         int
	MaxOpen           int
	FlapCount         int
	FlapThreshold     int
	LastMessageUpdate time.Time // 零值表示从未更新
	Cooldown          time.Duration
}

type raiseDecision struct {
	action        raiseAction
	updateMessage bool
	flapping      bool
}

// decideRaise 合并/新建/上限保护决策：
// - 已有未关闭 → 合并；冷却期外才更新 message
// - 新建前 OPEN 总数超限且为 LOW/INFO → 直接 IGNORED
// - 抖动窗口内翻转达阈值 → 标记 flapping（message 含"抖动"）
func decideRaise(in raiseInput) raiseDecision {
	d := raiseDecision{flapping: in.FlapCount >= in.FlapThreshold}
	if in.HasExisting {
		d.action = actionMerge
		d.updateMessage = in.LastMessageUpdate.IsZero() ||
			in.Now.Sub(in.LastMessageUpdate) >= in.Cooldown
		return d
	}
	if in.OpenTotal >= in.MaxOpen && (in.Severity == SeverityLow || in.Severity == SeverityInfo) {
		d.action = actionCreateIgnored
		return d
	}
	d.action = actionCreate
	return d
}

// decideRecover 自动恢复决策：抖动中保持 OPEN（返回 false）。
func decideRecover(flapCount, flapThreshold int) bool {
	return flapCount < flapThreshold
}

// parseFailureRate 计算失败率（%）。
func parseFailureRate(failures, processed int64) float64 {
	total := failures + processed
	if total == 0 {
		return 0
	}
	return float64(failures) / float64(total) * 100
}

// parseFailureRateHigh 失败率告警判定：失败数与失败率同时达阈。
func parseFailureRateHigh(failures int64, rate float64, minFailures int64, ratePercent float64) bool {
	return failures >= minFailures && rate >= ratePercent
}

// markFlapping 在 message 中补充抖动标记（幂等）。
func markFlapping(msg string) string {
	if strings.Contains(msg, "抖动") {
		return msg
	}
	return msg + flapMark
}

func msgOr(msg, def string) string {
	if msg != "" {
		return msg
	}
	return def
}

// metricFloat 从快照 metrics 取浮点值。
func metricFloat(m map[string]interface{}, key string) (float64, bool) {
	v, ok := m[key]
	if !ok || v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	}
	return 0, false
}

// metricInt 从快照 metrics 取整数值。
func metricInt(m map[string]interface{}, key string) (int64, bool) {
	f, ok := metricFloat(m, key)
	return int64(f), ok
}

func (e *Engine) lastMsgUpdate(key string) time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.msgUpdated[key]
}

func (e *Engine) setMsgUpdate(key string, t time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.msgUpdated[key] = t
}

// flapTracker 记录去重键的 OPEN↔RESOLVED 翻转时间（内存实现，进程重启后重新计数）。
type flapTracker struct {
	mu     sync.Mutex
	window time.Duration
	events map[string][]time.Time
}

func newFlapTracker(window time.Duration) *flapTracker {
	return &flapTracker{window: window, events: map[string][]time.Time{}}
}

// count 返回窗口内翻转次数（顺带清理过期记录）。
func (t *flapTracker) count(key string, now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(key, now)
	return len(t.events[key])
}

// record 记录一次翻转。
func (t *flapTracker) record(key string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(key, now)
	t.events[key] = append(t.events[key], now)
}

func (t *flapTracker) pruneLocked(key string, now time.Time) {
	evs := t.events[key]
	cutoff := now.Add(-t.window)
	keep := evs[:0]
	for _, ts := range evs {
		if ts.After(cutoff) {
			keep = append(keep, ts)
		}
	}
	if len(keep) == 0 {
		delete(t.events, key)
		return
	}
	t.events[key] = keep
}
