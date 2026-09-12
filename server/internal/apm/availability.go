// availability.go P1-01 A2：availability/correlation 判定逻辑与采集水位缓存。
//
// 证据纪律（任务书 §4.3）：
//   - reason_codes 只填有依据的原因：STORAGE_NOT_CONFIGURED（querier=nil）、
//     STORAGE_UNAVAILABLE（本次查询失败）、ACCESS_LOG_DISABLED（设置关闭且对应腿无数据）、
//     INGESTION_DELAY_CONFIRMED（水位证实的滞后：最近入库早于窗口终点且滞后超阈，
//     阈值与 systemalerts 告警同键同口径）、OUTSIDE_RETENTION（窗口完全超出分层 TTL
//     上限 14 天）、NO_MATCH（成功查询的零结果）、UNKNOWN（证据不足）；
//   - NO_INSTRUMENTATION_CONFIRMED / NOT_SAMPLED_CONFIRMED 本阶段无证据来源（无探针
//     注册/采样决策数据），词表冻结保留但不产出——单凭"查不到 Span"只报 NO_MATCH/UNKNOWN；
//   - last_collected_at/last_ingested_at 未知即为 null，严禁用 now 伪造；
//   - NOT_EXPECTED 仅在"网关终止且未调用源站"有证据时使用：当前证据来源为
//     access_logs.waf_action=BLOCK 或 security_events.action=BLOCK（请求级阻断动作）。
//     与 P0-04 的合流点：final_decision schema 落地后改由最终处置链 + 源站调用事实
//     证实（此处判定函数即替换点）；HTTP 403 状态码单独不作为证据。
package apm

import (
	"context"
	"log/slog"
	"regexp"
	"time"
)

const (
	// ingestWatermarkTTL 采集水位读数缓存 TTL（与 systemalerts 30s 评估周期同量级：
	// 页面查询共享一次 CH 读数，不为每次请求新增昂贵探测；DSN 热更新重建查询器后
	// 缓存按查询器身份失效）。
	ingestWatermarkTTL = 30 * time.Second
	// correlationPendingMargin "尚在采集途中"判定的有界余量：访问记录/Span 发生时间
	// 距 now 小于该值时允许 PENDING（网关 JSONL tail 采集 + OTLP 管线+聚合抖动余量；
	// 估计值而非精确延迟，与 estimated_lag_ms 口径一致）。
	correlationPendingMargin = 5 * time.Minute
	// appServicesCap 单应用映射 OTel 服务名集合上限（防异常数据下放大 IN 集合）。
	appServicesCap = 64
	// correlationServicesCap 关联候选服务名列表上限。
	correlationServicesCap = 16
)

// apm_alert 组采集滞后阈值（键/默认/合法区间与 systemalerts/ingest_lag.go 完全一致；
// apm 包不反向 import systemalerts——duck-type 不反向依赖纪律同 chstore_health.go）。
const (
	apmAlertSettingsGroup       = "apm_alert"
	apmAlertKeyIngestLagSeconds = "ingest_lag_seconds"
	defaultIngestLagSeconds     = 300
	minIngestLagSeconds         = 30
	maxIngestLagSeconds         = 86400
)

// chQueryStatus 本次 CH 查询的真实结果（availability 判定的直接证据）。
type chQueryStatus int

const (
	chQueryOK            chQueryStatus = iota
	chQueryNotConfigured               // querier=nil（DSN 空/建连失败降级）
	chQueryFailed                      // 查询/扫描/迭代任一环节失败
)

// now 时间源（nowFunc 为单测注入；默认 time.Now UTC）。
func (s *Store) now() time.Time {
	if s.nowFunc != nil {
		return s.nowFunc()
	}
	return time.Now().UTC()
}

// latestIngest 数据面采集水位（复用 CHHealth.LatestIngestAt 口径，短 TTL 缓存）。
// 返回 ok=false：无可用连接或读数失败（失败不缓存，下次调用重试——不缓存坏水位）；
// ok=true 且 hasData=false：表空无数据（缓存，非故障）。
func (s *Store) latestIngest(ctx context.Context) (latest time.Time, hasData, ok bool) {
	ch := s.conn(ctx)
	if ch == nil {
		return time.Time{}, false, false
	}
	now := s.now()
	s.wmMu.Lock()
	if s.wmValid && s.wmQuerier == ch && now.Sub(s.wmFetchedAt) < ingestWatermarkTTL {
		latest, hasData := s.wmLatest, s.wmHasData
		s.wmMu.Unlock()
		return latest, hasData, true
	}
	s.wmMu.Unlock()

	ts, has, err := NewCHHealth(ch).LatestIngestAt(ctx)
	if err != nil {
		slog.Warn("APM 采集水位读数失败，availability 水位字段留空", "error", err)
		return time.Time{}, false, false
	}
	s.wmMu.Lock()
	s.wmQuerier, s.wmFetchedAt, s.wmLatest, s.wmHasData, s.wmValid = ch, now, ts, has, true
	s.wmMu.Unlock()
	return ts, has, true
}

// ---------- availability 构建 ----------

// availabilityBase 空 availability（reason_codes/observed_sources 恒为数组而非 null）。
func availabilityBase() *Availability {
	return &Availability{ReasonCodes: []string{}, ObservedSources: []string{}}
}

// addReason 追加原因码（去重保序）。
func (a *Availability) addReason(codes ...string) {
	for _, c := range codes {
		found := false
		for _, e := range a.ReasonCodes {
			if e == c {
				found = true
				break
			}
		}
		if !found {
			a.ReasonCodes = append(a.ReasonCodes, c)
		}
	}
}

// fillWatermark 填入入库水位与估计滞后（仅有可比较水位时；ok=false 或表空则留 null）。
func (a *Availability) fillWatermark(latest time.Time, hasData, ok bool, now time.Time) {
	if !ok || !hasData {
		return
	}
	t := latest.UTC()
	a.LastIngestedAt = &t
	lag := now.Sub(t)
	if lag < 0 {
		lag = 0 // 时钟差：滞后估计不为负（时钟差容忍即 0 夹紧）
	}
	ms := lag.Milliseconds()
	a.EstimatedLagMS = &ms
}

// ingestionDelayed 水位证实的采集延迟：最近入库早于窗口终点且滞后超阈。
func ingestionDelayed(latest time.Time, hasData, ok bool, end, now time.Time, threshold time.Duration) bool {
	return ok && hasData && latest.Before(end) && now.Sub(latest) > threshold
}

// chAvailability CH 数据面列表类查询（trace-search/sql/exceptions）的 availability。
// status 为本次查询真实结果；matched 为是否有结果行；start/end 为查询窗口；
// extra 为调用方有证据追加的原因码（如 ACCESS_LOG_DISABLED）。
func (s *Store) chAvailability(ctx context.Context, status chQueryStatus, matched bool, start, end time.Time, ingestLagThreshold time.Duration, extra ...string) *Availability {
	a := availabilityBase()
	a.addReason(extra...)
	switch status {
	case chQueryNotConfigured:
		a.QueryState = queryStateUnavailable
		a.addReason(reasonStorageNotConfigured)
		return a
	case chQueryFailed:
		a.QueryState = queryStateUnavailable
		a.addReason(reasonStorageUnavailable)
		return a
	}
	// CH 在线：填水位（读数不可得时水位字段留 null，不伪造）
	now := s.now()
	latest, hasData, ok := s.latestIngest(ctx)
	a.fillWatermark(latest, hasData, ok, now)
	if matched {
		a.QueryState = queryStateReady
		a.ObservedSources = []string{sourceOTel}
		return a
	}
	a.QueryState = queryStateEmpty
	a.addReason(reasonNoMatch)
	// 窗口完全落在已知最长保留期（分层 TTL 上限 14 天）之外：零结果可由保留期解释
	if end.Before(now.Add(-traceSpansDefaultWindow)) {
		a.addReason(reasonOutsideRetention)
	}
	// 水位证实的采集延迟（与告警同口径阈值）
	if ingestionDelayed(latest, hasData, ok, end, now, ingestLagThreshold) {
		a.addReason(reasonIngestionDelayConfirmed)
	}
	return a
}

// gatewayAvailability 网关侧（PG 聚合）数据的 availability（overview/services/detail/endpoints）。
// matched=有实际数据；observed=网关侧观测到真实流量（observed_sources 证据）；
// lastSeen=最近观测时间（未知为 nil，不填 now）；extra 有证据原因码。
func gatewayAvailability(matched, observed bool, lastSeen *time.Time, extra ...string) *Availability {
	a := availabilityBase()
	a.addReason(extra...)
	if observed {
		a.ObservedSources = []string{sourceGateway}
	}
	if lastSeen != nil && !lastSeen.IsZero() {
		t := lastSeen.UTC()
		a.LastCollectedAt = &t
	}
	if matched {
		a.QueryState = queryStateReady
		return a
	}
	a.QueryState = queryStateEmpty
	a.addReason(reasonNoMatch)
	return a
}

// traceViewAvailability traces/{id} 的 availability：网关腿（PG access_logs/security_events）
// 与 OTel 腿（CH span）按本次真实结果逐腿判定。
func (s *Store) traceViewAvailability(ctx context.Context, chStatus chQueryStatus,
	accessLogs []TraceAccessLog, events []TraceSecurityEvent, spans []OTelSpan,
	truncated, hasRoot, accessLogEnabled bool, end *time.Time, ingestLagThreshold time.Duration) *Availability {

	a := availabilityBase()
	gatewayHit := len(accessLogs) > 0 || len(events) > 0
	otelHit := len(spans) > 0
	if gatewayHit {
		a.ObservedSources = append(a.ObservedSources, sourceGateway)
	}
	if otelHit {
		a.ObservedSources = append(a.ObservedSources, sourceOTel)
	}

	// 最近实际观测时间：仅取本次真实返回的事件时间（无数据为 null）
	var last time.Time
	for _, l := range accessLogs {
		if l.OccurredAt.After(last) {
			last = l.OccurredAt
		}
	}
	for _, e := range events {
		if e.OccurredAt.After(last) {
			last = e.OccurredAt
		}
	}
	for _, sp := range spans {
		if sp.StartTime.After(last) {
			last = sp.StartTime
		}
	}
	if !last.IsZero() {
		t := last.UTC()
		a.LastCollectedAt = &t
	}

	chDegraded := false
	switch chStatus {
	case chQueryNotConfigured:
		a.addReason(reasonStorageNotConfigured)
		chDegraded = true
	case chQueryFailed:
		a.addReason(reasonStorageUnavailable)
		chDegraded = true
	}
	if !accessLogEnabled && len(accessLogs) == 0 {
		a.addReason(reasonAccessLogDisabled)
	}

	now := s.now()
	switch {
	case gatewayHit && otelHit:
		a.QueryState = queryStateReady
		if truncated || !hasRoot {
			a.QueryState = queryStatePartial // 截断/缺根：可能不完整
			a.Partial = true
		}
	case otelHit:
		// 纯 OTel 命中：网关腿无记录不必然是缺失（东西向 trace 不经过网关）；
		// 访问日志关闭导致网关腿不可得则如实标注部分结果
		a.QueryState = queryStateReady
		if truncated || !hasRoot {
			a.QueryState = queryStatePartial
			a.Partial = true
		}
		if !accessLogEnabled && len(accessLogs) == 0 {
			a.Partial = true
		}
	case gatewayHit:
		// 仅网关腿：OTel 腿无 Span 的原因不可知（未采样/未接入/延迟不可区分），
		// 只报 NO_MATCH，不伪造 NOT_SAMPLED/NO_INSTRUMENTATION
		a.QueryState = queryStatePartial
		a.Partial = true
		if !chDegraded {
			a.addReason(reasonNoMatch)
		}
	default:
		// 双腿均无命中
		if chDegraded {
			a.QueryState = queryStateUnavailable
			a.addReason(reasonNoMatch)
			return a
		}
		a.QueryState = queryStateEmpty
		a.addReason(reasonNoMatch)
		if end != nil && end.Before(now.Add(-traceSpansDefaultWindow)) {
			a.addReason(reasonOutsideRetention)
		}
		if chStatus == chQueryOK {
			latest, hasData, ok := s.latestIngest(ctx)
			a.fillWatermark(latest, hasData, ok, now)
			wmEnd := now
			if end != nil {
				wmEnd = *end
			}
			if ingestionDelayed(latest, hasData, ok, wmEnd, now, ingestLagThreshold) {
				a.addReason(reasonIngestionDelayConfirmed)
			}
		}
		return a
	}
	if chStatus == chQueryOK {
		latest, hasData, ok := s.latestIngest(ctx)
		a.fillWatermark(latest, hasData, ok, now)
	}
	return a
}

// ---------- correlation 构建 ----------

// requestIDResolveRow request_id 在 access_logs 的命中行（关联证据；
// TraceID 可能为空——旧网关/未写入 trace 上下文，如实保留不编造）。
type requestIDResolveRow struct {
	TraceID    string // 合法化后小写 trace_id（非法/缺失为空串）
	OccurredAt time.Time
	WAFAction  string // 归一后动作（空串→ALLOW，与 TraceView 口径一致）
}

// blockEvidence 阻断证据：访问记录 waf_action=BLOCK 或安全事件 action=BLOCK。
// （P0-04 final_decision 未落地前的可证据来源；合流点见本文件头注释。）
func blockEvidence(rows []requestIDResolveRow, eventBlock bool) bool {
	if eventBlock {
		return true
	}
	for _, r := range rows {
		if r.WAFAction == "BLOCK" {
			return true
		}
	}
	return false
}

// latestOccurred 命中行最近发生时间（无行为零值）。
func latestOccurred(rows []requestIDResolveRow) time.Time {
	var t time.Time
	for _, r := range rows {
		if r.OccurredAt.After(t) {
			t = r.OccurredAt
		}
	}
	return t
}

// pendingByRecency 目标可能尚在采集/入库途中：发生时间距 now 在有界余量内，
// 或水位证实最近入库早于发生时间。
func pendingByRecency(occurred time.Time, wmLatest time.Time, wmKnown, wmHasData bool, now time.Time) bool {
	if !occurred.IsZero() && now.Sub(occurred) < correlationPendingMargin {
		return true
	}
	return wmKnown && wmHasData && !occurred.IsZero() && wmLatest.Before(occurred)
}

// correlationCandidatesFromFound 由 CH 命中项构建候选（各自时间/服务/匹配依据）；
// resolved 中未命中的 id 以 access_logs 依据补入（一对多不任取第一条）。
func correlationCandidatesFromFound(resolved []requestIDResolveRow, found []TraceSearchItem) []CorrelationCandidate {
	out := make([]CorrelationCandidate, 0, len(found)+len(resolved))
	hit := map[string]bool{}
	for _, it := range found {
		hit[it.TraceID] = true
		t := it.StartTime.UTC()
		services := it.Services
		if services == nil {
			services = []string{}
		}
		if len(services) > correlationServicesCap {
			services = services[:correlationServicesCap]
		}
		out = append(out, CorrelationCandidate{
			TraceID: it.TraceID, OccurredAt: &t, Services: services, MatchBasis: candidateBasisOTel,
		})
	}
	for _, r := range resolved {
		if r.TraceID == "" || hit[r.TraceID] {
			continue
		}
		t := r.OccurredAt.UTC()
		out = append(out, CorrelationCandidate{
			TraceID: r.TraceID, OccurredAt: &t, Services: []string{}, MatchBasis: candidateBasisAccessLogs,
		})
	}
	return out
}

// correlationFacts correlateRequestIDTrace 的输入证据（全部来自本次真实查询结果/
// 配置/水位读数；无证据字段保持零值）。
type correlationFacts struct {
	AccessLogEnabled bool
	Rows             []requestIDResolveRow // access_logs 命中行（应用约束已下推）
	ResolvedIDs      []string              // 合法 trace_id 集合（小写）
	EventAny         bool                  // security_events 存在该 request_id
	EventBlock       bool                  // security_events 存在 BLOCK 动作
	Found            []TraceSearchItem     // CH 命中项
	CHStatus         chQueryStatus
	WMKnown          bool
	WMHasData        bool
	WMLatest         time.Time
	Now              time.Time
	WindowEnd        time.Time
}

// correlateRequestIDTrace trace-search 按 request_id 检索的关联判定（纯逻辑，
// 五态 + UNKNOWN；判定矩阵见 availability_test.go）。
func correlateRequestIDTrace(f correlationFacts) *Correlation {
	c := &Correlation{
		MatchBasis: matchBasisRequestIDChain,
		Reason:     "",
		Candidates: []CorrelationCandidate{},
	}
	resolvedRows := make([]requestIDResolveRow, 0, len(f.ResolvedIDs))
	for _, r := range f.Rows {
		if r.TraceID != "" {
			resolvedRows = append(resolvedRows, r)
		}
	}

	// 数据面不可用：关联结果无法判定（已解析的候选如实列出，依据为网关侧）
	if f.CHStatus != chQueryOK {
		c.State = correlationUnknown
		c.Reason = "OTel 数据面不可用，无法确认 Span 是否存在"
		c.Candidates = correlationCandidatesFromFound(resolvedRows, nil)
		c.CandidateCount = len(c.Candidates)
		return c
	}

	if len(f.Rows) == 0 {
		switch {
		case f.EventBlock:
			// 无访问记录但有阻断事件：网关终止且未调用源站，无应用 Span 为预期
			c.State = correlationNotExpected
			c.Reason = "安全事件存在阻断动作（BLOCK）证据：请求已被网关终止、未调用源站，无应用 Span 为预期结果"
		case !f.AccessLogEnabled:
			c.State = correlationUnknown
			c.Reason = "访问日志未开启，无法经 access_logs 解析 request_id；已知 trace_id 可用 /apm/traces/{trace_id} 检索"
		case f.EventAny:
			c.State = correlationUnknown
			c.Reason = "存在该 request_id 的安全事件但无访问记录与 trace 上下文，无法建立关联"
		case f.Now.Sub(f.WindowEnd) < correlationPendingMargin:
			c.State = correlationPending
			c.Reason = "检索窗口覆盖最近时刻，访问记录可能尚在采集途中（可有界等待后重试，勿永久轮询）"
		default:
			c.State = correlationNotFound
			c.Reason = "窗口内无该 request_id 的访问记录与安全事件证据"
		}
		return c
	}

	if len(f.ResolvedIDs) == 0 {
		// 有访问记录但无 trace 上下文（旧网关/未写入 trace_id）
		if blockEvidence(f.Rows, f.EventBlock) {
			c.State = correlationNotExpected
			c.Reason = "访问记录/安全事件存在阻断动作（BLOCK）证据：请求已被网关终止、未调用源站，无应用 Span 为预期结果"
			return c
		}
		c.State = correlationUnknown
		c.Reason = "访问记录存在但无 trace 上下文（旧网关或未写入 trace_id）；是否未采样/未接探针无法区分，如实标记未知"
		return c
	}

	c.Candidates = correlationCandidatesFromFound(resolvedRows, f.Found)
	c.CandidateCount = len(c.Candidates)

	if len(f.Found) > 0 {
		if len(f.ResolvedIDs) == 1 && len(f.Found) == 1 {
			c.State = correlationMatched
			c.Reason = "request_id 经 access_logs 解析为唯一 trace_id 并在数据面命中"
		} else {
			c.State = correlationAmbiguous
			c.Reason = "request_id 解析出多个候选 trace（碰撞/重试），返回全部候选，不任取第一条"
		}
		return c
	}

	// 已解析 trace_id 但数据面无 Span
	switch {
	case blockEvidence(f.Rows, f.EventBlock):
		c.State = correlationNotExpected
		c.Reason = "访问记录/安全事件存在阻断动作（BLOCK）证据：请求已被网关终止、未调用源站，无应用 Span 为预期结果"
	case pendingByRecency(latestOccurred(f.Rows), f.WMLatest, f.WMKnown, f.WMHasData, f.Now):
		c.State = correlationPending
		c.Reason = "trace_id 已解析，Span 可能尚在采集/入库途中（可有界等待后重试，勿永久轮询）"
	case latestOccurred(f.Rows).Before(f.Now.Add(-traceSpansDefaultWindow)):
		c.State = correlationNotFound
		c.Reason = "请求发生时间已超出 Span 最长保留期（14 天），数据面记录已不可查"
	default:
		c.State = correlationUnknown
		c.Reason = "trace_id 已解析但数据面无对应 Span；未采样/未接入/已过期无法区分，如实标记未知"
	}
	return c
}

// traceViewFacts correlateTraceView 的输入证据。
type traceViewFacts struct {
	TraceID       string
	GatewayHit    bool      // access_logs 或 security_events 命中
	OTelHit       bool      // OTel span 命中
	BlockEvidence bool      // 网关腿阻断动作证据（waf_action/security_events action=BLOCK）
	OccurredMax   time.Time // 网关腿最近事件时间（无网关腿为零值）
	SpanStartMin  time.Time // 最早 span 开始时间（无 span 为零值）
	SpanServices  []string  // span 服务名（去重）
	CHStatus      chQueryStatus
	WMKnown       bool
	WMHasData     bool
	WMLatest      time.Time
	Now           time.Time
}

// correlateTraceView traces/{id} 的关联判定（trace_id 直达：目标由调用方精确指定）。
func correlateTraceView(f traceViewFacts) *Correlation {
	c := &Correlation{
		MatchBasis: matchBasisTraceIDDirect,
		Reason:     "",
		Candidates: []CorrelationCandidate{},
	}
	switch {
	case f.OTelHit:
		c.State = correlationMatched
		t := f.SpanStartMin.UTC()
		services := f.SpanServices
		if services == nil {
			services = []string{}
		}
		if len(services) > correlationServicesCap {
			services = services[:correlationServicesCap]
		}
		c.Candidates = []CorrelationCandidate{{
			TraceID: f.TraceID, OccurredAt: &t, Services: services, MatchBasis: candidateBasisOTel,
		}}
		c.CandidateCount = 1
		if f.GatewayHit {
			c.Reason = "trace_id 在网关访问记录与 OTel 数据面双侧命中"
		} else {
			c.Reason = "trace_id 在 OTel 数据面命中（网关侧无记录：东西向 trace 不经过网关，或访问日志未开启/已过期）"
		}
	case f.CHStatus != chQueryOK:
		c.State = correlationUnknown
		c.Reason = "OTel 数据面不可用，无法判定 Span 是否存在"
	case f.BlockEvidence:
		c.State = correlationNotExpected
		c.Reason = "访问记录/安全事件存在阻断动作（BLOCK）证据：请求已被网关终止、未调用源站，无应用 Span 为预期结果"
	case !f.GatewayHit:
		c.State = correlationNotFound
		c.Reason = "窗口内无该 trace_id 的网关记录与 OTel Span"
	case pendingByRecency(f.OccurredMax, f.WMLatest, f.WMKnown, f.WMHasData, f.Now):
		c.State = correlationPending
		c.Reason = "网关侧有记录，Span 可能尚在采集/入库途中（可有界等待后重试，勿永久轮询）"
	case f.OccurredMax.Before(f.Now.Add(-traceSpansDefaultWindow)):
		c.State = correlationNotFound
		c.Reason = "网关记录已超出 Span 最长保留期（14 天），数据面记录已不可查"
	default:
		c.State = correlationUnknown
		c.Reason = "网关侧有记录但数据面无对应 Span；未采样/未接入/已过期无法区分，如实标记未知"
	}
	return c
}

// ---------- 异常文本掩码与截断 ----------

const (
	// exceptionMessageMaxRunes 异常消息 rune 上限（纯文本，超出截断并标记）。
	exceptionMessageMaxRunes = 2048
	// exceptionStacktraceMaxRunes 堆栈 rune 上限（纯文本，超出截断并标记）。
	exceptionStacktraceMaxRunes = 8192
)

// exceptionSecretPatterns 异常文本常见凭据形态（纵深防御：exception.message/
// stacktrace 为应用上报原文，出接口前对典型密钥形态掩码；与 spanAttrWhitelist
// 数据最小化纪律同源——头体类值不出接口）。
var exceptionSecretPatterns = []*regexp.Regexp{
	// key=value / key: value 形态的常见凭据键（值部分掩码，键名保留定位上下文；
	// Bearer 方案值须整体匹配，否则只掩到 "Bearer" 一词而泄漏令牌本体）
	regexp.MustCompile(`(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[-_]?key|access[-_]?token|refresh[-_]?token|password|passwd|secret|token)(\s*[:=]\s*)("([^"]*)"|'([^']*)'|Bearer\s+[A-Za-z0-9._~+/=-]+|[^\s,;)\]]+)`),
	// Bearer 令牌形态（无键名前缀的独立出现）
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`),
}

// maskExceptionText 异常文本掩码：凭据形态替换为 ***（键名/方案名保留）。
func maskExceptionText(s string) string {
	s = exceptionSecretPatterns[0].ReplaceAllString(s, "$1$2***")
	return exceptionSecretPatterns[1].ReplaceAllString(s, "Bearer ***")
}

// capRunes 按 rune 上限截断（截断时 truncated=true；输出恒为纯文本，
// 前端只读渲染不负责执行）。
func capRunes(s string, max int) (string, bool) {
	r := []rune(s)
	if len(r) <= max {
		return s, false
	}
	return string(r[:max]), true
}
