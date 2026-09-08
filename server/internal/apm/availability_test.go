// availability_test.go P1-01 A2：availability/correlation 判定矩阵、采集水位缓存、
// 异常文本掩码与截断、SQL/异常 trace 级定位的查询构造与行映射、handler 参数校验。
package apm

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fixedNow 单测时间源（消除 time.Now 抖动）。
func fixedNow(now time.Time) func() time.Time { return func() time.Time { return now } }

// ---------- chAvailability 判定矩阵 ----------

// TestCHAvailabilityMatrix availability 构建：query_state/reason_codes/观测源/水位
// 全部从本次真实查询结果与水位读数判定；未知时间字段恒为 null 而非伪造 now。
func TestCHAvailabilityMatrix(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	start, end := now.Add(-time.Hour), now
	threshold := defaultIngestLagSeconds * time.Second
	ctx := context.Background()

	t.Run("not configured", func(t *testing.T) {
		s := &Store{nowFunc: fixedNow(now)}
		a := s.chAvailability(ctx, chQueryNotConfigured, false, start, end, threshold)
		if a.QueryState != queryStateUnavailable {
			t.Errorf("query_state = %q, want UNAVAILABLE", a.QueryState)
		}
		if len(a.ReasonCodes) != 1 || a.ReasonCodes[0] != reasonStorageNotConfigured {
			t.Errorf("reason_codes = %v, want [STORAGE_NOT_CONFIGURED]", a.ReasonCodes)
		}
		if a.LastIngestedAt != nil || a.EstimatedLagMS != nil || a.LastCollectedAt != nil {
			t.Error("watermark fields must be null when storage not configured")
		}
		if a.ObservedSources == nil || len(a.ObservedSources) != 0 {
			t.Errorf("observed_sources = %v, want empty array", a.ObservedSources)
		}
	})

	t.Run("query failed", func(t *testing.T) {
		s := &Store{nowFunc: fixedNow(now)}
		a := s.chAvailability(ctx, chQueryFailed, false, start, end, threshold)
		if a.QueryState != queryStateUnavailable {
			t.Errorf("query_state = %q, want UNAVAILABLE", a.QueryState)
		}
		if len(a.ReasonCodes) != 1 || a.ReasonCodes[0] != reasonStorageUnavailable {
			t.Errorf("reason_codes = %v, want [STORAGE_UNAVAILABLE]", a.ReasonCodes)
		}
	})

	t.Run("ready matched with watermark", func(t *testing.T) {
		q := &fakeCHQuerier{results: []*fakeCHRows{{scans: [][]any{{end}}}}}
		s := &Store{ch: q, nowFunc: fixedNow(now)}
		a := s.chAvailability(ctx, chQueryOK, true, start, end, threshold)
		if a.QueryState != queryStateReady {
			t.Errorf("query_state = %q, want READY", a.QueryState)
		}
		if len(a.ObservedSources) != 1 || a.ObservedSources[0] != sourceOTel {
			t.Errorf("observed_sources = %v, want [OTEL]", a.ObservedSources)
		}
		if len(a.ReasonCodes) != 0 {
			t.Errorf("reason_codes = %v, want empty", a.ReasonCodes)
		}
		if a.LastIngestedAt == nil || !a.LastIngestedAt.Equal(end) {
			t.Errorf("last_ingested_at = %v, want %v", a.LastIngestedAt, end)
		}
		if a.EstimatedLagMS == nil || *a.EstimatedLagMS != 0 {
			t.Errorf("estimated_lag_ms = %v, want 0", a.EstimatedLagMS)
		}
	})

	t.Run("empty no match", func(t *testing.T) {
		q := &fakeCHQuerier{results: []*fakeCHRows{{scans: [][]any{{end}}}}}
		s := &Store{ch: q, nowFunc: fixedNow(now)}
		a := s.chAvailability(ctx, chQueryOK, false, start, end, threshold)
		if a.QueryState != queryStateEmpty {
			t.Errorf("query_state = %q, want EMPTY", a.QueryState)
		}
		if len(a.ReasonCodes) != 1 || a.ReasonCodes[0] != reasonNoMatch {
			t.Errorf("reason_codes = %v, want [NO_MATCH]", a.ReasonCodes)
		}
		if len(a.ObservedSources) != 0 {
			t.Errorf("observed_sources = %v, want empty", a.ObservedSources)
		}
	})

	t.Run("empty outside retention", func(t *testing.T) {
		oldEnd := now.Add(-15 * 24 * time.Hour) // 超出分层 TTL 上限 14 天
		q := &fakeCHQuerier{results: []*fakeCHRows{{scans: [][]any{{oldEnd}}}}}
		s := &Store{ch: q, nowFunc: fixedNow(now)}
		a := s.chAvailability(ctx, chQueryOK, false, oldEnd.Add(-time.Hour), oldEnd, threshold)
		if a.QueryState != queryStateEmpty {
			t.Errorf("query_state = %q, want EMPTY", a.QueryState)
		}
		if !hasReason(a, reasonNoMatch) || !hasReason(a, reasonOutsideRetention) {
			t.Errorf("reason_codes = %v, want NO_MATCH+OUTSIDE_RETENTION", a.ReasonCodes)
		}
	})

	t.Run("empty ingestion delayed", func(t *testing.T) {
		// 水位证实：最近入库早于窗口终点且滞后超阈（300s）
		latest := end.Add(-10 * time.Minute)
		q := &fakeCHQuerier{results: []*fakeCHRows{{scans: [][]any{{latest}}}}}
		s := &Store{ch: q, nowFunc: fixedNow(now)}
		a := s.chAvailability(ctx, chQueryOK, false, start, end, threshold)
		if a.QueryState != queryStateEmpty {
			t.Errorf("query_state = %q, want EMPTY", a.QueryState)
		}
		if !hasReason(a, reasonNoMatch) || !hasReason(a, reasonIngestionDelayConfirmed) {
			t.Errorf("reason_codes = %v, want NO_MATCH+INGESTION_DELAY_CONFIRMED", a.ReasonCodes)
		}
		if a.EstimatedLagMS == nil || *a.EstimatedLagMS != int64(10*60*1000) {
			t.Errorf("estimated_lag_ms = %v, want 600000", a.EstimatedLagMS)
		}
	})

	t.Run("no ingestion delay when watermark covers window", func(t *testing.T) {
		latest := end.Add(-time.Minute) // 滞后 60s < 300s 阈值
		q := &fakeCHQuerier{results: []*fakeCHRows{{scans: [][]any{{latest}}}}}
		s := &Store{ch: q, nowFunc: fixedNow(now)}
		a := s.chAvailability(ctx, chQueryOK, false, start, end, threshold)
		if hasReason(a, reasonIngestionDelayConfirmed) {
			t.Errorf("reason_codes = %v, must not contain INGESTION_DELAY_CONFIRMED", a.ReasonCodes)
		}
	})

	t.Run("watermark read failure leaves null", func(t *testing.T) {
		q := &fakeCHQuerier{err: errors.New("ch down")}
		s := &Store{ch: q, nowFunc: fixedNow(now)}
		a := s.chAvailability(ctx, chQueryOK, true, start, end, threshold)
		if a.QueryState != queryStateReady {
			t.Errorf("query_state = %q, want READY（业务查询本身成功）", a.QueryState)
		}
		if a.LastIngestedAt != nil || a.EstimatedLagMS != nil {
			t.Error("watermark unreadable: fields must stay null（严禁伪造 now）")
		}
	})

	t.Run("extra reasons propagate", func(t *testing.T) {
		q := &fakeCHQuerier{results: []*fakeCHRows{{scans: [][]any{{end}}}}}
		s := &Store{ch: q, nowFunc: fixedNow(now)}
		a := s.chAvailability(ctx, chQueryOK, false, start, end, threshold, reasonAccessLogDisabled)
		if !hasReason(a, reasonAccessLogDisabled) || !hasReason(a, reasonNoMatch) {
			t.Errorf("reason_codes = %v, want ACCESS_LOG_DISABLED+NO_MATCH", a.ReasonCodes)
		}
	})
}

func hasReason(a *Availability, code string) bool {
	for _, c := range a.ReasonCodes {
		if c == code {
			return true
		}
	}
	return false
}

// ---------- latestIngest 水位缓存 ----------

// TestLatestIngestCache 短 TTL 缓存：TTL 内同查询器不重复读数；查询器身份变化
// （DSN 热更新重建）缓存失效；读数失败不缓存（下次重试，不缓存坏水位）。
func TestLatestIngestCache(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	latest := now.Add(-time.Minute)

	q := &fakeCHQuerier{results: []*fakeCHRows{{scans: [][]any{{latest}}}}}
	s := &Store{ch: q, nowFunc: fixedNow(now)}

	got, has, ok := s.latestIngest(ctx)
	if !ok || !has || !got.Equal(latest) {
		t.Fatalf("first read = %v/%v/%v", got, has, ok)
	}
	if len(q.queries) != 1 {
		t.Fatalf("queries = %d, want 1", len(q.queries))
	}
	// TTL 内第二次调用命中缓存（nowFunc 固定 ⇒ 距 fetchedAt 为 0 < 30s）
	got, has, ok = s.latestIngest(ctx)
	if !ok || !has || !got.Equal(latest) {
		t.Fatalf("cached read = %v/%v/%v", got, has, ok)
	}
	if len(q.queries) != 1 {
		t.Errorf("queries = %d, want 1 (cache hit within TTL)", len(q.queries))
	}

	// 查询器身份变化（热更新重建）→ 缓存失效重读
	q2 := &fakeCHQuerier{results: []*fakeCHRows{{scans: [][]any{{latest}}}}}
	s.ch = q2
	if _, _, ok := s.latestIngest(ctx); !ok {
		t.Fatal("read after querier swap failed")
	}
	if len(q2.queries) != 1 {
		t.Errorf("new querier queries = %d, want 1 (identity invalidates cache)", len(q2.queries))
	}

	// 读数失败不缓存：修复后重试成功
	q3 := &fakeCHQuerier{err: errors.New("ch down")}
	s.ch = q3
	if _, _, ok := s.latestIngest(ctx); ok {
		t.Error("failing querier must return ok=false")
	}
	q3.err = nil
	q3.results = []*fakeCHRows{{scans: [][]any{{latest}}}}
	if _, _, ok := s.latestIngest(ctx); !ok {
		t.Error("retry after failure must succeed（失败不缓存）")
	}
	if len(q3.queries) != 2 {
		t.Errorf("queries = %d, want 2 (failure not cached)", len(q3.queries))
	}

	// 表空（max(Timestamp) 为 NULL）：hasData=false 且缓存（非故障）
	q4 := &fakeCHQuerier{results: []*fakeCHRows{{scans: [][]any{{(*time.Time)(nil)}}}}}
	s.ch = q4
	_, has, ok = s.latestIngest(ctx)
	if !ok || has {
		t.Errorf("empty table = has/%v ok/%v, want false/true", has, ok)
	}
	if _, _, ok := s.latestIngest(ctx); !ok {
		t.Error("cached empty read failed")
	}
	if len(q4.queries) != 1 {
		t.Errorf("queries = %d, want 1 (empty result cached)", len(q4.queries))
	}
}

// ---------- correlateRequestIDTrace 判定矩阵 ----------

// TestCorrelateRequestIDTrace request_id 检索的关联判定（纯函数，五态 + UNKNOWN）；
// 证据纪律：NOT_EXPECTED 仅 BLOCK 动作证据；PENDING 仅近期/水位证实；其余如实 UNKNOWN。
func TestCorrelateRequestIDTrace(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	tid1 := strings.Repeat("ab", 16)
	tid2 := strings.Repeat("cd", 16)
	recent := now.Add(-time.Minute)          // 采集余量内
	old := now.Add(-2 * time.Hour)           // 超余量但在保留期内
	ancient := now.Add(-15 * 24 * time.Hour) // 超分层 TTL 上限

	foundItem := func(tid string, at time.Time) TraceSearchItem {
		return TraceSearchItem{TraceID: tid, StartTime: at, Services: []string{"gw"}}
	}
	base := func() correlationFacts {
		return correlationFacts{AccessLogEnabled: true, CHStatus: chQueryOK, Now: now, WindowEnd: now.Add(-time.Hour)}
	}

	t.Run("ch degraded is unknown with gateway candidates", func(t *testing.T) {
		f := base()
		f.CHStatus = chQueryFailed
		f.Rows = []requestIDResolveRow{{TraceID: tid1, OccurredAt: recent, WAFAction: "ALLOW"}}
		f.ResolvedIDs = []string{tid1}
		c := correlateRequestIDTrace(f)
		if c.State != correlationUnknown || c.Reason == "" {
			t.Errorf("state = %q reason %q, want UNKNOWN+reason", c.State, c.Reason)
		}
		if c.MatchBasis != matchBasisRequestIDChain {
			t.Errorf("match_basis = %q", c.MatchBasis)
		}
		if c.CandidateCount != 1 || len(c.Candidates) != 1 ||
			c.Candidates[0].MatchBasis != candidateBasisAccessLogs || c.Candidates[0].TraceID != tid1 {
			t.Errorf("candidates = %+v, want single access_logs candidate", c.Candidates)
		}
	})

	t.Run("no rows with block event is not expected", func(t *testing.T) {
		f := base()
		f.EventAny, f.EventBlock = true, true
		c := correlateRequestIDTrace(f)
		if c.State != correlationNotExpected {
			t.Errorf("state = %q, want NOT_EXPECTED（网关终止未调源站）", c.State)
		}
	})

	t.Run("no rows and access log disabled is unknown", func(t *testing.T) {
		f := base()
		f.AccessLogEnabled = false
		c := correlateRequestIDTrace(f)
		if c.State != correlationUnknown {
			t.Errorf("state = %q, want UNKNOWN（无法解析）", c.State)
		}
	})

	t.Run("no rows with event only is unknown", func(t *testing.T) {
		f := base()
		f.EventAny = true
		c := correlateRequestIDTrace(f)
		if c.State != correlationUnknown {
			t.Errorf("state = %q, want UNKNOWN", c.State)
		}
	})

	t.Run("no rows recent window is pending", func(t *testing.T) {
		f := base()
		f.WindowEnd = now.Add(-time.Minute)
		c := correlateRequestIDTrace(f)
		if c.State != correlationPending {
			t.Errorf("state = %q, want PENDING（采集途中）", c.State)
		}
	})

	t.Run("no rows old window is not found", func(t *testing.T) {
		c := correlateRequestIDTrace(base())
		if c.State != correlationNotFound {
			t.Errorf("state = %q, want NOT_FOUND", c.State)
		}
	})

	t.Run("rows without trace context and block is not expected", func(t *testing.T) {
		f := base()
		f.Rows = []requestIDResolveRow{{TraceID: "", OccurredAt: recent, WAFAction: "BLOCK"}}
		c := correlateRequestIDTrace(f)
		if c.State != correlationNotExpected {
			t.Errorf("state = %q, want NOT_EXPECTED（访问记录阻断证据）", c.State)
		}
	})

	t.Run("rows without trace context is unknown", func(t *testing.T) {
		f := base()
		f.Rows = []requestIDResolveRow{{TraceID: "", OccurredAt: recent, WAFAction: "ALLOW"}}
		c := correlateRequestIDTrace(f)
		if c.State != correlationUnknown {
			t.Errorf("state = %q, want UNKNOWN（不伪造未采样结论）", c.State)
		}
	})

	t.Run("single resolved and single found is matched", func(t *testing.T) {
		f := base()
		f.Rows = []requestIDResolveRow{{TraceID: tid1, OccurredAt: recent, WAFAction: "ALLOW"}}
		f.ResolvedIDs = []string{tid1}
		f.Found = []TraceSearchItem{foundItem(tid1, recent)}
		c := correlateRequestIDTrace(f)
		if c.State != correlationMatched || c.Reason == "" {
			t.Errorf("state = %q, want MATCHED", c.State)
		}
		if c.CandidateCount != 1 || c.Candidates[0].MatchBasis != candidateBasisOTel ||
			c.Candidates[0].OccurredAt == nil || !c.Candidates[0].OccurredAt.Equal(recent) {
			t.Errorf("candidates = %+v", c.Candidates)
		}
	})

	t.Run("multiple resolved is ambiguous with all candidates", func(t *testing.T) {
		f := base()
		f.Rows = []requestIDResolveRow{
			{TraceID: tid1, OccurredAt: recent, WAFAction: "ALLOW"},
			{TraceID: tid2, OccurredAt: old, WAFAction: "ALLOW"},
		}
		f.ResolvedIDs = []string{tid1, tid2}
		f.Found = []TraceSearchItem{foundItem(tid1, recent)}
		c := correlateRequestIDTrace(f)
		if c.State != correlationAmbiguous {
			t.Errorf("state = %q, want AMBIGUOUS（不任取第一条）", c.State)
		}
		if c.CandidateCount != 2 || len(c.Candidates) != 2 {
			t.Fatalf("candidates = %+v, want 2", c.Candidates)
		}
		if c.Candidates[0].MatchBasis != candidateBasisOTel || c.Candidates[0].TraceID != tid1 {
			t.Errorf("candidate[0] = %+v, want OTel/tid1", c.Candidates[0])
		}
		if c.Candidates[1].MatchBasis != candidateBasisAccessLogs || c.Candidates[1].TraceID != tid2 {
			t.Errorf("candidate[1] = %+v, want access_logs/tid2", c.Candidates[1])
		}
	})

	t.Run("resolved but unfound with block is not expected", func(t *testing.T) {
		f := base()
		f.Rows = []requestIDResolveRow{{TraceID: tid1, OccurredAt: old, WAFAction: "BLOCK"}}
		f.ResolvedIDs = []string{tid1}
		c := correlateRequestIDTrace(f)
		if c.State != correlationNotExpected {
			t.Errorf("state = %q, want NOT_EXPECTED", c.State)
		}
	})

	t.Run("resolved but unfound recent is pending", func(t *testing.T) {
		f := base()
		f.Rows = []requestIDResolveRow{{TraceID: tid1, OccurredAt: recent, WAFAction: "ALLOW"}}
		f.ResolvedIDs = []string{tid1}
		c := correlateRequestIDTrace(f)
		if c.State != correlationPending {
			t.Errorf("state = %q, want PENDING", c.State)
		}
	})

	t.Run("resolved but unfound pending by watermark", func(t *testing.T) {
		f := base()
		f.Rows = []requestIDResolveRow{{TraceID: tid1, OccurredAt: old, WAFAction: "ALLOW"}}
		f.ResolvedIDs = []string{tid1}
		f.WMKnown, f.WMHasData = true, true
		f.WMLatest = old.Add(-time.Minute) // 水位证实最近入库早于请求发生
		c := correlateRequestIDTrace(f)
		if c.State != correlationPending {
			t.Errorf("state = %q, want PENDING（水位证实）", c.State)
		}
	})

	t.Run("resolved but unfound beyond retention is not found", func(t *testing.T) {
		f := base()
		f.Rows = []requestIDResolveRow{{TraceID: tid1, OccurredAt: ancient, WAFAction: "ALLOW"}}
		f.ResolvedIDs = []string{tid1}
		c := correlateRequestIDTrace(f)
		if c.State != correlationNotFound {
			t.Errorf("state = %q, want NOT_FOUND（超保留期）", c.State)
		}
	})

	t.Run("resolved but unfound otherwise is unknown", func(t *testing.T) {
		f := base()
		f.Rows = []requestIDResolveRow{{TraceID: tid1, OccurredAt: old, WAFAction: "ALLOW"}}
		f.ResolvedIDs = []string{tid1}
		c := correlateRequestIDTrace(f)
		if c.State != correlationUnknown || c.Reason == "" {
			t.Errorf("state = %q, want UNKNOWN+reason（未采样/未接入不可区分）", c.State)
		}
		if c.CandidateCount != 1 || c.Candidates[0].MatchBasis != candidateBasisAccessLogs {
			t.Errorf("candidates = %+v, want access_logs candidate preserved", c.Candidates)
		}
	})
}

// ---------- correlateTraceView 判定矩阵 ----------

// TestCorrelateTraceView traces/{id} 的关联判定（trace_id 直达，恒携带）。
func TestCorrelateTraceView(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	tid := strings.Repeat("ab", 16)
	recent := now.Add(-time.Minute)
	old := now.Add(-2 * time.Hour)
	ancient := now.Add(-15 * 24 * time.Hour)
	base := func() traceViewFacts {
		return traceViewFacts{TraceID: tid, CHStatus: chQueryOK, Now: now}
	}

	t.Run("both legs hit is matched", func(t *testing.T) {
		f := base()
		f.GatewayHit, f.OTelHit = true, true
		f.SpanStartMin, f.SpanServices = recent, []string{"gw"}
		c := correlateTraceView(f)
		if c.State != correlationMatched || c.MatchBasis != matchBasisTraceIDDirect {
			t.Errorf("state = %q basis = %q", c.State, c.MatchBasis)
		}
		if c.CandidateCount != 1 || len(c.Candidates) != 1 ||
			c.Candidates[0].TraceID != tid || c.Candidates[0].MatchBasis != candidateBasisOTel ||
			c.Candidates[0].OccurredAt == nil || !c.Candidates[0].OccurredAt.Equal(recent) {
			t.Errorf("candidates = %+v", c.Candidates)
		}
		if !strings.Contains(c.Reason, "双侧命中") {
			t.Errorf("reason = %q, want 双侧命中", c.Reason)
		}
	})

	t.Run("otel only is matched", func(t *testing.T) {
		f := base()
		f.OTelHit = true
		f.SpanStartMin = recent
		c := correlateTraceView(f)
		if c.State != correlationMatched {
			t.Errorf("state = %q, want MATCHED（东西向 trace 不经过网关）", c.State)
		}
	})

	t.Run("ch degraded is unknown", func(t *testing.T) {
		f := base()
		f.CHStatus = chQueryNotConfigured
		c := correlateTraceView(f)
		if c.State != correlationUnknown || c.Reason == "" {
			t.Errorf("state = %q, want UNKNOWN", c.State)
		}
		if len(c.Candidates) != 0 || c.Candidates == nil {
			t.Errorf("candidates = %+v, want empty array", c.Candidates)
		}
	})

	t.Run("block evidence is not expected", func(t *testing.T) {
		f := base()
		f.GatewayHit, f.BlockEvidence = true, true
		f.OccurredMax = old
		c := correlateTraceView(f)
		if c.State != correlationNotExpected {
			t.Errorf("state = %q, want NOT_EXPECTED", c.State)
		}
	})

	t.Run("no evidence at all is not found", func(t *testing.T) {
		c := correlateTraceView(base())
		if c.State != correlationNotFound {
			t.Errorf("state = %q, want NOT_FOUND", c.State)
		}
	})

	t.Run("gateway hit recent is pending", func(t *testing.T) {
		f := base()
		f.GatewayHit = true
		f.OccurredMax = recent
		c := correlateTraceView(f)
		if c.State != correlationPending {
			t.Errorf("state = %q, want PENDING", c.State)
		}
	})

	t.Run("gateway hit beyond retention is not found", func(t *testing.T) {
		f := base()
		f.GatewayHit = true
		f.OccurredMax = ancient
		c := correlateTraceView(f)
		if c.State != correlationNotFound {
			t.Errorf("state = %q, want NOT_FOUND（超保留期）", c.State)
		}
	})

	t.Run("gateway hit old otherwise is unknown", func(t *testing.T) {
		f := base()
		f.GatewayHit = true
		f.OccurredMax = old
		c := correlateTraceView(f)
		if c.State != correlationUnknown {
			t.Errorf("state = %q, want UNKNOWN（不伪造未采样结论）", c.State)
		}
	})
}

// ---------- 异常文本掩码与截断 ----------

// TestMaskExceptionText 凭据形态掩码：key=value/key: value、引号值、Bearer 令牌
// （含 "Authorization: Bearer <token>" 整体掩码，不只掩 "Bearer" 一词）；普通文本不误伤。
func TestMaskExceptionText(t *testing.T) {
	cases := []struct{ in, want string }{
		{"dial failed password=hunter2 retry", "dial failed password=*** retry"},
		{"password: hunter2", "password: ***"},
		{"Authorization: Bearer abcdefgh12345678", "Authorization: ***"},
		{"Bearer abcdefgh12345678", "Bearer ***"},
		{"token: 'secret value'", "token: ***"},
		{`x-api-key="abcdef123"`, `x-api-key=***`},
		{"api_key=abc123, next", "api_key=***, next"},
		{"normal error: connection refused", "normal error: connection refused"},
		{"", ""},
	}
	for _, c := range cases {
		if got := maskExceptionText(c.in); got != c.want {
			t.Errorf("mask(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// 掩码后不得再出现令牌本体
	out := maskExceptionText("GET /api Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 failed")
	if strings.Contains(out, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") {
		t.Errorf("token leaked in %q", out)
	}
}

// TestCapRunes rune 上限截断（多字节字符按 rune 计；截断标记如实返回）。
func TestCapRunes(t *testing.T) {
	if s, tr := capRunes("abc", 5); s != "abc" || tr {
		t.Errorf("short = %q/%v", s, tr)
	}
	if s, tr := capRunes("abcde", 5); s != "abcde" || tr {
		t.Errorf("exact = %q/%v", s, tr)
	}
	long := strings.Repeat("密", 2100)
	out, tr := capRunes(long, 2048)
	if !tr || len([]rune(out)) != 2048 {
		t.Errorf("truncated = %d runes/%v, want 2048/true", len([]rune(out)), tr)
	}
}

// ---------- SQL/异常 trace 级定位：查询构造与行映射 ----------

// TestSQLTraceQueryBuilder trace 级 SQL 定位查询：单 trace 精确 + Client DB span +
// 强制时间窗 + service/db_system 下推 + LIMIT/OFFSET；严禁 SELECT 原始 db.statement
// （db.statement 仅出现于 hex(MD5()) 指纹与非空谓词——§11.1 数据最小化纪律）。
func TestSQLTraceQueryBuilder(t *testing.T) {
	start, end := chTestWindow()
	tid := strings.Repeat("ab", 16)
	f := SQLFilter{Start: start, End: end, Service: "order-svc", DBSystem: "postgresql",
		TraceID: tid, Sort: "calls", Page: 2, PageSize: 50}

	sql, args := buildSQLTraceListQuery(f)
	for _, w := range []string{
		"FROM apm.otel_traces", "TraceId = ?", "SpanKind = 'Client'",
		"SpanAttributes['db.statement'] != ''", "Timestamp >= ?", "Timestamp < ?",
		"ServiceName = ?", "SpanAttributes['db.system'] = ?",
		"hex(MD5(SpanAttributes['db.statement'])) AS sql_fingerprint",
		"GROUP BY db_system, sql_fingerprint", "LIMIT ? OFFSET ?",
	} {
		if !strings.Contains(sql, w) {
			t.Errorf("list query missing %q:\n%s", w, sql)
		}
	}
	if strings.Count(sql, "SpanAttributes['db.statement']") != 2 {
		t.Errorf("db.statement must appear exactly twice (fingerprint + non-empty predicate):\n%s", sql)
	}
	if len(args) != 7 || args[0] != tid || args[1] != start || args[2] != end ||
		args[3] != "order-svc" || args[4] != "postgresql" || args[5] != 50 || args[6] != 50 {
		t.Errorf("args = %v", args)
	}

	countSQL, countArgs := buildSQLTraceCountQuery(f)
	if !strings.Contains(countSQL, "SELECT count() FROM (") || !strings.Contains(countSQL, "TraceId = ?") {
		t.Errorf("count query:\n%s", countSQL)
	}
	if len(countArgs) != 5 {
		t.Errorf("count args = %v, want 5 (no pagination)", countArgs)
	}
}

// TestExceptionsTraceQueryBuilder trace 级异常定位查询：单 trace + ARRAY JOIN Events +
// exception 事件 + 强制时间窗；指纹与聚合表同式（hex(MD5(stacktrace 原文))）可对照。
func TestExceptionsTraceQueryBuilder(t *testing.T) {
	start, end := chTestWindow()
	tid := strings.Repeat("ab", 16)
	f := ExceptionsFilter{Start: start, End: end, Service: "order-svc", TraceID: tid, Page: 1, PageSize: 20}

	sql, args := buildExceptionsTraceListQuery(f)
	for _, w := range []string{
		"FROM apm.otel_traces", "ARRAY JOIN Events", "TraceId = ?", "Events.Name = 'exception'",
		"Timestamp >= ?", "Timestamp < ?", "ServiceName = ?",
		"Events.Attributes['exception.message']", "Events.Attributes['exception.stacktrace']",
		"hex(MD5(Events.Attributes['exception.stacktrace'])) AS fingerprint",
		"ORDER BY event_ts ASC", "LIMIT ? OFFSET ?",
	} {
		if !strings.Contains(sql, w) {
			t.Errorf("list query missing %q:\n%s", w, sql)
		}
	}
	if len(args) != 6 || args[0] != tid || args[5] != 0 {
		t.Errorf("args = %v", args)
	}

	countSQL, countArgs := buildExceptionsTraceCountQuery(f)
	if !strings.Contains(countSQL, "ARRAY JOIN Events") || !strings.Contains(countSQL, "SELECT count()") {
		t.Errorf("count query:\n%s", countSQL)
	}
	if len(countArgs) != 4 {
		t.Errorf("count args = %v, want 4 (no pagination)", countArgs)
	}
}

// TestScanExceptionTraceItem trace 级异常事件行映射：message/stacktrace 凭据掩码 +
// rune 上限截断（截断标记如实返回）；occurred_at 归一 UTC。
func TestScanExceptionTraceItem(t *testing.T) {
	tid := strings.Repeat("ab", 16)
	occ := time.Date(2026, 8, 30, 11, 30, 0, 0, time.UTC)

	rows := &fakeCHRows{scans: [][]any{{
		tid, "span01", "order-svc", occ, "java.lang.RuntimeException",
		"connect failed password=hunter2", "at com.x.Foo Bearer abcdefgh12345678\nat com.x.Bar", "fp01",
	}}}
	if !rows.Next() {
		t.Fatal("no row")
	}
	it, err := scanExceptionTraceItem(rows)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if it.TraceID != tid || it.SpanID != "span01" || it.ServiceName != "order-svc" || it.Fingerprint != "fp01" {
		t.Errorf("identity = %+v", it)
	}
	if it.ExceptionMessage != "connect failed password=***" {
		t.Errorf("message = %q, want masked", it.ExceptionMessage)
	}
	if strings.Contains(it.Stacktrace, "abcdefgh12345678") {
		t.Errorf("stacktrace leaked token: %q", it.Stacktrace)
	}
	if it.MessageTruncated || it.StacktraceTruncated {
		t.Error("short text must not be marked truncated")
	}
	if !it.OccurredAt.Equal(occ) {
		t.Errorf("occurred_at = %v", it.OccurredAt)
	}

	// 超长文本截断 + 标记
	rows = &fakeCHRows{scans: [][]any{{
		tid, "span02", "svc", occ, "Err",
		strings.Repeat("x", 3000), strings.Repeat("密", 9000), "fp02",
	}}}
	rows.Next()
	it, err = scanExceptionTraceItem(rows)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !it.MessageTruncated || len([]rune(it.ExceptionMessage)) != exceptionMessageMaxRunes {
		t.Errorf("message = %d runes/%v", len([]rune(it.ExceptionMessage)), it.MessageTruncated)
	}
	if !it.StacktraceTruncated || len([]rune(it.Stacktrace)) != exceptionStacktraceMaxRunes {
		t.Errorf("stacktrace = %d runes/%v", len([]rune(it.Stacktrace)), it.StacktraceTruncated)
	}
}

// ---------- Store 级：trace 模式与降级 availability ----------

// TestListSQLTraceMode trace_id 模式走 trace 级查询（非窗口聚合），match 语义字段
// 与 availability 如实回填。
func TestListSQLTraceMode(t *testing.T) {
	start, end := chTestWindow()
	tid := strings.Repeat("ab", 16)
	q := &fakeCHQuerier{results: []*fakeCHRows{
		{scans: [][]any{{uint64(1)}}},
		{scans: [][]any{{"postgresql", "fp01", "shop", "SELECT", uint64(2), uint64(0), 3.0, 5.0, []string{tid}}}},
		{scans: [][]any{{end}}}, // 采集水位
	}}
	s := &Store{ch: q}
	out, err := s.ListSQLFingerprints(context.Background(), SQLFilter{
		Start: start, End: end, TraceID: tid, Sort: "p95_ms", Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if out.MatchMode != matchModeTraceExact || out.MatchNote == "" || out.TraceID != tid {
		t.Errorf("match fields = %q/%q/%q", out.MatchMode, out.MatchNote, out.TraceID)
	}
	if out.Total != 1 || len(out.List) != 1 || out.DataSource != dataSourceOTel {
		t.Errorf("out = %+v", out)
	}
	if len(q.queries) != 3 {
		t.Fatalf("queries = %d, want 3 (count+list+watermark)", len(q.queries))
	}
	if !strings.Contains(q.queries[0], "TraceId = ?") || !strings.Contains(q.queries[1], "SpanKind = 'Client'") {
		t.Errorf("trace-mode queries:\n%s\n%s", q.queries[0], q.queries[1])
	}
	if out.Availability == nil || out.Availability.QueryState != queryStateReady {
		t.Errorf("availability = %+v, want READY", out.Availability)
	}

	// 窗口聚合模式对照：match_mode=window_aggregate
	q2 := &fakeCHQuerier{results: []*fakeCHRows{
		{scans: [][]any{{uint64(0)}}},
		{scans: [][]any{{end}}},
	}}
	s2 := &Store{ch: q2}
	out2, err := s2.ListSQLFingerprints(context.Background(), SQLFilter{Start: start, End: end, Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if out2.MatchMode != matchModeWindowAggregate || out2.MatchNote != matchNoteWindowAggregate || out2.TraceID != "" {
		t.Errorf("window match fields = %q/%q/%q", out2.MatchMode, out2.MatchNote, out2.TraceID)
	}
}

// TestListExceptionsTraceMode trace_id 模式直读 exception 事件（结果在
// trace_exceptions，list 恒空数组），文本掩码与 availability 如实回填。
func TestListExceptionsTraceMode(t *testing.T) {
	start, end := chTestWindow()
	tid := strings.Repeat("ab", 16)
	q := &fakeCHQuerier{results: []*fakeCHRows{
		{scans: [][]any{{uint64(1)}}},
		{scans: [][]any{{tid, "span01", "svc", start, "RuntimeException",
			"boom password=hunter2", "stack", "fp01"}}},
		{scans: [][]any{{end}}},
	}}
	s := &Store{ch: q}
	out, err := s.ListExceptions(context.Background(), ExceptionsFilter{
		Start: start, End: end, TraceID: tid, Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if out.MatchMode != matchModeTraceExact || out.MatchNote != matchNoteTraceExactExceptions {
		t.Errorf("match fields = %q/%q", out.MatchMode, out.MatchNote)
	}
	if len(out.TraceExceptions) != 1 || len(out.List) != 0 {
		t.Fatalf("trace_exceptions = %d, list = %d", len(out.TraceExceptions), len(out.List))
	}
	if strings.Contains(out.TraceExceptions[0].ExceptionMessage, "hunter2") {
		t.Errorf("message not masked: %q", out.TraceExceptions[0].ExceptionMessage)
	}
	if !strings.Contains(q.queries[1], "ARRAY JOIN Events") {
		t.Errorf("trace-mode query:\n%s", q.queries[1])
	}
	if out.Availability == nil || out.Availability.QueryState != queryStateReady {
		t.Errorf("availability = %+v, want READY", out.Availability)
	}
}

// TestSearchTracesDegradedAvailability CH 未配置/故障降级：availability 如实区分
// STORAGE_NOT_CONFIGURED / STORAGE_UNAVAILABLE；无 request_id 时 correlation 缺省。
func TestSearchTracesDegradedAvailability(t *testing.T) {
	start, end := chTestWindow()
	s := &Store{}
	out, err := s.SearchTraces(context.Background(), TraceSearchFilter{Start: start, End: end, Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if out.DataSource != dataSourceAgentless || out.Availability == nil {
		t.Fatalf("out = %+v", out)
	}
	if out.Availability.QueryState != queryStateUnavailable ||
		!hasReason(out.Availability, reasonStorageNotConfigured) {
		t.Errorf("availability = %+v, want UNAVAILABLE+STORAGE_NOT_CONFIGURED", out.Availability)
	}
	if out.Correlation != nil {
		t.Errorf("correlation = %+v, want nil（无 request_id 不经解析链）", out.Correlation)
	}

	s = &Store{ch: &fakeCHQuerier{err: errors.New("ch down")}}
	out, err = s.SearchTraces(context.Background(), TraceSearchFilter{Start: start, End: end, Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if out.Availability == nil || out.Availability.QueryState != queryStateUnavailable ||
		!hasReason(out.Availability, reasonStorageUnavailable) {
		t.Errorf("availability = %+v, want UNAVAILABLE+STORAGE_UNAVAILABLE", out.Availability)
	}
}

// ---------- handler 级：application_id / trace_id 校验与响应形状 ----------

// TestTraceSearchApplicationID application_id 校验三态：非法 UUID → 400；应用不存在 → 400
// （不静默忽略约束，与 endpoints 空页先例不同——任务书冻结口径）；合法 → 约束下推 store。
func TestTraceSearchApplicationID(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.traces.read")

	// 非法 UUID → 400，不触达 store
	rr := doGet(t, mux, "/api/v1/apm/trace-search", url.Values{"application_id": {"not-a-uuid"}})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid uuid status = %d, want 400, body: %s", rr.Code, rr.Body.String())
	}
	if repo.searchFilter != nil {
		t.Error("store must not be called on invalid application_id")
	}

	// 应用不存在 → 400（如实报错而非静默放弃约束）
	repo.notFound = true
	appID := uuid.New()
	rr = doGet(t, mux, "/api/v1/apm/trace-search", url.Values{"application_id": {appID.String()}})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing app status = %d, want 400, body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "应用不存在") {
		t.Errorf("body = %s, want 应用不存在 message", rr.Body.String())
	}
	if repo.searchFilter != nil {
		t.Error("store must not be called for missing application")
	}

	// 合法 → 200，约束与 availability 证据下推过滤器
	repo.notFound = false
	rr = doGet(t, mux, "/api/v1/apm/trace-search", url.Values{"application_id": {appID.String()}})
	if rr.Code != http.StatusOK {
		t.Fatalf("valid app status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if repo.searchFilter == nil || repo.searchFilter.ApplicationID == nil || *repo.searchFilter.ApplicationID != appID {
		t.Fatalf("filter application_id = %+v, want %v", repo.searchFilter, appID)
	}
	if repo.appCodeID != appID {
		t.Errorf("app existence check id = %v, want %v", repo.appCodeID, appID)
	}
	if repo.searchFilter.IngestLagThreshold != defaultIngestLagSeconds*time.Second {
		t.Errorf("ingest lag threshold = %v, want default %ds", repo.searchFilter.IngestLagThreshold, defaultIngestLagSeconds)
	}
}

// TestSQLTraceIDValidation sql trace_id：非法 → 400 不触达 store；合法归一小写下推。
func TestSQLTraceIDValidation(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.sql.read")

	rr := doGet(t, mux, "/api/v1/apm/sql", url.Values{"trace_id": {"xyz"}})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid trace_id status = %d, want 400", rr.Code)
	}
	if repo.sqlFilter != nil {
		t.Error("store must not be called on invalid trace_id")
	}

	valid := strings.ToUpper(strings.Repeat("ab", 16))
	rr = doGet(t, mux, "/api/v1/apm/sql", url.Values{"trace_id": {valid}})
	if rr.Code != http.StatusOK {
		t.Fatalf("valid trace_id status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if repo.sqlFilter == nil || repo.sqlFilter.TraceID != strings.Repeat("ab", 16) {
		t.Errorf("filter trace_id = %+v, want lowercased", repo.sqlFilter)
	}
	if repo.sqlFilter.IngestLagThreshold != defaultIngestLagSeconds*time.Second {
		t.Errorf("ingest lag threshold = %v, want default", repo.sqlFilter.IngestLagThreshold)
	}
}

// TestExceptionsTraceIDValidation exceptions trace_id：非法 → 400；合法下推。
func TestExceptionsTraceIDValidation(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.traces.read")

	rr := doGet(t, mux, "/api/v1/apm/exceptions", url.Values{"trace_id": {"not-hex"}})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid trace_id status = %d, want 400", rr.Code)
	}
	if repo.exceptionsFilter != nil {
		t.Error("store must not be called on invalid trace_id")
	}

	rr = doGet(t, mux, "/api/v1/apm/exceptions", url.Values{"trace_id": {strings.Repeat("cd", 16)}})
	if rr.Code != http.StatusOK {
		t.Fatalf("valid trace_id status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if repo.exceptionsFilter == nil || repo.exceptionsFilter.TraceID != strings.Repeat("cd", 16) {
		t.Errorf("filter = %+v", repo.exceptionsFilter)
	}
}

// TestTraceSearchResponseShape 响应形状：旧字段（list/data_source/message/page）保留，
// availability 恒携带；无 request_id 时 correlation 缺省（omitempty 不序列化 null）。
func TestTraceSearchResponseShape(t *testing.T) {
	repo := &fakeRepo{search: &TraceSearchData{
		List: []TraceSearchItem{}, Total: 0, Page: 1, PageSize: 20,
		DataSource: dataSourceAgentless, Message: "APM_CLICKHOUSE_DSN 未配置",
		Availability: &Availability{QueryState: queryStateUnavailable,
			ReasonCodes: []string{reasonStorageNotConfigured}, ObservedSources: []string{}},
	}}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.traces.read")

	rr := doGet(t, mux, "/api/v1/apm/trace-search", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	data := dataOf(t, rr)
	if data["data_source"] != "agentless" {
		t.Errorf("data_source = %v, want agentless（旧字段保留）", data["data_source"])
	}
	if _, ok := data["message"]; !ok {
		t.Error("message field missing（旧字段保留）")
	}
	if _, ok := data["list"]; !ok {
		t.Error("list field missing（旧字段保留）")
	}
	avail, ok := data["availability"].(map[string]interface{})
	if !ok {
		t.Fatalf("availability missing: %s", rr.Body.String())
	}
	if avail["query_state"] != queryStateUnavailable {
		t.Errorf("query_state = %v, want UNAVAILABLE", avail["query_state"])
	}
	if _, ok := data["correlation"]; ok {
		t.Errorf("correlation must be omitted without request_id: %s", rr.Body.String())
	}
}

// TestTraceViewAvailabilityParams traces/{id} 把访问日志开关与采集滞后阈值传入 store
// （availability/correlation 判定证据）；阈值越界回退默认。
func TestTraceViewAvailabilityParams(t *testing.T) {
	valid := strings.Repeat("ab", 16)

	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{accessLogEnabled: true, ingestLagSeconds: 600}, 10*time.Minute), "apm.traces.read")
	rr := doGet(t, mux, "/api/v1/apm/traces/"+valid, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if !repo.traceArgs.accessLogEnabled {
		t.Error("accessLogEnabled must be true（fakeSettings 开启）")
	}
	if repo.traceArgs.ingestLagThreshold != 600*time.Second {
		t.Errorf("ingestLagThreshold = %v, want 600s", repo.traceArgs.ingestLagThreshold)
	}

	// 越界阈值（< 30s）回退默认 300s
	repo2 := &fakeRepo{}
	mux2 := newTestMux(NewHandler(repo2, fakeSettings{ingestLagSeconds: 5}, 10*time.Minute), "apm.traces.read")
	rr = doGet(t, mux2, "/api/v1/apm/traces/"+valid, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if repo2.traceArgs.ingestLagThreshold != defaultIngestLagSeconds*time.Second {
		t.Errorf("out-of-range threshold = %v, want default %ds", repo2.traceArgs.ingestLagThreshold, defaultIngestLagSeconds)
	}
}
