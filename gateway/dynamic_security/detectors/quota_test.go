package detectors

import (
	"strconv"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// resetQuotaTrackersForTest 重置配额/对象维度包级追踪器（真实时钟）。
func resetQuotaTrackersForTest() {
	defaultHourlyQuotaTracker = newFixedWindowTracker(time.Hour, quotaMaxKeys, nil)
	defaultDailyQuotaTracker = newFixedWindowTracker(24*time.Hour, quotaMaxKeys, nil)
	defaultObjectRateTracker = newWindowTracker(objectRateMaxKeys, nil)
}

func TestFixedWindowTracker_CountAndReset(t *testing.T) {
	now := time.Date(2026, 9, 11, 10, 30, 0, 0, time.UTC)
	tr := newFixedWindowTracker(time.Hour, 100, func() time.Time { return now })
	for i := 1; i <= 3; i++ {
		if got := tr.add("k"); got != i {
			t.Fatalf("hit %d want count %d, got %d", i, i, got)
		}
	}
	// 窗口内（同一自然小时）继续累计
	now = now.Add(29 * time.Minute)
	if got := tr.add("k"); got != 4 {
		t.Fatalf("same window must accumulate, got %d", got)
	}
	// 跨入下一自然小时重置为 1
	now = now.Add(31 * time.Minute)
	if got := tr.add("k"); got != 1 {
		t.Fatalf("cross window must reset to 1, got %d", got)
	}
}

func TestFixedWindowTracker_DayAlignment(t *testing.T) {
	// 日配额按 UTC 自然日定界：23:59 → 次日 00:00 重置
	now := time.Date(2026, 9, 11, 23, 59, 0, 0, time.UTC)
	tr := newFixedWindowTracker(24*time.Hour, 100, func() time.Time { return now })
	if got := tr.add("k"); got != 1 {
		t.Fatalf("first hit want 1, got %d", got)
	}
	now = now.Add(2 * time.Minute) // 2026-09-12 00:01 UTC
	if got := tr.add("k"); got != 1 {
		t.Fatalf("cross UTC day must reset to 1, got %d", got)
	}
}

func TestFixedWindowTracker_LRUBound(t *testing.T) {
	tr := newFixedWindowTracker(time.Hour, 2, nil)
	tr.add("a")
	tr.add("b")
	tr.add("c") // 驱逐最久未用 a
	if got := tr.add("a"); got != 1 {
		t.Fatalf("evicted key must restart at 1, got %d", got)
	}
}

func TestAPIHourlyQuota_Exceeded(t *testing.T) {
	resetQuotaTrackersForTest()
	const key, ek = "auth:q1", "GET /v1/orders"
	for i := 1; i <= 3; i++ {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckAPIHourlyQuota(ctx, key, ek, 3)
		if ctx.MatchCount() != 0 {
			t.Fatalf("hit %d at/below limit must not match", i)
		}
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckAPIHourlyQuota(ctx, key, ek, 3)
	m := findMatch(ctx, "ratelimit.api_hourly_quota")
	if m == nil {
		t.Fatalf("over limit must match, got %+v", ctx.CopyMatches())
	}
	if m.Category != "RATE_LIMIT" || m.Severity != "HIGH" || m.ScoreDelta != 30 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["limit"] != "3" || m.Evidence["window_count"] != "4" || m.Evidence["window"] != "1h" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
}

func TestAPIHourlyQuota_WindowReset(t *testing.T) {
	now := time.Date(2026, 9, 11, 8, 0, 0, 0, time.UTC)
	defaultHourlyQuotaTracker = newFixedWindowTracker(time.Hour, quotaMaxKeys, func() time.Time { return now })
	const key, ek = "auth:q2", "GET /v1/items"
	for i := 0; i < 3; i++ {
		CheckAPIHourlyQuota(dsctx.New("t", dsctx.DefaultParseLimits()), key, ek, 2)
	}
	// 窗口内已超限
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckAPIHourlyQuota(ctx, key, ek, 2)
	if findMatch(ctx, "ratelimit.api_hourly_quota") == nil {
		t.Fatalf("over limit in window must match")
	}
	// 跨窗重置后不再命中
	now = now.Add(time.Hour)
	ctx2 := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckAPIHourlyQuota(ctx2, key, ek, 2)
	if ctx2.MatchCount() != 0 {
		t.Fatalf("after window reset must not match, got %+v", ctx2.CopyMatches())
	}
}

func TestAPIDailyQuota_Exceeded(t *testing.T) {
	resetQuotaTrackersForTest()
	const key, ek = "auth:q3", "POST /v1/orders"
	for i := 1; i <= 2; i++ {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckAPIDailyQuota(ctx, key, ek, 2)
		if ctx.MatchCount() != 0 {
			t.Fatalf("hit %d at/below limit must not match", i)
		}
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckAPIDailyQuota(ctx, key, ek, 2)
	m := findMatch(ctx, "ratelimit.api_daily_quota")
	if m == nil {
		t.Fatalf("over limit must match, got %+v", ctx.CopyMatches())
	}
	if m.Evidence["window"] != "1d" || m.Evidence["window_count"] != "3" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
}

func TestAPIDailyQuota_WindowReset(t *testing.T) {
	now := time.Date(2026, 9, 11, 23, 0, 0, 0, time.UTC)
	defaultDailyQuotaTracker = newFixedWindowTracker(24*time.Hour, quotaMaxKeys, func() time.Time { return now })
	const key, ek = "auth:q4", "GET /v1/report"
	for i := 0; i < 2; i++ {
		CheckAPIDailyQuota(dsctx.New("t", dsctx.DefaultParseLimits()), key, ek, 1)
	}
	now = now.Add(2 * time.Hour) // 跨 UTC 日
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckAPIDailyQuota(ctx, key, ek, 1)
	if ctx.MatchCount() != 0 {
		t.Fatalf("after UTC day rollover must not match, got %+v", ctx.CopyMatches())
	}
}

func TestAPIQuota_IdentityIsolation(t *testing.T) {
	// 负例：不同身份/端点计数隔离
	resetQuotaTrackersForTest()
	for i := 0; i < 3; i++ {
		CheckAPIHourlyQuota(dsctx.New("t", dsctx.DefaultParseLimits()), "auth:q5", "GET /v1/a", 3)
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckAPIHourlyQuota(ctx, "auth:q6", "GET /v1/a", 3)
	if ctx.MatchCount() != 0 {
		t.Fatalf("different identity must not share counter, got %+v", ctx.CopyMatches())
	}
	ctx2 := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckAPIHourlyQuota(ctx2, "auth:q5", "GET /v1/b", 3)
	if ctx2.MatchCount() != 0 {
		t.Fatalf("different endpoint must not share counter, got %+v", ctx2.CopyMatches())
	}
}

func TestAPIQuota_EmptyIdentitySkip(t *testing.T) {
	resetQuotaTrackersForTest()
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckAPIHourlyQuota(ctx, "", "GET /v1/a", 1)
	CheckAPIDailyQuota(ctx, "auth:q7", "", 1)
	if ctx.MatchCount() != 0 {
		t.Fatalf("empty identity/endpoint must skip, got %+v", ctx.CopyMatches())
	}
}

// objectRateParsed 构造含路径对象段的 Parsed（归一化模板与原始路径对齐切分口径）。
func objectRateParsed(rawPath, normPath string) *parser.Parsed {
	return &parser.Parsed{
		Method:         "GET",
		RawPath:        rawPath,
		NormalizedPath: normPath,
		Query:          map[string]string{},
	}
}

func TestObjectRate_Exceeded(t *testing.T) {
	resetQuotaTrackersForTest()
	p := objectRateParsed("/v1/orders/123", "/v1/orders/{id}")
	for i := 1; i <= 3; i++ {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckObjectRate(ctx, p, "auth:o1", "GET /v1/orders/{id}", "salt", 3)
		if ctx.MatchCount() != 0 {
			t.Fatalf("hit %d at/below limit must not match", i)
		}
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckObjectRate(ctx, p, "auth:o1", "GET /v1/orders/{id}", "salt", 3)
	m := findMatch(ctx, "ratelimit.object_rate")
	if m == nil {
		t.Fatalf("over limit must match, got %+v", ctx.CopyMatches())
	}
	if m.Category != "RATE_LIMIT" || m.Severity != "HIGH" || m.ScoreDelta != 30 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["source"] != "path" || m.Evidence["param"] != "id" || m.Evidence["window"] != "1m" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	// 对象原始值永不入证据
	for k, v := range m.Evidence {
		if v == "123" {
			t.Fatalf("raw object value must not appear in evidence: %s=%s", k, v)
		}
	}
}

func TestObjectRate_PerObjectIsolation(t *testing.T) {
	// 负例：同身份访问不同对象计数隔离（对象值哈希入键）
	resetQuotaTrackersForTest()
	for i := 0; i < 3; i++ {
		CheckObjectRate(dsctx.New("t", dsctx.DefaultParseLimits()),
			objectRateParsed("/v1/orders/100", "/v1/orders/{id}"), "auth:o2", "GET /v1/orders/{id}", "salt", 3)
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckObjectRate(ctx, objectRateParsed("/v1/orders/200", "/v1/orders/{id}"), "auth:o2", "GET /v1/orders/{id}", "salt", 3)
	if ctx.MatchCount() != 0 {
		t.Fatalf("different object must not share counter, got %+v", ctx.CopyMatches())
	}
}

func TestObjectRate_WindowReset(t *testing.T) {
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	defaultObjectRateTracker = newWindowTracker(objectRateMaxKeys, func() time.Time { return now })
	p := objectRateParsed("/v1/orders/123", "/v1/orders/{id}")
	for i := 0; i < 3; i++ {
		CheckObjectRate(dsctx.New("t", dsctx.DefaultParseLimits()), p, "auth:o3", "GET /v1/orders/{id}", "salt", 2)
	}
	now = now.Add(time.Minute)
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckObjectRate(ctx, p, "auth:o3", "GET /v1/orders/{id}", "salt", 2)
	if ctx.MatchCount() != 0 {
		t.Fatalf("after window reset must not match, got %+v", ctx.CopyMatches())
	}
}

func TestObjectRate_NoIdentifierOrIdentitySkip(t *testing.T) {
	resetQuotaTrackersForTest()
	// 静态路径无对象标识 → 不判
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckObjectRate(ctx, objectRateParsed("/v1/orders", "/v1/orders"), "auth:o4", "GET /v1/orders", "salt", 1)
	if ctx.MatchCount() != 0 {
		t.Fatalf("static path must not match, got %+v", ctx.CopyMatches())
	}
	// 空身份 → 跳过
	ctx2 := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckObjectRate(ctx2, objectRateParsed("/v1/orders/1", "/v1/orders/{id}"), "", "GET /v1/orders/{id}", "salt", 1)
	if ctx2.MatchCount() != 0 {
		t.Fatalf("empty identity must skip, got %+v", ctx2.CopyMatches())
	}
}

func TestPaginationSize_Exceeded(t *testing.T) {
	p := &parser.Parsed{Query: map[string]string{"page_size": "500"}}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckPaginationSize(ctx, p, 200)
	m := findMatch(ctx, "ratelimit.page_size_exceeded")
	if m == nil {
		t.Fatalf("over limit must match, got %+v", ctx.CopyMatches())
	}
	if m.Category != "RATE_LIMIT" || m.Severity != "MEDIUM" || m.ScoreDelta != 15 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["param"] != "page_size" || m.Evidence["value"] != "500" || m.Evidence["limit"] != "200" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
}

func TestPaginationSize_NoMatch(t *testing.T) {
	// 负例：恰好等于阈值 / 非数字值 / 非词表参数 / 无 Query
	for _, q := range []map[string]string{
		{"limit": "200"},
		{"limit": "abc"},
		{"foo": "9999"},
	} {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckPaginationSize(ctx, &parser.Parsed{Query: q}, 200)
		if ctx.MatchCount() != 0 {
			t.Fatalf("query %v must not match, got %+v", q, ctx.CopyMatches())
		}
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckPaginationSize(ctx, &parser.Parsed{Query: map[string]string{}}, 200)
	if ctx.MatchCount() != 0 {
		t.Fatalf("empty query must not match")
	}
}

func TestPaginationSize_DefaultLimit(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckPaginationSize(ctx, &parser.Parsed{Query: map[string]string{"limit": strconv.Itoa(DefaultMaxPageSize + 1)}}, 0)
	m := findMatch(ctx, "ratelimit.page_size_exceeded")
	if m == nil || m.Evidence["limit"] != strconv.Itoa(DefaultMaxPageSize) {
		t.Fatalf("over default limit must match with default limit, got %+v", ctx.CopyMatches())
	}
}

func TestBatchSize_Exceeded(t *testing.T) {
	p := &parser.Parsed{Query: map[string]string{"ids": "1,2,3,4"}}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckBatchSize(ctx, p, 3)
	m := findMatch(ctx, "ratelimit.batch_size_exceeded")
	if m == nil {
		t.Fatalf("over limit must match, got %+v", ctx.CopyMatches())
	}
	if m.Category != "RATE_LIMIT" || m.Severity != "HIGH" || m.ScoreDelta != 30 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["param"] != "ids" || m.Evidence["items"] != "4" || m.Evidence["limit"] != "3" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
}

func TestBatchSize_NoMatch(t *testing.T) {
	// 负例：恰好等于阈值 / 单值无逗号 / 空 Query
	for _, q := range []map[string]string{
		{"ids": "1,2,3"},
		{"id": "42"},
	} {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		CheckBatchSize(ctx, &parser.Parsed{Query: q}, 3)
		if ctx.MatchCount() != 0 {
			t.Fatalf("query %v must not match, got %+v", q, ctx.CopyMatches())
		}
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckBatchSize(ctx, &parser.Parsed{Query: map[string]string{}}, 3)
	if ctx.MatchCount() != 0 {
		t.Fatalf("empty query must not match")
	}
}

func TestBatchSize_DefaultLimit(t *testing.T) {
	val := ""
	for i := 1; i <= DefaultMaxBatchSize+1; i++ {
		if i > 1 {
			val += ","
		}
		val += strconv.Itoa(i)
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckBatchSize(ctx, &parser.Parsed{Query: map[string]string{"ids": val}}, 0)
	m := findMatch(ctx, "ratelimit.batch_size_exceeded")
	if m == nil || m.Evidence["limit"] != strconv.Itoa(DefaultMaxBatchSize) {
		t.Fatalf("over default limit must match with default limit, got %+v", ctx.CopyMatches())
	}
}
