// chstore_test.go ClickHouse 数据面单元测试：查询构造（过滤组合/时间窗/上限）、
// 行映射、attributes 白名单过滤、截断标志、DSN 缺失与 CH 故障降级。
// 不依赖真实 CH/PG——CHQuerier/CHRows 以 fake 注入，PG 路径（request_id 解析）
// 由 server/tests 集成测试覆盖。
package apm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ---------- fake CH ----------

// fakeCHRows 预置行的 CHRows（cols 为扫描目标类型标记，仅用于断言列数）。
type fakeCHRows struct {
	scans [][]any // 每行 Scan 的实参值（按查询列序）
	idx   int
	err   error
}

func (r *fakeCHRows) Next() bool { return r.idx < len(r.scans) }

// Scan 将预置值赋给目标指针（按位置；类型必须与查询列序一致）。
func (r *fakeCHRows) Scan(dest ...any) error {
	row := r.scans[r.idx]
	r.idx++
	if len(dest) != len(row) {
		return fmt.Errorf("scan arity = %d, want %d", len(dest), len(row))
	}
	for i, v := range row {
		switch d := dest[i].(type) {
		case *string:
			*d, _ = v.(string)
		case *time.Time:
			*d = v.(time.Time)
		case **time.Time: // nullable 时间列（如 max(Timestamp) 水位）
			switch tv := v.(type) {
			case time.Time:
				t := tv
				*d = &t
			case *time.Time:
				*d = tv
			default:
				*d = nil
			}
		case *uint64:
			*d = v.(uint64)
		case *int64:
			*d = v.(int64)
		case *float64:
			*d = v.(float64)
		case *[]string:
			*d, _ = v.([]string)
		case *map[string]string:
			*d, _ = v.(map[string]string)
		default:
			return fmt.Errorf("unsupported scan dest %T", dest[i])
		}
	}
	return nil
}

func (r *fakeCHRows) Close() error { return nil }
func (r *fakeCHRows) Err() error   { return r.err }

// fakeCHQuerier 按调用序返回预置结果（记录 SQL 与参数供断言）。
type fakeCHQuerier struct {
	queries []string
	args    [][]any
	results []*fakeCHRows
	err     error // 统一注入查询错误
}

func (q *fakeCHQuerier) Query(_ context.Context, query string, args ...any) (CHRows, error) {
	q.queries = append(q.queries, query)
	q.args = append(q.args, args)
	if q.err != nil {
		return nil, q.err
	}
	if len(q.results) == 0 {
		return &fakeCHRows{}, nil
	}
	r := q.results[0]
	q.results = q.results[1:]
	return r, nil
}

func chTestWindow() (time.Time, time.Time) {
	end := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	return end.Add(-time.Hour), end
}

// ---------- 查询构造 ----------

// TestTraceSearchQueryBuilder 过滤组合：时间窗恒在 WHERE；service/trace_ids 入 WHERE；
// min_duration/error 落 HAVING；分页 LIMIT/OFFSET 强制；全部参数化无拼接用户输入。
func TestTraceSearchQueryBuilder(t *testing.T) {
	start, end := chTestWindow()
	tid := strings.Repeat("ab", 16)

	cases := []struct {
		name       string
		filter     TraceSearchFilter
		wantWhere  []string // 必须出现的 WHERE 片段
		wantHaving []string // 必须出现的 HAVING 片段
		notHaving  []string // 不得出现的 HAVING 片段
		wantArgs   int
	}{
		{
			name:      "minimal window only",
			filter:    TraceSearchFilter{Start: start, End: end, Page: 1, PageSize: 20},
			wantWhere: []string{"Timestamp >= ?", "Timestamp < ?"},
			notHaving: []string{"HAVING"},
			wantArgs:  2 + 2, // start,end + limit,offset
		},
		{
			name: "full combo",
			filter: TraceSearchFilter{Start: start, End: end, Service: "order-svc",
				TraceIDs: []string{tid}, MinDurationMS: 250, ErrorOnly: true, Page: 3, PageSize: 50},
			wantWhere:  []string{"Timestamp >= ?", "Timestamp < ?", "ServiceName = ?", "TraceId IN (?)"},
			wantHaving: []string{"HAVING", "wall_ms >= ?", "error_count > 0"},
			wantArgs:   2 + 1 + 1 + 1 + 2,
		},
		{
			name: "multi trace ids",
			filter: TraceSearchFilter{Start: start, End: end,
				TraceIDs: []string{tid, strings.Repeat("cd", 16)}, Page: 1, PageSize: 100},
			wantWhere: []string{"TraceId IN (?)"},
			notHaving: []string{"HAVING"},
			wantArgs:  2 + 1 + 2,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sql, args := buildTraceSearchListQuery(c.filter)
			for _, w := range c.wantWhere {
				if !strings.Contains(sql, w) {
					t.Errorf("SQL missing %q:\n%s", w, sql)
				}
			}
			for _, h := range c.wantHaving {
				if !strings.Contains(sql, h) {
					t.Errorf("SQL missing HAVING %q:\n%s", h, sql)
				}
			}
			for _, h := range c.notHaving {
				if strings.Contains(sql, h) {
					t.Errorf("SQL must not contain %q:\n%s", h, sql)
				}
			}
			if len(args) != c.wantArgs {
				t.Errorf("args = %d, want %d (args=%v)", len(args), c.wantArgs, args)
			}
			if !strings.Contains(sql, "LIMIT ? OFFSET ?") {
				t.Errorf("list SQL must enforce LIMIT/OFFSET:\n%s", sql)
			}
			if !strings.Contains(sql, "GROUP BY TraceId") || !strings.Contains(sql, "ORDER BY start_time DESC") {
				t.Errorf("list SQL must group by trace and order by start_time desc:\n%s", sql)
			}
			// count 查询同口径（where/having 一致，无分页参数）
			countSQL, countArgs := buildTraceSearchCountQuery(c.filter)
			if !strings.HasPrefix(countSQL, "SELECT count() FROM (") {
				t.Errorf("count SQL shape:\n%s", countSQL)
			}
			if len(countArgs) != c.wantArgs-2 {
				t.Errorf("count args = %d, want %d", len(countArgs), c.wantArgs-2)
			}
			// 参数值 sanity：时间窗与过滤值按序绑定
			if args[0] != start || args[1] != end {
				t.Errorf("first args must be window, got %v/%v", args[0], args[1])
			}
		})
	}
}

// TestTraceSpansQueryBuilder 瀑布查询：trace_id 精确 + 强制时间窗 + 上限 maxTraceSpans+1。
func TestTraceSpansQueryBuilder(t *testing.T) {
	start, end := chTestWindow()
	sql, args := buildTraceSpansQuery(strings.Repeat("ab", 16), start, end)
	for _, w := range []string{"TraceId = ?", "Timestamp >= ?", "Timestamp < ?", "LIMIT ?"} {
		if !strings.Contains(sql, w) {
			t.Errorf("spans SQL missing %q:\n%s", w, sql)
		}
	}
	if len(args) != 4 || args[3] != maxTraceSpans+1 {
		t.Errorf("args = %v, want [trace_id start end %d]", args, maxTraceSpans+1)
	}
}

// ---------- 行映射 ----------

// TestScanTraceSearchRow 行映射：耗时换算与根 span 选取（Server 根优先，退任一字符串根）。
func TestScanTraceSearchRow(t *testing.T) {
	start, _ := chTestWindow()
	t.Run("server root preferred", func(t *testing.T) {
		rows := &fakeCHRows{scans: [][]any{{
			strings.Repeat("ab", 16), start, 123.456789, uint64(7), uint64(2),
			[]string{"gw", "order-svc"}, "order-svc", "GET /orders/{id}", "gw", "caddy",
		}}}
		if !rows.Next() {
			t.Fatal("no row")
		}
		it, err := scanTraceSearchRow(rows)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if it.RootService != "order-svc" || it.RootOperation != "GET /orders/{id}" {
			t.Errorf("root = %q/%q, want order-svc/GET /orders/{id}", it.RootService, it.RootOperation)
		}
		if it.DurationMS != 123.457 {
			t.Errorf("duration_ms = %v, want 123.457 (3dp)", it.DurationMS)
		}
		if it.SpanCount != 7 || it.ErrorCount != 2 || len(it.Services) != 2 {
			t.Errorf("counts/services = %d/%d/%v", it.SpanCount, it.ErrorCount, it.Services)
		}
	})
	t.Run("fallback to any root", func(t *testing.T) {
		rows := &fakeCHRows{scans: [][]any{{
			strings.Repeat("cd", 16), start, 5.0, uint64(1), uint64(0),
			[]string{"worker"}, "", "", "worker", "consume",
		}}}
		rows.Next()
		it, err := scanTraceSearchRow(rows)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if it.RootService != "worker" || it.RootOperation != "consume" {
			t.Errorf("root fallback = %q/%q", it.RootService, it.RootOperation)
		}
	})
	t.Run("no root honest empty", func(t *testing.T) {
		rows := &fakeCHRows{scans: [][]any{{
			strings.Repeat("ef", 16), start, 9.0, uint64(2), uint64(0),
			nil, "", "", "", "",
		}}}
		rows.Next()
		it, err := scanTraceSearchRow(rows)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if it.RootService != "" || it.RootOperation != "" {
			t.Errorf("rootless trace must return empty root, got %q/%q", it.RootService, it.RootOperation)
		}
		if it.Services == nil {
			t.Error("services must be empty array not nil")
		}
	})
}

// TestScanOTelSpanRow span 映射：纳秒→毫秒 3 位小数；attributes 白名单过滤。
func TestScanOTelSpanRow(t *testing.T) {
	ts := time.Date(2026, 8, 30, 11, 59, 59, 0, time.UTC)
	rows := &fakeCHRows{scans: [][]any{{
		"span01", "", "order-svc", "GET /orders/{id}", "Server", ts, uint64(1_234_567_890), "Error",
		map[string]string{
			"http.method":                       "GET",
			"http.route":                        "/orders/{id}",
			"http.status_code":                  "500",
			"db.system":                         "postgresql",
			"db.statement":                      "SELECT * FROM users WHERE password='x'", // 严禁透传
			"url.query":                         "token=abc",                              // 严禁透传
			"http.request.header.authorization": "Bearer xyz",                             // 严禁透传
			"jiuzhang.waf_action":               "BLOCK",
			"unknown.future.key":                "dropped",
		},
	}}}
	if !rows.Next() {
		t.Fatal("no row")
	}
	sp, err := scanOTelSpanRow(rows)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if sp.DurationMS != 1234.568 {
		t.Errorf("duration_ms = %v, want 1234.568", sp.DurationMS)
	}
	if sp.StatusCode != "Error" || sp.SpanKind != "Server" || sp.ParentSpanID != "" {
		t.Errorf("span fields = %+v", sp)
	}
	want := map[string]string{
		"http.method": "GET", "http.route": "/orders/{id}", "http.status_code": "500",
		"db.system": "postgresql", "jiuzhang.waf_action": "BLOCK",
	}
	if len(sp.Attributes) != len(want) {
		t.Fatalf("attributes = %v, want keys %v", sp.Attributes, want)
	}
	for k, v := range want {
		if sp.Attributes[k] != v {
			t.Errorf("attribute %q = %q, want %q", k, sp.Attributes[k], v)
		}
	}
	for _, banned := range []string{"db.statement", "url.query", "http.request.header.authorization", "unknown.future.key"} {
		if _, ok := sp.Attributes[banned]; ok {
			t.Errorf("attribute %q must be filtered out", banned)
		}
	}
}

// TestFilterSpanAttributesNil nil attributes → 空 map（JSON 输出 {} 而非 null）。
func TestFilterSpanAttributesNil(t *testing.T) {
	if out := filterSpanAttributes(nil); out == nil || len(out) != 0 {
		t.Errorf("nil attrs = %v, want empty non-nil map", out)
	}
}

// ---------- Store 降级与截断 ----------

// TestSearchTracesNoCH DSN 缺失降级：querier=nil → 空页 + agentless + message。
func TestSearchTracesNoCH(t *testing.T) {
	s := &Store{} // ch 为 nil
	start, end := chTestWindow()
	out, err := s.SearchTraces(context.Background(), TraceSearchFilter{Start: start, End: end, Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("degraded search must not error: %v", err)
	}
	if out.DataSource != dataSourceAgentless || out.Total != 0 || len(out.List) != 0 || out.Message == "" {
		t.Errorf("degraded = %+v", out)
	}
	if out.List == nil {
		t.Error("list must be empty array not nil")
	}
}

// TestSearchTracesCHErrors CH 各阶段故障均降级为空页（不 500）。
func TestSearchTracesCHErrors(t *testing.T) {
	start, end := chTestWindow()
	f := TraceSearchFilter{Start: start, End: end, Page: 1, PageSize: 20}

	t.Run("count query error", func(t *testing.T) {
		s := &Store{ch: &fakeCHQuerier{err: errors.New("ch down")}}
		out, err := s.SearchTraces(context.Background(), f)
		if err != nil || out.DataSource != dataSourceAgentless || out.Total != 0 {
			t.Errorf("count error degrade = %+v, err=%v", out, err)
		}
	})
	t.Run("list query error", func(t *testing.T) {
		q := &fakeCHQuerier{results: []*fakeCHRows{{scans: [][]any{{uint64(3)}}}}}
		// 第二条查询（list）失败
		q2 := &flakySecondQuery{inner: q}
		s := &Store{ch: q2}
		out, err := s.SearchTraces(context.Background(), f)
		if err != nil || out.DataSource != dataSourceAgentless {
			t.Errorf("list error degrade = %+v, err=%v", out, err)
		}
	})
	t.Run("rows iterate error", func(t *testing.T) {
		q := &fakeCHQuerier{results: []*fakeCHRows{
			{scans: [][]any{{uint64(1)}}},
			{err: errors.New("stream broken")},
		}}
		s := &Store{ch: q}
		out, err := s.SearchTraces(context.Background(), f)
		if err != nil || out.DataSource != dataSourceAgentless {
			t.Errorf("iterate error degrade = %+v, err=%v", out, err)
		}
	})
}

// flakySecondQuery 第二次 Query 失败（list 阶段故障注入）。
type flakySecondQuery struct {
	inner *fakeCHQuerier
	n     int
}

func (f *flakySecondQuery) Query(ctx context.Context, query string, args ...any) (CHRows, error) {
	f.n++
	if f.n == 2 {
		return nil, errors.New("ch list down")
	}
	return f.inner.Query(ctx, query, args...)
}

// TestSearchTracesHappyPath count+list 双查询、total 回填与 SQL 参数顺序；
// 第三次查询为 availability 采集水位（max(Timestamp)）。
func TestSearchTracesHappyPath(t *testing.T) {
	start, end := chTestWindow()
	tid := strings.Repeat("ab", 16)
	q := &fakeCHQuerier{results: []*fakeCHRows{
		{scans: [][]any{{uint64(1)}}},
		{scans: [][]any{{tid, start, 42.5, uint64(3), uint64(1),
			[]string{"gw"}, "", "", "gw", "caddy"}}},
		{scans: [][]any{{end}}}, // 采集水位
	}}
	s := &Store{ch: q}
	out, err := s.SearchTraces(context.Background(), TraceSearchFilter{
		Start: start, End: end, Service: "gw", Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if out.DataSource != dataSourceOTel || out.Total != 1 || len(out.List) != 1 {
		t.Fatalf("out = %+v", out)
	}
	if out.List[0].TraceID != tid || out.List[0].RootService != "gw" || out.List[0].DurationMS != 42.5 {
		t.Errorf("item = %+v", out.List[0])
	}
	if len(q.queries) != 3 {
		t.Fatalf("queries = %d, want 3 (count+list+watermark)", len(q.queries))
	}
	// count 无分页参数；list 末两参为 limit/offset
	if got := q.args[1][len(q.args[1])-2:]; got[0] != 20 || got[1] != 0 {
		t.Errorf("list limit/offset = %v", got)
	}
	if !strings.Contains(q.queries[2], "max(Timestamp) FROM apm.otel_traces") {
		t.Errorf("watermark query = %q", q.queries[2])
	}
	// availability：READY + 观测源 OTEL + 水位如实回填
	if out.Availability == nil {
		t.Fatal("availability must be present")
	}
	if out.Availability.QueryState != queryStateReady {
		t.Errorf("query_state = %q, want %q", out.Availability.QueryState, queryStateReady)
	}
	if len(out.Availability.ObservedSources) != 1 || out.Availability.ObservedSources[0] != sourceOTel {
		t.Errorf("observed_sources = %v, want [%s]", out.Availability.ObservedSources, sourceOTel)
	}
	if out.Availability.LastIngestedAt == nil || !out.Availability.LastIngestedAt.Equal(end) {
		t.Errorf("last_ingested_at = %v, want %v", out.Availability.LastIngestedAt, end)
	}
}

// TestQueryTraceSpansTruncated 截断标志：返回 maxTraceSpans+1 行时 truncated=true 且只保留 1000。
func TestQueryTraceSpansTruncated(t *testing.T) {
	ts := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	scans := make([][]any, 0, maxTraceSpans+1)
	for i := 0; i < maxTraceSpans+1; i++ {
		scans = append(scans, []any{
			fmt.Sprintf("span%04d", i), "", "svc", "op", "Internal", ts, uint64(1000), "Ok",
			map[string]string{},
		})
	}
	s := &Store{ch: &fakeCHQuerier{results: []*fakeCHRows{{scans: scans}}}}
	spans, truncated, status := s.queryTraceSpans(context.Background(), strings.Repeat("ab", 16), ts.Add(-time.Hour), ts)
	if status != chQueryOK {
		t.Errorf("status = %v, want chQueryOK", status)
	}
	if !truncated {
		t.Error("1001 rows must set truncated=true")
	}
	if len(spans) != maxTraceSpans {
		t.Errorf("spans = %d, want %d", len(spans), maxTraceSpans)
	}
}

// TestQueryTraceSpansDegraded CH 未配置/故障时返回空且不截断，状态如实区分。
func TestQueryTraceSpansDegraded(t *testing.T) {
	ts := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	s := &Store{}
	spans, truncated, status := s.queryTraceSpans(context.Background(), strings.Repeat("ab", 16), ts.Add(-time.Hour), ts)
	if truncated || len(spans) != 0 || spans == nil {
		t.Errorf("no-CH spans = %v/%v", spans, truncated)
	}
	if status != chQueryNotConfigured {
		t.Errorf("no-CH status = %v, want chQueryNotConfigured", status)
	}
	s = &Store{ch: &fakeCHQuerier{err: errors.New("ch down")}}
	spans, truncated, status = s.queryTraceSpans(context.Background(), strings.Repeat("ab", 16), ts.Add(-time.Hour), ts)
	if truncated || len(spans) != 0 {
		t.Errorf("ch-error spans = %v/%v", spans, truncated)
	}
	if status != chQueryFailed {
		t.Errorf("ch-error status = %v, want chQueryFailed", status)
	}
}
