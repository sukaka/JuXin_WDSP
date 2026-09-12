// chstore_aggregates_test.go 阶段3 第一批查询单测：SQL 指纹/异常指纹/服务依赖的
// 查询构造（过滤组合/时间窗/上限）、行映射、DSN 缺失与 CH 故障降级、依赖边截断。
// 不依赖真实 CH——CHQuerier/CHRows fake 复用 chstore_test.go。
package apm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// ---------- SQL 指纹查询构造 ----------

// TestSQLQueryBuilder 过滤组合：时间窗恒在两侧子查询 WHERE；service/db_system 同步下推；
// sort 白名单映射；分页 LIMIT/OFFSET 强制；指纹公式与物化视图一致且不出原始 statement。
func TestSQLQueryBuilder(t *testing.T) {
	start, end := chTestWindow()

	cases := []struct {
		name      string
		filter    SQLFilter
		wantOrder string
		wantArgs  int // list 参数数（agg 子查询 + raw 子查询 + limit/offset）
	}{
		{"minimal", SQLFilter{Start: start, End: end, Sort: "p95_ms", Page: 1, PageSize: 20},
			"p95_ms DESC", 2 + 2 + 2},
		{"full combo", SQLFilter{Start: start, End: end, Service: "order-svc", DBSystem: "postgresql",
			Sort: "calls", Page: 2, PageSize: 50},
			"calls DESC", 4 + 4 + 2},
		{"avg sort", SQLFilter{Start: start, End: end, Sort: "avg_ms", Page: 1, PageSize: 100},
			"avg_ms DESC", 2 + 2 + 2},
		{"unknown sort falls back", SQLFilter{Start: start, End: end, Sort: "bogus", Page: 1, PageSize: 20},
			"p95_ms DESC", 2 + 2 + 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sql, args := buildSQLListQuery(c.filter)
			for _, w := range []string{
				"FROM apm.apm_sql_minutes", "Minute >= ?", "Minute < ?",
				"FROM apm.otel_traces", "Timestamp >= ?", "Timestamp < ?",
				"hex(MD5(SpanAttributes['db.statement']))",
				"LIMIT ? OFFSET ?", "ORDER BY " + c.wantOrder,
			} {
				if !strings.Contains(sql, w) {
					t.Errorf("SQL missing %q:\n%s", w, sql)
				}
			}
			// 严禁透出原始 statement（只允许出现在指纹化表达式中）
			if strings.Contains(sql, "SpanAttributes['db.statement']) AS") ||
				strings.Contains(sql, "SELECT SpanAttributes['db.statement']") {
				t.Errorf("SQL must not select raw db.statement:\n%s", sql)
			}
			if len(args) != c.wantArgs {
				t.Errorf("args = %d, want %d (args=%v)", len(args), c.wantArgs, args)
			}
			if args[0] != start || args[1] != end {
				t.Errorf("first args must be agg window, got %v/%v", args[0], args[1])
			}
			if got := args[len(args)-2:]; got[0] != c.filter.PageSize || got[1] != (c.filter.Page-1)*c.filter.PageSize {
				t.Errorf("limit/offset = %v", got)
			}
			// count 查询同过滤口径（仅聚合表，无分页参数）
			countSQL, countArgs := buildSQLCountQuery(c.filter)
			if !strings.HasPrefix(countSQL, "SELECT count() FROM (") ||
				!strings.Contains(countSQL, "apm.apm_sql_minutes") {
				t.Errorf("count SQL shape:\n%s", countSQL)
			}
			if strings.Contains(countSQL, "otel_traces") {
				t.Errorf("count must not scan raw table:\n%s", countSQL)
			}
			wantCount := 2 // 聚合子查询窗口参数
			if c.filter.Service != "" {
				wantCount++
			}
			if c.filter.DBSystem != "" {
				wantCount++
			}
			if len(countArgs) != wantCount {
				t.Errorf("count args = %d, want %d", len(countArgs), wantCount)
			}
		})
	}

	// service/db_system 过滤值按序绑定且两侧一致
	f := SQLFilter{Start: start, End: end, Service: "svc-a", DBSystem: "mysql", Sort: "p95_ms", Page: 1, PageSize: 20}
	_, args := buildSQLListQuery(f)
	// 顺序：agg(start,end,service,db) + raw(start,end,service,db) + limit/offset
	wantSeq := []any{start, end, "svc-a", "mysql", start, end, "svc-a", "mysql", 20, 0}
	if len(args) != len(wantSeq) {
		t.Fatalf("args = %v", args)
	}
	for i, w := range wantSeq {
		if args[i] != w {
			t.Errorf("args[%d] = %v, want %v", i, args[i], w)
		}
	}
}

// TestScanSQLRow 行映射：计数 UInt64→int64；耗时 3 位小数；空示例数组非 nil。
func TestScanSQLRow(t *testing.T) {
	rows := &fakeCHRows{scans: [][]any{{
		"postgresql", "0123456789abcdef0123456789abcdef", "shop", "SELECT",
		uint64(120), uint64(3), 45.1234567, 88.9999, []string{strings.Repeat("ab", 16)},
	}}}
	if !rows.Next() {
		t.Fatal("no row")
	}
	it, err := scanSQLRow(rows)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if it.DBSystem != "postgresql" || it.Namespace != "shop" || it.Operation != "SELECT" {
		t.Errorf("identity = %+v", it)
	}
	if it.Calls != 120 || it.ErrorCount != 3 {
		t.Errorf("counts = %d/%d", it.Calls, it.ErrorCount)
	}
	if it.AvgMS != 45.123 || it.P95MS != 89 {
		t.Errorf("latency = %v/%v, want 45.123/89", it.AvgMS, it.P95MS)
	}
	if len(it.SampleTraceIDs) != 1 {
		t.Errorf("samples = %v", it.SampleTraceIDs)
	}

	rows = &fakeCHRows{scans: [][]any{{
		"redis", "ff", "", "", uint64(1), uint64(0), 0.0001, 0.0, nil,
	}}}
	rows.Next()
	it, err = scanSQLRow(rows)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if it.SampleTraceIDs == nil {
		t.Error("sample_trace_ids must be empty array not nil")
	}
}

// ---------- SQL/异常 Store 降级 ----------

// TestStage3NoCH DSN 缺失降级：querier=nil → 空数据 + agentless + 提示。
func TestStage3NoCH(t *testing.T) {
	s := &Store{} // ch 为 nil
	start, end := chTestWindow()

	sqlOut, err := s.ListSQLFingerprints(context.Background(), SQLFilter{Start: start, End: end, Sort: "p95_ms", Page: 1, PageSize: 20})
	if err != nil || sqlOut.DataSource != dataSourceAgentless || sqlOut.Total != 0 || len(sqlOut.List) != 0 || sqlOut.Message == "" {
		t.Errorf("sql degrade = %+v, err=%v", sqlOut, err)
	}
	if sqlOut.List == nil {
		t.Error("sql list must be empty array not nil")
	}

	excOut, err := s.ListExceptions(context.Background(), ExceptionsFilter{Start: start, End: end, Page: 1, PageSize: 20})
	if err != nil || excOut.DataSource != dataSourceAgentless || excOut.Total != 0 || len(excOut.List) != 0 || excOut.Message == "" {
		t.Errorf("exceptions degrade = %+v, err=%v", excOut, err)
	}
	if excOut.List == nil {
		t.Error("exceptions list must be empty array not nil")
	}

	depOut, err := s.ListDependencies(context.Background(), DependenciesFilter{Start: start, End: end})
	if err != nil || depOut.DataSource != dataSourceAgentless || len(depOut.Edges) != 0 || depOut.Note == "" {
		t.Errorf("dependencies degrade = %+v, err=%v", depOut, err)
	}
	if depOut.Edges == nil {
		t.Error("edges must be empty array not nil")
	}
}

// TestStage3CHErrors CH 各阶段故障均降级为空数据（不 500）。
func TestStage3CHErrors(t *testing.T) {
	start, end := chTestWindow()

	t.Run("sql count error", func(t *testing.T) {
		s := &Store{ch: &fakeCHQuerier{err: errors.New("ch down")}}
		out, err := s.ListSQLFingerprints(context.Background(), SQLFilter{Start: start, End: end, Page: 1, PageSize: 20})
		if err != nil || out.DataSource != dataSourceAgentless || out.Total != 0 {
			t.Errorf("degrade = %+v, err=%v", out, err)
		}
	})
	t.Run("sql list scan error", func(t *testing.T) {
		q := &fakeCHQuerier{results: []*fakeCHRows{
			{scans: [][]any{{uint64(1)}}},
			{scans: [][]any{{"only-one-col"}}}, // 列数不符触发 scan 错误
		}}
		s := &Store{ch: q}
		out, err := s.ListSQLFingerprints(context.Background(), SQLFilter{Start: start, End: end, Page: 1, PageSize: 20})
		if err != nil || out.DataSource != dataSourceAgentless {
			t.Errorf("degrade = %+v, err=%v", out, err)
		}
	})
	t.Run("exceptions list iterate error", func(t *testing.T) {
		q := &fakeCHQuerier{results: []*fakeCHRows{
			{scans: [][]any{{uint64(1)}}},
			{err: errors.New("stream broken")},
		}}
		s := &Store{ch: q}
		out, err := s.ListExceptions(context.Background(), ExceptionsFilter{Start: start, End: end, Page: 1, PageSize: 20})
		if err != nil || out.DataSource != dataSourceAgentless {
			t.Errorf("degrade = %+v, err=%v", out, err)
		}
	})
	t.Run("dependencies query error", func(t *testing.T) {
		s := &Store{ch: &fakeCHQuerier{err: errors.New("ch down")}}
		out, err := s.ListDependencies(context.Background(), DependenciesFilter{Start: start, End: end})
		if err != nil || out.DataSource != dataSourceAgentless || out.Note == "" {
			t.Errorf("degrade = %+v, err=%v", out, err)
		}
	})
}

// TestSQLHappyPath count+list 双查询、total 回填与 DataSource=otel。
func TestSQLHappyPath(t *testing.T) {
	start, end := chTestWindow()
	tid := strings.Repeat("ab", 16)
	q := &fakeCHQuerier{results: []*fakeCHRows{
		{scans: [][]any{{uint64(1)}}},
		{scans: [][]any{{"postgresql", "fp01", "shop", "SELECT", uint64(10), uint64(1),
			12.5, 40.0, []string{tid}}}},
	}}
	s := &Store{ch: q}
	out, err := s.ListSQLFingerprints(context.Background(), SQLFilter{
		Start: start, End: end, Service: "order-svc", Sort: "calls", Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if out.DataSource != dataSourceOTel || out.Total != 1 || len(out.List) != 1 {
		t.Fatalf("out = %+v", out)
	}
	row := out.List[0]
	if row.SQLFingerprint != "fp01" || row.Calls != 10 || row.ErrorCount != 1 || row.P95MS != 40 {
		t.Errorf("row = %+v", row)
	}
	if len(q.queries) != 3 {
		t.Fatalf("queries = %d, want 3 (count+list+watermark)", len(q.queries))
	}
}

// TestSQLZeroTotal total=0 时只发 count 查询（不发 list）；随后一次采集水位查询（availability 用）。
func TestSQLZeroTotal(t *testing.T) {
	start, end := chTestWindow()
	q := &fakeCHQuerier{results: []*fakeCHRows{{scans: [][]any{{uint64(0)}}}}}
	s := &Store{ch: q}
	out, err := s.ListSQLFingerprints(context.Background(), SQLFilter{Start: start, End: end, Page: 1, PageSize: 20})
	if err != nil || out.Total != 0 || out.DataSource != dataSourceOTel || out.Message != "" {
		t.Errorf("out = %+v, err=%v", out, err)
	}
	if len(q.queries) != 2 {
		t.Errorf("queries = %d, want 2 (count+watermark)", len(q.queries))
	}
	if out.Availability == nil || out.Availability.QueryState != queryStateEmpty {
		t.Errorf("availability = %+v, want EMPTY", out.Availability)
	}
}

// ---------- 异常指纹查询构造与行映射 ----------

// TestExceptionsQueryBuilder 两级聚合：内层 countMerge/anyMerge 按排序键合并，
// 外层 groupUniqArray 收集服务与示例；时间窗恒在 WHERE；service 下推；LIMIT/OFFSET 强制。
func TestExceptionsQueryBuilder(t *testing.T) {
	start, end := chTestWindow()
	f := ExceptionsFilter{Start: start, End: end, Service: "order-svc", Page: 3, PageSize: 50}

	sql, args := buildExceptionsListQuery(f)
	for _, w := range []string{
		"FROM apm.apm_exception_fingerprints", "Minute >= ?", "Minute < ?",
		"ServiceName = ?", "countMerge(SampleCount)", "anyMerge(ExampleTraceId)",
		"groupUniqArray(16)(svc)", "groupUniqArray(3)(example)",
		"GROUP BY ExceptionType, Fingerprint", "ORDER BY count DESC", "LIMIT ? OFFSET ?",
	} {
		if !strings.Contains(sql, w) {
			t.Errorf("SQL missing %q:\n%s", w, sql)
		}
	}
	// 不出堆栈原文：只允许出现在指纹化表达式之外的地方绝不出现
	if strings.Contains(sql, "exception.stacktrace']) AS") {
		t.Errorf("SQL must not select raw stacktrace:\n%s", sql)
	}
	// 参数：start,end,service + limit,offset
	if len(args) != 5 || args[0] != start || args[1] != end || args[2] != "order-svc" ||
		args[3] != 50 || args[4] != 100 {
		t.Errorf("args = %v", args)
	}

	countSQL, countArgs := buildExceptionsCountQuery(f)
	if !strings.HasPrefix(countSQL, "SELECT count() FROM (") {
		t.Errorf("count SQL shape:\n%s", countSQL)
	}
	if len(countArgs) != 3 {
		t.Errorf("count args = %v, want 3", countArgs)
	}
}

// TestScanExceptionRow 行映射：分钟桶时间与数组字段；空数组非 nil。
func TestScanExceptionRow(t *testing.T) {
	first := time.Date(2026, 8, 30, 11, 3, 0, 0, time.UTC)
	last := time.Date(2026, 8, 30, 11, 47, 0, 0, time.UTC)
	rows := &fakeCHRows{scans: [][]any{{
		"java.lang.RuntimeException", "abc123", uint64(42), first, last,
		[]string{"order-svc", "payment-svc"}, []string{strings.Repeat("ab", 16)},
	}}}
	if !rows.Next() {
		t.Fatal("no row")
	}
	it, err := scanExceptionRow(rows)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if it.ExceptionType != "java.lang.RuntimeException" || it.Count != 42 {
		t.Errorf("row = %+v", it)
	}
	if !it.FirstSeenAt.Equal(first) || !it.LastSeenAt.Equal(last) {
		t.Errorf("seen = %v/%v", it.FirstSeenAt, it.LastSeenAt)
	}
	if len(it.AffectedServices) != 2 || len(it.SampleTraceIDs) != 1 {
		t.Errorf("arrays = %v/%v", it.AffectedServices, it.SampleTraceIDs)
	}

	rows = &fakeCHRows{scans: [][]any{{"", "ff", uint64(1), first, last, nil, nil}}}
	rows.Next()
	it, err = scanExceptionRow(rows)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if it.AffectedServices == nil || it.SampleTraceIDs == nil {
		t.Error("arrays must be empty array not nil")
	}
}

// ---------- 服务依赖查询构造与行映射 ----------

// TestDependenciesQueryBuilder CLIENT/PRODUCER 口径、属性优先级链、无对端剔除、
// 时间窗强制、LIMIT 上限+1 截断探测。
func TestDependenciesQueryBuilder(t *testing.T) {
	start, end := chTestWindow()
	f := DependenciesFilter{Start: start, End: end, Service: "order-svc"}

	sql, args := buildDependenciesQuery(f)
	for _, w := range []string{
		"FROM apm.otel_traces", "SpanKind IN ('Client', 'Producer')",
		"Timestamp >= ?", "Timestamp < ?", "ServiceName = ?",
		"SpanAttributes['db.system']", "SpanAttributes['messaging.system']",
		"SpanAttributes['peer.service']", "SpanAttributes['server.address']",
		"HAVING target != ''", "LIMIT ?",
	} {
		if !strings.Contains(sql, w) {
			t.Errorf("SQL missing %q:\n%s", w, sql)
		}
	}
	if len(args) != 4 || args[0] != start || args[1] != end || args[2] != "order-svc" ||
		args[3] != maxDependencyEdges+1 {
		t.Errorf("args = %v, want [start end service %d]", args, maxDependencyEdges+1)
	}
}

// TestScanDependencyEdge 行映射：错误率/耗时 3 位小数。
func TestScanDependencyEdge(t *testing.T) {
	rows := &fakeCHRows{scans: [][]any{{
		"order-svc", "postgresql/shop", "db", uint64(200), 0.04567, 8.12345,
	}}}
	if !rows.Next() {
		t.Fatal("no row")
	}
	e, err := scanDependencyEdge(rows)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if e.Source != "order-svc" || e.Target != "postgresql/shop" || e.TargetType != "db" {
		t.Errorf("edge = %+v", e)
	}
	if e.Calls != 200 || e.ErrorRate != 0.046 || e.AvgMS != 8.123 {
		t.Errorf("metrics = %d/%v/%v", e.Calls, e.ErrorRate, e.AvgMS)
	}
}

// TestListDependenciesTruncated 截断：返回 maxDependencyEdges+1 行时只保留上限并在 note 标注。
func TestListDependenciesTruncated(t *testing.T) {
	scans := make([][]any, 0, maxDependencyEdges+1)
	for i := 0; i < maxDependencyEdges+1; i++ {
		scans = append(scans, []any{"svc", "target", "service", uint64(1), 0.0, 1.0})
	}
	s := &Store{ch: &fakeCHQuerier{results: []*fakeCHRows{{scans: scans}}}}
	start, end := chTestWindow()
	out, err := s.ListDependencies(context.Background(), DependenciesFilter{Start: start, End: end})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(out.Edges) != maxDependencyEdges {
		t.Errorf("edges = %d, want %d", len(out.Edges), maxDependencyEdges)
	}
	if !strings.Contains(out.Note, "上限") || !strings.Contains(out.Note, "派生") {
		t.Errorf("note must mark truncation and derivation, got %q", out.Note)
	}
}

// TestListDependenciesNote 正常返回时 note 如实标注客户端 span 单视角派生。
func TestListDependenciesNote(t *testing.T) {
	s := &Store{ch: &fakeCHQuerier{results: []*fakeCHRows{{scans: [][]any{
		{"order-svc", "payment-svc", "service", uint64(5), 0.0, 12.0},
	}}}}}
	start, end := chTestWindow()
	out, err := s.ListDependencies(context.Background(), DependenciesFilter{Start: start, End: end})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if out.DataSource != dataSourceOTel || len(out.Edges) != 1 {
		t.Fatalf("out = %+v", out)
	}
	if !strings.Contains(out.Note, "基于客户端 span") {
		t.Errorf("note must state client-span derivation, got %q", out.Note)
	}
}
