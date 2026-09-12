// chstore_integration_test.go ClickHouse 数据面真实查询集成测试（阶段2 下半）。
//
// 运行方式（与 WP9 锁定镜像一致，ClickHouse 25.8-alpine；该镜像未设
// CLICKHOUSE_PASSWORD 时 default 用户仅允许 localhost 连接，宿主机访问必须显式设密码）：
//
//	docker run -d --name jiuzhang-ch-test -e CLICKHOUSE_PASSWORD=test -p 18123:9000 clickhouse/clickhouse-server:25.8-alpine
//	docker exec jiuzhang-ch-test clickhouse-client --password test --query "CREATE DATABASE IF NOT EXISTS apm"
//	APM_CH_TEST_DSN="clickhouse://default:test@127.0.0.1:18123/apm" \
//	  go test ./internal/apm -run TestCHStore -count=1
//
// APM_CH_TEST_DSN 未设置时 t.Skip（环境不可用如实跳过，不 mock 冒充）。
// 测试自助建 schema：直接执行 deployment/apm/clickhouse/001_otel_traces.sql
// （顺带验证交付 schema 可干净落地），灌入合成 span 后跑真实查询。
package apm

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// applyCHSchema 执行 schema 文件全部语句（按分号切分；文件内无字符串内分号）。
func applyCHSchema(t *testing.T, ctx context.Context, conn interface {
	Exec(context.Context, string, ...any) error
}, file string) {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "deployment", "apm", "clickhouse", file)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema %s: %v", path, err)
	}
	for _, stmt := range strings.Split(string(raw), ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("apply schema %s: %v\nstmt: %s", file, err, stmt)
		}
	}
}

// setupCHTest 建连 + 重建 apm 库 + 落地 001 schema。
func setupCHTest(t *testing.T) (context.Context, *Store, func()) {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	dsn := os.Getenv("APM_CH_TEST_DSN")
	if dsn == "" {
		t.Skip("APM_CH_TEST_DSN not set, skipping ClickHouse integration test")
	}
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := conn.Ping(ctx); err != nil {
		cancel()
		t.Skipf("ClickHouse unreachable (%v), skipping", err)
	}
	// 清库重建（DSN 默认库为 apm；DROP 保证用例独立）
	if err := conn.Exec(ctx, "DROP DATABASE IF EXISTS apm"); err != nil {
		cancel()
		t.Fatalf("drop apm db: %v", err)
	}
	applyCHSchema(t, ctx, conn, "001_otel_traces.sql")
	return ctx, &Store{ch: chQuerier{conn: conn}}, cancel
}

// chTestSpan 合成 span 行（列子集插入，Nested 事件/链接受缺省为空）。
type chTestSpan struct {
	ts       time.Time
	traceID  string
	spanID   string
	parentID string
	name     string
	kind     string
	service  string
	attrs    map[string]string
	durNS    uint64
	status   string
}

func insertCHSpans(t *testing.T, ctx context.Context, conn driver.Conn, spans []chTestSpan) {
	t.Helper()
	batch, err := conn.PrepareBatch(ctx, `INSERT INTO apm.otel_traces
(Timestamp, TraceId, SpanId, ParentSpanId, TraceState, SpanName, SpanKind, ServiceName,
 ResourceAttributes, ScopeName, ScopeVersion, SpanAttributes, Duration, StatusCode, StatusMessage)`)
	if err != nil {
		t.Fatalf("prepare batch: %v", err)
	}
	for _, s := range spans {
		if err := batch.Append(s.ts, s.traceID, s.spanID, s.parentID, "", s.name, s.kind, s.service,
			map[string]string{}, "test", "v0", s.attrs, s.durNS, s.status, ""); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := batch.Send(); err != nil {
		t.Fatalf("send batch: %v", err)
	}
}

// TestCHStoreTraceSearchAndSpans 真实 CH：合成两条 trace，验证检索过滤组合与瀑布映射。
func TestCHStoreTraceSearchAndSpans(t *testing.T) {
	ctx, store, cancel := setupCHTest(t)
	defer cancel()

	// 造数：tid1 三 span（Server 根 + DB 子 + 跨服务 Error 子），tid2 单 span
	base := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Millisecond)
	tid1 := strings.Repeat("aa", 16)
	tid2 := strings.Repeat("bb", 16)
	spans := []chTestSpan{
		{base, tid1, "root000000000001", "", "GET /orders/{id}", "Server", "order-svc",
			map[string]string{"http.method": "GET", "http.route": "/orders/{id}", "http.status_code": "200"},
			250 * 1e6, "Ok"},
		{base.Add(10 * time.Millisecond), tid1, "child00000000001", "root000000000001", "SELECT orders", "Client", "order-svc",
			map[string]string{"db.system": "postgresql", "db.operation.name": "SELECT", "db.namespace": "shop",
				"db.statement": "SELECT * FROM orders WHERE id = 42"}, // 白名单必须剔除
			100 * 1e6, "Ok"},
		{base.Add(120 * time.Millisecond), tid1, "child00000000002", "root000000000001", "POST /pay", "Server", "payment-svc",
			map[string]string{"http.method": "POST", "http.route": "/pay", "http.status_code": "502"},
			120 * 1e6, "Error"},
		{base.Add(time.Minute), tid2, "root000000000002", "", "GET /stock", "Server", "inventory-svc",
			map[string]string{"http.method": "GET", "http.route": "/stock"}, 20 * 1e6, "Ok"},
	}
	// 直连 conn 造数（Store 只读，不经 Store 写入）
	conn := store.ch.(chQuerier).conn
	insertCHSpans(t, ctx, conn, spans)

	win := TraceSearchFilter{
		Start: base.Add(-time.Hour), End: time.Now().UTC().Add(time.Minute), Page: 1, PageSize: 20}

	// 1) 无过滤：两条 trace 全出，按开始时间倒序（tid2 晚于 tid1）
	out, err := store.SearchTraces(ctx, win)
	if err != nil {
		t.Fatalf("search all: %v", err)
	}
	if out.DataSource != dataSourceOTel || out.Total != 2 || len(out.List) != 2 {
		t.Fatalf("search all = %+v", out)
	}
	if out.List[0].TraceID != tid2 || out.List[1].TraceID != tid1 {
		t.Errorf("order = %s,%s; want %s,%s", out.List[0].TraceID, out.List[1].TraceID, tid2, tid1)
	}
	row1 := out.List[1]
	if row1.RootService != "order-svc" || row1.RootOperation != "GET /orders/{id}" {
		t.Errorf("tid1 root = %q/%q", row1.RootService, row1.RootOperation)
	}
	if row1.SpanCount != 3 || row1.ErrorCount != 1 {
		t.Errorf("tid1 counts = %d/%d, want 3/1", row1.SpanCount, row1.ErrorCount)
	}
	if len(row1.Services) != 2 {
		t.Errorf("tid1 services = %v, want 2", row1.Services)
	}
	// 墙钟 = 最晚 span 结束 − 最早开始：root 结束 250ms 晚于 child2 的 240ms，故为 250ms
	if row1.DurationMS != 250 {
		t.Errorf("tid1 wall duration = %v, want 250", row1.DurationMS)
	}

	// 2) service 精确过滤
	f := win
	f.Service = "payment-svc"
	out, err = store.SearchTraces(ctx, f)
	if err != nil || out.Total != 1 || out.List[0].TraceID != tid1 {
		t.Errorf("service filter = %+v, err=%v", out, err)
	}

	// 3) trace_id 直达
	f = win
	f.TraceIDs = []string{tid2}
	out, err = store.SearchTraces(ctx, f)
	if err != nil || out.Total != 1 || out.List[0].TraceID != tid2 {
		t.Errorf("trace_id filter = %+v, err=%v", out, err)
	}

	// 4) min_duration_ms（tid1 墙钟 240ms，tid2 为 20ms）
	f = win
	f.MinDurationMS = 200
	out, err = store.SearchTraces(ctx, f)
	if err != nil || out.Total != 1 || out.List[0].TraceID != tid1 {
		t.Errorf("min_duration filter = %+v, err=%v", out, err)
	}

	// 5) error=true（仅 tid1 含 Error span）
	f = win
	f.ErrorOnly = true
	out, err = store.SearchTraces(ctx, f)
	if err != nil || out.Total != 1 || out.List[0].TraceID != tid1 {
		t.Errorf("error filter = %+v, err=%v", out, err)
	}

	// 6) 分页：page_size=1 两页
	f = win
	f.Page, f.PageSize = 2, 1
	out, err = store.SearchTraces(ctx, f)
	if err != nil || out.Total != 2 || len(out.List) != 1 || out.List[0].TraceID != tid1 {
		t.Errorf("page 2 = %+v, err=%v", out, err)
	}

	// 7) 瀑布：tid1 三 span 正序、无截断、白名单剔除 db.statement
	gotSpans, truncated, qStatus := store.queryTraceSpans(ctx, tid1, win.Start, win.End)
	if qStatus != chQueryOK {
		t.Fatalf("query status = %v, want chQueryOK", qStatus)
	}
	if truncated || len(gotSpans) != 3 {
		t.Fatalf("spans = %d, truncated=%v", len(gotSpans), truncated)
	}
	if gotSpans[0].SpanID != "root000000000001" || gotSpans[0].ParentSpanID != "" {
		t.Errorf("first span = %+v", gotSpans[0])
	}
	if gotSpans[0].Attributes["http.route"] != "/orders/{id}" {
		t.Errorf("root attrs = %v", gotSpans[0].Attributes)
	}
	if _, leaked := gotSpans[1].Attributes["db.statement"]; leaked {
		t.Error("db.statement must be filtered from span attributes")
	}
	if gotSpans[1].Attributes["db.namespace"] != "shop" {
		t.Errorf("db attrs = %v", gotSpans[1].Attributes)
	}
	if gotSpans[1].DurationMS != 100 {
		t.Errorf("child duration = %v, want 100", gotSpans[1].DurationMS)
	}

	// 8) 时间窗外查不到（窗口约束生效）
	out, err = store.SearchTraces(ctx, TraceSearchFilter{
		Start: base.Add(-2 * time.Hour), End: base.Add(-time.Hour), Page: 1, PageSize: 20})
	if err != nil || out.Total != 0 {
		t.Errorf("out-of-window = %+v, err=%v", out, err)
	}
}

// setupCHTestFull 建连 + 重建 apm 库 + 落地 001/002 schema（阶段3 聚合表与物化视图）。
// 顺带验证 002 交付 schema 可干净落地（物化视图即时聚合，随后插入即产出）。
func setupCHTestFull(t *testing.T) (context.Context, *Store, func()) {
	t.Helper()
	ctx, store, cancel := setupCHTest(t)
	applyCHSchema(t, ctx, store.ch.(chQuerier).conn, "002_aggregates.sql")
	return ctx, store, cancel
}

// chTestEvent 合成 span 事件（对应 otel_traces Events Nested 列）。
type chTestEvent struct {
	ts    time.Time
	name  string
	attrs map[string]string
}

// chTestSpanFull 合成 span 行 + 事件（无事件传空切片）。
type chTestSpanFull struct {
	chTestSpan
	events []chTestEvent
}

func insertCHSpansFull(t *testing.T, ctx context.Context, conn driver.Conn, spans []chTestSpanFull) {
	t.Helper()
	batch, err := conn.PrepareBatch(ctx, `INSERT INTO apm.otel_traces
(Timestamp, TraceId, SpanId, ParentSpanId, TraceState, SpanName, SpanKind, ServiceName,
 ResourceAttributes, ScopeName, ScopeVersion, SpanAttributes, Duration, StatusCode, StatusMessage,
 Events.Timestamp, Events.Name, Events.Attributes)`)
	if err != nil {
		t.Fatalf("prepare batch: %v", err)
	}
	for _, s := range spans {
		ets, enames, eattrs := []time.Time{}, []string{}, []map[string]string{}
		for _, e := range s.events {
			ets, enames, eattrs = append(ets, e.ts), append(enames, e.name), append(eattrs, e.attrs)
		}
		if err := batch.Append(s.ts, s.traceID, s.spanID, s.parentID, "", s.name, s.kind, s.service,
			map[string]string{}, "test", "v0", s.attrs, s.durNS, s.status, "",
			ets, enames, eattrs); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := batch.Send(); err != nil {
		t.Fatalf("send batch: %v", err)
	}
}

// TestCHStoreStage3Aggregates 真实 CH（001+002 schema）：合成 DB/异常/客户端 span，
// 验证 SQL 指纹聚合（分钟聚合表 + 原始表派生 p95/示例 trace）、异常指纹聚合
// （002 AggregatingMergeTree 表）与服务依赖边（客户端 span 单视角派生）三接口。
func TestCHStoreStage3Aggregates(t *testing.T) {
	ctx, store, cancel := setupCHTestFull(t)
	defer cancel()

	base := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Millisecond)
	tidSQL := strings.Repeat("cc", 16)
	tidExc := strings.Repeat("dd", 16)
	stack := "java.lang.RuntimeException: boom\n\tat com.shop.OrderService.get(OrderService.java:42)"

	spans := []chTestSpanFull{
		// ---- SQL：order-svc postgresql 两个指纹（F1 五次含一次 Error，F2 三次） ----
		{chTestSpan: chTestSpan{base, tidSQL, "sqlf1000000000001", "", "SELECT orders", "Client", "order-svc",
			map[string]string{"db.system": "postgresql", "db.namespace": "shop",
				"db.operation.name": "SELECT", "db.statement": "SELECT * FROM orders WHERE id = ?"},
			10 * 1e6, "Ok"}},
		{chTestSpan: chTestSpan{base.Add(time.Second), tidSQL, "sqlf1000000000002", "", "SELECT orders", "Client", "order-svc",
			map[string]string{"db.system": "postgresql", "db.namespace": "shop",
				"db.operation.name": "SELECT", "db.statement": "SELECT * FROM orders WHERE id = ?"},
			20 * 1e6, "Ok"}},
		{chTestSpan: chTestSpan{base.Add(2 * time.Second), tidSQL, "sqlf1000000000003", "", "SELECT orders", "Client", "order-svc",
			map[string]string{"db.system": "postgresql", "db.namespace": "shop",
				"db.operation.name": "SELECT", "db.statement": "SELECT * FROM orders WHERE id = ?"},
			30 * 1e6, "Ok"}},
		{chTestSpan: chTestSpan{base.Add(3 * time.Second), tidSQL, "sqlf1000000000004", "", "SELECT orders", "Client", "order-svc",
			map[string]string{"db.system": "postgresql", "db.namespace": "shop",
				"db.operation.name": "SELECT", "db.statement": "SELECT * FROM orders WHERE id = ?"},
			40 * 1e6, "Ok"}},
		{chTestSpan: chTestSpan{base.Add(4 * time.Second), tidSQL, "sqlf1000000000005", "", "SELECT orders", "Client", "order-svc",
			map[string]string{"db.system": "postgresql", "db.namespace": "shop",
				"db.operation.name": "SELECT", "db.statement": "SELECT * FROM orders WHERE id = ?"},
			100 * 1e6, "Error"}},
		{chTestSpan: chTestSpan{base, tidSQL, "sqlf2000000000001", "", "UPDATE inventory", "Client", "order-svc",
			map[string]string{"db.system": "postgresql", "db.namespace": "shop",
				"db.operation.name": "UPDATE", "db.statement": "UPDATE inventory SET stock = ? WHERE sku = ?"},
			200 * 1e6, "Ok"}},
		{chTestSpan: chTestSpan{base.Add(time.Second), tidSQL, "sqlf2000000000002", "", "UPDATE inventory", "Client", "order-svc",
			map[string]string{"db.system": "postgresql", "db.namespace": "shop",
				"db.operation.name": "UPDATE", "db.statement": "UPDATE inventory SET stock = ? WHERE sku = ?"},
			300 * 1e6, "Ok"}},
		{chTestSpan: chTestSpan{base.Add(2 * time.Second), tidSQL, "sqlf2000000000003", "", "UPDATE inventory", "Client", "order-svc",
			map[string]string{"db.system": "postgresql", "db.namespace": "shop",
				"db.operation.name": "UPDATE", "db.statement": "UPDATE inventory SET stock = ? WHERE sku = ?"},
			400 * 1e6, "Ok"}},
		// ---- SQL：payment-svc redis 单指纹（验证 service/db_system 过滤） ----
		{chTestSpan: chTestSpan{base, tidSQL, "sqlf3000000000001", "", "GET session", "Client", "payment-svc",
			map[string]string{"db.system": "redis", "db.namespace": "0",
				"db.operation.name": "GET", "db.statement": "GET session:?"},
			5 * 1e6, "Ok"}},
		// ---- 依赖：order-svc → payment-svc（peer.service → service 边） ----
		{chTestSpan: chTestSpan{base, tidSQL, "dep10000000000001", "", "POST /pay", "Client", "order-svc",
			map[string]string{"peer.service": "payment-svc", "http.method": "POST"},
			50 * 1e6, "Ok"}},
		// ---- 依赖：order-svc → cdn.example.com（仅 server.address → external 边） ----
		{chTestSpan: chTestSpan{base, tidSQL, "dep20000000000001", "", "GET /assets", "Client", "order-svc",
			map[string]string{"server.address": "cdn.example.com", "http.method": "GET"},
			30 * 1e6, "Error"}},
		// ---- 依赖：order-svc → kafka/orders-topic（Producer → messaging 边） ----
		{chTestSpan: chTestSpan{base, tidSQL, "dep30000000000001", "", "publish orders-topic", "Producer", "order-svc",
			map[string]string{"messaging.system": "kafka", "messaging.destination.name": "orders-topic"},
			8 * 1e6, "Ok"}},
		// ---- 异常：同堆栈指纹两个服务各一次（跨分钟，验证首末出现与影响服务） ----
		{chTestSpan: chTestSpan{base, tidExc, "exc10000000000001", "", "GET /orders/{id}", "Server", "order-svc",
			map[string]string{"http.route": "/orders/{id}"}, 120 * 1e6, "Error"},
			events: []chTestEvent{{base, "exception", map[string]string{
				"exception.type": "java.lang.RuntimeException", "exception.stacktrace": stack}}}},
		{chTestSpan: chTestSpan{base.Add(time.Minute), tidExc, "exc20000000000001", "", "POST /pay", "Server", "payment-svc",
			map[string]string{"http.route": "/pay"}, 80 * 1e6, "Error"},
			events: []chTestEvent{{base.Add(time.Minute), "exception", map[string]string{
				"exception.type": "java.lang.RuntimeException", "exception.stacktrace": stack}}}},
	}
	conn := store.ch.(chQuerier).conn
	insertCHSpansFull(t, ctx, conn, spans)

	start, end := base.Add(-time.Hour), time.Now().UTC().Add(time.Minute)

	// ---------- 1) SQL 指纹聚合 ----------
	sqlOut, err := store.ListSQLFingerprints(ctx, SQLFilter{Start: start, End: end, Sort: "calls", Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("sql list: %v", err)
	}
	if sqlOut.DataSource != dataSourceOTel || sqlOut.Total != 3 || len(sqlOut.List) != 3 {
		t.Fatalf("sql out = %+v", sqlOut)
	}
	// sort=calls 倒序：F1(5) > F2(3) > F3(1)
	f1, f2 := sqlOut.List[0], sqlOut.List[1]
	if f1.Calls != 5 || f1.ErrorCount != 1 || f2.Calls != 3 {
		t.Errorf("calls order = %d,%d,%d; errors = %d",
			sqlOut.List[0].Calls, sqlOut.List[1].Calls, sqlOut.List[2].Calls, f1.ErrorCount)
	}
	if f1.DBSystem != "postgresql" || f1.Namespace != "shop" || f1.Operation != "SELECT" {
		t.Errorf("F1 identity = %+v", f1)
	}
	if f1.AvgMS != 40 {
		t.Errorf("F1 avg_ms = %v, want 40", f1.AvgMS)
	}
	if f1.P95MS < 40 || f1.P95MS > 100 {
		t.Errorf("F1 p95_ms = %v, want within [40,100]", f1.P95MS)
	}
	if len(f1.SampleTraceIDs) == 0 || len(f1.SampleTraceIDs) > 3 || f1.SampleTraceIDs[0] != tidSQL {
		t.Errorf("F1 samples = %v, want ≤3 containing %s", f1.SampleTraceIDs, tidSQL)
	}
	// 指纹为 32 位 hex（MD5 hex），绝不回原始 statement
	for _, r := range sqlOut.List {
		if len(r.SQLFingerprint) != 32 {
			t.Errorf("fingerprint = %q, want 32-hex", r.SQLFingerprint)
		}
	}

	// db_system / service 过滤
	f := SQLFilter{Start: start, End: end, Sort: "p95_ms", Page: 1, PageSize: 20, DBSystem: "redis"}
	out, err := store.ListSQLFingerprints(ctx, f)
	if err != nil || out.Total != 1 || out.List[0].DBSystem != "redis" || out.List[0].Calls != 1 {
		t.Errorf("db_system filter = %+v, err=%v", out, err)
	}
	f = SQLFilter{Start: start, End: end, Sort: "p95_ms", Page: 1, PageSize: 20, Service: "payment-svc"}
	out, err = store.ListSQLFingerprints(ctx, f)
	if err != nil || out.Total != 1 || out.List[0].Operation != "GET" {
		t.Errorf("service filter = %+v, err=%v", out, err)
	}

	// ---------- 2) 异常指纹聚合 ----------
	excOut, err := store.ListExceptions(ctx, ExceptionsFilter{Start: start, End: end, Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("exceptions list: %v", err)
	}
	if excOut.DataSource != dataSourceOTel || excOut.Total != 1 || len(excOut.List) != 1 {
		t.Fatalf("exceptions out = %+v", excOut)
	}
	ex := excOut.List[0]
	if ex.ExceptionType != "java.lang.RuntimeException" || ex.Count != 2 {
		t.Errorf("exception row = %+v", ex)
	}
	if len(ex.Fingerprint) != 32 {
		t.Errorf("exception fingerprint = %q, want 32-hex", ex.Fingerprint)
	}
	// 分钟桶粒度首末出现（等于 toStartOfMinute 截断桶起点）
	if !ex.FirstSeenAt.Equal(base.Truncate(time.Minute)) {
		t.Errorf("first_seen = %v, want minute bucket of %v", ex.FirstSeenAt, base)
	}
	if !ex.LastSeenAt.Equal(base.Add(time.Minute).Truncate(time.Minute)) {
		t.Errorf("last_seen = %v, want minute bucket of %v", ex.LastSeenAt, base.Add(time.Minute))
	}
	if len(ex.AffectedServices) != 2 {
		t.Errorf("affected services = %v, want 2 (order-svc/payment-svc)", ex.AffectedServices)
	}
	if len(ex.SampleTraceIDs) == 0 || len(ex.SampleTraceIDs) > 3 || ex.SampleTraceIDs[0] != tidExc {
		t.Errorf("exception samples = %v", ex.SampleTraceIDs)
	}
	// service 过滤后只剩单服务一次
	out2, err := store.ListExceptions(ctx, ExceptionsFilter{Start: start, End: end, Service: "order-svc", Page: 1, PageSize: 20})
	if err != nil || out2.Total != 1 || out2.List[0].Count != 1 || len(out2.List[0].AffectedServices) != 1 {
		t.Errorf("exceptions service filter = %+v, err=%v", out2, err)
	}

	// ---------- 3) 服务依赖边 ----------
	depOut, err := store.ListDependencies(ctx, DependenciesFilter{Start: start, End: end})
	if err != nil {
		t.Fatalf("dependencies list: %v", err)
	}
	if depOut.DataSource != dataSourceOTel || !strings.Contains(depOut.Note, "基于客户端 span") {
		t.Fatalf("dependencies out = %+v", depOut)
	}
	edges := map[string]DependencyEdge{}
	for _, e := range depOut.Edges {
		edges[e.Source+"->"+e.Target] = e
	}
	// order-svc → postgresql/shop：8 次 db 调用（5+3），错误率 1/8=0.125，
	// 平均耗时 (10+20+30+40+100+200+300+400)/8 = 137.5ms
	e, ok := edges["order-svc->postgresql/shop"]
	if !ok || e.TargetType != "db" || e.Calls != 8 || e.ErrorRate != 0.125 || e.AvgMS != 137.5 {
		t.Errorf("db edge = %+v, want calls=8 error_rate=0.125 avg_ms=137.5", e)
	}
	// order-svc → payment-svc（peer.service → service）
	e, ok = edges["order-svc->payment-svc"]
	if !ok || e.TargetType != "service" || e.Calls != 1 {
		t.Errorf("service edge = %+v", e)
	}
	// order-svc → cdn.example.com（仅 server.address → external）
	e, ok = edges["order-svc->cdn.example.com"]
	if !ok || e.TargetType != "external" || e.Calls != 1 || e.ErrorRate != 1 {
		t.Errorf("external edge = %+v", e)
	}
	// order-svc → kafka/orders-topic（Producer → messaging）
	e, ok = edges["order-svc->kafka/orders-topic"]
	if !ok || e.TargetType != "messaging" || e.Calls != 1 {
		t.Errorf("messaging edge = %+v", e)
	}
	// payment-svc → redis/0
	e, ok = edges["payment-svc->redis/0"]
	if !ok || e.TargetType != "db" || e.Calls != 1 {
		t.Errorf("redis edge = %+v", e)
	}
	// service 过滤：仅 order-svc 源端边（4 条）
	depOut2, err := store.ListDependencies(ctx, DependenciesFilter{Start: start, End: end, Service: "order-svc"})
	if err != nil || len(depOut2.Edges) != 4 {
		t.Errorf("dependencies service filter edges = %d, want 4 (%+v)", len(depOut2.Edges), depOut2)
	}
	for _, e := range depOut2.Edges {
		if e.Source != "order-svc" {
			t.Errorf("unexpected source %q", e.Source)
		}
	}
}

// TestCHStoreTraceLevelLocation 真实 CH（P1-01 A2）：SQL/异常 trace 级精确定位
// （仅从指定 trace 的 Span/exception 事件派生）与 trace-search 服务名集合约束
// （应用约束下推 ServiceName IN）。
func TestCHStoreTraceLevelLocation(t *testing.T) {
	ctx, store, cancel := setupCHTest(t)
	defer cancel()

	base := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Millisecond)
	tidA := strings.Repeat("e1", 16)
	tidB := strings.Repeat("e2", 16)
	stackSecret := "java.lang.RuntimeException: connect failed password=hunter2\n" +
		"\tat com.shop.OrderService.get(OrderService.java:42) Authorization: Bearer abcdefgh12345678"

	spans := []chTestSpanFull{
		// tidA（order-svc）：两个 DB Client span 同指纹 + 一个带敏感文本的 exception 事件
		{chTestSpan: chTestSpan{base, tidA, "a-root0000000001", "", "GET /orders/{id}", "Server", "order-svc",
			map[string]string{"http.route": "/orders/{id}"}, 200 * 1e6, "Error"},
			events: []chTestEvent{{base.Add(50 * time.Millisecond), "exception", map[string]string{
				"exception.type":       "java.lang.RuntimeException",
				"exception.message":    "connect failed password=hunter2",
				"exception.stacktrace": stackSecret}}}},
		{chTestSpan: chTestSpan{base.Add(10 * time.Millisecond), tidA, "a-db10000000000001", "a-root0000000001", "SELECT orders", "Client", "order-svc",
			map[string]string{"db.system": "postgresql", "db.namespace": "shop",
				"db.operation.name": "SELECT", "db.statement": "SELECT * FROM orders WHERE id = ?"},
			30 * 1e6, "Ok"}},
		{chTestSpan: chTestSpan{base.Add(50 * time.Millisecond), tidA, "a-db20000000000002", "a-root0000000001", "SELECT orders", "Client", "order-svc",
			map[string]string{"db.system": "postgresql", "db.namespace": "shop",
				"db.operation.name": "SELECT", "db.statement": "SELECT * FROM orders WHERE id = ?"},
			40 * 1e6, "Ok"}},
		// tidB（inventory-svc）：另一条 trace 的 DB span（不应混入 tidA 的 trace 级结果）
		{chTestSpan: chTestSpan{base.Add(time.Minute), tidB, "b-root0000000001", "", "GET /stock", "Server", "inventory-svc",
			map[string]string{"http.route": "/stock"}, 20 * 1e6, "Ok"}},
		{chTestSpan: chTestSpan{base.Add(time.Minute).Add(5 * time.Millisecond), tidB, "b-db10000000000001", "b-root0000000001", "SELECT stock", "Client", "inventory-svc",
			map[string]string{"db.system": "postgresql", "db.namespace": "shop",
				"db.operation.name": "SELECT", "db.statement": "SELECT * FROM stock WHERE sku = ?"},
			10 * 1e6, "Ok"}},
	}
	conn := store.ch.(chQuerier).conn
	insertCHSpansFull(t, ctx, conn, spans)

	start, end := base.Add(-time.Hour), time.Now().UTC().Add(time.Minute)

	// 1) SQL trace 级定位：仅 tidA 的 DB span 派生（1 个指纹、calls=2），tidB 不混入
	sqlOut, err := store.ListSQLFingerprints(ctx, SQLFilter{
		Start: start, End: end, TraceID: tidA, Sort: "calls", Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("sql trace mode: %v", err)
	}
	if sqlOut.MatchMode != matchModeTraceExact || sqlOut.TraceID != tidA {
		t.Errorf("match fields = %q/%q", sqlOut.MatchMode, sqlOut.TraceID)
	}
	if sqlOut.Total != 1 || len(sqlOut.List) != 1 || sqlOut.List[0].Calls != 2 {
		t.Fatalf("sql trace out = %+v", sqlOut)
	}
	if sqlOut.List[0].DBSystem != "postgresql" || sqlOut.List[0].Operation != "SELECT" {
		t.Errorf("sql trace row = %+v", sqlOut.List[0])
	}
	for _, r := range sqlOut.List {
		if len(r.SampleTraceIDs) != 1 || r.SampleTraceIDs[0] != tidA {
			t.Errorf("samples = %v, want [%s]（仅该 trace）", r.SampleTraceIDs, tidA)
		}
	}
	if sqlOut.Availability == nil || sqlOut.Availability.QueryState != queryStateReady {
		t.Errorf("sql availability = %+v, want READY", sqlOut.Availability)
	}

	// tidB 的 trace 级定位：另一指纹（语句不同）
	sqlOut, err = store.ListSQLFingerprints(ctx, SQLFilter{
		Start: start, End: end, TraceID: tidB, Page: 1, PageSize: 20})
	if err != nil || sqlOut.Total != 1 || len(sqlOut.List) != 1 || sqlOut.List[0].Calls != 1 {
		t.Errorf("sql trace tidB = %+v, err=%v", sqlOut, err)
	}

	// 2) 异常 trace 级定位：tidA 的 exception 事件逐条返回，敏感文本掩码
	excOut, err := store.ListExceptions(ctx, ExceptionsFilter{
		Start: start, End: end, TraceID: tidA, Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("exceptions trace mode: %v", err)
	}
	if excOut.MatchMode != matchModeTraceExact || len(excOut.TraceExceptions) != 1 || len(excOut.List) != 0 {
		t.Fatalf("exceptions trace out = %+v", excOut)
	}
	item := excOut.TraceExceptions[0]
	if item.TraceID != tidA || item.ExceptionType != "java.lang.RuntimeException" || len(item.Fingerprint) != 32 {
		t.Errorf("exception item = %+v", item)
	}
	if strings.Contains(item.ExceptionMessage, "hunter2") || strings.Contains(item.Stacktrace, "hunter2") ||
		strings.Contains(item.Stacktrace, "abcdefgh12345678") {
		t.Errorf("credential leaked: message=%q stacktrace=%q", item.ExceptionMessage, item.Stacktrace)
	}
	if !strings.Contains(item.ExceptionMessage, "password=***") || !strings.Contains(item.Stacktrace, "Authorization: ***") {
		t.Errorf("masked text = %q / %q", item.ExceptionMessage, item.Stacktrace)
	}
	// tidB 无异常事件：如实空（trace_exceptions 空数组非 nil）
	excOut, err = store.ListExceptions(ctx, ExceptionsFilter{
		Start: start, End: end, TraceID: tidB, Page: 1, PageSize: 20})
	if err != nil || excOut.Total != 0 || len(excOut.TraceExceptions) != 0 || excOut.TraceExceptions == nil {
		t.Errorf("exceptions trace tidB = %+v, err=%v", excOut, err)
	}
	if excOut.Availability == nil || excOut.Availability.QueryState != queryStateEmpty {
		t.Errorf("exceptions availability = %+v, want EMPTY+NO_MATCH", excOut.Availability)
	}

	// 3) trace-search 服务名集合约束（应用约束下推口径：ServiceName IN）
	f := TraceSearchFilter{Start: start, End: end, Page: 1, PageSize: 20,
		ServiceNames: []string{"inventory-svc"}}
	out, err := store.SearchTraces(ctx, f)
	if err != nil || out.Total != 1 || out.List[0].TraceID != tidB {
		t.Errorf("service-names constraint = %+v, err=%v", out, err)
	}
	// 集合内多服务：两条 trace 全出
	f.ServiceNames = []string{"order-svc", "inventory-svc"}
	out, err = store.SearchTraces(ctx, f)
	if err != nil || out.Total != 2 {
		t.Errorf("service-names multi = %+v, err=%v", out, err)
	}
	// 集合不含任何已埋点服务：如实空页（数据面在线口径，DataSource=otel）
	f.ServiceNames = []string{"unknown-svc"}
	out, err = store.SearchTraces(ctx, f)
	if err != nil || out.Total != 0 || out.DataSource != dataSourceOTel {
		t.Errorf("service-names empty = %+v, err=%v", out, err)
	}
	if out.Availability == nil || out.Availability.QueryState != queryStateEmpty ||
		len(out.Availability.ReasonCodes) == 0 || out.Availability.ReasonCodes[0] != reasonNoMatch {
		t.Errorf("empty availability = %+v, want EMPTY+NO_MATCH", out.Availability)
	}
}
