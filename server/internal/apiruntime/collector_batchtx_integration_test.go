// collector_batchtx_integration_test.go W22 采集器事务批量化的真实 PG 集成测试与基准。
// 由一次性 PG 容器驱动（test/performance/w22-collector-batchtx-bench.sh 自起自删），
// 环境变量 APIRUNTIME_TEST_PG_DSN 未设置时整体跳过（本地单测零依赖）。
// 覆盖：全 recorder 装配端到端一致、重放安全（断点回退重读不产生重复行）、
// 毒记录副作用按记录回滚（记录级 SAVEPOINT）、死事务整体回滚且断点不生成。
package apiruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apillm"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/database"
)

// integrationPool 连接一次性 PG 容器并应用全部迁移（幂等：已应用版本跳过）。
func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("APIRUNTIME_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("APIRUNTIME_TEST_PG_DSN not set, skipping PG integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect pg: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		pool.Close()
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// truncateIngest 清空采集链路涉及的全部表（用例间隔离）。
func truncateIngest(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx, `
TRUNCATE api_runtime_events, api_schema_violations, api_runtime_findings,
  api_learning_samples, api_learning_jobs, api_parameter_value_obs, api_response_schemas,
  api_file_assets, api_llm_observations, api_endpoint_traffic_buckets,
  api_endpoint_path_segments, api_endpoints CASCADE`)
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// newIntegrationCollector 按 main.go 生产装配全量 recorder；useTx 时接线批次事务。
func newIntegrationCollector(pool *pgxpool.Pool, logPath, cpPath string, useTx bool) *Collector {
	rtStore := NewStore(pool)
	assetStore := apiassets.NewStore(pool)
	c := NewCollector(rtStore, "it-collector", logPath, cpPath, "node-it")
	c.SetDiscoveryUpserter(assetStore)
	c.SetResolver(NewAppResolver(applications.NewStore(pool)))
	c.SetSampleRecorder(assetStore)
	c.SetViolationSaver(rtStore)
	c.SetFindingSaver(rtStore)
	c.SetParamObsRecorder(NewParamObsStore(pool))
	c.SetRespSchemaRecorder(NewRespSchemaStore(pool))
	c.SetTrafficRecorder(assetStore)
	c.SetFileObsRecorder(NewFileObsStore(pool))
	c.SetLLMObsRecorder(apillm.NewObsStore(pool))
	if useTx {
		c.SetBatchTxFactory(pool.Begin)
	}
	return c
}

// benchRecord 构造第 i 条合成事件（与网关上报形态一致：
// 75% ALLOW 透传（参数+响应观测）、20% BLOCK（schema 明细 + 全维度观测）、
// 5% 文件+LLM 观测）。endpoint 键池小（贴近真实：少数端点高命中）。
func benchRecord(i int) Record {
	ep := fmt.Sprintf("GET /v1/bench/e%d", i%7)
	rec := Record{
		RequestID:           fmt.Sprintf("it-%d", i),
		EndpointKey:         ep,
		Method:              "GET",
		PathTemplate:        fmt.Sprintf("/v1/bench/e%d", i%7),
		IsAPI:               true,
		APIConfidence:       0.9,
		FinalAction:         "ALLOW",
		RiskLevel:           "NONE",
		OccurredAt:          time.Now().UTC(),
		SourceFingerprint:   "srcfp",
		IdentityFingerprint: "idfp",
		ResponseStatus:      200,
		ClientIP:            "10.1.2.3",
		ParamObservations: []ParamObservation{
			{Location: "QUERY", Name: "id", BaseType: "number", Length: 3, ValueHash: fmt.Sprintf("h%d", i%97)},
		},
		ResponseObservations: []dsctx.ResponseObservation{
			{StatusCode: 200, ContentType: "application/json", Fields: map[string]string{"id": "number", "name": "string"}},
		},
	}
	switch i % 20 {
	case 3, 7, 11, 15: // 20% BLOCK notable：schema 明细 → 主事件 + 违例 + findings
		rec.FinalAction = "BLOCK"
		rec.RiskLevel = "HIGH"
		rec.RiskScore = 80
		rec.Details = []dsctx.DetectorMatch{{
			Detector: "api_schema", RuleID: "schema.type_mismatch", Category: "BLOCK",
			Severity: "HIGH", Message: "type mismatch for id", ScoreDelta: 80,
			Evidence: map[string]string{"field": "id", "want": "number", "got": "string"},
		}}
	case 0: // 5% 文件 + LLM 观测
		rec.FileObservations = []FileObservation{
			{Direction: "DOWNLOAD", FileName: fmt.Sprintf("report-%d.csv", i), Extension: "csv", MIME: "text/csv", Size: 1024},
		}
		rec.LLMObservation = &apillm.LLMObservation{Model: "gpt-x", PromptLenBucket: "1k-4k", TotalTokens: 1234, Stream: true}
	}
	return rec
}

func benchLines(n int) []string {
	lines := make([]string, 0, n)
	for i := 0; i < n; i++ {
		raw, err := json.Marshal(benchRecord(i))
		if err != nil {
			panic(err) // Record 全字段可序列化，永不失败
		}
		lines = append(lines, string(raw))
	}
	return lines
}

// tableCount 点查行数（断言辅助）。
func tableCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table string) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// 端到端一致：批次事务模式下入库结果与逐语句 autocommit 完全一致（同一批合成事件
// 各跑一遍，逐表对比行数）；同时校验各表行数符合记录构成（发现/流量/观测/违例/findings）。
func TestBatchTxIntegration_EndToEndConsistent(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	lines := benchLines(2000)
	writeLines(t, logPath, lines)

	counts := map[string]int64{}
	tables := []string{
		"api_runtime_events", "api_schema_violations", "api_runtime_findings",
		"api_parameter_value_obs", "api_response_schemas", "api_file_assets",
		"api_llm_observations", "api_endpoints", "api_endpoint_traffic_buckets",
		"api_endpoint_path_segments",
	}
	for _, mode := range []string{"autocommit", "batchtx"} {
		truncateIngest(t, ctx, pool)
		cpPath := filepath.Join(dir, "checkpoint-"+mode)
		c := newIntegrationCollector(pool, logPath, cpPath, mode == "batchtx")
		c.SetFlushPolicy(500, time.Hour) // 多批次（2000/500=4 + EOF）
		n, err := c.CollectOnce(ctx)
		if err != nil {
			t.Fatalf("%s CollectOnce: %v", mode, err)
		}
		if n != len(lines) {
			t.Fatalf("%s want %d processed, got %d", mode, len(lines), n)
		}
		for _, tb := range tables {
			got := tableCount(t, ctx, pool, tb)
			if mode == "autocommit" {
				counts[tb] = got
			} else if counts[tb] != got {
				t.Fatalf("table %s: batchtx %d rows != autocommit %d rows（两种模式入库必须一致）", tb, got, counts[tb])
			}
		}
	}
	// 构成校验（batchtx 最后一遍数据）：notable 20% = 400 主事件/违例；7 端点；
	// 文件观测 100（i%20==0）；LLM 观测 100；findings 按 dedup 指纹聚合（每端点 1 行）
	if got := tableCount(t, ctx, pool, "api_runtime_events"); got != 400 {
		t.Fatalf("want 400 notable events, got %d", got)
	}
	if got := tableCount(t, ctx, pool, "api_schema_violations"); got != 400 {
		t.Fatalf("want 400 violations, got %d", got)
	}
	if got := tableCount(t, ctx, pool, "api_endpoints"); got != 7 {
		t.Fatalf("want 7 endpoints, got %d", got)
	}
	if got := tableCount(t, ctx, pool, "api_file_assets"); got != 100 {
		t.Fatalf("want 100 file assets, got %d", got)
	}
	if got := tableCount(t, ctx, pool, "api_llm_observations"); got != 100 {
		t.Fatalf("want 100 llm observations, got %d", got)
	}
	if got := tableCount(t, ctx, pool, "api_runtime_findings"); got != 7 {
		t.Fatalf("want 7 deduped findings (one per endpoint), got %d", got)
	}
	if got := tableCount(t, ctx, pool, "api_endpoint_traffic_buckets"); got != 7 {
		t.Fatalf("want 7 traffic buckets (one per endpoint), got %d", got)
	}
	// 断点推进到文件尾
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if cp := readCheckpoint(t, filepath.Join(dir, "checkpoint-batchtx")); cp.Offset != info.Size() {
		t.Fatalf("checkpoint offset = %d, want file size %d", cp.Offset, info.Size())
	}
}

// 重放安全：批次事务提交后删除断点文件（模拟断点丢失/容器重建），全量重读，
// 各幂等表行数不变（request_id WHERE NOT EXISTS / ON CONFLICT / 派生幂等键兜底；
// 计数列（hit_count/transfer_count/sample_count）允许累加，断点丢失场景与
// autocommit 路径的既有语义一致——此处断言不产生重复行）。
func TestBatchTxIntegration_ReplaySafe(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	truncateIngest(t, ctx, pool)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")
	lines := benchLines(1000)
	writeLines(t, logPath, lines)

	c := newIntegrationCollector(pool, logPath, cpPath, true)
	c.SetFlushPolicy(300, time.Hour)
	if _, err := c.CollectOnce(ctx); err != nil {
		t.Fatalf("first CollectOnce: %v", err)
	}
	before := map[string]int64{}
	for _, tb := range []string{
		"api_runtime_events", "api_schema_violations", "api_runtime_findings",
		"api_parameter_value_obs", "api_response_schemas", "api_file_assets",
		"api_llm_observations", "api_endpoints",
	} {
		before[tb] = tableCount(t, ctx, pool, tb)
	}

	// 断点丢失 → 全量重放
	if err := os.Remove(cpPath); err != nil {
		t.Fatal(err)
	}
	c2 := newIntegrationCollector(pool, logPath, cpPath, true)
	c2.SetFlushPolicy(300, time.Hour)
	n, err := c2.CollectOnce(ctx)
	if err != nil {
		t.Fatalf("replay CollectOnce: %v", err)
	}
	if n != len(lines) {
		t.Fatalf("want full replay of %d lines, got %d", len(lines), n)
	}
	for tb, want := range before {
		if got := tableCount(t, ctx, pool, tb); got != want {
			t.Fatalf("table %s after replay: %d rows, want %d（重放不产生重复行）", tb, got, want)
		}
	}
}

// 毒记录：参数名超列宽（>255）的记录触发副作用语句失败，记录级 SAVEPOINT 回滚
// 该记录全部副作用（含其端点发现 upsert），其余记录与批次提交、断点前移不受影响；
// 毒记录主事件照常入库（「副作用失败不阻断主事件」与 autocommit 语义一致）。
func TestBatchTxIntegration_PoisonRecordRolledBack(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	truncateIngest(t, ctx, pool)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")

	good1 := benchRecord(1)
	good2 := benchRecord(2)
	poison := benchRecord(3) // BLOCK notable（主事件必须落库）
	poison.RequestID = "poison-1"
	poison.EndpointKey = "GET /v1/poison/{id}"
	poison.PathTemplate = "/v1/poison/{id}"
	poison.ParamObservations = []ParamObservation{
		{Location: "QUERY", Name: strings.Repeat("x", 300), BaseType: "string", Length: 1, ValueHash: "p"},
	}
	writeLines(t, logPath, []string{mustJSON(t, good1), mustJSON(t, poison), mustJSON(t, good2)})

	c := newIntegrationCollector(pool, logPath, cpPath, true)
	c.SetFlushPolicy(100, time.Hour)
	n, err := c.CollectOnce(ctx)
	if err != nil {
		t.Fatalf("CollectOnce must tolerate poison record: %v", err)
	}
	if n != 3 {
		t.Fatalf("want 3 processed, got %d", n)
	}
	// 好记录端点落库；毒记录端点随记录级子事务回滚（发现 upsert 一并撤销）
	if got := tableCount(t, ctx, pool, "api_endpoints"); got != 2 {
		t.Fatalf("want 2 good endpoints, got %d", got)
	}
	var poisonEp int64
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM api_endpoints WHERE endpoint_key='GET /v1/poison/{id}'`).Scan(&poisonEp); err != nil {
		t.Fatal(err)
	}
	if poisonEp != 0 {
		t.Fatal("poison record endpoint must be rolled back with its record savepoint")
	}
	// 毒记录主事件照常入库（notable），共 1 条 BLOCK 主事件
	if got := tableCount(t, ctx, pool, "api_runtime_events"); got != 1 {
		t.Fatalf("want 1 primary event (poison is notable), got %d", got)
	}
	// 断点推进到文件尾（失败副作用不阻断采集）
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if cp := readCheckpoint(t, cpPath); cp.Offset != info.Size() {
		t.Fatalf("checkpoint offset = %d, want file size %d", cp.Offset, info.Size())
	}
}

// 死事务（Begin 即回滚）：批次整体失败、断点文件不生成、无任何数据残留；
// 换正常工厂后重放完整落库（「失败断点不前移且重放安全」在真实 PG 上成立）。
func TestBatchTxIntegration_DeadTxRollback(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	truncateIngest(t, ctx, pool)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")
	lines := benchLines(10)
	writeLines(t, logPath, lines)

	deadFactory := func(ctx context.Context) (pgx.Tx, error) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return nil, err
		}
		_ = tx.Rollback(ctx)
		return tx, nil
	}
	c := newIntegrationCollector(pool, logPath, cpPath, false)
	c.SetBatchTxFactory(deadFactory)
	if _, err := c.CollectOnce(ctx); err == nil {
		t.Fatal("want failure from dead tx, got nil")
	}
	if _, err := os.Stat(cpPath); err == nil {
		t.Fatal("checkpoint must not exist after dead batch（断点不前移）")
	}
	for _, tb := range []string{"api_runtime_events", "api_endpoints", "api_parameter_value_obs"} {
		if got := tableCount(t, ctx, pool, tb); got != 0 {
			t.Fatalf("table %s must stay empty after rollback, got %d rows", tb, got)
		}
	}

	// 重放：正常事务工厂，完整落库
	c2 := newIntegrationCollector(pool, logPath, cpPath, true)
	c2.SetFlushPolicy(100, time.Hour)
	n, err := c2.CollectOnce(ctx)
	if err != nil {
		t.Fatalf("replay CollectOnce: %v", err)
	}
	if n != len(lines) {
		t.Fatalf("want %d replayed, got %d", len(lines), n)
	}
	if got := tableCount(t, ctx, pool, "api_endpoints"); got != 7 {
		t.Fatalf("want 7 endpoints after replay, got %d", got)
	}
}

// BenchmarkCollectorIngest 逐语句 autocommit vs 批次事务在 1 万合成事件上的入库对比。
// 每个 benchmark 迭代重建数据并全量采集一轮；rows/s 由 go test 输出。
// 复跑：bash test/performance/w22-collector-batchtx-bench.sh
func BenchmarkCollectorIngest(b *testing.B) {
	dsn := os.Getenv("APIRUNTIME_TEST_PG_DSN")
	if dsn == "" {
		b.Skip("APIRUNTIME_TEST_PG_DSN not set, skipping PG benchmark")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		b.Fatalf("connect pg: %v", err)
	}
	defer pool.Close()
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		b.Fatalf("migrate: %v", err)
	}
	lines := benchLines(10000)

	for _, mode := range []string{"autocommit", "batchtx"} {
		b.Run(mode, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				if _, err := pool.Exec(ctx, `
TRUNCATE api_runtime_events, api_schema_violations, api_runtime_findings,
  api_learning_samples, api_learning_jobs, api_parameter_value_obs, api_response_schemas,
  api_file_assets, api_llm_observations, api_endpoint_traffic_buckets,
  api_endpoint_path_segments, api_endpoints CASCADE`); err != nil {
					b.Fatalf("truncate: %v", err)
				}
				dir := b.TempDir()
				logPath := filepath.Join(dir, "api-runtime-events.log")
				if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
					b.Fatal(err)
				}
				c := newIntegrationCollector(pool, logPath, filepath.Join(dir, "checkpoint"), mode == "batchtx")
				c.SetFlushPolicy(2000, 2*time.Second) // 生产默认节奏（W20）
				b.StartTimer()
				start := time.Now()
				n, err := c.CollectOnce(ctx)
				elapsed := time.Since(start)
				b.StopTimer()
				if err != nil {
					b.Fatalf("CollectOnce: %v", err)
				}
				if n != len(lines) {
					b.Fatalf("want %d processed, got %d", len(lines), n)
				}
				b.ReportMetric(float64(len(lines))/elapsed.Seconds(), "rows/s")
			}
		})
	}
}
