// W20 采集器批量化修复：全量访问日志采集器（accesslogs）集成测试。
//
// 覆盖（真实 PostgreSQL，不 mock）：批量/周期 flush 参数接线后 CollectOnce 全量入库 +
// 断点精确落文件尾；重复采集幂等（request_id 唯一索引去重，行数不增）；断点回退重放
// 有界且幂等（模拟崩溃后从断点重扫，已入库行不重复）；增量追加续传。
// 现场与改造依据：docs/evidence/api-security-performance-baseline.md §11.8 发现 2。
//
// 运行方式（与既有 PG-only 集成测试同一纪律）：
//
//	POSTGRES_PASSWORD=... go test ./tests -run TestAccessLogsCollectorFlush -count=1
//
// 无 POSTGRES_PASSWORD 时 t.Skip。
package tests

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/accesslogs"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/database"
)

// setupAccessLogsFlushDB 重建测试库并执行全量迁移（只需 PostgreSQL；不依赖 Valkey/完整应用）。
func setupAccessLogsFlushDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	password := os.Getenv("POSTGRES_PASSWORD")
	if password == "" {
		t.Skip("POSTGRES_PASSWORD not set, skipping integration test")
	}
	cfg := config.DBConfig{
		Host:     envOr("POSTGRES_HOST", "127.0.0.1"),
		Port:     envInt("POSTGRES_PORT", 5432),
		Database: testDBName,
		User:     envOr("POSTGRES_USER", "jiuzhang"),
		Password: password,
		SSLMode:  "disable",
		MaxConns: 5,
	}
	ctx := context.Background()
	adminDSN := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable",
		cfg.User, cfg.Password, cfg.Host, cfg.Port)
	adminPool, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin db: %v", err)
	}
	_, _ = adminPool.Exec(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s", testDBName))
	if _, err := adminPool.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s", testDBName)); err != nil {
		adminPool.Close()
		t.Fatalf("create test db: %v", err)
	}
	adminPool.Close()

	db, err := database.Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := database.Migrate(ctx, db, "../migrations", "up"); err != nil {
		db.Close()
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func accessLogLine(requestID string, at time.Time) string {
	return fmt.Sprintf(`{"occurred_at":%q,"request_id":%q,"domain":"w20.example.com","gateway_node_id":"node-1",`+
		`"client_ip":"203.0.113.10","client_port":51000,"request_method":"GET","request_uri":"/v1/items?id=1",`+
		`"request_path":"/v1/items","http_version":"HTTP/1.1","response_status":200,"bytes_in":0,"bytes_out":128,`+
		`"duration_ms":3,"waf_action":"ALLOW"}`,
		at.Format(time.RFC3339Nano), requestID)
}

func countAccessLogs(t *testing.T, ctx context.Context, db *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM access_logs`).Scan(&n); err != nil {
		t.Fatalf("count access_logs: %v", err)
	}
	return n
}

func readAccessLogCheckpoint(t *testing.T, ctx context.Context, db *pgxpool.Pool, collectorID string) int64 {
	t.Helper()
	var off int64
	if err := db.QueryRow(ctx,
		`SELECT file_offset FROM event_collector_checkpoints WHERE collector_id = $1`, collectorID).Scan(&off); err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	return off
}

func TestAccessLogsCollectorFlush(t *testing.T) {
	db := setupAccessLogsFlushDB(t)
	ctx := context.Background()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "access-full.jsonl")
	now := time.Now().UTC()
	lines := make([]string, 0, 7)
	for i := 1; i <= 5; i++ {
		lines = append(lines, accessLogLine(fmt.Sprintf("w20-al-%d", i), now.Add(time.Duration(i)*time.Second)))
	}
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}

	// 批量阈值 2 / 周期阈值 1ns：扫描中途多次落断点（触发路径存在性由真实 DB 验证）
	c := accesslogs.NewCollector(db, "w20-accesslog-flush", logPath)
	c.SetFlushPolicy(2, time.Nanosecond)

	n, err := c.CollectOnce(ctx)
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 5 {
		t.Fatalf("want 5 processed, got %d", n)
	}
	if got := countAccessLogs(t, ctx, db); got != 5 {
		t.Fatalf("access_logs rows = %d, want 5", got)
	}
	// EOF 末次 flush 后断点精确落在文件尾
	if off := readAccessLogCheckpoint(t, ctx, db, "w20-accesslog-flush"); off != info.Size() {
		t.Fatalf("checkpoint offset = %d, want file size %d", off, info.Size())
	}

	// 幂等：无新内容再采零处理、行数不增
	if n2, err := c.CollectOnce(ctx); err != nil || n2 != 0 {
		t.Fatalf("second CollectOnce want (0,nil), got (%d,%v)", n2, err)
	}
	if got := countAccessLogs(t, ctx, db); got != 5 {
		t.Fatalf("rows after idle recollect = %d, want 5", got)
	}

	// 断点回退重放（模拟崩溃后从断点重扫）：重置断点到第 2 行末尾，重读 3 行，
	// request_id 唯一索引去重——行数不增、无重复（重放安全兜底）。
	off2 := int64(len(lines[0]) + 1 + len(lines[1]) + 1)
	if _, err := db.Exec(ctx,
		`UPDATE event_collector_checkpoints SET file_offset = $1 WHERE collector_id = $2`,
		off2, "w20-accesslog-flush"); err != nil {
		t.Fatalf("rewind checkpoint: %v", err)
	}
	n3, err := c.CollectOnce(ctx)
	if err != nil {
		t.Fatalf("replay CollectOnce: %v", err)
	}
	if n3 != 3 {
		t.Fatalf("want bounded replay of 3 lines, got %d", n3)
	}
	if got := countAccessLogs(t, ctx, db); got != 5 {
		t.Fatalf("rows after replay = %d, want 5（request_id 幂等去重）", got)
	}
	if off := readAccessLogCheckpoint(t, ctx, db, "w20-accesslog-flush"); off != info.Size() {
		t.Fatalf("checkpoint after replay = %d, want %d", off, info.Size())
	}

	// 增量续传：追加 2 行只处理新增部分
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for i := 6; i <= 7; i++ {
		if _, err := f.WriteString(accessLogLine(fmt.Sprintf("w20-al-%d", i), now.Add(time.Duration(i)*time.Second)) + "\n"); err != nil {
			f.Close()
			t.Fatal(err)
		}
	}
	f.Close()
	n4, err := c.CollectOnce(ctx)
	if err != nil {
		t.Fatalf("incremental CollectOnce: %v", err)
	}
	if n4 != 2 {
		t.Fatalf("want 2 incremental lines, got %d", n4)
	}
	if got := countAccessLogs(t, ctx, db); got != 7 {
		t.Fatalf("rows after append = %d, want 7", got)
	}
}
