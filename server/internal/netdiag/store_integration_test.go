// store_integration_test.go netdiag_jobs 仓储集成测试（迁移 000160 契约 + CRUD/状态机）。
// 依赖一次性 PostgreSQL：NETDIAG_TEST_PG_DSN 未设置时 t.Skip（环境不可用如实跳过，不 mock 冒充）。
package netdiag

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func openNetdiagPostgres(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("NETDIAG_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("NETDIAG_TEST_PG_DSN not set, skipping netdiag PG integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("create pg pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping pg: %v", err)
	}
	return pool, ctx
}

func TestNetdiagStorePostgresContract(t *testing.T) {
	pool, ctx := openNetdiagPostgres(t)

	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	// 重跑应为空转（保护部分发布后重试）
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("rerun migrations: %v", err)
	}
	var applied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version = 160`).Scan(&applied); err != nil {
		t.Fatalf("check migration record: %v", err)
	}
	if applied != 1 {
		t.Fatalf("migration 160 records=%d, want 1", applied)
	}

	s := NewStore(pool)
	uid := uuid.New()
	j, err := s.Create(ctx, "it-gateway-01", ActionPing, "10.0.0.1", Params{Count: 4}, &uid, "req-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if j.Status != StatusPending || j.Action != ActionPing || j.DecodeParams().Count != 4 {
		t.Fatalf("创建内容不符: %+v", j)
	}

	got, err := s.GetByID(ctx, j.ID)
	if err != nil || got.Target != "10.0.0.1" {
		t.Fatalf("GetByID: %v %+v", err, got)
	}
	if _, err := s.GetByID(ctx, uuid.New()); err != ErrNotFound {
		t.Fatalf("不存在应 ErrNotFound: %v", err)
	}

	jobs, total, err := s.List(ctx, ActionPing, "", 1, 20)
	if err != nil || total != 1 || len(jobs) != 1 {
		t.Fatalf("List: %v total=%d len=%d", err, total, len(jobs))
	}
	if _, total, err := s.List(ctx, ActionCapture, "", 1, 20); err != nil || total != 0 {
		t.Fatalf("List 过滤: %v total=%d", err, total)
	}

	ok, err := s.MarkRunning(ctx, j.ID)
	if err != nil || !ok {
		t.Fatalf("MarkRunning: %v ok=%v", err, ok)
	}
	if ok, _ := s.MarkRunning(ctx, j.ID); ok {
		t.Fatal("重复 MarkRunning 应返回 false")
	}

	exit := 0
	dur := int64(100)
	if err := s.Finish(ctx, j.ID, StatusSuccess, "pong", &exit, &dur, ""); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	got, _ = s.GetByID(ctx, j.ID)
	if got.Status != StatusSuccess || got.ResultText != "pong" || got.ExitCode == nil || *got.ExitCode != 0 ||
		got.DurationMs == nil || *got.DurationMs != 100 || got.FinishedAt == nil {
		t.Fatalf("终态内容不符: %+v", got)
	}
	if err := s.Finish(ctx, j.ID, StatusFailed, "x", nil, nil, "y"); err != ErrNotFound {
		t.Fatalf("终态后 Finish 应 ErrNotFound: %v", err)
	}

	// StopPending 状态机
	j2, err := s.Create(ctx, "it-gateway-01", ActionDNSQuery, "example.com", Params{}, nil, "")
	if err != nil {
		t.Fatalf("Create2: %v", err)
	}
	if ok, err := s.StopPending(ctx, j2.ID); err != nil || !ok {
		t.Fatalf("StopPending: %v ok=%v", err, ok)
	}
	if ok, _ := s.StopPending(ctx, j2.ID); ok {
		t.Fatal("重复 StopPending 应返回 false")
	}

	// 产物登记
	j3, err := s.Create(ctx, "it-gateway-01", ActionCapture, "10.0.0.1", Params{Iface: "eth0", DurationSec: 10}, nil, "")
	if err != nil {
		t.Fatalf("Create3: %v", err)
	}
	if err := s.SetCaptureArtifact(ctx, j3.ID, CaptureFileName(j3.ID), 1024, "ab"); err != nil {
		t.Fatalf("SetCaptureArtifact: %v", err)
	}
	got, _ = s.GetByID(ctx, j3.ID)
	if got.CaptureFile != CaptureFileName(j3.ID) || got.CaptureHash != "ab" || got.CaptureSize == nil || *got.CaptureSize != 1024 {
		t.Fatalf("产物字段不符: %+v", got)
	}

	// capture_packets 解析列表（迁移 000163）：SetCapturePackets 入库、GetByID 带出、List 不查该列
	if got.CapturePackets != nil {
		t.Fatalf("未登记时 capture_packets 应为 NULL，实际 %s", got.CapturePackets)
	}
	packetsJSON := []byte(`[{"no":1,"ts":"2023-11-14T22:13:20.123456Z","src":"172.19.0.1","dst":"172.19.0.2","sport":52344,"dport":8080,"proto":"TCP","flags":"SYN,ACK","length":74,"preview":"GET /"}]`)
	if err := s.SetCapturePackets(ctx, j3.ID, packetsJSON); err != nil {
		t.Fatalf("SetCapturePackets: %v", err)
	}
	got, _ = s.GetByID(ctx, j3.ID)
	// jsonb 回读会重排对象键/规整空白，按语义比对
	var decoded []CapturePacket
	if err := json.Unmarshal(got.CapturePackets, &decoded); err != nil {
		t.Fatalf("capture_packets 应为 JSON 数组: %v", err)
	}
	if len(decoded) != 1 || decoded[0].Proto != "TCP" || decoded[0].Flags != "SYN,ACK" ||
		decoded[0].Sport == nil || *decoded[0].Sport != 52344 || decoded[0].Length != 74 {
		t.Fatalf("capture_packets 内容不符: %s", got.CapturePackets)
	}
	capJobs, capTotal, err := s.List(ctx, ActionCapture, "", 1, 20)
	if err != nil || capTotal != 1 || len(capJobs) != 1 {
		t.Fatalf("List capture: %v total=%d", err, capTotal)
	}
	if capJobs[0].CapturePackets != nil {
		t.Fatalf("列表不应查 capture_packets 列，实际 %s", capJobs[0].CapturePackets)
	}
}
