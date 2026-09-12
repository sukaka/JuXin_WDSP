package audits

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errTest = errors.New("injected audit store failure")

// 故障注入：审计库不可用（惰性连接池指向不可用端口，Begin 必然立即失败）时，
// RecordWithFallback 不 panic、不向调用方返回错误，失败进入结构化错误日志与计数器，
// 且日志不泄露摘要中的敏感 payload。
func TestRecordWithFallbackAuditDown(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://127.0.0.1:1/audits_test?connect_timeout=2")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()
	s := NewService(pool)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})))
	defer slog.SetDefault(prev)

	before := WriteFailures()
	in := RecordInput{
		Username:      "admin",
		Module:        "apm",
		Action:        "update",
		ObjectType:    "setting",
		ObjectID:      "apm:clickhouse_dsn",
		Result:        ResultSuccess,
		RiskLevel:     RiskHigh,
		RequestID:     "req-fallback",
		BeforeSummary: `{"password":"super-secret"}`,
	}
	RecordWithFallback(context.Background(), s, in)

	if got := WriteFailures(); got != before+1 {
		t.Errorf("WriteFailures = %d, want %d", got, before+1)
	}
	out := buf.String()
	if !strings.Contains(out, "audit record lost after business success") {
		t.Errorf("缺少错误日志: %q", out)
	}
	for _, want := range []string{"req-fallback", "update", "setting", "apm:clickhouse_dsn", "admin"} {
		if !strings.Contains(out, want) {
			t.Errorf("日志缺少 %q: %q", want, out)
		}
	}
	if strings.Contains(out, "super-secret") || strings.Contains(out, "password") {
		t.Errorf("日志泄露敏感 payload 细节: %q", out)
	}
}

// 计数器单调递增：连续失败逐次累加，不互相覆盖。
func TestRecordWithFallbackCountsEachFailure(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://127.0.0.1:1/audits_test?connect_timeout=2")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()
	s := NewService(pool)

	before := WriteFailures()
	for i := 0; i < 3; i++ {
		RecordWithFallback(context.Background(), s, RecordInput{Action: "update", Result: ResultSuccess})
	}
	if got := WriteFailures(); got != before+3 {
		t.Errorf("WriteFailures = %d, want %d", got, before+3)
	}
}

// nil Recorder 安全跳过（审计未接线的测试场景）；接口实现（非 *Service）失败同样计入兜底。
type failRecorder struct{ err error }

func (f failRecorder) Record(context.Context, RecordInput) error { return f.err }

func TestRecordWithFallbackNilAndInterface(t *testing.T) {
	RecordWithFallback(context.Background(), nil, RecordInput{Action: "noop"}) // 不得 panic

	before := WriteFailures()
	RecordWithFallback(context.Background(), failRecorder{err: errTest}, RecordInput{Action: "update"})
	if got := WriteFailures(); got != before+1 {
		t.Errorf("WriteFailures = %d, want %d", got, before+1)
	}
}

func TestServiceQueuesFailedAuditAndRetriesExactlyOnce(t *testing.T) {
	s := NewService(nil)
	queueDir := filepath.Join(t.TempDir(), "audit-outbox")
	if err := s.ConfigureFallback(queueDir); err != nil {
		t.Fatalf("ConfigureFallback: %v", err)
	}

	attempts := 0
	s.persistOverride = func(_ context.Context, in RecordInput, deliveryID *uuid.UUID) (bool, error) {
		attempts++
		if attempts == 1 {
			return false, errTest
		}
		if deliveryID == nil || *deliveryID == uuid.Nil {
			t.Fatal("补写必须携带稳定 delivery_id")
		}
		if strings.Contains(in.BeforeSummary, "super-secret") {
			t.Fatal("持久化队列中的摘要必须先脱敏")
		}
		return true, nil
	}

	RecordWithFallback(context.Background(), s, RecordInput{
		Username:      "admin",
		Module:        "users",
		Action:        "update",
		ObjectType:    "user",
		ObjectID:      "u-1",
		BeforeSummary: `{"password":"super-secret"}`,
		Result:        ResultSuccess,
	})

	if got := RetryPending(); got != 1 {
		t.Fatalf("RetryPending = %d, want 1", got)
	}
	info, err := os.Stat(filepath.Join(queueDir, fallbackQueueFilename))
	if err != nil {
		t.Fatalf("持久化队列不存在: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("队列权限 = %o, want 600", got)
	}

	if err := s.DrainFallback(context.Background()); err != nil {
		t.Fatalf("DrainFallback: %v", err)
	}
	if got := RetryPending(); got != 0 {
		t.Fatalf("RetryPending = %d, want 0", got)
	}
	if attempts != 2 {
		t.Fatalf("persist attempts = %d, want 2", attempts)
	}
	if _, err := os.Stat(filepath.Join(queueDir, fallbackQueueFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("队列清空后应删除文件，stat err = %v", err)
	}
}

func TestDrainFallbackKeepsEntryWhenRetryFails(t *testing.T) {
	s := NewService(nil)
	queueDir := t.TempDir()
	if err := s.ConfigureFallback(queueDir); err != nil {
		t.Fatalf("ConfigureFallback: %v", err)
	}
	s.persistOverride = func(context.Context, RecordInput, *uuid.UUID) (bool, error) {
		return false, errTest
	}
	RecordWithFallback(context.Background(), s, RecordInput{Module: "settings", Action: "update"})

	if err := s.DrainFallback(context.Background()); !errors.Is(err, errTest) {
		t.Fatalf("DrainFallback error = %v, want %v", err, errTest)
	}
	if got := RetryPending(); got != 1 {
		t.Fatalf("RetryPending = %d, want 1", got)
	}
	if _, err := os.Stat(filepath.Join(queueDir, fallbackQueueFilename)); err != nil {
		t.Fatalf("失败补写后队列必须保留: %v", err)
	}
}

func TestRenderMetricsContainsAuditDeliveryState(t *testing.T) {
	got := RenderMetrics()
	for _, metric := range []string{
		"audit_write_failures_total",
		"audit_retry_queue_pending",
		"audit_retry_success_total",
		"audit_retry_enqueue_failures_total",
	} {
		if !strings.Contains(got, metric) {
			t.Errorf("指标输出缺少 %s", metric)
		}
	}
}
