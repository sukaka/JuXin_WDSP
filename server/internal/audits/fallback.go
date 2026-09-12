package audits

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

const fallbackQueueFilename = "operation-audit.jsonl"

var (
	writeFailures   atomic.Uint64
	retryPending    atomic.Uint64
	retrySuccesses  atomic.Uint64
	enqueueFailures atomic.Uint64
)

type fallbackEntry struct {
	DeliveryID uuid.UUID   `json:"delivery_id"`
	QueuedAt   time.Time   `json:"queued_at"`
	Input      RecordInput `json:"input"`
}

// WriteFailures 返回进程启动以来审计数据库写入失败累计次数。
func WriteFailures() uint64 { return writeFailures.Load() }

// RetryPending 返回当前本地持久化补写队列中的记录数。
func RetryPending() uint64 { return retryPending.Load() }

// RenderMetrics 输出 Prometheus 文本格式的审计投递指标。
func RenderMetrics() string {
	return fmt.Sprintf(`# HELP audit_write_failures_total Total audit database write failures.
# TYPE audit_write_failures_total counter
audit_write_failures_total %d
# HELP audit_retry_queue_pending Audit records waiting in the durable retry queue.
# TYPE audit_retry_queue_pending gauge
audit_retry_queue_pending %d
# HELP audit_retry_success_total Audit retry queue entries successfully reconciled.
# TYPE audit_retry_success_total counter
audit_retry_success_total %d
# HELP audit_retry_enqueue_failures_total Total failures to persist an audit retry entry.
# TYPE audit_retry_enqueue_failures_total counter
audit_retry_enqueue_failures_total %d
`, writeFailures.Load(), retryPending.Load(), retrySuccesses.Load(), enqueueFailures.Load())
}

// Recorder 是 RecordWithFallback 所需的最小审计记录接口。
type Recorder interface {
	Record(ctx context.Context, in RecordInput) error
}

// ConfigureFallback 初始化本地持久化补写队列。目录和队列文件分别限制为
// 0700/0600；若已有队列则在启动时恢复待补写计数。
func (s *Service) ConfigureFallback(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("audit fallback directory is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create audit fallback directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("protect audit fallback directory: %w", err)
	}

	path := filepath.Join(dir, fallbackQueueFilename)
	s.fallbackMu.Lock()
	defer s.fallbackMu.Unlock()
	entries, err := readFallbackEntries(path)
	if err != nil {
		return fmt.Errorf("read audit fallback queue: %w", err)
	}
	s.fallbackPath = path
	retryPending.Store(uint64(len(entries)))
	return nil
}

// SetFallbackHooks 装配补写队列失败与恢复回调。回调不得修改审计队列。
func (s *Service) SetFallbackHooks(failed func(context.Context, uint64, error), recovered func(context.Context)) {
	s.fallbackMu.Lock()
	defer s.fallbackMu.Unlock()
	s.failureHook = failed
	s.recoveredHook = recovered
}

// RecordWithFallback 在业务已成功后写审计。Service 配置了持久化补写目录时，
// 数据库故障会先把脱敏后的记录同步落盘，再由后台任务补写；只有数据库和本地
// 队列同时失败时才把记录标记为丢失。接口替身保持原有日志与计数语义。
func RecordWithFallback(ctx context.Context, r Recorder, in RecordInput) {
	if r == nil {
		return
	}
	if svc, ok := r.(*Service); ok {
		if err := svc.recordDurably(ctx, in); err != nil {
			slog.Error("audit record lost after business success",
				"request_id", in.RequestID, "module", in.Module, "action", in.Action,
				"object_type", in.ObjectType, "object_id", in.ObjectID,
				"username", in.Username, "error", err)
		}
		return
	}
	if err := r.Record(ctx, in); err != nil {
		writeFailures.Add(1)
		slog.Error("audit record lost after business success",
			"request_id", in.RequestID, "module", in.Module, "action", in.Action,
			"object_type", in.ObjectType, "object_id", in.ObjectID,
			"username", in.Username, "error", err)
	}
}

func (s *Service) recordDurably(ctx context.Context, in RecordInput) error {
	if _, err := s.persist(ctx, in, nil); err == nil {
		return nil
	} else {
		writeFailures.Add(1)
		primaryErr := err
		entry := fallbackEntry{
			DeliveryID: uuid.New(),
			QueuedAt:   time.Now().UTC(),
			Input:      sanitizeInput(in),
		}
		pending, hook, queueErr := s.enqueueFallback(entry)
		if queueErr != nil {
			enqueueFailures.Add(1)
			return errors.Join(primaryErr, fmt.Errorf("persist audit fallback: %w", queueErr))
		}
		slog.Error("audit record queued for retry",
			"request_id", in.RequestID, "module", in.Module, "action", in.Action,
			"object_type", in.ObjectType, "object_id", in.ObjectID,
			"username", in.Username, "pending", pending, "error", primaryErr)
		if hook != nil {
			hook(ctx, pending, primaryErr)
		}
		return nil
	}
}

func (s *Service) persist(ctx context.Context, in RecordInput, deliveryID *uuid.UUID) (bool, error) {
	if s.persistOverride != nil {
		return s.persistOverride(ctx, in, deliveryID)
	}
	return s.recordWithDelivery(ctx, in, deliveryID)
}

func sanitizeInput(in RecordInput) RecordInput {
	in.BeforeSummary = MaskSensitiveJSON(in.BeforeSummary)
	in.AfterSummary = MaskSensitiveJSON(in.AfterSummary)
	return in
}

func (s *Service) enqueueFallback(entry fallbackEntry) (uint64, func(context.Context, uint64, error), error) {
	s.fallbackMu.Lock()
	defer s.fallbackMu.Unlock()
	if s.fallbackPath == "" {
		return retryPending.Load(), nil, errors.New("audit fallback is not configured")
	}
	f, err := os.OpenFile(s.fallbackPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return retryPending.Load(), nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return retryPending.Load(), nil, err
	}
	encodeErr := json.NewEncoder(f).Encode(entry)
	if encodeErr == nil {
		encodeErr = f.Sync()
	}
	closeErr := f.Close()
	if encodeErr != nil {
		return retryPending.Load(), nil, encodeErr
	}
	if closeErr != nil {
		return retryPending.Load(), nil, closeErr
	}
	pending := retryPending.Add(1)
	return pending, s.failureHook, nil
}

// DrainFallback 按队列顺序补写。delivery_id 唯一索引保证进程在数据库提交后、
// 队列改写前崩溃时可安全重放，不会生成重复审计记录。
func (s *Service) DrainFallback(ctx context.Context) error {
	s.fallbackMu.Lock()
	if s.fallbackPath == "" {
		s.fallbackMu.Unlock()
		return nil
	}
	entries, err := readFallbackEntries(s.fallbackPath)
	if err != nil {
		s.fallbackMu.Unlock()
		return err
	}
	if len(entries) == 0 {
		retryPending.Store(0)
		s.fallbackMu.Unlock()
		return nil
	}

	completed := 0
	for i := range entries {
		if _, err := s.persist(ctx, entries[i].Input, &entries[i].DeliveryID); err != nil {
			writeFailures.Add(1)
			hook := s.failureHook
			// 成功项仍保留在队列文件中，下一轮依靠 delivery_id 幂等重放；
			// 指标必须反映磁盘中的真实条目数，不能少报。
			pending := uint64(len(entries))
			retryPending.Store(pending)
			s.fallbackMu.Unlock()
			if hook != nil {
				hook(ctx, pending, err)
			}
			return err
		}
		completed++
	}

	if err := rewriteFallbackEntries(s.fallbackPath, nil); err != nil {
		retryPending.Store(uint64(len(entries)))
		s.fallbackMu.Unlock()
		return fmt.Errorf("clear audit fallback queue: %w", err)
	}
	retryPending.Store(0)
	retrySuccesses.Add(uint64(completed))
	recovered := s.recoveredHook
	s.fallbackMu.Unlock()
	if recovered != nil {
		recovered(ctx)
	}
	return nil
}

// RunFallback 启动持久化队列后台补写，启动即尝试一次，之后按间隔重试。
func (s *Service) RunFallback(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	drain := func() {
		if err := s.DrainFallback(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Warn("audit fallback retry failed", "pending", RetryPending(), "error", err)
		}
	}
	drain()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			drain()
		}
	}
}

func readFallbackEntries(path string) ([]fallbackEntry, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	entries := make([]fallbackEntry, 0)
	decoder := json.NewDecoder(bufio.NewReader(f))
	for {
		var entry fallbackEntry
		if err := decoder.Decode(&entry); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		if entry.DeliveryID == uuid.Nil {
			return nil, errors.New("audit fallback entry has empty delivery_id")
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func rewriteFallbackEntries(path string, entries []fallbackEntry) error {
	dir := filepath.Dir(path)
	if len(entries) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDirectory(dir)
	}
	tmp, err := os.CreateTemp(dir, ".operation-audit-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	encoder := json.NewEncoder(tmp)
	for i := range entries {
		if err := encoder.Encode(entries[i]); err != nil {
			cleanup()
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return syncDirectory(dir)
}

func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
