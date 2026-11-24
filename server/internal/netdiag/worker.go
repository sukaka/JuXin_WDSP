// worker.go 网络诊断调度 Worker：
// PENDING → 原子写共享卷请求文件并置 RUNNING；轮询 netmgrd 回写的结果文件落库终态；
// 超时收割；抓包产物搬移（共享卷 → 服务端数据目录，sha256 入库）并解析数据包列表入库；孤儿文件清理。
package netdiag

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// orphanFileMaxAge diag 目录下无对应任务且超过该时长的文件视为孤儿清理。
const orphanFileMaxAge = time.Hour

// diagDir 共享卷诊断目录（<SidecarDir>/diag）。
func diagDir(sidecarDir string) string { return filepath.Join(sidecarDir, "diag") }

// requestPath/resultPath/stopFlagPath 契约文件路径。
func requestPath(sidecarDir string, id uuid.UUID) string {
	return filepath.Join(diagDir(sidecarDir), "request-"+id.String()+".json")
}

func resultPath(sidecarDir string, id uuid.UUID) string {
	return filepath.Join(diagDir(sidecarDir), "result-"+id.String()+".json")
}

func stopFlagPath(sidecarDir string, id uuid.UUID) string {
	return filepath.Join(diagDir(sidecarDir), "stop-"+id.String())
}

// CaptureFileName 抓包产物文件名（capture-<jobUUID>.pcap）。
func CaptureFileName(id uuid.UUID) string { return "capture-" + id.String() + ".pcap" }

// CapturePath 服务端数据目录中的抓包产物路径（文件名仅由任务 ID 派生）。
func CapturePath(dataDir string, id uuid.UUID) (string, error) {
	name := CaptureFileName(id)
	if strings.ContainsAny(name, "/\\") || filepath.Base(name) != name {
		return "", fmt.Errorf("invalid capture file name: %q", name)
	}
	return filepath.Join(dataDir, name), nil
}

// sidecarRequest 请求文件内容（server 写，netmgrd 消费；字段顺序与冻结契约一致）。
type sidecarRequest struct {
	Version    int    `json:"version"`
	JobID      string `json:"job_id"`
	Node       string `json:"node"`
	Action     string `json:"action"`
	Target     string `json:"target"`
	Params     Params `json:"params"`
	TimeoutSec int    `json:"timeout_sec"`
}

// sidecarResult 结果文件内容（netmgrd 写，server Worker 消费）。
type sidecarResult struct {
	JobID       string `json:"job_id"`
	Status      string `json:"status"`
	ExitCode    *int   `json:"exit_code"`
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	DurationMs  *int64 `json:"duration_ms"`
	CaptureFile string `json:"capture_file"`
	CaptureSize int64  `json:"capture_size"`
	FinishedAt  string `json:"finished_at"`
}

// workerStore Worker 依赖的仓储接口。
type workerStore interface {
	ListByStatus(ctx context.Context, statuses ...string) ([]Job, error)
	MarkRunning(ctx context.Context, id uuid.UUID) (bool, error)
	Finish(ctx context.Context, id uuid.UUID, status, resultText string, exitCode *int, durationMs *int64, failureMsg string) error
	SetCaptureArtifact(ctx context.Context, id uuid.UUID, file string, size int64, hash string) error
	SetCapturePackets(ctx context.Context, id uuid.UUID, packets []byte) error
}

// Worker 诊断调度工人。
type Worker struct {
	store      workerStore
	sidecarDir string
	dataDir    string
	nodeName   string
	now        func() time.Time // 测试可注入时钟
}

// NewWorker 创建调度工人。
func NewWorker(store workerStore, sidecarDir, dataDir, nodeName string) *Worker {
	return &Worker{store: store, sidecarDir: sidecarDir, dataDir: dataDir, nodeName: nodeName, now: time.Now}
}

// Run 周期调度（interval 由装配层传入，生产 2s）。
func (w *Worker) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		w.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// ensureSharedDiagDir 确保 sidecarDir 与 diag 子目录存在且为 0770（显式 Chmod 避免 umask 剥离组写位），
// 使加入共享组 1000（无 CAP_DAC_OVERRIDE）的 netmgrd 可读写请求/结果文件，且不开放 other 权限。
func ensureSharedDiagDir(sidecarDir string) error {
	if err := os.MkdirAll(sidecarDir, 0o770); err != nil {
		return err
	}
	if err := os.Chmod(sidecarDir, 0o770); err != nil {
		return err
	}
	dir := diagDir(sidecarDir)
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return err
	}
	return os.Chmod(dir, 0o770)
}

func (w *Worker) tick(ctx context.Context) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("netdiag worker tick panic", "panic", rec)
		}
	}()
	if err := ensureSharedDiagDir(w.sidecarDir); err != nil {
		slog.Error("netdiag worker: create diag dir failed", "error", err)
		return
	}
	w.dispatch(ctx)
	w.collect(ctx)
	w.sweepOrphans(ctx)
}

// dispatch PENDING → 写请求文件 → RUNNING。
func (w *Worker) dispatch(ctx context.Context) {
	jobs, err := w.store.ListByStatus(ctx, StatusPending)
	if err != nil {
		slog.Error("netdiag worker: list pending failed", "error", err)
		return
	}
	for i := range jobs {
		j := &jobs[i]
		if j.Node != w.nodeName {
			continue // 非本节点任务（多节点部署由对应节点 API 消费）
		}
		if err := writeRequestFile(w.sidecarDir, j); err != nil {
			slog.Error("netdiag worker: write request failed", "job_id", j.ID, "error", err)
			continue
		}
		if ok, err := w.store.MarkRunning(ctx, j.ID); err != nil {
			slog.Error("netdiag worker: mark running failed", "job_id", j.ID, "error", err)
			_ = os.Remove(requestPath(w.sidecarDir, j.ID))
		} else if !ok {
			// 竞态：任务已被停止/完成，回收请求文件
			_ = os.Remove(requestPath(w.sidecarDir, j.ID))
		}
	}
}

// writeRequestFile 原子写请求文件（0640，tmp+rename；供同组 1000 且无 CAP_DAC_OVERRIDE 的 netmgrd 只读消费，禁止 other 访问）。
func writeRequestFile(sidecarDir string, j *Job) error {
	params := j.DecodeParams()
	req := sidecarRequest{
		Version:    1,
		JobID:      j.ID.String(),
		Node:       j.Node,
		Action:     j.Action,
		Target:     j.Target,
		Params:     params,
		TimeoutSec: int(actionTimeout(j.Action, params).Seconds()),
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	payload = append(payload, '\n')
	dir := diagDir(sidecarDir)
	tmp, err := os.CreateTemp(dir, ".request-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp request file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod request file: %w", err)
	}
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write request file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync request file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close request file: %w", err)
	}
	if err := os.Rename(tmpName, requestPath(sidecarDir, j.ID)); err != nil {
		return fmt.Errorf("rename request file: %w", err)
	}
	return nil
}

// collect 轮询 RUNNING 任务：消费结果文件落库终态；超时收割。
func (w *Worker) collect(ctx context.Context) {
	jobs, err := w.store.ListByStatus(ctx, StatusRunning)
	if err != nil {
		slog.Error("netdiag worker: list running failed", "error", err)
		return
	}
	for i := range jobs {
		j := &jobs[i]
		if j.Node != w.nodeName {
			continue
		}
		res, err := readResultFile(w.sidecarDir, j.ID)
		if err != nil {
			slog.Error("netdiag worker: read result failed", "job_id", j.ID, "error", err)
			continue
		}
		if res != nil {
			w.consumeResult(ctx, j, res)
			continue
		}
		w.reapTimeout(ctx, j)
	}
}

func readResultFile(sidecarDir string, id uuid.UUID) (*sidecarResult, error) {
	raw, err := os.ReadFile(resultPath(sidecarDir, id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var res sidecarResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("parse result file: %w", err)
	}
	return &res, nil
}

// consumeResult 消费 netmgrd 结果文件：落库终态、搬移抓包产物、删除结果文件。
func (w *Worker) consumeResult(ctx context.Context, j *Job, res *sidecarResult) {
	status := res.Status
	switch status {
	case StatusSuccess, StatusFailed, StatusTimeout, StatusStopped:
	default:
		status = StatusFailed
	}
	resultText := mergeResultText(res.Stdout, res.Stderr)
	failureMsg := ""
	if status == StatusFailed {
		failureMsg = truncate(res.Stderr, 512)
		if failureMsg == "" {
			failureMsg = "诊断执行失败"
		}
	}
	if status == StatusTimeout && failureMsg == "" {
		failureMsg = "诊断执行超时"
	}
	if status == StatusStopped && failureMsg == "" {
		failureMsg = "任务已停止"
	}
	// 抓包产物：搬入服务端数据目录并算 sha256 入库（失败不阻断终态落库，仅不登记产物）
	if j.Action == ActionCapture && status == StatusSuccess && res.CaptureFile != "" {
		if err := w.importCapture(ctx, j.ID); err != nil {
			slog.Error("netdiag worker: import capture failed", "job_id", j.ID, "error", err)
		} else {
			w.parseCapture(ctx, j.ID)
		}
	}
	if err := w.store.Finish(ctx, j.ID, status, resultText, res.ExitCode, res.DurationMs, failureMsg); err != nil {
		slog.Error("netdiag worker: finish failed", "job_id", j.ID, "error", err)
		return // 结果文件保留，下轮重试
	}
	_ = os.Remove(resultPath(w.sidecarDir, j.ID))
	_ = os.Remove(stopFlagPath(w.sidecarDir, j.ID))
}

// importCapture 把共享卷 pcap 搬入数据目录、算 sha256 入库、删共享卷 pcap。
func (w *Worker) importCapture(ctx context.Context, id uuid.UUID) error {
	src := filepath.Join(diagDir(w.sidecarDir), CaptureFileName(id))
	dst, err := CapturePath(w.dataDir, id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(w.dataDir, 0o750); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open shared capture: %w", err)
	}
	defer func() { _ = in.Close() }()
	tmp, err := os.CreateTemp(w.dataDir, ".capture-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp capture: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	sum := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, sum), in)
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("copy capture: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync capture: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close capture: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("rename capture: %w", err)
	}
	if err := w.store.SetCaptureArtifact(ctx, id, CaptureFileName(id), size, hex.EncodeToString(sum.Sum(nil))); err != nil {
		return fmt.Errorf("record capture artifact: %w", err)
	}
	_ = os.Remove(src)
	return nil
}

// parseCapture 解析已入库的 pcap 产物，数据包列表 JSON 存入 capture_packets 列。
// 解析失败不阻断任务成功：仅记 Warn，列保持 NULL（页面回退为仅显示下载按钮）。
func (w *Worker) parseCapture(ctx context.Context, id uuid.UUID) {
	path, err := CapturePath(w.dataDir, id)
	if err != nil {
		slog.Warn("netdiag worker: capture path invalid, skip parse", "job_id", id, "error", err)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		slog.Warn("netdiag worker: open capture for parse failed", "job_id", id, "error", err)
		return
	}
	defer func() { _ = f.Close() }()
	packets, truncated, err := ParsePcapReader(bufio.NewReaderSize(f, 64*1024))
	if err != nil {
		slog.Warn("netdiag worker: parse capture failed", "job_id", id, "error", err)
		return
	}
	raw, err := json.Marshal(packets)
	if err != nil {
		slog.Warn("netdiag worker: marshal capture packets failed", "job_id", id, "error", err)
		return
	}
	if err := w.store.SetCapturePackets(ctx, id, raw); err != nil {
		slog.Warn("netdiag worker: record capture packets failed", "job_id", id, "error", err)
		return
	}
	if truncated {
		slog.Info("netdiag worker: capture parsed with truncation", "job_id", id, "parsed", len(packets), "max", MaxCapturePackets)
	}
}

// reapTimeout 超时收割：启动后超过动作级 deadline 仍无结果 → TIMEOUT，尽力清理共享卷残留。
func (w *Worker) reapTimeout(ctx context.Context, j *Job) {
	started := j.CreatedAt
	if j.StartedAt != nil {
		started = *j.StartedAt
	}
	deadline := started.Add(actionTimeout(j.Action, j.DecodeParams()))
	if w.now().Before(deadline) {
		return
	}
	failureMsg := "诊断执行超时"
	if err := w.store.Finish(ctx, j.ID, StatusTimeout, "", nil, nil, failureMsg); err != nil {
		if !errors.Is(err, ErrNotFound) {
			slog.Error("netdiag worker: reap timeout failed", "job_id", j.ID, "error", err)
		}
		return
	}
	_ = os.Remove(requestPath(w.sidecarDir, j.ID))
	_ = os.Remove(stopFlagPath(w.sidecarDir, j.ID))
}

// sweepOrphans 清理 diag 目录下无对应任务且超过 1 小时的孤儿文件。
func (w *Worker) sweepOrphans(ctx context.Context) {
	dir := diagDir(w.sidecarDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	known := map[string]bool{}
	jobs, err := w.store.ListByStatus(ctx, StatusPending, StatusRunning)
	if err != nil {
		return
	}
	for _, j := range jobs {
		known[j.ID.String()] = true
	}
	cutoff := w.now().Add(-orphanFileMaxAge)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue // 临时文件由写入方自清理
		}
		jobID := orphanJobID(name)
		if jobID == "" || known[jobID] {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			slog.Warn("netdiag worker: remove orphan failed", "file", name, "error", err)
		}
	}
}

// orphanJobID 从契约文件名中提取任务 ID（request-/result-/stop-/capture- 前缀），
// 非契约文件名返回空串（不清理未知文件）。
func orphanJobID(name string) string {
	rest := ""
	switch {
	case strings.HasPrefix(name, "request-") && strings.HasSuffix(name, ".json"):
		rest = strings.TrimSuffix(strings.TrimPrefix(name, "request-"), ".json")
	case strings.HasPrefix(name, "result-") && strings.HasSuffix(name, ".json"):
		rest = strings.TrimSuffix(strings.TrimPrefix(name, "result-"), ".json")
	case strings.HasPrefix(name, "stop-"):
		rest = strings.TrimPrefix(name, "stop-")
	case strings.HasPrefix(name, "capture-") && strings.HasSuffix(name, ".pcap"):
		rest = strings.TrimSuffix(strings.TrimPrefix(name, "capture-"), ".pcap")
	}
	if _, err := uuid.Parse(rest); err != nil {
		return ""
	}
	return rest
}

// mergeResultText 合并 stdout/stderr 并截断到入库上限。
func mergeResultText(stdout, stderr string) string {
	out := stdout
	if stderr != "" {
		if out != "" {
			out += "\n[stderr]\n"
		}
		out += stderr
	}
	return truncate(out, maxResultTextBytes)
}

// truncate 按字节截断（不切断 UTF-8 序列尾）。
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := s[:max]
	for len(cut) > 0 && (cut[len(cut)-1]&0xC0) == 0x80 {
		cut = cut[:len(cut)-1]
	}
	return cut
}
