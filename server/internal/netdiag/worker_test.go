// worker_test.go 调度 Worker 单元测试：临时目录 fake 共享卷契约——
// PENDING 下发请求文件（逐字段对契约）、结果消费落库终态、超时收割、
// pcap 搬移+sha256 入库、孤儿文件清理。
package netdiag

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// workerStoreStub Worker 仓储 stub（内存态记录调用）。
type workerStoreStub struct {
	mu        sync.Mutex
	jobs      map[uuid.UUID]*Job
	finished  map[uuid.UUID]finishCall
	artifacts map[uuid.UUID]artifactCall
	packets   map[uuid.UUID][]byte
}

type finishCall struct {
	status     string
	resultText string
	exitCode   *int
	durationMs *int64
	failureMsg string
}

type artifactCall struct {
	file string
	size int64
	hash string
}

func newWorkerStoreStub() *workerStoreStub {
	return &workerStoreStub{jobs: map[uuid.UUID]*Job{}, finished: map[uuid.UUID]finishCall{}, artifacts: map[uuid.UUID]artifactCall{}, packets: map[uuid.UUID][]byte{}}
}

func (s *workerStoreStub) add(j *Job) {
	s.mu.Lock()
	s.jobs[j.ID] = j
	s.mu.Unlock()
}

func (s *workerStoreStub) ListByStatus(_ context.Context, statuses ...string) ([]Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := map[string]bool{}
	for _, st := range statuses {
		want[st] = true
	}
	out := []Job{}
	for _, j := range s.jobs {
		if want[j.Status] {
			out = append(out, *j)
		}
	}
	return out, nil
}

func (s *workerStoreStub) MarkRunning(_ context.Context, id uuid.UUID) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok || j.Status != StatusPending {
		return false, nil
	}
	j.Status = StatusRunning
	now := time.Now()
	j.StartedAt = &now
	return true, nil
}

func (s *workerStoreStub) Finish(_ context.Context, id uuid.UUID, status, resultText string, exitCode *int, durationMs *int64, failureMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok || (j.Status != StatusPending && j.Status != StatusRunning) {
		return ErrNotFound
	}
	j.Status = status
	s.finished[id] = finishCall{status: status, resultText: resultText, exitCode: exitCode, durationMs: durationMs, failureMsg: failureMsg}
	return nil
}

func (s *workerStoreStub) SetCaptureArtifact(_ context.Context, id uuid.UUID, file string, size int64, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.artifacts[id] = artifactCall{file: file, size: size, hash: hash}
	return nil
}

func (s *workerStoreStub) SetCapturePackets(_ context.Context, id uuid.UUID, packets []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packets[id] = append([]byte(nil), packets...)
	return nil
}

type workerEnv struct {
	worker  *Worker
	store   *workerStoreStub
	sidecar string
	data    string
}

func newWorkerEnv(t *testing.T) *workerEnv {
	t.Helper()
	sidecar := t.TempDir()
	data := t.TempDir()
	st := newWorkerStoreStub()
	w := NewWorker(st, sidecar, data, "it-gateway-01")
	return &workerEnv{worker: w, store: st, sidecar: sidecar, data: data}
}

func pendingJob(t *testing.T, action, target string, params Params) *Job {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	return &Job{
		ID: uuid.New(), Node: "it-gateway-01", Action: action, Target: target,
		Params: raw, Status: StatusPending, CreatedAt: time.Now(),
	}
}

// TestDispatchWritesRequestFile PENDING → 请求文件逐字段对冻结契约 + 置 RUNNING。
func TestDispatchWritesRequestFile(t *testing.T) {
	env := newWorkerEnv(t)
	j := pendingJob(t, ActionCapture, "10.0.0.1", Params{
		Iface: "eth0", DurationSec: 10, FilterProto: "tcp", FilterPort: 443, FilterHost: "example.com",
	})
	env.store.add(j)
	env.worker.tick(context.Background())

	j = env.store.jobs[j.ID]
	if j.Status != StatusRunning {
		t.Fatalf("应置 RUNNING，实际 %s", j.Status)
	}
	raw, err := os.ReadFile(requestPath(env.sidecar, j.ID))
	if err != nil {
		t.Fatalf("读取请求文件: %v", err)
	}
	var req map[string]interface{}
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatalf("请求文件非 JSON: %v", err)
	}
	if req["version"] != float64(1) {
		t.Fatalf("version 不符: %v", req["version"])
	}
	if req["job_id"] != j.ID.String() {
		t.Fatalf("job_id 不符: %v", req["job_id"])
	}
	if req["node"] != "it-gateway-01" {
		t.Fatalf("node 不符: %v", req["node"])
	}
	if req["action"] != ActionCapture || req["target"] != "10.0.0.1" {
		t.Fatalf("action/target 不符: %v", req)
	}
	// capture duration 10 → timeout_sec = 10+30 = 40
	if req["timeout_sec"] != float64(40) {
		t.Fatalf("timeout_sec 不符: %v", req["timeout_sec"])
	}
	params, ok := req["params"].(map[string]interface{})
	if !ok {
		t.Fatalf("params 缺失: %v", req)
	}
	if params["iface"] != "eth0" || params["duration_sec"] != float64(10) ||
		params["filter_proto"] != "tcp" || params["filter_port"] != float64(443) ||
		params["filter_host"] != "example.com" {
		t.Fatalf("params 不符: %v", params)
	}
	// 目录 0770（组 1000 可读写，适配无 CAP_DAC_OVERRIDE 的 netmgrd；无 other 权限）
	for _, d := range []string{env.sidecar, diagDir(env.sidecar)} {
		dinfo, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if dinfo.Mode().Perm() != 0o770 {
			t.Fatalf("目录 %s 权限应为 0770，实际 %o", d, dinfo.Mode().Perm())
		}
	}
	// 请求文件权限 0640（同组 1000 只读消费，禁止 other 访问）
	info, err := os.Stat(requestPath(env.sidecar, j.ID))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("请求文件权限应为 0640，实际 %o", info.Mode().Perm())
	}
}

// TestDispatchSkipsOtherNode 非本节点任务不下发。
func TestDispatchSkipsOtherNode(t *testing.T) {
	env := newWorkerEnv(t)
	j := pendingJob(t, ActionPing, "10.0.0.1", Params{Count: 4})
	j.Node = "other-node"
	env.store.add(j)
	env.worker.tick(context.Background())
	if _, err := os.Stat(requestPath(env.sidecar, j.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("非本节点不应写请求文件: %v", err)
	}
	if env.store.jobs[j.ID].Status != StatusPending {
		t.Fatalf("非本节点应保持 PENDING，实际 %s", env.store.jobs[j.ID].Status)
	}
}

// writeResult 伪造 netmgrd 回写结果文件。
func writeResult(t *testing.T, sidecar string, id uuid.UUID, res sidecarResult) {
	t.Helper()
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(diagDir(sidecar), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resultPath(sidecar, id), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestConsumeResultTerminal 消费结果文件 → 终态正确（result_text 合并、结果文件删除）。
func TestConsumeResultTerminal(t *testing.T) {
	env := newWorkerEnv(t)
	j := pendingJob(t, ActionPing, "10.0.0.1", Params{Count: 4})
	env.store.add(j)
	env.worker.tick(context.Background()) // PENDING → RUNNING

	exit := 0
	dur := int64(1234)
	writeResult(t, env.sidecar, j.ID, sidecarResult{
		JobID: j.ID.String(), Status: StatusSuccess, ExitCode: &exit,
		Stdout: "4 packets transmitted, 4 received", Stderr: "", DurationMs: &dur,
		FinishedAt: time.Now().UTC().Format(time.RFC3339),
	})
	env.worker.tick(context.Background()) // 消费结果

	fin, ok := env.store.finished[j.ID]
	if !ok {
		t.Fatal("应落库终态")
	}
	if fin.status != StatusSuccess {
		t.Fatalf("终态应 SUCCESS，实际 %s", fin.status)
	}
	if fin.resultText != "4 packets transmitted, 4 received" {
		t.Fatalf("result_text 不符: %q", fin.resultText)
	}
	if fin.exitCode == nil || *fin.exitCode != 0 || fin.durationMs == nil || *fin.durationMs != 1234 {
		t.Fatalf("exit_code/duration_ms 不符: %+v", fin)
	}
	if _, err := os.Stat(resultPath(env.sidecar, j.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("消费后应删除结果文件: %v", err)
	}
}

// TestConsumeResultFailedStderr FAILED 终态合并 stderr 且带失败原因。
func TestConsumeResultFailedStderr(t *testing.T) {
	env := newWorkerEnv(t)
	j := pendingJob(t, ActionTCPProbe, "10.0.0.1", Params{Port: 443})
	env.store.add(j)
	env.worker.tick(context.Background())

	exit := 1
	writeResult(t, env.sidecar, j.ID, sidecarResult{
		JobID: j.ID.String(), Status: StatusFailed, ExitCode: &exit,
		Stdout: "probe start", Stderr: "connection refused",
	})
	env.worker.tick(context.Background())

	fin := env.store.finished[j.ID]
	if fin.status != StatusFailed {
		t.Fatalf("终态应 FAILED，实际 %s", fin.status)
	}
	if fin.resultText != "probe start\n[stderr]\nconnection refused" {
		t.Fatalf("result_text 合并不符: %q", fin.resultText)
	}
	if fin.failureMsg != "connection refused" {
		t.Fatalf("failure_message 不符: %q", fin.failureMsg)
	}
}

// TestCaptureImport 抓包产物搬移：共享卷 pcap → 数据目录 + sha256 入库 + 删共享卷文件。
func TestCaptureImport(t *testing.T) {
	env := newWorkerEnv(t)
	j := pendingJob(t, ActionCapture, "10.0.0.1", Params{Iface: "eth0", DurationSec: 5})
	env.store.add(j)
	env.worker.tick(context.Background())

	pcap := []byte("\xd4\xc3\xb2\xa1 fake pcap content")
	if err := os.WriteFile(filepath.Join(diagDir(env.sidecar), CaptureFileName(j.ID)), pcap, 0o600); err != nil {
		t.Fatal(err)
	}
	writeResult(t, env.sidecar, j.ID, sidecarResult{
		JobID: j.ID.String(), Status: StatusSuccess,
		CaptureFile: CaptureFileName(j.ID), CaptureSize: int64(len(pcap)),
	})
	env.worker.tick(context.Background())

	art, ok := env.store.artifacts[j.ID]
	if !ok {
		t.Fatal("应登记抓包产物")
	}
	sum := sha256.Sum256(pcap)
	if art.hash != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha256 不符: %s", art.hash)
	}
	if art.size != int64(len(pcap)) || art.file != CaptureFileName(j.ID) {
		t.Fatalf("产物元数据不符: %+v", art)
	}
	moved, err := os.ReadFile(filepath.Join(env.data, CaptureFileName(j.ID)))
	if err != nil {
		t.Fatalf("产物应搬入数据目录: %v", err)
	}
	if string(moved) != string(pcap) {
		t.Fatal("产物内容不符")
	}
	if _, err := os.Stat(filepath.Join(diagDir(env.sidecar), CaptureFileName(j.ID))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("共享卷 pcap 应删除: %v", err)
	}
	if fin := env.store.finished[j.ID]; fin.status != StatusSuccess {
		t.Fatalf("终态应 SUCCESS，实际 %s", fin.status)
	}
}

// TestCaptureParsePackets 抓包成功后 Worker 解析 pcap：数据包列表 JSON 入库。
func TestCaptureParsePackets(t *testing.T) {
	env := newWorkerEnv(t)
	j := pendingJob(t, ActionCapture, "10.0.0.1", Params{Iface: "eth0", DurationSec: 5})
	env.store.add(j)
	env.worker.tick(context.Background())

	frame := ethFrame(0x0800, ipv4Packet(6, [4]byte{172, 19, 0, 1}, [4]byte{172, 19, 0, 2},
		tcpSegment(52344, 8080, 0x12, []byte("GET / HTTP/1.1"))))
	pcap := newPcap(t, binary.LittleEndian).add(1700000000, 123456, frame, 74).bytes()
	if err := os.WriteFile(filepath.Join(diagDir(env.sidecar), CaptureFileName(j.ID)), pcap, 0o600); err != nil {
		t.Fatal(err)
	}
	writeResult(t, env.sidecar, j.ID, sidecarResult{
		JobID: j.ID.String(), Status: StatusSuccess,
		CaptureFile: CaptureFileName(j.ID), CaptureSize: int64(len(pcap)),
	})
	env.worker.tick(context.Background())

	raw, ok := env.store.packets[j.ID]
	if !ok {
		t.Fatal("应登记 capture_packets 解析列表")
	}
	var pkts []CapturePacket
	if err := json.Unmarshal(raw, &pkts); err != nil {
		t.Fatalf("capture_packets 应为 JSON 数组: %v", err)
	}
	if len(pkts) != 1 || pkts[0].Proto != "TCP" || pkts[0].Flags != "SYN,ACK" ||
		pkts[0].Sport == nil || *pkts[0].Sport != 52344 || pkts[0].Preview == "" {
		t.Fatalf("解析列表内容不符: %+v", pkts)
	}
	if fin := env.store.finished[j.ID]; fin.status != StatusSuccess {
		t.Fatalf("终态应 SUCCESS，实际 %s", fin.status)
	}
}

// TestCaptureParseFailureKeepsNull 解析失败（非法 pcap）不阻断任务成功：
// 终态仍 SUCCESS，capture_packets 不登记（保持 NULL，页面回退下载按钮）。
func TestCaptureParseFailureKeepsNull(t *testing.T) {
	env := newWorkerEnv(t)
	j := pendingJob(t, ActionCapture, "10.0.0.1", Params{Iface: "eth0", DurationSec: 5})
	env.store.add(j)
	env.worker.tick(context.Background())

	bad := make([]byte, 24)
	binary.BigEndian.PutUint32(bad[:4], 0xdeadbeef) // 非法 magic
	if err := os.WriteFile(filepath.Join(diagDir(env.sidecar), CaptureFileName(j.ID)), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	writeResult(t, env.sidecar, j.ID, sidecarResult{
		JobID: j.ID.String(), Status: StatusSuccess,
		CaptureFile: CaptureFileName(j.ID), CaptureSize: int64(len(bad)),
	})
	env.worker.tick(context.Background())

	if _, ok := env.store.packets[j.ID]; ok {
		t.Fatal("解析失败不应登记 capture_packets")
	}
	fin, ok := env.store.finished[j.ID]
	if !ok || fin.status != StatusSuccess {
		t.Fatalf("解析失败不应阻断 SUCCESS 终态: %+v", fin)
	}
	if _, ok := env.store.artifacts[j.ID]; !ok {
		t.Fatal("产物仍应正常登记（sha256 入库）")
	}
}

// TestReapTimeout 超时收割：超过动作 deadline 无结果 → TIMEOUT + 清理共享卷残留。
func TestReapTimeout(t *testing.T) {
	env := newWorkerEnv(t)
	j := pendingJob(t, ActionPing, "10.0.0.1", Params{Count: 4})
	env.store.add(j)
	env.worker.tick(context.Background()) // PENDING → RUNNING

	// 推进时钟超过 ping deadline（40s）
	env.worker.now = func() time.Time { return time.Now().Add(41 * time.Second) }
	env.worker.tick(context.Background())

	fin, ok := env.store.finished[j.ID]
	if !ok {
		t.Fatal("超时任务应收割")
	}
	if fin.status != StatusTimeout || fin.failureMsg == "" {
		t.Fatalf("收割终态不符: %+v", fin)
	}
	if _, err := os.Stat(requestPath(env.sidecar, j.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("收割后应删除残留请求文件: %v", err)
	}
}

// TestNoReapBeforeDeadline 未超时不收割。
func TestNoReapBeforeDeadline(t *testing.T) {
	env := newWorkerEnv(t)
	j := pendingJob(t, ActionPing, "10.0.0.1", Params{Count: 4})
	env.store.add(j)
	env.worker.tick(context.Background())
	env.worker.tick(context.Background()) // 仍 RUNNING，无结果未超时
	if env.store.jobs[j.ID].Status != StatusRunning {
		t.Fatalf("未超时应保持 RUNNING，实际 %s", env.store.jobs[j.ID].Status)
	}
	if _, ok := env.store.finished[j.ID]; ok {
		t.Fatal("未超时不应落库终态")
	}
}

// TestSweepOrphans 孤儿文件清理：无对应任务且超龄删除，低龄/有任务保留，未知文件不碰。
func TestSweepOrphans(t *testing.T) {
	env := newWorkerEnv(t)
	dir := diagDir(env.sidecar)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	write := func(name string, mtime time.Time) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	orphanID := uuid.New()
	write("request-"+orphanID.String()+".json", old)      // 超龄孤儿 → 删
	write("capture-"+uuid.NewString()+".pcap", old)       // 超龄孤儿 → 删
	write("result-"+uuid.NewString()+".json", time.Now()) // 低龄 → 保留
	write("unrelated.txt", old)                           // 非契约文件 → 保留

	// 有对应任务（RUNNING）的超龄文件 → 保留
	live := pendingJob(t, ActionPing, "10.0.0.1", Params{Count: 4})
	env.store.add(live)
	env.worker.tick(context.Background()) // → RUNNING 并生成请求文件
	if err := os.Chtimes(requestPath(env.sidecar, live.ID), old, old); err != nil {
		t.Fatal(err)
	}

	env.worker.sweepOrphans(context.Background())

	if _, err := os.Stat(filepath.Join(dir, "request-"+orphanID.String()+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("超龄孤儿请求文件应删除")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name()] = true
	}
	if names["unrelated.txt"] != true {
		t.Fatal("非契约文件不应清理")
	}
	if !names["request-"+live.ID.String()+".json"] {
		t.Fatal("有对应任务的文件不应清理")
	}
}

// TestOrphanJobID 契约文件名解析。
func TestOrphanJobID(t *testing.T) {
	id := uuid.NewString()
	for _, name := range []string{"request-" + id + ".json", "result-" + id + ".json", "stop-" + id, "capture-" + id + ".pcap"} {
		if got := orphanJobID(name); got != id {
			t.Fatalf("%s 应解析出 %s，实际 %q", name, id, got)
		}
	}
	for _, name := range []string{"foo.json", "request-not-a-uuid.json", ".tmp", ""} {
		if got := orphanJobID(name); got != "" {
			t.Fatalf("%s 应返回空，实际 %q", name, got)
		}
	}
}
