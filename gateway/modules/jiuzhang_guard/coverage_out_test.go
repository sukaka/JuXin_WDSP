package jiuzhang_guard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
)

func TestCoverageEmitterDisabledByDefault(t *testing.T) {
	resetCovOutForTest()
	t.Cleanup(resetCovOutForTest)
	os.Unsetenv(covEnabledEnv)
	if e := coverageEmitter(); e != nil {
		t.Fatal("未显式开启时应返回 nil（默认关闭）")
	}
}

func TestCoverageEmitterEnabledLifecycle(t *testing.T) {
	resetCovOutForTest()
	t.Cleanup(resetCovOutForTest)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "coverage-observations.jsonl")
	t.Setenv(covEnabledEnv, "1")
	t.Setenv(covLogEnv, logPath)
	t.Setenv(covNodeEnv, "gw-test-1")

	e := coverageEmitter()
	if e == nil {
		t.Fatal("开启后应返回非 nil 发射器")
	}
	if coverageEmitter() != e {
		t.Fatal("进程级单例：两次获取应为同一句柄")
	}

	// 发射一条合法观测 → 落盘一行
	e.Emit(coverage.Observation{
		RequestID:     "rid-out-1",
		ApplicationID: "app-out",
		EndpointKey:   "GET /v1/out/{id}",
		Detector:      "pipeline",
		Phase:         coverage.PhaseRequest,
		Scope:         coverage.ScopeDeclared{Bytes: 10, Messages: 1, Direction: "request"},
		Status:        coverage.StatusFull,
		BytesExamined: 10,
		PolicyVersion: "pol-out",
	})
	e.Stop()
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("输出文件不存在: %v", err)
	}
	if !strings.Contains(string(raw), "rid-out-1") {
		t.Fatalf("观测行未落盘: %s", raw)
	}

	// 立即写一份计数快照 → counter_snapshot 行带 node_id 与冻结阶段集合
	if covHandle == nil {
		t.Fatal("开启后句柄不应为空")
	}
	DefaultCovCounters.Reset()
	DefaultCovCounters.Inc(StageTotal)
	DefaultCovCounters.Inc(StageTotal)
	covHandle.writeCounterSnapshot()
	raw2, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var found counterSnapshotLine
	ok := false
	for _, ln := range strings.Split(strings.TrimSpace(string(raw2)), "\n") {
		var cs counterSnapshotLine
		if err := json.Unmarshal([]byte(ln), &cs); err == nil && cs.RecordType == "counter_snapshot" {
			found = cs
			ok = true
		}
	}
	if !ok {
		t.Fatalf("未找到 counter_snapshot 行: %s", raw2)
	}
	if found.NodeID != "gw-test-1" {
		t.Fatalf("node_id=%s want gw-test-1", found.NodeID)
	}
	stageCount := map[CovStage]uint64{}
	for _, c := range found.Counts {
		stageCount[c.Stage] = c.Count
	}
	if stageCount[StageTotal] != 2 {
		t.Fatalf("total=%d want 2", stageCount[StageTotal])
	}
	if _, err := time.Parse(time.RFC3339, found.CapturedAt); err != nil {
		t.Fatalf("captured_at 非法: %v", err)
	}
}
