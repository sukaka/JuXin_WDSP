package sitediscovery

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validLine(t *testing.T, kv map[string]interface{}) []byte {
	t.Helper()
	m := map[string]interface{}{
		"type":         "site_discovery",
		"node":         "gw-1",
		"domain":       "example.com",
		"ip":           "10.0.0.5",
		"port":         443,
		"protocol":     "HTTPS",
		"source_mode":  "MIRROR",
		"hits":         12,
		"client_count": 4,
		"window_start": "2026-08-21T04:00:00Z",
		"window_end":   "2026-08-21T04:00:30Z",
	}
	for k, v := range kv {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func writeLog(t *testing.T, dir string, lines ...[]byte) string {
	t.Helper()
	path := filepath.Join(dir, "site-discovery.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if _, err := f.Write(l); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// 基本采集：好行入库、坏行写错误文件、非本类型行跳过、断点保存。
func TestCollectorCollectOnce(t *testing.T) {
	dir := t.TempDir()
	good1 := validLine(t, nil)
	good2 := validLine(t, map[string]interface{}{"domain": "", "ip": "10.0.0.9", "port": 80, "protocol": "HTTP"})
	other := []byte(`{"type":"heartbeat","node":"gw-1"}` + "\n") // 非 site_discovery：跳过
	bad := []byte(`{"type":"site_discovery","ip":"oops","port":443,"protocol":"HTTPS"}` + "\n")

	logPath := writeLog(t, dir, good1, good2, other, bad)
	store := NewMemStore()
	c := NewCollector(store, "test-collector", logPath, "", "node-default")

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 4 {
		t.Errorf("processed = %d, want 4", n)
	}
	list, total, err := store.List(context.Background(), ListFilter{Page: 1, PageSize: 20})
	if err != nil || total != 2 {
		t.Fatalf("upserted total=%d err=%v", total, err)
	}
	// 空域名条目入库（domain 可空串）
	var ipOnly *Discovery
	for i := range list {
		if list[i].IP == "10.0.0.9" {
			ipOnly = &list[i]
		}
	}
	if ipOnly == nil || ipOnly.Domain != "" || ipOnly.Protocol != ProtocolHTTP {
		t.Fatalf("ip-only discovery: %+v", ipOnly)
	}
	m := c.Metrics()
	if m["skipped_count"].(int64) != 1 || m["failed_count"].(int64) != 1 || m["saved_count"].(int64) != 2 {
		t.Fatalf("metrics: %+v", m)
	}
	// 错误文件记录坏行
	errData, err := os.ReadFile(logPath + ".errors")
	if err != nil {
		t.Fatalf("error file missing: %v", err)
	}
	if !strings.Contains(string(errData), "oops") {
		t.Errorf("error file should contain bad line, got: %s", errData)
	}
	// 断点已保存且等于文件大小
	cpData, err := os.ReadFile(logPath + ".checkpoint")
	if err != nil {
		t.Fatalf("checkpoint missing: %v", err)
	}
	var cp checkpoint
	if err := json.Unmarshal(cpData, &cp); err != nil {
		t.Fatalf("checkpoint corrupt: %v", err)
	}
	info, _ := os.Stat(logPath)
	if cp.Offset != info.Size() {
		t.Errorf("checkpoint offset = %d, want %d", cp.Offset, info.Size())
	}
}

// 断点续传：无新内容不重复入库；追加后只采增量。
func TestCollectorResumeFromCheckpoint(t *testing.T) {
	dir := t.TempDir()
	logPath := writeLog(t, dir, validLine(t, nil))
	store := NewMemStore()
	c := NewCollector(store, "c", logPath, "", "n")

	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, total, _ := store.List(context.Background(), ListFilter{Page: 1, PageSize: 20})
	if total != 1 {
		t.Fatalf("first collect total=%d, want 1", total)
	}
	// 无新内容
	if n, err := c.CollectOnce(context.Background()); err != nil || n != 0 {
		t.Fatalf("second collect = %d, %v; want 0, nil", n, err)
	}
	// 追加一行：同站点 hits 累加（重放安全由唯一键 upsert 兜底）
	f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.Write(validLine(t, map[string]interface{}{"hits": 8, "client_count": 6}))
	_ = f.Close()
	if n, err := c.CollectOnce(context.Background()); err != nil || n != 1 {
		t.Fatalf("incremental collect = %d, %v; want 1, nil", n, err)
	}
	list, total, _ := store.List(context.Background(), ListFilter{Page: 1, PageSize: 20})
	if total != 1 || list[0].SeenCount != 20 || list[0].ClientCount != 6 {
		t.Fatalf("incremental upsert wrong: total=%d %+v", total, list)
	}
}

// 轮转：删除重建（inode 复用、相同大小）时按前缀指纹检测，从头重读。
func TestCollectorRotation(t *testing.T) {
	dir := t.TempDir()
	oldLine := validLine(t, map[string]interface{}{"domain": "old.example.com"})
	newLine := validLine(t, map[string]interface{}{"domain": "new.example.com"})
	if len(oldLine) != len(newLine) {
		t.Fatal("test requires equal-sized old and new files")
	}
	logPath := writeLog(t, dir, oldLine)
	store := NewMemStore()
	c := NewCollector(store, "c", logPath, "", "n")
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	cpData, err := os.ReadFile(logPath + ".checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	var cp checkpoint
	if err := json.Unmarshal(cpData, &cp); err != nil {
		t.Fatal(err)
	}

	// 轮转：删除后以相同大小重建，并强制模拟 inode 被系统复用。
	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	logPath2 := writeLog(t, dir, newLine)
	if logPath != logPath2 {
		t.Fatal("path mismatch")
	}
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cp.Inode = fileInode(f)
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	cpData, err = json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath+".checkpoint", cpData, 0o600); err != nil {
		t.Fatal(err)
	}

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, total, _ := store.List(context.Background(), ListFilter{Page: 1, PageSize: 20})
	if n != 1 || total != 2 {
		t.Errorf("rotation re-read failed: n=%d total=%d", n, total)
	}
}

// 不完整行（无换行结尾）不前移断点，补全后采集。
func TestCollectorDoesNotCheckpointPartialLine(t *testing.T) {
	dir := t.TempDir()
	line := validLine(t, map[string]interface{}{"domain": "partial.example.com"})
	logPath := writeLog(t, dir, line[:len(line)-1])
	store := NewMemStore()
	c := NewCollector(store, "c", logPath, "", "n")

	if n, err := c.CollectOnce(context.Background()); err != nil || n != 0 {
		t.Fatalf("partial collect = %d, %v; want 0, nil", n, err)
	}
	cpData, err := os.ReadFile(logPath + ".checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	var cp checkpoint
	if err := json.Unmarshal(cpData, &cp); err != nil {
		t.Fatal(err)
	}
	if cp.Offset != 0 {
		t.Fatalf("partial line checkpoint offset = %d, want 0", cp.Offset)
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{'\n'}); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if n, err := c.CollectOnce(context.Background()); err != nil || n != 1 {
		t.Fatalf("completed collect = %d, %v; want 1, nil", n, err)
	}
	_, total, _ := store.List(context.Background(), ListFilter{Page: 1, PageSize: 20})
	if total != 1 {
		t.Fatalf("completed line not collected: total=%d", total)
	}
}

// 损坏断点：告警并从头开始。
func TestCollectorCorruptCheckpoint(t *testing.T) {
	dir := t.TempDir()
	logPath := writeLog(t, dir, validLine(t, nil))
	if err := os.WriteFile(logPath+".checkpoint", []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewMemStore()
	c := NewCollector(store, "c", logPath, "", "n")
	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, total, _ := store.List(context.Background(), ListFilter{Page: 1, PageSize: 20})
	if n != 1 || total != 1 {
		t.Errorf("corrupt checkpoint should reset to 0: n=%d total=%d", n, total)
	}
}

// 网关缺 node 字段：回落采集器配置节点名。
func TestCollectorNodeFallback(t *testing.T) {
	dir := t.TempDir()
	logPath := writeLog(t, dir, validLine(t, map[string]interface{}{"node": ""}))
	store := NewMemStore()
	c := NewCollector(store, "c", logPath, "", "gw-fallback")
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	list, total, _ := store.List(context.Background(), ListFilter{Page: 1, PageSize: 20})
	if total != 1 || list[0].GatewayNode != "gw-fallback" {
		t.Fatalf("node fallback: %+v", list)
	}
}

// 日志文件不存在：空转不报错。
func TestCollectorMissingLogFile(t *testing.T) {
	dir := t.TempDir()
	store := NewMemStore()
	c := NewCollector(store, "c", filepath.Join(dir, "absent.jsonl"), "", "n")
	n, err := c.CollectOnce(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("missing log: n=%d err=%v, want 0, nil", n, err)
	}
}
