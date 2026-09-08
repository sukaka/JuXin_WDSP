package accesscontrolevents

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/temporaryblocks"
)

func validLine(t *testing.T, overrides map[string]interface{}) []byte {
	t.Helper()
	m := map[string]interface{}{
		"request_id":      "req-001",
		"occurred_at":     "2026-07-21T08:00:00Z",
		"application_id":  "550e8400-e29b-41d4-a716-446655440000",
		"client_ip":       "192.168.1.10",
		"connection_ip":   "10.0.0.2",
		"domain":          "shop.example.com",
		"request_method":  "GET",
		"request_path":    "/api/list",
		"event_type":      "CC_REQUEST_REJECTED",
		"action":          "REJECT",
		"policy_id":       "660e8400-e29b-41d4-a716-446655440000",
		"gateway_node_id": "gw-1",
		"message":         "rate limit exceeded",
	}
	for k, v := range overrides {
		m[k] = v
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func TestParseEventLineValid(t *testing.T) {
	evt, err := ParseEventLine(validLine(t, nil), "default-node")
	if err != nil {
		t.Fatalf("valid line rejected: %v", err)
	}
	if evt.RequestID != "req-001" || evt.EventType != "CC_REQUEST_REJECTED" || evt.Action != "REJECT" {
		t.Errorf("unexpected event: %+v", evt)
	}
	if evt.ClientIP != "192.168.1.10" || evt.ConnectionIP != "10.0.0.2" {
		t.Errorf("unexpected ips: %+v", evt)
	}
	if evt.ApplicationID == nil || evt.ApplicationID.String() != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("unexpected application_id: %+v", evt.ApplicationID)
	}
	wantTime := time.Date(2026, 7, 21, 8, 0, 0, 0, time.UTC)
	if !evt.OccurredAt.Equal(wantTime) {
		t.Errorf("occurred_at = %v, want %v", evt.OccurredAt, wantTime)
	}
}

func TestParseEventLineProto(t *testing.T) {
	// 网关上报 proto → 解析带出
	evt, err := ParseEventLine(validLine(t, map[string]interface{}{"proto": "HTTP/3"}), "n")
	if err != nil {
		t.Fatal(err)
	}
	if evt.Proto != "HTTP/3" {
		t.Errorf("proto = %q, want HTTP/3", evt.Proto)
	}
	// 旧版网关事件无 proto 键 → 缺失容忍（空串，落库为 NULL）
	evt, err = ParseEventLine(validLine(t, nil), "n")
	if err != nil {
		t.Fatal(err)
	}
	if evt.Proto != "" {
		t.Errorf("missing proto must default to empty, got %q", evt.Proto)
	}
	// 超长 proto 截断（防注入）
	evt, err = ParseEventLine(validLine(t, map[string]interface{}{"proto": strings.Repeat("H", 64)}), "n")
	if err != nil {
		t.Fatal(err)
	}
	if len(evt.Proto) != 32 {
		t.Errorf("proto not truncated: len=%d", len(evt.Proto))
	}
}

func TestParseEventLineIPv6Normalized(t *testing.T) {
	evt, err := ParseEventLine(validLine(t, map[string]interface{}{
		"client_ip": "2001:0db8:0000:0000:0000:ff00:0042:8329",
	}), "n")
	if err != nil {
		t.Fatalf("ipv6 line rejected: %v", err)
	}
	if evt.ClientIP != "2001:db8::ff00:42:8329" {
		t.Errorf("ipv6 not normalized: %s", evt.ClientIP)
	}
}

func TestParseEventLineDefaultNode(t *testing.T) {
	evt, err := ParseEventLine(validLine(t, map[string]interface{}{"gateway_node_id": ""}), "fallback-node")
	if err != nil {
		t.Fatal(err)
	}
	if evt.GatewayNodeID != "fallback-node" {
		t.Errorf("gateway_node_id = %q, want fallback-node", evt.GatewayNodeID)
	}
}

func TestParseEventLineBadLines(t *testing.T) {
	cases := []struct {
		name string
		line []byte
	}{
		{"empty", []byte("\n")},
		{"not json", []byte("this is not json\n")},
		{"missing event_type", validLine(t, map[string]interface{}{"event_type": ""})},
		{"missing occurred_at", validLine(t, map[string]interface{}{"occurred_at": ""})},
		{"bad occurred_at", validLine(t, map[string]interface{}{"occurred_at": "2026年7月"})},
		{"missing client_ip", validLine(t, map[string]interface{}{"client_ip": ""})},
		{"bad client_ip", validLine(t, map[string]interface{}{"client_ip": "999.1.1.1"})},
		{"bad connection_ip", validLine(t, map[string]interface{}{"connection_ip": "not-an-ip"})},
		{"bad application_id", validLine(t, map[string]interface{}{"application_id": "not-a-uuid"})},
	}
	for _, c := range cases {
		if _, err := ParseEventLine(c.line, "n"); err == nil {
			t.Errorf("%s: expected parse error", c.name)
		}
	}
}

func TestParseEventLineLongFieldsTruncated(t *testing.T) {
	evt, err := ParseEventLine(validLine(t, map[string]interface{}{
		"request_path": strings.Repeat("a", 600),
		"message":      strings.Repeat("b", 600),
	}), "n")
	if err != nil {
		t.Fatal(err)
	}
	if len(evt.RequestPath) != 512 || len(evt.Message) != 512 {
		t.Errorf("fields not truncated: path=%d message=%d", len(evt.RequestPath), len(evt.Message))
	}
}

// fakeEventStore 是内存 EventStore（不连真实 DB）。
type fakeEventStore struct {
	mu        sync.Mutex
	events    []Event
	summaries []RuntimeSummary
	insertErr error
}

func (f *fakeEventStore) Insert(ctx context.Context, events []Event) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.insertErr != nil {
		return 0, f.insertErr
	}
	f.events = append(f.events, events...)
	return len(events), nil
}

func (f *fakeEventStore) InsertRuntimeSummary(ctx context.Context, sum RuntimeSummary) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.summaries = append(f.summaries, sum)
	return nil
}

// fakeBlockUpserter 记录临时封禁入库调用。
type fakeBlockUpserter struct {
	mu     sync.Mutex
	blocks []*temporaryblocks.Block
}

func (f *fakeBlockUpserter) UpsertFromEvent(ctx context.Context, b *temporaryblocks.Block) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocks = append(f.blocks, b)
	return nil
}

// fakeHitRecorder 记录规则命中计数调用。
type fakeHitRecorder struct {
	mu    sync.Mutex
	ruleN map[uuid.UUID]int
}

func (f *fakeHitRecorder) IncrementHit(ctx context.Context, ruleID uuid.UUID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ruleN == nil {
		f.ruleN = map[uuid.UUID]int{}
	}
	f.ruleN[ruleID]++
	return nil
}

func writeEventsFile(t *testing.T, dir string, lines ...[]byte) string {
	t.Helper()
	path := filepath.Join(dir, "guard-events.jsonl")
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

func TestCollectorCollectOnce(t *testing.T) {
	dir := t.TempDir()
	policyID := "660e8400-e29b-41d4-a716-446655440000"
	blockExpires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)

	good1 := validLine(t, map[string]interface{}{"request_id": "r1", "proto": "HTTP/2.0"})
	good2 := validLine(t, map[string]interface{}{
		"request_id":       "r2",
		"event_type":       "CC_TEMP_BLOCK_CREATED",
		"action":           "TEMP_BLOCK",
		"block_expires_at": blockExpires,
	})
	good3 := validLine(t, map[string]interface{}{
		"request_id":     "r3",
		"event_type":     "CC_THRESHOLD_EXCEEDED",
		"action":         "LOG",
		"access_rule_id": "770e8400-e29b-41d4-a716-446655440000",
		"policy_id":      policyID,
	})
	bad := []byte(`{"event_type": "BROKEN"}` + "\n")

	logPath := writeEventsFile(t, dir, good1, good2, good3, bad)

	store := &fakeEventStore{}
	blocks := &fakeBlockUpserter{}
	hits := &fakeHitRecorder{}
	c := NewCollector(store, "test-collector", logPath, "", "node-1")
	c.SetBlockUpserter(blocks)
	c.SetHitRecorder(hits)

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 4 {
		t.Errorf("processed = %d, want 4", n)
	}
	if len(store.events) != 3 {
		t.Fatalf("inserted = %d, want 3", len(store.events))
	}
	// proto 随事件落批（r1 上报 HTTP/2.0；r2/r3 未上报为空串，入库侧落 NULL）
	if store.events[0].Proto != "HTTP/2.0" {
		t.Errorf("collected proto = %q, want HTTP/2.0", store.events[0].Proto)
	}
	if store.events[1].Proto != "" || store.events[2].Proto != "" {
		t.Errorf("missing proto must stay empty: %q/%q", store.events[1].Proto, store.events[2].Proto)
	}
	// 封禁副作用：CC_TEMP_BLOCK_CREATED → UpsertFromEvent
	if len(blocks.blocks) != 1 {
		t.Fatalf("blocks upserted = %d, want 1", len(blocks.blocks))
	}
	b := blocks.blocks[0]
	if b.ClientIP != "192.168.1.10" || b.TriggerType != temporaryblocks.TriggerCCAuto {
		t.Errorf("unexpected block: %+v", b)
	}
	if b.TriggerPolicyID == nil || b.TriggerPolicyID.String() != policyID {
		t.Errorf("unexpected trigger policy: %+v", b.TriggerPolicyID)
	}
	if len(b.TriggerEventIDs) != 1 || b.TriggerEventIDs[0] != "r2" {
		t.Errorf("unexpected trigger events: %+v", b.TriggerEventIDs)
	}
	// 命中计数：CC_THRESHOLD_EXCEEDED 且 access_rule_id 非空
	if hits.ruleN[uuid.MustParse("770e8400-e29b-41d4-a716-446655440000")] != 1 {
		t.Errorf("rule hits = %v, want 1 for rule 770e...", hits.ruleN)
	}
	// 策略汇总：3 条事件同 policy，2 条拒绝（r2 TEMP_BLOCK, r1 REJECT）
	if len(store.summaries) != 1 {
		t.Fatalf("summaries = %d, want 1", len(store.summaries))
	}
	sum := store.summaries[0]
	if sum.PolicyID.String() != policyID || sum.TotalRequests != 3 || sum.RejectedRequests != 2 {
		t.Errorf("unexpected summary: %+v", sum)
	}
	// 错误文件记录坏行
	errData, err := os.ReadFile(logPath + ".errors")
	if err != nil {
		t.Fatalf("error file missing: %v", err)
	}
	if !strings.Contains(string(errData), "BROKEN") {
		t.Errorf("error file should contain bad line, got: %s", errData)
	}
	// checkpoint 已保存
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

func TestCollectorResumeFromCheckpoint(t *testing.T) {
	dir := t.TempDir()
	logPath := writeEventsFile(t, dir, validLine(t, map[string]interface{}{"request_id": "r1"}))

	store := &fakeEventStore{}
	c := NewCollector(store, "c", logPath, "", "n")
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.events) != 1 {
		t.Fatalf("first collect inserted = %d, want 1", len(store.events))
	}
	// 无新内容：返回 0，不重复入库
	if n, err := c.CollectOnce(context.Background()); err != nil || n != 0 {
		t.Fatalf("second collect = %d, %v; want 0, nil", n, err)
	}
	if len(store.events) != 1 {
		t.Fatalf("duplicate insert: %d events", len(store.events))
	}
	// 追加新行：只采集增量
	f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.Write(validLine(t, map[string]interface{}{"request_id": "r2"}))
	_ = f.Close()
	if n, err := c.CollectOnce(context.Background()); err != nil || n != 1 {
		t.Fatalf("incremental collect = %d, %v; want 1, nil", n, err)
	}
	if len(store.events) != 2 || store.events[1].RequestID != "r2" {
		t.Fatalf("incremental events wrong: %+v", store.events)
	}
}

func TestCollectorRotation(t *testing.T) {
	dir := t.TempDir()
	oldLine := validLine(t, map[string]interface{}{"request_id": "old"})
	newLine := validLine(t, map[string]interface{}{"request_id": "new"})
	if len(oldLine) != len(newLine) {
		t.Fatal("test requires equal-sized old and new files")
	}
	logPath := writeEventsFile(t, dir, oldLine)
	store := &fakeEventStore{}
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
	logPath2 := writeEventsFile(t, dir, newLine)
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
	if n != 1 || len(store.events) != 2 || store.events[1].RequestID != "new" {
		t.Errorf("rotation re-read failed: n=%d events=%+v", n, store.events)
	}
}

func TestCollectorDoesNotCheckpointPartialLine(t *testing.T) {
	dir := t.TempDir()
	line := validLine(t, map[string]interface{}{"request_id": "completed-later"})
	logPath := writeEventsFile(t, dir, line[:len(line)-1])
	store := &fakeEventStore{}
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
	if len(store.events) != 1 || store.events[0].RequestID != "completed-later" {
		t.Fatalf("completed event not collected: %+v", store.events)
	}
}

func TestCollectorCorruptCheckpoint(t *testing.T) {
	dir := t.TempDir()
	logPath := writeEventsFile(t, dir, validLine(t, map[string]interface{}{"request_id": "r1"}))
	// 写入损坏的 checkpoint
	if err := os.WriteFile(logPath+".checkpoint", []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := &fakeEventStore{}
	c := NewCollector(store, "c", logPath, "", "n")
	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(store.events) != 1 {
		t.Errorf("corrupt checkpoint should reset to 0: n=%d events=%d", n, len(store.events))
	}
}

func TestCollectorRejectsInvalidCheckpointValues(t *testing.T) {
	dir := t.TempDir()
	logPath := writeEventsFile(t, dir, validLine(t, map[string]interface{}{"request_id": "r1"}))
	cpData, err := json.Marshal(checkpoint{
		Offset:       1,
		PrefixSize:   checkpointPrefixLimit + 1,
		PrefixSHA256: strings.Repeat("0", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath+".checkpoint", cpData, 0o600); err != nil {
		t.Fatal(err)
	}
	store := &fakeEventStore{}
	c := NewCollector(store, "c", logPath, "", "n")
	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(store.events) != 1 {
		t.Errorf("invalid checkpoint should reset to 0: n=%d events=%d", n, len(store.events))
	}
}

func TestCollectorMissingLogFile(t *testing.T) {
	store := &fakeEventStore{}
	c := NewCollector(store, "c", filepath.Join(t.TempDir(), "nonexistent.jsonl"), "", "n")
	n, err := c.CollectOnce(context.Background())
	if err != nil || n != 0 {
		t.Errorf("missing log file: n=%d err=%v, want 0, nil", n, err)
	}
}

func TestCollectorBatchFlush(t *testing.T) {
	dir := t.TempDir()
	var lines [][]byte
	for i := 0; i < 5; i++ {
		lines = append(lines, validLine(t, map[string]interface{}{
			"request_id": fmt.Sprintf("r%d", i),
		}))
	}
	logPath := writeEventsFile(t, dir, lines...)
	store := &fakeEventStore{}
	c := NewCollector(store, "c", logPath, "", "n")
	c.SetBatchSize(2)
	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 || len(store.events) != 5 {
		t.Errorf("batch flush: n=%d inserted=%d, want 5/5", n, len(store.events))
	}
}

func TestCollectorInsertErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	logPath := writeEventsFile(t, dir, validLine(t, nil))
	store := &fakeEventStore{insertErr: fmt.Errorf("db down")}
	c := NewCollector(store, "c", logPath, "", "n")
	if _, err := c.CollectOnce(context.Background()); err == nil {
		t.Error("insert error should propagate")
	}
}

func TestCSFormulaInjection(t *testing.T) {
	cases := map[string]string{
		"=cmd|'/c calc'!A1": "'=cmd|'/c calc'!A1",
		"+1+2":              "'+1+2",
		"-2+3":              "'-2+3",
		"@SUM(1+1)":         "'@SUM(1+1)",
		"normal":            "normal",
		"a,b":               "\"a,b\"",
	}
	for in, want := range cases {
		if got := csvCell(in); got != want {
			t.Errorf("csvCell(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPolicyUUID(t *testing.T) {
	if _, ok := policyUUID(""); ok {
		t.Error("empty policy_id should not parse")
	}
	if _, ok := policyUUID("cc1"); ok {
		t.Error("non-uuid policy_id should not parse")
	}
	id := uuid.New()
	if got, ok := policyUUID(id.String()); !ok || got != id {
		t.Error("uuid policy_id should parse")
	}
}
