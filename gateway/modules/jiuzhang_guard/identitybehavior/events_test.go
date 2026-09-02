package identitybehavior

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// readEventLines 读取事件 JSONL（每行解析为 map 便于字段断言）。
func readEventLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

func newEventTestLogger(t *testing.T) (*EventLogger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity-events.log")
	l, err := NewEventLogger(path, "gw-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

func testBase(identityKey, ip string) CommonRecord {
	return CommonRecord{
		RequestID:          "req-1",
		OccurredAt:         time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
		AppID:              "app-1",
		AppCode:            "shop",
		Domain:             "waf-test.local",
		Method:             "GET",
		Path:               "/.git/config",
		IdentityKey:        identityKey,
		IdentityType:       IdentityBot,
		ClientIP:           ip,
		UserAgent:          "curl/8.1",
		TLSFingerprint:     "tlsfp",
		BrowserFingerprint: "brfp",
	}
}

func TestEmitIdentityObservationFields(t *testing.T) {
	l, path := newEventTestLogger(t)
	creds := []Credential{
		{Type: CredentialJWT, Hash: "h1", AccountID: "u1", JWTSubject: "u1", OAuthClientID: "c1"},
		{Type: CredentialAPIKey, Hash: "h2"},
	}
	l.EmitIdentityObservation(testBase("ik-1", "203.0.113.1"), creds)
	lines := readEventLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("lines: %d", len(lines))
	}
	m := lines[0]
	checks := map[string]any{
		"record_type":         RecordIdentityObservation,
		"request_id":          "req-1",
		"gateway_node":        "gw-test",
		"app_id":              "app-1",
		"app_code":            "shop",
		"domain":              "waf-test.local",
		"method":              "GET",
		"path":                "/.git/config",
		"identity_key":        "ik-1",
		"identity_type":       "BOT",
		"client_ip":           "203.0.113.1",
		"user_agent":          "curl/8.1",
		"tls_fingerprint":     "tlsfp",
		"browser_fingerprint": "brfp",
	}
	for k, want := range checks {
		if m[k] != want {
			t.Fatalf("field %s = %v, want %v", k, m[k], want)
		}
	}
	if _, ok := m["occurred_at"].(string); !ok {
		t.Fatalf("occurred_at missing: %v", m)
	}
	cl, ok := m["credentials"].([]any)
	if !ok || len(cl) != 2 {
		t.Fatalf("credentials: %v", m["credentials"])
	}
	c0 := cl[0].(map[string]any)
	if c0["type"] != "JWT" || c0["hash"] != "h1" || c0["account_id"] != "u1" || c0["jwt_subject"] != "u1" || c0["oauth_client_id"] != "c1" {
		t.Fatalf("credential json: %v", c0)
	}
	// 空凭据序列化为 [] 而非 null
	l2, path2 := newEventTestLogger(t)
	l2.EmitIdentityObservation(testBase("ik-2", "203.0.113.2"), nil)
	if got := readEventLines(t, path2)[0]["credentials"]; got == nil {
		t.Fatal("credentials must be [] not null")
	}
}

func TestEmitBehaviorSnapshotFields(t *testing.T) {
	l, path := newEventTestLogger(t)
	snap := &Snapshot{}
	snap.Windows[Window1m] = WindowCounts{WindowStart: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC), RequestCount: 7, UniqueURICount: 3, NewURICount: 2, Status404Count: 1}
	snap.Windows[Window5m] = WindowCounts{RequestCount: 20, SensitivePathHits: 5, AuthFailCount: 4, ParameterMutationCount: 6, Status401Count: 4, Status403Count: 1, Status405Count: 1, Status500Count: 1}
	l.EmitBehaviorSnapshot(testBase("ik-1", "203.0.113.1"), snap)
	lines := readEventLines(t, path)
	if len(lines) != 1 || lines[0]["record_type"] != RecordBehaviorSnapshot {
		t.Fatalf("lines: %v", lines)
	}
	windows, ok := lines[0]["windows"].(map[string]any)
	if !ok || len(windows) != 4 {
		t.Fatalf("windows: %v", lines[0]["windows"])
	}
	for _, name := range []string{"1m", "5m", "30m", "24h"} {
		w, ok := windows[name].(map[string]any)
		if !ok {
			t.Fatalf("window %s missing: %v", name, windows)
		}
		for _, field := range []string{"window_start", "request_count", "unique_uri_count", "new_uri_count",
			"status_401_count", "status_403_count", "status_404_count", "status_405_count", "status_500_count",
			"auth_fail_count", "parameter_mutation_count", "sensitive_path_hits"} {
			if _, ok := w[field]; !ok {
				t.Fatalf("window %s missing field %s: %v", name, field, w)
			}
		}
	}
	w1 := windows["1m"].(map[string]any)
	if w1["request_count"].(float64) != 7 || w1["unique_uri_count"].(float64) != 3 || w1["status_404_count"].(float64) != 1 {
		t.Fatalf("1m window values: %v", w1)
	}
	w5 := windows["5m"].(map[string]any)
	if w5["sensitive_path_hits"].(float64) != 5 || w5["auth_fail_count"].(float64) != 4 || w5["parameter_mutation_count"].(float64) != 6 {
		t.Fatalf("5m window values: %v", w5)
	}
}

func TestEmitReconSignalFields(t *testing.T) {
	l, path := newEventTestLogger(t)
	sig := Signal{
		RuleCode:    RuleSensitivePathProbe,
		RuleVersion: RuleVersion,
		Signal:      SignalSensitivePathProbe,
		ScoreDelta:  15,
		Mode:        ModeObserve,
		Reason:      "request path matches sensitive path prefix",
		Window:      "request",
		Metadata:    map[string]any{"matched_prefix": "/.git"},
	}
	l.EmitReconSignal(testBase("ik-1", "203.0.113.1"), sig)
	lines := readEventLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("lines: %d", len(lines))
	}
	m := lines[0]
	checks := map[string]any{
		"record_type":  RecordReconSignal,
		"rule_code":    "RECON-PATH-001",
		"rule_version": "1.0.0",
		"signal":       "SENSITIVE_PATH_PROBE",
		"mode":         "OBSERVE",
		"window":       "request",
		"reason":       "request path matches sensitive path prefix",
	}
	for k, want := range checks {
		if m[k] != want {
			t.Fatalf("field %s = %v, want %v", k, m[k], want)
		}
	}
	if m["risk_score_delta"].(float64) != 15 {
		t.Fatalf("risk_score_delta: %v", m["risk_score_delta"])
	}
	meta, ok := m["metadata"].(map[string]any)
	if !ok || meta["matched_prefix"] != "/.git" {
		t.Fatalf("metadata: %v", m["metadata"])
	}
}

// 节流：identity_observation 每 identity 5min 至多 1 条；新 IP / 新凭据立即发。
func TestObservationThrottle(t *testing.T) {
	l, path := newEventTestLogger(t)
	base := testBase("ik-1", "203.0.113.1")
	l.EmitIdentityObservation(base, nil)
	l.EmitIdentityObservation(base, nil) // 同 identity+IP+凭据，5min 内 → 节流
	if n := len(readEventLines(t, path)); n != 1 {
		t.Fatalf("throttled: %d", n)
	}
	// 新 IP 立即发
	l.EmitIdentityObservation(testBase("ik-1", "198.51.100.2"), nil)
	if n := len(readEventLines(t, path)); n != 2 {
		t.Fatalf("new ip must emit: %d", n)
	}
	// 新凭据立即发
	l.EmitIdentityObservation(testBase("ik-1", "198.51.100.2"), []Credential{{Type: CredentialAPIKey, Hash: "hx"}})
	if n := len(readEventLines(t, path)); n != 3 {
		t.Fatalf("new credential must emit: %d", n)
	}
	// 超过 5min 再发（注入时钟）
	lines := len(readEventLines(t, path))
	l.mu.Lock()
	l.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	l.mu.Unlock()
	l.EmitIdentityObservation(testBase("ik-1", "198.51.100.2"), []Credential{{Type: CredentialAPIKey, Hash: "hx"}})
	if n := len(readEventLines(t, path)); n != lines+1 {
		t.Fatalf("after interval must emit: %d -> %d", lines, n)
	}
}

// 节流：behavior_snapshot 每 identity 60s 至多 1 条；recon_signal 每 (identity,rule) 60s 至多 1 条。
func TestSnapshotAndSignalThrottle(t *testing.T) {
	l, path := newEventTestLogger(t)
	base := testBase("ik-1", "203.0.113.1")
	snap := &Snapshot{}
	l.EmitBehaviorSnapshot(base, snap)
	l.EmitBehaviorSnapshot(base, snap)
	l.EmitBehaviorSnapshot(testBase("ik-2", "203.0.113.2"), snap) // 不同 identity 不受影响
	sigA := Signal{RuleCode: "R-1", Signal: "S1", Mode: ModeObserve}
	sigB := Signal{RuleCode: "R-2", Signal: "S2", Mode: ModeObserve}
	l.EmitReconSignal(base, sigA)
	l.EmitReconSignal(base, sigA) // 同 (identity,rule) 节流
	l.EmitReconSignal(base, sigB) // 不同 rule 放行
	lines := readEventLines(t, path)
	var snapshots, signals int
	for _, m := range lines {
		switch m["record_type"] {
		case RecordBehaviorSnapshot:
			snapshots++
		case RecordReconSignal:
			signals++
		}
	}
	if snapshots != 2 {
		t.Fatalf("snapshot throttle: %d", snapshots)
	}
	if signals != 2 {
		t.Fatalf("signal throttle: %d", signals)
	}
	// 60s 后同 rule 再发
	l.mu.Lock()
	l.now = func() time.Time { return time.Now().Add(61 * time.Second) }
	l.mu.Unlock()
	l.EmitReconSignal(base, sigA)
	var n int
	for _, m := range readEventLines(t, path) {
		if m["record_type"] == RecordReconSignal {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("after interval signal must emit: %d", n)
	}
}

// 快照触发：1m 桶起点轮转时即使不足 60s 也发；同桶内不足 60s 不发；60s 节流语义保留。
func TestSnapshotBucketRotationTrigger(t *testing.T) {
	l, path := newEventTestLogger(t)
	base := testBase("ik-1", "203.0.113.1")
	t0 := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	// 固定时钟：前四次调用距首次均 < 60s
	l.mu.Lock()
	l.now = func() time.Time { return t0.Add(10 * time.Second) }
	l.mu.Unlock()

	snapIn := func(bucket time.Time) *Snapshot {
		s := &Snapshot{}
		s.Windows[Window1m] = WindowCounts{WindowStart: bucket, RequestCount: 1}
		return s
	}
	snapshotCount := func() int {
		n := 0
		for _, m := range readEventLines(t, path) {
			if m["record_type"] == RecordBehaviorSnapshot {
				n++
			}
		}
		return n
	}

	b1 := t0                                 // 第一个 1m 桶起点
	b2 := t0.Add(time.Minute)                // 轮转后的 1m 桶起点
	l.EmitBehaviorSnapshot(base, snapIn(b1)) // 首次 → 发
	l.EmitBehaviorSnapshot(base, snapIn(b1)) // 同桶且 <60s → 不发
	if n := snapshotCount(); n != 1 {
		t.Fatalf("same bucket within 60s must throttle: %d", n)
	}
	l.EmitBehaviorSnapshot(base, snapIn(b2)) // 桶轮转，<60s → 发
	if n := snapshotCount(); n != 2 {
		t.Fatalf("bucket rotation must emit: %d", n)
	}
	l.EmitBehaviorSnapshot(base, snapIn(b2)) // 同一新桶内 <60s → 不发
	if n := snapshotCount(); n != 2 {
		t.Fatalf("same rotated bucket within 60s must throttle: %d", n)
	}
	// 拨快 61s：同桶但距上次 ≥60s → 发（60s 节流语义保留）
	l.mu.Lock()
	l.now = func() time.Time { return t0.Add(10*time.Second + 61*time.Second) }
	l.mu.Unlock()
	l.EmitBehaviorSnapshot(base, snapIn(b2))
	if n := snapshotCount(); n != 3 {
		t.Fatalf("after 60s same bucket must emit: %d", n)
	}
}

// 多 IP 轮换（AI 自动化渗透典型特征）：已知集内 IP 回归不重复发——5 个 IP 轮 30 轮只发
// 5 条，而非旧实现只记上次 IP 导致的近乎每请求一条（实况 150 请求曾发出 105 条）。
func TestObservationRotatingIPs(t *testing.T) {
	l, path := newEventTestLogger(t)
	ips := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5"}
	for round := 0; round < 30; round++ {
		for _, ip := range ips {
			l.EmitIdentityObservation(testBase("ik-1", ip), nil)
		}
	}
	if n := len(readEventLines(t, path)); n != len(ips) {
		t.Fatalf("rotating known IPs must emit once per IP: %d, want %d", n, len(ips))
	}
	// 第 6 个新 IP 立即发；凭据变化立即发；距上次 ≥5min 重发
	l.EmitIdentityObservation(testBase("ik-1", "203.0.113.6"), nil)
	l.EmitIdentityObservation(testBase("ik-1", "203.0.113.6"), []Credential{{Type: CredentialAPIKey, Hash: "hx"}})
	l.mu.Lock()
	l.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	l.mu.Unlock()
	l.EmitIdentityObservation(testBase("ik-1", "203.0.113.6"), []Credential{{Type: CredentialAPIKey, Hash: "hx"}})
	if n := len(readEventLines(t, path)); n != len(ips)+3 {
		t.Fatalf("new ip / cred change / interval must emit: %d", n)
	}
}

// 已知 IP 集有界（最近 16 个，超出淘汰最旧）：第 17 个 IP 淘汰首个，其回归按新 IP 再发；
// 集内 IP 回归不重复发。
func TestObservationKnownIPEviction(t *testing.T) {
	l, path := newEventTestLogger(t)
	for i := 1; i <= obsKnownIPsCap+1; i++ {
		l.EmitIdentityObservation(testBase("ik-1", fmt.Sprintf("203.0.113.%d", i)), nil)
	}
	if n := len(readEventLines(t, path)); n != obsKnownIPsCap+1 {
		t.Fatalf("one emit per new ip: %d", n)
	}
	// 203.0.113.1 已被第 17 个 IP 淘汰 → 回归按新 IP 再发
	l.EmitIdentityObservation(testBase("ik-1", "203.0.113.1"), nil)
	if n := len(readEventLines(t, path)); n != obsKnownIPsCap+2 {
		t.Fatalf("evicted ip must re-emit: %d", n)
	}
	// 203.0.113.3 仍在已知集 → 不重复发
	l.EmitIdentityObservation(testBase("ik-1", "203.0.113.3"), nil)
	if n := len(readEventLines(t, path)); n != obsKnownIPsCap+2 {
		t.Fatalf("known ip must not re-emit: %d", n)
	}
}

// 轮转补发语义：1m 记录回放刚完成桶原始计数（window_start=上一桶）；其余窗口保持当前估值；
// 60s 节流分支（同桶超时）仍发当前滑窗估值，不回放。
func TestSnapshotRotationEmitsCompletedBucket(t *testing.T) {
	l, path := newEventTestLogger(t)
	base := testBase("ik-1", "203.0.113.1")
	t0 := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	b1 := t0
	b2 := t0.Add(time.Minute)
	l.mu.Lock()
	l.now = func() time.Time { return t0.Add(30 * time.Second) }
	l.mu.Unlock()

	snapAt := func(cur time.Time, completed WindowCounts) *Snapshot {
		s := &Snapshot{CompletedWindow: completed}
		s.Windows[Window1m] = WindowCounts{WindowStart: cur, RequestCount: 1.8}
		s.Windows[Window5m] = WindowCounts{WindowStart: cur, RequestCount: 51}
		return s
	}
	window1m := func(line map[string]any) map[string]any {
		return line["windows"].(map[string]any)["1m"].(map[string]any)
	}

	l.EmitBehaviorSnapshot(base, snapAt(b1, WindowCounts{})) // 首发（b1）：当前窗
	// 轮转到 b2（<60s）：补发，1m = 完成桶 b1 原始计数
	completed := WindowCounts{WindowStart: b1, RequestCount: 50, Status404Count: 30, UniqueURICount: 12}
	l.EmitBehaviorSnapshot(base, snapAt(b2, completed))
	lines := readEventLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("rotation must emit: %d", len(lines))
	}
	w1 := window1m(lines[1])
	if got := w1["request_count"].(float64); got != 50 {
		t.Fatalf("rotation 1m must replay completed bucket count: %v", got)
	}
	if got := w1["status_404_count"].(float64); got != 30 {
		t.Fatalf("completed 404: %v", got)
	}
	if got := w1["unique_uri_count"].(float64); got != 12 {
		t.Fatalf("completed unique: %v", got)
	}
	if got := w1["window_start"].(string); got != b1.Format(time.RFC3339Nano) {
		t.Fatalf("rotation 1m window_start must be completed bucket: %v", got)
	}
	// 其余窗口保持当前滑窗估值
	w5 := lines[1]["windows"].(map[string]any)["5m"].(map[string]any)
	if got := w5["request_count"].(float64); got != 51 {
		t.Fatalf("non-1m windows keep current estimate: %v", got)
	}
	// 60s 节流分支回归：同桶超时仍发当前滑窗估值（window_start=当前桶，不回放）
	l.mu.Lock()
	l.now = func() time.Time { return t0.Add(30*time.Second + 61*time.Second) }
	l.mu.Unlock()
	l.EmitBehaviorSnapshot(base, snapAt(b2, completed))
	lines = readEventLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("60s throttle must emit: %d", len(lines))
	}
	w1 = window1m(lines[2])
	if got := w1["request_count"].(float64); got != 2 { // math.Round(1.8)
		t.Fatalf("60s branch must keep current window estimate: %v", got)
	}
	if got := w1["window_start"].(string); got != b2.Format(time.RFC3339Nano) {
		t.Fatalf("60s branch window_start must be current bucket: %v", got)
	}
}

// 字段去敏：控制字符剥离 + 超长截断（防日志注入）。
func TestEventSanitize(t *testing.T) {
	l, path := newEventTestLogger(t)
	base := testBase("ik-1", "203.0.113.1")
	base.Path = "/ok\nINJECTED" + string(make([]byte, 600))
	base.UserAgent = "ua\r\nfake"
	l.EmitIdentityObservation(base, nil)
	m := readEventLines(t, path)[0]
	p := m["path"].(string)
	if len(p) > maxEventPathLen || containsControl(p) {
		t.Fatalf("path sanitize: %q", p)
	}
	if containsControl(m["user_agent"].(string)) {
		t.Fatalf("ua sanitize: %q", m["user_agent"])
	}
}

func containsControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// Close 幂等；关闭后再次 Close 不报错。
func TestEventLoggerCloseIdempotent(t *testing.T) {
	l, _ := newEventTestLogger(t)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}
