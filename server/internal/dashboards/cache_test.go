package dashboards

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/response"
)

type fakeValkeyEntry struct {
	val       string
	expiresAt time.Time
	ttlArg    time.Duration
}

type fakeValkey struct {
	t      *testing.T
	ln     net.Listener
	closed atomic.Bool

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	data     map[string]fakeValkeyEntry
	getCalls int
	setCalls int
	failGet  bool
	failSet  bool
	getDelay time.Duration
	setDelay time.Duration
}

func newFakeValkey(t *testing.T) *fakeValkey {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake valkey: %v", err)
	}
	f := &fakeValkey{
		t:     t,
		ln:    ln,
		conns: make(map[net.Conn]struct{}),
		data:  make(map[string]fakeValkeyEntry),
	}
	go f.serve()
	t.Cleanup(func() { f.close() })
	return f
}

func (f *fakeValkey) close() {
	if f.closed.Swap(true) {
		return
	}
	_ = f.ln.Close()
	f.mu.Lock()
	for c := range f.conns {
		_ = c.Close()
	}
	f.conns = map[net.Conn]struct{}{}
	f.mu.Unlock()
}

func (f *fakeValkey) hostPort() (string, int) {
	addr := f.ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

func (f *fakeValkey) newCacheClient(t *testing.T) *cache.Client {
	t.Helper()
	host, port := f.hostPort()
	c, err := cache.New(context.Background(), config.CacheConfig{Host: host, Port: port})
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func (f *fakeValkey) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		if f.closed.Load() {
			_ = conn.Close()
			return
		}
		f.mu.Lock()
		f.conns[conn] = struct{}{}
		f.mu.Unlock()
		go f.handle(conn)
	}
}

func readRESPCommand(br *bufio.Reader) ([]string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("unexpected resp line: %q", line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		head, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		head = strings.TrimRight(head, "\r\n")
		if !strings.HasPrefix(head, "$") {
			return nil, fmt.Errorf("unexpected bulk head: %q", head)
		}
		l, err := strconv.Atoi(head[1:])
		if err != nil {
			return nil, err
		}
		buf := make([]byte, l+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:l]))
	}
	return args, nil
}

func respBulk(s string) string {
	return fmt.Sprintf("$%d\r\n%s\r\n", len(s), s)
}

func (f *fakeValkey) handle(conn net.Conn) {
	defer func() {
		f.mu.Lock()
		delete(f.conns, conn)
		f.mu.Unlock()
		_ = conn.Close()
	}()
	br := bufio.NewReader(conn)
	for {
		args, err := readRESPCommand(br)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		cmd := strings.ToUpper(args[0])

		f.mu.Lock()
		getDelay := f.getDelay
		setDelay := f.setDelay
		f.mu.Unlock()

		if cmd == "GET" && getDelay > 0 {
			time.Sleep(getDelay)
		}
		if cmd == "SET" && setDelay > 0 {
			time.Sleep(setDelay)
		}

		f.mu.Lock()
		var reply string
		switch cmd {
		case "HELLO":
			reply = "-ERR unknown command 'HELLO'\r\n"
		case "PING":
			reply = "+PONG\r\n"
		case "GET":
			f.getCalls++
			if f.failGet {
				reply = "-ERR simulated get failure\r\n"
			} else if len(args) < 2 {
				reply = "-ERR wrong number of arguments\r\n"
			} else {
				ent, ok := f.data[args[1]]
				if ok && !ent.expiresAt.IsZero() && time.Now().After(ent.expiresAt) {
					delete(f.data, args[1])
					ok = false
				}
				if !ok {
					reply = "$-1\r\n"
				} else {
					reply = respBulk(ent.val)
				}
			}
		case "SET":
			f.setCalls++
			if f.failSet {
				reply = "-ERR simulated set failure\r\n"
			} else if len(args) < 3 {
				reply = "-ERR wrong number of arguments\r\n"
			} else {
				var ttl time.Duration
				for i := 3; i+1 < len(args); i += 2 {
					opt := strings.ToUpper(args[i])
					v, pErr := strconv.ParseInt(args[i+1], 10, 64)
					if pErr == nil {
						switch opt {
						case "EX":
							ttl = time.Duration(v) * time.Second
						case "PX":
							ttl = time.Duration(v) * time.Millisecond
						}
					}
				}
				var exp time.Time
				if ttl > 0 {
					exp = time.Now().Add(ttl)
				}
				f.data[args[1]] = fakeValkeyEntry{
					val:       args[2],
					expiresAt: exp,
					ttlArg:    ttl,
				}
				reply = "+OK\r\n"
			}
		case "DEL":
			var deleted int
			for _, k := range args[1:] {
				if _, ok := f.data[k]; ok {
					delete(f.data, k)
					deleted++
				}
			}
			reply = fmt.Sprintf(":%d\r\n", deleted)
		case "TTL":
			if len(args) < 2 {
				reply = ":-2\r\n"
			} else if ent, ok := f.data[args[1]]; !ok {
				reply = ":-2\r\n"
			} else if ent.expiresAt.IsZero() {
				reply = ":-1\r\n"
			} else {
				rem := int64(time.Until(ent.expiresAt).Seconds())
				if rem < 0 {
					delete(f.data, args[1])
					reply = ":-2\r\n"
				} else {
					reply = fmt.Sprintf(":%d\r\n", rem)
				}
			}
		case "INFO":
			reply = respBulk("# Memory\r\nused_memory:2097152\r\n")
		default:
			reply = "+OK\r\n"
		}
		f.mu.Unlock()

		if _, err := conn.Write([]byte(reply)); err != nil {
			return
		}
	}
}

func (f *fakeValkey) snapshot() (gets, sets int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.getCalls, f.setCalls
}

func (f *fakeValkey) entry(key string) (fakeValkeyEntry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ent, ok := f.data[key]
	return ent, ok
}

func (f *fakeValkey) seedRaw(key, raw string, ttl time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	f.data[key] = fakeValkeyEntry{val: raw, expiresAt: exp, ttlArg: ttl}
}

func sampleSecurityData(rangeName string) *SecurityOverviewData {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	return &SecurityOverviewData{
		GeneratedAt: now,
		Range:       rangeName,
		Today: &TodayCounters{
			RequestsTotal: 100,
			WAFEvents:     5,
			ProtectedApps: 2,
		},
		Trends: &SecurityTrendData{
			Start:       now.Add(-time.Hour),
			End:         now,
			StepSeconds: 60,
			Times:       []time.Time{},
			Requests:    []float64{},
			Events:      []float64{},
			Blocks:      []float64{},
			Observes:    []float64{},
			CCExceeded:  []float64{},
			IPDeny:      []float64{},
			RiskLevels:  map[string][]float64{},
			Disposition: map[string][]float64{},
		},
		Top: &TopData{
			AttackTypes:  []KV{},
			SourceIPs:    []SourceIPStat{},
			Applications: []KV{},
			Rules:        []KV{},
			URIs:         []URIStat{},
		},
		Risks: &RiskData{
			HighUnprocessedEvents: []EventSummary{},
			FailedPublishTasks:    []PublishTaskSummary{},
			GatewayIssues:         []ComponentIssue{},
			CollectorLag:          &CollectorLag{Jobs: []JobStatus{}},
		},
	}
}

func sampleRuntimeData() *RuntimeOverviewData {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	up := 3600.0
	mem := int64(2097152)
	return &RuntimeOverviewData{
		GeneratedAt: now,
		Components: []ComponentStatus{
			{
				Component: "GATEWAY",
				Status:    "UP",
				TakenAt:   now,
				Metrics:   map[string]interface{}{"uptime_seconds": up},
			},
		},
		Gateway: &GatewayRuntime{Status: "UP", UptimeSeconds: &up, SnapshotAt: &now},
		Publish: &PublishStats{WindowDays: 30, Total: 4, Success: 4, SuccessRate: 1},
		Reports: &ReportStats{WindowDays: 30, Total: 2, Success: 2, SuccessRate: 1},
		Storage: &StorageStats{PGDatabaseSizeBytes: 8192, ValkeyUsedMemoryBytes: &mem, DiskPath: "/app"},
	}
}

func sampleAuditData() *AuditOverviewData {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	return &AuditOverviewData{
		GeneratedAt:             now,
		TodayDispositions:       3,
		UnprocessedEvents:       7,
		TodayAudits:             11,
		RecentAudits:            []AuditSummary{},
		DispositionDistribution: []StatusCount{{Status: "UNPROCESSED", Count: 7}},
		ActionStats:             []ActionCount{{Action: "applications.update", Count: 5}},
	}
}

func doDashboardReq(h http.HandlerFunc, target, reqID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if reqID != "" {
		req = req.WithContext(context.WithValue(req.Context(), response.RequestIDKey, reqID))
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestDashboardCacheMissPopulateHitAndNilDBHit(t *testing.T) {
	fk := newFakeValkey(t)
	c := fk.newCacheClient(t)

	var secCalls, runCalls, audCalls atomic.Int32
	h := NewHandler(nil, nil)
	h.SetCache(c)
	h.loadSecurity = func(_ context.Context, rangeName string, _ time.Duration) (*SecurityOverviewData, error) {
		secCalls.Add(1)
		return sampleSecurityData(rangeName), nil
	}
	h.loadRuntime = func(_ context.Context) (*RuntimeOverviewData, error) {
		runCalls.Add(1)
		return sampleRuntimeData(), nil
	}
	h.loadAudit = func(_ context.Context) (*AuditOverviewData, error) {
		audCalls.Add(1)
		return sampleAuditData(), nil
	}

	// 1. SecurityOverview: miss -> populate -> hit (even from a nil-DB handler)
	r1 := doDashboardReq(h.SecurityOverview, "/api/v1/dashboard/security-overview?range=24h", "req-sec-1")
	if r1.Code != http.StatusOK {
		t.Fatalf("security miss status=%d body=%s", r1.Code, r1.Body.String())
	}
	if secCalls.Load() != 1 {
		t.Fatalf("secCalls=%d, want 1", secCalls.Load())
	}
	if cc := r1.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", cc)
	}
	ent, ok := fk.entry("jiuzhang:dashboard:v1:security-overview:24h")
	if !ok {
		t.Fatal("expected security-overview:24h key in Valkey")
	}
	if ent.ttlArg != 20*time.Second {
		t.Fatalf("security ttlArg=%v, want 20s", ent.ttlArg)
	}

	// Empty range normalizes to 24h and hits the same cache key
	r2 := doDashboardReq(h.SecurityOverview, "/api/v1/dashboard/security-overview", "req-sec-2")
	if r2.Code != http.StatusOK {
		t.Fatalf("security hit status=%d body=%s", r2.Code, r2.Body.String())
	}
	if secCalls.Load() != 1 {
		t.Fatalf("secCalls after hit=%d, want 1", secCalls.Load())
	}

	var body1, body2 struct {
		Code      string               `json:"code"`
		RequestID string               `json:"request_id"`
		Data      SecurityOverviewData `json:"data"`
	}
	if err := json.Unmarshal(r1.Body.Bytes(), &body1); err != nil {
		t.Fatalf("unmarshal r1: %v", err)
	}
	if err := json.Unmarshal(r2.Body.Bytes(), &body2); err != nil {
		t.Fatalf("unmarshal r2: %v", err)
	}
	if body1.RequestID != "req-sec-1" || body2.RequestID != "req-sec-2" {
		t.Fatalf("request_id mismatch: %q vs %q", body1.RequestID, body2.RequestID)
	}
	if body2.Data.Range != "24h" || body2.Data.Today.RequestsTotal != 100 {
		t.Fatalf("unexpected cached security data: %+v", body2.Data)
	}

	// 2. RuntimeOverview & AuditOverview populate
	if r := doDashboardReq(h.RuntimeOverview, "/api/v1/dashboard/runtime-overview", "req-run-1"); r.Code != http.StatusOK {
		t.Fatalf("runtime miss status=%d", r.Code)
	}
	if r := doDashboardReq(h.RuntimeOverview, "/api/v1/dashboard/runtime-overview", "req-run-2"); r.Code != http.StatusOK {
		t.Fatalf("runtime hit status=%d", r.Code)
	}
	if runCalls.Load() != 1 {
		t.Fatalf("runCalls=%d, want 1", runCalls.Load())
	}
	if ent, ok := fk.entry("jiuzhang:dashboard:v1:runtime-overview"); !ok || ent.ttlArg != 20*time.Second {
		t.Fatalf("runtime cache entry missing or bad ttl: ok=%v ttl=%v", ok, ent.ttlArg)
	}

	if r := doDashboardReq(h.AuditOverview, "/api/v1/dashboard/audit-overview", "req-aud-1"); r.Code != http.StatusOK {
		t.Fatalf("audit miss status=%d", r.Code)
	}
	if r := doDashboardReq(h.AuditOverview, "/api/v1/dashboard/audit-overview", "req-aud-2"); r.Code != http.StatusOK {
		t.Fatalf("audit hit status=%d", r.Code)
	}
	if audCalls.Load() != 1 {
		t.Fatalf("audCalls=%d, want 1", audCalls.Load())
	}
	if ent, ok := fk.entry("jiuzhang:dashboard:v1:audit-overview"); !ok || ent.ttlArg != 20*time.Second {
		t.Fatalf("audit cache entry missing or bad ttl: ok=%v ttl=%v", ok, ent.ttlArg)
	}

	// 3. Separate handler with NewHandler(nil, nil) and NO spy overrides serves pre-warmed Valkey hits without panic
	coldHandlerWithNilDB := NewHandler(nil, nil)
	coldHandlerWithNilDB.SetCache(c)
	for _, tc := range []struct {
		fn   http.HandlerFunc
		path string
	}{
		{coldHandlerWithNilDB.SecurityOverview, "/api/v1/dashboard/security-overview?range=24h"},
		{coldHandlerWithNilDB.RuntimeOverview, "/api/v1/dashboard/runtime-overview"},
		{coldHandlerWithNilDB.AuditOverview, "/api/v1/dashboard/audit-overview"},
	} {
		rec := doDashboardReq(tc.fn, tc.path, "req-nil-db-hit")
		if rec.Code != http.StatusOK {
			t.Fatalf("nil-DB handler cache hit %s returned %d: %s", tc.path, rec.Code, rec.Body.String())
		}
	}
}

func TestDashboardSecurityRangeValidationBypassesCacheAndDB(t *testing.T) {
	fk := newFakeValkey(t)
	c := fk.newCacheClient(t)

	var secCalls atomic.Int32
	h := NewHandler(nil, nil)
	h.SetCache(c)
	h.loadSecurity = func(_ context.Context, rangeName string, _ time.Duration) (*SecurityOverviewData, error) {
		secCalls.Add(1)
		return sampleSecurityData(rangeName), nil
	}

	// Invalid range must reject with 400 and make 0 Valkey / 0 DB calls
	bad := doDashboardReq(h.SecurityOverview, "/api/v1/dashboard/security-overview?range=2h", "req-bad")
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "INVALID_ARGUMENT") {
		t.Fatalf("bad range got status=%d body=%s", bad.Code, bad.Body.String())
	}
	gets, sets := fk.snapshot()
	if gets != 0 || sets != 0 || secCalls.Load() != 0 {
		t.Fatalf("invalid range touched Valkey/DB: gets=%d sets=%d secCalls=%d", gets, sets, secCalls.Load())
	}

	// 7d uses its own key
	r7d := doDashboardReq(h.SecurityOverview, "/api/v1/dashboard/security-overview?range=7d", "req-7d")
	if r7d.Code != http.StatusOK || secCalls.Load() != 1 {
		t.Fatalf("7d status=%d secCalls=%d", r7d.Code, secCalls.Load())
	}
	if _, ok := fk.entry("jiuzhang:dashboard:v1:security-overview:7d"); !ok {
		t.Fatal("expected 7d cache key")
	}
}

func TestDashboardCacheTTLExpiry(t *testing.T) {
	fk := newFakeValkey(t)
	c := fk.newCacheClient(t)

	var calls atomic.Int32
	h := NewHandler(nil, nil)
	h.SetCache(c)
	h.cacheTTL = 100 * time.Millisecond
	h.loadRuntime = func(_ context.Context) (*RuntimeOverviewData, error) {
		calls.Add(1)
		return sampleRuntimeData(), nil
	}

	if r := doDashboardReq(h.RuntimeOverview, "/api/v1/dashboard/runtime-overview", "t1"); r.Code != http.StatusOK {
		t.Fatalf("r1 status=%d", r.Code)
	}
	if r := doDashboardReq(h.RuntimeOverview, "/api/v1/dashboard/runtime-overview", "t2"); r.Code != http.StatusOK {
		t.Fatalf("r2 status=%d", r.Code)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls before expiry=%d, want 1", calls.Load())
	}

	time.Sleep(150 * time.Millisecond)

	if r := doDashboardReq(h.RuntimeOverview, "/api/v1/dashboard/runtime-overview", "t3"); r.Code != http.StatusOK {
		t.Fatalf("r3 status=%d", r.Code)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls after expiry=%d, want 2", calls.Load())
	}
}

type typedNilOverviewCache struct{}

func (t *typedNilOverviewCache) Get(context.Context, string) (string, error) {
	return "", errors.New("should not be called")
}

func (t *typedNilOverviewCache) Set(context.Context, string, string, time.Duration) error {
	return errors.New("should not be called")
}

func TestDashboardCacheFailOpenVariants(t *testing.T) {
	t.Run("nil client, zero-value client, typed-nil interface", func(t *testing.T) {
		var calls atomic.Int32
		h := NewHandler(nil, nil)
		h.loadAudit = func(_ context.Context) (*AuditOverviewData, error) {
			calls.Add(1)
			return sampleAuditData(), nil
		}

		// SetCache(nil)
		h.SetCache(nil)
		if r := doDashboardReq(h.AuditOverview, "/api/v1/dashboard/audit-overview", "n1"); r.Code != http.StatusOK {
			t.Fatalf("nil cache status=%d", r.Code)
		}

		// Non-nil *cache.Client with nil Redis()
		h.SetCache(&cache.Client{})
		if r := doDashboardReq(h.AuditOverview, "/api/v1/dashboard/audit-overview", "n2"); r.Code != http.StatusOK {
			t.Fatalf("empty cache.Client status=%d", r.Code)
		}

		// Typed-nil overviewCache interface
		var tn *typedNilOverviewCache
		h.ovCache = tn
		if r := doDashboardReq(h.AuditOverview, "/api/v1/dashboard/audit-overview", "n3"); r.Code != http.StatusOK {
			t.Fatalf("typed-nil cache status=%d", r.Code)
		}

		if calls.Load() != 3 {
			t.Fatalf("calls=%d, want 3", calls.Load())
		}
	})

	t.Run("GET and SET errors fail open", func(t *testing.T) {
		fk := newFakeValkey(t)
		fk.failGet = true
		fk.failSet = true
		c := fk.newCacheClient(t)

		var calls atomic.Int32
		h := NewHandler(nil, nil)
		h.SetCache(c)
		h.loadSecurity = func(_ context.Context, rangeName string, _ time.Duration) (*SecurityOverviewData, error) {
			calls.Add(1)
			return sampleSecurityData(rangeName), nil
		}

		r := doDashboardReq(h.SecurityOverview, "/api/v1/dashboard/security-overview?range=1h", "err1")
		if r.Code != http.StatusOK || calls.Load() != 1 {
			t.Fatalf("status=%d calls=%d", r.Code, calls.Load())
		}
	})

	t.Run("Valkey closed fails open", func(t *testing.T) {
		fk := newFakeValkey(t)
		c := fk.newCacheClient(t)
		fk.close()

		var calls atomic.Int32
		h := NewHandler(nil, nil)
		h.SetCache(c)
		h.cacheOpTimeout = 100 * time.Millisecond
		h.loadRuntime = func(_ context.Context) (*RuntimeOverviewData, error) {
			calls.Add(1)
			return sampleRuntimeData(), nil
		}

		r := doDashboardReq(h.RuntimeOverview, "/api/v1/dashboard/runtime-overview", "closed1")
		if r.Code != http.StatusOK || calls.Load() != 1 {
			t.Fatalf("closed Valkey status=%d calls=%d", r.Code, calls.Load())
		}
	})

	t.Run("Valkey GET timeout fails open within bounded time", func(t *testing.T) {
		fk := newFakeValkey(t)
		c := fk.newCacheClient(t)
		fk.mu.Lock()
		fk.getDelay = 400 * time.Millisecond
		fk.mu.Unlock()

		var calls atomic.Int32
		h := NewHandler(nil, nil)
		h.SetCache(c)
		h.cacheOpTimeout = 80 * time.Millisecond
		h.loadAudit = func(_ context.Context) (*AuditOverviewData, error) {
			calls.Add(1)
			return sampleAuditData(), nil
		}

		start := time.Now()
		r := doDashboardReq(h.AuditOverview, "/api/v1/dashboard/audit-overview", "to1")
		elapsed := time.Since(start)
		if r.Code != http.StatusOK || calls.Load() != 1 {
			t.Fatalf("timeout status=%d calls=%d", r.Code, calls.Load())
		}
		if elapsed >= 350*time.Millisecond {
			t.Fatalf("cacheOpTimeout did not bound GET latency: elapsed=%v", elapsed)
		}
	})

	t.Run("Valkey SET timeout fails open within bounded time", func(t *testing.T) {
		fk := newFakeValkey(t)
		c := fk.newCacheClient(t)
		fk.mu.Lock()
		fk.setDelay = 400 * time.Millisecond
		fk.mu.Unlock()

		var calls atomic.Int32
		h := NewHandler(nil, nil)
		h.SetCache(c)
		h.cacheOpTimeout = 80 * time.Millisecond
		h.loadAudit = func(_ context.Context) (*AuditOverviewData, error) {
			calls.Add(1)
			return sampleAuditData(), nil
		}

		start := time.Now()
		r := doDashboardReq(h.AuditOverview, "/api/v1/dashboard/audit-overview", "to-set")
		elapsed := time.Since(start)
		if r.Code != http.StatusOK || calls.Load() != 1 {
			t.Fatalf("SET timeout status=%d calls=%d", r.Code, calls.Load())
		}
		if elapsed >= 350*time.Millisecond {
			t.Fatalf("cacheOpTimeout did not bound SET latency: elapsed=%v", elapsed)
		}
	})

	t.Run("Corrupt cached JSON falls back to DB and overwrites key", func(t *testing.T) {
		fk := newFakeValkey(t)
		c := fk.newCacheClient(t)
		fk.seedRaw("jiuzhang:dashboard:v1:audit-overview", "{not-valid-json", 20*time.Second)

		var calls atomic.Int32
		h := NewHandler(nil, nil)
		h.SetCache(c)
		h.loadAudit = func(_ context.Context) (*AuditOverviewData, error) {
			calls.Add(1)
			return sampleAuditData(), nil
		}

		r1 := doDashboardReq(h.AuditOverview, "/api/v1/dashboard/audit-overview", "corrupt1")
		if r1.Code != http.StatusOK || calls.Load() != 1 {
			t.Fatalf("corrupt fallback status=%d calls=%d", r1.Code, calls.Load())
		}
		r2 := doDashboardReq(h.AuditOverview, "/api/v1/dashboard/audit-overview", "corrupt2")
		if r2.Code != http.StatusOK || calls.Load() != 1 {
			t.Fatalf("post-repair cache hit status=%d calls=%d", r2.Code, calls.Load())
		}
	})
}

func TestDashboardSingleflightCoalescingAndCancelIsolation(t *testing.T) {
	fk := newFakeValkey(t)
	c := fk.newCacheClient(t)

	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})

	h := NewHandler(nil, nil)
	h.SetCache(c)
	h.loadSecurity = func(ctx context.Context, rangeName string, _ time.Duration) (*SecurityOverviewData, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return sampleSecurityData(rangeName), nil
	}

	const workers = 16
	var wg sync.WaitGroup
	codes := make([]int, workers)

	// Request 0 starts the singleflight load, then cancels its own context while others wait.
	ctx0, cancel0 := context.WithCancel(context.Background())
	wg.Add(1)
	go func() {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/security-overview?range=24h", nil).WithContext(ctx0)
		rec := httptest.NewRecorder()
		h.SecurityOverview(rec, req)
		codes[0] = rec.Code
	}()

	<-started

	for i := 1; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rec := doDashboardReq(h.SecurityOverview, "/api/v1/dashboard/security-overview?range=24h", fmt.Sprintf("sf-%d", idx))
			codes[idx] = rec.Code
		}(i)
	}

	// Give remaining goroutines a brief moment to attach to the in-flight singleflight call
	time.Sleep(30 * time.Millisecond)
	cancel0()
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	if calls.Load() != 1 {
		t.Fatalf("singleflight loader calls=%d, want 1", calls.Load())
	}
	for i := 1; i < workers; i++ {
		if codes[i] != http.StatusOK {
			t.Fatalf("waiter %d status=%d, want 200", i, codes[i])
		}
	}
}

func TestDeriveGatewayRuntimeParity(t *testing.T) {
	if got := deriveGatewayRuntime(nil); got.Status != "UNKNOWN" || got.SnapshotAt != nil || got.UptimeSeconds != nil {
		t.Fatalf("empty components = %+v, want UNKNOWN", got)
	}
	t1 := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	t2 := t1.Add(5 * time.Minute)
	t3 := t2.Add(5 * time.Minute)
	components := []ComponentStatus{
		{Component: "POSTGRES", Status: "UP", TakenAt: t3, Metrics: map[string]interface{}{"uptime_seconds": 999.0}},
		{Component: "gateway-primary", Status: "DEGRADED", TakenAt: t1, Metrics: map[string]interface{}{"uptime_seconds": 120.5}},
		{Component: "GATEWAY", Status: "UP", TakenAt: t2, Metrics: map[string]interface{}{"uptime_seconds": 456.25}},
	}
	got := deriveGatewayRuntime(components)
	if got.Status != "UP" {
		t.Fatalf("Status=%q, want UP", got.Status)
	}
	if got.SnapshotAt == nil || !got.SnapshotAt.Equal(t2) {
		t.Fatalf("SnapshotAt=%v, want %v", got.SnapshotAt, t2)
	}
	if got.UptimeSeconds == nil || *got.UptimeSeconds != 456.25 {
		t.Fatalf("UptimeSeconds=%v, want 456.25", got.UptimeSeconds)
	}
}
