package xdpaccel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
)

func TestValidateConfigAndNICGuards(t *testing.T) {
	valid := &Config{
		Enabled:             true,
		SocketPath:          " /run/jiuzhang/xdpguard.sock ",
		Interfaces:          []string{" eth0 ", "ens192", "bond0.100"},
		AttachMode:          " NATIVE ",
		SyncIntervalSeconds: 10,
	}
	NormalizeConfig(valid)
	if valid.SocketPath != "/run/jiuzhang/xdpguard.sock" || valid.AttachMode != AttachModeNative {
		t.Fatalf("normalize mismatch: %+v", valid)
	}
	if errs := ValidateConfig(valid); len(errs) > 0 {
		t.Fatalf("valid config rejected: %+v", errs)
	}

	// Disabled with empty interfaces is valid.
	disabled := DefaultConfig()
	if errs := ValidateConfig(disabled); len(errs) > 0 {
		t.Fatalf("default disabled config rejected: %+v", errs)
	}

	fieldSet := func(errs []FieldError) map[string]bool {
		m := map[string]bool{}
		for _, e := range errs {
			m[e.Field] = true
		}
		return m
	}

	tooMany := make([]string, MaxInterfaces+1)
	for i := range tooMany {
		tooMany[i] = "eth" + string(rune('a'+i))
	}

	cases := []struct {
		name   string
		mutate func(*Config)
		field  string
	}{
		{"enabled requires >=1 interface", func(c *Config) { c.Enabled = true; c.Interfaces = []string{} }, "interfaces"},
		{"empty socket", func(c *Config) { c.SocketPath = "" }, "socket_path"},
		{"socket /tmp rejected", func(c *Config) { c.SocketPath = "/tmp/xdpguard.sock" }, "socket_path"},
		{"socket traversal rejected", func(c *Config) { c.SocketPath = "/var/run/caddy/sidecars/../docker.sock" }, "socket_path"},
		{"socket dotdot in filename", func(c *Config) { c.SocketPath = "/run/jiuzhang/a..b.sock" }, "socket_path"},
		{"socket double slash", func(c *Config) { c.SocketPath = "/run/jiuzhang//xdpguard.sock" }, "socket_path"},
		{"socket trailing slash", func(c *Config) { c.SocketPath = "/var/run/caddy/sidecars/" }, "socket_path"},
		{"socket http ssrf", func(c *Config) { c.SocketPath = "http://127.0.0.1:9000/v1/sync" }, "socket_path"},
		{"socket unix scheme", func(c *Config) { c.SocketPath = "unix:///var/run/caddy/sidecars/xdpguard.sock" }, "socket_path"},
		{"socket control char", func(c *Config) { c.SocketPath = "/run/jiuzhang/xdp\nguard.sock" }, "socket_path"},
		{"socket too long", func(c *Config) { c.SocketPath = "/run/jiuzhang/" + strings.Repeat("a", MaxSocketPathLen) }, "socket_path"},
		{"invalid attach mode", func(c *Config) { c.AttachMode = "offload" }, "attach_mode"},
		{"sync interval 0", func(c *Config) { c.SyncIntervalSeconds = 0 }, "sync_interval_seconds"},
		{"sync interval 301", func(c *Config) { c.SyncIntervalSeconds = 301 }, "sync_interval_seconds"},
		{"too many interfaces", func(c *Config) { c.Interfaces = tooMany }, "interfaces"},
		{"duplicate interfaces", func(c *Config) { c.Interfaces = []string{"eth0", "eth0"} }, "interfaces"},
		{"loopback lo", func(c *Config) { c.Interfaces = []string{"lo"} }, "interfaces"},
		{"loopback LO uppercase", func(c *Config) { c.Interfaces = []string{"LO"} }, "interfaces"},
		{"docker0", func(c *Config) { c.Interfaces = []string{"docker0"} }, "interfaces"},
		{"docker uppercase", func(c *Config) { c.Interfaces = []string{"DOCKER0"} }, "interfaces"},
		{"br- bridge", func(c *Config) { c.Interfaces = []string{"br-abcdef12"} }, "interfaces"},
		{"veth", func(c *Config) { c.Interfaces = []string{"veth1234"} }, "interfaces"},
		{"virbr", func(c *Config) { c.Interfaces = []string{"virbr0"} }, "interfaces"},
		{"cni", func(c *Config) { c.Interfaces = []string{"cni0"} }, "interfaces"},
		{"flannel", func(c *Config) { c.Interfaces = []string{"flannel.1"} }, "interfaces"},
		{"cali", func(c *Config) { c.Interfaces = []string{"cali9f8e7d"} }, "interfaces"},
		{"tun", func(c *Config) { c.Interfaces = []string{"tun0"} }, "interfaces"},
		{"tap", func(c *Config) { c.Interfaces = []string{"tap0"} }, "interfaces"},
		{"wg", func(c *Config) { c.Interfaces = []string{"wg0"} }, "interfaces"},
		{"bad chars", func(c *Config) { c.Interfaces = []string{"eth0;id"} }, "interfaces"},
		{"too long nic (>15)", func(c *Config) { c.Interfaces = []string{"enp0123456789abcd"} }, "interfaces"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := *valid
			cp.Interfaces = nonNilStrings(valid.Interfaces)
			tc.mutate(&cp)
			errs := ValidateConfig(&cp)
			if !fieldSet(errs)[tc.field] {
				t.Fatalf("expected error on field %q, got %+v", tc.field, errs)
			}
		})
	}

	if msg := ValidateReason(strings.Repeat("a", MaxReasonLen+1)); msg == "" {
		t.Fatal("expected overlong reason to fail")
	}
	if msg := ValidateReason("bad\x00reason"); msg == "" {
		t.Fatal("expected control char reason to fail")
	}
	if msg := ValidateReason("允许换行\n和制表\t原因说明"); msg != "" {
		t.Fatalf("valid reason rejected: %s", msg)
	}
}

func TestFilterBlocklistProtectedOverlapAndNormalization(t *testing.T) {
	blacklist := []string{
		"203.0.113.55",           // valid single IPv4 -> 203.0.113.55/32
		"198.51.100.12/24",       // host bits masked -> 198.51.100.0/24
		"::ffff:203.0.113.55",    // IPv4-in-IPv6 duplicate -> deduped with 203.0.113.55/32
		"2001:db8:abcd::1",       // valid IPv6 -> 2001:db8:abcd::1/128
		"10.0.0.0/8",             // broad CIDR overlapping protected 10.0.0.5 -> EXCLUDED
		"192.168.10.25",          // inside protected CIDR 192.168.10.0/24 -> EXCLUDED
		"0.0.0.0/0",              // overlaps loopback/unspecified -> EXCLUDED
		"::/0",                   // overlaps ::1/:: -> EXCLUDED
		"127.0.0.1",              // loopback -> EXCLUDED
		"::1",                    // IPv6 loopback -> EXCLUDED
		"169.254.169.254",        // link-local metadata -> EXCLUDED
		"fe80::1",                // IPv6 link-local -> EXCLUDED
		"224.0.0.1",              // multicast -> EXCLUDED
		"ff02::1",                // IPv6 multicast -> EXCLUDED
		"255.255.255.255",        // broadcast -> EXCLUDED
		"0.0.0.0",                // unspecified -> EXCLUDED
		"::",                     // unspecified v6 -> EXCLUDED
		"not-an-ip",              // invalid -> skipped safely
		"fe80::1%eth0",           // zoned -> skipped safely
	}
	tempBlocks := []string{
		"198.51.100.99",   // valid single IP -> 198.51.100.99/32
		"203.0.113.55",    // duplicate with blacklist -> deduped
		"10.0.0.5",        // exact protected IP -> EXCLUDED
		"2001:db8:ffff::", // overlaps protected 2001:db8:ffff::/48 -> EXCLUDED
	}
	protected := []string{
		"10.0.0.5",
		"192.168.10.0/24",
		"2001:db8:ffff::/48",
		"::ffff:10.0.0.5", // duplicate unmapped -> deduped
	}

	blocked, protOut, excluded := FilterBlocklist(blacklist, tempBlocks, protected)

	wantBlocked := []string{
		"198.51.100.0/24",
		"198.51.100.99/32",
		"203.0.113.55/32",
		"2001:db8:abcd::1/128",
	}
	if !reflect.DeepEqual(blocked, wantBlocked) {
		t.Fatalf("blocked = %v, want %v", blocked, wantBlocked)
	}

	wantProtected := []string{
		"10.0.0.5/32",
		"192.168.10.0/24",
		"2001:db8:ffff::/48",
	}
	if !reflect.DeepEqual(protOut, wantProtected) {
		t.Fatalf("protected = %v, want %v", protOut, wantProtected)
	}

	// Excluded unique candidates:
	// 10.0.0.0/8, 192.168.10.25/32, 0.0.0.0/0, ::/0, 127.0.0.1/32, ::1/128,
	// 169.254.169.254/32, fe80::1/128, 224.0.0.1/32, ff02::1/128,
	// 255.255.255.255/32, 0.0.0.0/32, ::/128, 10.0.0.5/32, 2001:db8:ffff::/128 => 15
	if excluded != 15 {
		t.Fatalf("excludedCount = %d, want 15", excluded)
	}

	// Empty inputs always return non-nil slices.
	emptyB, emptyP, emptyEx := FilterBlocklist(nil, nil, nil)
	if emptyB == nil || emptyP == nil || len(emptyB) != 0 || len(emptyP) != 0 || emptyEx != 0 {
		t.Fatalf("empty FilterBlocklist mismatch: b=%#v p=%#v ex=%d", emptyB, emptyP, emptyEx)
	}
}

func TestStoreSQLGlobalOnlyGuardInvariants(t *testing.T) {
	// Static regression guard verifying store.go SQL strictly restricts to global rules & global temp blocks.
	data, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatalf("read store.go: %v", err)
	}
	src := string(data)
	for _, required := range []string{
		"FROM ip_access_rules",
		"rule_type = 'DENY'",
		"scope_type = 'GLOBAL'",
		"application_id IS NULL",
		"FROM temporary_blocks",
		"block_expires_at > now()",
		"FROM protected_addresses",
		"status = 'ENABLED'",
	} {
		if !strings.Contains(src, required) {
			t.Errorf("store.go missing critical global-only SQL guard %q", required)
		}
	}
}

func startTestUnixDaemon(t *testing.T, handler http.Handler) (string, string) {
	t.Helper()
	// Keep temp dir short so macOS Unix socket sun_path (<=104 bytes) never overflows.
	dir, err := os.MkdirTemp("/tmp", "xdptest-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sock := filepath.Join(dir, "xdpguard.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("net.Listen unix: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	})
	return dir + "/", sock
}

func TestUnixClientSecurityAndRoundtrip(t *testing.T) {
	prodClient := NewUnixClient(500*time.Millisecond, time.Second)

	// 1. Missing socket under allowed prefix -> honestly reports unavailable & fallback_userspace
	missingPath := "/var/run/caddy/sidecars/definitely-missing-xdpguard-test.sock"
	stMissing := prodClient.ProbeStatus(context.Background(), missingPath)
	if stMissing.Available || stMissing.Status != StatusUnavailable || stMissing.Mode != ModeFallbackUserspace ||
		stMissing.KernelAttached || stMissing.SocketPath != missingPath || stMissing.Error == "" {
		t.Fatalf("missing socket must honestly report unavailable: %+v", stMissing)
	}
	if _, err := prodClient.PushSync(context.Background(), missingPath, SyncRequest{}); !errors.Is(err, ErrDaemonUnavailable) {
		t.Fatalf("PushSync on missing socket = %v, want ErrDaemonUnavailable", err)
	}

	// 2. Real Unix socket daemon with /v1/stats and /v1/sync
	var (
		mu          sync.Mutex
		lastSyncReq *SyncRequest
	)
	prefix, sock := startTestUnixDaemon(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/stats":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":                   "ok",
				"mode":                     "xdp_native",
				"kernel_attached":          true,
				"attach_mode_requested":    "auto",
				"interfaces":               []map[string]interface{}{{"name": "eth0", "attached": true, "mode": "xdp_native", "error": ""}},
				"dropped_v4_packets":       12345,
				"dropped_v6_packets":       67,
				"passed_packets":           999999,
				"synced_v4_cidrs":          2,
				"synced_v6_cidrs":          1,
				"excluded_protected_count": 1,
				"last_sync_at":             "2026-11-26T14:00:00Z",
				"error":                    "",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sync":
			var req SyncRequest
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			mu.Lock()
			cp := req
			lastSyncReq = &cp
			mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			if !req.Enabled {
				_ = json.NewEncoder(w).Encode(SyncResponse{
					Synced:             true,
					Mode:               ModeFallbackUserspace,
					KernelAttached:     false,
					AttachedInterfaces: []string{},
					LastSyncAt:         "2026-11-26T14:01:00Z",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(SyncResponse{
				Synced:                 true,
				Mode:                   ModeXDPNative,
				KernelAttached:         true,
				AttachedInterfaces:     req.Interfaces,
				SyncedV4CIDRs:          2,
				SyncedV6CIDRs:          1,
				ExcludedProtectedCount: 1,
				InvalidCIDRsSkipped:    0,
				LastSyncAt:             "2026-11-26T14:00:00Z",
			})
		default:
			http.NotFound(w, r)
		}
	}))

	// 3. Production client strictly rejects /tmp socket (testAllowedPrefix never set in prod)
	stProdReject := prodClient.ProbeStatus(context.Background(), sock)
	if stProdReject.Available || stProdReject.Status != StatusInvalidSocketPath {
		t.Fatalf("production client must reject /tmp socket: %+v", stProdReject)
	}
	if _, err := prodClient.PushSync(context.Background(), sock, SyncRequest{}); !errors.Is(err, ErrInvalidSocketPath) {
		t.Fatalf("production PushSync must reject /tmp socket, got %v", err)
	}

	// 4. Test client probes /v1/stats cleanly
	testClient := &UnixClient{statusTimeout: time.Second, syncTimeout: time.Second, testAllowedPrefix: prefix}
	stOK := testClient.ProbeStatus(context.Background(), sock)
	if !stOK.Available || stOK.Status != StatusOK || stOK.Mode != ModeXDPNative || !stOK.KernelAttached ||
		stOK.DroppedV4Packets != 12345 || stOK.DroppedV6Packets != 67 || stOK.PassedPackets != 999999 ||
		len(stOK.Interfaces) != 1 || stOK.Interfaces[0].Name != "eth0" {
		t.Fatalf("unexpected live /v1/stats result: %+v", stOK)
	}

	// 5. Symlink inside allowed dir MUST be rejected
	linkPath := filepath.Join(strings.TrimSuffix(prefix, "/"), "escape.sock")
	if err := os.Symlink(sock, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	stLink := testClient.ProbeStatus(context.Background(), linkPath)
	if stLink.Available || !strings.Contains(stLink.Error, "符号链接") {
		t.Fatalf("symlink socket must be rejected on ProbeStatus: %+v", stLink)
	}
	if _, err := testClient.PushSync(context.Background(), linkPath, SyncRequest{}); !errors.Is(err, ErrDaemonUnavailable) || !strings.Contains(err.Error(), "符号链接") {
		t.Fatalf("symlink socket must be rejected on PushSync: %v", err)
	}

	// 6. Regular file inside allowed dir MUST be rejected
	regPath := filepath.Join(strings.TrimSuffix(prefix, "/"), "plain.sock")
	if err := os.WriteFile(regPath, []byte("not-a-socket"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}
	stReg := testClient.ProbeStatus(context.Background(), regPath)
	if stReg.Available || !strings.Contains(stReg.Error, "Unix Domain Socket") {
		t.Fatalf("regular file must be rejected: %+v", stReg)
	}

	// 7. PushSync exact wire contract roundtrip
	syncResp, err := testClient.PushSync(context.Background(), sock, SyncRequest{
		Enabled:        true,
		AttachMode:     AttachModeAuto,
		Interfaces:     []string{"eth0"},
		BlockedCIDRs:   []string{"203.0.113.5/32", "198.51.100.0/24", "2001:db8::1/128"},
		ProtectedCIDRs: []string{"10.0.0.1/32"},
	})
	if err != nil {
		t.Fatalf("PushSync failed: %v", err)
	}
	if !syncResp.Synced || !syncResp.KernelAttached || syncResp.Mode != ModeXDPNative || syncResp.SyncedV4CIDRs != 2 || syncResp.SyncedV6CIDRs != 1 {
		t.Fatalf("unexpected sync response: %+v", syncResp)
	}
	mu.Lock()
	if lastSyncReq == nil || lastSyncReq.SchemaVersion != SchemaVersion || len(lastSyncReq.BlockedCIDRs) != 3 {
		t.Fatalf("unexpected sync request received by daemon: %+v", lastSyncReq)
	}
	mu.Unlock()

	// 8. Fallback from 404 /v1/stats -> /healthz
	prefixHz, sockHz := startTestUnixDaemon(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":                   "degraded",
				"mode":                     "fallback_userspace",
				"kernel_attached":          false,
				"attached_interfaces":      []string{},
				"dropped_v4_packets":       0,
				"dropped_v6_packets":       0,
				"synced_v4_cidrs":          0,
				"synced_v6_cidrs":          0,
				"excluded_protected_count": 2,
				"last_sync_at":             "2026-11-26T14:02:00Z",
				"error":                    "CAP_BPF unavailable in unprivileged container",
			})
			return
		}
		http.NotFound(w, r)
	}))
	hzClient := &UnixClient{statusTimeout: time.Second, syncTimeout: time.Second, testAllowedPrefix: prefixHz}
	stHz := hzClient.ProbeStatus(context.Background(), sockHz)
	if !stHz.Available || stHz.Status != StatusDegraded || stHz.Mode != ModeFallbackUserspace || stHz.KernelAttached ||
		stHz.ExcludedProtectedCount != 2 || !strings.Contains(stHz.Error, "CAP_BPF") {
		t.Fatalf("healthz fallback mismatch: %+v", stHz)
	}

	// 9. Oversized response (>64KiB) rejected cleanly
	prefixBig, sockBig := startTestUnixDaemon(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxResponseBodyBytes+100)))
	}))
	bigClient := &UnixClient{statusTimeout: time.Second, syncTimeout: time.Second, testAllowedPrefix: prefixBig}
	stBig := bigClient.ProbeStatus(context.Background(), sockBig)
	if stBig.Available || stBig.Status != StatusUnavailable {
		t.Fatalf("oversized response must be rejected: %+v", stBig)
	}
}

type fakeRepo struct {
	mu          sync.Mutex
	cfg         *Config
	blacklist   []string
	tempBlocks  []string
	protected   []string
	saveCount   int
}

func newFakeRepo() *fakeRepo {
	cfg := DefaultConfig()
	cfg.Version = 1
	cfg.UpdatedAt = time.Date(2026, 11, 26, 13, 50, 0, 0, time.UTC)
	return &fakeRepo{cfg: cfg}
}

func (f *fakeRepo) GetConfig(_ context.Context) (*Config, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *f.cfg
	cp.Interfaces = nonNilStrings(f.cfg.Interfaces)
	return &cp, nil
}

func (f *fakeRepo) SaveConfig(_ context.Context, cfg *Config, _ uuid.UUID) (*Config, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *cfg
	cp.Interfaces = nonNilStrings(cfg.Interfaces)
	cp.Version = f.cfg.Version + 1
	cp.UpdatedAt = time.Now().UTC()
	f.cfg = &cp
	f.saveCount++
	out := cp
	out.Interfaces = nonNilStrings(cp.Interfaces)
	return &out, nil
}

func (f *fakeRepo) LoadGlobalBlockSources(_ context.Context) ([]string, []string, []string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return nonNilStrings(f.blacklist), nonNilStrings(f.tempBlocks), nonNilStrings(f.protected), nil
}

type spyAudit struct {
	mu      sync.Mutex
	records []audits.RecordInput
}

func (s *spyAudit) Record(_ context.Context, in audits.RecordInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, in)
	return nil
}

func (s *spyAudit) snapshot() []audits.RecordInput {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]audits.RecordInput, len(s.records))
	copy(out, s.records)
	return out
}

func reqWithPerms(method, target, body string, perms ...string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, bytes.NewBufferString(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	pset := make(map[string]bool, len(perms))
	for _, p := range perms {
		pset[p] = true
	}
	pr := &authz.Principal{
		UserID:      uuid.New(),
		Username:    "opsadmin",
		Permissions: perms,
		PermsSet:    pset,
	}
	return r.WithContext(authz.WithPrincipal(r.Context(), pr))
}

func TestHandlerLifecycleFailOpenAndRBAC(t *testing.T) {
	// Start a real local Unix-socket fake xdpguard daemon
	var (
		mu       sync.Mutex
		received []SyncRequest
	)
	prefix, sock := startTestUnixDaemon(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/stats":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":                   "ok",
				"mode":                     "xdp_generic",
				"kernel_attached":          true,
				"attach_mode_requested":    "auto",
				"interfaces":               []map[string]interface{}{{"name": "eth0", "attached": true, "mode": "xdp_generic", "error": ""}},
				"dropped_v4_packets":       42,
				"dropped_v6_packets":       3,
				"passed_packets":           1000,
				"synced_v4_cidrs":          2,
				"synced_v6_cidrs":          0,
				"excluded_protected_count": 0,
				"last_sync_at":             "2026-11-26T14:10:00Z",
				"error":                    "",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sync":
			var req SyncRequest
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			mu.Lock()
			received = append(received, req)
			mu.Unlock()
			if !req.Enabled {
				_ = json.NewEncoder(w).Encode(SyncResponse{
					Synced:             true,
					Mode:               ModeFallbackUserspace,
					KernelAttached:     false,
					AttachedInterfaces: []string{},
					LastSyncAt:         "2026-11-26T14:11:00Z",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(SyncResponse{
				Synced:                 true,
				Mode:                   ModeXDPGeneric,
				KernelAttached:         true,
				AttachedInterfaces:     req.Interfaces,
				SyncedV4CIDRs:          len(req.BlockedCIDRs),
				SyncedV6CIDRs:          0,
				ExcludedProtectedCount: 0,
				LastSyncAt:             "2026-11-26T14:10:00Z",
			})
		default:
			http.NotFound(w, r)
		}
	}))

	repo := newFakeRepo()
	repo.blacklist = []string{"203.0.113.10", "10.0.0.0/8"} // 10.0.0.0/8 overlaps protected 10.0.0.1
	repo.tempBlocks = []string{"198.51.100.7", "127.0.0.1"}  // 127.0.0.1 is loopback
	repo.protected = []string{"10.0.0.1"}

	auditSpy := &spyAudit{}
	testClient := &UnixClient{statusTimeout: time.Second, syncTimeout: time.Second, testAllowedPrefix: prefix}
	syncer := NewSyncer(repo, testClient)
	h := NewHandler(repo, testClient, syncer, nil)
	h.audits = auditSpy

	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/xdp-acceleration/config", middleware.RequirePermission("xdp_accel.read")(http.HandlerFunc(h.GetConfig)))
	mux.Handle("PUT /api/v1/xdp-acceleration/config", middleware.RequirePermission("xdp_accel.manage")(http.HandlerFunc(h.PutConfig)))
	mux.Handle("GET /api/v1/xdp-acceleration/status", middleware.RequirePermission("xdp_accel.read")(http.HandlerFunc(h.GetStatus)))
	mux.Handle("POST /api/v1/xdp-acceleration/sync", middleware.RequirePermission("xdp_accel.manage")(http.HandlerFunc(h.PostSync)))

	// 1. RBAC: read-only user can GET config/status, denied 403 on PUT/POST
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, reqWithPerms(http.MethodGet, "/api/v1/xdp-acceleration/config", "", "xdp_accel.read"))
	if rec.Code != http.StatusOK {
		t.Fatalf("read-only GET config = %d: %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, reqWithPerms(http.MethodPut, "/api/v1/xdp-acceleration/config", `{}`, "xdp_accel.read"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("read-only PUT config must be 403, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, reqWithPerms(http.MethodPost, "/api/v1/xdp-acceleration/sync", "", "xdp_accel.read"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("read-only POST sync must be 403, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, reqWithPerms(http.MethodGet, "/api/v1/xdp-acceleration/status", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no-perm GET status must be 403, got %d", rec.Code)
	}

	// 2. PUT invalid NIC (lo / docker0) -> 400
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, reqWithPerms(http.MethodPut, "/api/v1/xdp-acceleration/config",
		`{"enabled":true,"socket_path":"`+sock+`","interfaces":["lo"],"attach_mode":"auto","sync_interval_seconds":5}`,
		"xdp_accel.manage"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with lo must return 400, got %d: %s", rec.Code, rec.Body.String())
	}

	// 3. PUT valid config with live daemon -> 200 + sync_result + control_plane_excluded_count == 2 + HIGH audit
	putLive := `{"enabled":true,"socket_path":"` + sock + `","interfaces":["eth0"],"attach_mode":"auto","sync_interval_seconds":10,"reason":"启用核心业务网口 XDP 丢包"}`
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, reqWithPerms(http.MethodPut, "/api/v1/xdp-acceleration/config", putLive, "xdp_accel.manage"))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT live config = %d: %s", rec.Code, rec.Body.String())
	}
	var envPut struct {
		Data UpdateConfigResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envPut); err != nil {
		t.Fatalf("unmarshal PUT live: %v", err)
	}
	if envPut.Data.Config == nil || !envPut.Data.Config.Enabled || envPut.Data.Config.Version != 2 {
		t.Fatalf("unexpected saved config: %+v", envPut.Data.Config)
	}
	if envPut.Data.SyncResult == nil || !envPut.Data.SyncResult.Synced || !envPut.Data.SyncResult.KernelAttached ||
		envPut.Data.SyncResult.ControlPlaneExcludedCount != 2 || envPut.Data.SyncResult.SyncedV4CIDRs != 2 || envPut.Data.SyncWarning != "" {
		t.Fatalf("unexpected sync_result: %+v warning=%q", envPut.Data.SyncResult, envPut.Data.SyncWarning)
	}
	// Verify protected/loopback CIDRs were stripped BEFORE hitting daemon
	mu.Lock()
	if len(received) != 1 {
		t.Fatalf("expected 1 daemon sync, got %d", len(received))
	}
	wantBlocked := []string{"198.51.100.7/32", "203.0.113.10/32"}
	if !reflect.DeepEqual(received[0].BlockedCIDRs, wantBlocked) {
		t.Fatalf("daemon received blocked_cidrs=%v, want %v", received[0].BlockedCIDRs, wantBlocked)
	}
	if !reflect.DeepEqual(received[0].ProtectedCIDRs, []string{"10.0.0.1/32"}) {
		t.Fatalf("daemon received protected_cidrs=%v, want [10.0.0.1/32]", received[0].ProtectedCIDRs)
	}
	mu.Unlock()

	// 4. GET status with live daemon -> 200 available=true
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, reqWithPerms(http.MethodGet, "/api/v1/xdp-acceleration/status", "", "xdp_accel.read"))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d: %s", rec.Code, rec.Body.String())
	}
	var envSt struct {
		Data Status `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envSt); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if !envSt.Data.Available || !envSt.Data.KernelAttached || envSt.Data.DroppedV4Packets != 42 {
		t.Fatalf("unexpected status: %+v", envSt.Data)
	}

	// 5. POST /sync with live daemon -> 200 + SYNC audit
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, reqWithPerms(http.MethodPost, "/api/v1/xdp-acceleration/sync", "", "xdp_accel.manage"))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST sync = %d: %s", rec.Code, rec.Body.String())
	}
	var envSync struct {
		Data SyncResult `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envSync); err != nil {
		t.Fatalf("unmarshal sync: %v", err)
	}
	if !envSync.Data.Synced || envSync.Data.ControlPlaneExcludedCount != 2 {
		t.Fatalf("unexpected POST sync result: %+v", envSync.Data)
	}

	// 6. PUT disabled (enabled=false) -> sends enabled:false & empty blocked_cidrs to detach cleanly
	putDisable := `{"enabled":false,"socket_path":"` + sock + `","interfaces":["eth0"],"attach_mode":"auto","sync_interval_seconds":5}`
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, reqWithPerms(http.MethodPut, "/api/v1/xdp-acceleration/config", putDisable, "xdp_accel.manage"))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT disable = %d: %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	last := received[len(received)-1]
	mu.Unlock()
	if last.Enabled || len(last.BlockedCIDRs) != 0 {
		t.Fatalf("disable sync must send enabled=false & empty blocked_cidrs, got %+v", last)
	}

	// 7. Fail-open when daemon socket absent: PUT still saves (200 + sync_warning), POST /sync returns 503
	absentSock := "/var/run/caddy/sidecars/absent-xdpguard-test.sock"
	putOffline := `{"enabled":true,"socket_path":"` + absentSock + `","interfaces":["eth0"],"attach_mode":"auto","sync_interval_seconds":5}`
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, reqWithPerms(http.MethodPut, "/api/v1/xdp-acceleration/config", putOffline, "xdp_accel.manage"))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT fail-open when daemon absent must still return 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var envOfflinePut struct {
		Data UpdateConfigResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envOfflinePut); err != nil {
		t.Fatalf("unmarshal offline PUT: %v", err)
	}
	if envOfflinePut.Data.Config == nil || envOfflinePut.Data.Config.SocketPath != absentSock ||
		envOfflinePut.Data.SyncResult != nil || envOfflinePut.Data.SyncWarning == "" {
		t.Fatalf("offline PUT must save config with sync_warning: %+v", envOfflinePut.Data)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, reqWithPerms(http.MethodPost, "/api/v1/xdp-acceleration/sync", "", "xdp_accel.manage"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST sync when daemon absent must return 503, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify audit trail captured UPDATE + SYNC records with frozen module/object_type/action
	recs := auditSpy.snapshot()
	if len(recs) != 5 {
		t.Fatalf("expected 5 audit records (3 UPDATE + 2 SYNC), got %d: %+v", len(recs), recs)
	}
	if recs[0].Module != "xdp_acceleration" || recs[0].ObjectType != "xdp_acceleration_config" ||
		recs[0].Action != "UPDATE" || recs[0].RiskLevel != audits.RiskHigh {
		t.Fatalf("first audit mismatch: %+v", recs[0])
	}
	if recs[1].Action != "SYNC" || recs[1].Result != audits.ResultSuccess {
		t.Fatalf("second audit mismatch: %+v", recs[1])
	}
	if recs[2].Action != "UPDATE" || recs[2].RiskLevel != audits.RiskMedium {
		t.Fatalf("disable audit should be MEDIUM risk: %+v", recs[2])
	}
	if recs[4].Action != "SYNC" || recs[4].Result != audits.ResultFailure || recs[4].FailureReason == "" {
		t.Fatalf("failed sync audit mismatch: %+v", recs[4])
	}
}

func TestSyncerStartLoopGracefulCancel(t *testing.T) {
	repo := newFakeRepo()
	repo.cfg.Enabled = true
	repo.cfg.SyncIntervalSeconds = 1
	repo.cfg.SocketPath = "/var/run/caddy/sidecars/nonexistent-loop-test.sock"

	syncer := NewSyncer(repo, NewUnixClient(200*time.Millisecond, 200*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		syncer.StartLoop(ctx)
	}()
	// Cancel shortly after start and verify loop exits cleanly without blocking.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartLoop did not exit cleanly after context cancellation")
	}
}
