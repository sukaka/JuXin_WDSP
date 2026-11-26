package xdpguard

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func unixHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

type mockAttachedBackend struct {
	syncResp    SyncResponse
	syncErr     error
	statsResp   StatsResponse
	healthzResp HealthzResponse
	lastReq     SyncRequest
}

func (m *mockAttachedBackend) Sync(_ context.Context, req SyncRequest) (SyncResponse, error) {
	m.lastReq = req
	if m.syncErr != nil {
		return SyncResponse{}, m.syncErr
	}
	return m.syncResp, nil
}
func (m *mockAttachedBackend) Stats(_ context.Context) StatsResponse     { return m.statsResp }
func (m *mockAttachedBackend) Healthz(_ context.Context) HealthzResponse { return m.healthzResp }
func (m *mockAttachedBackend) Close() error                              { return nil }

func shortTempSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "xdp-*")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestServerUnixSocketLifecycleAndContracts(t *testing.T) {
	tmpDir := shortTempSocketDir(t)
	sockPath := filepath.Join(tmpDir, "xdp.sock")

	// Pre-create a stale Unix socket to verify Listen cleans it up safely.
	staleLn, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("create stale socket: %v", err)
	}
	_ = staleLn.Close()
	// On macOS/Linux net.UnixListener.Close unlinks automatically unless SetUnlinkOnClose(false).
	if ul, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"}); err == nil {
		ul.SetUnlinkOnClose(false)
		_ = ul.Close()
	}

	fixedNow := func() time.Time { return time.Date(2026, 11, 26, 14, 0, 0, 0, time.UTC) }
	backend, err := NewBackend(BackendOptions{
		DefaultAttachMode:  AttachModeAuto,
		ExcludedInterfaces: []string{"eno1"},
		HostAddrsProvider:  fakeHostAddrs("192.168.100.5/24"),
		Now:                fixedNow,
	})
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}
	defer backend.Close()

	srv, err := NewServer(sockPath, backend)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve() }()

	// Verify 0660 permissions on Unix socket.
	fi, err := os.Lstat(sockPath)
	if err != nil {
		t.Fatalf("Lstat socket failed: %v", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected Unix socket, got mode %v", fi.Mode())
	}
	if perm := fi.Mode().Perm(); perm != 0o660 {
		t.Fatalf("socket permissions = %#o, want 0660", perm)
	}

	client := unixHTTPClient(sockPath)

	// 1. Initial GET /healthz (idle disabled state).
	resp, err := client.Get("http://unix/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz status=%d body=%s", resp.StatusCode, string(body))
	}
	if strings.Contains(string(body), `"attached_interfaces":null`) {
		t.Fatalf("attached_interfaces must serialize as [], not null: %s", string(body))
	}
	var hz HealthzResponse
	if err := json.Unmarshal(body, &hz); err != nil {
		t.Fatalf("unmarshal healthz: %v", err)
	}
	if hz.Status != StatusOK || hz.Mode != ModeFallbackUserspace || hz.KernelAttached {
		t.Fatalf("unexpected initial healthz: %+v", hz)
	}

	// 2. POST /v1/sync with unknown field -> 400.
	badUnknown := `{"schema_version":1,"enabled":false,"attach_mode":"auto","interfaces":[],"blocked_cidrs":[],"protected_cidrs":[],"extra":true}`
	resp, err = client.Post("http://unix/v1/sync", "application/json", strings.NewReader(badUnknown))
	if err != nil {
		t.Fatalf("POST unknown field failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown field, got %d", resp.StatusCode)
	}

	// 3. POST /v1/sync with forbidden NIC ("lo" / "docker0" / operator-excluded "eno1") -> 400.
	for _, badNIC := range []string{"lo", "docker0", "veth123", "eno1"} {
		payload := SyncRequest{
			SchemaVersion:  1,
			Enabled:        true,
			AttachMode:     "auto",
			Interfaces:     []string{badNIC},
			BlockedCIDRs:   []string{"203.0.113.5/32"},
			ProtectedCIDRs: []string{},
		}
		raw, _ := json.Marshal(payload)
		resp, err = client.Post("http://unix/v1/sync", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("POST bad NIC %s failed: %v", badNIC, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for forbidden NIC %q, got %d", badNIC, resp.StatusCode)
		}
	}

	// 4. POST /v1/sync exceeding 2 MiB (valid JSON structure) -> 413.
	oversized := append(append([]byte(`{"schema_version":1,"enabled":false,"attach_mode":"auto","interfaces":[],"blocked_cidrs":["`), bytes.Repeat([]byte("1"), MaxSyncBodyBytes+64)...), []byte(`"],"protected_cidrs":[]}`)...)
	resp, err = client.Post("http://unix/v1/sync", "application/json", bytes.NewReader(oversized))
	if err != nil {
		t.Fatalf("POST oversized failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for >2MiB payload, got %d", resp.StatusCode)
	}

	// 5. POST /v1/sync valid enabled=true -> honest fail-open fallback on non-Linux / unprivileged host,
	//    with full protected exclusion & invalid CIDR accounting.
	syncReq := SyncRequest{
		SchemaVersion:  1,
		Enabled:        true,
		AttachMode:     AttachModeAuto,
		Interfaces:     []string{"eth0"},
		BlockedCIDRs:   []string{"203.0.113.5", "127.0.0.1", "10.0.0.0/8", "192.168.100.0/24", "bad-cidr"},
		ProtectedCIDRs: []string{"10.0.0.1/32"},
	}
	raw, _ := json.Marshal(syncReq)
	resp, err = client.Post("http://unix/v1/sync", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST /v1/sync failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/sync status=%d body=%s", resp.StatusCode, string(body))
	}
	var sr SyncResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		t.Fatalf("unmarshal sync response: %v", err)
	}
	if sr.KernelAttached || sr.Mode != ModeFallbackUserspace || sr.Synced {
		t.Fatalf("expected honest fail-open fallback response, got %+v", sr)
	}
	// Excluded: 127.0.0.1 (loopback) + 10.0.0.0/8 (overlaps protected 10.0.0.1) + 192.168.100.0/24 (overlaps host 192.168.100.5) = 3.
	if sr.ExcludedProtectedCount != 3 || sr.InvalidCIDRsSkipped != 1 {
		t.Fatalf("unexpected filter counters: excluded=%d invalid=%d", sr.ExcludedProtectedCount, sr.InvalidCIDRsSkipped)
	}
	if sr.LastSyncAt != "2026-11-26T14:00:00Z" || sr.Error == "" {
		t.Fatalf("unexpected timestamp/error: %+v", sr)
	}

	// 6. GET /v1/stats reflects degraded fallback_userspace with per-interface diagnostic.
	resp, err = client.Get("http://unix/v1/stats")
	if err != nil {
		t.Fatalf("GET /v1/stats failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	var st StatsResponse
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("unmarshal stats: %v", err)
	}
	if st.Status != StatusDegraded || st.Mode != ModeFallbackUserspace || st.KernelAttached || st.AttachModeRequested != AttachModeAuto {
		t.Fatalf("unexpected stats: %+v", st)
	}
	if len(st.Interfaces) != 1 || st.Interfaces[0].Name != "eth0" || st.Interfaces[0].Attached || st.Interfaces[0].Error == "" {
		t.Fatalf("unexpected interface stats: %+v", st.Interfaces)
	}

	// 7. POST /v1/sync enabled=false -> cleanly detaches and returns ok/synced=true.
	disableReq := SyncRequest{
		SchemaVersion:  1,
		Enabled:        false,
		AttachMode:     AttachModeAuto,
		Interfaces:     []string{},
		BlockedCIDRs:   []string{},
		ProtectedCIDRs: []string{},
	}
	raw, _ = json.Marshal(disableReq)
	resp, err = client.Post("http://unix/v1/sync", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST disable sync failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	var disableResp SyncResponse
	if err := json.Unmarshal(body, &disableResp); err != nil {
		t.Fatalf("unmarshal disable sync: %v", err)
	}
	if !disableResp.Synced || disableResp.KernelAttached || disableResp.Error != "" {
		t.Fatalf("unexpected disable response: %+v", disableResp)
	}

	// 8. Method/path enforcement.
	resp, err = client.Post("http://unix/healthz", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /healthz failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST /healthz, got %d", resp.StatusCode)
	}
	resp, err = client.Get("http://unix/unknown")
	if err != nil {
		t.Fatalf("GET /unknown failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for GET /unknown, got %d", resp.StatusCode)
	}

	// 9. Graceful shutdown removes Unix socket file.
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}
	if _, err := os.Lstat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("expected Unix socket to be removed after shutdown, stat err=%v", err)
	}
}

func TestServerRefusesSymlinkAndRegularFileAndAllowsAttachedMock(t *testing.T) {
	tmpDir := shortTempSocketDir(t)
	mock := &mockAttachedBackend{
		healthzResp: HealthzResponse{
			Status:             StatusOK,
			Mode:               ModeXDPNative,
			KernelAttached:     true,
			AttachedInterfaces: []string{"ens192"},
			DroppedV4Packets:   4200,
			DroppedV6Packets:   150,
			SyncedV4CIDRs:      12,
			SyncedV6CIDRs:      3,
			LastSyncAt:         "2026-11-26T14:00:00Z",
		},
		statsResp: StatsResponse{
			Status:              StatusOK,
			Mode:                ModeXDPNative,
			KernelAttached:      true,
			AttachModeRequested: AttachModeAuto,
			Interfaces: []InterfaceStatus{
				{Name: "ens192", Attached: true, Mode: ModeXDPNative},
			},
			DroppedV4Packets: 4200,
			DroppedV6Packets: 150,
			PassedPackets:    99000,
			SyncedV4CIDRs:    12,
			SyncedV6CIDRs:    3,
			LastSyncAt:       "2026-11-26T14:00:00Z",
		},
	}

	// Regular file refusal.
	regFile := filepath.Join(tmpDir, "regular.sock")
	if err := os.WriteFile(regFile, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}
	sReg, err := NewServer(regFile, mock)
	if err != nil {
		t.Fatalf("NewServer regular: %v", err)
	}
	if err := sReg.Listen(); err == nil {
		t.Fatal("expected Listen to refuse overwriting a regular file")
	}

	// Symlink refusal.
	symPath := filepath.Join(tmpDir, "link.sock")
	if err := os.Symlink(regFile, symPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	sSym, err := NewServer(symPath, mock)
	if err != nil {
		t.Fatalf("NewServer symlink: %v", err)
	}
	if err := sSym.Listen(); err == nil {
		t.Fatal("expected Listen to refuse symlink path")
	}

	// Bad socket paths rejected by NewServer.
	for _, badPath := range []string{"", "relative.sock", "/tmp/../etc/a.sock", "/var/run/a/", "tcp://127.0.0.1:9000"} {
		if _, err := NewServer(badPath, mock); err == nil {
			t.Fatalf("expected NewServer to reject socket path %q", badPath)
		}
	}

	// Verify attached mock responses over Unix socket.
	sockPath := filepath.Join(tmpDir, "attached.sock")
	s, err := NewServer(sockPath, mock)
	if err != nil {
		t.Fatalf("NewServer attached: %v", err)
	}
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen attached: %v", err)
	}
	go func() { _ = s.Serve() }()
	defer s.Shutdown(context.Background())

	client := unixHTTPClient(sockPath)
	resp, err := client.Get("http://unix/v1/stats")
	if err != nil {
		t.Fatalf("GET /v1/stats attached failed: %v", err)
	}
	defer resp.Body.Close()
	var st StatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatalf("decode attached stats: %v", err)
	}
	if !st.KernelAttached || st.Mode != ModeXDPNative || st.DroppedV4Packets != 4200 || st.PassedPackets != 99000 {
		t.Fatalf("unexpected attached stats: %+v", st)
	}
}
