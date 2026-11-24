package hasyncd

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type testEnv struct {
	t           *testing.T
	tmpDir      string
	sidecarDir  string
	hostctlDir  string
	upgradesDir string
	ifacesLog   string
	caddySock   string
	caddyMu     sync.Mutex
	caddyConfig string
	caddyStatus int
	caddyErrMsg string
	secret      []byte
	now         time.Time
	srv         *Server
	ts          *httptest.Server
	caddySrv    *http.Server
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	// Use short temp dir on macOS/Linux so Unix socket path stays under 104 bytes.
	tmpDir, err := os.MkdirTemp("", "hasyncd-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	sidecarDir := filepath.Join(tmpDir, "sidecars")
	hostctlDir := filepath.Join(tmpDir, "hostctl")
	upgradesDir := filepath.Join(tmpDir, "upgrades")
	ifacesLog := filepath.Join(tmpDir, "node-interfaces.jsonl")
	caddySock := filepath.Join(tmpDir, "caddy.sock")
	secretFile := filepath.Join(tmpDir, "hasync.secret")

	for _, d := range []string{sidecarDir, hostctlDir, upgradesDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(secretFile, []byte(testSharedSecretHex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret, err := ParseSecretHex(testSharedSecretHex)
	if err != nil {
		t.Fatal(err)
	}

	env := &testEnv{
		t:           t,
		tmpDir:      tmpDir,
		sidecarDir:  sidecarDir,
		hostctlDir:  hostctlDir,
		upgradesDir: upgradesDir,
		ifacesLog:   ifacesLog,
		caddySock:   caddySock,
		caddyConfig: `{"admin":{"listen":"unix//var/run/caddy/admin.sock"},"apps":{"http":{"servers":{"s0":{"routes":[{"handle":[{"handler":"jiuzhang_guard","api_policy_version":"pol-v42"}]}]}}}}}`,
		caddyStatus: http.StatusOK,
		secret:      secret,
		now:         time.Unix(1764000000, 0).UTC(),
	}

	ln, err := net.Listen("unix", caddySock)
	if err != nil {
		t.Fatalf("listen mock caddy unix sock: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/config/", func(w http.ResponseWriter, r *http.Request) {
		env.caddyMu.Lock()
		cfg := env.caddyConfig
		env.caddyMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, cfg)
	})
	mux.HandleFunc("/load", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		env.caddyMu.Lock()
		status := env.caddyStatus
		errMsg := env.caddyErrMsg
		if status == http.StatusOK {
			env.caddyConfig = string(body)
		}
		env.caddyMu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, errMsg)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	env.caddySrv = &http.Server{Handler: mux}
	go func() { _ = env.caddySrv.Serve(ln) }()
	t.Cleanup(func() { _ = env.caddySrv.Close() })

	srv, err := NewServer(Config{
		NodeName:        "gw-b",
		SecretFile:      secretFile,
		CaddySocket:     caddySock,
		SidecarDir:      sidecarDir,
		HostctlDir:      hostctlDir,
		UpgradesDir:     upgradesDir,
		NodeIfacesLog:   ifacesLog,
		Version:         "1.12.0",
		MaxPackageBytes: 4096,
		NowFunc:         func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	env.srv = srv
	env.ts = httptest.NewServer(srv.Handler())
	t.Cleanup(env.ts.Close)
	return env
}

func (e *testEnv) signedDo(method, path string, body []byte, extraHeaders map[string]string) *http.Response {
	e.t.Helper()
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, e.ts.URL+path, bodyReader)
	if err != nil {
		e.t.Fatal(err)
	}
	var nonceRaw [16]byte
	_, _ = rand.Read(nonceRaw[:])
	nonce := hex.EncodeToString(nonceRaw[:])
	tsStr := strconv.FormatInt(e.now.Unix(), 10)
	sum := sha256.Sum256(body)
	bodyHex := hex.EncodeToString(sum[:])

	req.Header.Set(HeaderNode, "gw-a")
	req.Header.Set(HeaderTimestamp, tsStr)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderBodySHA256, bodyHex)
	req.Header.Set(HeaderSignature, ComputeSignature(e.secret, method, req.URL.EscapedPath(), tsStr, nonce, bodyHex))
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("do %s %s: %v", method, path, err)
	}
	return resp
}

func TestZeroUnauthenticatedEndpoints(t *testing.T) {
	env := newTestEnv(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/health"},
		{http.MethodGet, "/v1/status"},
		{http.MethodGet, "/v1/caddy/config-hash"},
		{http.MethodPost, "/v1/caddy/load"},
		{http.MethodPut, "/v1/sidecars/ha-vip.json"},
		{http.MethodDelete, "/v1/sidecars/ha-vip.json"},
		{http.MethodPost, "/v1/firewall/ensure"},
		{http.MethodPost, "/v1/upgrades/packages"},
		{http.MethodPost, "/v1/upgrades/execute"},
		{http.MethodGet, "/v1/upgrades/jobs/11111111-1111-4111-8111-111111111111"},
		{http.MethodGet, "/healthz"},
	} {
		req, _ := http.NewRequest(tc.method, env.ts.URL+tc.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s %s without auth: got %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
	}
}

func TestHealthAndStatusEndpoints(t *testing.T) {
	env := newTestEnv(t)

	// Prepare status files and interfaces log.
	haVipJSON := `{"group":"ha-main","node":"gw-b","state":"BACKUP","keepalived_running":true}`
	netJSON := `{"ok":true,"node":"gw-b","link_pairs":[]}`
	if err := os.WriteFile(filepath.Join(env.sidecarDir, "ha-vip-status.json"), []byte(haVipJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.sidecarDir, "network-status.json"), []byte(netJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	ifacesContent := strings.Join([]string{
		`{"node_name":"gw-b","ifname":"eth1","mac":"00:11:22:33:44:55","ip_addresses":["10.0.0.2/24"],"media_type":"TP","link_speed":1000,"operstate":"down","collected_at":"2026-11-24T10:00:00Z"}`,
		`{corrupt json line`,
		`{"node_name":"gw-b","ifname":"eth0","mac":"00:11:22:33:44:00","ip_addresses":["192.168.1.2/24"],"media_type":"TP","link_speed":10000,"operstate":"up","collected_at":"2026-11-24T10:01:00Z"}`,
		`{"node_name":"gw-b","ifname":"eth1","mac":"00:11:22:33:44:55","ip_addresses":["10.0.0.2/24"],"media_type":"TP","link_speed":1000,"operstate":"up","collected_at":"2026-11-24T10:01:00Z"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(env.ifacesLog, []byte(ifacesContent), 0o640); err != nil {
		t.Fatal(err)
	}

	// GET /v1/health
	resp := env.signedDo(http.MethodGet, "/v1/health", nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status=%d", resp.StatusCode)
	}
	var health HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if health.Node != "gw-b" || health.Version != "1.12.0" || !health.CaddyReachable || !health.HostctlReady || !health.UpgradeReady {
		t.Fatalf("unexpected health response: %+v", health)
	}

	// GET /v1/status
	sResp := env.signedDo(http.MethodGet, "/v1/status", nil, nil)
	defer sResp.Body.Close()
	if sResp.StatusCode != http.StatusOK {
		t.Fatalf("status http=%d", sResp.StatusCode)
	}
	var st StatusResponse
	if err := json.NewDecoder(sResp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Node != "gw-b" || st.PolicyVersion != "pol-v42" || !st.CaddyReachable || len(st.ConfigHash) != 64 {
		t.Fatalf("unexpected status response: %+v", st)
	}
	if len(st.HaVipStatus) == 0 || st.HaVipStatusMtime == nil {
		t.Fatalf("expected ha_vip_status and mtime")
	}
	if len(st.NetworkStatus) == 0 || st.NetworkStatusMtime == nil {
		t.Fatalf("expected network_status and mtime")
	}
	if len(st.Interfaces) != 2 || st.Interfaces[0].IfName != "eth0" || st.Interfaces[1].IfName != "eth1" || st.Interfaces[1].OperState != "up" {
		t.Fatalf("expected deduplicated latest interfaces [eth0, eth1(up)], got %+v", st.Interfaces)
	}
}

func TestCaddyLoadAndCanonicalHash(t *testing.T) {
	env := newTestEnv(t)

	// Different admin.listen values must yield the exact same CanonicalBusinessConfigHash.
	cfgA := `{"admin":{"listen":"unix//var/run/caddy/admin.sock"},"apps":{"http":{"servers":{"s0":{"listen":[":80"],"routes":[{"handle":[{"handler":"jiuzhang_guard","api_policy_version":"pol-v99"}]}]}}}}}`
	cfgB := `{"admin":{"listen":"10.0.0.2:2019"},"apps":{"http":{"servers":{"s0":{"routes":[{"handle":[{"api_policy_version":"pol-v99","handler":"jiuzhang_guard"}]}],"listen":[":80"]}}}}}`

	hashA, err := CanonicalBusinessConfigHash([]byte(cfgA))
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := CanonicalBusinessConfigHash([]byte(cfgB))
	if err != nil {
		t.Fatal(err)
	}
	if hashA != hashB {
		t.Fatalf("business config hash should ignore admin and key order: %s vs %s", hashA, hashB)
	}

	// POST /v1/caddy/load succeeds.
	resp := env.signedDo(http.MethodPost, "/v1/caddy/load", []byte(cfgB), map[string]string{"Content-Type": "application/json"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("caddy load status=%d body=%s", resp.StatusCode, string(b))
	}

	// GET /v1/caddy/config-hash matches hashA and pol-v99.
	hResp := env.signedDo(http.MethodGet, "/v1/caddy/config-hash", nil, nil)
	defer hResp.Body.Close()
	if hResp.StatusCode != http.StatusOK {
		t.Fatalf("config-hash status=%d", hResp.StatusCode)
	}
	var ch CaddyConfigHashResponse
	if err := json.NewDecoder(hResp.Body).Decode(&ch); err != nil {
		t.Fatal(err)
	}
	if ch.ConfigHash != hashA || ch.PolicyVersion != "pol-v99" {
		t.Fatalf("unexpected config hash resp: %+v want hash=%s", ch, hashA)
	}

	// Caddy error response must redact private keys.
	env.caddyMu.Lock()
	env.caddyStatus = http.StatusBadRequest
	env.caddyErrMsg = "load failed: -----BEGIN PRIVATE KEY-----\nSECRET_KEY_BYTES\n-----END PRIVATE KEY-----"
	env.caddyMu.Unlock()
	errResp := env.signedDo(http.MethodPost, "/v1/caddy/load", []byte(cfgA), nil)
	defer errResp.Body.Close()
	if errResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 from caddy error, got %d", errResp.StatusCode)
	}
	var loadErr CaddyLoadResponse
	if err := json.NewDecoder(errResp.Body).Decode(&loadErr); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(loadErr.Error, "SECRET_KEY_BYTES") || !strings.Contains(loadErr.Error, "[REDACTED_PRIVATE_KEY]") {
		t.Fatalf("private key not redacted in caddy error: %q", loadErr.Error)
	}

	// Invalid JSON rejected before calling Caddy.
	env.caddyMu.Lock()
	env.caddyStatus = http.StatusOK
	env.caddyMu.Unlock()
	badResp := env.signedDo(http.MethodPost, "/v1/caddy/load", []byte(`not-json`), nil)
	_ = badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid json, got %d", badResp.StatusCode)
	}
}

func TestSidecarAllowlistPermissionsAndDelete(t *testing.T) {
	env := newTestEnv(t)

	// Disallowed filenames must be rejected.
	for _, bad := range []string{"ha-vip-status.json", "network-status.json", "evil.json", "../escape.json"} {
		resp := env.signedDo(http.MethodPut, "/v1/sidecars/"+bad, []byte(`{"a":1}`), nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("PUT %s: got %d, want 400", bad, resp.StatusCode)
		}
	}

	// Invalid JSON / JSON array rejected.
	for _, payload := range []string{`not-json`, `[1,2,3]`, `null`} {
		resp := env.signedDo(http.MethodPut, "/v1/sidecars/network.json", []byte(payload), nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("PUT invalid payload %q: got %d, want 400", payload, resp.StatusCode)
		}
	}

	// All 4 allowlisted files succeed with exact permissions.
	for name, wantMode := range map[string]os.FileMode{
		"ha-vip.json":    0o640,
		"network.json":   0o644,
		"tproxyd.json":   0o644,
		"mirrorcap.json": 0o644,
	} {
		payload := []byte(`{"file":"` + name + `","ok":true}`)
		resp := env.signedDo(http.MethodPut, "/v1/sidecars/"+name, payload, nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT %s: status=%d", name, resp.StatusCode)
		}
		fi, err := os.Stat(filepath.Join(env.sidecarDir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if fi.Mode().Perm() != wantMode {
			t.Fatalf("%s mode=%04o want %04o", name, fi.Mode().Perm(), wantMode)
		}
	}

	// DELETE removes file and second DELETE is idempotent.
	del1 := env.signedDo(http.MethodDelete, "/v1/sidecars/ha-vip.json", nil, nil)
	var d1 SidecarDeleteResponse
	_ = json.NewDecoder(del1.Body).Decode(&d1)
	_ = del1.Body.Close()
	if del1.StatusCode != http.StatusOK || !d1.Deleted {
		t.Fatalf("first delete: status=%d resp=%+v", del1.StatusCode, d1)
	}
	del2 := env.signedDo(http.MethodDelete, "/v1/sidecars/ha-vip.json", nil, nil)
	var d2 SidecarDeleteResponse
	_ = json.NewDecoder(del2.Body).Decode(&d2)
	_ = del2.Body.Close()
	if del2.StatusCode != http.StatusOK || d2.Deleted {
		t.Fatalf("second idempotent delete: status=%d resp=%+v", del2.StatusCode, d2)
	}
}

func TestFirewallEnsureHostctlV2Compatibility(t *testing.T) {
	env := newTestEnv(t)

	// Pre-populate .hostctl-secret to verify exact v2 signature computation.
	hostctlSecret := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	if err := os.WriteFile(filepath.Join(env.hostctlDir, ".hostctl-secret"), []byte(hostctlSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Invalid requests rejected.
	for _, body := range []string{
		`{"ports":[]}`,
		`{"ports":[0]}`,
		`{"ports":[65536]}`,
		`{"ports":[80],"request_id":"../bad"}`,
		`{"ports":[80],"requested_by":"bad\ninjection"}`,
	} {
		resp := env.signedDo(http.MethodPost, "/v1/firewall/ensure", []byte(body), nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid firewall req %s: got %d, want 400", body, resp.StatusCode)
		}
	}

	// >64 ports rejected.
	manyPorts := make([]int, 65)
	for i := range manyPorts {
		manyPorts[i] = 1000 + i
	}
	manyBody, _ := json.Marshal(FirewallEnsureRequest{Ports: manyPorts, RequestID: "req-many", RequestedBy: "publish"})
	respMany := env.signedDo(http.MethodPost, "/v1/firewall/ensure", manyBody, nil)
	_ = respMany.Body.Close()
	if respMany.StatusCode != http.StatusBadRequest {
		t.Fatalf(">64 ports: got %d, want 400", respMany.StatusCode)
	}

	// Valid request with unsorted duplicates -> sorted unique ports and exact v2 HMAC!
	validBody, _ := json.Marshal(FirewallEnsureRequest{
		Ports:       []int{8443, 80, 443, 80},
		RequestID:   "req-sync-001",
		RequestedBy: "gateway-publish",
		UserID:      "00000000-0000-0000-0000-000000000001",
	})
	resp := env.signedDo(http.MethodPost, "/v1/firewall/ensure", validBody, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("firewall ensure status=%d body=%s", resp.StatusCode, string(b))
	}
	var fwResp FirewallEnsureResponse
	if err := json.NewDecoder(resp.Body).Decode(&fwResp); err != nil {
		t.Fatal(err)
	}
	wantFile := "firewall_ensure-1764000000-req-sync-001.json"
	if fwResp.File != wantFile {
		t.Fatalf("flag filename=%q want %q", fwResp.File, wantFile)
	}

	// Read back flag file and verify EXACT v2 canonical payload & HMAC matching systemops/hostctl-exec.sh.
	rawFlag, err := os.ReadFile(filepath.Join(env.hostctlDir, wantFile))
	if err != nil {
		t.Fatalf("read flag file: %v", err)
	}
	var cmd hostctlCommand
	if err := json.Unmarshal(rawFlag, &cmd); err != nil {
		t.Fatalf("unmarshal flag: %v", err)
	}
	if cmd.Action != "firewall_ensure" || cmd.DelaySeconds != 0 || len(cmd.Ports) != 3 || cmd.Ports[0] != 80 || cmd.Ports[1] != 443 || cmd.Ports[2] != 8443 {
		t.Fatalf("unexpected flag cmd: %+v", cmd)
	}
	wantCanonical := "v2\nfirewall_ensure\ngateway-publish\n00000000-0000-0000-0000-000000000001\nreq-sync-001\n2025-11-24T16:00:00Z\n0\n80,443,8443"
	mac := hmac.New(sha256.New, []byte(hostctlSecret))
	_, _ = mac.Write([]byte(wantCanonical))
	wantHMAC := hex.EncodeToString(mac.Sum(nil))
	if cmd.HMAC != wantHMAC {
		t.Fatalf("hostctl v2 HMAC mismatch:\n got: %s\nwant: %s", cmd.HMAC, wantHMAC)
	}
}

func TestUpgradePackageUploadExecuteAndJobResult(t *testing.T) {
	env := newTestEnv(t)

	// Invalid package filenames rejected.
	for _, bad := range []string{"", "../evil.tar.gz", "a/b.tar.gz", "a..b.tar.gz", ".hidden.tar.gz", "pkg.tar.gz.sig", "script.sh"} {
		resp := env.signedDo(http.MethodPost, "/v1/upgrades/packages", []byte("abc"), map[string]string{
			HeaderPackageFilename: bad,
		})
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("bad filename %q: got %d, want 400", bad, resp.StatusCode)
		}
	}

	// SHA-256 mismatch during streaming upload MUST fail before atomic rename and leave no file behind!
	claimedPayload := []byte("real-upgrade-tarball-content")
	tamperedPayload := []byte("tampered-upgrade-tarball-content")
	claimedSum := sha256.Sum256(claimedPayload)
	claimedHex := hex.EncodeToString(claimedSum[:])
	{
		req, _ := http.NewRequest(http.MethodPost, env.ts.URL+"/v1/upgrades/packages", bytes.NewReader(tamperedPayload))
		tsStr := strconv.FormatInt(env.now.Unix(), 10)
		nonce := "1234567890abcdef1234567890abcdef"
		req.Header.Set(HeaderNode, "gw-a")
		req.Header.Set(HeaderTimestamp, tsStr)
		req.Header.Set(HeaderNonce, nonce)
		req.Header.Set(HeaderBodySHA256, claimedHex)
		req.Header.Set(HeaderSignature, ComputeSignature(env.secret, http.MethodPost, "/v1/upgrades/packages", tsStr, nonce, claimedHex))
		req.Header.Set(HeaderPackageFilename, "jiuzhang-wdsp-update-full-1.13.0-amd64.tar.gz")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("tampered upload: got %d, want 401", resp.StatusCode)
		}
		entries, _ := os.ReadDir(filepath.Join(env.upgradesDir, "packages"))
		if len(entries) != 0 {
			t.Fatalf("tampered upload left files in packages dir: %v", entries)
		}
	}

	// Oversized upload (>4096 configured in testEnv) fails with 413 and cleans temp file.
	bigBody := bytes.Repeat([]byte("A"), 5000)
	respBig := env.signedDo(http.MethodPost, "/v1/upgrades/packages", bigBody, map[string]string{
		HeaderPackageFilename: "jiuzhang-wdsp-update-full-1.13.0-amd64.tar.gz",
	})
	_ = respBig.Body.Close()
	if respBig.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload: got %d, want 413", respBig.StatusCode)
	}
	if entries, _ := os.ReadDir(filepath.Join(env.upgradesDir, "packages")); len(entries) != 0 {
		t.Fatalf("oversized upload left temp files: %v", entries)
	}

	// Valid upload succeeds and sets mode 0640.
	pkgName := "jiuzhang-wdsp-update-full-1.13.0-amd64.tar.gz"
	respUp := env.signedDo(http.MethodPost, "/v1/upgrades/packages", claimedPayload, map[string]string{
		HeaderPackageFilename: pkgName,
	})
	defer respUp.Body.Close()
	if respUp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(respUp.Body)
		t.Fatalf("valid upload: status=%d body=%s", respUp.StatusCode, string(b))
	}
	var upRes UpgradePackageUploadResponse
	if err := json.NewDecoder(respUp.Body).Decode(&upRes); err != nil {
		t.Fatal(err)
	}
	if !upRes.OK || upRes.Filename != pkgName || upRes.SHA256 != claimedHex || upRes.Size != int64(len(claimedPayload)) {
		t.Fatalf("unexpected upload response: %+v", upRes)
	}
	pkgInfo, err := os.Stat(filepath.Join(env.upgradesDir, "packages", pkgName))
	if err != nil {
		t.Fatal(err)
	}
	if pkgInfo.Mode().Perm() != 0o640 {
		t.Fatalf("package mode=%04o want 0640", pkgInfo.Mode().Perm())
	}

	// Execute with wrong SHA-256 rejected.
	jobID := "11111111-2222-4333-8444-555555555555"
	badExecBody, _ := json.Marshal(UpgradeExecuteRequest{
		JobID:         jobID,
		PackageFile:   pkgName,
		PackageSHA256: strings.Repeat("a", 64),
		VersionFrom:   "1.12.0",
		VersionTo:     "1.13.0",
		RequestedAt:   env.now,
	})
	respBadExec := env.signedDo(http.MethodPost, "/v1/upgrades/execute", badExecBody, nil)
	_ = respBadExec.Body.Close()
	if respBadExec.StatusCode != http.StatusBadRequest {
		t.Fatalf("execute wrong sha: got %d, want 400", respBadExec.StatusCode)
	}

	// Valid execute writes executor/jobs/<job_id>.json with 0640.
	execBody, _ := json.Marshal(UpgradeExecuteRequest{
		JobID:         jobID,
		PackageFile:   pkgName,
		PackageSHA256: claimedHex,
		VersionFrom:   "1.12.0",
		VersionTo:     "1.13.0",
		RequestedAt:   env.now,
	})
	respExec := env.signedDo(http.MethodPost, "/v1/upgrades/execute", execBody, nil)
	_ = respExec.Body.Close()
	if respExec.StatusCode != http.StatusOK {
		t.Fatalf("valid execute: got %d, want 200", respExec.StatusCode)
	}
	jobFile := filepath.Join(env.upgradesDir, "executor", "jobs", jobID+".json")
	jobInfo, err := os.Stat(jobFile)
	if err != nil {
		t.Fatal(err)
	}
	if jobInfo.Mode().Perm() != 0o640 {
		t.Fatalf("job file mode=%04o want 0640", jobInfo.Mode().Perm())
	}

	// GET job result before executor writes result -> {pending: true}.
	respPend := env.signedDo(http.MethodGet, "/v1/upgrades/jobs/"+jobID, nil, nil)
	var pendRes UpgradeJobResult
	_ = json.NewDecoder(respPend.Body).Decode(&pendRes)
	_ = respPend.Body.Close()
	if respPend.StatusCode != http.StatusOK || !pendRes.Pending || pendRes.JobID != jobID {
		t.Fatalf("expected pending result, got status=%d resp=%+v", respPend.StatusCode, pendRes)
	}

	// Write executor result and verify GET returns parsed result.
	resultsDir := filepath.Join(env.upgradesDir, "executor", "results")
	if err := os.MkdirAll(resultsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	resultJSON := `{"job_id":"` + jobID + `","status":"SUCCESS","stage":"VERIFYING","finished_at":"2026-11-24T16:10:00Z"}`
	if err := os.WriteFile(filepath.Join(resultsDir, jobID+".json"), []byte(resultJSON), 0o640); err != nil {
		t.Fatal(err)
	}
	respDone := env.signedDo(http.MethodGet, "/v1/upgrades/jobs/"+jobID, nil, nil)
	var doneRes UpgradeJobResult
	_ = json.NewDecoder(respDone.Body).Decode(&doneRes)
	_ = respDone.Body.Close()
	if respDone.StatusCode != http.StatusOK || doneRes.Pending || doneRes.Status != "SUCCESS" || doneRes.Stage != "VERIFYING" {
		t.Fatalf("expected SUCCESS result, got status=%d resp=%+v", respDone.StatusCode, doneRes)
	}

	// Invalid UUID rejected on GET.
	respBadUUID := env.signedDo(http.MethodGet, "/v1/upgrades/jobs/not-a-uuid", nil, nil)
	_ = respBadUUID.Body.Close()
	if respBadUUID.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid uuid: got %d, want 400", respBadUUID.StatusCode)
	}
}

func TestNewServerFailClosedValidation(t *testing.T) {
	tmp := t.TempDir()
	secretFile := filepath.Join(tmp, "secret.key")
	if err := os.WriteFile(secretFile, []byte(testSharedSecretHex), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := NewServer(Config{SecretFile: secretFile}); err == nil {
		t.Fatal("expected missing node name to fail closed")
	}
	if _, err := NewServer(Config{NodeName: "gw-b"}); err == nil {
		t.Fatal("expected missing secret file to fail closed")
	}
	if _, err := NewServer(Config{NodeName: "gw-b", SecretFile: filepath.Join(tmp, "missing")}); err == nil {
		t.Fatal("expected unreadable secret file to fail closed")
	}
	if _, err := NewServer(Config{NodeName: "gw-b", SecretFile: secretFile, TLSCertFile: "/tmp/a.crt"}); err == nil {
		t.Fatal("expected tls-cert without tls-key to fail closed")
	}
}

func TestHostctlSecretBootstrapAndMalformedFailClosed(t *testing.T) {
	env := newTestEnv(t)

	// Fresh hostctl dir without .hostctl-secret should bootstrap 0600 secret and write valid v2 flag.
	body, _ := json.Marshal(FirewallEnsureRequest{
		Ports:       []int{443},
		RequestID:   "req-bootstrap-001",
		RequestedBy: "gateway-publish",
	})
	resp := env.signedDo(http.MethodPost, "/v1/firewall/ensure", body, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected bootstrap firewall ensure to succeed, got %d", resp.StatusCode)
	}
	secPath := filepath.Join(env.hostctlDir, ".hostctl-secret")
	sfi, err := os.Stat(secPath)
	if err != nil {
		t.Fatalf("expected bootstrapped .hostctl-secret: %v", err)
	}
	if sfi.Mode().Perm() != 0o600 {
		t.Fatalf("bootstrapped secret mode=%04o want 0600", sfi.Mode().Perm())
	}

	// Corrupt .hostctl-secret -> health hostctl_ready=false AND POST /v1/firewall/ensure fails closed!
	if err := os.WriteFile(secPath, []byte("not-valid-hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hResp := env.signedDo(http.MethodGet, "/v1/health", nil, nil)
	var health HealthResponse
	_ = json.NewDecoder(hResp.Body).Decode(&health)
	_ = hResp.Body.Close()
	if health.HostctlReady {
		t.Fatal("expected hostctl_ready=false when .hostctl-secret is malformed")
	}
	failResp := env.signedDo(http.MethodPost, "/v1/firewall/ensure", body, nil)
	_ = failResp.Body.Close()
	if failResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when .hostctl-secret malformed, got %d", failResp.StatusCode)
	}
}
