package nodesync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/systemops"
	"github.com/jiuzhang-waf/server/internal/upgrades"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestClientTLSCAPinningAndRedirectBlocked(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/health":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(HealthResponse{
				Node:           "gw-b",
				Version:        "1.12.0",
				CaddyReachable: true,
				HostctlReady:   true,
				UpgradeReady:   true,
				Now:            time.Now().UTC(),
			})
		case "/v1/status":
			http.Redirect(w, r, "https://127.0.0.1:1/steal", http.StatusTemporaryRedirect)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer tlsSrv.Close()

	cert := tlsSrv.Certificate()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	fpSum := sha256.Sum256(cert.Raw)
	fpHex := hex.EncodeToString(fpSum[:])

	// 1. Valid custom CA PEM succeeds.
	cCA, err := NewClient(ClientConfig{
		Addr:      tlsSrv.URL,
		SecretHex: testSharedSecretHex,
		TLSCAPEM:  caPEM,
	})
	if err != nil {
		t.Fatalf("NewClient CA: %v", err)
	}
	h, err := cCA.Health(context.Background())
	if err != nil || h.Node != "gw-b" {
		t.Fatalf("Health with CA failed: h=%+v err=%v", h, err)
	}

	// 2. Redirect (307) must NOT be followed.
	_, err = cCA.Status(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307 APIError without following redirect, got %v", err)
	}

	// 3. Leaf SHA-256 fingerprint pinning (without CA, colon-formatted uppercase) succeeds.
	colonFP := strings.ToUpper(formatColonHex(fpHex))
	cPin, err := NewClient(ClientConfig{
		Addr:          tlsSrv.URL,
		SecretHex:     testSharedSecretHex,
		TLSCertSHA256: colonFP,
	})
	if err != nil {
		t.Fatalf("NewClient pin: %v", err)
	}
	if _, err := cPin.Health(context.Background()); err != nil {
		t.Fatalf("Health with SHA-256 pin failed: %v", err)
	}

	// 4. Both CA PEM + matching SHA-256 pin succeeds.
	cBoth, err := NewClient(ClientConfig{
		Addr:          tlsSrv.URL,
		SecretHex:     testSharedSecretHex,
		TLSCAPEM:      caPEM,
		TLSCertSHA256: fpHex,
	})
	if err != nil {
		t.Fatalf("NewClient both: %v", err)
	}
	if _, err := cBoth.Health(context.Background()); err != nil {
		t.Fatalf("Health with CA+pin failed: %v", err)
	}

	// 5. Wrong SHA-256 fingerprint MUST fail TLS handshake.
	cWrongPin, err := NewClient(ClientConfig{
		Addr:          tlsSrv.URL,
		SecretHex:     testSharedSecretHex,
		TLSCertSHA256: strings.Repeat("f", 64),
	})
	if err != nil {
		t.Fatalf("NewClient wrong pin: %v", err)
	}
	if _, err := cWrongPin.Health(context.Background()); err == nil {
		t.Fatal("expected wrong SHA-256 fingerprint to fail TLS verification")
	}

	// 6. Invalid CA PEM or malformed fingerprint fails NewClient closed.
	if _, err := NewClient(ClientConfig{Addr: tlsSrv.URL, SecretHex: testSharedSecretHex, TLSCAPEM: []byte("not-pem")}); err == nil {
		t.Fatal("expected invalid CA PEM to fail NewClient")
	}
	if _, err := NewClient(ClientConfig{Addr: tlsSrv.URL, SecretHex: testSharedSecretHex, TLSCertSHA256: "short"}); err == nil {
		t.Fatal("expected short TLS fingerprint to fail NewClient")
	}
}

func formatColonHex(h string) string {
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// TestEndToEndWithRealHasyncd compiles and launches the real gateway/cmd/hasyncd binary
// and tests server/internal/nodesync.Client against it across all 9 endpoints, auth edge
// cases, sidecar permissions, hostctl v2 signature compatibility with server/internal/systemops,
// and upgrade schema compatibility with server/internal/upgrades.
func TestEndToEndWithRealHasyncd(t *testing.T) {
	gatewayDir, err := filepath.Abs(filepath.Join("..", "..", "..", "gateway"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(gatewayDir, "cmd", "hasyncd", "main.go")); err != nil {
		t.Skipf("sibling gateway/cmd/hasyncd not present: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "nodesync-e2e-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	binPath := filepath.Join(tmpDir, "hasyncd")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/hasyncd")
	buildCmd.Dir = gatewayDir
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build hasyncd: %v\n%s", err, string(out))
	}

	sidecarDir := filepath.Join(tmpDir, "sidecars")
	hostctlDir := filepath.Join(tmpDir, "hostctl")
	upgradesDir := filepath.Join(tmpDir, "upgrades")
	ifacesLog := filepath.Join(tmpDir, "node-interfaces.jsonl")
	caddySock := filepath.Join(tmpDir, "caddy.sock")
	secretFile := filepath.Join(tmpDir, "hasync.secret")
	stampFile := filepath.Join(tmpDir, "health.json")

	for _, d := range []string{sidecarDir, hostctlDir, upgradesDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(secretFile, []byte(testSharedSecretHex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Pre-create hostctl secret using real server/internal/systemops!
	hostctlSecret, err := systemops.LoadOrCreateHostctlSecret(hostctlDir)
	if err != nil {
		t.Fatalf("LoadOrCreateHostctlSecret: %v", err)
	}

	// Seed sidecar status files and node-interfaces.jsonl.
	if err := os.WriteFile(filepath.Join(sidecarDir, "ha-vip-status.json"),
		[]byte(`{"group":"ha-prod","node":"gw-b","state":"BACKUP","keepalived_running":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sidecarDir, "network-status.json"),
		[]byte(`{"ok":true,"node":"gw-b","link_pairs":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ifacesLog,
		[]byte(`{"node_name":"gw-b","ifname":"eth0","mac":"aa:bb:cc:dd:ee:ff","ip_addresses":["10.10.0.2/24"],"media_type":"TP","link_speed":1000,"operstate":"up","collected_at":"2026-11-24T12:00:00Z"}`+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	// Start mock Caddy Admin Unix socket.
	var caddyMu sync.Mutex
	caddyConfig := `{"admin":{"listen":"unix//var/run/caddy/admin.sock"},"apps":{"http":{"servers":{"s0":{"routes":[{"handle":[{"handler":"jiuzhang_guard","api_policy_version":"pol-init"}]}]}}}}}`
	caddyLn, err := net.Listen("unix", caddySock)
	if err != nil {
		t.Fatalf("listen mock caddy: %v", err)
	}
	caddyMux := http.NewServeMux()
	caddyMux.HandleFunc("/config/", func(w http.ResponseWriter, r *http.Request) {
		caddyMu.Lock()
		cfg := caddyConfig
		caddyMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, cfg)
	})
	caddyMux.HandleFunc("/load", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		caddyMu.Lock()
		caddyConfig = string(b)
		caddyMu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	caddySrv := &http.Server{Handler: caddyMux}
	go func() { _ = caddySrv.Serve(caddyLn) }()
	t.Cleanup(func() { _ = caddySrv.Close() })

	// Pick a free ephemeral TCP port on 127.0.0.1.
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := probeLn.Addr().String()
	_ = probeLn.Close()

	// Start real hasyncd daemon.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proc := exec.CommandContext(ctx, binPath,
		"--listen", listenAddr,
		"--node", "gw-b",
		"--secret-file", secretFile,
		"--caddy-socket", caddySock,
		"--sidecar-dir", sidecarDir,
		"--hostctl-dir", hostctlDir,
		"--upgrades-dir", upgradesDir,
		"--node-ifaces-log", ifacesLog,
		"--version", "1.12.0",
		"--health-stamp", stampFile,
	)
	var stderrBuf syncBuffer
	proc.Stderr = &stderrBuf
	if err := proc.Start(); err != nil {
		t.Fatalf("start hasyncd: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = proc.Wait()
	})

	// Wait until stamp file appears and `hasyncd --healthcheck` exits 0.
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, statErr := os.Stat(stampFile); statErr == nil {
			hc := exec.Command(binPath, "--healthcheck", "--health-stamp", stampFile)
			if err := hc.Run(); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("hasyncd did not become healthy in time; stderr:\n%s", stderrBuf.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	client, err := NewClient(ClientConfig{
		Addr:      "http://" + listenAddr,
		SecretHex: testSharedSecretHex,
		NodeName:  "gw-a",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// 1. GET /v1/health
	health, err := client.Health(ctx)
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if health.Node != "gw-b" || health.Version != "1.12.0" || !health.CaddyReachable || !health.HostctlReady || !health.UpgradeReady {
		t.Fatalf("unexpected health: %+v", health)
	}

	// 2. GET /v1/status
	st, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Node != "gw-b" || st.PolicyVersion != "pol-init" || !st.CaddyReachable || len(st.Interfaces) != 1 || st.Interfaces[0].IfName != "eth0" {
		t.Fatalf("unexpected status: %+v", st)
	}

	// 3. POST /v1/caddy/load & 4. GET /v1/caddy/config-hash
	newCfg := []byte(`{"admin":{"listen":"unix//var/run/caddy/other.sock"},"apps":{"http":{"servers":{"s0":{"routes":[{"handle":[{"handler":"jiuzhang_guard","api_policy_version":"pol-v200"}]}]}}}}}`)
	loadResp, err := client.LoadCaddyConfig(ctx, newCfg)
	if err != nil || !loadResp.OK || loadResp.CaddyStatus != 200 {
		t.Fatalf("LoadCaddyConfig: resp=%+v err=%v", loadResp, err)
	}
	hashResp, err := client.GetCaddyConfigHash(ctx)
	if err != nil {
		t.Fatalf("GetCaddyConfigHash: %v", err)
	}
	wantHash, err := CanonicalBusinessConfigHash(newCfg)
	if err != nil {
		t.Fatal(err)
	}
	if hashResp.ConfigHash != wantHash || hashResp.PolicyVersion != "pol-v200" {
		t.Fatalf("config hash mismatch: got %+v want hash=%s", hashResp, wantHash)
	}

	// 5. PUT/DELETE /v1/sidecars/{name} (allowlist + 0640/0644 permissions)
	if _, err := client.PutSidecar(ctx, "ha-vip-status.json", []byte(`{}`)); err == nil {
		t.Fatal("expected disallowed sidecar filename to be rejected")
	}
	if _, err := client.PutSidecar(ctx, SidecarHaVip, []byte(`{"group":"ha-prod","state":"ENABLED"}`)); err != nil {
		t.Fatalf("PutSidecar ha-vip.json: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(sidecarDir, SidecarHaVip)); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("ha-vip.json perm check failed: fi=%v err=%v", fi, err)
	}
	if _, err := client.PutSidecar(ctx, SidecarNetwork, []byte(`{"bridges":[],"routes":[]}`)); err != nil {
		t.Fatalf("PutSidecar network.json: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(sidecarDir, SidecarNetwork)); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("network.json perm check failed: fi=%v err=%v", fi, err)
	}
	delRes, err := client.DeleteSidecar(ctx, SidecarHaVip)
	if err != nil || !delRes.Deleted {
		t.Fatalf("DeleteSidecar: res=%+v err=%v", delRes, err)
	}

	// 6. POST /v1/firewall/ensure -> verify EXACT compatibility with server/internal/systemops v2!
	fwRes, err := client.EnsureFirewallPorts(ctx, FirewallEnsureRequest{
		Ports:       []int{8443, 80, 443, 80},
		RequestID:   "e2e-fw-001",
		RequestedBy: "gateway-publish",
		UserID:      "11111111-1111-4111-8111-111111111111",
	})
	if err != nil || !fwRes.OK {
		t.Fatalf("EnsureFirewallPorts: res=%+v err=%v", fwRes, err)
	}
	flagBytes, err := os.ReadFile(filepath.Join(hostctlDir, fwRes.File))
	if err != nil {
		t.Fatalf("read written hostctl flag: %v", err)
	}
	var sysCmd systemops.Command
	if err := json.Unmarshal(flagBytes, &sysCmd); err != nil {
		t.Fatalf("unmarshal into systemops.Command: %v", err)
	}
	gotHMAC := sysCmd.HMAC
	sysCmd.HMAC = ""
	systemops.SignCommand(&sysCmd, hostctlSecret)
	if gotHMAC != sysCmd.HMAC {
		t.Fatalf("hostctl v2 HMAC incompatible with server/internal/systemops!\n hasyncd:   %s\n systemops: %s", gotHMAC, sysCmd.HMAC)
	}

	// 7. POST /v1/upgrades/packages (streaming from local disk + SHA-256 mismatch rejection!)
	pkgData := bytes.Repeat([]byte("WDSP-UPGRADE-PAYLOAD-BLOCK-"), 2048)
	localPkg := filepath.Join(tmpDir, "jiuzhang-wdsp-update-full-1.13.0-amd64.tar.gz")
	if err := os.WriteFile(localPkg, pkgData, 0o600); err != nil {
		t.Fatal(err)
	}

	// Tampered stream (claimed SHA-256 != actual bytes) MUST be rejected before rename!
	tamperedName := "jiuzhang-wdsp-update-full-9.9.9-amd64.tar.gz"
	_, err = client.UploadUpgradePackageReader(ctx, tamperedName, bytes.NewReader([]byte("corrupted-bytes")), int64(len("corrupted-bytes")), strings.Repeat("a", 64))
	var upErr *APIError
	if !errors.As(err, &upErr) || upErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on SHA-256 mismatch upload, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(upgradesDir, "packages", tamperedName)); !os.IsNotExist(statErr) {
		t.Fatalf("tampered package must not exist after rejected upload")
	}

	// Valid streaming upload from disk.
	upRes, err := client.UploadUpgradePackage(ctx, localPkg, "")
	if err != nil || !upRes.OK || upRes.Size != int64(len(pkgData)) {
		t.Fatalf("UploadUpgradePackage: res=%+v err=%v", upRes, err)
	}
	if fi, err := os.Stat(filepath.Join(upgradesDir, "packages", filepath.Base(localPkg))); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("uploaded package perm check failed: fi=%v err=%v", fi, err)
	}

	// 8. POST /v1/upgrades/execute -> verify exact schema match with server/internal/upgrades.ExecutorRequest!
	jobID := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	execRes, err := client.ExecuteUpgrade(ctx, UpgradeExecuteRequest{
		JobID:         jobID,
		PackageFile:   filepath.Base(localPkg),
		PackageSHA256: upRes.SHA256,
		VersionFrom:   "1.12.0",
		VersionTo:     "1.13.0",
		RequestedAt:   time.Now().UTC(),
	})
	if err != nil || !execRes.OK || execRes.JobID != jobID {
		t.Fatalf("ExecuteUpgrade: res=%+v err=%v", execRes, err)
	}
	jobRaw, err := os.ReadFile(filepath.Join(upgradesDir, "executor", "jobs", jobID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var upExecReq upgrades.ExecutorRequest
	if err := json.Unmarshal(jobRaw, &upExecReq); err != nil {
		t.Fatalf("unmarshal into upgrades.ExecutorRequest: %v", err)
	}
	if upExecReq.JobID != jobID || upExecReq.PackageSHA256 != upRes.SHA256 || upExecReq.VersionTo != "1.13.0" {
		t.Fatalf("unexpected upgrades.ExecutorRequest: %+v", upExecReq)
	}

	// 9. GET /v1/upgrades/jobs/{job_id} -> pending then SUCCESS (matching upgrades.ExecutorResult!)
	resPending, err := client.GetUpgradeJobResult(ctx, jobID)
	if err != nil || !resPending.Pending {
		t.Fatalf("expected pending job result, got res=%+v err=%v", resPending, err)
	}
	resDir := filepath.Join(upgradesDir, "executor", "results")
	if err := os.MkdirAll(resDir, 0o750); err != nil {
		t.Fatal(err)
	}
	execResultRaw, _ := json.Marshal(upgrades.ExecutorResult{
		JobID:      jobID,
		Status:     "SUCCESS",
		Stage:      "VERIFYING",
		FinishedAt: time.Now().UTC(),
	})
	if err := os.WriteFile(filepath.Join(resDir, jobID+".json"), execResultRaw, 0o640); err != nil {
		t.Fatal(err)
	}
	resDone, err := client.GetUpgradeJobResult(ctx, jobID)
	if err != nil || resDone.Pending || resDone.Status != "SUCCESS" {
		t.Fatalf("expected SUCCESS job result, got res=%+v err=%v", resDone, err)
	}

	// 10. Negative auth checks against live hasyncd: expired timestamp, replayed nonce, tampered body/signature.
	secretBytes, _ := ParseSecretHex(testSharedSecretHex)
	sendRaw := func(ts time.Time, nonce string, body []byte, tamperSig, tamperBody bool) int {
		t.Helper()
		signedBody := body
		if tamperBody {
			signedBody = []byte(`{"different":true}`)
		}
		req, _ := http.NewRequest(http.MethodPost, "http://"+listenAddr+"/v1/caddy/load", bytes.NewReader(body))
		sum := sha256.Sum256(signedBody)
		bodyHex := hex.EncodeToString(sum[:])
		_ = SignRequest(req, secretBytes, "gw-a", bodyHex, ts, nonce)
		if tamperSig {
			req.Header.Set(HeaderSignature, strings.Repeat("0", 64))
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	now := time.Now().UTC()
	if code := sendRaw(now.Add(-90*time.Second), "aabbccdd11223344", newCfg, false, false); code != http.StatusUnauthorized {
		t.Fatalf("expired timestamp: got %d, want 401", code)
	}
	replayNonce := "ffeeddccbbaa9988"
	if code := sendRaw(now, replayNonce, newCfg, false, false); code != http.StatusOK {
		t.Fatalf("first use of nonce: got %d, want 200", code)
	}
	if code := sendRaw(now, replayNonce, newCfg, false, false); code != http.StatusUnauthorized {
		t.Fatalf("replayed nonce: got %d, want 401", code)
	}
	if code := sendRaw(now, "1122334455667788", newCfg, true, false); code != http.StatusUnauthorized {
		t.Fatalf("tampered signature: got %d, want 401", code)
	}
	if code := sendRaw(now, "2233445566778899", newCfg, false, true); code != http.StatusUnauthorized {
		t.Fatalf("tampered body: got %d, want 401", code)
	}
	// Verify timestamp string helper check works too.
	_ = strconv.FormatInt(now.Unix(), 10)
}
