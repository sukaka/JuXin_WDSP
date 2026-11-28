package nodesync

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func seedTestRuleRelease(t *testing.T, rulesDir, version, manifestSHA string) {
	t.Helper()
	relDir := filepath.Join(rulesDir, "releases", version)
	files := map[string]string{
		"coraza.conf":                         "SecRuleEngine DetectionOnly\n",
		"crs/crs-setup.conf":                  "SecDefaultAction \"phase:1,log,auditlog,pass\"\n",
		"crs/rules/REQUEST-901.conf":          "SecRule REQUEST_URI \"@contains x\" \"id:901001,phase:1,pass\"\n",
		"exclusions/before-crs.conf":          "# before\n",
		"exclusions/after-crs.conf":           "# after\n",
		"jiuzhang/jiuzhang-custom.conf":       "# custom\n",
		"jiuzhang/post-contrib-blocking.conf": "SecRule TX:INBOUND_ANOMALY_SCORE \"@ge 5\" \"id:9000101,phase:2,deny,status:403\"\n",
	}
	for rel, content := range files {
		full := filepath.Join(relDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if manifestSHA != "" {
		metaDir := filepath.Join(rulesDir, ".meta")
		if err := os.MkdirAll(metaDir, 0o750); err != nil {
			t.Fatal(err)
		}
		metaBytes, _ := json.Marshal(map[string]any{
			"version":         version,
			"manifest_sha256": manifestSHA,
			"staged_at":       time.Now().UTC(),
		})
		if err := os.WriteFile(filepath.Join(metaDir, version+".json"), metaBytes, 0o640); err != nil {
			t.Fatal(err)
		}
	}
}

func makeDummySignedRulePackArchive(t *testing.T, version string) (string, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes := []byte(`{"schema_version":1,"product":"wdsp","package_type":"rulepack","rulepack_version":"` + version + `","crs_version":"4.28.0","files":[],"files_manifest_sha256":""}`)
	sigB64 := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, manifestBytes))

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	writeEntry := func(name string, data []byte) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o640, Size: int64(len(data)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(data)
	}
	writeEntry("manifest.json", manifestBytes)
	writeEntry("manifest.sig", []byte(sigB64+"\n"))
	_ = tw.Close()
	_ = gz.Close()

	p := filepath.Join(t.TempDir(), "jiuzhang-wdsp-rulepack-"+version+".tar.gz")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return p, hex.EncodeToString(sum[:])
}

func startRealHasyncdForTest(t *testing.T, binPath, rulesDir string) (addr string, stop func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "nodesync-rp-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	sidecarDir := filepath.Join(tmpDir, "sidecars")
	hostctlDir := filepath.Join(tmpDir, "hostctl")
	upgradesDir := filepath.Join(tmpDir, "upgrades")
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

	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := probeLn.Addr().String()
	_ = probeLn.Close()

	args := []string{
		"--listen", listenAddr,
		"--node", "gw-b",
		"--secret-file", secretFile,
		"--sidecar-dir", sidecarDir,
		"--hostctl-dir", hostctlDir,
		"--upgrades-dir", upgradesDir,
		"--version", "1.20.0",
		"--health-stamp", stampFile,
	}
	if rulesDir != "" {
		args = append(args, "--rules-dir", rulesDir)
	}

	ctx, cancel := context.WithCancel(context.Background())
	proc := exec.CommandContext(ctx, binPath, args...)
	var stderrBuf syncBuffer
	proc.Stderr = &stderrBuf
	if err := proc.Start(); err != nil {
		cancel()
		t.Fatalf("start hasyncd: %v", err)
	}
	cleanup := func() {
		cancel()
		_ = proc.Wait()
	}
	t.Cleanup(cleanup)

	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, statErr := os.Stat(stampFile); statErr == nil {
			if err := exec.Command(binPath, "--healthcheck", "--health-stamp", stampFile).Run(); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("hasyncd did not become healthy; stderr:\n%s", stderrBuf.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return "http://" + listenAddr, cleanup
}

// TestEndToEndRulePacksWithRealHasyncd compiles and runs the real gateway/cmd/hasyncd binary
// and verifies nodesync.Manager & Client end-to-end across health rulepack_ready, status,
// embedded production Ed25519 key enforcement on stage, activate, and delete guards.
func TestEndToEndRulePacksWithRealHasyncd(t *testing.T) {
	gatewayDir, err := filepath.Abs(filepath.Join("..", "..", "..", "gateway"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(gatewayDir, "cmd", "hasyncd", "main.go")); err != nil {
		t.Skipf("sibling gateway/cmd/hasyncd not present: %v", err)
	}

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "hasyncd")
	buildCmd := exec.Command("go", "build", "-o", binPath, "./cmd/hasyncd")
	buildCmd.Dir = gatewayDir
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build hasyncd: %v\n%s", err, string(out))
	}

	ctx := context.Background()

	// Part A: real hasyncd WITHOUT --rules-dir -> rulepack_ready=false and clear precheck error.
	addrDisabled, stopDisabled := startRealHasyncdForTest(t, binPath, "")
	defer stopDisabled()

	nodeDisabled := uuid.New()
	storeA := newMemNodeStore(NodeCredential{
		NodeID:               nodeDisabled,
		NodeName:             "gw-b-legacy",
		SyncAgentAddr:        addrDisabled,
		SyncSecretCiphertext: "enc:" + testSharedSecretHex,
		SyncEnabled:          true,
	})
	mgrA := NewManager(storeA, fakeDecryptor{}, ManagerConfig{LocalNodeName: "gw-a"})

	hA, err := mgrA.CheckNodeHealth(ctx, nodeDisabled)
	if err != nil {
		t.Fatalf("CheckNodeHealth(disabled): %v", err)
	}
	if hA.RulePackReady {
		t.Fatalf("expected rulepack_ready=false without --rules-dir, got %+v", hA)
	}
	stA, err := mgrA.CheckNodeRulePackStatus(ctx, nodeDisabled)
	if err != nil {
		t.Fatalf("CheckNodeRulePackStatus(disabled): %v", err)
	}
	if !stA.Reachable || stA.RulePackReady || stA.Error == "" {
		t.Fatalf("expected reachable=true, rulepack_ready=false, error!=empty, got %+v", stA)
	}

	// Part B: real hasyncd WITH --rules-dir configured.
	rulesDir := t.TempDir()
	v1SHA := strings.Repeat("1", 64)
	oldSHA := strings.Repeat("2", 64)
	seedTestRuleRelease(t, rulesDir, "builtin-1.19.1", "")
	seedTestRuleRelease(t, rulesDir, "20261201.1", v1SHA)
	seedTestRuleRelease(t, rulesDir, "20261115.1", oldSHA)
	if err := os.Symlink("releases/builtin-1.19.1", filepath.Join(rulesDir, "current")); err != nil {
		t.Fatal(err)
	}

	addrReady, stopReady := startRealHasyncdForTest(t, binPath, rulesDir)
	defer stopReady()

	nodeB := uuid.New()
	storeB := newMemNodeStore(NodeCredential{
		NodeID:               nodeB,
		NodeName:             "gw-b",
		SyncAgentAddr:        addrReady,
		SyncSecretCiphertext: "enc:" + testSharedSecretHex,
		SyncEnabled:          true,
	})
	mgrB := NewManager(storeB, fakeDecryptor{}, ManagerConfig{LocalNodeName: "gw-a"})

	// 1. Health reports rulepack_ready=true
	hB, err := mgrB.CheckNodeHealth(ctx, nodeB)
	if err != nil || !hB.RulePackReady {
		t.Fatalf("CheckNodeHealth(ready) = (%+v, %v)", hB, err)
	}

	// 2. Status returns active_symlink, active_version, staged_versions, disk_free_bytes
	stB, err := mgrB.CheckNodeRulePackStatus(ctx, nodeB)
	if err != nil {
		t.Fatalf("CheckNodeRulePackStatus(ready): %v", err)
	}
	if !stB.Reachable || !stB.RulePackReady || !stB.RulesDirWritable || stB.ActiveVersion != "builtin-1.19.1" || stB.ActiveSymlink != "releases/builtin-1.19.1" {
		t.Fatalf("unexpected status: %+v", stB)
	}
	if stB.StagedVersions["20261201.1"] != v1SHA || stB.StagedVersions["20261115.1"] != oldSHA || stB.DiskFreeBytes <= 0 {
		t.Fatalf("unexpected staged_versions/disk: %+v", stB)
	}

	// 3. Real hasyncd MUST reject archive signed with ephemeral non-production Ed25519 key (400)!
	archivePath, archiveSHA := makeDummySignedRulePackArchive(t, "20261220.1")
	_, err = mgrB.StageRulePack(ctx, nodeB, "20261220.1", archivePath, archiveSHA)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 from real hasyncd embedded prod Ed25519 verification, got %v", err)
	}

	// 4. Activate with mismatched manifest_sha256 rejected with 409 Conflict
	_, err = mgrB.ActivateRulePack(ctx, nodeB, "20261201.1", strings.Repeat("f", 64))
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict {
		t.Fatalf("expected HTTP 409 on wrong manifest_sha256, got %v", err)
	}

	// 5. Activate 20261201.1 with matching manifest_sha256 succeeds and updates relative symlink
	actResp, err := mgrB.ActivateRulePack(ctx, nodeB, "20261201.1", v1SHA)
	if err != nil || !actResp.OK || actResp.ActiveSymlink != "releases/20261201.1" {
		t.Fatalf("ActivateRulePack(20261201.1) = (%+v, %v)", actResp, err)
	}
	gotLink, err := os.Readlink(filepath.Join(rulesDir, "current"))
	if err != nil || gotLink != "releases/20261201.1" {
		t.Fatalf("real hasyncd current symlink = %q (err=%v), want releases/20261201.1", gotLink, err)
	}

	// 6. Status reflects newly activated version
	stB2, err := mgrB.CheckNodeRulePackStatus(ctx, nodeB)
	if err != nil || stB2.ActiveVersion != "20261201.1" {
		t.Fatalf("status after activate = (%+v, %v)", stB2, err)
	}

	// 7. Delete active current release refused with 409 Conflict
	_, err = mgrB.DeleteRulePackRelease(ctx, nodeB, "20261201.1")
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict {
		t.Fatalf("expected HTTP 409 deleting active release, got %v", err)
	}

	// 8. Delete builtin release refused client-side
	if _, err := mgrB.DeleteRulePackRelease(ctx, nodeB, "builtin-1.19.1"); err == nil {
		t.Fatal("expected deleting builtin-* to be refused")
	}

	// 9. Delete inactive release 20261115.1 succeeds and removes directory + metadata
	delResp, err := mgrB.DeleteRulePackRelease(ctx, nodeB, "20261115.1")
	if err != nil || !delResp.OK || !delResp.Deleted {
		t.Fatalf("DeleteRulePackRelease(20261115.1) = (%+v, %v)", delResp, err)
	}
	if _, err := os.Stat(filepath.Join(rulesDir, "releases", "20261115.1")); !os.IsNotExist(err) {
		t.Fatal("expected inactive release directory to be deleted")
	}
}

type rebindTestResolver struct {
	calls atomic.Int32
}

func (r *rebindTestResolver) LookupIP(_ context.Context, _, _ string) ([]net.IP, error) {
	if r.calls.Add(1) == 1 {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	return []net.IP{net.ParseIP("8.8.8.8")}, nil
}

func TestManagerRulePackStreamingAndSSRFProtections(t *testing.T) {
	var (
		mu             sync.Mutex
		stagedVersions = map[string]string{}
		activeVer      = "builtin-1.19.1"
	)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderSignature) == "" || r.Header.Get(HeaderNode) != "gw-a" {
			http.Error(w, `{"error":"missing auth"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/health":
			_ = json.NewEncoder(w).Encode(HealthResponse{
				Node:          "gw-b",
				Version:       "1.20.0",
				RulePackReady: true,
				Now:           time.Now().UTC(),
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/rulepacks/stage":
			ver := r.Header.Get(HeaderRulePackVersion)
			hdrSHA := r.Header.Get(HeaderRulePackPackageSHA256)
			body, _ := io.ReadAll(r.Body)
			sum := sha256.Sum256(body)
			actualSHA := hex.EncodeToString(sum[:])
			if ver == "" || hdrSHA != actualSHA || r.Header.Get(HeaderBodySHA256) != actualSHA {
				http.Error(w, `{"error":"header or body sha mismatch"}`, http.StatusBadRequest)
				return
			}
			manifestSHA := actualSHA // test surrogate
			mu.Lock()
			prev, exists := stagedVersions[ver]
			if exists && prev != manifestSHA {
				mu.Unlock()
				http.Error(w, `{"error":"conflict"}`, http.StatusConflict)
				return
			}
			stagedVersions[ver] = manifestSHA
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(RulePackStageResponse{
				OK:             true,
				Version:        ver,
				ManifestSHA256: manifestSHA,
				FileSHA256:     actualSHA,
				FileSize:       int64(len(body)),
				Idempotent:     exists,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/rulepacks/status":
			mu.Lock()
			cp := make(map[string]string, len(stagedVersions))
			for k, v := range stagedVersions {
				cp[k] = v
			}
			cur := activeVer
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(RulePackStatusResponse{
				RulesDirWritable: true,
				ActiveSymlink:    "releases/" + cur,
				ActiveVersion:    cur,
				StagedVersions:   cp,
				DiskFreeBytes:    10 << 30,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/rulepacks/activate":
			var req RulePackActivateRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			activeVer = req.Version
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(RulePackActivateResponse{
				OK:             true,
				Version:        req.Version,
				ActiveSymlink:  "releases/" + req.Version,
				ManifestSHA256: req.ManifestSHA256,
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/rulepacks/releases/"):
			ver := strings.TrimPrefix(r.URL.Path, "/v1/rulepacks/releases/")
			mu.Lock()
			_, existed := stagedVersions[ver]
			delete(stagedVersions, ver)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(RulePackDeleteResponse{OK: true, Version: ver, Deleted: existed})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	nodeOK := uuid.New()
	nodePublicIP := uuid.New()
	nodeMetaIP := uuid.New()
	nodeRebind := uuid.New()

	store := newMemNodeStore(
		NodeCredential{NodeID: nodeOK, NodeName: "gw-b", SyncAgentAddr: srv.URL, SyncSecretCiphertext: "enc:" + testSharedSecretHex, SyncEnabled: true},
		NodeCredential{NodeID: nodePublicIP, NodeName: "gw-public", SyncAgentAddr: "https://8.8.8.8:18443", SyncSecretCiphertext: "enc:" + testSharedSecretHex, SyncEnabled: true},
		NodeCredential{NodeID: nodeMetaIP, NodeName: "gw-meta", SyncAgentAddr: "http://169.254.169.254:18443", SyncSecretCiphertext: "enc:" + testSharedSecretHex, SyncEnabled: true},
		NodeCredential{NodeID: nodeRebind, NodeName: "gw-rebind", SyncAgentAddr: "https://rebind.internal:18443", SyncSecretCiphertext: "enc:" + testSharedSecretHex, SyncEnabled: true},
	)

	mgr := NewManager(store, fakeDecryptor{}, ManagerConfig{
		LocalNodeName: "gw-a",
		TLSCAPEM:      caPEM,
	})
	ctx := context.Background()

	// 1. Streaming stage -> 200, idempotent re-stage -> 200 (Idempotent=true), conflict -> 409
	arc1, sha1 := makeDummySignedRulePackArchive(t, "20261201.1")
	stageRes, err := mgr.StageRulePack(ctx, nodeOK, "20261201.1", arc1, sha1)
	if err != nil || !stageRes.OK || stageRes.Idempotent || stageRes.FileSHA256 != sha1 {
		t.Fatalf("StageRulePack = (%+v, %v)", stageRes, err)
	}
	stageAgain, err := mgr.StageRulePack(ctx, nodeOK, "20261201.1", arc1, sha1)
	if err != nil || !stageAgain.OK || !stageAgain.Idempotent {
		t.Fatalf("idempotent StageRulePack = (%+v, %v)", stageAgain, err)
	}
	arcConflict, shaConflict := makeDummySignedRulePackArchive(t, "20261201.1")
	_, err = mgr.StageRulePack(ctx, nodeOK, "20261201.1", arcConflict, shaConflict)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 conflict on different content for same version, got %v", err)
	}

	// Local SHA-256 mismatch caught client-side before sending
	if _, err := mgr.StageRulePack(ctx, nodeOK, "20261201.1", arc1, strings.Repeat("a", 64)); err == nil {
		t.Fatal("expected local expectedSHA256 mismatch to fail closed")
	}

	// 2. Activate + status + delete
	if _, err := mgr.ActivateRulePack(ctx, nodeOK, "20261201.1", stageRes.ManifestSHA256); err != nil {
		t.Fatalf("ActivateRulePack: %v", err)
	}
	st, err := mgr.CheckNodeRulePackStatus(ctx, nodeOK)
	if err != nil || !st.RulePackReady || st.ActiveVersion != "20261201.1" {
		t.Fatalf("CheckNodeRulePackStatus = (%+v, %v)", st, err)
	}
	if _, err := mgr.DeleteRulePackRelease(ctx, nodeOK, "20261201.1"); err != nil {
		t.Fatalf("DeleteRulePackRelease: %v", err)
	}

	// 3. SSRF protection on CheckNodeHealth & CheckNodeRulePackStatus (public IP & cloud metadata blocked!)
	for _, id := range []uuid.UUID{nodePublicIP, nodeMetaIP} {
		if _, err := mgr.CheckNodeHealth(ctx, id); !errors.Is(err, ErrSyncAgentAddrDenied) {
			t.Fatalf("CheckNodeHealth(%s): want ErrSyncAgentAddrDenied, got %v", id, err)
		}
		if _, err := mgr.CheckNodeRulePackStatus(ctx, id); !errors.Is(err, ErrSyncAgentAddrDenied) {
			t.Fatalf("CheckNodeRulePackStatus(%s): want ErrSyncAgentAddrDenied, got %v", id, err)
		}
	}

	// 4. Dial-time DNS rebinding protection on CheckNodeHealth & CheckNodeRulePackStatus!
	rebindMgr1 := NewManager(store, fakeDecryptor{}, ManagerConfig{
		LocalNodeName: "gw-a",
		Resolver:      &rebindTestResolver{},
	})
	if _, err := rebindMgr1.CheckNodeHealth(ctx, nodeRebind); !errors.Is(err, ErrSyncAgentAddrDenied) {
		t.Fatalf("CheckNodeHealth DNS rebind: want ErrSyncAgentAddrDenied, got %v", err)
	}
	rebindMgr2 := NewManager(store, fakeDecryptor{}, ManagerConfig{
		LocalNodeName: "gw-a",
		Resolver:      &rebindTestResolver{},
	})
	if _, err := rebindMgr2.CheckNodeRulePackStatus(ctx, nodeRebind); !errors.Is(err, ErrSyncAgentAddrDenied) {
		t.Fatalf("CheckNodeRulePackStatus DNS rebind: want ErrSyncAgentAddrDenied, got %v", err)
	}
}
