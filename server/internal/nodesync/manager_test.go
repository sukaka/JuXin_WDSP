package nodesync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type memNodeStore struct {
	mu    sync.RWMutex
	nodes map[uuid.UUID]*NodeCredential
}

func newMemNodeStore(creds ...NodeCredential) *memNodeStore {
	s := &memNodeStore{nodes: make(map[uuid.UUID]*NodeCredential, len(creds))}
	for i := range creds {
		c := creds[i]
		s.nodes[c.NodeID] = &c
	}
	return s
}

func (s *memNodeStore) GetCredentialByID(_ context.Context, nodeID uuid.UUID) (*NodeCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.nodes[nodeID]
	if !ok {
		return nil, ErrNodeNotFound
	}
	cp := *c
	return &cp, nil
}

func (s *memNodeStore) GetCredentialByName(_ context.Context, nodeName string) (*NodeCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.nodes {
		if c.NodeName == nodeName {
			cp := *c
			return &cp, nil
		}
	}
	return nil, ErrNodeNotFound
}

func (s *memNodeStore) ListSyncAgentNodes(_ context.Context) ([]NodeCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]NodeCredential, 0, len(s.nodes))
	for _, c := range s.nodes {
		if c.SyncAgentAddr != "" {
			out = append(out, *c)
		}
	}
	return out, nil
}

func (s *memNodeStore) ListNodesByNames(_ context.Context, nodeNames []string) ([]NodeCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	want := make(map[string]bool, len(nodeNames))
	for _, n := range nodeNames {
		want[n] = true
	}
	out := make([]NodeCredential, 0, len(nodeNames))
	for _, c := range s.nodes {
		if want[c.NodeName] {
			out = append(out, *c)
		}
	}
	return out, nil
}

type fakeDecryptor struct {
	err error
}

func (d fakeDecryptor) Decrypt(encoded string) (string, error) {
	if d.err != nil {
		return "", d.err
	}
	return strings.TrimPrefix(encoded, "enc:"), nil
}

func TestManagerFullRPCAndStatusFlow(t *testing.T) {
	secretHex := testSharedSecretHex
	var (
		mu             sync.Mutex
		loadedConfig   []byte
		sidecars       = map[string][]byte{}
		deletedSidecar []string
		firewallPorts  []int
		uploadedFile   string
		executedJobID  string
	)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify HMAC auth headers are present on every call
		if r.Header.Get(HeaderSignature) == "" || r.Header.Get(HeaderNode) != "gw-a" {
			http.Error(w, `{"error":"missing auth"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/health":
			_ = json.NewEncoder(w).Encode(HealthResponse{
				Node:           "gw-b",
				Version:        "1.12.0",
				CaddyReachable: true,
				HostctlReady:   true,
				UpgradeReady:   true,
				Now:            time.Now().UTC(),
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/caddy/load":
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			loadedConfig = body
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(CaddyLoadResponse{OK: true, CaddyStatus: 200})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/caddy/config-hash":
			mu.Lock()
			cfg := loadedConfig
			mu.Unlock()
			h, _ := CanonicalBusinessConfigHash(cfg)
			_ = json.NewEncoder(w).Encode(CaddyConfigHashResponse{ConfigHash: h, PolicyVersion: "v42"})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/sidecars/"):
			name := strings.TrimPrefix(r.URL.Path, "/v1/sidecars/")
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			sidecars[name] = body
			mu.Unlock()
			sum := sha256.Sum256(body)
			_ = json.NewEncoder(w).Encode(SidecarWriteResponse{OK: true, Name: name, Size: len(body), SHA256: hex.EncodeToString(sum[:])})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/sidecars/"):
			name := strings.TrimPrefix(r.URL.Path, "/v1/sidecars/")
			mu.Lock()
			delete(sidecars, name)
			deletedSidecar = append(deletedSidecar, name)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(SidecarDeleteResponse{OK: true, Name: name, Deleted: true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/firewall/ensure":
			var req FirewallEnsureRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			firewallPorts = append([]int(nil), req.Ports...)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(FirewallEnsureResponse{OK: true, File: "fw.json", Ports: req.Ports, RequestID: req.RequestID})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/upgrades/packages":
			body, _ := io.ReadAll(r.Body)
			sum := sha256.Sum256(body)
			fn := r.Header.Get(HeaderPackageFilename)
			mu.Lock()
			uploadedFile = fn
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(UpgradePackageUploadResponse{OK: true, Filename: fn, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/upgrades/execute":
			var req UpgradeExecuteRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			executedJobID = req.JobID
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(UpgradeExecuteResponse{OK: true, JobID: req.JobID, Status: "SUBMITTED"})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/upgrades/jobs/"):
			jobID := strings.TrimPrefix(r.URL.Path, "/v1/upgrades/jobs/")
			_ = json.NewEncoder(w).Encode(UpgradeJobResult{Pending: false, JobID: jobID, Status: "SUCCESS", Stage: "DONE"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	nodeB := uuid.New()
	now := time.Now().UTC()
	store := newMemNodeStore(
		NodeCredential{
			NodeID:               nodeB,
			NodeName:             "gw-b",
			SyncAgentAddr:        srv.URL,
			SyncSecretCiphertext: "enc:" + secretHex,
			SyncEnabled:          true,
			HaVipStatus:          json.RawMessage(`{"group":"ha-main","node":"gw-b","state":"BACKUP","keepalived_running":true}`),
			HaVipStatusAt:        &now,
			NetworkStatus:        json.RawMessage(`{"ok":true,"message":"applied"}`),
			NetworkStatusAt:      &now,
		},
		NodeCredential{
			NodeID:   uuid.New(),
			NodeName: "gw-a",
		},
	)

	mgr := NewManager(store, fakeDecryptor{}, ManagerConfig{
		LocalNodeName: "gw-a",
		TLSCAPEM:      caPEM,
	})
	ctx := context.Background()

	// 1. ProbeNodeHealth
	hResp, latency, err := mgr.ProbeNodeHealth(ctx, nodeB)
	if err != nil || !hResp.CaddyReachable || hResp.Version != "1.12.0" || latency < 0 {
		t.Fatalf("ProbeNodeHealth = (%+v, %d, %v)", hResp, latency, err)
	}

	// 2. SyncCaddyConfig
	cfgStr := `{"admin":{"listen":"unix//run/caddy/admin.sock"},"apps":{"http":{"servers":{"s0":{"listen":[":80"]}}}}}`
	wantHash, _ := CanonicalBusinessConfigHash([]byte(cfgStr))
	gotHash, err := mgr.SyncCaddyConfig(ctx, gatewayconfig.SyncTarget{NodeID: nodeB, NodeName: "gw-b", SyncAgentAddr: srv.URL}, cfgStr)
	if err != nil || gotHash != wantHash {
		t.Fatalf("SyncCaddyConfig = (%q, %v), want %q", gotHash, err, wantHash)
	}

	// 3. SyncSidecarFile & SyncFirewallPorts
	if err := mgr.SyncSidecarFile(ctx, gatewayconfig.SyncTarget{NodeID: nodeB, NodeName: "gw-b"}, SidecarTproxyd, []byte(`{"enabled":true}`)); err != nil {
		t.Fatalf("SyncSidecarFile: %v", err)
	}
	if err := mgr.SyncFirewallPorts(ctx, gatewayconfig.SyncTarget{NodeID: nodeB, NodeName: "gw-b"}, []int{80, 443}, uuid.New(), "req-1"); err != nil {
		t.Fatalf("SyncFirewallPorts: %v", err)
	}
	mu.Lock()
	if len(firewallPorts) != 2 || firewallPorts[0] != 80 || firewallPorts[1] != 443 {
		t.Fatalf("firewallPorts = %v", firewallPorts)
	}
	mu.Unlock()

	// 4. hagroups RemoteSyncer + NodeStatusProvider
	if err := mgr.PushHaVip(ctx, "gw-b", []byte(`{"group":"ha-main","state":"ENABLED"}`)); err != nil {
		t.Fatalf("PushHaVip: %v", err)
	}
	if err := mgr.DeleteHaVip(ctx, "gw-b"); err != nil {
		t.Fatalf("DeleteHaVip: %v", err)
	}
	statuses, err := mgr.GetNodeHaVipStatuses(ctx, []string{"gw-b", "gw-missing"})
	if err != nil || len(statuses) != 1 || statuses["gw-b"].Source != "remote" {
		t.Fatalf("GetNodeHaVipStatuses = (%+v, %v)", statuses, err)
	}

	// 5. netconfig remote sync & status
	editable, err := mgr.IsRemoteEditable(ctx, "gw-b")
	if err != nil || !editable {
		t.Fatalf("IsRemoteEditable(gw-b) = (%v, %v)", editable, err)
	}
	editableA, err := mgr.IsRemoteEditable(ctx, "gw-a")
	if err != nil || editableA {
		t.Fatalf("IsRemoteEditable(gw-a) = (%v, %v)", editableA, err)
	}
	if err := mgr.PushNetworkConfig(ctx, "gw-b", []byte(`{"bridges":[],"ip_forward":true,"routes":[]}`)); err != nil {
		t.Fatalf("PushNetworkConfig: %v", err)
	}
	netSt, err := mgr.GetNodeNetworkStatus(ctx, "gw-b")
	if err != nil || !strings.Contains(string(netSt), `"ok":true`) {
		t.Fatalf("GetNodeNetworkStatus = (%s, %v)", string(netSt), err)
	}
	remoteList, err := mgr.ListRemoteEditableNodes(ctx)
	if err != nil || len(remoteList) != 1 || remoteList[0] != "gw-b" {
		t.Fatalf("ListRemoteEditableNodes = (%v, %v)", remoteList, err)
	}

	// 6. Remote Upgrade primitives
	pkgDir := t.TempDir()
	pkgPath := filepath.Join(pkgDir, "jiuzhang-wdsp-update-full-1.13.0-amd64.tar.gz")
	pkgBytes := []byte("fake-upgrade-archive-content")
	if err := os.WriteFile(pkgPath, pkgBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	pkgSum := sha256.Sum256(pkgBytes)
	pkgSHA := hex.EncodeToString(pkgSum[:])

	upResp, err := mgr.UploadUpgradePackage(ctx, nodeB, pkgPath, filepath.Base(pkgPath), pkgSHA)
	if err != nil || !upResp.OK || upResp.SHA256 != pkgSHA {
		t.Fatalf("UploadUpgradePackage = (%+v, %v)", upResp, err)
	}
	jobID := uuid.NewString()
	execResp, err := mgr.ExecuteUpgrade(ctx, nodeB, UpgradeExecuteRequest{
		JobID:         jobID,
		PackageFile:   filepath.Base(pkgPath),
		PackageSHA256: pkgSHA,
		VersionFrom:   "1.12.0",
		VersionTo:     "1.13.0",
	})
	if err != nil || !execResp.OK || executedJobID != jobID {
		t.Fatalf("ExecuteUpgrade = (%+v, %v)", execResp, err)
	}
	jobRes, err := mgr.GetUpgradeJobResult(ctx, nodeB, jobID)
	if err != nil || jobRes.Pending || jobRes.Status != "SUCCESS" {
		t.Fatalf("GetUpgradeJobResult = (%+v, %v)", jobRes, err)
	}
	mu.Lock()
	if uploadedFile != filepath.Base(pkgPath) || len(deletedSidecar) != 1 || deletedSidecar[0] != SidecarHaVip {
		t.Fatalf("unexpected side effects: uploaded=%q deleted=%v", uploadedFile, deletedSidecar)
	}
	mu.Unlock()
}

func TestManagerFailClosedCredentials(t *testing.T) {
	nodeID := uuid.New()
	store := newMemNodeStore(NodeCredential{
		NodeID:               nodeID,
		NodeName:             "gw-b",
		SyncAgentAddr:        "https://10.0.0.2:18443",
		SyncSecretCiphertext: "enc:" + testSharedSecretHex,
	})
	// Missing decryptor fails closed
	mgrNoDec := NewManager(store, nil, ManagerConfig{})
	if _, _, err := mgrNoDec.ClientForNodeID(context.Background(), nodeID); err == nil {
		t.Fatal("expected error when decryptor is nil")
	}
	// Decrypt failure fails closed
	mgrBadDec := NewManager(store, fakeDecryptor{err: errors.New("wrong key")}, ManagerConfig{})
	if _, _, err := mgrBadDec.ClientForNodeID(context.Background(), nodeID); err == nil {
		t.Fatal("expected error when decrypt fails")
	}
	// Missing secret fails closed
	nodeNoSecret := uuid.New()
	store.nodes[nodeNoSecret] = &NodeCredential{NodeID: nodeNoSecret, NodeName: "gw-nosec", SyncAgentAddr: "https://10.0.0.2:18443"}
	mgr := NewManager(store, fakeDecryptor{}, ManagerConfig{})
	if _, _, err := mgr.ClientForNodeID(context.Background(), nodeNoSecret); err == nil {
		t.Fatal("expected error when secret ciphertext is empty")
	}
}

func TestManagerRemoteEditableRequiresSyncEnabled(t *testing.T) {
	store := newMemNodeStore(
		NodeCredential{
			NodeID:               uuid.New(),
			NodeName:             "gw-enabled",
			SyncAgentAddr:        "https://10.0.0.2:18443",
			SyncSecretCiphertext: "enc:" + testSharedSecretHex,
			SyncEnabled:          true,
		},
		NodeCredential{
			NodeID:               uuid.New(),
			NodeName:             "gw-disabled",
			SyncAgentAddr:        "https://10.0.0.3:18443",
			SyncSecretCiphertext: "enc:" + testSharedSecretHex,
			SyncEnabled:          false,
		},
	)
	mgr := NewManager(store, fakeDecryptor{}, ManagerConfig{LocalNodeName: "gw-a"})
	ctx := context.Background()

	if editable, err := mgr.IsRemoteEditable(ctx, "gw-enabled"); err != nil || !editable {
		t.Fatalf("IsRemoteEditable(gw-enabled) = (%v, %v), want (true, nil)", editable, err)
	}
	if editable, err := mgr.IsRemoteEditable(ctx, "gw-disabled"); err != nil || editable {
		t.Fatalf("IsRemoteEditable(gw-disabled) = (%v, %v), want (false, nil)", editable, err)
	}
	list, err := mgr.ListRemoteEditableNodes(ctx)
	if err != nil || len(list) != 1 || list[0] != "gw-enabled" {
		t.Fatalf("ListRemoteEditableNodes = (%v, %v), want [gw-enabled]", list, err)
	}
}
