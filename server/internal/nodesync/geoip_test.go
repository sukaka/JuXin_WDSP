package nodesync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
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
	"testing"
	"time"

	"github.com/google/uuid"
)

func buildTestXDBv4(tag string) []byte {
	const (
		headerSize  = 256
		vectorSize  = 256 * 256 * 8
		minFileSize = headerSize + vectorSize
		segSizeV4   = 14
	)
	buf := make([]byte, minFileSize)
	binary.LittleEndian.PutUint16(buf[0:2], 3)
	binary.LittleEndian.PutUint16(buf[2:4], 1)
	binary.LittleEndian.PutUint16(buf[16:18], 4)
	binary.LittleEndian.PutUint16(buf[18:20], 4)

	region := []byte("中国|浙江省|杭州市|电信|CN|" + tag)
	dataPtr := uint32(len(buf))
	buf = append(buf, region...)

	segOff := uint32(len(buf))
	var seg [segSizeV4]byte
	binary.LittleEndian.PutUint32(seg[0:4], 0xdf050500)
	binary.LittleEndian.PutUint32(seg[4:8], 0xdf0505ff)
	binary.LittleEndian.PutUint16(seg[8:10], uint16(len(region)))
	binary.LittleEndian.PutUint32(seg[10:14], dataPtr)
	buf = append(buf, seg[:]...)

	binary.LittleEndian.PutUint32(buf[8:12], segOff)
	binary.LittleEndian.PutUint32(buf[12:16], segOff)
	vOff := headerSize + (223*256+5)*8
	binary.LittleEndian.PutUint32(buf[vOff:vOff+4], segOff)
	binary.LittleEndian.PutUint32(buf[vOff+4:vOff+8], segOff)
	return buf
}

func buildTestMMDB(tag string) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01})
	buf.Write(make([]byte, 16))
	buf.WriteString("NODESYNC-MMDB-" + tag)
	buf.WriteString("\xab\xcd\xefMaxMind.com")
	buf.WriteByte((7 << 5) | 4)
	writeStr := func(s string) {
		buf.WriteByte((2 << 5) | byte(len(s)))
		buf.WriteString(s)
	}
	writeU16 := func(v uint16) {
		buf.WriteByte((5 << 5) | 2)
		buf.WriteByte(byte(v >> 8))
		buf.WriteByte(byte(v))
	}
	writeU32 := func(v uint32) {
		buf.WriteByte((6 << 5) | 4)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		buf.Write(b[:])
	}
	writeStr("node_count")
	writeU32(1)
	writeStr("record_size")
	writeU16(24)
	writeStr("binary_format_major_version")
	writeU16(2)
	writeStr("ip_version")
	writeU16(6)
	return buf.Bytes()
}

func TestClientGeoIPPushAndStatusAgainstHTTPTest(t *testing.T) {
	secretBytes, err := ParseSecretHex(testSharedSecretHex)
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu       sync.Mutex
		revision string
		slots    = map[string]GeoIPSlotMeta{}
	)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify HMAC signature & body hash strictly.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"read body"}`, http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256(body)
		actualHex := hex.EncodeToString(sum[:])
		if r.Header.Get(HeaderBodySHA256) != actualHex {
			http.Error(w, `{"error":"body sha256 mismatch"}`, http.StatusUnauthorized)
			return
		}
		expectedSig := ComputeSignature(
			secretBytes,
			r.Method,
			r.URL.EscapedPath(),
			r.Header.Get(HeaderTimestamp),
			r.Header.Get(HeaderNonce),
			actualHex,
		)
		if r.Header.Get(HeaderSignature) != expectedSig {
			http.Error(w, `{"error":"signature mismatch"}`, http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/geoip/status":
			mu.Lock()
			cpSlots := make(map[string]GeoIPSlotMeta, len(slots))
			for k, v := range slots {
				cpSlots[k] = v
			}
			rev := revision
			mu.Unlock()
			now := time.Now().UTC()
			_ = json.NewEncoder(w).Encode(GeoIPStatusResponse{
				Node:       "gw-b",
				GeoIPReady: true,
				Revision:   rev,
				UpdatedAt:  &now,
				Slots:      cpSlots,
			})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/geoip/slots/"):
			slot := strings.TrimPrefix(r.URL.Path, "/v1/geoip/slots/")
			geoSHA := r.Header.Get(HeaderGeoIPSHA256)
			geoRev := r.Header.Get(HeaderGeoIPRevision)
			if geoSHA != actualHex {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "X-GeoIP-SHA256 mismatch"})
				return
			}
			now := time.Now().UTC()
			fn := slot + ".mmdb"
			if slot == GeoIPSlotDBIPCity {
				fn = "city.mmdb"
			}
			mu.Lock()
			revision = geoRev
			slots[slot] = GeoIPSlotMeta{
				Filename:   fn,
				SHA256:     actualHex,
				SizeBytes:  int64(len(body)),
				SourceType: "HA_SYNC",
				UpdatedAt:  &now,
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(GeoIPSlotPushResponse{
				OK:        true,
				Node:      "gw-b",
				Slot:      slot,
				Filename:  fn,
				SHA256:    actualHex,
				SizeBytes: int64(len(body)),
				Revision:  geoRev,
				UpdatedAt: now,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	cli, err := NewClient(ClientConfig{
		Addr:      srv.URL,
		SecretHex: testSharedSecretHex,
		NodeName:  "gw-a",
		TLSCAPEM:  caPEM,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	tmpDir := t.TempDir()
	mmdbData := buildTestMMDB("client-test")
	mmdbSum := sha256.Sum256(mmdbData)
	mmdbSHA := hex.EncodeToString(mmdbSum[:])
	localFile := filepath.Join(tmpDir, "city.mmdb")
	if err := os.WriteFile(localFile, mmdbData, 0o600); err != nil {
		t.Fatal(err)
	}

	// Client-side validation rejects invalid slot, invalid revision, and mismatched expectedSHA256.
	if _, err := cli.PushGeoIPSlot(context.Background(), "../bad", localFile, mmdbSHA, "rev-1"); err == nil {
		t.Fatal("expected invalid slot to fail")
	}
	if _, err := cli.PushGeoIPSlot(context.Background(), GeoIPSlotDBIPCity, localFile, mmdbSHA, "../badrev"); err == nil {
		t.Fatal("expected invalid revision to fail")
	}
	if _, err := cli.PushGeoIPSlot(context.Background(), GeoIPSlotDBIPCity, localFile, strings.Repeat("0", 64), "rev-1"); err == nil {
		t.Fatal("expected local expectedSHA256 mismatch to fail")
	}

	// Valid push succeeds.
	rev := "20261128T083000Z-abcd1234"
	pushResp, err := cli.PushGeoIPSlot(context.Background(), GeoIPSlotDBIPCity, localFile, mmdbSHA, rev)
	if err != nil {
		t.Fatalf("PushGeoIPSlot: %v", err)
	}
	if !pushResp.OK || pushResp.Slot != GeoIPSlotDBIPCity || pushResp.SHA256 != mmdbSHA || pushResp.Revision != rev || pushResp.SizeBytes != int64(len(mmdbData)) {
		t.Fatalf("unexpected pushResp: %+v", pushResp)
	}

	// Status reflects pushed slot & revision.
	stResp, err := cli.GetGeoIPStatus(context.Background())
	if err != nil {
		t.Fatalf("GetGeoIPStatus: %v", err)
	}
	if stResp.Node != "gw-b" || !stResp.GeoIPReady || stResp.Revision != rev {
		t.Fatalf("unexpected status: %+v", stResp)
	}
	slotMeta, ok := stResp.Slots[GeoIPSlotDBIPCity]
	if !ok || slotMeta.SHA256 != mmdbSHA || slotMeta.SizeBytes != int64(len(mmdbData)) {
		t.Fatalf("unexpected slot meta: %+v", stResp.Slots)
	}
}

func TestManagerPushGeoIPSlotToPeersAndListPeerStatus(t *testing.T) {
	// Peer B: healthy & accepts GeoIP slot push.
	var (
		bMu    sync.Mutex
		bRev   string
		bSlots = map[string]GeoIPSlotMeta{}
	)
	peerB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderSignature) == "" || r.Header.Get(HeaderNode) != "gw-a" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/v1/geoip/slots/country":
			body, _ := io.ReadAll(r.Body)
			sum := sha256.Sum256(body)
			shaHex := hex.EncodeToString(sum[:])
			rev := r.Header.Get(HeaderGeoIPRevision)
			now := time.Now().UTC()
			bMu.Lock()
			bRev = rev
			bSlots["country"] = GeoIPSlotMeta{Filename: "country.mmdb", SHA256: shaHex, SizeBytes: int64(len(body)), SourceType: "HA_SYNC", UpdatedAt: &now}
			bMu.Unlock()
			_ = json.NewEncoder(w).Encode(GeoIPSlotPushResponse{
				OK: true, Node: "gw-b", Slot: "country", Filename: "country.mmdb",
				SHA256: shaHex, SizeBytes: int64(len(body)), Revision: rev, UpdatedAt: now,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/geoip/status":
			bMu.Lock()
			rev := bRev
			cp := map[string]GeoIPSlotMeta{}
			for k, v := range bSlots {
				cp[k] = v
			}
			bMu.Unlock()
			_ = json.NewEncoder(w).Encode(GeoIPStatusResponse{
				Node: "gw-b", GeoIPReady: true, Revision: rev, Slots: cp,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer peerB.Close()

	// Peer C: unconfigured GeoIP dir (503 fail-closed).
	peerC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "geoip sync directory is not configured"})
	}))
	defer peerC.Close()

	// Disabled peer D & local node A must NEVER be contacted.
	unexpectedHit := false
	neverSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		unexpectedHit = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer neverSrv.Close()

	store := newMemNodeStore(
		NodeCredential{
			NodeID:               uuid.New(),
			NodeName:             "gw-a", // local node -> must skip
			SyncAgentAddr:        neverSrv.URL,
			SyncSecretCiphertext: "enc:" + testSharedSecretHex,
			SyncEnabled:          true,
		},
		NodeCredential{
			NodeID:               uuid.New(),
			NodeName:             "gw-c",
			SyncAgentAddr:        peerC.URL,
			SyncSecretCiphertext: "enc:" + testSharedSecretHex,
			SyncEnabled:          true,
		},
		NodeCredential{
			NodeID:               uuid.New(),
			NodeName:             "gw-b",
			SyncAgentAddr:        peerB.URL,
			SyncSecretCiphertext: "enc:" + testSharedSecretHex,
			SyncEnabled:          true,
		},
		NodeCredential{
			NodeID:               uuid.New(),
			NodeName:             "gw-d-disabled",
			SyncAgentAddr:        neverSrv.URL,
			SyncSecretCiphertext: "enc:" + testSharedSecretHex,
			SyncEnabled:          false, // disabled -> must skip
		},
	)

	mgr := NewManager(store, fakeDecryptor{}, ManagerConfig{LocalNodeName: "gw-a"})

	mmdbData := buildTestMMDB("mgr-peer-push")
	mmdbSum := sha256.Sum256(mmdbData)
	mmdbSHA := hex.EncodeToString(mmdbSum[:])
	localFile := filepath.Join(t.TempDir(), "country.mmdb")
	if err := os.WriteFile(localFile, mmdbData, 0o600); err != nil {
		t.Fatal(err)
	}

	rev := "20261128T083500Z-beef0001"
	pushResults, err := mgr.PushGeoIPSlotToPeers(context.Background(), GeoIPSlotCountry, localFile, mmdbSHA, rev)
	if err != nil {
		t.Fatalf("PushGeoIPSlotToPeers: %v", err)
	}
	if unexpectedHit {
		t.Fatal("local or sync-disabled node must NOT be called")
	}
	if len(pushResults) != 2 {
		t.Fatalf("expected 2 peer results (gw-b, gw-c), got %d: %+v", len(pushResults), pushResults)
	}
	// Deterministic sorted order by NodeName: gw-b, then gw-c.
	if pushResults[0].NodeName != "gw-b" || !pushResults[0].OK || pushResults[0].SHA256 != mmdbSHA || pushResults[0].Revision != rev {
		t.Fatalf("unexpected gw-b push result: %+v", pushResults[0])
	}
	if pushResults[1].NodeName != "gw-c" || pushResults[1].OK || !strings.Contains(pushResults[1].Error, "503") {
		t.Fatalf("expected gw-c to fail with 503 error, got: %+v", pushResults[1])
	}

	statuses, err := mgr.ListPeerGeoIPStatus(context.Background())
	if err != nil {
		t.Fatalf("ListPeerGeoIPStatus: %v", err)
	}
	if len(statuses) != 2 {
		t.Fatalf("expected 2 peer statuses, got %d", len(statuses))
	}
	if statuses[0].NodeName != "gw-b" || !statuses[0].Reachable || !statuses[0].GeoIPReady || statuses[0].Revision != rev {
		t.Fatalf("unexpected gw-b status: %+v", statuses[0])
	}
	if statuses[0].Slots["country"].SHA256 != mmdbSHA {
		t.Fatalf("unexpected gw-b country slot: %+v", statuses[0].Slots)
	}
	if statuses[1].NodeName != "gw-c" || statuses[1].Reachable || !strings.Contains(statuses[1].Error, "503") {
		t.Fatalf("expected gw-c status failure with 503, got: %+v", statuses[1])
	}
}

// TestGeoIPSyncEndToEndWithRealHasyncd compiles and runs the real gateway/cmd/hasyncd binary
// with --geoip-dir and verifies nodesync.Manager push/status plus .revision.json output.
func TestGeoIPSyncEndToEndWithRealHasyncd(t *testing.T) {
	gatewayDir, err := filepath.Abs(filepath.Join("..", "..", "..", "gateway"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(gatewayDir, "cmd", "hasyncd", "main.go")); err != nil {
		t.Skipf("sibling gateway/cmd/hasyncd not present: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "nodesync-geoip-e2e-*")
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

	geoipDir := filepath.Join(tmpDir, "peer-geoip")
	secretFile := filepath.Join(tmpDir, "hasync.secret")
	stampFile := filepath.Join(tmpDir, "health.json")
	if err := os.WriteFile(secretFile, []byte(testSharedSecretHex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := probeLn.Addr().String()
	_ = probeLn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proc := exec.CommandContext(ctx, binPath,
		"--listen", listenAddr,
		"--node", "gw-standby",
		"--secret-file", secretFile,
		"--geoip-dir", geoipDir,
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

	store := newMemNodeStore(NodeCredential{
		NodeID:               uuid.New(),
		NodeName:             "gw-standby",
		SyncAgentAddr:        "http://" + listenAddr,
		SyncSecretCiphertext: "enc:" + testSharedSecretHex,
		SyncEnabled:          true,
	})
	mgr := NewManager(store, fakeDecryptor{}, ManagerConfig{LocalNodeName: "gw-primary"})

	// Prepare local valid XDB v4 and MMDB files.
	xdbData := buildTestXDBv4("e2e-v1")
	xdbSum := sha256.Sum256(xdbData)
	xdbSHA := hex.EncodeToString(xdbSum[:])
	localXDB := filepath.Join(tmpDir, "ip2region_v4.xdb")
	if err := os.WriteFile(localXDB, xdbData, 0o600); err != nil {
		t.Fatal(err)
	}

	mmdbData := buildTestMMDB("e2e-city-v1")
	mmdbSum := sha256.Sum256(mmdbData)
	mmdbSHA := hex.EncodeToString(mmdbSum[:])
	localMMDB := filepath.Join(tmpDir, "city.mmdb")
	if err := os.WriteFile(localMMDB, mmdbData, 0o600); err != nil {
		t.Fatal(err)
	}

	// Push ip2region_v4 then dbip_city via Manager.
	rev1 := "20261128T084000Z-e2e00001"
	res1, err := mgr.PushGeoIPSlotToPeers(ctx, GeoIPSlotIP2RegionV4, localXDB, xdbSHA, rev1)
	if err != nil || len(res1) != 1 || !res1[0].OK || res1[0].SHA256 != xdbSHA {
		t.Fatalf("push ip2region_v4 failed: res=%+v err=%v", res1, err)
	}

	rev2 := "20261128T084100Z-e2e00002"
	res2, err := mgr.PushGeoIPSlotToPeers(ctx, GeoIPSlotDBIPCity, localMMDB, mmdbSHA, rev2)
	if err != nil || len(res2) != 1 || !res2[0].OK || res2[0].SHA256 != mmdbSHA {
		t.Fatalf("push dbip_city failed: res=%+v err=%v", res2, err)
	}

	// Corrupt file pushed through Client must be rejected by real hasyncd with 400.
	corruptPath := filepath.Join(tmpDir, "corrupt.mmdb")
	corruptData := bytes.Repeat([]byte("BAD"), 100)
	corruptSum := sha256.Sum256(corruptData)
	if err := os.WriteFile(corruptPath, corruptData, 0o600); err != nil {
		t.Fatal(err)
	}
	cli, _, err := mgr.ClientForNodeName(ctx, "gw-standby")
	if err != nil {
		t.Fatal(err)
	}
	_, err = cli.PushGeoIPSlot(ctx, GeoIPSlotCountry, corruptPath, hex.EncodeToString(corruptSum[:]), "20261128T084200Z-bad00001")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 APIError for corrupt mmdb, got %v", err)
	}

	// Verify peer status reports both valid slots and rev2.
	peerStatuses, err := mgr.ListPeerGeoIPStatus(ctx)
	if err != nil || len(peerStatuses) != 1 || !peerStatuses[0].Reachable || !peerStatuses[0].GeoIPReady {
		t.Fatalf("ListPeerGeoIPStatus failed: statuses=%+v err=%v", peerStatuses, err)
	}
	if peerStatuses[0].Revision != rev2 || len(peerStatuses[0].Slots) != 2 {
		t.Fatalf("unexpected peer status: %+v", peerStatuses[0])
	}
	if peerStatuses[0].Slots[GeoIPSlotIP2RegionV4].SHA256 != xdbSHA || peerStatuses[0].Slots[GeoIPSlotDBIPCity].SHA256 != mmdbSHA {
		t.Fatalf("unexpected peer slots: %+v", peerStatuses[0].Slots)
	}

	// Verify .revision.json written on standby matches apigeo.RevisionState schema.
	revRaw, err := os.ReadFile(filepath.Join(geoipDir, ".revision.json"))
	if err != nil {
		t.Fatalf("read standby .revision.json: %v", err)
	}
	var revObj struct {
		Revision  string    `json:"revision"`
		UpdatedAt time.Time `json:"updated_at"`
		Slots     map[string]struct {
			Filename   string    `json:"filename"`
			SHA256     string    `json:"sha256"`
			SizeBytes  int64     `json:"size_bytes"`
			SourceType string    `json:"source_type"`
			UpdatedAt  time.Time `json:"updated_at"`
		} `json:"slots"`
	}
	if err := json.Unmarshal(revRaw, &revObj); err != nil {
		t.Fatalf("unmarshal .revision.json: %v", err)
	}
	if revObj.Revision != rev2 || revObj.UpdatedAt.IsZero() || len(revObj.Slots) != 2 {
		t.Fatalf("unexpected standby .revision.json: %+v", revObj)
	}
	if revObj.Slots[GeoIPSlotIP2RegionV4].Filename != "ip2region_v4.xdb" || revObj.Slots[GeoIPSlotIP2RegionV4].SourceType != "HA_SYNC" {
		t.Fatalf("unexpected standby ip2region_v4 revision entry: %+v", revObj.Slots[GeoIPSlotIP2RegionV4])
	}
	if revObj.Slots[GeoIPSlotDBIPCity].Filename != "city.mmdb" || revObj.Slots[GeoIPSlotDBIPCity].SourceType != "HA_SYNC" {
		t.Fatalf("unexpected standby dbip_city revision entry: %+v", revObj.Slots[GeoIPSlotDBIPCity])
	}
}
