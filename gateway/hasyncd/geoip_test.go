package hasyncd

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
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

func newGeoIPTestEnv(t *testing.T, geoIPDir string, maxGeoIPBytes int64) *testEnv {
	t.Helper()
	env := newTestEnv(t)

	secretFile := filepath.Join(env.tmpDir, "hasync.secret")
	srv, err := NewServer(Config{
		NodeName:        "gw-b",
		SecretFile:      secretFile,
		CaddySocket:     env.caddySock,
		SidecarDir:      env.sidecarDir,
		HostctlDir:      env.hostctlDir,
		UpgradesDir:     env.upgradesDir,
		GeoIPDir:        geoIPDir,
		NodeIfacesLog:   env.ifacesLog,
		Version:         "1.20.1",
		MaxPackageBytes: 4096,
		MaxGeoIPBytes:   maxGeoIPBytes,
		NowFunc:         func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatalf("NewServer with GeoIPDir: %v", err)
	}
	env.ts.Close()
	env.srv = srv
	env.ts = httptest.NewServer(srv.Handler())
	t.Cleanup(env.ts.Close)
	return env
}

// buildSyntheticXDB builds a minimal valid ip2region XDB v2/v3 file (IPv4 or IPv6)
// passing both hasyncd fast validation and server/internal/apigeo.ParseXDB.
func buildSyntheticXDB(version, ipVersion uint16, tag string) []byte {
	buf := make([]byte, xdbMinFileSize)
	binary.LittleEndian.PutUint16(buf[0:2], version)
	binary.LittleEndian.PutUint16(buf[2:4], xdbIndexPolicyVector)
	if version >= 3 {
		binary.LittleEndian.PutUint16(buf[16:18], ipVersion)
		binary.LittleEndian.PutUint16(buf[18:20], 4)
	}

	region := []byte("中国|广东省|广州市|电信|CN|" + tag)
	dataPtr := uint32(len(buf))
	buf = append(buf, region...)

	segOff := uint32(len(buf))
	if ipVersion == 6 {
		var seg [xdbSegSizeV6]byte
		seg[0] = 0x24
		seg[1] = 0x00
		seg[16] = 0x24
		seg[17] = 0x00
		seg[31] = 0xff
		binary.LittleEndian.PutUint16(seg[32:34], uint16(len(region)))
		binary.LittleEndian.PutUint32(seg[34:38], dataPtr)
		buf = append(buf, seg[:]...)
		vOff := xdbHeaderSize + (0x24*256+0x00)*8
		binary.LittleEndian.PutUint32(buf[vOff:vOff+4], segOff)
		binary.LittleEndian.PutUint32(buf[vOff+4:vOff+8], segOff)
	} else {
		var seg [xdbSegSizeV4]byte
		binary.LittleEndian.PutUint32(seg[0:4], 0x72727200)
		binary.LittleEndian.PutUint32(seg[4:8], 0x727272ff)
		binary.LittleEndian.PutUint16(seg[8:10], uint16(len(region)))
		binary.LittleEndian.PutUint32(seg[10:14], dataPtr)
		buf = append(buf, seg[:]...)
		vOff := xdbHeaderSize + (114*256+114)*8
		binary.LittleEndian.PutUint32(buf[vOff:vOff+4], segOff)
		binary.LittleEndian.PutUint32(buf[vOff+4:vOff+8], segOff)
	}

	binary.LittleEndian.PutUint32(buf[8:12], segOff)
	binary.LittleEndian.PutUint32(buf[12:16], segOff)
	return buf
}

// buildSyntheticMMDB builds a minimal valid MaxMind DB v2 file containing
// search tree + 16-byte separator + "\xab\xcd\xefMaxMind.com" + valid MMDB metadata map.
func buildSyntheticMMDB(tag string) []byte {
	var buf bytes.Buffer
	// Minimal search tree: 1 node (record_size=24 -> 6 bytes) pointing to node_count (1 = not found).
	buf.Write([]byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01})
	// 16-byte data section separator.
	buf.Write(make([]byte, 16))
	// Tag payload inside data section so different versions have distinct SHA-256 digests.
	buf.WriteString("WDSP-MMDB-FIXTURE-" + tag)
	// Metadata marker.
	buf.Write(mmdbMetadataMarker)
	// Metadata map with 4 entries: node_count, record_size, binary_format_major_version, ip_version.
	buf.WriteByte((mmdbDataTypeMap << 5) | 4)
	writeMMDBStr := func(s string) {
		buf.WriteByte((2 << 5) | byte(len(s))) // dtUTF8 = 2
		buf.WriteString(s)
	}
	writeMMDBUint16 := func(v uint16) {
		buf.WriteByte((5 << 5) | 2) // dtUint16 = 5, 2 bytes big-endian
		buf.WriteByte(byte(v >> 8))
		buf.WriteByte(byte(v))
	}
	writeMMDBUint32 := func(v uint32) {
		buf.WriteByte((6 << 5) | 4) // dtUint32 = 6, 4 bytes big-endian
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		buf.Write(b[:])
	}
	writeMMDBStr("node_count")
	writeMMDBUint32(1)
	writeMMDBStr("record_size")
	writeMMDBUint16(24)
	writeMMDBStr("binary_format_major_version")
	writeMMDBUint16(2)
	writeMMDBStr("ip_version")
	writeMMDBUint16(6)
	return buf.Bytes()
}

func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestGeoIPRequiresHMACAuth(t *testing.T) {
	geoDir := filepath.Join(t.TempDir(), "geoip")
	env := newGeoIPTestEnv(t, geoDir, 0)

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/geoip/status"},
		{http.MethodPut, "/v1/geoip/slots/ip2region_v4"},
		{http.MethodPut, "/v1/geoip/slots/dbip_city"},
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

func TestGeoIPUnconfiguredReturns503FailClosed(t *testing.T) {
	// Default testEnv leaves GeoIPDir empty -> fail-closed 503.
	env := newTestEnv(t)

	resp := env.signedDo(http.MethodGet, "/v1/geoip/status", nil, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("GET /v1/geoip/status when unconfigured: got %d, want 503", resp.StatusCode)
	}

	payload := buildSyntheticMMDB("unconfigured")
	putResp := env.signedDo(http.MethodPut, "/v1/geoip/slots/country", payload, map[string]string{
		HeaderGeoIPSHA256:   sha256HexBytes(payload),
		HeaderGeoIPRevision: "20261128T080000Z-aaaa1111",
	})
	_ = putResp.Body.Close()
	if putResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("PUT /v1/geoip/slots/country when unconfigured: got %d, want 503", putResp.StatusCode)
	}
}

func TestGeoIPValidXDBAndMMDBUploadStatusAndRevisionJSON(t *testing.T) {
	geoDir := filepath.Join(t.TempDir(), "geoip")
	env := newGeoIPTestEnv(t, geoDir, 0)

	// Initial status before any slot file exists.
	initResp := env.signedDo(http.MethodGet, "/v1/geoip/status", nil, nil)
	var initSt GeoIPStatusResponse
	if err := json.NewDecoder(initResp.Body).Decode(&initSt); err != nil {
		t.Fatal(err)
	}
	_ = initResp.Body.Close()
	if initResp.StatusCode != http.StatusOK || initSt.Node != "gw-b" || !initSt.GeoIPReady || len(initSt.Slots) != 0 {
		t.Fatalf("unexpected initial status: code=%d resp=%+v", initResp.StatusCode, initSt)
	}

	// Upload valid XDB v3 IPv4 to ip2region_v4.
	xdbV4 := buildSyntheticXDB(3, 4, "v4-rev1")
	xdbV4SHA := sha256HexBytes(xdbV4)
	rev1 := "20261128T080100Z-1111aaaa"
	resp1 := env.signedDo(http.MethodPut, "/v1/geoip/slots/ip2region_v4", xdbV4, map[string]string{
		HeaderGeoIPSHA256:   xdbV4SHA,
		HeaderGeoIPRevision: rev1,
	})
	var push1 GeoIPSlotPushResponse
	if err := json.NewDecoder(resp1.Body).Decode(&push1); err != nil {
		t.Fatal(err)
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK || !push1.OK || push1.Slot != "ip2region_v4" ||
		push1.Filename != "ip2region_v4.xdb" || push1.SHA256 != xdbV4SHA ||
		push1.SizeBytes != int64(len(xdbV4)) || push1.Revision != rev1 {
		t.Fatalf("unexpected ip2region_v4 push response: code=%d resp=%+v", resp1.StatusCode, push1)
	}
	if fi, err := os.Stat(filepath.Join(geoDir, "ip2region_v4.xdb")); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("ip2region_v4.xdb stat/perm failed: fi=%v err=%v", fi, err)
	}

	// Upload valid XDB v3 IPv6 to ip2region_v6 and valid MMDB to dbip_city concurrently.
	xdbV6 := buildSyntheticXDB(3, 6, "v6-rev2")
	xdbV6SHA := sha256HexBytes(xdbV6)
	mmdbCity := buildSyntheticMMDB("city-rev2")
	mmdbCitySHA := sha256HexBytes(mmdbCity)
	rev2 := "20261128T080200Z-2222bbbb"

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r := env.signedDo(http.MethodPut, "/v1/geoip/slots/ip2region_v6", xdbV6, map[string]string{
			HeaderGeoIPSHA256:   xdbV6SHA,
			HeaderGeoIPRevision: rev2,
		})
		_ = r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Errorf("ip2region_v6 upload status=%d", r.StatusCode)
		}
	}()
	go func() {
		defer wg.Done()
		r := env.signedDo(http.MethodPut, "/v1/geoip/slots/dbip_city", mmdbCity, map[string]string{
			HeaderGeoIPSHA256:   mmdbCitySHA,
			HeaderGeoIPRevision: rev2,
		})
		_ = r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Errorf("dbip_city upload status=%d", r.StatusCode)
		}
	}()
	wg.Wait()

	// Verify .revision.json matches apigeo.RevisionState schema with all 3 slots preserved.
	revRaw, err := os.ReadFile(filepath.Join(geoDir, ".revision.json"))
	if err != nil {
		t.Fatalf("read .revision.json: %v", err)
	}
	var revState geoIPRevisionState
	if err := json.Unmarshal(revRaw, &revState); err != nil {
		t.Fatalf("unmarshal .revision.json: %v", err)
	}
	if revState.Revision != rev2 || revState.UpdatedAt.IsZero() || len(revState.Slots) != 3 {
		t.Fatalf("unexpected .revision.json: %+v", revState)
	}
	if revState.Slots["ip2region_v4"].SHA256 != xdbV4SHA || revState.Slots["ip2region_v4"].SourceType != "HA_SYNC" {
		t.Fatalf("unexpected ip2region_v4 revision entry: %+v", revState.Slots["ip2region_v4"])
	}
	if revState.Slots["ip2region_v6"].Filename != "ip2region_v6.xdb" || revState.Slots["ip2region_v6"].SHA256 != xdbV6SHA {
		t.Fatalf("unexpected ip2region_v6 revision entry: %+v", revState.Slots["ip2region_v6"])
	}
	if revState.Slots["dbip_city"].Filename != "city.mmdb" || revState.Slots["dbip_city"].SHA256 != mmdbCitySHA {
		t.Fatalf("unexpected dbip_city revision entry: %+v", revState.Slots["dbip_city"])
	}

	// Verify GET /v1/geoip/status reports all 3 slots accurately.
	stResp := env.signedDo(http.MethodGet, "/v1/geoip/status", nil, nil)
	var st GeoIPStatusResponse
	if err := json.NewDecoder(stResp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	_ = stResp.Body.Close()
	if stResp.StatusCode != http.StatusOK || !st.GeoIPReady || st.Revision != rev2 || st.UpdatedAt == nil || len(st.Slots) != 3 {
		t.Fatalf("unexpected status after upload: code=%d resp=%+v", stResp.StatusCode, st)
	}
	if st.Slots["dbip_city"].Filename != "city.mmdb" || st.Slots["dbip_city"].SHA256 != mmdbCitySHA || st.Slots["dbip_city"].SizeBytes != int64(len(mmdbCity)) {
		t.Fatalf("unexpected dbip_city slot meta: %+v", st.Slots["dbip_city"])
	}

	// Staging dir must have zero leftover temp files.
	stagingEntries, _ := os.ReadDir(filepath.Join(geoDir, ".staging"))
	if len(stagingEntries) != 0 {
		t.Fatalf("expected clean .staging dir, found %v", stagingEntries)
	}
}

func TestGeoIPRejectsSHA256MismatchInvalidHeadersAndTamperedBody(t *testing.T) {
	geoDir := filepath.Join(t.TempDir(), "geoip")
	env := newGeoIPTestEnv(t, geoDir, 0)

	mmdb := buildSyntheticMMDB("valid")
	validSHA := sha256HexBytes(mmdb)

	// 1. Missing X-GeoIP-SHA256 -> 400.
	resp := env.signedDo(http.MethodPut, "/v1/geoip/slots/country", mmdb, map[string]string{
		HeaderGeoIPRevision: "20261128T080000Z-aaaa0001",
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing X-GeoIP-SHA256: got %d, want 400", resp.StatusCode)
	}

	// 2. X-GeoIP-SHA256 does not match body SHA-256 -> 400.
	resp = env.signedDo(http.MethodPut, "/v1/geoip/slots/country", mmdb, map[string]string{
		HeaderGeoIPSHA256:   strings.Repeat("f", 64),
		HeaderGeoIPRevision: "20261128T080000Z-aaaa0002",
	})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatched X-GeoIP-SHA256: got %d, want 400", resp.StatusCode)
	}

	// 3. Invalid X-GeoIP-Revision (missing, path traversal, whitespace) -> 400.
	for _, badRev := range []string{"", "../evil", "a/b", "rev with space", "-starts-dash"} {
		r := env.signedDo(http.MethodPut, "/v1/geoip/slots/country", mmdb, map[string]string{
			HeaderGeoIPSHA256:   validSHA,
			HeaderGeoIPRevision: badRev,
		})
		_ = r.Body.Close()
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("bad revision %q: got %d, want 400", badRev, r.StatusCode)
		}
	}

	// 4. Tampered stream: signed for validSHA and X-GeoIP-SHA256=validSHA, but body bytes altered -> 401.
	tampered := buildSyntheticMMDB("tampered-payload")
	req, _ := http.NewRequest(http.MethodPut, env.ts.URL+"/v1/geoip/slots/country", bytes.NewReader(tampered))
	tsStr := strconv.FormatInt(env.now.Unix(), 10)
	nonce := "abcdef0123456789abcdef0123456789"
	req.Header.Set(HeaderNode, "gw-a")
	req.Header.Set(HeaderTimestamp, tsStr)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderBodySHA256, validSHA)
	req.Header.Set(HeaderSignature, ComputeSignature(env.secret, http.MethodPut, "/v1/geoip/slots/country", tsStr, nonce, validSHA))
	req.Header.Set(HeaderGeoIPSHA256, validSHA)
	req.Header.Set(HeaderGeoIPRevision, "20261128T080000Z-aaaa0003")
	tResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = tResp.Body.Close()
	if tResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered stream: got %d, want 401", tResp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(geoDir, "country.mmdb")); !os.IsNotExist(err) {
		t.Fatalf("country.mmdb must not exist after rejected uploads")
	}
	if entries, _ := os.ReadDir(filepath.Join(geoDir, ".staging")); len(entries) != 0 {
		t.Fatalf("rejected upload left staging files: %v", entries)
	}
}

func TestGeoIPRejectsCorruptXDBMMDBAndOversizedPayloads(t *testing.T) {
	geoDir := filepath.Join(t.TempDir(), "geoip")
	// Set a small override cap (700 KiB) so oversized rejection is fast while valid synthetic XDB (~524 KiB) passes.
	env := newGeoIPTestEnv(t, geoDir, 700<<10)

	send := func(slot string, payload []byte) int {
		t.Helper()
		resp := env.signedDo(http.MethodPut, "/v1/geoip/slots/"+slot, payload, map[string]string{
			HeaderGeoIPSHA256:   sha256HexBytes(payload),
			HeaderGeoIPRevision: "20261128T080500Z-bad00001",
		})
		defer resp.Body.Close()
		_, _ = io.ReadAll(resp.Body)
		return resp.StatusCode
	}

	// XDB too small (< 524544 bytes).
	if code := send("ip2region_v4", bytes.Repeat([]byte("X"), 1024)); code != http.StatusBadRequest {
		t.Fatalf("tiny xdb: got %d, want 400", code)
	}

	// XDB unsupported version (version = 9).
	badVer := buildSyntheticXDB(3, 4, "badver")
	binary.LittleEndian.PutUint16(badVer[0:2], 9)
	if code := send("ip2region_v4", badVer); code != http.StatusBadRequest {
		t.Fatalf("bad xdb version: got %d, want 400", code)
	}

	// XDB unsupported index policy (policy = 2).
	badPolicy := buildSyntheticXDB(3, 4, "badpolicy")
	binary.LittleEndian.PutUint16(badPolicy[2:4], 2)
	if code := send("ip2region_v4", badPolicy); code != http.StatusBadRequest {
		t.Fatalf("bad xdb policy: got %d, want 400", code)
	}

	// XDB out-of-bounds end index ptr.
	badPtr := buildSyntheticXDB(3, 4, "badptr")
	binary.LittleEndian.PutUint32(badPtr[12:16], uint32(len(badPtr)+100))
	if code := send("ip2region_v4", badPtr); code != http.StatusBadRequest {
		t.Fatalf("out-of-bounds xdb ptr: got %d, want 400", code)
	}

	// XDB IP version mismatch: IPv6 uploaded into ip2region_v4 slot, and IPv4 into ip2region_v6 slot.
	if code := send("ip2region_v4", buildSyntheticXDB(3, 6, "wrong-v6")); code != http.StatusBadRequest {
		t.Fatalf("v6 xdb in v4 slot: got %d, want 400", code)
	}
	if code := send("ip2region_v6", buildSyntheticXDB(2, 4, "wrong-v2")); code != http.StatusBadRequest {
		t.Fatalf("v2/v4 xdb in v6 slot: got %d, want 400", code)
	}

	// Corrupt MMDB: missing MaxMind marker.
	if code := send("dbip_city", bytes.Repeat([]byte("M"), 512)); code != http.StatusBadRequest {
		t.Fatalf("mmdb without marker: got %d, want 400", code)
	}

	// Corrupt MMDB: marker present but followed by non-map byte (0x00).
	badMeta := append(bytes.Repeat([]byte{0x01}, 64), mmdbMetadataMarker...)
	badMeta = append(badMeta, 0x00, 0x01, 0x02)
	if code := send("country", badMeta); code != http.StatusBadRequest {
		t.Fatalf("mmdb non-map metadata: got %d, want 400", code)
	}

	// Oversized payload (>700 KiB cap) -> 413 Request Entity Too Large.
	oversized := bytes.Repeat([]byte("A"), 750<<10)
	if code := send("country", oversized); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized payload: got %d, want 413", code)
	}

	// Ensure nothing was committed and staging is empty.
	if entries, _ := os.ReadDir(filepath.Join(geoDir, ".staging")); len(entries) != 0 {
		t.Fatalf("staging not cleaned after invalid uploads: %v", entries)
	}
}

func TestGeoIPRejectsInvalidSlotPathTraversalAndWrongMethods(t *testing.T) {
	geoDir := filepath.Join(t.TempDir(), "geoip")
	env := newGeoIPTestEnv(t, geoDir, 0)

	mmdb := buildSyntheticMMDB("slotcheck")
	headers := map[string]string{
		HeaderGeoIPSHA256:   sha256HexBytes(mmdb),
		HeaderGeoIPRevision: "20261128T080600Z-slot0001",
	}

	for _, badPath := range []string{
		"/v1/geoip/slots/unknown_slot",
		"/v1/geoip/slots/ip2region_v4.xdb",
		"/v1/geoip/slots/.revision.json",
		"/v1/geoip/slots/a/b",
		"/v1/geoip/slots/../etc/passwd",
		"/v1/geoip/slots/..%2Fevil",
	} {
		r := env.signedDo(http.MethodPut, badPath, mmdb, headers)
		_ = r.Body.Close()
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("PUT %s: got %d, want 400", badPath, r.StatusCode)
		}
	}

	// Method checks -> 405.
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/v1/geoip/status"},
		{http.MethodGet, "/v1/geoip/slots/country"},
		{http.MethodDelete, "/v1/geoip/slots/country"},
	} {
		r := env.signedDo(tc.method, tc.path, nil, nil)
		_ = r.Body.Close()
		if r.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s: got %d, want 405", tc.method, tc.path, r.StatusCode)
		}
	}
}

func TestGeoIPBackupRetentionCapAndLegacyArchive(t *testing.T) {
	geoDir := filepath.Join(t.TempDir(), "geoip")
	if err := os.MkdirAll(geoDir, 0o750); err != nil {
		t.Fatal(err)
	}
	env := newGeoIPTestEnv(t, geoDir, 0)

	// Seed legacy shadowed filenames for dbip_city.
	legacyDBIP := buildSyntheticMMDB("legacy-dbip-2026-10")
	legacyMaxMind := buildSyntheticMMDB("legacy-geolite2-city")
	legacyDBIPPath := filepath.Join(geoDir, "dbip-city-lite-2026-10.mmdb")
	legacyMaxMindPath := filepath.Join(geoDir, "GeoLite2-City.mmdb")
	if err := os.WriteFile(legacyDBIPPath, legacyDBIP, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyMaxMindPath, legacyMaxMind, 0o640); err != nil {
		t.Fatal(err)
	}

	// Push canonical dbip_city -> should archive both legacy files to .backups/dbip_city and remove them from geoDir.
	cityV1 := buildSyntheticMMDB("city-canonical-v1")
	r := env.signedDo(http.MethodPut, "/v1/geoip/slots/dbip_city", cityV1, map[string]string{
		HeaderGeoIPSHA256:   sha256HexBytes(cityV1),
		HeaderGeoIPRevision: "20261128T081000Z-city0001",
	})
	_ = r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("dbip_city upload status=%d", r.StatusCode)
	}
	if _, err := os.Stat(legacyDBIPPath); !os.IsNotExist(err) {
		t.Fatalf("legacy dbip-city-lite file should have been removed after archive")
	}
	if _, err := os.Stat(legacyMaxMindPath); !os.IsNotExist(err) {
		t.Fatalf("legacy GeoLite2-City.mmdb should have been removed after archive")
	}
	if _, err := os.Stat(filepath.Join(geoDir, "city.mmdb")); err != nil {
		t.Fatalf("canonical city.mmdb missing: %v", err)
	}
	cityBackups, err := os.ReadDir(filepath.Join(geoDir, ".backups", "dbip_city"))
	if err != nil {
		t.Fatalf("read dbip_city backups: %v", err)
	}
	if len(cityBackups) != 2 {
		t.Fatalf("expected 2 archived legacy backups in .backups/dbip_city, got %d (%v)", len(cityBackups), cityBackups)
	}

	// Upload 5 distinct versions of country advancing clock 1s per push -> backups capped at 3 newest!
	for i := 1; i <= 5; i++ {
		env.now = env.now.Add(1 * time.Second)
		data := buildSyntheticMMDB("country-v" + strconv.Itoa(i))
		resp := env.signedDo(http.MethodPut, "/v1/geoip/slots/country", data, map[string]string{
			HeaderGeoIPSHA256:   sha256HexBytes(data),
			HeaderGeoIPRevision: "20261128T08100" + strconv.Itoa(i) + "Z-cnt0000" + strconv.Itoa(i),
		})
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("country upload v%d: status=%d", i, resp.StatusCode)
		}
	}

	countryBackups, err := os.ReadDir(filepath.Join(geoDir, ".backups", "country"))
	if err != nil {
		t.Fatalf("read country backups: %v", err)
	}
	if len(countryBackups) != geoIPMaxBackups {
		t.Fatalf("expected %d backups (cap), got %d", geoIPMaxBackups, len(countryBackups))
	}
	// Verify every backup name conforms to apigeo.SlotManager rollback backupIDPattern.
	for _, b := range countryBackups {
		if !geoIPBackupIDRE.MatchString(b.Name()) {
			t.Fatalf("backup name %q does not match apigeo rollback pattern", b.Name())
		}
	}
	// Verify oldest version (v1) was pruned while v2, v3, v4 remain backed up (v5 is active).
	v1Short := sha256HexBytes(buildSyntheticMMDB("country-v1"))[:12]
	for _, b := range countryBackups {
		if strings.Contains(b.Name(), v1Short) {
			t.Fatalf("oldest backup v1 (%s) should have been pruned, found %q", v1Short, b.Name())
		}
	}
}
