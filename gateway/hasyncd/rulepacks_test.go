package hasyncd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type rpTarEntry struct {
	name     string
	data     []byte
	typeflag byte
	linkname string
}

func minimalRulePackFiles() map[string][]byte {
	return map[string][]byte{
		"rules/coraza.conf":                                       []byte("SecRuleEngine DetectionOnly\n"),
		"rules/crs/VERSION.txt":                                   []byte("4.28.0\n"),
		"rules/crs/crs-setup.conf":                                []byte("SecDefaultAction \"phase:1,log,auditlog,pass\"\n"),
		"rules/crs/rules/REQUEST-901-INITIALIZATION.conf":         []byte("SecRule REQUEST_URI \"@contains init\" \"id:901001,phase:1,pass\"\n"),
		"rules/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf": []byte("SecRule ARGS \"@pmFromFile sql.data\" \"id:942100,phase:2,block\"\n"),
		"rules/crs/rules/sql.data":                                []byte("union select\n"),
		"rules/exclusions/before-crs.conf":                        []byte("# before\n"),
		"rules/exclusions/after-crs.conf":                         []byte("# after\n"),
		"rules/jiuzhang/jiuzhang-custom.conf":                     []byte("# custom\n"),
		"rules/jiuzhang/post-contrib-blocking.conf":               []byte("SecRule TX:INBOUND_ANOMALY_SCORE \"@ge 5\" \"id:9000101,phase:2,deny,status:403\"\n"),
	}
}

func buildSignedTestRulePack(
	t *testing.T,
	version string,
	priv ed25519.PrivateKey,
	mutate func(m *rulePackManifest, files map[string][]byte, extra *[]rpTarEntry),
	postSignMutate func(manifestBytes *[]byte, sigB64 *[]byte),
) (archiveBytes []byte, archiveSHA256 string, manifestSHA256 string) {
	t.Helper()
	files := minimalRulePackFiles()
	var extra []rpTarEntry
	manifest := rulePackManifest{
		SchemaVersion:    rulePackSchemaVersion,
		Product:          rulePackProductWDSP,
		PackageType:      rulePackPackageType,
		RulePackVersion:  version,
		CRSVersion:       "4.28.0",
		MinSystemVersion: "1.19.1",
	}
	if mutate != nil {
		mutate(&manifest, files, &extra)
	}

	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	if len(manifest.Files) == 0 {
		for _, p := range paths {
			sum := sha256.Sum256(files[p])
			manifest.Files = append(manifest.Files, rulePackManifestFile{
				Path:   p,
				SHA256: hex.EncodeToString(sum[:]),
				Size:   int64(len(files[p])),
			})
		}
	}
	if manifest.FilesManifestSHA256 == "" {
		fj, err := json.Marshal(manifest.Files)
		if err != nil {
			t.Fatalf("marshal files: %v", err)
		}
		d := sha256.Sum256(fj)
		manifest.FilesManifestSHA256 = hex.EncodeToString(d[:])
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	var sigB64 []byte
	if priv != nil {
		sig := ed25519.Sign(priv, manifestBytes)
		sigB64 = []byte(base64.StdEncoding.EncodeToString(sig) + "\n")
	}
	if postSignMutate != nil {
		postSignMutate(&manifestBytes, &sigB64)
	}

	mSum := sha256.Sum256(manifestBytes)
	manifestSHA256 = hex.EncodeToString(mSum[:])

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	writeEntry := func(name string, data []byte, typeflag byte, linkname string) {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o640,
			Size:     int64(len(data)),
			Typeflag: typeflag,
			Linkname: linkname,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header %s: %v", name, err)
		}
		if len(data) > 0 {
			if _, err := tw.Write(data); err != nil {
				t.Fatalf("write tar body %s: %v", name, err)
			}
		}
	}
	writeEntry("manifest.json", manifestBytes, tar.TypeReg, "")
	if len(sigB64) > 0 {
		writeEntry("manifest.sig", sigB64, tar.TypeReg, "")
	}
	for _, p := range paths {
		writeEntry(p, files[p], tar.TypeReg, "")
	}
	for _, ex := range extra {
		writeEntry(ex.name, ex.data, ex.typeflag, ex.linkname)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	archiveBytes = buf.Bytes()
	aSum := sha256.Sum256(archiveBytes)
	archiveSHA256 = hex.EncodeToString(aSum[:])
	return archiveBytes, archiveSHA256, manifestSHA256
}

type rulePackTestEnv struct {
	t        *testing.T
	tmpDir   string
	rulesDir string
	secret   []byte
	now      time.Time
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	srv      *Server
	ts       *httptest.Server
}

func newRulePackTestEnv(t *testing.T, withRulesDir bool, useProdKey bool, maxRulePackBytes int64) *rulePackTestEnv {
	t.Helper()
	tmpDir := t.TempDir()
	secret, err := ParseSecretHex(testSharedSecretHex)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var rulesDir string
	if withRulesDir {
		rulesDir = filepath.Join(tmpDir, "rules")
		if err := os.MkdirAll(rulesDir, 0o750); err != nil {
			t.Fatal(err)
		}
	}

	cfg := Config{
		NodeName:         "gw-b",
		SecretBytes:      secret,
		SidecarDir:       filepath.Join(tmpDir, "sidecars"),
		HostctlDir:       filepath.Join(tmpDir, "hostctl"),
		UpgradesDir:      filepath.Join(tmpDir, "upgrades"),
		RulesDir:         rulesDir,
		MaxRulePackBytes: maxRulePackBytes,
		Version:          "1.20.0",
		NowFunc:          func() time.Time { return time.Unix(1764000000, 0).UTC() },
	}
	if !useProdKey {
		cfg.RulePackVerifyKey = pub
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &rulePackTestEnv{
		t:        t,
		tmpDir:   tmpDir,
		rulesDir: rulesDir,
		secret:   secret,
		now:      time.Unix(1764000000, 0).UTC(),
		pub:      pub,
		priv:     priv,
		srv:      srv,
		ts:       ts,
	}
}

func (e *rulePackTestEnv) signedDo(method, path string, body []byte, extraHeaders map[string]string) *http.Response {
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

func TestRulePackAuthAndDisabledState(t *testing.T) {
	// 1. All 4 rulepack endpoints MUST reject unauthenticated requests with 401.
	env := newRulePackTestEnv(t, true, false, 0)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/v1/rulepacks/stage"},
		{http.MethodGet, "/v1/rulepacks/status"},
		{http.MethodPost, "/v1/rulepacks/activate"},
		{http.MethodDelete, "/v1/rulepacks/releases/20261201.1"},
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

	// 2. Wrong HTTP methods return 405.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/rulepacks/stage"},
		{http.MethodPost, "/v1/rulepacks/status"},
		{http.MethodGet, "/v1/rulepacks/activate"},
		{http.MethodGet, "/v1/rulepacks/releases/20261201.1"},
	} {
		resp := env.signedDo(tc.method, tc.path, nil, nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s wrong method: got %d, want 405", tc.method, tc.path, resp.StatusCode)
		}
	}

	// 3. When RulesDir is empty, /v1/health reports rulepack_ready=false and all 4 endpoints return 503.
	disabled := newRulePackTestEnv(t, false, false, 0)
	hResp := disabled.signedDo(http.MethodGet, "/v1/health", nil, nil)
	var health HealthResponse
	_ = json.NewDecoder(hResp.Body).Decode(&health)
	_ = hResp.Body.Close()
	if hResp.StatusCode != http.StatusOK || health.RulePackReady {
		t.Fatalf("expected rulepack_ready=false when RulesDir is empty, got status=%d health=%+v", hResp.StatusCode, health)
	}
	for _, tc := range []struct {
		method, path string
		body         []byte
	}{
		{http.MethodPost, "/v1/rulepacks/stage", []byte("x")},
		{http.MethodGet, "/v1/rulepacks/status", nil},
		{http.MethodPost, "/v1/rulepacks/activate", []byte(`{"version":"20261201.1"}`)},
		{http.MethodDelete, "/v1/rulepacks/releases/20261201.1", nil},
	} {
		resp := disabled.signedDo(tc.method, tc.path, tc.body, nil)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("%s %s when RulesDir empty: got %d, want 503", tc.method, tc.path, resp.StatusCode)
		}
	}
}

func TestRulePackHealthReadOnlyDirReportsNotReady(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("read-only chmod test requires non-root unix")
	}
	env := newRulePackTestEnv(t, true, false, 0)
	hResp1 := env.signedDo(http.MethodGet, "/v1/health", nil, nil)
	var h1 HealthResponse
	_ = json.NewDecoder(hResp1.Body).Decode(&h1)
	_ = hResp1.Body.Close()
	if !h1.RulePackReady {
		t.Fatalf("expected rulepack_ready=true on writable dir, got %+v", h1)
	}

	if err := os.Chmod(env.rulesDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(env.rulesDir, 0o750) })

	hResp2 := env.signedDo(http.MethodGet, "/v1/health", nil, nil)
	var h2 HealthResponse
	_ = json.NewDecoder(hResp2.Body).Decode(&h2)
	_ = hResp2.Body.Close()
	if h2.RulePackReady {
		t.Fatalf("expected rulepack_ready=false on read-only dir, got %+v", h2)
	}
}

func TestRulePackEmbeddedProdKeyRejectsEphemeralSignature(t *testing.T) {
	pub, err := ReleaseRulePackPublicKey()
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("ReleaseRulePackPublicKey failed: len=%d err=%v", len(pub), err)
	}
	// Server configured WITHOUT RulePackVerifyKey uses embedded production public key.
	env := newRulePackTestEnv(t, true, true, 0)
	raw, shaHex, _ := buildSignedTestRulePack(t, "20261201.1", env.priv, nil, nil)
	resp := env.signedDo(http.MethodPost, "/v1/rulepacks/stage", raw, map[string]string{
		HeaderRulePackVersion:       "20261201.1",
		HeaderRulePackPackageSHA256: shaHex,
	})
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "Ed25519") {
		t.Fatalf("expected 400 Ed25519 rejection from prod key, got %d body=%s", resp.StatusCode, string(body))
	}
	if _, err := os.Stat(filepath.Join(env.rulesDir, "releases", "20261201.1")); !os.IsNotExist(err) {
		t.Fatal("rejected archive must not be extracted into releases/")
	}
}

func TestRulePackStageSecurityRejections(t *testing.T) {
	env := newRulePackTestEnv(t, true, false, 0)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)

	stageExpect := func(name, headerVer string, raw []byte, headerSHA string, wantCode int) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			hdrs := map[string]string{}
			if headerVer != "" {
				hdrs[HeaderRulePackVersion] = headerVer
			}
			if headerSHA != "" {
				hdrs[HeaderRulePackPackageSHA256] = headerSHA
			}
			resp := env.signedDo(http.MethodPost, "/v1/rulepacks/stage", raw, hdrs)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != wantCode {
				t.Fatalf("got status %d (body=%s), want %d", resp.StatusCode, string(body), wantCode)
			}
		})
	}

	validRaw, validSHA, _ := buildSignedTestRulePack(t, "20261201.1", env.priv, nil, nil)

	stageExpect("missing version header", "", validRaw, validSHA, http.StatusBadRequest)
	stageExpect("builtin version header rejected", "builtin-1.20.0", validRaw, validSHA, http.StatusBadRequest)
	stageExpect("invalid date version header", "20261399.1", validRaw, validSHA, http.StatusBadRequest)
	stageExpect("missing package sha256 header", "20261201.1", validRaw, "", http.StatusBadRequest)
	stageExpect("mismatched package sha256 header", "20261201.1", validRaw, strings.Repeat("a", 64), http.StatusBadRequest)
	stageExpect("header version != manifest version", "20261202.1", validRaw, validSHA, http.StatusBadRequest)

	// Wrong signing key
	wrongKeyRaw, wrongKeySHA, _ := buildSignedTestRulePack(t, "20261201.1", otherPriv, nil, nil)
	stageExpect("wrong Ed25519 key", "20261201.1", wrongKeyRaw, wrongKeySHA, http.StatusBadRequest)

	// Missing manifest.sig
	noSigRaw, noSigSHA, _ := buildSignedTestRulePack(t, "20261201.1", nil, nil, nil)
	stageExpect("missing manifest.sig", "20261201.1", noSigRaw, noSigSHA, http.StatusBadRequest)

	// Tampered manifest after signing
	tamperedManifestRaw, tamperedManifestSHA, _ := buildSignedTestRulePack(t, "20261201.1", env.priv, nil, func(mb *[]byte, _ *[]byte) {
		*mb = append(*mb, ' ')
	})
	stageExpect("tampered manifest bytes", "20261201.1", tamperedManifestRaw, tamperedManifestSHA, http.StatusBadRequest)

	// Tampered file content (signed manifest still has original hash)
	tamperedFileRaw, tamperedFileSHA, _ := buildSignedTestRulePack(t, "20261201.1", env.priv, func(m *rulePackManifest, files map[string][]byte, _ *[]rpTarEntry) {
		paths := make([]string, 0, len(files))
		for p := range files {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			s := sha256.Sum256(files[p])
			m.Files = append(m.Files, rulePackManifestFile{Path: p, SHA256: hex.EncodeToString(s[:]), Size: int64(len(files[p]))})
		}
		files["rules/coraza.conf"] = []byte("SecRuleEngine Off\n")
	}, nil)
	stageExpect("tampered file hash mismatch", "20261201.1", tamperedFileRaw, tamperedFileSHA, http.StatusBadRequest)

	// package_type != rulepack
	upgradeTypeRaw, upgradeTypeSHA, _ := buildSignedTestRulePack(t, "20261201.1", env.priv, func(m *rulePackManifest, _ map[string][]byte, _ *[]rpTarEntry) {
		m.PackageType = "upgrade"
	}, nil)
	stageExpect("package_type!=rulepack", "20261201.1", upgradeTypeRaw, upgradeTypeSHA, http.StatusBadRequest)

	// product != wdsp
	wrongProdRaw, wrongProdSHA, _ := buildSignedTestRulePack(t, "20261201.1", env.priv, func(m *rulePackManifest, _ map[string][]byte, _ *[]rpTarEntry) {
		m.Product = "other"
	}, nil)
	stageExpect("product!=wdsp", "20261201.1", wrongProdRaw, wrongProdSHA, http.StatusBadRequest)

	// Symlink inside archive
	symlinkRaw, symlinkSHA, _ := buildSignedTestRulePack(t, "20261201.1", env.priv, func(_ *rulePackManifest, _ map[string][]byte, extra *[]rpTarEntry) {
		*extra = append(*extra, rpTarEntry{name: "rules/evil.conf", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"})
	}, nil)
	stageExpect("symlink inside archive", "20261201.1", symlinkRaw, symlinkSHA, http.StatusBadRequest)

	// Path traversal inside archive
	travRaw, travSHA, _ := buildSignedTestRulePack(t, "20261201.1", env.priv, func(_ *rulePackManifest, _ map[string][]byte, extra *[]rpTarEntry) {
		*extra = append(*extra, rpTarEntry{name: "rules/../../etc/evil.conf", data: []byte("# bad"), typeflag: tar.TypeReg})
	}, nil)
	stageExpect("path traversal inside archive", "20261201.1", travRaw, travSHA, http.StatusBadRequest)

	// Disallowed extension (.sh)
	shRaw, shSHA, _ := buildSignedTestRulePack(t, "20261201.1", env.priv, func(_ *rulePackManifest, files map[string][]byte, _ *[]rpTarEntry) {
		files["rules/evil.sh"] = []byte("#!/bin/sh\nid\n")
	}, nil)
	stageExpect("disallowed .sh extension", "20261201.1", shRaw, shSHA, http.StatusBadRequest)

	// Missing required anchor
	noAnchorRaw, noAnchorSHA, _ := buildSignedTestRulePack(t, "20261201.1", env.priv, func(_ *rulePackManifest, files map[string][]byte, _ *[]rpTarEntry) {
		delete(files, "rules/jiuzhang/post-contrib-blocking.conf")
	}, nil)
	stageExpect("missing required anchor", "20261201.1", noAnchorRaw, noAnchorSHA, http.StatusBadRequest)

	// Tampered files_manifest_sha256
	badFilesDigestRaw, badFilesDigestSHA, _ := buildSignedTestRulePack(t, "20261201.1", env.priv, func(m *rulePackManifest, _ map[string][]byte, _ *[]rpTarEntry) {
		m.FilesManifestSHA256 = strings.Repeat("b", 64)
	}, nil)
	stageExpect("bad files_manifest_sha256", "20261201.1", badFilesDigestRaw, badFilesDigestSHA, http.StatusBadRequest)

	// Body stream tampered relative to signed X-JZ-Body-SHA256 -> 401
	t.Run("stream body sha256 mismatch returns 401", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, env.ts.URL+"/v1/rulepacks/stage", bytes.NewReader([]byte("corrupted-stream")))
		tsStr := strconv.FormatInt(env.now.Unix(), 10)
		nonce := "abcdef0123456789abcdef0123456789"
		req.Header.Set(HeaderNode, "gw-a")
		req.Header.Set(HeaderTimestamp, tsStr)
		req.Header.Set(HeaderNonce, nonce)
		req.Header.Set(HeaderBodySHA256, validSHA)
		req.Header.Set(HeaderSignature, ComputeSignature(env.secret, http.MethodPost, "/v1/rulepacks/stage", tsStr, nonce, validSHA))
		req.Header.Set(HeaderRulePackVersion, "20261201.1")
		req.Header.Set(HeaderRulePackPackageSHA256, validSHA)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("got %d, want 401", resp.StatusCode)
		}
	})

	// Oversized archive returns 413
	t.Run("oversized archive returns 413", func(t *testing.T) {
		smallCapEnv := newRulePackTestEnv(t, true, false, 128)
		resp := smallCapEnv.signedDo(http.MethodPost, "/v1/rulepacks/stage", validRaw, map[string]string{
			HeaderRulePackVersion:       "20261201.1",
			HeaderRulePackPackageSHA256: validSHA,
		})
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("got %d, want 413", resp.StatusCode)
		}
	})

	// Ensure no release was committed from any failed test.
	if entries, _ := os.ReadDir(filepath.Join(env.rulesDir, "releases")); len(entries) != 0 {
		t.Fatalf("expected zero releases after rejected stages, got %v", entries)
	}
}

func TestRulePackLifecycleStageIdempotentConflictStatusActivateDelete(t *testing.T) {
	env := newRulePackTestEnv(t, true, false, 0)

	// Seed a builtin release on disk (as apply.sh / baremetal install does) to verify delete guards and rollback activation.
	builtinDir := filepath.Join(env.rulesDir, "releases", "builtin-1.19.1")
	for rel, content := range minimalRulePackFiles() {
		dst := filepath.Join(builtinDir, filepath.FromSlash(strings.TrimPrefix(rel, "rules/")))
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, content, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("releases/builtin-1.19.1", filepath.Join(env.rulesDir, "current")); err != nil {
		t.Fatal(err)
	}

	// 1. Stage v1 (20261201.1) -> 200 OK
	v1Raw, v1FileSHA, v1ManifestSHA := buildSignedTestRulePack(t, "20261201.1", env.priv, nil, nil)
	resp1 := env.signedDo(http.MethodPost, "/v1/rulepacks/stage", v1Raw, map[string]string{
		HeaderRulePackVersion:       "20261201.1",
		HeaderRulePackPackageSHA256: v1FileSHA,
	})
	var stage1 RulePackStageResponse
	_ = json.NewDecoder(resp1.Body).Decode(&stage1)
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK || !stage1.OK || stage1.Idempotent || stage1.ManifestSHA256 != v1ManifestSHA || stage1.FileSHA256 != v1FileSHA {
		t.Fatalf("stage v1 failed: status=%d resp=%+v", resp1.StatusCode, stage1)
	}

	// Verify permissions (0640) and no metadata file leaked inside releases/20261201.1/
	corazaInfo, err := os.Stat(filepath.Join(env.rulesDir, "releases", "20261201.1", "coraza.conf"))
	if err != nil {
		t.Fatalf("expected extracted coraza.conf: %v", err)
	}
	if corazaInfo.Mode().Perm() != 0o640 {
		t.Fatalf("coraza.conf mode=%04o want 0640", corazaInfo.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(env.rulesDir, "releases", "20261201.1", "manifest.json")); !os.IsNotExist(err) {
		t.Fatal("manifest.json must not be extracted into releases/<ver>/")
	}

	// 2. Idempotent re-stage of exact same v1 -> 200 OK with Idempotent=true
	resp1Again := env.signedDo(http.MethodPost, "/v1/rulepacks/stage", v1Raw, map[string]string{
		HeaderRulePackVersion:       "20261201.1",
		HeaderRulePackPackageSHA256: v1FileSHA,
	})
	var stage1Again RulePackStageResponse
	_ = json.NewDecoder(resp1Again.Body).Decode(&stage1Again)
	_ = resp1Again.Body.Close()
	if resp1Again.StatusCode != http.StatusOK || !stage1Again.OK || !stage1Again.Idempotent || stage1Again.ManifestSHA256 != v1ManifestSHA {
		t.Fatalf("idempotent re-stage failed: status=%d resp=%+v", resp1Again.StatusCode, stage1Again)
	}

	// 3. Conflicting stage of SAME version 20261201.1 with different content -> 409 Conflict
	v1ConflictRaw, v1ConflictSHA, _ := buildSignedTestRulePack(t, "20261201.1", env.priv, func(_ *rulePackManifest, files map[string][]byte, _ *[]rpTarEntry) {
		files["rules/jiuzhang/jiuzhang-custom.conf"] = []byte("# different content\n")
	}, nil)
	respConflict := env.signedDo(http.MethodPost, "/v1/rulepacks/stage", v1ConflictRaw, map[string]string{
		HeaderRulePackVersion:       "20261201.1",
		HeaderRulePackPackageSHA256: v1ConflictSHA,
	})
	_ = respConflict.Body.Close()
	if respConflict.StatusCode != http.StatusConflict {
		t.Fatalf("conflicting re-stage: got %d, want 409", respConflict.StatusCode)
	}

	// 4. Stage v2 (20261215.1) -> 200 OK
	v2Raw, v2FileSHA, v2ManifestSHA := buildSignedTestRulePack(t, "20261215.1", env.priv, nil, nil)
	resp2 := env.signedDo(http.MethodPost, "/v1/rulepacks/stage", v2Raw, map[string]string{
		HeaderRulePackVersion:       "20261215.1",
		HeaderRulePackPackageSHA256: v2FileSHA,
	})
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("stage v2: got %d, want 200", resp2.StatusCode)
	}

	// 5. GET /v1/rulepacks/status reports accurate active_symlink, staged_versions, releases, disk_free_bytes
	stResp := env.signedDo(http.MethodGet, "/v1/rulepacks/status", nil, nil)
	var st RulePackStatusResponse
	_ = json.NewDecoder(stResp.Body).Decode(&st)
	_ = stResp.Body.Close()
	if stResp.StatusCode != http.StatusOK || !st.RulesDirWritable || st.ActiveSymlink != "releases/builtin-1.19.1" || st.ActiveVersion != "builtin-1.19.1" {
		t.Fatalf("unexpected status: code=%d st=%+v", stResp.StatusCode, st)
	}
	if st.StagedVersions["20261201.1"] != v1ManifestSHA || st.StagedVersions["20261215.1"] != v2ManifestSHA {
		t.Fatalf("unexpected staged_versions: %+v", st.StagedVersions)
	}
	if _, hasBuiltin := st.StagedVersions["builtin-1.19.1"]; !hasBuiltin {
		t.Fatalf("expected builtin-1.19.1 in staged_versions: %+v", st.StagedVersions)
	}
	if st.DiskFreeBytes <= 0 {
		t.Fatalf("expected positive disk_free_bytes, got %d", st.DiskFreeBytes)
	}

	// 6. POST /v1/rulepacks/activate guards & atomic switch
	// Missing version -> 404
	actMissing := env.signedDo(http.MethodPost, "/v1/rulepacks/activate", []byte(`{"version":"20261231.1"}`), nil)
	_ = actMissing.Body.Close()
	if actMissing.StatusCode != http.StatusNotFound {
		t.Fatalf("activate missing: got %d, want 404", actMissing.StatusCode)
	}
	// Wrong manifest_sha256 -> 409
	actWrongSHA := env.signedDo(http.MethodPost, "/v1/rulepacks/activate", []byte(`{"version":"20261201.1","manifest_sha256":"`+strings.Repeat("f", 64)+`"}`), nil)
	_ = actWrongSHA.Body.Close()
	if actWrongSHA.StatusCode != http.StatusConflict {
		t.Fatalf("activate wrong manifest_sha256: got %d, want 409", actWrongSHA.StatusCode)
	}
	// Valid activate v1 -> 200 and relative symlink current -> releases/20261201.1
	actBody, _ := json.Marshal(RulePackActivateRequest{Version: "20261201.1", ManifestSHA256: v1ManifestSHA})
	actOK := env.signedDo(http.MethodPost, "/v1/rulepacks/activate", actBody, nil)
	var actRes RulePackActivateResponse
	_ = json.NewDecoder(actOK.Body).Decode(&actRes)
	_ = actOK.Body.Close()
	if actOK.StatusCode != http.StatusOK || !actRes.OK || actRes.ActiveSymlink != "releases/20261201.1" {
		t.Fatalf("activate v1 failed: status=%d resp=%+v", actOK.StatusCode, actRes)
	}
	linkTarget, err := os.Readlink(filepath.Join(env.rulesDir, "current"))
	if err != nil || linkTarget != "releases/20261201.1" {
		t.Fatalf("current symlink = %q (err=%v), want releases/20261201.1", linkTarget, err)
	}

	// 7. DELETE /v1/rulepacks/releases/{version} guards & cleanup
	// Refuse deleting active current release -> 409
	delActive := env.signedDo(http.MethodDelete, "/v1/rulepacks/releases/20261201.1", nil, nil)
	_ = delActive.Body.Close()
	if delActive.StatusCode != http.StatusConflict {
		t.Fatalf("delete active current: got %d, want 409", delActive.StatusCode)
	}
	// Refuse deleting builtin-* -> 409
	delBuiltin := env.signedDo(http.MethodDelete, "/v1/rulepacks/releases/builtin-1.19.1", nil, nil)
	_ = delBuiltin.Body.Close()
	if delBuiltin.StatusCode != http.StatusConflict {
		t.Fatalf("delete builtin: got %d, want 409", delBuiltin.StatusCode)
	}
	// Refuse invalid version regex -> 400
	delInvalid := env.signedDo(http.MethodDelete, "/v1/rulepacks/releases/not-a-version", nil, nil)
	_ = delInvalid.Body.Close()
	if delInvalid.StatusCode != http.StatusBadRequest {
		t.Fatalf("delete invalid version: got %d, want 400", delInvalid.StatusCode)
	}
	// Delete inactive v2 -> 200 deleted=true
	delV2 := env.signedDo(http.MethodDelete, "/v1/rulepacks/releases/20261215.1", nil, nil)
	var delRes RulePackDeleteResponse
	_ = json.NewDecoder(delV2.Body).Decode(&delRes)
	_ = delV2.Body.Close()
	if delV2.StatusCode != http.StatusOK || !delRes.OK || !delRes.Deleted {
		t.Fatalf("delete inactive v2: status=%d resp=%+v", delV2.StatusCode, delRes)
	}
	if _, err := os.Stat(filepath.Join(env.rulesDir, "releases", "20261215.1")); !os.IsNotExist(err) {
		t.Fatal("expected v2 release dir to be removed")
	}
	if _, err := os.Stat(filepath.Join(env.rulesDir, ".meta", "20261215.1.json")); !os.IsNotExist(err) {
		t.Fatal("expected v2 metadata file to be removed")
	}
	// Second delete of v2 -> idempotent 200 deleted=false
	delV2Again := env.signedDo(http.MethodDelete, "/v1/rulepacks/releases/20261215.1", nil, nil)
	var delRes2 RulePackDeleteResponse
	_ = json.NewDecoder(delV2Again.Body).Decode(&delRes2)
	_ = delV2Again.Body.Close()
	if delV2Again.StatusCode != http.StatusOK || !delRes2.OK || delRes2.Deleted {
		t.Fatalf("idempotent delete v2: status=%d resp=%+v", delV2Again.StatusCode, delRes2)
	}

	// Activate rollback to builtin-1.19.1 (empty manifest_sha256) succeeds and switches symlink cleanly.
	actBuiltin := env.signedDo(http.MethodPost, "/v1/rulepacks/activate", []byte(`{"version":"builtin-1.19.1"}`), nil)
	_ = actBuiltin.Body.Close()
	if actBuiltin.StatusCode != http.StatusOK {
		t.Fatalf("activate builtin rollback: got %d, want 200", actBuiltin.StatusCode)
	}
	linkTarget2, err := os.Readlink(filepath.Join(env.rulesDir, "current"))
	if err != nil || linkTarget2 != "releases/builtin-1.19.1" {
		t.Fatalf("rollback current symlink = %q (err=%v), want releases/builtin-1.19.1", linkTarget2, err)
	}
}
