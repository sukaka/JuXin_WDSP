package rulepacks

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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const repoRulesRoot = "../../../gateway/rules"

// buildSignedRulePackFromDir 将指定规则目录按生产协议打成签名 tar.gz（支持通过 mutate 钩子构造故障夹具）。
func buildSignedRulePackFromDir(
	t *testing.T,
	rulesDir string,
	version, crsVersion, minSysVer string,
	priv ed25519.PrivateKey,
	mutate func(manifest *Manifest, files map[string][]byte, extraEntries *[]tarFixtureEntry),
) []byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(rulesDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || d.Name() == ".DS_Store" {
			return nil
		}
		rel, err := filepath.Rel(rulesDir, p)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files["rules/"+filepath.ToSlash(rel)] = raw
		return nil
	})
	if err != nil {
		t.Fatalf("walk rules dir: %v", err)
	}

	var extraEntries []tarFixtureEntry
	manifest := Manifest{
		SchemaVersion:    SchemaVersion,
		Product:          ProductWDSP,
		PackageType:      PackageTypeRulePack,
		RulePackVersion:  version,
		CRSVersion:       crsVersion,
		MinSystemVersion: minSysVer,
		CorazaCompat:     ">=3.7.0 <4.0.0",
		Changelog:        []string{"测试规则包 " + version},
	}

	if mutate != nil {
		mutate(&manifest, files, &extraEntries)
	}

	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	if len(manifest.Files) == 0 {
		for _, p := range paths {
			sum := sha256.Sum256(files[p])
			manifest.Files = append(manifest.Files, ManifestFile{
				Path:   p,
				SHA256: hex.EncodeToString(sum[:]),
				Size:   int64(len(files[p])),
			})
		}
	}
	if manifest.FilesManifestSHA256 == "" {
		fj, err := json.Marshal(manifest.Files)
		if err != nil {
			t.Fatalf("marshal manifest files: %v", err)
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
		sigRaw := ed25519.Sign(priv, manifestBytes)
		sigB64 = []byte(base64.StdEncoding.EncodeToString(sigRaw) + "\n")
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	writeTar := func(name string, data []byte, typeflag byte, linkname string) {
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

	writeTar("manifest.json", manifestBytes, tar.TypeReg, "")
	if priv != nil {
		writeTar("manifest.sig", sigB64, tar.TypeReg, "")
	}
	for _, p := range paths {
		writeTar(p, files[p], tar.TypeReg, "")
	}
	for _, ex := range extraEntries {
		writeTar(ex.name, ex.data, ex.typeflag, ex.linkname)
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

type tarFixtureEntry struct {
	name     string
	data     []byte
	typeflag byte
	linkname string
}

// makeMinimalRulesTree 在临时目录构造最小合法规则目录，加快安全红线单测执行。
func makeMinimalRulesTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"coraza.conf":                                       "SecRuleEngine DetectionOnly\n",
		"crs/VERSION.txt":                                   "4.28.0\n",
		"crs/crs-setup.conf":                                "SecDefaultAction \"phase:1,log,auditlog,pass\"\n",
		"crs/rules/REQUEST-901-INITIALIZATION.conf":         "SecRule REQUEST_URI \"@contains test-init\" \"id:901001,phase:1,pass,msg:'Init rule',tag:'attack-protocol',severity:'NOTICE'\"\n",
		"crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf": "SecRule ARGS \"@pmFromFile sql-test.data\" \"id:942100,phase:2,block,msg:'SQLi test',tag:'attack-sqli',severity:'CRITICAL'\"\n",
		"crs/rules/sql-test.data":                           "union select\n",
		"contrib/CUSTOM_PACK/cve-emergency.conf":            "SecRule REQUEST_URI \"@contains /cve-2026-9999\" \"id:1000090,phase:2,block,msg:'CVE-2026-9999 Test',tag:'attack-rce',severity:'CRITICAL'\"\n",
		"exclusions/before-crs.conf":                        "# before\n",
		"exclusions/after-crs.conf":                         "# after\n",
		"jiuzhang/jiuzhang-custom.conf":                     "# custom\n",
		"jiuzhang/post-contrib-blocking.conf":               "SecRule TX:INBOUND_ANOMALY_SCORE \"@ge 5\" \"id:9000101,phase:2,deny,status:403,msg:'Post blocking',severity:'CRITICAL'\"\n",
	}
	for rel, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(body), 0o640); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return dir
}

func TestVersionValidationAndComparison(t *testing.T) {
	valid := []string{"20261201.1", "20261201.10", "20260228.999"}
	for _, v := range valid {
		if err := ValidateRulePackVersion(v); err != nil {
			t.Errorf("expected valid version %q, got %v", v, err)
		}
	}
	invalid := []string{"", "20261201", "20261301.1", "20261201.0", "20261201.1000", "1.19.1", "builtin-1.19.1", "../20261201.1"}
	for _, v := range invalid {
		if err := ValidateRulePackVersion(v); err == nil {
			t.Errorf("expected invalid version %q to fail", v)
		}
	}

	cases := []struct {
		a, b string
		want int
	}{
		{"builtin-1.19.1", "20261201.1", -1},
		{"20261201.1", "builtin-1.19.1", 1},
		{"20261201.2", "20261201.10", -1},
		{"20261215.1", "20261201.99", 1},
		{"20261201.1", "20261201.1", 0},
	}
	for _, tc := range cases {
		got, err := CompareRulePackVersion(tc.a, tc.b)
		if err != nil {
			t.Fatalf("CompareRulePackVersion(%s, %s): %v", tc.a, tc.b, err)
		}
		if got != tc.want {
			t.Errorf("CompareRulePackVersion(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestVerifyAndStaticGateAgainstRealRepoRules(t *testing.T) {
	if _, err := os.Stat(filepath.Join(repoRulesRoot, "coraza.conf")); err != nil {
		t.Skip("repo gateway/rules not accessible")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	raw := buildSignedRulePackFromDir(t, repoRulesRoot, "20261201.1", "4.28.0", "1.19.1", priv, nil)
	archivePath := filepath.Join(t.TempDir(), "jiuzhang-wdsp-rulepack-20261201.1.tar.gz")
	if err := os.WriteFile(archivePath, raw, 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	art, err := VerifyArchiveFileWithKey(archivePath, "1.19.1", pub)
	if err != nil {
		t.Fatalf("VerifyArchiveFileWithKey real repo rules failed: %v", err)
	}
	if art.Manifest.RulePackVersion != "20261201.1" || art.Manifest.CRSVersion != "4.28.0" {
		t.Fatalf("unexpected manifest metadata: %+v", art.Manifest)
	}

	dest := filepath.Join(t.TempDir(), "extracted")
	if err := ExtractRulesToDir(archivePath, dest); err != nil {
		t.Fatalf("ExtractRulesToDir failed: %v", err)
	}
	staticRes, err := StaticGateCheckDir(dest)
	if err != nil {
		t.Fatalf("StaticGateCheckDir real repo rules failed: %v", err)
	}
	if len(staticRes.Rules) < 500 {
		t.Fatalf("expected >500 parsed rules from real repo, got %d", len(staticRes.Rules))
	}
}

func TestArtifactSecurityRedlines(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	minDir := makeMinimalRulesTree(t)

	t.Run("wrong public key rejected", func(t *testing.T) {
		raw := buildSignedRulePackFromDir(t, minDir, "20261201.1", "4.28.0", "1.19.1", priv, nil)
		_, err := VerifyArchiveBytesWithKey(raw, "1.19.1", otherPub)
		if !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("want ErrInvalidSignature, got %v", err)
		}
	})

	t.Run("missing signature rejected", func(t *testing.T) {
		raw := buildSignedRulePackFromDir(t, minDir, "20261201.1", "4.28.0", "1.19.1", nil, nil)
		_, err := VerifyArchiveBytesWithKey(raw, "1.19.1", pub)
		if !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("want ErrInvalidSignature, got %v", err)
		}
	})

	t.Run("upgrade package_type rejected", func(t *testing.T) {
		raw := buildSignedRulePackFromDir(t, minDir, "20261201.1", "4.28.0", "1.19.1", priv, func(m *Manifest, _ map[string][]byte, _ *[]tarFixtureEntry) {
			m.PackageType = "upgrade"
		})
		_, err := VerifyArchiveBytesWithKey(raw, "1.19.1", pub)
		if !errors.Is(err, ErrInvalidArchive) {
			t.Fatalf("want ErrInvalidArchive, got %v", err)
		}
	})

	t.Run("incompatible min_system_version rejected", func(t *testing.T) {
		raw := buildSignedRulePackFromDir(t, minDir, "20261201.1", "4.28.0", "9.9.9", priv, nil)
		_, err := VerifyArchiveBytesWithKey(raw, "1.19.1", pub)
		if !errors.Is(err, ErrIncompatibleSystem) {
			t.Fatalf("want ErrIncompatibleSystem, got %v", err)
		}
	})

	t.Run("symlink inside tar rejected", func(t *testing.T) {
		raw := buildSignedRulePackFromDir(t, minDir, "20261201.1", "4.28.0", "1.19.1", priv, func(_ *Manifest, _ map[string][]byte, extra *[]tarFixtureEntry) {
			*extra = append(*extra, tarFixtureEntry{
				name:     "rules/evil-link.conf",
				typeflag: tar.TypeSymlink,
				linkname: "/etc/passwd",
			})
		})
		_, err := VerifyArchiveBytesWithKey(raw, "1.19.1", pub)
		if !errors.Is(err, ErrInvalidArchive) {
			t.Fatalf("want ErrInvalidArchive for symlink, got %v", err)
		}
	})

	t.Run("path traversal rejected", func(t *testing.T) {
		raw := buildSignedRulePackFromDir(t, minDir, "20261201.1", "4.28.0", "1.19.1", priv, func(_ *Manifest, _ map[string][]byte, extra *[]tarFixtureEntry) {
			*extra = append(*extra, tarFixtureEntry{
				name:     "rules/../../etc/evil.conf",
				data:     []byte("# bad"),
				typeflag: tar.TypeReg,
			})
		})
		_, err := VerifyArchiveBytesWithKey(raw, "1.19.1", pub)
		if !errors.Is(err, ErrInvalidArchive) {
			t.Fatalf("want ErrInvalidArchive for path traversal, got %v", err)
		}
	})

	t.Run("disallowed shell script extension rejected", func(t *testing.T) {
		raw := buildSignedRulePackFromDir(t, minDir, "20261201.1", "4.28.0", "1.19.1", priv, func(_ *Manifest, files map[string][]byte, _ *[]tarFixtureEntry) {
			files["rules/hijack.sh"] = []byte("#!/bin/sh\nid\n")
		})
		_, err := VerifyArchiveBytesWithKey(raw, "1.19.1", pub)
		if !errors.Is(err, ErrInvalidArchive) {
			t.Fatalf("want ErrInvalidArchive for .sh file, got %v", err)
		}
	})

	t.Run("missing anchor post-contrib-blocking rejected", func(t *testing.T) {
		raw := buildSignedRulePackFromDir(t, minDir, "20261201.1", "4.28.0", "1.19.1", priv, func(_ *Manifest, files map[string][]byte, _ *[]tarFixtureEntry) {
			delete(files, "rules/jiuzhang/post-contrib-blocking.conf")
		})
		_, err := VerifyArchiveBytesWithKey(raw, "1.19.1", pub)
		if !errors.Is(err, ErrInvalidArchive) {
			t.Fatalf("want ErrInvalidArchive for missing anchor, got %v", err)
		}
	})

	t.Run("tampered file hash mismatch rejected", func(t *testing.T) {
		raw := buildSignedRulePackFromDir(t, minDir, "20261201.1", "4.28.0", "1.19.1", priv, func(m *Manifest, files map[string][]byte, _ *[]tarFixtureEntry) {
			// 先按原始内容算清 manifest，再篡改文件字节但保持签名匹配 manifest
			paths := make([]string, 0, len(files))
			for p := range files {
				paths = append(paths, p)
			}
			sort.Strings(paths)
			for _, p := range paths {
				sum := sha256.Sum256(files[p])
				m.Files = append(m.Files, ManifestFile{Path: p, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(files[p]))})
			}
			files["rules/coraza.conf"] = []byte("SecRuleEngine Off\n")
		})
		_, err := VerifyArchiveBytesWithKey(raw, "1.19.1", pub)
		if !errors.Is(err, ErrInvalidArchive) {
			t.Fatalf("want ErrInvalidArchive for hash mismatch, got %v", err)
		}
	})
}

func TestStaticGateRejections(t *testing.T) {
	t.Run("rejects forbidden @inspectFile", func(t *testing.T) {
		dir := makeMinimalRulesTree(t)
		bad := filepath.Join(dir, "contrib/CUSTOM_PACK/bad.conf")
		_ = os.WriteFile(bad, []byte("SecRule FILES_TMPNAMES \"@inspectFile /usr/bin/scan\" \"id:1009901,phase:2,deny\"\n"), 0o640)
		_, err := StaticGateCheckDir(dir)
		if !errors.Is(err, ErrStaticGateFailed) || !strings.Contains(err.Error(), "inspectFile") {
			t.Fatalf("expected ErrStaticGateFailed for @inspectFile, got %v", err)
		}
	})

	t.Run("rejects forbidden SecRuleScript", func(t *testing.T) {
		dir := makeMinimalRulesTree(t)
		bad := filepath.Join(dir, "contrib/CUSTOM_PACK/lua.conf")
		_ = os.WriteFile(bad, []byte("SecRuleScript /etc/evil.lua \"id:1009902,phase:2,deny\"\n"), 0o640)
		_, err := StaticGateCheckDir(dir)
		if !errors.Is(err, ErrStaticGateFailed) {
			t.Fatalf("expected ErrStaticGateFailed for SecRuleScript, got %v", err)
		}
	})

	t.Run("rejects missing @pmFromFile data file", func(t *testing.T) {
		dir := makeMinimalRulesTree(t)
		bad := filepath.Join(dir, "contrib/CUSTOM_PACK/pm.conf")
		_ = os.WriteFile(bad, []byte("SecRule ARGS \"@pmFromFile nonexistent.data\" \"id:1009903,phase:2,block,msg:'missing data'\"\n"), 0o640)
		_, err := StaticGateCheckDir(dir)
		if !errors.Is(err, ErrStaticGateFailed) || !strings.Contains(err.Error(), "nonexistent.data") {
			t.Fatalf("expected ErrStaticGateFailed for missing pmFromFile, got %v", err)
		}
	})

	t.Run("rejects duplicate rule ID across files", func(t *testing.T) {
		dir := makeMinimalRulesTree(t)
		dup := filepath.Join(dir, "contrib/CUSTOM_PACK/dup.conf")
		_ = os.WriteFile(dup, []byte("SecRule ARGS \"@contains x\" \"id:942100,phase:2,block,msg:'duplicate'\"\n"), 0o640)
		_, err := StaticGateCheckDir(dir)
		if !errors.Is(err, ErrStaticGateFailed) || !strings.Contains(err.Error(), "942100") {
			t.Fatalf("expected ErrStaticGateFailed for duplicate rule ID 942100, got %v", err)
		}
	})
}
