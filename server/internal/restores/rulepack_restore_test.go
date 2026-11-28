package restores

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
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/backups"
	"github.com/jiuzhang-waf/server/internal/encryption"
	"github.com/jiuzhang-waf/server/internal/rulepacks"
)

func testEncryptionService(t *testing.T) *encryption.Service {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	svc, err := encryption.NewWithKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func buildSignedRulePackBytes(t *testing.T, version string, priv ed25519.PrivateKey) []byte {
	t.Helper()
	files := map[string][]byte{
		"rules/coraza.conf":                                       []byte("SecRuleEngine On\n# " + version + "\n"),
		"rules/crs/VERSION.txt":                                   []byte("4.28.0\n"),
		"rules/crs/crs-setup.conf":                                []byte("SecDefaultAction \"phase:1,log,auditlog,pass\"\n"),
		"rules/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf": []byte("SecRule ARGS \"@contains union\" \"id:942100,phase:2,block,msg:'SQLi'\"\n"),
		"rules/exclusions/before-crs.conf":                        []byte("# before\n"),
		"rules/exclusions/after-crs.conf":                         []byte("# after\n"),
		"rules/jiuzhang/jiuzhang-custom.conf":                     []byte("# custom\n"),
		"rules/jiuzhang/post-contrib-blocking.conf":               []byte("SecRule TX:INBOUND_ANOMALY_SCORE \"@ge 5\" \"id:9000101,phase:2,deny,status:403\"\n"),
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	manifest := rulepacks.Manifest{
		SchemaVersion:    rulepacks.SchemaVersion,
		Product:          rulepacks.ProductWDSP,
		PackageType:      rulepacks.PackageTypeRulePack,
		RulePackVersion:  version,
		CRSVersion:       "4.28.0",
		MinSystemVersion: "1.19.0",
	}
	for _, p := range paths {
		sum := sha256.Sum256(files[p])
		manifest.Files = append(manifest.Files, rulepacks.ManifestFile{
			Path:   p,
			SHA256: hex.EncodeToString(sum[:]),
			Size:   int64(len(files[p])),
		})
	}
	fj, err := json.Marshal(manifest.Files)
	if err != nil {
		t.Fatal(err)
	}
	fd := sha256.Sum256(fj)
	manifest.FilesManifestSHA256 = hex.EncodeToString(fd[:])
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sigRaw := ed25519.Sign(priv, manifestBytes)
	sigB64 := []byte(base64.StdEncoding.EncodeToString(sigRaw) + "\n")

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	writeReg := func(name string, data []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o640, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	writeReg("manifest.json", manifestBytes)
	writeReg("manifest.sig", sigB64)
	for _, p := range paths {
		writeReg(p, files[p])
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildFullBackupWithRulePack(
	t *testing.T,
	enc *encryption.Service,
	dir string,
	packID uuid.UUID,
	declaredVersion string,
	archiveBytes []byte,
	manifestSHA string,
) string {
	t.Helper()
	srcArchive := filepath.Join(dir, "src-"+uuid.NewString()+".tar.gz")
	if err := os.WriteFile(srcArchive, archiveBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	fileSum := sha256.Sum256(archiveBytes)

	backupID := uuid.NewString()
	backupPath := filepath.Join(dir, "backup-"+backupID+".jzbk")
	w, err := backups.CreateWriterWithID(backupPath, enc, backupID)
	if err != nil {
		t.Fatal(err)
	}
	gzw := gzip.NewWriter(w)
	tw := tar.NewWriter(gzw)
	row := []byte(`{"id":"r1"}` + "\n")
	rowSum := sha256.Sum256(row)
	if err := tw.WriteHeader(&tar.Header{Name: backups.SegmentEntryName("roles"), Mode: 0o600, Size: int64(len(row))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(row); err != nil {
		t.Fatal(err)
	}
	rpMeta, err := backups.WriteRulePackArchiveEntry(tw, backups.RulePackArchiveMeta{
		PackID:          packID.String(),
		RulePackVersion: declaredVersion,
		CRSVersion:      "4.28.0",
		FileName:        "jiuzhang-wdsp-rulepack-" + declaredVersion + ".tar.gz",
		EntryName:       backups.RulePackArchiveEntryName,
		FileSHA256:      hex.EncodeToString(fileSum[:]),
		ManifestSHA256:  manifestSHA,
	}, srcArchive)
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}
	m := &backups.Manifest{
		Format:         backups.FormatName,
		FormatVersion:  backups.FormatVersion,
		BackupID:       backupID,
		BackupType:     backups.TypeFull,
		CreatedAt:      time.Now().UTC(),
		SchemaVersion:  255,
		AppComponent:   "test",
		Compression:    "gzip",
		ArchiveFormat:  "tar",
		Tables:         []backups.TableManifest{{Name: "roles", Group: backups.GroupDatabase, Columns: []string{"id"}, RowCount: 1, ByteCount: int64(len(row)), SHA256: hex.EncodeToString(rowSum[:])}},
		TotalRows:      1,
		ActiveRulePack: rpMeta,
	}
	if _, _, err := w.Finish(m); err != nil {
		t.Fatal(err)
	}
	return backupPath
}

func TestRestoreRulePackFromBackupVerifiesAndExtracts(t *testing.T) {
	enc := testEncryptionService(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	rulesStoreDir := filepath.Join(dataDir, "rules")
	packID := uuid.New()
	archiveBytes := buildSignedRulePackBytes(t, "20261201.1", priv)
	art, err := rulepacks.VerifyArchiveBytesWithKey(archiveBytes, "1.20.0", pub)
	if err != nil {
		t.Fatalf("verify fixture archive: %v", err)
	}
	backupPath := buildFullBackupWithRulePack(t, enc, dataDir, packID, "20261201.1", archiveBytes, art.ManifestSHA256)

	ex := backups.NewExporter(nil, enc, dataDir)
	svc := NewService(nil, nil, nil, ex, dataDir, nil, nil)
	svc.SetRulesStoreDir(rulesStoreDir)
	svc.SetRulePackVerifyKeyForTest(pub)

	restoredVer, err := svc.RestoreRulePackFromBackup(backupPath, ScopeFull)
	if err != nil {
		t.Fatalf("RestoreRulePackFromBackup: %v", err)
	}
	if restoredVer != "20261201.1" {
		t.Fatalf("restoredVer = %q, want 20261201.1", restoredVer)
	}

	linkTarget, err := os.Readlink(filepath.Join(rulesStoreDir, "current"))
	if err != nil {
		t.Fatalf("readlink current: %v", err)
	}
	if linkTarget != filepath.Join("releases", "20261201.1") {
		t.Fatalf("current symlink = %q, want releases/20261201.1", linkTarget)
	}
	storage := rulepacks.NewStorage(rulesStoreDir, filepath.Join(dataDir, backups.RulePackArchivesDirName))
	if !storage.HasRelease("20261201.1") {
		t.Fatal("expected staged release 20261201.1 to have all anchor files")
	}
	persisted := filepath.Join(dataDir, backups.RulePackArchivesDirName, packID.String()+".tar.gz")
	st, err := os.Stat(persisted)
	if err != nil || st.Size() != int64(len(archiveBytes)) {
		t.Fatalf("persisted archive invalid: stat=%v err=%v", st, err)
	}

	// Non-rulepack scope (DATABASE) must not touch rulesStoreDir
	otherStore := filepath.Join(dataDir, "rules-untouched")
	svc.SetRulesStoreDir(otherStore)
	verDB, err := svc.RestoreRulePackFromBackup(backupPath, ScopeDatabase)
	if err != nil || verDB != "" {
		t.Fatalf("ScopeDatabase should skip rulepack restore, got (%q, %v)", verDB, err)
	}
	if _, err := os.Stat(otherStore); !os.IsNotExist(err) {
		t.Fatalf("ScopeDatabase should not create rules dir, stat err = %v", err)
	}
}

func TestRestoreRulePackFromBackupRejectsWrongSignatureAndVersionMismatch(t *testing.T) {
	enc := testEncryptionService(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	dataDir := t.TempDir()
	packID := uuid.New()
	archiveBytes := buildSignedRulePackBytes(t, "20261201.1", priv)
	art, err := rulepacks.VerifyArchiveBytesWithKey(archiveBytes, "1.20.0", pub)
	if err != nil {
		t.Fatal(err)
	}
	backupPath := buildFullBackupWithRulePack(t, enc, dataDir, packID, "20261201.1", archiveBytes, art.ManifestSHA256)

	// 1. Wrong Ed25519 verification key -> fail closed, rulesStoreDir remains untouched
	rulesDir1 := filepath.Join(dataDir, "rules-wrong-key")
	ex := backups.NewExporter(nil, enc, dataDir)
	svc := NewService(nil, nil, nil, ex, dataDir, nil, nil)
	svc.SetRulesStoreDir(rulesDir1)
	svc.SetRulePackVerifyKeyForTest(wrongPub)
	if _, err := svc.RestoreRulePackFromBackup(backupPath, ScopeFull); !errors.Is(err, rulepacks.ErrInvalidSignature) {
		t.Fatalf("wrong Ed25519 key: want ErrInvalidSignature, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(rulesDir1, "current")); !os.IsNotExist(err) {
		t.Fatalf("current symlink must not be created on signature failure")
	}

	// 2. Version mismatch between backup manifest ActiveRulePack and signed rulepack manifest.json -> fail closed
	mismatchBackup := buildFullBackupWithRulePack(t, enc, dataDir, uuid.New(), "20261202.1", archiveBytes, art.ManifestSHA256)
	rulesDir2 := filepath.Join(dataDir, "rules-version-mismatch")
	svc.SetRulesStoreDir(rulesDir2)
	svc.SetRulePackVerifyKeyForTest(pub)
	if _, err := svc.RestoreRulePackFromBackup(mismatchBackup, ScopeFull); !errors.Is(err, rulepacks.ErrInvalidArchive) {
		t.Fatalf("version mismatch: want ErrInvalidArchive, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(rulesDir2, "current")); !os.IsNotExist(err) {
		t.Fatalf("current symlink must not be created on version mismatch")
	}
}
