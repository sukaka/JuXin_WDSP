package backups

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
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/rulepacks"
)

func buildSignedRulePackArchiveForTest(t *testing.T, version string, priv ed25519.PrivateKey) []byte {
	t.Helper()
	files := map[string][]byte{
		"rules/coraza.conf":                                       []byte("SecRuleEngine On\n"),
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

func TestTablesIncludeWafRulePacksAndTopology(t *testing.T) {
	expected := map[string]string{
		"waf_rule_packs":            GroupConfig,
		"waf_rule_pack_jobs":        GroupAudit,
		"waf_rule_pack_node_states": GroupAudit,
	}
	for name, wantGroup := range expected {
		td, ok := TableByName(name)
		if !ok {
			t.Fatalf("missing rulepack table %q from Tables", name)
		}
		if td.Group != wantGroup {
			t.Errorf("table %q group = %q, want %q", name, td.Group, wantGroup)
		}
	}
	order, err := RestoreOrder([]string{"waf_rule_packs", "users"})
	if err != nil {
		t.Fatalf("RestoreOrder error: %v", err)
	}
	if len(order) != 2 || order[0] != "users" || order[1] != "waf_rule_packs" {
		t.Fatalf("unexpected restore order: %v", order)
	}
}

func TestRulePackArchiveInclusionWalkAndExtract(t *testing.T) {
	enc := testEnc(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	packID := uuid.New()
	archiveBytes := buildSignedRulePackArchiveForTest(t, "20261201.1", priv)
	archiveDir := filepath.Join(dataDir, RulePackArchivesDirName)
	if err := os.MkdirAll(archiveDir, 0o750); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(archiveDir, packID.String()+".tar.gz")
	if err := os.WriteFile(archivePath, archiveBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	art, err := rulepacks.VerifyArchiveFileWithKey(archivePath, "1.20.0", pub)
	if err != nil {
		t.Fatalf("verify test archive: %v", err)
	}

	resolved, err := ResolveRulePackArchivePath(dataDir, packID, "")
	if err != nil || resolved != archivePath {
		t.Fatalf("ResolveRulePackArchivePath = (%q, %v), want %q", resolved, err, archivePath)
	}

	backupPath := filepath.Join(dataDir, "full-with-rulepack.jzbk")
	backupID := uuid.NewString()
	w, err := CreateWriterWithID(backupPath, enc, backupID)
	if err != nil {
		t.Fatal(err)
	}
	gzw := gzip.NewWriter(w)
	tw := tar.NewWriter(gzw)

	row := []byte(`{"id":"r1"}` + "\n")
	rowSum := sha256.Sum256(row)
	if err := tw.WriteHeader(&tar.Header{Name: SegmentEntryName("roles"), Mode: 0o600, Size: int64(len(row))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(row); err != nil {
		t.Fatal(err)
	}
	rpMeta, err := WriteRulePackArchiveEntry(tw, RulePackArchiveMeta{
		PackID:          packID.String(),
		RulePackVersion: "20261201.1",
		CRSVersion:      "4.28.0",
		FileName:        "jiuzhang-wdsp-rulepack-20261201.1.tar.gz",
		EntryName:       RulePackArchiveEntryName,
		FileSHA256:      art.FileSHA256,
		ManifestSHA256:  art.ManifestSHA256,
	}, resolved)
	if err != nil {
		t.Fatalf("WriteRulePackArchiveEntry: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}
	m := &Manifest{
		Format:         FormatName,
		FormatVersion:  FormatVersion,
		BackupID:       backupID,
		BackupType:     TypeFull,
		CreatedAt:      time.Now().UTC(),
		SchemaVersion:  255,
		AppComponent:   "test",
		Compression:    "gzip",
		ArchiveFormat:  "tar",
		Tables:         []TableManifest{{Name: "roles", Group: GroupDatabase, Columns: []string{"id"}, RowCount: 1, ByteCount: int64(len(row)), SHA256: hex.EncodeToString(rowSum[:])}},
		TotalRows:      1,
		ActiveRulePack: rpMeta,
	}
	if _, _, err := w.Finish(m); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	ex := &Exporter{enc: enc, dataDir: dataDir}
	var gotTableRows int64
	if err := ex.WalkSegments(backupPath, func(mm *Manifest) error {
		if mm.ActiveRulePack == nil || mm.ActiveRulePack.RulePackVersion != "20261201.1" {
			t.Fatalf("unexpected manifest ActiveRulePack: %+v", mm.ActiveRulePack)
		}
		return nil
	}, func(_ string, r io.Reader) error {
		rows, _, _, err := statSegment(r)
		gotTableRows += rows
		return err
	}); err != nil {
		t.Fatalf("WalkSegments: %v", err)
	}
	if gotTableRows != 1 {
		t.Fatalf("gotTableRows = %d, want 1", gotTableRows)
	}

	extractDir := t.TempDir()
	em, err := ex.Extract(backupPath, extractDir)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if em.ActiveRulePack == nil || em.ActiveRulePack.RulePackVersion != "20261201.1" {
		t.Fatalf("extracted manifest missing ActiveRulePack: %+v", em.ActiveRulePack)
	}
	extractedArchive := filepath.Join(extractDir, ExtractedRulePackFileName)
	reVerified, err := rulepacks.VerifyArchiveFileWithKey(extractedArchive, "1.20.0", pub)
	if err != nil {
		t.Fatalf("VerifyArchiveFileWithKey on extracted rulepack: %v", err)
	}
	if reVerified.FileSHA256 != art.FileSHA256 || reVerified.Manifest.RulePackVersion != "20261201.1" {
		t.Fatalf("extracted archive metadata mismatch: %+v", reVerified)
	}
}

func TestRulePackArchiveValidationAndFailClosedChecks(t *testing.T) {
	enc := testEnc(t)
	dir := t.TempDir()
	ex := &Exporter{enc: enc, dataDir: dir}

	// 1. ResolveRulePackArchivePath rejects symlinks and outside paths
	linkPackID := uuid.New()
	archiveDir := filepath.Join(dir, RulePackArchivesDirName)
	if err := os.MkdirAll(archiveDir, 0o750); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside.tar.gz")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(archiveDir, linkPackID.String()+".tar.gz")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveRulePackArchivePath(dir, linkPackID, outside); !errors.Is(err, ErrBadFile) {
		t.Fatalf("expected ErrBadFile for symlink rulepack archive, got %v", err)
	}

	// 2. Manifest.Validate rejects invalid ActiveRulePack metadata
	validMeta := func() *RulePackArchiveMeta {
		return &RulePackArchiveMeta{
			PackID:          uuid.NewString(),
			RulePackVersion: "20261201.1",
			EntryName:       RulePackArchiveEntryName,
			FileSize:        128,
			FileSHA256:      strings.Repeat("a", 64),
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*RulePackArchiveMeta)
	}{
		{"builtin version", func(r *RulePackArchiveMeta) { r.RulePackVersion = "builtin-1.20.0" }},
		{"bad entry name", func(r *RulePackArchiveMeta) { r.EntryName = "../evil.tar.gz" }},
		{"bad uuid", func(r *RulePackArchiveMeta) { r.PackID = "not-a-uuid" }},
		{"zero size", func(r *RulePackArchiveMeta) { r.FileSize = 0 }},
		{"oversized", func(r *RulePackArchiveMeta) { r.FileSize = rulepacks.MaxArchiveBytes + 1 }},
		{"bad sha256", func(r *RulePackArchiveMeta) { r.FileSHA256 = "short" }},
	} {
		meta := validMeta()
		tc.mutate(meta)
		if err := meta.Validate(); err == nil {
			t.Errorf("%s: expected validation error", tc.name)
		}
	}

	// 3. Backup with declared ActiveRulePack but missing tar entry must fail closed
	missingPath := filepath.Join(dir, "missing-rp.jzbk")
	w, err := CreateWriter(missingPath, enc)
	if err != nil {
		t.Fatal(err)
	}
	gzw := gzip.NewWriter(w)
	tw := tar.NewWriter(gzw)
	row := []byte(`{"id":"r1"}` + "\n")
	rowSum := sha256.Sum256(row)
	_ = tw.WriteHeader(&tar.Header{Name: SegmentEntryName("roles"), Mode: 0o600, Size: int64(len(row))})
	_, _ = tw.Write(row)
	_ = tw.Close()
	_ = gzw.Close()
	m := &Manifest{
		Format: FormatName, FormatVersion: FormatVersion, BackupID: uuid.NewString(),
		BackupType: TypeFull, CreatedAt: time.Now().UTC(), SchemaVersion: 255,
		AppComponent: "test", Compression: "gzip", ArchiveFormat: "tar",
		Tables:         []TableManifest{{Name: "roles", Group: GroupDatabase, Columns: []string{"id"}, RowCount: 1, ByteCount: int64(len(row)), SHA256: hex.EncodeToString(rowSum[:])}},
		TotalRows:      1,
		ActiveRulePack: validMeta(),
	}
	if _, _, err := w.Finish(m); err != nil {
		t.Fatal(err)
	}
	if err := ex.WalkSegments(missingPath, nil, nil); !errors.Is(err, ErrManifestInvalid) {
		t.Fatalf("missing rulepack tar entry: want ErrManifestInvalid, got %v", err)
	}

	// 4. Backup with unexpected rulepack tar entry not declared in manifest must fail closed
	unexpPath := filepath.Join(dir, "unexpected-rp.jzbk")
	w2, err := CreateWriter(unexpPath, enc)
	if err != nil {
		t.Fatal(err)
	}
	gzw2 := gzip.NewWriter(w2)
	tw2 := tar.NewWriter(gzw2)
	_ = tw2.WriteHeader(&tar.Header{Name: SegmentEntryName("roles"), Mode: 0o600, Size: int64(len(row))})
	_, _ = tw2.Write(row)
	_ = tw2.WriteHeader(&tar.Header{Name: RulePackArchiveEntryName, Mode: 0o600, Size: 4})
	_, _ = tw2.Write([]byte("evil"))
	_ = tw2.Close()
	_ = gzw2.Close()
	m2 := &Manifest{
		Format: FormatName, FormatVersion: FormatVersion, BackupID: uuid.NewString(),
		BackupType: TypeFull, CreatedAt: time.Now().UTC(), SchemaVersion: 255,
		AppComponent: "test", Compression: "gzip", ArchiveFormat: "tar",
		Tables:    []TableManifest{{Name: "roles", Group: GroupDatabase, Columns: []string{"id"}, RowCount: 1, ByteCount: int64(len(row)), SHA256: hex.EncodeToString(rowSum[:])}},
		TotalRows: 1,
	}
	if _, _, err := w2.Finish(m2); err != nil {
		t.Fatal(err)
	}
	if err := ex.WalkSegments(unexpPath, nil, nil); !errors.Is(err, ErrBadFile) {
		t.Fatalf("unexpected rulepack tar entry: want ErrBadFile, got %v", err)
	}
}
