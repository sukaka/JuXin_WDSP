package upgrades

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestUpgradesRejectsRulePackArchive(t *testing.T) {
	files := []manifestFile{{Path: "rules/coraza.conf", Size: 5, SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}}
	fj, _ := json.Marshal(files)
	fsum := sha256.Sum256(fj)

	manifest := packageManifest{
		Product:             "wdsp",
		PackageType:         "rulepack",
		Version:             "20261201.1",
		Arch:                runtime.GOARCH,
		Files:               files,
		FilesManifestSHA256: hex.EncodeToString(fsum[:]),
	}
	mBytes, _ := json.Marshal(manifest)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o644, Size: int64(len(mBytes)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(mBytes)
	_ = tw.WriteHeader(&tar.Header{Name: "rules/coraza.conf", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hello"))
	_ = tw.Close()
	_ = gz.Close()

	if _, err := readPackageManifestInfo(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "rulepack") {
		t.Fatalf("readPackageManifestInfo should reject package_type=rulepack, got: %v", err)
	}
	pkg := &Package{VersionTo: "20261201.1"}
	if _, _, err := verifyPackageArchive(buf.Bytes(), pkg); err == nil || !strings.Contains(err.Error(), "rulepack") {
		t.Fatalf("verifyPackageArchive should reject package_type=rulepack, got: %v", err)
	}
}
