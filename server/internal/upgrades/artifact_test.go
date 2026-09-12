package upgrades

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

type testArchiveEntry struct {
	name string
	data []byte
}

func testManifest(t *testing.T, version string, files map[string][]byte) []byte {
	t.Helper()
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	listed := make([]manifestFile, 0, len(paths))
	for _, path := range paths {
		hash := sha256.Sum256(files[path])
		listed = append(listed, manifestFile{
			Path:   path,
			SHA256: hex.EncodeToString(hash[:]),
			Size:   int64(len(files[path])),
		})
	}
	filesJSON, err := json.Marshal(listed)
	if err != nil {
		t.Fatal(err)
	}
	filesDigest := sha256.Sum256(filesJSON)
	manifest, err := json.Marshal(packageManifest{
		Product:             "wdsp",
		Version:             version,
		Arch:                runtime.GOARCH,
		Files:               listed,
		FilesManifestSHA256: hex.EncodeToString(filesDigest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func writeSignedTestArtifact(t *testing.T, path, version string, entries []testArchiveEntry) (Package, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gz)
	for _, entry := range entries {
		if err := tarWriter.WriteHeader(&tar.Header{
			Name: entry.name,
			Mode: 0o600,
			Size: int64(len(entry.data)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	content := archive.Bytes()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, content)
	encodedSignature := base64.StdEncoding.EncodeToString(signature)
	if err := os.WriteFile(path+".sig", []byte(encodedSignature), 0o600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(content)
	return Package{
		FileName:    filepath.Base(path),
		VersionFrom: "2.0.0",
		VersionTo:   version,
		FileHash:    hex.EncodeToString(hash[:]),
		FileSize:    int64(len(content)),
	}, publicKey, privateKey
}

func TestVerifyPackageArtifactWithKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jiuzhang-offline-2.1.0.tar.gz")
	payload := []byte("signed payload")
	manifest := testManifest(t, "2.1.0", map[string][]byte{"payload/app.bin": payload})
	pkg, publicKey, _ := writeSignedTestArtifact(t, path, "2.1.0", []testArchiveEntry{
		{name: "release-2.1.0/manifest.json", data: manifest},
		{name: "release-2.1.0/payload/app.bin", data: payload},
	})

	if err := verifyPackageArtifactWithKey(path, &pkg, publicKey); err != nil {
		t.Fatalf("合法升级包验证失败: %v", err)
	}
}

func TestVerifyPackageArtifactRejectsInvalidSignature(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jiuzhang-offline-2.1.0.tar.gz")
	payload := []byte("signed payload")
	manifest := testManifest(t, "2.1.0", map[string][]byte{"payload/app.bin": payload})
	pkg, publicKey, privateKey := writeSignedTestArtifact(t, path, "2.1.0", []testArchiveEntry{
		{name: "release/manifest.json", data: manifest},
		{name: "release/payload/app.bin", data: payload},
	})
	badSignature := ed25519.Sign(privateKey, []byte("different content"))
	if err := os.WriteFile(path+".sig", []byte(base64.StdEncoding.EncodeToString(badSignature)), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := verifyPackageArtifactWithKey(path, &pkg, publicKey); err == nil {
		t.Fatal("错误签名应被拒绝")
	}
}

func TestVerifyPackageArtifactRejectsManifestContentMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jiuzhang-offline-2.1.0.tar.gz")
	original := []byte("original payload")
	manifest := testManifest(t, "2.1.0", map[string][]byte{"payload/app.bin": original})
	pkg, publicKey, _ := writeSignedTestArtifact(t, path, "2.1.0", []testArchiveEntry{
		{name: "release/manifest.json", data: manifest},
		{name: "release/payload/app.bin", data: []byte("tampered payload")},
	})

	if err := verifyPackageArtifactWithKey(path, &pkg, publicKey); err == nil {
		t.Fatal("manifest 与归档内容不一致时应被拒绝")
	}
}

func TestVerifyPackageArtifactRejectsUnsafeArchiveLayouts(t *testing.T) {
	tests := []struct {
		name    string
		entries func(t *testing.T) []testArchiveEntry
	}{
		{
			name: "mixed roots",
			entries: func(t *testing.T) []testArchiveEntry {
				payload := []byte("payload")
				return []testArchiveEntry{
					{name: "release-a/manifest.json", data: testManifest(t, "2.1.0", map[string][]byte{"payload/app.bin": payload})},
					{name: "release-b/payload/app.bin", data: payload},
				}
			},
		},
		{
			name: "archive traversal",
			entries: func(t *testing.T) []testArchiveEntry {
				return []testArchiveEntry{{name: "release/../manifest.json", data: []byte("{}")}}
			},
		},
		{
			name: "manifest traversal",
			entries: func(t *testing.T) []testArchiveEntry {
				payload := []byte("payload")
				return []testArchiveEntry{
					{name: "release/manifest.json", data: testManifest(t, "2.1.0", map[string][]byte{"../escape": payload})},
					{name: "release/payload/app.bin", data: payload},
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "jiuzhang-offline-2.1.0.tar.gz")
			pkg, publicKey, _ := writeSignedTestArtifact(t, path, "2.1.0", test.entries(t))
			if err := verifyPackageArtifactWithKey(path, &pkg, publicKey); err == nil {
				t.Fatal("不安全归档布局应被拒绝")
			}
		})
	}
}
