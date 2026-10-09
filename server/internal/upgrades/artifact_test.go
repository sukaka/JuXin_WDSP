package upgrades

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	return testManifestWithProtocol(t, version, "", "", 0, files)
}

// testManifestWithProtocol 构造 manifest.json；from/to 非空时写入执行器协议
// 版本字段，targetSchema >0 时写入 target_schema_version。
func testManifestWithProtocol(t *testing.T, version, from, to string, targetSchema int, files map[string][]byte) []byte {
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
		VersionFrom:         from,
		VersionTo:           to,
		TargetSchemaVersion: targetSchema,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func writeTestArchive(t *testing.T, path string, entries []testArchiveEntry) []byte {
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
	return content
}

// writeEmbeddedTestArtifact 构造内嵌签名格式升级包：归档根目录含
// manifest.json 与 manifest.sig（对 manifest.json 原始字节的签名），无旁车 .sig。
func writeEmbeddedTestArtifact(t *testing.T, path, versionFrom, versionTo string, payload map[string][]byte) (Package, ed25519.PublicKey, ed25519.PrivateKey, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifestWithProtocol(t, versionTo, versionFrom, versionTo, 0, payload)
	signature := ed25519.Sign(privateKey, manifest)
	entries := []testArchiveEntry{
		{name: "release-" + versionTo + "/manifest.json", data: manifest},
		{name: "release-" + versionTo + "/manifest.sig", data: []byte(base64.StdEncoding.EncodeToString(signature) + "\n")},
	}
	names := make([]string, 0, len(payload))
	for name := range payload {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entries = append(entries, testArchiveEntry{name: "release-" + versionTo + "/" + name, data: payload[name]})
	}
	content := writeTestArchive(t, path, entries)
	hash := sha256.Sum256(content)
	return Package{
		FileName:    filepath.Base(path),
		VersionFrom: versionFrom,
		VersionTo:   versionTo,
		FileHash:    hex.EncodeToString(hash[:]),
		FileSize:    int64(len(content)),
	}, publicKey, privateKey, manifest
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

// ---------- 内嵌 manifest.sig 验签（新包格式） ----------

// TestVerifyPackageArtifactEmbeddedSignature 内嵌签名正例：无旁车 .sig，
// manifest.sig 对 manifest.json 原始字节验签通过。
func TestVerifyPackageArtifactEmbeddedSignature(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jiuzhang-offline-2.1.0.tar.gz")
	pkg, publicKey, _, _ := writeEmbeddedTestArtifact(t, path, "2.0.0", "2.1.0",
		map[string][]byte{"payload/app.bin": []byte("signed payload")})
	if _, err := os.Stat(path + ".sig"); !os.IsNotExist(err) {
		t.Fatal("内嵌签名格式不应依赖旁车 .sig")
	}

	if err := verifyPackageArtifactWithKey(path, &pkg, publicKey); err != nil {
		t.Fatalf("内嵌签名升级包验证失败: %v", err)
	}
}

// TestVerifyPackageArtifactRejectsBadEmbeddedSignature 内嵌签名与
// manifest.json 内容不匹配（签的是别的字节）必须拒绝。
func TestVerifyPackageArtifactRejectsBadEmbeddedSignature(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jiuzhang-offline-2.1.0.tar.gz")
	pkg, publicKey, privateKey, manifest := writeEmbeddedTestArtifact(t, path, "2.0.0", "2.1.0",
		map[string][]byte{"payload/app.bin": []byte("signed payload")})
	badSignature := ed25519.Sign(privateKey, []byte("different manifest"))
	payload := []byte("signed payload")
	writeTestArchive(t, path, []testArchiveEntry{
		{name: "release-2.1.0/manifest.json", data: manifest},
		{name: "release-2.1.0/manifest.sig", data: []byte(base64.StdEncoding.EncodeToString(badSignature))},
		{name: "release-2.1.0/payload/app.bin", data: payload},
	})
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(content)
	pkg.FileHash = hex.EncodeToString(hash[:])
	pkg.FileSize = int64(len(content))

	if err := verifyPackageArtifactWithKey(path, &pkg, publicKey); err == nil {
		t.Fatal("错误的内嵌签名应被拒绝")
	}
}

// TestVerifyPackageArtifactRejectsMalformedEmbeddedSignature manifest.sig
// 不是合法 base64 Ed25519 签名时必须拒绝（不得降级回落旁车）。
func TestVerifyPackageArtifactRejectsMalformedEmbeddedSignature(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jiuzhang-offline-2.1.0.tar.gz")
	payload := []byte("signed payload")
	manifest := testManifest(t, "2.1.0", map[string][]byte{"payload/app.bin": payload})
	writeTestArchive(t, path, []testArchiveEntry{
		{name: "release/manifest.json", data: manifest},
		{name: "release/manifest.sig", data: []byte("not-base64!!!")},
		{name: "release/payload/app.bin", data: payload},
	})
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(content)
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pkg := Package{
		FileName:    filepath.Base(path),
		VersionFrom: "2.0.0",
		VersionTo:   "2.1.0",
		FileHash:    hex.EncodeToString(hash[:]),
		FileSize:    int64(len(content)),
	}

	if err := verifyPackageArtifactWithKey(path, &pkg, publicKey); err == nil {
		t.Fatal("畸形 manifest.sig 应被拒绝")
	}
}

// TestVerifyPackageArtifactRejectsManifestSigInFilesList manifest.sig 与
// manifest.json 同为保留路径，出现在 files 清单必须拒绝。
func TestVerifyPackageArtifactRejectsManifestSigInFilesList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jiuzhang-offline-2.1.0.tar.gz")
	payload := []byte("payload")
	sigContent := []byte("placeholder")
	listed := []manifestFile{
		{Path: "payload/app.bin", SHA256: hashHex(payload), Size: int64(len(payload))},
		{Path: "manifest.sig", SHA256: hashHex(sigContent), Size: int64(len(sigContent))},
	}
	filesJSON, err := json.Marshal(listed)
	if err != nil {
		t.Fatal(err)
	}
	filesDigest := sha256.Sum256(filesJSON)
	manifest, err := json.Marshal(packageManifest{
		Product: "wdsp", Version: "2.1.0", Arch: runtime.GOARCH,
		Files: listed, FilesManifestSHA256: hex.EncodeToString(filesDigest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	writeTestArchive(t, path, []testArchiveEntry{
		{name: "release/manifest.json", data: manifest},
		{name: "release/manifest.sig", data: sigContent},
		{name: "release/payload/app.bin", data: payload},
	})
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(content)
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pkg := Package{
		FileName:    filepath.Base(path),
		VersionFrom: "2.0.0",
		VersionTo:   "2.1.0",
		FileHash:    hex.EncodeToString(hash[:]),
		FileSize:    int64(len(content)),
	}

	if err := verifyPackageArtifactWithKey(path, &pkg, publicKey); err == nil {
		t.Fatal("files 清单包含 manifest.sig 应被拒绝")
	}
}

// TestVerifyPackageArtifactRejectsDuplicateManifestSig 重复 manifest.sig 必须拒绝。
func TestVerifyPackageArtifactRejectsDuplicateManifestSig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jiuzhang-offline-2.1.0.tar.gz")
	payload := []byte("payload")
	manifest := testManifest(t, "2.1.0", map[string][]byte{"payload/app.bin": payload})
	writeTestArchive(t, path, []testArchiveEntry{
		{name: "release/manifest.json", data: manifest},
		{name: "release/manifest.sig", data: []byte("a")},
		{name: "release//manifest.sig", data: []byte("b")},
		{name: "release/payload/app.bin", data: payload},
	})
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(content)
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pkg := Package{
		FileName:    filepath.Base(path),
		VersionFrom: "2.0.0",
		VersionTo:   "2.1.0",
		FileHash:    hex.EncodeToString(hash[:]),
		FileSize:    int64(len(content)),
	}

	if err := verifyPackageArtifactWithKey(path, &pkg, publicKey); err == nil {
		t.Fatal("重复 manifest.sig 应被拒绝")
	}
}

// TestVerifyPackageArtifactFallbackRequiresSidecar 旧格式包（无 manifest.sig）
// 缺少旁车 .sig 时必须拒绝。
func TestVerifyPackageArtifactFallbackRequiresSidecar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jiuzhang-offline-2.1.0.tar.gz")
	payload := []byte("signed payload")
	manifest := testManifest(t, "2.1.0", map[string][]byte{"payload/app.bin": payload})
	content := writeTestArchive(t, path, []testArchiveEntry{
		{name: "release/manifest.json", data: manifest},
		{name: "release/payload/app.bin", data: payload},
	})
	hash := sha256.Sum256(content)
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pkg := Package{
		FileName:    filepath.Base(path),
		VersionFrom: "2.0.0",
		VersionTo:   "2.1.0",
		FileHash:    hex.EncodeToString(hash[:]),
		FileSize:    int64(len(content)),
	}

	if err := verifyPackageArtifactWithKey(path, &pkg, publicKey); err == nil {
		t.Fatal("无 manifest.sig 且无旁车签名的旧格式包应被拒绝")
	}
}

// TestReadPackageManifestInfo 上传登记前的包内 manifest 信息提取。
func TestReadPackageManifestInfo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pkg.tar.gz")
	// 新格式：含执行器协议版本字段 + manifest.sig
	_, _, _, manifest := writeEmbeddedTestArtifact(t, path, "2.0.0", "2.1.0",
		map[string][]byte{"payload/app.bin": []byte("payload")})
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := readPackageManifestInfo(content)
	if err != nil {
		t.Fatalf("readPackageManifestInfo 意外失败: %v", err)
	}
	if info.versionFrom != "2.0.0" || info.versionTo != "2.1.0" {
		t.Errorf("版本 = %s -> %s, want 2.0.0 -> 2.1.0", info.versionFrom, info.versionTo)
	}
	if !info.hasEmbeddedSig {
		t.Error("hasEmbeddedSig 应为 true")
	}
	if !bytes.Equal(info.raw, manifest) {
		t.Error("raw 应为 manifest.json 归档内原始字节")
	}

	// 旧格式：无版本字段、无 manifest.sig
	legacy := filepath.Join(dir, "legacy.tar.gz")
	payload := []byte("payload")
	legacyContent := writeTestArchive(t, legacy, []testArchiveEntry{
		{name: "release/manifest.json", data: testManifest(t, "2.1.0", map[string][]byte{"payload/app.bin": payload})},
		{name: "release/payload/app.bin", data: payload},
	})
	info, err = readPackageManifestInfo(legacyContent)
	if err != nil {
		t.Fatalf("旧格式 readPackageManifestInfo 意外失败: %v", err)
	}
	if info.versionFrom != "" || info.versionTo != "" {
		t.Errorf("旧格式版本字段应为空, got %s -> %s", info.versionFrom, info.versionTo)
	}
	if info.hasEmbeddedSig {
		t.Error("旧格式 hasEmbeddedSig 应为 false")
	}

	// 非归档内容
	if _, err := readPackageManifestInfo([]byte("not an archive")); err == nil {
		t.Error("非法归档应报错")
	}
}

func TestReleasePublicKeyMatchesPackagingTrustRoot(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "ops", "offline-package", "release-signing.pub"))
	if err != nil {
		t.Fatalf("读取打包信任根: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("打包信任根不是有效 PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("解析打包信任根: %v", err)
	}
	expected, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatal("打包信任根不是 Ed25519 公钥")
	}
	actual, err := packageReleasePublicKey()
	if err != nil {
		t.Fatalf("解析服务端信任根: %v", err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("服务端内嵌发布公钥与打包使用的 release-signing.pub 不一致")
	}
}

func TestScanPackageArchiveReaderStreamsLargePayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pkg.tar.gz")
	payload := bytes.Repeat([]byte("x"), int(maxArtifactManifestBytes)+1)
	manifest := testManifest(t, "2.1.0", map[string][]byte{"payload/large.bin": payload})
	content := writeTestArchive(t, path, []testArchiveEntry{
		{name: "release/manifest.json", data: manifest},
		{name: "release/payload/large.bin", data: payload},
	})

	scan, err := scanPackageArchiveReader(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("流式扫描大载荷失败: %v", err)
	}
	got, ok := scan.files["payload/large.bin"]
	if !ok || got.size != int64(len(payload)) {
		t.Fatalf("大载荷索引不正确: %+v", got)
	}
	if len(scan.manifestBytes) != len(manifest) {
		t.Fatalf("manifest 保留字节数=%d, want %d", len(scan.manifestBytes), len(manifest))
	}
}

func TestReadPackageManifestInfoFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pkg.tar.gz")
	writeEmbeddedTestArtifact(t, path, "2.0.0", "2.1.0", map[string][]byte{"payload/app.bin": []byte("payload")})
	info, err := readPackageManifestInfoFile(path)
	if err != nil {
		t.Fatalf("流式读取 manifest 信息失败: %v", err)
	}
	if info.versionFrom != "2.0.0" || info.versionTo != "2.1.0" || !info.hasEmbeddedSig {
		t.Fatalf("manifest 信息=%+v", info)
	}
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
