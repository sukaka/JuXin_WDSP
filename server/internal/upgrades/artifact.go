package upgrades

// artifact.go implements the fixed-root verification performed before an
// uploaded or scheduled upgrade package can be treated as executable.
//
// The public key is intentionally embedded in the production binary.  The
// corresponding private key is never stored in the repository.  Tests use
// verifyPackageArtifactWithKey with an ephemeral key so the production trust
// root cannot be replaced through an environment variable.

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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// releasePublicKeyPEM is the public release trust root.  Rotation requires a
// reviewed binary/configuration change; no private key belongs in this tree.
const releasePublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEApGM/1+Y45NHIQ9F6zv5SH0NbiEjFA5hmx22R4nDAGus=
-----END PUBLIC KEY-----`

const (
	maxArtifactExpandedBytes = int64(8 << 30)
	maxArtifactManifestBytes = int64(8 << 20)
	maxArtifactManifestFiles = 100000
)

// PackageArtifactVerifier verifies the file at path against the package
// record.  Keeping this as a function makes the trust-boundary tests explicit
// without weakening the production verifier.
type PackageArtifactVerifier func(path string, pkg *Package) error

type packageManifest struct {
	Product             string         `json:"product"`
	Version             string         `json:"version"`
	Arch                string         `json:"arch"`
	Files               []manifestFile `json:"files"`
	FilesManifestSHA256 string         `json:"files_manifest_sha256"`
}

type manifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type archiveFile struct {
	size int64
	hash string
}

type archiveEntry struct {
	path    string
	size    int64
	hash    string
	content []byte
}

// verifyPackageArtifact verifies the production trust root, the database
// record, the detached signature, and the archive manifest/content binding.
func verifyPackageArtifact(path string, pkg *Package) error {
	pub, err := packageReleasePublicKey()
	if err != nil {
		return err
	}
	return verifyPackageArtifactWithKey(path, pkg, pub)
}

func packageReleasePublicKey() (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(releasePublicKeyPEM))
	if block == nil {
		return nil, errors.New("发布公钥 PEM 无效")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析发布公钥失败: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("发布公钥不是 Ed25519 公钥")
	}
	return append(ed25519.PublicKey(nil), pub...), nil
}

// verifyPackageArtifactWithKey is intentionally unexported: callers in this
// package can inject an ephemeral key in tests, while runtime paths use the
// fixed production trust root above.
func verifyPackageArtifactWithKey(path string, pkg *Package, pub ed25519.PublicKey) error {
	if pkg == nil {
		return errors.New("升级包记录为空")
	}
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("升级包验签公钥无效")
	}
	if filepath.Base(pkg.FileName) != pkg.FileName || pkg.FileName == "" {
		return errors.New("升级包登记文件名无效")
	}
	if filepath.Base(path) != pkg.FileName {
		return fmt.Errorf("升级包文件名与登记不一致: %s", filepath.Base(path))
	}

	stat, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("升级包文件不可读: %w", err)
	}
	if !stat.Mode().IsRegular() {
		return errors.New("升级包必须是普通文件")
	}
	if stat.Size() != pkg.FileSize {
		return fmt.Errorf("升级包大小与登记不一致: actual=%d expected=%d", stat.Size(), pkg.FileSize)
	}
	actualHash, _, err := hashFileStreaming(path)
	if err != nil {
		return fmt.Errorf("计算升级包摘要失败: %w", err)
	}
	if !strings.EqualFold(actualHash, pkg.FileHash) {
		return errors.New("升级包 SHA-256 与登记不一致")
	}

	sigRaw, err := os.ReadFile(path + ".sig")
	if err != nil {
		return fmt.Errorf("升级包签名旁车文件不可读: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("升级包签名旁车文件格式无效")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取升级包失败: %w", err)
	}
	if !ed25519.Verify(pub, content, signature) {
		return errors.New("升级包 Ed25519 签名验证失败")
	}
	if err := verifyPackageArchive(content, pkg); err != nil {
		return fmt.Errorf("升级包 manifest/内容校验失败: %w", err)
	}
	return nil
}

func verifyPackageArchive(content []byte, pkg *Package) error {
	gz, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("gzip 格式无效: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tarReader := tar.NewReader(gz)
	var entries []archiveEntry
	var expanded int64
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("tar 格式无效: %w", err)
		}
		normalized, err := normalizeArchivePath(header.Name)
		if err != nil {
			return err
		}
		if normalized == "" {
			continue
		}
		if header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return fmt.Errorf("归档包含不允许的文件类型: %s", header.Name)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Size < 0 || expanded > maxArtifactExpandedBytes-header.Size {
			return errors.New("归档解压大小超出安全上限")
		}
		expanded += header.Size
		if header.Size > maxArtifactExpandedBytes {
			return errors.New("归档成员大小超出安全上限")
		}

		hash := sha256.New()
		limited := io.LimitReader(tarReader, header.Size)
		var dst bytes.Buffer
		if _, err := io.Copy(io.MultiWriter(hash, &dst), limited); err != nil {
			return fmt.Errorf("读取归档成员失败: %w", err)
		}
		if int64(dst.Len()) != header.Size {
			return fmt.Errorf("归档成员大小不完整: %s", header.Name)
		}
		entry := archiveEntry{
			path: normalized,
			size: header.Size,
			hash: hex.EncodeToString(hash.Sum(nil)),
		}
		if filepath.Base(normalized) == "manifest.json" {
			if header.Size > maxArtifactManifestBytes {
				return errors.New("manifest.json 超出安全大小上限")
			}
			entry.content = append([]byte(nil), dst.Bytes()...)
		}
		entries = append(entries, entry)
	}

	root := commonArchiveRoot(entries)
	files := make(map[string]archiveFile)
	var manifestBytes []byte
	manifestFound := false
	for _, entry := range entries {
		normalized := stripArchiveRoot(entry.path, root)
		if normalized == "" {
			continue
		}
		if normalized == "manifest.json" {
			if manifestFound {
				return errors.New("归档包含重复 manifest.json")
			}
			manifestBytes = append([]byte(nil), entry.content...)
			manifestFound = true
			continue
		}
		if _, exists := files[normalized]; exists {
			return fmt.Errorf("归档包含重复文件: %s", normalized)
		}
		files[normalized] = archiveFile{size: entry.size, hash: entry.hash}
	}
	if !manifestFound {
		return errors.New("归档缺少 manifest.json")
	}

	var manifest packageManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return fmt.Errorf("manifest.json 不是合法 JSON: %w", err)
	}
	if manifest.Version != pkg.VersionTo {
		return fmt.Errorf("manifest 版本与升级目标不一致: %s", manifest.Version)
	}
	if manifest.Arch != runtime.GOARCH {
		return fmt.Errorf("manifest 架构与当前服务不一致: %s != %s", manifest.Arch, runtime.GOARCH)
	}
	if len(manifest.Files) == 0 || len(manifest.Files) > maxArtifactManifestFiles {
		return errors.New("manifest 文件清单为空或超出数量上限")
	}
	filesJSON, err := json.Marshal(manifest.Files)
	if err != nil {
		return fmt.Errorf("序列化 manifest 文件清单失败: %w", err)
	}
	filesDigest := sha256.Sum256(filesJSON)
	if !strings.EqualFold(hex.EncodeToString(filesDigest[:]), manifest.FilesManifestSHA256) {
		return errors.New("manifest 文件清单摘要不一致")
	}
	listed := make(map[string]struct{}, len(manifest.Files))
	for _, item := range manifest.Files {
		normalized, err := normalizeArchivePath(item.Path)
		if err != nil {
			return fmt.Errorf("manifest 文件路径无效: %w", err)
		}
		if normalized == "manifest.json" || normalized == "" {
			return errors.New("manifest 文件清单包含保留路径")
		}
		if _, duplicate := listed[normalized]; duplicate {
			return fmt.Errorf("manifest 文件清单重复: %s", normalized)
		}
		listed[normalized] = struct{}{}
		actual, ok := files[normalized]
		if !ok {
			return fmt.Errorf("manifest 声明的文件缺失: %s", normalized)
		}
		if actual.size != item.Size || !strings.EqualFold(actual.hash, item.SHA256) {
			return fmt.Errorf("manifest 文件摘要或大小不一致: %s", normalized)
		}
	}
	if len(files) != len(listed) {
		return errors.New("归档存在未在 manifest 中声明的文件")
	}
	return nil
}

func normalizeArchivePath(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '\x00') {
		return "", errors.New("归档包含空文件名")
	}
	if strings.Contains(name, "\\") || filepath.IsAbs(name) {
		return "", fmt.Errorf("归档路径不安全: %s", name)
	}
	for _, part := range strings.Split(name, string(filepath.Separator)) {
		if part == ".." {
			return "", fmt.Errorf("归档路径穿越: %s", name)
		}
	}
	cleaned := filepath.Clean(name)
	if cleaned == "." || cleaned == "" {
		return "", nil
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("归档路径穿越: %s", name)
	}
	if cleaned == "" || cleaned == "." {
		return "", nil
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("归档路径穿越: %s", name)
	}
	return cleaned, nil
}

func commonArchiveRoot(entries []archiveEntry) string {
	if len(entries) == 0 {
		return ""
	}
	root := firstArchiveComponent(entries[0].path)
	if root == "" {
		return ""
	}
	for _, entry := range entries[1:] {
		if firstArchiveComponent(entry.path) != root {
			return ""
		}
	}
	return root
}

func firstArchiveComponent(path string) string {
	if index := strings.IndexByte(path, filepath.Separator); index >= 0 {
		return path[:index]
	}
	return path
}

func stripArchiveRoot(path, root string) string {
	if root == "" {
		return path
	}
	prefix := root + string(filepath.Separator)
	if strings.HasPrefix(path, prefix) {
		return strings.TrimPrefix(path, prefix)
	}
	if path == root {
		return ""
	}
	return path
}
