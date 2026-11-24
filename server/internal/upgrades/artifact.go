package upgrades

// artifact.go implements the fixed-root verification performed before an
// uploaded or scheduled upgrade package can be treated as executable.
//
// Two signature transports are supported, selected by the archive content:
//   - 内嵌签名（新包格式）：归档根目录的 manifest.sig（base64 单行文本）是对
//     manifest.json 归档内原始字节的 Ed25519 签名。链式信任：
//     manifest.sig → manifest.json → files_manifest_sha256 → 逐文件 sha256。
//   - 旁车签名（旧包格式）：无 manifest.sig 时回落到 <package>.sig 旁车文件，
//     验签对象为整个 tar.gz 原始字节。
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
MCowBQYDK2VwAyEAJBzjZs04R6NVLDuKoJsViPuBEGlo70z/zpnKi6ZHq2s=
-----END PUBLIC KEY-----`

const (
	maxArtifactExpandedBytes = int64(8 << 30)
	maxArtifactManifestBytes = int64(8 << 20)
	maxArtifactManifestFiles = 100000
	// maxArtifactArchiveEntries 约束归档索引元数据，避免海量空成员耗尽内存或 CPU。
	maxArtifactArchiveEntries = maxArtifactManifestFiles + 2
	// maxArtifactManifestSigBytes manifest.sig 大小上限（base64 Ed25519 签名仅约 88 字符）。
	maxArtifactManifestSigBytes = int64(4096)
	// 流式扫描期间最多保留一个可能的包装根和裸根的清单/签名各一份。
	maxArtifactMetadataBytes = 2 * (maxArtifactManifestBytes + maxArtifactManifestSigBytes)
	// 旧旁车签名对整个 tar.gz 验签，Ed25519 API 必须获得完整消息；新版内嵌签名
	// 不受该限制。拒绝大旧包而不是无界读入内存。
	maxLegacyDetachedPackageBytes = int64(64 << 20)
)

// PackageArtifactVerifier verifies the file at path against the package
// record.  Keeping this as a function makes the trust-boundary tests explicit
// without weakening the production verifier.
type PackageArtifactVerifier func(path string, pkg *Package) error

type packageManifest struct {
	Product             string          `json:"product"`
	PackageType         string          `json:"package_type,omitempty"`
	Version             string          `json:"version"`
	Arch                string          `json:"arch"`
	Components          []string        `json:"components,omitempty"`
	Images              []manifestImage `json:"images,omitempty"`
	Files               []manifestFile  `json:"files"`
	FilesManifestSHA256 string          `json:"files_manifest_sha256"`
	// 执行器协议字段（新包必有）：登记版本号与目标迁移号的包内来源。
	VersionFrom         string `json:"version_from,omitempty"`
	VersionTo           string `json:"version_to,omitempty"`
	TargetSchemaVersion int    `json:"target_schema_version,omitempty"`
}

type manifestImage struct {
	Component        string   `json:"component"`
	Service          string   `json:"service"`
	Image            string   `json:"image"`
	Tar              string   `json:"tar"`
	DeliveryMode     string   `json:"delivery_mode,omitempty"`
	BaseLayers       []string `json:"base_layers,omitempty"`
	DiffIDs          []string `json:"diff_ids,omitempty"`
	RuntimeSanitized bool     `json:"runtime_sanitized,omitempty"`
}

func isValidLayerDiffID(s string) bool {
	if !strings.HasPrefix(s, "sha256:") || len(s) != len("sha256:")+64 {
		return false
	}
	for i := len("sha256:"); i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
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

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("打开升级包失败: %w", err)
	}
	manifestBytes, embeddedSig, verifyErr := verifyPackageArchiveReader(f, pkg)
	closeErr := f.Close()
	if verifyErr != nil {
		return fmt.Errorf("升级包 manifest/内容校验失败: %w", verifyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("关闭升级包失败: %w", closeErr)
	}
	if embeddedSig != nil {
		// 内嵌签名模式：manifest.sig 是对 manifest.json 归档内原始字节的签名。
		if !ed25519.Verify(pub, manifestBytes, embeddedSig) {
			return errors.New("升级包内嵌 manifest.sig 签名验证失败")
		}
		return nil
	}
	// 回落到旧格式：旁车 detached 签名（验签对象为整个 tar.gz 原始字节）。
	sigRaw, err := os.ReadFile(path + ".sig")
	if err != nil {
		return fmt.Errorf("升级包签名旁车文件不可读: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("升级包签名旁车文件格式无效")
	}
	if stat.Size() > maxLegacyDetachedPackageBytes {
		return fmt.Errorf("旧格式旁车签名升级包超过 %d MiB；请使用含 manifest.sig 的新版升级包", maxLegacyDetachedPackageBytes>>20)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取旧格式升级包失败: %w", err)
	}
	if !ed25519.Verify(pub, content, signature) {
		return errors.New("升级包 Ed25519 签名验证失败")
	}
	return nil
}

// archiveScan 归档结构扫描结果（不含 manifest JSON 语义校验）。
type archiveScan struct {
	manifestBytes []byte                 // 根级 manifest.json 原始字节（nil 表示缺失）
	manifestSig   []byte                 // 根级 manifest.sig 原始字节（base64 文本，nil 表示缺失）
	files         map[string]archiveFile // 根级相对路径 → 实际文件摘要
}

// scanPackageArchive 兼容内存夹具；生产路径应使用 scanPackageArchiveReader，避免
// 将完整升级包读入内存。
func scanPackageArchive(content []byte) (*archiveScan, error) {
	return scanPackageArchiveReader(bytes.NewReader(content))
}

// scanPackageArchiveReader 流式解析 tar.gz 归档：路径归一化与安全检查、大小上限、
// 仅有界保留根级 manifest.json / manifest.sig 原始字节，并汇总普通文件摘要。
func scanPackageArchiveReader(reader io.Reader) (*archiveScan, error) {
	gz, err := gzip.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("gzip 格式无效: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tarReader := tar.NewReader(gz)
	var entries []archiveEntry
	var expanded int64
	var buffered int64
	var possibleRoot string
	seen := make(map[string]struct{})
	entryCount := 0
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar 格式无效: %w", err)
		}
		entryCount++
		if entryCount > maxArtifactArchiveEntries {
			return nil, errors.New("归档成员数量超出安全上限")
		}
		normalized, err := normalizeArchivePath(header.Name)
		if err != nil {
			return nil, err
		}
		if normalized == "" {
			continue
		}
		if header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return nil, fmt.Errorf("归档包含不允许的文件类型: %s", header.Name)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if _, exists := seen[normalized]; exists {
			return nil, fmt.Errorf("归档包含重复文件: %s", normalized)
		}
		seen[normalized] = struct{}{}
		if len(entries) == 0 {
			possibleRoot = firstArchiveComponent(normalized)
		} else if firstArchiveComponent(normalized) != possibleRoot {
			possibleRoot = ""
		}
		if header.Size < 0 || expanded > maxArtifactExpandedBytes-header.Size {
			return nil, errors.New("归档解压大小超出安全上限")
		}
		expanded += header.Size
		if header.Size > maxArtifactExpandedBytes {
			return nil, errors.New("归档成员大小超出安全上限")
		}

		hash := sha256.New()
		entry := archiveEntry{
			path: normalized,
			size: header.Size,
		}
		metadataPath := stripArchiveRoot(normalized, possibleRoot)
		if normalized == "manifest.json" || normalized == "manifest.sig" {
			metadataPath = normalized
		}
		switch metadataPath {
		case "manifest.json":
			if header.Size > maxArtifactManifestBytes {
				return nil, errors.New("manifest.json 超出安全大小上限")
			}
		case "manifest.sig":
			if header.Size > maxArtifactManifestSigBytes {
				return nil, errors.New("manifest.sig 超出安全大小上限")
			}
		}
		if metadataPath == "manifest.json" || metadataPath == "manifest.sig" {
			if buffered > maxArtifactMetadataBytes-header.Size {
				return nil, errors.New("归档清单累计缓冲超出安全上限")
			}
			buffered += header.Size
			entry.content = make([]byte, header.Size)
			n, err := io.ReadFull(io.TeeReader(io.LimitReader(tarReader, header.Size), hash), entry.content)
			if err != nil || int64(n) != header.Size {
				if err != nil {
					return nil, fmt.Errorf("读取归档成员失败: %w", err)
				}
				return nil, fmt.Errorf("归档成员大小不完整: %s", header.Name)
			}
		} else {
			n, err := io.Copy(hash, io.LimitReader(tarReader, header.Size))
			if err != nil {
				return nil, fmt.Errorf("读取归档成员失败: %w", err)
			}
			if n != header.Size {
				return nil, fmt.Errorf("归档成员大小不完整: %s", header.Name)
			}
		}
		entry.hash = hex.EncodeToString(hash.Sum(nil))
		entries = append(entries, entry)
	}

	root := commonArchiveRoot(entries)
	scan := &archiveScan{files: make(map[string]archiveFile)}
	for _, entry := range entries {
		normalized := stripArchiveRoot(entry.path, root)
		if normalized == "" {
			continue
		}
		switch normalized {
		case "manifest.json":
			if scan.manifestBytes != nil {
				return nil, errors.New("归档包含重复 manifest.json")
			}
			scan.manifestBytes = entry.content
			continue
		case "manifest.sig":
			if scan.manifestSig != nil {
				return nil, errors.New("归档包含重复 manifest.sig")
			}
			scan.manifestSig = entry.content
			continue
		}
		if _, exists := scan.files[normalized]; exists {
			return nil, fmt.Errorf("归档包含重复文件: %s", normalized)
		}
		scan.files[normalized] = archiveFile{size: entry.size, hash: entry.hash}
	}
	return scan, nil
}

// verifyPackageArchive 校验归档结构、manifest 语义与逐文件摘要绑定。
// 返回 manifest.json 原始字节与解码后的内嵌签名（无 manifest.sig 时为 nil），
// 供调用方完成信任根验签。
func verifyPackageArchive(content []byte, pkg *Package) ([]byte, []byte, error) {
	return verifyPackageArchiveReader(bytes.NewReader(content), pkg)
}

// verifyPackageArchiveReader 是生产归档校验入口，始终流式读取压缩包。
func verifyPackageArchiveReader(reader io.Reader, pkg *Package) ([]byte, []byte, error) {
	scan, err := scanPackageArchiveReader(reader)
	if err != nil {
		return nil, nil, err
	}
	if scan.manifestBytes == nil {
		return nil, nil, errors.New("归档缺少 manifest.json")
	}

	var manifest packageManifest
	if err := json.Unmarshal(scan.manifestBytes, &manifest); err != nil {
		return nil, nil, fmt.Errorf("manifest.json 不是合法 JSON: %w", err)
	}
	if manifest.Version != pkg.VersionTo {
		return nil, nil, fmt.Errorf("manifest 版本与升级目标不一致: %s", manifest.Version)
	}
	if manifest.VersionFrom != "" && pkg.VersionFrom != "" && manifest.VersionFrom != pkg.VersionFrom {
		return nil, nil, fmt.Errorf("manifest 起始版本与升级登记不一致: %s != %s", manifest.VersionFrom, pkg.VersionFrom)
	}
	if manifest.Arch != runtime.GOARCH {
		return nil, nil, fmt.Errorf("manifest 架构与当前服务不一致: %s != %s", manifest.Arch, runtime.GOARCH)
	}
	if manifest.PackageType == "upgrade" && len(manifest.Images) > 0 {
		for _, img := range manifest.Images {
			mode := img.DeliveryMode
			if mode != "" && mode != "full" && mode != "layer-delta" {
				return nil, nil, fmt.Errorf("manifest 镜像交付模式无效: %s (%s)", img.Component, mode)
			}
			if mode == "layer-delta" {
				if len(img.BaseLayers) == 0 {
					return nil, nil, fmt.Errorf("layer-delta 升级包组件 %s 缺少 base_layers 声明", img.Component)
				}
				for _, layer := range img.BaseLayers {
					if !isValidLayerDiffID(layer) {
						return nil, nil, fmt.Errorf("layer-delta 升级包组件 %s 含非法 base_layers 摘要: %s", img.Component, layer)
					}
				}
			}
			for _, did := range img.DiffIDs {
				if !isValidLayerDiffID(did) {
					return nil, nil, fmt.Errorf("manifest 镜像组件 %s 含非法 diff_id 摘要: %s", img.Component, did)
				}
			}
		}
	}
	if len(manifest.Files) == 0 || len(manifest.Files) > maxArtifactManifestFiles {
		return nil, nil, errors.New("manifest 文件清单为空或超出数量上限")
	}
	filesJSON, err := json.Marshal(manifest.Files)
	if err != nil {
		return nil, nil, fmt.Errorf("序列化 manifest 文件清单失败: %w", err)
	}
	filesDigest := sha256.Sum256(filesJSON)
	if !strings.EqualFold(hex.EncodeToString(filesDigest[:]), manifest.FilesManifestSHA256) {
		return nil, nil, errors.New("manifest 文件清单摘要不一致")
	}
	listed := make(map[string]struct{}, len(manifest.Files))
	for _, item := range manifest.Files {
		normalized, err := normalizeArchivePath(item.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("manifest 文件路径无效: %w", err)
		}
		// manifest.json 与 manifest.sig 同为保留路径，不得出现在文件清单
		if normalized == "manifest.json" || normalized == "manifest.sig" || normalized == "" {
			return nil, nil, errors.New("manifest 文件清单包含保留路径")
		}
		if _, duplicate := listed[normalized]; duplicate {
			return nil, nil, fmt.Errorf("manifest 文件清单重复: %s", normalized)
		}
		listed[normalized] = struct{}{}
		actual, ok := scan.files[normalized]
		if !ok {
			return nil, nil, fmt.Errorf("manifest 声明的文件缺失: %s", normalized)
		}
		if actual.size != item.Size || !strings.EqualFold(actual.hash, item.SHA256) {
			return nil, nil, fmt.Errorf("manifest 文件摘要或大小不一致: %s", normalized)
		}
	}
	if len(scan.files) != len(listed) {
		return nil, nil, errors.New("归档存在未在 manifest 中声明的文件")
	}

	var embeddedSig []byte
	if scan.manifestSig != nil {
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(scan.manifestSig)))
		if err != nil || len(sig) != ed25519.SignatureSize {
			return nil, nil, errors.New("manifest.sig 不是有效的 base64 Ed25519 签名")
		}
		embeddedSig = sig
	}
	return scan.manifestBytes, embeddedSig, nil
}

// packageManifestInfo 上传登记时从包内 manifest.json 解析出的信息。
type packageManifestInfo struct {
	raw            []byte // manifest.json 归档内原始字节
	versionFrom    string
	versionTo      string
	targetSchema   int
	hasEmbeddedSig bool // 归档根目录存在 manifest.sig
}

// readPackageManifestInfo 提取包内 manifest 登记信息（不做验签与逐文件校验，
// 信任边界仍是 verifyPackageArtifact）。归档不可解析或缺 manifest.json 时返回错误。
func readPackageManifestInfo(content []byte) (*packageManifestInfo, error) {
	return readPackageManifestInfoReader(bytes.NewReader(content))
}

func readPackageManifestInfoFile(path string) (*packageManifestInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readPackageManifestInfoReader(f)
}

func readPackageManifestInfoReader(reader io.Reader) (*packageManifestInfo, error) {
	scan, err := scanPackageArchiveReader(reader)
	if err != nil {
		return nil, err
	}
	if scan.manifestBytes == nil {
		return nil, errors.New("归档缺少 manifest.json")
	}
	var manifest packageManifest
	if err := json.Unmarshal(scan.manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("manifest.json 不是合法 JSON: %w", err)
	}
	return &packageManifestInfo{
		raw:            scan.manifestBytes,
		versionFrom:    strings.TrimSpace(manifest.VersionFrom),
		versionTo:      strings.TrimSpace(manifest.VersionTo),
		targetSchema:   manifest.TargetSchemaVersion,
		hasEmbeddedSig: scan.manifestSig != nil,
	}, nil
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
