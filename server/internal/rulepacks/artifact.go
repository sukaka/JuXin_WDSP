package rulepacks

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
	"regexp"
	"sort"
	"strings"

	"github.com/jiuzhang-waf/server/internal/wafrules"
)

// releasePublicKeyPEM 生产发布验签公钥（Ed25519，与 upgrades/artifact.go 和
// ops/offline-package/release-signing.pub 保持严格同源；禁止经环境变量替换）。
const releasePublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJBzjZs04R6NVLDuKoJsViPuBEGlo70z/zpnKi6ZHq2s=
-----END PUBLIC KEY-----`

var (
	// archivePathCharRe 强制归档路径仅含安全 ASCII 字符，保证 Python/Go 紧凑 JSON 序列化字节一致。
	archivePathCharRe = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

	// 必备锚点文件（与 gatewayconfig/generator.go 固定 Include 链严格对齐）
	requiredAnchorFiles = []string{
		"rules/coraza.conf",
		"rules/crs/crs-setup.conf",
		"rules/exclusions/before-crs.conf",
		"rules/exclusions/after-crs.conf",
		"rules/jiuzhang/jiuzhang-custom.conf",
		"rules/jiuzhang/post-contrib-blocking.conf",
	}

	// 允许的扩展名白名单（拒绝 .sh / .so / 可执行文件等无关载荷）
	allowedFileExts = map[string]bool{
		".conf":      true,
		".data":      true,
		".txt":       true,
		".md":        true,
		".example":   true,
		".gitkeep":   true,
		".gitignore": true,
	}

	// 允许的无扩展名元数据文件白名单
	allowedBaseNames = map[string]bool{
		"LICENSE":   true,
		"NOTICE":    true,
		"INSTALL":   true,
		"PINNED":    true,
		"README":    true,
		"CHANGELOG": true,
	}

	// Coraza 不兼容或高危操作符/指令（与 docs/RULE_PACKS.md 红线一致）
	forbiddenDirectivesRe = []*regexp.Regexp{
		regexp.MustCompile(`(?i)@inspectFile\b`),
		regexp.MustCompile(`(?i)\bSecRuleScript\b`),
		regexp.MustCompile(`(?i)@rbl\b`),
	}
	includeDirectiveRe = regexp.MustCompile(`(?i)^\s*Include(?:Optional)?\s+["']?([^"'\s#]+)["']?`)
	pmFromFileRe       = regexp.MustCompile(`(?i)!?@pmFromFile\s+([^\s"']+)`)
	cveExtractRe       = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
)

// VerifiedArtifact 是归档验签与逐文件摘要核验通过后的不可变产物摘要。
type VerifiedArtifact struct {
	Manifest       Manifest
	ManifestRaw    []byte
	ManifestSHA256 string
	FileSHA256     string
	FileSize       int64
	ArchiveFiles   map[string]archiveFileInfo
}

type archiveFileInfo struct {
	size int64
	hash string
}

type rawArchiveEntry struct {
	path    string
	size    int64
	hash    string
	content []byte
}

type scannedArchive struct {
	manifestBytes []byte
	manifestSig   []byte
	files         map[string]archiveFileInfo
}

// StaticCheckResult 是规则包静态门禁通过后的规则解析汇总。
type StaticCheckResult struct {
	Rules           []*wafrules.Rule
	BySource        map[string]int
	ByAttackType    map[string]int
	DetectedCVEs    []string
	CheckedConfFile int
}

// ReleasePublicKey 解析内嵌的生产 Ed25519 发布公钥。
func ReleasePublicKey() (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(releasePublicKeyPEM))
	if block == nil {
		return nil, errors.New("内置发布公钥 PEM 无效")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析内置发布公钥失败: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("内置发布公钥不是合法 Ed25519 公钥")
	}
	return append(ed25519.PublicKey(nil), pub...), nil
}

// VerifyArchiveFile 使用内嵌生产公钥验证磁盘上的离线规则包。
func VerifyArchiveFile(path, currentSystemVersion string) (*VerifiedArtifact, error) {
	pub, err := ReleasePublicKey()
	if err != nil {
		return nil, err
	}
	return VerifyArchiveFileWithKey(path, currentSystemVersion, pub)
}

// VerifyArchiveFileWithKey 使用指定公钥验证磁盘上的离线规则包（单测可注入临时密钥）。
func VerifyArchiveFileWithKey(path, currentSystemVersion string, pub ed25519.PublicKey) (*VerifiedArtifact, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: 公钥无效", ErrInvalidSignature)
	}
	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法读取规则包文件: %v", ErrInvalidArchive, err)
	}
	if !stat.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: 规则包必须是普通文件", ErrInvalidArchive)
	}
	if stat.Size() <= 0 || stat.Size() > MaxArchiveBytes {
		return nil, fmt.Errorf("%w: 规则包大小 %d 字节超出允许范围（1B ~ %dMiB）", ErrInvalidArchive, stat.Size(), MaxArchiveBytes>>20)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: 打开规则包失败: %v", ErrInvalidArchive, err)
	}
	defer func() { _ = f.Close() }()

	hasher := sha256.New()
	tee := io.TeeReader(io.LimitReader(f, MaxArchiveBytes+1), hasher)
	art, err := verifyArchiveReaderWithKey(tee, currentSystemVersion, pub)
	if err != nil {
		return nil, err
	}
	// 读完剩余尾部字节（如 gzip trailer 后填充），确保外层文件哈希与磁盘完全一致。
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return nil, fmt.Errorf("%w: 读取归档尾部失败: %v", ErrInvalidArchive, err)
	}
	art.FileSize = stat.Size()
	art.FileSHA256 = hex.EncodeToString(hasher.Sum(nil))
	return art, nil
}

// VerifyArchiveBytesWithKey 便捷验证内存字节（主要用于单元测试）。
func VerifyArchiveBytesWithKey(content []byte, currentSystemVersion string, pub ed25519.PublicKey) (*VerifiedArtifact, error) {
	if int64(len(content)) == 0 || int64(len(content)) > MaxArchiveBytes {
		return nil, fmt.Errorf("%w: 规则包大小超出安全上限", ErrInvalidArchive)
	}
	art, err := verifyArchiveReaderWithKey(bytes.NewReader(content), currentSystemVersion, pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)
	art.FileSize = int64(len(content))
	art.FileSHA256 = hex.EncodeToString(sum[:])
	return art, nil
}

func verifyArchiveReaderWithKey(reader io.Reader, currentSystemVersion string, pub ed25519.PublicKey) (*VerifiedArtifact, error) {
	scan, err := scanRulePackArchive(reader)
	if err != nil {
		return nil, err
	}
	if len(scan.manifestBytes) == 0 {
		return nil, fmt.Errorf("%w: 归档缺少 manifest.json", ErrInvalidArchive)
	}
	if len(scan.manifestSig) == 0 {
		return nil, fmt.Errorf("%w: 归档缺少内嵌签名文件 manifest.sig", ErrInvalidSignature)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(scan.manifestSig)))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: manifest.sig 不是有效的 base64 Ed25519 签名", ErrInvalidSignature)
	}
	// 信任根验签先于任意语义消费：确保未签名/篡改包立刻 fail-closed 拒绝。
	if !ed25519.Verify(pub, scan.manifestBytes, sigBytes) {
		return nil, fmt.Errorf("%w: manifest.sig 签名校验不匹配", ErrInvalidSignature)
	}

	var manifest Manifest
	if err := json.Unmarshal(scan.manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("%w: manifest.json 不是合法 JSON: %v", ErrInvalidArchive, err)
	}
	if manifest.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: 不支持的规则包 schema_version=%d", ErrInvalidArchive, manifest.SchemaVersion)
	}
	if manifest.Product != ProductWDSP {
		return nil, fmt.Errorf("%w: 非法 product=%q（期望 %q）", ErrInvalidArchive, manifest.Product, ProductWDSP)
	}
	if manifest.PackageType != PackageTypeRulePack {
		return nil, fmt.Errorf("%w: 非规则包类型 package_type=%q（系统升级包请到「系统升级」页面上传）", ErrInvalidArchive, manifest.PackageType)
	}
	if err := ValidateRulePackVersion(manifest.RulePackVersion); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
	}
	manifest.CRSVersion = strings.TrimSpace(manifest.CRSVersion)
	if manifest.CRSVersion == "" || len(manifest.CRSVersion) > 32 {
		return nil, fmt.Errorf("%w: manifest 缺少有效 crs_version", ErrInvalidArchive)
	}
	if strings.TrimSpace(manifest.MinSystemVersion) != "" && strings.TrimSpace(currentSystemVersion) != "" {
		cmp, err := CompareSemver(currentSystemVersion, manifest.MinSystemVersion)
		if err != nil {
			return nil, fmt.Errorf("%w: 最低系统版本字段格式无效 (%q): %v", ErrInvalidArchive, manifest.MinSystemVersion, err)
		}
		if cmp < 0 {
			return nil, fmt.Errorf("%w: 需要系统版本 >= %s，当前版本为 %s", ErrIncompatibleSystem, manifest.MinSystemVersion, currentSystemVersion)
		}
	}

	if len(manifest.Files) == 0 || len(manifest.Files) > MaxArchiveEntries {
		return nil, fmt.Errorf("%w: manifest 文件清单为空或超出上限", ErrInvalidArchive)
	}
	filesJSON, err := json.Marshal(manifest.Files)
	if err != nil {
		return nil, fmt.Errorf("%w: 序列化 manifest.files 失败: %v", ErrInvalidArchive, err)
	}
	filesDigest := sha256.Sum256(filesJSON)
	if !strings.EqualFold(hex.EncodeToString(filesDigest[:]), strings.TrimSpace(manifest.FilesManifestSHA256)) {
		return nil, fmt.Errorf("%w: files_manifest_sha256 摘要不一致", ErrInvalidArchive)
	}

	listed := make(map[string]struct{}, len(manifest.Files))
	hasCRSRule := false
	for _, item := range manifest.Files {
		norm, err := normalizeRulePackPath(item.Path)
		if err != nil {
			return nil, fmt.Errorf("%w: manifest 路径非法: %v", ErrInvalidArchive, err)
		}
		if norm == "manifest.json" || norm == "manifest.sig" || norm == "" {
			return nil, fmt.Errorf("%w: manifest.files 不得包含保留路径 %q", ErrInvalidArchive, norm)
		}
		if !strings.HasPrefix(norm, "rules/") {
			return nil, fmt.Errorf("%w: 规则包文件必须位于 rules/ 目录下: %s", ErrInvalidArchive, norm)
		}
		if !isAllowedRulePackFile(norm) {
			return nil, fmt.Errorf("%w: 规则包包含不允许的文件类型或扩展名: %s", ErrInvalidArchive, norm)
		}
		if _, dup := listed[norm]; dup {
			return nil, fmt.Errorf("%w: manifest.files 存在重复路径: %s", ErrInvalidArchive, norm)
		}
		listed[norm] = struct{}{}

		actual, ok := scan.files[norm]
		if !ok {
			return nil, fmt.Errorf("%w: manifest 声明的文件缺失: %s", ErrInvalidArchive, norm)
		}
		if actual.size != item.Size || !strings.EqualFold(actual.hash, strings.TrimSpace(item.SHA256)) {
			return nil, fmt.Errorf("%w: 文件大小或 SHA-256 校验不一致: %s", ErrInvalidArchive, norm)
		}
		if strings.HasPrefix(norm, "rules/crs/rules/") && strings.HasSuffix(norm, ".conf") &&
			!strings.HasSuffix(norm, ".example") && !strings.Contains(filepath.Base(norm), "EXCLUSION") && actual.size > 0 {
			hasCRSRule = true
		}
	}
	if len(scan.files) != len(listed) {
		return nil, fmt.Errorf("%w: 归档包含未在 manifest.files 中声明的多余文件", ErrInvalidArchive)
	}
	for _, anchor := range requiredAnchorFiles {
		info, ok := scan.files[anchor]
		if !ok || info.size <= 0 {
			return nil, fmt.Errorf("%w: 缺少必备核心规则文件或文件为空: %s", ErrInvalidArchive, anchor)
		}
	}
	if !hasCRSRule {
		return nil, fmt.Errorf("%w: rules/crs/rules/ 目录缺少可用 CRS 规则文件", ErrInvalidArchive)
	}

	manifestSum := sha256.Sum256(scan.manifestBytes)
	return &VerifiedArtifact{
		Manifest:       manifest,
		ManifestRaw:    scan.manifestBytes,
		ManifestSHA256: hex.EncodeToString(manifestSum[:]),
		ArchiveFiles:   scan.files,
	}, nil
}

func scanRulePackArchive(reader io.Reader) (*scannedArchive, error) {
	gz, err := gzip.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("%w: gzip 解压头无效: %v", ErrInvalidArchive, err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	var entries []rawArchiveEntry
	var expanded int64
	var buffered int64
	var possibleRoot string
	seen := make(map[string]struct{})
	entryCount := 0

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: tar 归档损坏: %v", ErrInvalidArchive, err)
		}
		entryCount++
		if entryCount > MaxArchiveEntries {
			return nil, fmt.Errorf("%w: 归档成员数量超出安全上限 (%d)", ErrInvalidArchive, MaxArchiveEntries)
		}
		norm, err := normalizeRulePackPath(hdr.Name)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
		}
		if norm == "" {
			continue
		}
		if hdr.Typeflag != tar.TypeDir && hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return nil, fmt.Errorf("%w: 归档包含禁止的文件类型（仅允许普通文件与目录）: %s", ErrInvalidArchive, hdr.Name)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if _, dup := seen[norm]; dup {
			return nil, fmt.Errorf("%w: 归档包含重复文件路径: %s", ErrInvalidArchive, norm)
		}
		seen[norm] = struct{}{}

		if len(entries) == 0 {
			possibleRoot = firstComponent(norm)
		} else if firstComponent(norm) != possibleRoot {
			possibleRoot = ""
		}

		if hdr.Size < 0 || hdr.Size > MaxSingleFileBytes {
			return nil, fmt.Errorf("%w: 归档单文件 %s 大小 (%d) 超出上限 (%dMiB)", ErrInvalidArchive, norm, hdr.Size, MaxSingleFileBytes>>20)
		}
		if expanded > MaxExpandedBytes-hdr.Size {
			return nil, fmt.Errorf("%w: 归档解压总大小超出安全上限 (%dMiB)", ErrInvalidArchive, MaxExpandedBytes>>20)
		}
		expanded += hdr.Size

		metaPath := stripRoot(norm, possibleRoot)
		if norm == "manifest.json" || norm == "manifest.sig" {
			metaPath = norm
		}

		h := sha256.New()
		entry := rawArchiveEntry{path: norm, size: hdr.Size}
		if metaPath == "manifest.json" || metaPath == "manifest.sig" {
			if metaPath == "manifest.json" && hdr.Size > MaxManifestBytes {
				return nil, fmt.Errorf("%w: manifest.json 超出安全上限", ErrInvalidArchive)
			}
			if metaPath == "manifest.sig" && hdr.Size > MaxManifestSigBytes {
				return nil, fmt.Errorf("%w: manifest.sig 超出安全上限", ErrInvalidArchive)
			}
			maxMetaBuf := 2 * (MaxManifestBytes + MaxManifestSigBytes)
			if buffered > maxMetaBuf-hdr.Size {
				return nil, fmt.Errorf("%w: 归档清单缓冲超出安全上限", ErrInvalidArchive)
			}
			buffered += hdr.Size
			entry.content = make([]byte, hdr.Size)
			n, err := io.ReadFull(io.TeeReader(io.LimitReader(tr, hdr.Size), h), entry.content)
			if err != nil || int64(n) != hdr.Size {
				return nil, fmt.Errorf("%w: 读取归档清单 %s 失败", ErrInvalidArchive, norm)
			}
		} else {
			n, err := io.Copy(h, io.LimitReader(tr, hdr.Size))
			if err != nil || n != hdr.Size {
				return nil, fmt.Errorf("%w: 读取归档成员 %s 不完整", ErrInvalidArchive, norm)
			}
		}
		entry.hash = hex.EncodeToString(h.Sum(nil))
		entries = append(entries, entry)
	}

	root := detectCommonRoot(entries)
	scan := &scannedArchive{files: make(map[string]archiveFileInfo, len(entries))}
	for _, e := range entries {
		rel := stripRoot(e.path, root)
		if rel == "" {
			continue
		}
		switch rel {
		case "manifest.json":
			if scan.manifestBytes != nil {
				return nil, fmt.Errorf("%w: 归档存在重复 manifest.json", ErrInvalidArchive)
			}
			scan.manifestBytes = e.content
		case "manifest.sig":
			if scan.manifestSig != nil {
				return nil, fmt.Errorf("%w: 归档存在重复 manifest.sig", ErrInvalidArchive)
			}
			scan.manifestSig = e.content
		default:
			if _, dup := scan.files[rel]; dup {
				return nil, fmt.Errorf("%w: 归档存在重复文件: %s", ErrInvalidArchive, rel)
			}
			scan.files[rel] = archiveFileInfo{size: e.size, hash: e.hash}
		}
	}
	return scan, nil
}

// ExtractRulesToDir 将已验签规则包内的 rules/ 目录安全解压到 destRulesDir。
// 严格剥离 rules/ 前缀，仅允许普通文件，强制设置目录 0750 / 文件 0640 权限。
func ExtractRulesToDir(archivePath, destRulesDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("打开规则包失败: %w", err)
	}
	defer func() { _ = f.Close() }()

	// 先确定是否存在统一顶层包装目录（复用扫描逻辑）
	gz1, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("打开 gzip 失败: %w", err)
	}
	tr1 := tar.NewReader(gz1)
	var entryPaths []rawArchiveEntry
	for {
		hdr, err := tr1.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = gz1.Close()
			return fmt.Errorf("扫描 tar 失败: %w", err)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		norm, err := normalizeRulePackPath(hdr.Name)
		if err != nil {
			_ = gz1.Close()
			return err
		}
		if norm != "" {
			entryPaths = append(entryPaths, rawArchiveEntry{path: norm})
		}
	}
	_ = gz1.Close()
	root := detectCommonRoot(entryPaths)

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("重置规则包文件指针失败: %w", err)
	}
	gz2, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("重新打开 gzip 失败: %w", err)
	}
	defer func() { _ = gz2.Close() }()

	if err := os.MkdirAll(destRulesDir, 0o750); err != nil {
		return fmt.Errorf("创建目标规则目录失败: %w", err)
	}
	cleanDest := filepath.Clean(destRulesDir)
	var expanded int64
	tr2 := tar.NewReader(gz2)
	for {
		hdr, err := tr2.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("解压 tar 失败: %w", err)
		}
		norm, err := normalizeRulePackPath(hdr.Name)
		if err != nil {
			return err
		}
		if norm == "" || hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return fmt.Errorf("%w: 解压时拒绝非普通文件 %s", ErrInvalidArchive, hdr.Name)
		}
		rel := stripRoot(norm, root)
		if !strings.HasPrefix(rel, "rules/") {
			continue // 跳过 manifest.json / manifest.sig
		}
		sub := strings.TrimPrefix(rel, "rules/")
		if sub == "" || !isAllowedRulePackFile(rel) {
			return fmt.Errorf("%w: 解压时遇到不允许路径 %s", ErrInvalidArchive, rel)
		}
		if hdr.Size < 0 || hdr.Size > MaxSingleFileBytes || expanded > MaxExpandedBytes-hdr.Size {
			return fmt.Errorf("%w: 解压大小超出安全上限", ErrInvalidArchive)
		}
		expanded += hdr.Size

		target := filepath.Join(cleanDest, filepath.FromSlash(sub))
		if !strings.HasPrefix(target, cleanDest+string(filepath.Separator)) {
			return fmt.Errorf("%w: 目标路径越界: %s", ErrInvalidArchive, sub)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return fmt.Errorf("创建子目录失败: %w", err)
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
		if err != nil {
			return fmt.Errorf("创建规则文件 %s 失败: %w", sub, err)
		}
		n, copyErr := io.Copy(out, io.LimitReader(tr2, hdr.Size))
		syncErr := out.Sync()
		closeErr := out.Close()
		if copyErr != nil || n != hdr.Size {
			return fmt.Errorf("写入规则文件 %s 不完整: %v", sub, copyErr)
		}
		if syncErr != nil {
			return fmt.Errorf("刷盘规则文件 %s 失败: %w", sub, syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("关闭规则文件 %s 失败: %w", sub, closeErr)
		}
	}
	return nil
}

// StaticGateCheckDir 对解压后的 rulesRoot 执行完整静态安全门禁与规则解析校验：
//  1. 扫描全部 .conf 文件，拒绝禁用操作符（@inspectFile / SecRuleScript / @rbl）与越界 Include；
//  2. 验证全部 @pmFromFile 目标数据文件真实存在于 rulesRoot 内；
//  3. 调用 wafrules.ParseCRSFile 解析全部来源目录，要求 ParseFailed == 0 且跨文件无重复 Rule ID。
func StaticGateCheckDir(rulesRoot string) (*StaticCheckResult, error) {
	cleanRoot := filepath.Clean(rulesRoot)
	var confFiles []string
	err := filepath.WalkDir(cleanRoot, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(d.Name(), ".conf") {
			confFiles = append(confFiles, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: 扫描规则目录失败: %v", ErrStaticGateFailed, err)
	}
	sort.Strings(confFiles)
	if len(confFiles) == 0 {
		return nil, fmt.Errorf("%w: 规则目录不包含任何 .conf 文件", ErrStaticGateFailed)
	}

	// 1. 逐文件扫描禁用指令、越界 Include 与 @pmFromFile 完整性（忽略 # 注释行）
	for _, cf := range confFiles {
		relPath, _ := filepath.Rel(cleanRoot, cf)
		raw, err := os.ReadFile(cf)
		if err != nil {
			return nil, fmt.Errorf("%w: 读取规则文件 %s 失败: %v", ErrStaticGateFailed, relPath, err)
		}
		lines := strings.Split(string(raw), "\n")
		for idx, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			for _, re := range forbiddenDirectivesRe {
				if re.MatchString(trimmed) {
					return nil, fmt.Errorf("%w: %s:%d 包含 Coraza 不兼容或禁止的指令/操作符 (%s)",
						ErrStaticGateFailed, relPath, idx+1, re.String())
				}
			}
			if m := includeDirectiveRe.FindStringSubmatch(trimmed); m != nil {
				inc := strings.TrimSpace(m[1])
				if filepath.IsAbs(inc) || strings.Contains(inc, "..") {
					return nil, fmt.Errorf("%w: %s:%d 包含不安全的 Include 路径 %q",
						ErrStaticGateFailed, relPath, idx+1, inc)
				}
			}
			for _, m := range pmFromFileRe.FindAllStringSubmatch(trimmed, -1) {
				dataRef := strings.TrimSpace(m[1])
				if filepath.IsAbs(dataRef) || strings.Contains(dataRef, "..") {
					return nil, fmt.Errorf("%w: %s:%d 的 @pmFromFile 引用非法路径 %q",
						ErrStaticGateFailed, relPath, idx+1, dataRef)
				}
				// Coraza 查找顺序：先相对当前 .conf 所在目录，再相对 rulesRoot
				cand1 := filepath.Join(filepath.Dir(cf), filepath.FromSlash(dataRef))
				cand2 := filepath.Join(cleanRoot, filepath.FromSlash(dataRef))
				if !isRegularFileUnder(cand1, cleanRoot) && !isRegularFileUnder(cand2, cleanRoot) {
					return nil, fmt.Errorf("%w: %s:%d 引用的 @pmFromFile 数据文件缺失: %s",
						ErrStaticGateFailed, relPath, idx+1, dataRef)
				}
			}
		}
	}

	// 2. 按生产同步口径解析全部来源并做 Rule ID 全库查重
	crsDir := filepath.Join(cleanRoot, "crs", "rules")
	sources := wafrules.BuildSyncSources(crsDir)
	res := &StaticCheckResult{
		BySource:        make(map[string]int),
		ByAttackType:    make(map[string]int),
		CheckedConfFile: len(confFiles),
	}
	seenIDs := make(map[int]string)
	cveSet := make(map[string]struct{})

	for _, sd := range sources {
		files, err := filepath.Glob(filepath.Join(sd.Dir, "*.conf"))
		if err != nil {
			return nil, fmt.Errorf("%w: 遍历来源目录 %s 失败: %v", ErrStaticGateFailed, sd.Source, err)
		}
		sort.Strings(files)
		usable := 0
		for _, f := range files {
			base := filepath.Base(f)
			if strings.HasSuffix(base, ".example") || strings.Contains(base, "EXCLUSION") {
				continue
			}
			usable++
			rules, failed, err := wafrules.ParseCRSFile(f, sd.Source)
			if err != nil {
				return nil, fmt.Errorf("%w: 解析规则文件 %s 失败: %v", ErrStaticGateFailed, base, err)
			}
			if len(failed) > 0 {
				return nil, fmt.Errorf("%w: 规则文件 %s 存在 %d 条无法解析的规则（示例: %s）",
					ErrStaticGateFailed, base, len(failed), failed[0])
			}
			for _, r := range rules {
				if prevFile, dup := seenIDs[r.RuleID]; dup {
					return nil, fmt.Errorf("%w: 检测到重复规则 ID %d（文件 %s 与 %s 冲突）",
						ErrStaticGateFailed, r.RuleID, prevFile, base)
				}
				seenIDs[r.RuleID] = sd.Source + "/" + base
				res.Rules = append(res.Rules, r)
				res.BySource[r.RuleSource]++
				res.ByAttackType[r.AttackType]++
				for _, cve := range cveExtractRe.FindAllString(r.Name+" "+r.Message+" "+string(r.Tags), -1) {
					cveSet[strings.ToUpper(cve)] = struct{}{}
				}
			}
		}
		if sd.Source == wafrules.SourceCRS && usable == 0 {
			return nil, fmt.Errorf("%w: OWASP CRS 主规则目录为空", ErrStaticGateFailed)
		}
	}
	if len(res.Rules) == 0 {
		return nil, fmt.Errorf("%w: 未从规则包解析到任何有效 SecRule", ErrStaticGateFailed)
	}
	for cve := range cveSet {
		res.DetectedCVEs = append(res.DetectedCVEs, cve)
	}
	sort.Strings(res.DetectedCVEs)
	return res, nil
}

func isRegularFileUnder(path, root string) bool {
	clean := filepath.Clean(path)
	if !strings.HasPrefix(clean, root+string(filepath.Separator)) {
		return false
	}
	st, err := os.Stat(clean)
	return err == nil && st.Mode().IsRegular()
}

func isAllowedRulePackFile(rel string) bool {
	base := filepath.Base(rel)
	if allowedBaseNames[base] {
		return true
	}
	ext := strings.ToLower(filepath.Ext(base))
	if ext != "" && allowedFileExts[ext] {
		return true
	}
	// 处理 .gitkeep / .gitignore 等以点开头文件名
	if allowedFileExts[strings.ToLower(base)] {
		return true
	}
	return false
}

func normalizeRulePackPath(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '\x00') {
		return "", errors.New("归档包含空路径或 NUL 字节")
	}
	if strings.Contains(name, "\\") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("归档路径不允许绝对路径或反斜杠: %s", name)
	}
	trimmed := strings.TrimPrefix(name, "./")
	trimmed = strings.TrimSuffix(trimmed, "/")
	if trimmed == "" || trimmed == "." {
		return "", nil
	}
	for _, part := range strings.Split(trimmed, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("归档包含非法路径段或目录穿越: %s", name)
		}
	}
	if !archivePathCharRe.MatchString(trimmed) {
		return "", fmt.Errorf("归档路径包含非法字符: %s", name)
	}
	return trimmed, nil
}

func firstComponent(p string) string {
	if idx := strings.IndexByte(p, '/'); idx >= 0 {
		return p[:idx]
	}
	return p
}

func detectCommonRoot(entries []rawArchiveEntry) string {
	if len(entries) == 0 {
		return ""
	}
	root := firstComponent(entries[0].path)
	if root == "" || root == "manifest.json" || root == "manifest.sig" || root == "rules" {
		return ""
	}
	for _, e := range entries[1:] {
		if firstComponent(e.path) != root {
			return ""
		}
	}
	return root
}

func stripRoot(p, root string) string {
	if root == "" {
		return p
	}
	prefix := root + "/"
	if strings.HasPrefix(p, prefix) {
		return strings.TrimPrefix(p, prefix)
	}
	if p == root {
		return ""
	}
	return p
}
