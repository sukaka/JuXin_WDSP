package rulepacks

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/google/uuid"
)

// Storage 管理版本化规则快照存储目录：
//
//	<storeDir>/
//	├── releases/
//	│   ├── builtin-<ver>/
//	│   └── <YYYYMMDD.N>/
//	├── current -> releases/<active_ver>    (相对软链，跨容器/宿主机挂载通用)
//	└── .staging/                            (临时解包区，完成后原子 rename)
type Storage struct {
	storeDir    string
	archivesDir string
}

// NewStorage 创建规则包存储管理器。storeDir 为空表示仅运行于只读兼容模式。
func NewStorage(storeDir, archivesDir string) *Storage {
	return &Storage{
		storeDir:    strings.TrimSpace(storeDir),
		archivesDir: strings.TrimSpace(archivesDir),
	}
}

// StoreDir 返回版本化规则根目录路径。
func (s *Storage) StoreDir() string {
	return s.storeDir
}

// ArchivesDir 返回签名原始规则包持久化归档目录。
func (s *Storage) ArchivesDir() string {
	return s.archivesDir
}

// Enabled 判断是否启用了版本化规则存储。
func (s *Storage) Enabled() bool {
	return s.storeDir != ""
}

// ReleasesDir 返回 releases 父目录路径。
func (s *Storage) ReleasesDir() string {
	return filepath.Join(s.storeDir, "releases")
}

// StagingDir 返回 .staging 临时解包目录路径。
func (s *Storage) StagingDir() string {
	return filepath.Join(s.storeDir, ".staging")
}

// ReleaseDir 返回指定规则包版本对应的本地快照路径。
func (s *Storage) ReleaseDir(version string) string {
	return filepath.Join(s.ReleasesDir(), version)
}

// ReleaseCRSDir 返回指定规则包版本对应的 crs/rules 目录路径。
func (s *Storage) ReleaseCRSDir(version string) string {
	return filepath.Join(s.ReleaseDir(version), "crs", "rules")
}

// CurrentSymlinkPath 返回 current 相对符号链接路径。
func (s *Storage) CurrentSymlinkPath() string {
	return filepath.Join(s.storeDir, "current")
}

// Writable 检查规则存储目录是否已配置且当前进程具备可写权限。
func (s *Storage) Writable() bool {
	if !s.Enabled() {
		return false
	}
	if err := os.MkdirAll(s.ReleasesDir(), 0o750); err != nil {
		return false
	}
	if err := os.MkdirAll(s.StagingDir(), 0o750); err != nil {
		return false
	}
	probe := filepath.Join(s.StagingDir(), ".write-probe-"+uuid.NewString())
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return true
}

// HasRelease 检查指定版本的规则快照是否完整落盘（存在关键锚点文件）。
func (s *Storage) HasRelease(version string) bool {
	if !s.Enabled() || ValidateAnyReleaseVersion(version) != nil {
		return false
	}
	dir := s.ReleaseDir(version)
	for _, rel := range []string{
		"coraza.conf",
		"crs/crs-setup.conf",
		"jiuzhang/post-contrib-blocking.conf",
	} {
		st, err := os.Stat(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
			return false
		}
	}
	return true
}

// CurrentSymlinkVersion 读取 current 软链指向的版本名（空串表示未初始化）。
func (s *Storage) CurrentSymlinkVersion() (string, error) {
	if !s.Enabled() {
		return "", nil
	}
	target, err := os.Readlink(s.CurrentSymlinkPath())
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	cleaned := filepath.ToSlash(filepath.Clean(target))
	if !strings.HasPrefix(cleaned, "releases/") {
		return "", fmt.Errorf("current 软链指向非预期路径: %s", target)
	}
	ver := strings.TrimPrefix(cleaned, "releases/")
	if err := ValidateAnyReleaseVersion(ver); err != nil {
		return "", fmt.Errorf("current 软链版本名无效 (%q): %w", ver, err)
	}
	return ver, nil
}

// EnsureSeeded 确保规则版本存储已完成首次初始化：
//   - 若 current 已指向合法且完整的快照，保持原状（绝不覆盖客户已生效的更新规则包）；
//   - 否则从 seedDir 原子复制一份基线快照到 releases/<builtinVersion> 并切换 current 软链。
//
// 返回 (seededNow, activeVersion, error)。
func (s *Storage) EnsureSeeded(seedDir, builtinVersion string) (bool, string, error) {
	if !s.Enabled() {
		return false, "", ErrStorageUnavailable
	}
	if err := ValidateAnyReleaseVersion(builtinVersion); err != nil {
		return false, "", err
	}
	if err := os.MkdirAll(s.ReleasesDir(), 0o750); err != nil {
		return false, "", fmt.Errorf("创建 releases 目录失败: %w", err)
	}
	if err := os.MkdirAll(s.StagingDir(), 0o750); err != nil {
		return false, "", fmt.Errorf("创建 .staging 目录失败: %w", err)
	}
	if s.archivesDir != "" {
		if err := os.MkdirAll(s.archivesDir, 0o750); err != nil {
			return false, "", fmt.Errorf("创建规则包归档目录失败: %w", err)
		}
	}

	if curVer, err := s.CurrentSymlinkVersion(); err == nil && curVer != "" && s.HasRelease(curVer) {
		return false, curVer, nil
	}

	// 若目标 builtin 快照已存在且完整，仅修复 current 软链
	if s.HasRelease(builtinVersion) {
		if err := s.SwitchCurrentSymlink(builtinVersion); err != nil {
			return false, "", err
		}
		return false, builtinVersion, nil
	}

	seedRoot := ResolveSeedRoot(seedDir)
	if seedRoot == "" {
		return false, "", fmt.Errorf("%w: 未找到可用内置规则种子目录 (configured=%q)", ErrStorageUnavailable, seedDir)
	}
	tmpDir := filepath.Join(s.StagingDir(), "seed-"+uuid.NewString())
	defer func() { _ = os.RemoveAll(tmpDir) }()
	if err := copyRulesTree(seedRoot, tmpDir); err != nil {
		return false, "", fmt.Errorf("复制规则种子目录失败: %w", err)
	}
	dest := s.ReleaseDir(builtinVersion)
	if err := os.RemoveAll(dest); err != nil {
		return false, "", fmt.Errorf("清理残留目标目录失败: %w", err)
	}
	if err := os.Rename(tmpDir, dest); err != nil {
		return false, "", fmt.Errorf("原子落盘种子快照失败: %w", err)
	}
	if !s.HasRelease(builtinVersion) {
		return false, "", fmt.Errorf("种子快照缺少核心锚点文件: %s", dest)
	}
	if err := s.SwitchCurrentSymlink(builtinVersion); err != nil {
		return false, "", err
	}
	return true, builtinVersion, nil
}

// StageArchive 将已验签规则包原子解压到 releases/<version>/（先解压到 .staging，校验锚点后 rename）。
func (s *Storage) StageArchive(archivePath, version string) (string, error) {
	if !s.Enabled() {
		return "", ErrStorageUnavailable
	}
	if err := ValidateAnyReleaseVersion(version); err != nil {
		return "", err
	}
	if err := os.MkdirAll(s.ReleasesDir(), 0o750); err != nil {
		return "", fmt.Errorf("创建 releases 目录失败: %w", err)
	}
	if err := os.MkdirAll(s.StagingDir(), 0o750); err != nil {
		return "", fmt.Errorf("创建 .staging 目录失败: %w", err)
	}

	tmpDir := filepath.Join(s.StagingDir(), "stage-"+version+"-"+uuid.NewString())
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if err := ExtractRulesToDir(archivePath, tmpDir); err != nil {
		return "", err
	}
	dest := s.ReleaseDir(version)
	if _, err := os.Stat(dest); err == nil {
		// 目标已存在（例如此前中断残留或重复回滚补发）：先挪走旧目录再原子替换，最后删除旧目录
		backupOld := filepath.Join(s.StagingDir(), "old-"+version+"-"+uuid.NewString())
		if err := os.Rename(dest, backupOld); err != nil {
			return "", fmt.Errorf("移走旧快照目录失败: %w", err)
		}
		if err := os.Rename(tmpDir, dest); err != nil {
			_ = os.Rename(backupOld, dest) // 尽力恢复
			return "", fmt.Errorf("原子替换快照目录失败: %w", err)
		}
		_ = os.RemoveAll(backupOld)
	} else {
		if err := os.Rename(tmpDir, dest); err != nil {
			return "", fmt.Errorf("原子落盘规则快照失败: %w", err)
		}
	}
	if !s.HasRelease(version) {
		return "", fmt.Errorf("%w: 解压后的快照缺少核心锚点文件 (%s)", ErrInvalidArchive, version)
	}
	return dest, nil
}

// SwitchCurrentSymlink 原子切换相对符号链接 current -> releases/<version>。
func (s *Storage) SwitchCurrentSymlink(version string) error {
	if !s.Enabled() {
		return ErrStorageUnavailable
	}
	if !s.HasRelease(version) {
		return fmt.Errorf("目标规则快照不存在或不完整: %s", version)
	}
	relTarget := filepath.Join("releases", version)
	tmpLink := filepath.Join(s.storeDir, ".current.tmp."+uuid.NewString())
	if err := os.Symlink(relTarget, tmpLink); err != nil {
		return fmt.Errorf("创建临时相对软链失败: %w", err)
	}
	if err := os.Rename(tmpLink, s.CurrentSymlinkPath()); err != nil {
		_ = os.Remove(tmpLink)
		return fmt.Errorf("原子切换 current 软链失败: %w", err)
	}
	return nil
}

// ListReleases 列出 releases/ 目录下的所有合法快照版本号（按版本新到旧排序）。
func (s *Storage) ListReleases() ([]string, error) {
	if !s.Enabled() {
		return nil, nil
	}
	entries, err := os.ReadDir(s.ReleasesDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if ValidateAnyReleaseVersion(e.Name()) == nil {
			out = append(out, e.Name())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		c, err := CompareRulePackVersion(out[i], out[j])
		if err != nil {
			return out[i] > out[j]
		}
		return c > 0
	})
	return out, nil
}

// PruneReleases 按保留策略清理超出 retention 的历史快照。
// 绝不删除 protected 集合中的版本及内置种子（builtin-*）。
func (s *Storage) PruneReleases(retention int, protected map[string]bool) ([]string, error) {
	if !s.Enabled() {
		return nil, nil
	}
	if retention < MinRetention {
		retention = DefaultRetention
	}
	if retention > MaxRetention {
		retention = MaxRetention
	}
	all, err := s.ListReleases()
	if err != nil {
		return nil, err
	}
	var dated []string
	for _, v := range all {
		if IsBuiltinVersion(v) {
			continue
		}
		dated = append(dated, v)
	}
	// dated 已按版本从新到旧排序，保留前 retention 个
	if len(dated) <= retention {
		return nil, nil
	}
	var pruned []string
	for _, v := range dated[retention:] {
		if protected[v] {
			continue
		}
		if err := os.RemoveAll(s.ReleaseDir(v)); err != nil {
			return pruned, fmt.Errorf("清理旧快照 %s 失败: %w", v, err)
		}
		pruned = append(pruned, v)
	}
	return pruned, nil
}

// PersistArchive 将已验签的临时上传归档原子保存到持久化归档目录（0600）。
func (s *Storage) PersistArchive(tmpPath string, packID uuid.UUID) (string, error) {
	if s.archivesDir == "" {
		return "", ErrStorageUnavailable
	}
	if err := os.MkdirAll(s.archivesDir, 0o750); err != nil {
		return "", fmt.Errorf("创建归档目录失败: %w", err)
	}
	dest := filepath.Join(s.archivesDir, packID.String()+".tar.gz")
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return "", fmt.Errorf("设置归档文件权限失败: %w", err)
	}
	if err := os.Rename(tmpPath, dest); err == nil {
		return dest, nil
	}
	// 跨文件系统时回落安全复制 + 原子 rename
	stageDest := dest + ".tmp." + uuid.NewString()
	in, err := os.Open(tmpPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(stageDest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(stageDest)
		return "", fmt.Errorf("复制归档失败: copy=%v sync=%v close=%v", copyErr, syncErr, closeErr)
	}
	if err := os.Rename(stageDest, dest); err != nil {
		_ = os.Remove(stageDest)
		return "", err
	}
	_ = os.Remove(tmpPath)
	return dest, nil
}

// ResolveSeedRoot 探测可用的规则种子根目录（含 coraza.conf 与 crs/rules/*.conf）。
func ResolveSeedRoot(configured string) string {
	candidates := []string{}
	if c := strings.TrimSpace(configured); c != "" {
		candidates = append(candidates, c)
		// 若传入的是 .../crs/rules，自动推导上两级目录作为 rules 根
		if filepath.Base(c) == "rules" && filepath.Base(filepath.Dir(c)) == "crs" {
			candidates = append(candidates, filepath.Dir(filepath.Dir(c)))
		}
	}
	candidates = append(candidates,
		"/app/gateway/rules",
		"gateway/rules",
		filepath.Join("..", "gateway/rules"),
		"/etc/caddy/rules",
	)
	for _, cand := range candidates {
		if hasCoreSeedFiles(cand) {
			return cand
		}
	}
	return ""
}

func hasCoreSeedFiles(root string) bool {
	if root == "" {
		return false
	}
	for _, rel := range []string{"coraza.conf", "crs/crs-setup.conf", "jiuzhang/post-contrib-blocking.conf"} {
		st, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
			return false
		}
	}
	confs, err := filepath.Glob(filepath.Join(root, "crs", "rules", "*.conf"))
	return err == nil && len(confs) > 0
}

// copyRulesTree 复制规则目录树（忽略符号链接，强制目录 0750 / 文件 0640 权限，供共享组/1000 只读访问）。
func copyRulesTree(src, dst string) error {
	cleanSrc := filepath.Clean(src)
	return filepath.WalkDir(cleanSrc, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(cleanSrc, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil // 种子复制跳过符号链接，防止目录逃逸
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer func() { _ = in.Close() }()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = out.Close()
			return err
		}
		if err := out.Sync(); err != nil {
			_ = out.Close()
			return err
		}
		return out.Close()
	})
}

// DiskFreeBytes 返回目录所在分区的非特权可用字节数（无法检测时返回 -1）。
func DiskFreeBytes(dir string) int64 {
	if strings.TrimSpace(dir) == "" {
		return -1
	}
	checkDir := dir
	for {
		if st, err := os.Stat(checkDir); err == nil && st.IsDir() {
			break
		}
		parent := filepath.Dir(checkDir)
		if parent == checkDir {
			return -1
		}
		checkDir = parent
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(checkDir, &st); err != nil {
		return -1
	}
	return int64(st.Bavail) * int64(st.Bsize)
}
