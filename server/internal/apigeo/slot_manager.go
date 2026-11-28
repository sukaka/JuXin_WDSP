// slot_manager.go GeoIP 归属地库槽位存储、解压验真、原子切换、备份回滚与目录 revision 维护。
//
// 安全基线：
//   - 槽位白名单（ip2region_v4 / ip2region_v6 / dbip_city / city_ipv6 / country），严禁路径穿越；
//   - 解压严格使用 io.LimitReader 拦截 gzip / tar.gz 炸弹，tar 条目拒绝绝对路径、.. 与符号链接；
//   - 先通过 OpenXDB / OpenMMDB + 探针 IP 验真，再 fsync + os.Rename 原子替换活跃文件；
//   - 活跃文件变更前自动备份至 .backups/<slot>/（每槽位最多保留 3 份），支持可逆一键回滚；
//   - 原子更新 .revision.json 通知本机与 HA 备节点 ReloadableEngine 无感热重载。
package apigeo

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// 槽位标识白名单（与迁移 000256 geoip_slot_configs CHECK 约束严格一致）。
const (
	SlotIP2RegionV4 = "ip2region_v4"
	SlotIP2RegionV6 = "ip2region_v6"
	SlotDBIPCity    = "dbip_city"
	SlotCityIPv6    = "city_ipv6"
	SlotCountry     = "country"
)

// 活跃来源词表（与迁移 000256 CHECK 约束一致）。
const (
	SourceTypeBuiltin  = "BUILTIN"
	SourceTypeOnline   = "ONLINE"
	SourceTypeOffline  = "OFFLINE"
	SourceTypeHASync   = "HA_SYNC"
	SourceTypeRollback = "ROLLBACK"
)

const (
	revisionFileName    = ".revision.json"
	stagingDirName      = ".staging"
	backupsDirName      = ".backups"
	maxBackupsPerSlot   = 3
	maxArchiveOverhead  = 8 << 20 // 允许 tar/gzip 封装额外开销 8 MiB
	maxTarEntries       = 256     // 防恶意海量条目 tar 包
)

// 哨兵错误（HTTP 层用于精确区分 400 / 404 / 413 / 500）。
var (
	ErrInvalidSlot     = errors.New("无效的 GeoIP 槽位")
	ErrInvalidBackupID = errors.New("无效的备份标识")
	ErrBackupNotFound  = errors.New("指定的 GeoIP 备份不存在")
	ErrGeoFileTooLarge = errors.New("GeoIP 文件体积超过槽位上限")
	ErrGeoFileInvalid  = errors.New("GeoIP 文件格式或内容校验未通过")
	ErrSHA256Mismatch  = errors.New("GeoIP 文件 SHA-256 校验不匹配")
)

var (
	backupIDPattern = regexp.MustCompile(`^[0-9]{10,14}-[0-9a-f]{12}\.(xdb|mmdb)$`)
	sha256HexRE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// SlotSpec 描述单个 GeoIP 槽位的规范文件名、格式与安全限制。
type SlotSpec struct {
	Slot              string
	DisplayName       string
	CanonicalFile     string
	Format            string // "xdb" | "mmdb"
	Ext               string // ".xdb" | ".mmdb"
	RequiredIPVersion int    // 4 / 6 / 0(双栈均可)
	MaxBytes          int64
	// LegacyPatterns 激活该槽位时需从 <geoipDir> 归档的旧命名模式（防 findFirstMatch 优先级抢占）。
	LegacyPatterns []string
	// FallbackPatterns 扫描内置/回退目录时的匹配模式。
	FallbackPatterns []string
}

// SlotOrder 槽位固定展示顺序。
var SlotOrder = []string{
	SlotIP2RegionV4,
	SlotIP2RegionV6,
	SlotDBIPCity,
	SlotCityIPv6,
	SlotCountry,
}

var slotSpecs = map[string]SlotSpec{
	SlotIP2RegionV4: {
		Slot:              SlotIP2RegionV4,
		DisplayName:       "ip2region IPv4（国内省市/运营商）",
		CanonicalFile:     "ip2region_v4.xdb",
		Format:            "xdb",
		Ext:               ".xdb",
		RequiredIPVersion: 4,
		MaxBytes:          64 << 20,
		LegacyPatterns:    []string{"ip2region.xdb"},
		FallbackPatterns:  []string{"ip2region_v4.xdb", "ip2region.xdb"},
	},
	SlotIP2RegionV6: {
		Slot:              SlotIP2RegionV6,
		DisplayName:       "ip2region IPv6（国内省市/运营商）",
		CanonicalFile:     "ip2region_v6.xdb",
		Format:            "xdb",
		Ext:               ".xdb",
		RequiredIPVersion: 6,
		MaxBytes:          128 << 20,
		FallbackPatterns:  []string{"ip2region_v6.xdb"},
	},
	SlotDBIPCity: {
		Slot:              SlotDBIPCity,
		DisplayName:       "全球城市库（DB-IP Lite / MaxMind GeoLite2 City）",
		CanonicalFile:     "city.mmdb",
		Format:            "mmdb",
		Ext:               ".mmdb",
		RequiredIPVersion: 0,
		MaxBytes:          256 << 20,
		LegacyPatterns:    []string{"dbip-city-lite*.mmdb", "GeoLite2-City.mmdb"},
		FallbackPatterns:  []string{"dbip-city-lite*.mmdb", "city.mmdb", "GeoLite2-City.mmdb"},
	},
	SlotCityIPv6: {
		Slot:              SlotCityIPv6,
		DisplayName:       "IPv6 专用城市库（MMDB）",
		CanonicalFile:     "city-ipv6.mmdb",
		Format:            "mmdb",
		Ext:               ".mmdb",
		RequiredIPVersion: 6,
		MaxBytes:          128 << 20,
		FallbackPatterns:  []string{"city-ipv6.mmdb"},
	},
	SlotCountry: {
		Slot:              SlotCountry,
		DisplayName:       "国家码回退库（DB-IP / GeoLite2 / Country MMDB）",
		CanonicalFile:     "country.mmdb",
		Format:            "mmdb",
		Ext:               ".mmdb",
		RequiredIPVersion: 0,
		MaxBytes:          32 << 20,
		LegacyPatterns:    []string{"dbip-country-lite*.mmdb", "GeoLite2-Country.mmdb"},
		FallbackPatterns:  []string{"dbip-country-lite*.mmdb", "country.mmdb", "GeoLite2-Country.mmdb"},
	},
}

// ValidSlot 校验槽位标识并返回其规格。
func ValidSlot(slot string) (SlotSpec, bool) {
	spec, ok := slotSpecs[strings.TrimSpace(slot)]
	return spec, ok
}

// RevisionState 写入 <geoipDir>/.revision.json 的目录版本元数据。
type RevisionState struct {
	Revision  string                      `json:"revision"`
	UpdatedAt time.Time                   `json:"updated_at"`
	Slots     map[string]RevisionSlotMeta `json:"slots"`
}

// RevisionSlotMeta 单个槽位在 .revision.json 中的摘要。
type RevisionSlotMeta struct {
	Filename   string    `json:"filename"`
	SHA256     string    `json:"sha256"`
	SizeBytes  int64     `json:"size_bytes"`
	SourceType string    `json:"source_type"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// BackupEntry 槽位可回滚的历史备份项。
type BackupEntry struct {
	BackupID  string    `json:"backup_id"`
	Filename  string    `json:"filename"`
	SHA256    string    `json:"sha256"`
	SizeBytes int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
}

// SlotDiskState 槽位在磁盘上的实际状态快照。
type SlotDiskState struct {
	Slot           string        `json:"slot"`
	DisplayName    string        `json:"display_name"`
	CanonicalFile  string        `json:"canonical_file"`
	Format         string        `json:"format"`
	MaxBytes       int64         `json:"max_bytes"`
	ActiveOrigin   string        `json:"active_origin"` // runtime | builtin | missing
	ActiveFilename string        `json:"active_filename"`
	SHA256         string        `json:"sha256"`
	SizeBytes      int64         `json:"size_bytes"`
	UpdatedAt      *time.Time    `json:"updated_at,omitempty"`
	Backups        []BackupEntry `json:"backups"`
}

// InstallResult 一次槽位安装或回滚的结果。
type InstallResult struct {
	Slot           string             `json:"slot"`
	Filename       string             `json:"filename"`
	PreviousSHA256 string             `json:"previous_sha256"`
	NewSHA256      string             `json:"new_sha256"`
	SizeBytes      int64              `json:"size_bytes"`
	Revision       string             `json:"revision"`
	Unchanged      bool               `json:"unchanged"`
	LoadedSources  []string           `json:"loaded_sources"`
	HAResults      []HANodeSyncResult `json:"ha_results,omitempty"`
}

// SlotManager 管理 <dataDir>/geoip 目录下的槽位文件、备份与热重载。
type SlotManager struct {
	geoipDir   string
	searchDirs []string
	engine     *ReloadableEngine
	mu         sync.Mutex
	now        func() time.Time
}

// NewSlotManager 创建槽位管理器。geoipDir 为运行期可写目录（如 <dataDir>/geoip）。
func NewSlotManager(geoipDir string, engine *ReloadableEngine, searchDirs ...string) *SlotManager {
	cleanedSearch := make([]string, 0, len(searchDirs))
	for _, d := range searchDirs {
		d = strings.TrimSpace(d)
		if d != "" {
			cleanedSearch = append(cleanedSearch, filepath.Clean(d))
		}
	}
	if len(cleanedSearch) == 0 && engine != nil {
		cleanedSearch = engine.Dirs()
	}
	return &SlotManager{
		geoipDir:   filepath.Clean(strings.TrimSpace(geoipDir)),
		searchDirs: cleanedSearch,
		engine:     engine,
		now:        func() time.Time { return time.Now().UTC() },
	}
}

// GeoIPDir 返回运行期 GeoIP 目录路径。
func (m *SlotManager) GeoIPDir() string { return m.geoipDir }

// Engine 返回绑定的可热重载引擎。
func (m *SlotManager) Engine() *ReloadableEngine { return m.engine }

// InstallSlotFromReader 接收原始/gzip/tar.gz GeoIP 流，验真后原子安装到目标槽位并触发热重载。
func (m *SlotManager) InstallSlotFromReader(slot, originalFilename string, src io.Reader, expectedSHA256, sourceType string) (*InstallResult, error) {
	spec, ok := ValidSlot(slot)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrInvalidSlot, slot)
	}
	if src == nil {
		return nil, fmt.Errorf("%w: 文件流为空", ErrGeoFileInvalid)
	}
	expectedSHA256 = strings.ToLower(strings.TrimSpace(expectedSHA256))
	if expectedSHA256 != "" && !sha256HexRE.MatchString(expectedSHA256) {
		return nil, fmt.Errorf("%w: expected_sha256 须为 64 位十六进制 SHA-256", ErrSHA256Mismatch)
	}
	if sourceType == "" {
		sourceType = SourceTypeOffline
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureDirs(); err != nil {
		return nil, err
	}

	stagedDBPath := filepath.Join(m.stagingDir(), fmt.Sprintf("%s-%d%s", spec.Slot, m.now().UnixNano(), spec.Ext))
	defer func() { _ = os.Remove(stagedDBPath) }()

	newSHA256, newSize, err := m.extractGeoPayload(src, originalFilename, spec, expectedSHA256, stagedDBPath)
	if err != nil {
		return nil, err
	}
	if err := verifyStagedGeoFile(stagedDBPath, spec); err != nil {
		return nil, err
	}

	return m.commitStagedSlotLocked(spec, stagedDBPath, newSHA256, newSize, sourceType)
}

// RollbackSlot 将指定槽位回滚至 .backups/<slot>/<backupID>（回滚前重新验真并备份当前活跃文件）。
func (m *SlotManager) RollbackSlot(slot, backupID string) (*InstallResult, error) {
	spec, ok := ValidSlot(slot)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrInvalidSlot, slot)
	}
	backupID = strings.TrimSpace(backupID)
	if !backupIDPattern.MatchString(backupID) || !strings.HasSuffix(backupID, spec.Ext) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidBackupID, backupID)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureDirs(); err != nil {
		return nil, err
	}

	backupPath := filepath.Join(m.slotBackupDir(spec.Slot), backupID)
	linfo, err := os.Lstat(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrBackupNotFound, backupID)
		}
		return nil, err
	}
	if !linfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: 备份项不是普通文件", ErrInvalidBackupID)
	}

	stagedDBPath := filepath.Join(m.stagingDir(), fmt.Sprintf("rollback-%s-%d%s", spec.Slot, m.now().UnixNano(), spec.Ext))
	defer func() { _ = os.Remove(stagedDBPath) }()

	newSHA256, newSize, err := copyFileWithSHA256(backupPath, stagedDBPath, spec.MaxBytes)
	if err != nil {
		return nil, err
	}
	if err := verifyStagedGeoFile(stagedDBPath, spec); err != nil {
		return nil, fmt.Errorf("%w: 历史备份校验失败: %v", ErrGeoFileInvalid, err)
	}

	return m.commitStagedSlotLocked(spec, stagedDBPath, newSHA256, newSize, SourceTypeRollback)
}

// InspectSlots 检查全部 5 个槽位在运行期与内置回退目录中的状态及备份列表。
func (m *SlotManager) InspectSlots() ([]SlotDiskState, *RevisionState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rev := m.readRevisionLocked()
	out := make([]SlotDiskState, 0, len(SlotOrder))
	for _, slotName := range SlotOrder {
		spec := slotSpecs[slotName]
		state := SlotDiskState{
			Slot:          spec.Slot,
			DisplayName:   spec.DisplayName,
			CanonicalFile: spec.CanonicalFile,
			Format:        spec.Format,
			MaxBytes:      spec.MaxBytes,
			ActiveOrigin:  "missing",
			Backups:       m.listBackupsLocked(spec),
		}
		// 优先检查运行期目录 <geoipDir>
		if runtimePath := findFirstMatch([]string{m.geoipDir}, spec.FallbackPatterns); runtimePath != "" {
			if info, err := os.Stat(runtimePath); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
				state.ActiveOrigin = "runtime"
				state.ActiveFilename = filepath.Base(runtimePath)
				state.SizeBytes = info.Size()
				mt := info.ModTime().UTC()
				state.UpdatedAt = &mt
				// 若 .revision.json 中记录的文件名与大小匹配则直接复用摘要，否则现场计算
				if rev != nil {
					if meta, ok := rev.Slots[spec.Slot]; ok && meta.Filename == state.ActiveFilename && meta.SizeBytes == state.SizeBytes && meta.SHA256 != "" {
						state.SHA256 = meta.SHA256
					}
				}
				if state.SHA256 == "" {
					if sum, err := fileSHA256(runtimePath); err == nil {
						state.SHA256 = sum
					}
				}
			}
		}
		// 运行期无文件时回退检查其余搜索目录（内置镜像库等）
		if state.ActiveOrigin == "missing" {
			var fallbackDirs []string
			for _, d := range m.searchDirs {
				if filepath.Clean(d) == m.geoipDir {
					continue
				}
				fallbackDirs = append(fallbackDirs, d)
			}
			if builtinPath := findFirstMatch(fallbackDirs, spec.FallbackPatterns); builtinPath != "" {
				if info, err := os.Stat(builtinPath); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
					state.ActiveOrigin = "builtin"
					state.ActiveFilename = filepath.Base(builtinPath)
					state.SizeBytes = info.Size()
					mt := info.ModTime().UTC()
					state.UpdatedAt = &mt
					if sum, err := fileSHA256(builtinPath); err == nil {
						state.SHA256 = sum
					}
				}
			}
		}
		out = append(out, state)
	}
	return out, rev, nil
}

// ActiveSlotFilePath 返回指定槽位在运行期目录的活跃文件绝对路径与 SHA-256（供 HA 同步推送用）。
func (m *SlotManager) ActiveSlotFilePath(slot string) (string, string, int64, error) {
	spec, ok := ValidSlot(slot)
	if !ok {
		return "", "", 0, fmt.Errorf("%w: %q", ErrInvalidSlot, slot)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	activePath := filepath.Join(m.geoipDir, spec.CanonicalFile)
	info, err := os.Stat(activePath)
	if err != nil {
		return "", "", 0, err
	}
	sum, err := fileSHA256(activePath)
	if err != nil {
		return "", "", 0, err
	}
	return activePath, sum, info.Size(), nil
}

func (m *SlotManager) commitStagedSlotLocked(spec SlotSpec, stagedDBPath, newSHA256 string, newSize int64, sourceType string) (*InstallResult, error) {
	activePath := filepath.Join(m.geoipDir, spec.CanonicalFile)
	var prevSHA256 string
	if info, err := os.Stat(activePath); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
		if sum, sumErr := fileSHA256(activePath); sumErr == nil {
			prevSHA256 = sum
		}
	}

	legacyFiles := m.findLegacyFilesLocked(spec)
	// 内容完全一致且无残留抢占文件时短路返回，避免无效备份与磁盘写放大
	if prevSHA256 != "" && prevSHA256 == newSHA256 && len(legacyFiles) == 0 {
		rev := m.readRevisionLocked()
		revID := ""
		if rev != nil {
			revID = rev.Revision
		}
		var sources []string
		if m.engine != nil {
			sources = m.engine.Sources()
		}
		return &InstallResult{
			Slot:           spec.Slot,
			Filename:       spec.CanonicalFile,
			PreviousSHA256: prevSHA256,
			NewSHA256:      newSHA256,
			SizeBytes:      newSize,
			Revision:       revID,
			Unchanged:      true,
			LoadedSources:  sources,
		}, nil
	}

	// 1. 备份当前活跃文件及被替代的旧命名文件
	if prevSHA256 != "" {
		if err := m.archiveToBackupLocked(spec, activePath, prevSHA256); err != nil {
			return nil, fmt.Errorf("备份当前 GeoIP 文件失败: %w", err)
		}
	}
	for _, lf := range legacyFiles {
		if sum, sumErr := fileSHA256(lf); sumErr == nil {
			if err := m.archiveToBackupLocked(spec, lf, sum); err != nil {
				return nil, fmt.Errorf("归档旧命名 GeoIP 文件失败: %w", err)
			}
		}
	}

	// 2. fsync 后原子覆盖活跃文件
	if err := syncFile(stagedDBPath); err != nil {
		return nil, fmt.Errorf("落盘同步临时 GeoIP 文件失败: %w", err)
	}
	if err := os.Chmod(stagedDBPath, 0o640); err != nil {
		return nil, fmt.Errorf("设置 GeoIP 文件权限失败: %w", err)
	}
	if err := os.Rename(stagedDBPath, activePath); err != nil {
		return nil, fmt.Errorf("原子替换活跃 GeoIP 文件失败: %w", err)
	}

	// 清理已归档的旧命名文件（避免 findFirstMatch 按高优先级抢占 canonical 文件）
	for _, lf := range legacyFiles {
		if filepath.Clean(lf) != filepath.Clean(activePath) {
			_ = os.Remove(lf)
		}
	}

	m.pruneBackupsLocked(spec)

	// 3. 原子更新 .revision.json
	now := m.now()
	rev := m.readRevisionLocked()
	if rev == nil {
		rev = &RevisionState{Slots: map[string]RevisionSlotMeta{}}
	}
	if rev.Slots == nil {
		rev.Slots = map[string]RevisionSlotMeta{}
	}
	rev.Revision = newRevisionID(now)
	rev.UpdatedAt = now
	rev.Slots[spec.Slot] = RevisionSlotMeta{
		Filename:   spec.CanonicalFile,
		SHA256:     newSHA256,
		SizeBytes:  newSize,
		SourceType: sourceType,
		UpdatedAt:  now,
	}
	if err := m.writeRevisionLocked(rev); err != nil {
		return nil, fmt.Errorf("写入 GeoIP revision 文件失败: %w", err)
	}

	// 4. 立即触发本机零重启热重载
	var loadedSources []string
	if m.engine != nil {
		eng := m.engine.Reload()
		loadedSources = eng.Sources()
	}

	return &InstallResult{
		Slot:           spec.Slot,
		Filename:       spec.CanonicalFile,
		PreviousSHA256: prevSHA256,
		NewSHA256:      newSHA256,
		SizeBytes:      newSize,
		Revision:       rev.Revision,
		Unchanged:      false,
		LoadedSources:  loadedSources,
	}, nil
}

// extractGeoPayload 流式落盘原始字节，自动识别原始 / .gz / .tar.gz（MaxMind GeoLite2），
// 防解压炸弹与路径穿越，输出最终解压后的 DB 文件至 destPath。
func (m *SlotManager) extractGeoPayload(src io.Reader, originalFilename string, spec SlotSpec, expectedSHA256, destPath string) (string, int64, error) {
	rawPath := filepath.Join(m.stagingDir(), fmt.Sprintf("raw-%s-%d.tmp", spec.Slot, m.now().UnixNano()))
	defer func() { _ = os.Remove(rawPath) }()

	maxRawBytes := spec.MaxBytes + maxArchiveOverhead
	rawFile, err := os.OpenFile(rawPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		return "", 0, fmt.Errorf("创建临时接收文件失败: %w", err)
	}
	rawHasher := sha256.New()
	rawWritten, copyErr := io.Copy(io.MultiWriter(rawFile, rawHasher), io.LimitReader(src, maxRawBytes+1))
	_ = rawFile.Close()
	if copyErr != nil {
		return "", 0, fmt.Errorf("读取 GeoIP 文件流失败: %w", copyErr)
	}
	if rawWritten == 0 {
		return "", 0, fmt.Errorf("%w: 文件内容为空", ErrGeoFileInvalid)
	}
	if rawWritten > maxRawBytes {
		return "", 0, fmt.Errorf("%w: 上传/下载文件超过上限 (%d 字节)", ErrGeoFileTooLarge, maxRawBytes)
	}
	rawSHA256 := hex.EncodeToString(rawHasher.Sum(nil))

	isGzip, err := hasGzipMagic(rawPath)
	if err != nil {
		return "", 0, fmt.Errorf("读取文件头失败: %w", err)
	}

	var extractedSHA256 string
	var extractedSize int64

	if !isGzip {
		if rawWritten > spec.MaxBytes {
			return "", 0, fmt.Errorf("%w: 文件大小 %d 超过槽位上限 %d 字节", ErrGeoFileTooLarge, rawWritten, spec.MaxBytes)
		}
		if err := os.Rename(rawPath, destPath); err != nil {
			return "", 0, fmt.Errorf("移动临时文件失败: %w", err)
		}
		extractedSHA256 = rawSHA256
		extractedSize = rawWritten
	} else {
		isTarGz, err := isGzippedTar(rawPath, originalFilename)
		if err != nil {
			return "", 0, fmt.Errorf("%w: gzip 解压检查失败: %v", ErrGeoFileInvalid, err)
		}
		if isTarGz {
			extractedSHA256, extractedSize, err = extractFromTarGz(rawPath, spec, destPath)
		} else {
			extractedSHA256, extractedSize, err = extractFromPlainGzip(rawPath, spec, destPath)
		}
		if err != nil {
			return "", 0, err
		}
	}

	if expectedSHA256 != "" && expectedSHA256 != rawSHA256 && expectedSHA256 != extractedSHA256 {
		return "", 0, fmt.Errorf("%w: 期望 %s，实际原始 %s / 解压后 %s",
			ErrSHA256Mismatch, expectedSHA256, rawSHA256, extractedSHA256)
	}
	return extractedSHA256, extractedSize, nil
}

func hasGzipMagic(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var hdr [2]byte
	n, err := io.ReadFull(f, hdr[:])
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return false, err
	}
	return n >= 2 && hdr[0] == 0x1f && hdr[1] == 0x8b, nil
}

// isGzippedTar 通过扩展名提示或解压前 512 字节中的 POSIX ustar 魔数判断是否为 .tar.gz 归档。
func isGzippedTar(rawPath, originalFilename string) (bool, error) {
	lower := strings.ToLower(strings.TrimSpace(originalFilename))
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		return true, nil
	}
	f, err := os.Open(rawPath)
	if err != nil {
		return false, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return false, err
	}
	defer gz.Close()
	var hdr [512]byte
	n, err := io.ReadFull(gz, hdr[:])
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return false, err
	}
	if n >= 263 && string(hdr[257:262]) == "ustar" {
		return true, nil
	}
	return false, nil
}

func extractFromPlainGzip(rawPath string, spec SlotSpec, destPath string) (string, int64, error) {
	f, err := os.Open(rawPath)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", 0, fmt.Errorf("%w: 非法 gzip 流: %v", ErrGeoFileInvalid, err)
	}
	defer gz.Close()

	dst, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", 0, err
	}
	hasher := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(dst, hasher), io.LimitReader(gz, spec.MaxBytes+1))
	closeErr := dst.Close()
	if copyErr != nil {
		return "", 0, fmt.Errorf("%w: 解压 gzip 失败: %v", ErrGeoFileInvalid, copyErr)
	}
	if closeErr != nil {
		return "", 0, closeErr
	}
	if n == 0 {
		return "", 0, fmt.Errorf("%w: 解压后内容为空", ErrGeoFileInvalid)
	}
	if n > spec.MaxBytes {
		return "", 0, fmt.Errorf("%w: 解压后体积超过槽位上限 %d 字节", ErrGeoFileTooLarge, spec.MaxBytes)
	}
	return hex.EncodeToString(hasher.Sum(nil)), n, nil
}

// extractFromTarGz 安全从 .tar.gz（如 MaxMind GeoLite2-City_*.tar.gz）提取唯一匹配的 .mmdb/.xdb 文件。
func extractFromTarGz(rawPath string, spec SlotSpec, destPath string) (string, int64, error) {
	f, err := os.Open(rawPath)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", 0, fmt.Errorf("%w: 非法 tar.gz 流: %v", ErrGeoFileInvalid, err)
	}
	defer gz.Close()

	// 总解压读取预算（防止 tar 包内嵌非目标超大垃圾文件导致 CPU/IO 耗尽）
	limitedStream := io.LimitReader(gz, spec.MaxBytes+maxArchiveOverhead+1)
	tr := tar.NewReader(limitedStream)

	matchedCount := 0
	var extractedSHA256 string
	var extractedSize int64

	for entries := 0; ; entries++ {
		if entries >= maxTarEntries {
			return "", 0, fmt.Errorf("%w: tar.gz 条目数超过保护上限 %d", ErrGeoFileInvalid, maxTarEntries)
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", 0, fmt.Errorf("%w: 解析 tar.gz 失败: %v", ErrGeoFileInvalid, err)
		}
		if err := validateTarEntryPath(hdr.Name); err != nil {
			return "", 0, err
		}
		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
			return "", 0, fmt.Errorf("%w: tar.gz 不允许包含符号链接或硬链接 (%s)", ErrGeoFileInvalid, hdr.Name)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		base := path.Base(hdr.Name)
		if !strings.HasSuffix(strings.ToLower(base), spec.Ext) {
			continue
		}
		matchedCount++
		if matchedCount > 1 {
			return "", 0, fmt.Errorf("%w: tar.gz 包含多个 %s 文件，无法确定目标库", ErrGeoFileInvalid, spec.Ext)
		}
		if hdr.Size <= 0 {
			return "", 0, fmt.Errorf("%w: tar.gz 目标文件 %s 为空", ErrGeoFileInvalid, base)
		}
		if hdr.Size > spec.MaxBytes {
			return "", 0, fmt.Errorf("%w: tar.gz 内目标文件超过槽位上限 %d 字节", ErrGeoFileTooLarge, spec.MaxBytes)
		}
		dst, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return "", 0, err
		}
		hasher := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(dst, hasher), io.LimitReader(tr, spec.MaxBytes+1))
		closeErr := dst.Close()
		if copyErr != nil {
			return "", 0, fmt.Errorf("%w: 提取 tar.gz 目标文件失败: %v", ErrGeoFileInvalid, copyErr)
		}
		if closeErr != nil {
			return "", 0, closeErr
		}
		if n > spec.MaxBytes {
			return "", 0, fmt.Errorf("%w: 提取文件超过槽位上限 %d 字节", ErrGeoFileTooLarge, spec.MaxBytes)
		}
		extractedSHA256 = hex.EncodeToString(hasher.Sum(nil))
		extractedSize = n
	}

	if matchedCount == 0 {
		return "", 0, fmt.Errorf("%w: tar.gz 中未找到 %s 数据文件", ErrGeoFileInvalid, spec.Ext)
	}
	return extractedSHA256, extractedSize, nil
}

func validateTarEntryPath(name string) error {
	cleaned := strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(cleaned, "/") {
		return fmt.Errorf("%w: tar.gz 包含绝对路径 %q", ErrGeoFileInvalid, name)
	}
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == ".." {
			return fmt.Errorf("%w: tar.gz 包含路径穿越段 %q", ErrGeoFileInvalid, name)
		}
	}
	return nil
}

// verifyStagedGeoFile 使用自研只读解析器 + 探针 IP 全面校验待生效文件。
func verifyStagedGeoFile(stagedPath string, spec SlotSpec) error {
	switch spec.Format {
	case "xdb":
		x, err := OpenXDB(stagedPath)
		if err != nil {
			return fmt.Errorf("%w: XDB 解析失败: %v", ErrGeoFileInvalid, err)
		}
		if spec.RequiredIPVersion != 0 && x.IPVersion() != spec.RequiredIPVersion {
			return fmt.Errorf("%w: XDB IP 版本为 IPv%d，与槽位 %s（期望 IPv%d）不匹配",
				ErrGeoFileInvalid, x.IPVersion(), spec.Slot, spec.RequiredIPVersion)
		}
		probes := []string{"1.1.1.1", "114.114.114.114"}
		if x.IPVersion() == 6 {
			probes = []string{"2001:4860:4860::8888", "2400:3200::1"}
		}
		for _, ipStr := range probes {
			if _, err := x.Lookup(netip.MustParseAddr(ipStr)); err != nil {
				return fmt.Errorf("%w: XDB 探针查询 %s 失败: %v", ErrGeoFileInvalid, ipStr, err)
			}
		}
		return nil

	case "mmdb":
		m, err := OpenMMDB(stagedPath)
		if err != nil {
			return fmt.Errorf("%w: MMDB 解析失败: %v", ErrGeoFileInvalid, err)
		}
		if spec.RequiredIPVersion == 6 && m.meta.ipVersion != 6 {
			return fmt.Errorf("%w: MMDB 仅支持 IPv%d，无法写入 IPv6 槽位 %s",
				ErrGeoFileInvalid, m.meta.ipVersion, spec.Slot)
		}
		if _, err := m.LookupLocation(netip.MustParseAddr("1.1.1.1")); err != nil {
			return fmt.Errorf("%w: MMDB IPv4 探针查询失败: %v", ErrGeoFileInvalid, err)
		}
		if m.meta.ipVersion == 6 {
			if _, err := m.LookupLocation(netip.MustParseAddr("2001:4860:4860::8888")); err != nil {
				return fmt.Errorf("%w: MMDB IPv6 探针查询失败: %v", ErrGeoFileInvalid, err)
			}
		}
		return nil

	default:
		return fmt.Errorf("%w: 未知格式 %s", ErrGeoFileInvalid, spec.Format)
	}
}

func (m *SlotManager) stagingDir() string {
	return filepath.Join(m.geoipDir, stagingDirName)
}

func (m *SlotManager) slotBackupDir(slot string) string {
	return filepath.Join(m.geoipDir, backupsDirName, slot)
}

func (m *SlotManager) ensureDirs() error {
	for _, dir := range []string{m.geoipDir, m.stagingDir(), filepath.Join(m.geoipDir, backupsDirName)} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("创建 GeoIP 目录 %s 失败: %w", dir, err)
		}
	}
	for _, slot := range SlotOrder {
		if err := os.MkdirAll(m.slotBackupDir(slot), 0o750); err != nil {
			return fmt.Errorf("创建 GeoIP 备份目录失败: %w", err)
		}
	}
	return nil
}

func (m *SlotManager) findLegacyFilesLocked(spec SlotSpec) []string {
	var out []string
	seen := map[string]bool{}
	for _, pat := range spec.LegacyPatterns {
		matches, err := filepath.Glob(filepath.Join(m.geoipDir, pat))
		if err != nil {
			continue
		}
		for _, p := range matches {
			clean := filepath.Clean(p)
			if seen[clean] || filepath.Base(clean) == spec.CanonicalFile {
				continue
			}
			if info, statErr := os.Stat(clean); statErr == nil && info.Mode().IsRegular() && info.Size() > 0 {
				seen[clean] = true
				out = append(out, clean)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (m *SlotManager) archiveToBackupLocked(spec SlotSpec, srcPath, sha string) error {
	if len(sha) < 12 {
		return nil
	}
	short := sha[:12]
	backupDir := m.slotBackupDir(spec.Slot)
	// 若备份目录已存在同摘要文件则不重复复制
	if entries, err := os.ReadDir(backupDir); err == nil {
		suffix := "-" + short + spec.Ext
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), suffix) {
				return nil
			}
		}
	}
	backupName := fmt.Sprintf("%d-%s%s", m.now().Unix(), short, spec.Ext)
	dstPath := filepath.Join(backupDir, backupName)
	tmpPath := dstPath + ".tmp"
	if _, _, err := copyFileWithSHA256(srcPath, tmpPath, spec.MaxBytes); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := syncFile(tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, dstPath)
}

func (m *SlotManager) pruneBackupsLocked(spec SlotSpec) {
	backups := m.listBackupsLocked(spec)
	if len(backups) <= maxBackupsPerSlot {
		return
	}
	for _, old := range backups[maxBackupsPerSlot:] {
		_ = os.Remove(filepath.Join(m.slotBackupDir(spec.Slot), old.BackupID))
	}
}

func (m *SlotManager) listBackupsLocked(spec SlotSpec) []BackupEntry {
	backupDir := m.slotBackupDir(spec.Slot)
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return []BackupEntry{}
	}
	var out []BackupEntry
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !backupIDPattern.MatchString(name) || !strings.HasSuffix(name, spec.Ext) {
			continue
		}
		full := filepath.Join(backupDir, name)
		info, statErr := os.Stat(full)
		if statErr != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			continue
		}
		sum, _ := fileSHA256(full)
		out = append(out, BackupEntry{
			BackupID:  name,
			Filename:  spec.CanonicalFile,
			SHA256:    sum,
			SizeBytes: info.Size(),
			CreatedAt: info.ModTime().UTC(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].BackupID != out[j].BackupID {
			return out[i].BackupID > out[j].BackupID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

func (m *SlotManager) readRevisionLocked() *RevisionState {
	raw, err := os.ReadFile(filepath.Join(m.geoipDir, revisionFileName))
	if err != nil || len(raw) == 0 {
		return nil
	}
	var rev RevisionState
	if err := json.Unmarshal(raw, &rev); err != nil {
		return nil
	}
	return &rev
}

func (m *SlotManager) writeRevisionLocked(rev *RevisionState) error {
	raw, err := json.MarshalIndent(rev, "", "  ")
	if err != nil {
		return err
	}
	revPath := filepath.Join(m.geoipDir, revisionFileName)
	tmpPath := filepath.Join(m.stagingDir(), fmt.Sprintf("revision-%d.json", m.now().UnixNano()))
	if err := os.WriteFile(tmpPath, raw, 0o640); err != nil {
		return err
	}
	if err := syncFile(tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, revPath)
}

func newRevisionID(now time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}

func fileSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFileWithSHA256(srcPath, dstPath string, maxBytes int64) (string, int64, error) {
	src, err := os.Open(srcPath)
	if err != nil {
		return "", 0, err
	}
	defer src.Close()
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(dst, h), io.LimitReader(src, maxBytes+1))
	closeErr := dst.Close()
	if copyErr != nil {
		return "", 0, copyErr
	}
	if closeErr != nil {
		return "", 0, closeErr
	}
	if n > maxBytes {
		return "", 0, fmt.Errorf("%w: 文件超过 %d 字节上限", ErrGeoFileTooLarge, maxBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func syncFile(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
