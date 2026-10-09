// precheck.go 升级前检查：事实采集 + 纯函数评估。
package upgrades

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/encryption"
)

// 检查结果
const (
	CheckPass    = "PASS"
	CheckWarning = "WARNING"
	CheckFail    = "FAIL"
)

// 磁盘余量阈值
const (
	diskMinBytes  = 2 << 30 // 2GiB：低于此值 FAIL
	diskWarnBytes = 4 << 30 // 4GiB：低于此值 WARNING
)

// recentBackupWindow 最近全量备份有效窗口（24h）。
const recentBackupWindow = 24 * time.Hour

// CheckItem 单项预检结果（落 upgrade_jobs.precheck JSON 数组）。
type CheckItem struct {
	Name    string `json:"name"`
	Result  string `json:"result"` // PASS / WARNING / FAIL
	Message string `json:"message"`
}

// Facts 预检事实（由采集器填充，评估为纯函数）。
type Facts struct {
	CurrentVersion     string     // 当前系统版本
	PackageVersionFrom string     // 升级包要求的起始版本
	PackageVersionTo   string     // 升级包目标版本
	DiskFreeBytes      int64      // 数据目录所在磁盘剩余字节
	PostgresReachable  bool       // PostgreSQL 可达
	ValkeyReachable    bool       // Valkey 可达
	ActiveTasks        []string   // 进行中的发布/备份/恢复/报告任务描述
	MaxMigration       int        // 本地迁移文件最大版本号；<0 表示读取失败
	TargetSchema       int        // manifest 声明的目标迁移号；0 表示未声明
	MasterKey          bool       // 主密钥已配置
	LastFullBackupAt   *time.Time // 最近一次已验证 FULL 备份完成时间
	CriticalOpenAlerts int        // CRITICAL 且 OPEN 的告警数
	Now                time.Time  // 评估时刻

	// 升级包文件完整性（登记期望 vs 采集实际）
	PackageFileExpectedName string // 登记的文件名
	PackageFileExpectedHash string // 登记的 SHA-256
	PackageFileExpectedSize int64  // 登记的字节数
	PackageFileExists       bool   // 服务端目录中文件存在且可读
	PackageFileActualHash   string // 实际 SHA-256（不存在时为空）
	PackageFileActualSize   int64  // 实际字节数
	PackageArtifactVerified bool   // 固定信任根、签名与归档 manifest 均通过
	PackageArtifactMessage  string // 验证失败原因（供预检审计与诊断使用）
}

// Evaluate 预检评估（纯函数，单测直接覆盖）。
func Evaluate(f Facts) []CheckItem {
	items := []CheckItem{
		checkVersionMatch(f),
		checkDiskSpace(f),
		checkPostgres(f),
		checkValkey(f),
		checkActiveTasks(f),
		checkMigrationCompat(f),
		checkMasterKey(f),
		checkRecentBackup(f),
		checkCriticalAlerts(f),
		checkPackageFile(f),
		checkPackageArtifact(f),
	}
	return items
}

// HasFail 是否存在 FAIL 项。
func HasFail(items []CheckItem) bool {
	for _, it := range items {
		if it.Result == CheckFail {
			return true
		}
	}
	return false
}

// checkVersionMatch 当前版本必须与升级包 version_from 一致，且 version_to 更高。
func checkVersionMatch(f Facts) CheckItem {
	it := CheckItem{Name: "version_match"}
	from, err := ParseVersion(f.PackageVersionFrom)
	if err != nil {
		it.Result, it.Message = CheckFail, "升级包起始版本号无效："+err.Error()
		return it
	}
	to, err := ParseVersion(f.PackageVersionTo)
	if err != nil {
		it.Result, it.Message = CheckFail, "升级包目标版本号无效："+err.Error()
		return it
	}
	cur, err := ParseVersion(f.CurrentVersion)
	if err != nil {
		it.Result, it.Message = CheckFail, "当前系统版本号无效："+err.Error()
		return it
	}
	if cur.Compare(from) != 0 {
		it.Result = CheckFail
		it.Message = fmt.Sprintf("当前版本 %s 与升级包要求起始版本 %s 不匹配", cur, from)
		return it
	}
	if to.Compare(cur) <= 0 {
		it.Result = CheckFail
		it.Message = fmt.Sprintf("目标版本 %s 不高于当前版本 %s", to, cur)
		return it
	}
	it.Result = CheckPass
	it.Message = fmt.Sprintf("版本路径 %s -> %s", cur, to)
	return it
}

// checkDiskSpace 磁盘剩余 ≥2GiB（2~4GiB 为 WARNING）。
func checkDiskSpace(f Facts) CheckItem {
	it := CheckItem{Name: "disk_space"}
	switch {
	case f.DiskFreeBytes < 0:
		it.Result, it.Message = CheckFail, "无法获取磁盘剩余空间"
	case f.DiskFreeBytes < diskMinBytes:
		it.Result = CheckFail
		it.Message = fmt.Sprintf("磁盘剩余 %.1fGiB，低于最低要求 2GiB", float64(f.DiskFreeBytes)/float64(1<<30))
	case f.DiskFreeBytes < diskWarnBytes:
		it.Result = CheckWarning
		it.Message = fmt.Sprintf("磁盘剩余 %.1fGiB，建议保留 4GiB 以上", float64(f.DiskFreeBytes)/float64(1<<30))
	default:
		it.Result = CheckPass
		it.Message = fmt.Sprintf("磁盘剩余 %.1fGiB", float64(f.DiskFreeBytes)/float64(1<<30))
	}
	return it
}

func checkPostgres(f Facts) CheckItem {
	it := CheckItem{Name: "postgres_reachable"}
	if f.PostgresReachable {
		it.Result, it.Message = CheckPass, "PostgreSQL 连接正常"
	} else {
		it.Result, it.Message = CheckFail, "PostgreSQL 不可达"
	}
	return it
}

func checkValkey(f Facts) CheckItem {
	it := CheckItem{Name: "valkey_reachable"}
	if f.ValkeyReachable {
		it.Result, it.Message = CheckPass, "Valkey 连接正常"
	} else {
		it.Result, it.Message = CheckFail, "Valkey 不可达"
	}
	return it
}

// checkActiveTasks 无进行中的发布/备份/恢复/报告任务。
func checkActiveTasks(f Facts) CheckItem {
	it := CheckItem{Name: "no_active_tasks"}
	if len(f.ActiveTasks) == 0 {
		it.Result, it.Message = CheckPass, "无进行中的发布/备份/恢复/报告任务"
		return it
	}
	it.Result = CheckFail
	msg := "存在进行中的任务：" + strings.Join(f.ActiveTasks, "；")
	it.Message = truncate(msg, 400)
	return it
}

// checkMigrationCompat 仅确认当前镜像中的迁移目录可读。升级包的目标迁移文件随
// 已签名目标 API 镜像交付，不能用当前镜像的最大迁移号限制其目标版本。
func checkMigrationCompat(f Facts) CheckItem {
	it := CheckItem{Name: "migration_compat"}
	if f.MaxMigration < 0 {
		it.Result, it.Message = CheckFail, "无法读取本地迁移文件目录"
		return it
	}
	it.Result = CheckPass
	if f.TargetSchema > 0 {
		it.Message = fmt.Sprintf("目标迁移号 %d；当前镜像迁移最大号 %d，目标镜像启动时执行并校验", f.TargetSchema, f.MaxMigration)
	} else {
		it.Message = fmt.Sprintf("本地迁移文件最大号 %d（升级包未声明目标迁移号）", f.MaxMigration)
	}
	return it
}

func checkMasterKey(f Facts) CheckItem {
	it := CheckItem{Name: "master_key"}
	if f.MasterKey {
		it.Result, it.Message = CheckPass, "主密钥已配置，加密/备份可用"
	} else {
		it.Result, it.Message = CheckFail, "主密钥未配置（JIUZHANG_MASTER_KEY），无法创建加密备份"
	}
	return it
}

// checkRecentBackup 最近 24h 内存在已验证 FULL 备份。
// 缺失/过期为 WARNING（BACKUP 步骤会在升级前创建新备份）。
func checkRecentBackup(f Facts) CheckItem {
	it := CheckItem{Name: "recent_backup"}
	if f.LastFullBackupAt == nil {
		it.Result, it.Message = CheckWarning, "无已验证的全量备份，升级流程将自动创建"
		return it
	}
	age := f.Now.Sub(*f.LastFullBackupAt)
	if age > recentBackupWindow {
		it.Result = CheckWarning
		it.Message = fmt.Sprintf("最近全量备份已过期 %.1f 小时，升级流程将自动创建新备份", age.Hours())
		return it
	}
	it.Result = CheckPass
	it.Message = fmt.Sprintf("最近全量备份 %.1f 小时前完成", age.Hours())
	return it
}

func checkCriticalAlerts(f Facts) CheckItem {
	it := CheckItem{Name: "no_critical_alerts"}
	if f.CriticalOpenAlerts == 0 {
		it.Result, it.Message = CheckPass, "无未处置的严重告警"
	} else {
		it.Result = CheckFail
		it.Message = fmt.Sprintf("存在 %d 条未处置的严重告警，须先处置", f.CriticalOpenAlerts)
	}
	return it
}

// checkPackageFile 升级包文件完整性：服务端目录中文件必须存在，且大小/SHA-256 与登记一致。
func checkPackageFile(f Facts) CheckItem {
	it := CheckItem{Name: "package_file"}
	if !f.PackageFileExists {
		it.Result = CheckFail
		it.Message = fmt.Sprintf("升级包文件 %s 不存在于服务端升级包目录或不可读", f.PackageFileExpectedName)
		return it
	}
	if f.PackageFileActualSize != f.PackageFileExpectedSize {
		it.Result = CheckFail
		it.Message = fmt.Sprintf("升级包文件大小与登记不一致（实际 %d 字节，登记 %d 字节）",
			f.PackageFileActualSize, f.PackageFileExpectedSize)
		return it
	}
	if !strings.EqualFold(f.PackageFileActualHash, f.PackageFileExpectedHash) {
		it.Result = CheckFail
		it.Message = "升级包文件 SHA-256 与登记不一致，文件可能被篡改或损坏"
		return it
	}
	it.Result = CheckPass
	it.Message = fmt.Sprintf("升级包文件完整性校验通过（%s，%.1fMiB）",
		f.PackageFileExpectedName, float64(f.PackageFileExpectedSize)/float64(1<<20))
	return it
}

// checkPackageArtifact 要求升级包不仅摘要匹配，还必须通过固定信任根、
// detached signature 与归档 manifest 的联合验证。
func checkPackageArtifact(f Facts) CheckItem {
	it := CheckItem{Name: "package_artifact"}
	if !f.PackageFileExists {
		it.Result = CheckFail
		it.Message = "升级包文件不存在，无法验证签名与归档内容"
		return it
	}
	if !f.PackageArtifactVerified {
		it.Result = CheckFail
		it.Message = "升级包签名或归档内容验证失败"
		if f.PackageArtifactMessage != "" {
			it.Message += "：" + truncate(f.PackageArtifactMessage, 400)
		}
		return it
	}
	it.Result = CheckPass
	it.Message = "升级包固定信任根、签名与 manifest 内容绑定验证通过"
	return it
}

// ---------- 事实采集 ----------

// migrationFileRe 迁移文件名（取 6 位版本号）。
var migrationFileRe = regexp.MustCompile(`^(\d{6})_[a-z0-9_]+\.up\.sql$`)

// MaxMigrationVersion 读取迁移目录最大版本号；失败返回 -1。
func MaxMigrationVersion(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return -1
	}
	max := 0
	for _, e := range entries {
		m := migrationFileRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		if v, err := strconv.Atoi(m[1]); err == nil && v > max {
			max = v
		}
	}
	return max
}

// ManifestTargetSchema 从升级包 manifest 提取目标迁移号（target_schema_version，可缺省）。
func ManifestTargetSchema(manifest json.RawMessage) int {
	if len(manifest) == 0 {
		return 0
	}
	var m struct {
		TargetSchemaVersion int `json:"target_schema_version"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return 0
	}
	return m.TargetSchemaVersion
}

// DiskFreeBytes 返回路径所在文件系统剩余字节数；失败返回 -1。
func DiskFreeBytes(path string) int64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(filepath.Clean(path), &st); err != nil {
		return -1
	}
	return int64(st.Bavail) * int64(st.Bsize)
}

// Prechecker 预检事实采集器。
type Prechecker struct {
	db            *pgxpool.Pool
	pingValkey    func(ctx context.Context) error
	dataDir       string
	migrationsDir string
	// packagesDir 升级包存储目录；为空时 package_file 检查项按文件缺失处理。
	packagesDir string
	// currentVersion 为空时使用 CurrentVersion 常量；
	// 优先读 system_settings 的 system:current_version。
	currentVersion   string
	artifactVerifier PackageArtifactVerifier
}

// NewPrechecker 创建预检器。pingValkey 可为 nil（视为不可达）。
func NewPrechecker(db *pgxpool.Pool, pingValkey func(ctx context.Context) error, dataDir, migrationsDir string) *Prechecker {
	return &Prechecker{
		db:               db,
		pingValkey:       pingValkey,
		dataDir:          dataDir,
		migrationsDir:    migrationsDir,
		artifactVerifier: verifyPackageArtifact,
	}
}

// SetPackagesDir 注入升级包存储目录（package_file 完整性检查项的数据源）。
func (p *Prechecker) SetPackagesDir(dir string) *Prechecker { p.packagesDir = dir; return p }

// SetArtifactVerifier 为隔离测试注入临时信任根；生产装配保持固定验签器。
func (p *Prechecker) SetArtifactVerifier(verifier PackageArtifactVerifier) *Prechecker {
	p.artifactVerifier = verifier
	return p
}

// VerifyArtifact 在预检或执行提交前复核升级包，防止登记后文件被替换。
func (p *Prechecker) VerifyArtifact(path string, pkg *Package) error {
	if p == nil || p.artifactVerifier == nil {
		return errors.New("升级包验签器未配置")
	}
	return p.artifactVerifier(path, pkg)
}

// Gather 采集预检事实。单项采集失败不中断，以不利值呈现（由 Evaluate 判 FAIL）。
func (p *Prechecker) Gather(ctx context.Context, pkg *Package) Facts {
	f := Facts{
		PackageVersionFrom:      pkg.VersionFrom,
		PackageVersionTo:        pkg.VersionTo,
		Now:                     time.Now().UTC(),
		MaxMigration:            MaxMigrationVersion(p.migrationsDir),
		TargetSchema:            ManifestTargetSchema(pkg.Manifest),
		MasterKey:               encryption.IsConfigured(),
		DiskFreeBytes:           DiskFreeBytes(p.dataDir),
		PackageFileExpectedName: pkg.FileName,
		PackageFileExpectedHash: pkg.FileHash,
		PackageFileExpectedSize: pkg.FileSize,
	}

	f.CurrentVersion = p.currentSystemVersion(ctx)

	f.PostgresReachable = p.db.Ping(ctx) == nil
	if p.pingValkey != nil {
		f.ValkeyReachable = p.pingValkey(ctx) == nil
	}

	if p.packagesDir != "" {
		path := filepath.Join(p.packagesDir, filepath.Base(pkg.FileName))
		if hash, size, err := hashFileStreaming(path); err == nil {
			f.PackageFileExists = true
			f.PackageFileActualHash = hash
			f.PackageFileActualSize = size
			if hash == pkg.FileHash && size == pkg.FileSize {
				if err := p.VerifyArtifact(path, pkg); err == nil {
					f.PackageArtifactVerified = true
				} else {
					f.PackageArtifactMessage = err.Error()
				}
			} else {
				f.PackageArtifactMessage = "升级包摘要或大小与登记不一致"
			}
		} else {
			f.PackageArtifactMessage = err.Error()
		}
	}

	f.ActiveTasks = p.activeTasks(ctx)
	f.LastFullBackupAt = p.lastFullBackup(ctx)
	f.CriticalOpenAlerts = p.criticalOpenAlerts(ctx)
	return f
}

// currentSystemVersion 读 system_settings 的 system:current_version，缺省回退常量。
func (p *Prechecker) currentSystemVersion(ctx context.Context) string {
	if p.currentVersion != "" {
		return p.currentVersion
	}
	var raw []byte
	err := p.db.QueryRow(ctx, `
SELECT setting_value FROM system_settings
WHERE setting_group = 'system' AND setting_key = 'current_version'`).Scan(&raw)
	if err == nil {
		var v string
		if json.Unmarshal(raw, &v) == nil && v != "" {
			return v
		}
	}
	return CurrentVersion
}

// activeTasks 汇总进行中的发布/备份/恢复/报告任务。
func (p *Prechecker) activeTasks(ctx context.Context) []string {
	queries := []struct {
		desc  string
		query string
	}{
		{"配置发布任务", `SELECT count(*) FROM gateway_publish_tasks WHERE status NOT IN ('SUCCESS','FAILED','CANCELLED')`},
		{"备份任务", `SELECT count(*) FROM backup_jobs WHERE status IN ('PENDING','RUNNING','VERIFYING')`},
		{"恢复任务", `SELECT count(*) FROM restore_jobs WHERE status NOT IN ('SUCCESS','FAILED','CANCELLED')`},
		{"报告任务", `SELECT count(*) FROM report_jobs WHERE status IN ('PENDING','COLLECTING','AGGREGATING','RENDERING')`},
	}
	var out []string
	for _, q := range queries {
		var n int64
		if err := p.db.QueryRow(ctx, q.query).Scan(&n); err != nil {
			out = append(out, q.desc+"状态查询失败")
			continue
		}
		if n > 0 {
			out = append(out, fmt.Sprintf("%d 个%s进行中", n, q.desc))
		}
	}
	return out
}

// lastFullBackup 最近一次已验证 FULL 备份完成时间。
func (p *Prechecker) lastFullBackup(ctx context.Context) *time.Time {
	var t *time.Time
	err := p.db.QueryRow(ctx, `
SELECT max(finished_at) FROM backup_jobs
WHERE backup_type = 'FULL' AND status = 'SUCCESS' AND verified`).Scan(&t)
	if err != nil {
		return nil
	}
	return t
}

// criticalOpenAlerts 未处置 CRITICAL 告警数。
func (p *Prechecker) criticalOpenAlerts(ctx context.Context) int {
	var n int
	err := p.db.QueryRow(ctx, `
SELECT count(*) FROM system_alerts WHERE severity = 'CRITICAL' AND status = 'OPEN'`).Scan(&n)
	if err != nil {
		// 查询失败按存在告警处理（保守阻断升级）
		return 1
	}
	return n
}
