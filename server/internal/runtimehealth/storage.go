package runtimehealth

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/cache"
)

// 存储统计限制
const (
	storageQueryTimeout = 8 * time.Second
	maxDirWalkEntries   = 200000 // 目录统计遍历上限（防异常目录拖垮）
)

// PartitionSize 是单个关系（表/分区）的容量。
type PartitionSize struct {
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
}

// StorageStats 是存储监控汇总（GET /system-health/storage 响应）。
type StorageStats struct {
	PostgresSizeBytes     int64           `json:"postgres_size_bytes"`
	DBConnections         int             `json:"db_connections"`
	Partitions            []PartitionSize `json:"partitions"`
	ValkeyUsedMemoryBytes int64           `json:"valkey_used_memory_bytes"`
	ValkeyMaxMemoryBytes  int64           `json:"valkey_max_memory_bytes"`
	DiskTotalBytes        uint64          `json:"disk_total_bytes"`
	DiskFreeBytes         uint64          `json:"disk_free_bytes"`
	ReportsSizeBytes      int64           `json:"reports_size_bytes"`
	ReportsFileCount      int             `json:"reports_file_count"`
	BackupsSizeBytes      int64           `json:"backups_size_bytes"`
	BackupsFileCount      int             `json:"backups_file_count"`
	CollectedAt           time.Time       `json:"collected_at"`
}

// StorageProbe 采集存储类指标（pg 容量、分区 top10、Valkey 内存、文件目录、磁盘）。
type StorageProbe struct {
	db         *pgxpool.Pool
	cache      *cache.Client
	diskPath   string
	reportsDir string
	backupsDir string
}

// NewStorageProbe 创建存储探针。reportsDir/backupsDir 为空时用默认相对路径。
func NewStorageProbe(db *pgxpool.Pool, cacheClient *cache.Client, diskPath, reportsDir, backupsDir string) *StorageProbe {
	if diskPath == "" {
		diskPath = "/app"
	}
	if reportsDir == "" {
		reportsDir = "runtime/reports"
	}
	if backupsDir == "" {
		backupsDir = "runtime/backups"
	}
	return &StorageProbe{db: db, cache: cacheClient, diskPath: diskPath,
		reportsDir: reportsDir, backupsDir: backupsDir}
}

// Collect 采集存储指标。Valkey/目录类失败仅置零值，数据库与磁盘失败返回错误。
func (p *StorageProbe) Collect(ctx context.Context) (*StorageStats, error) {
	stats := &StorageStats{CollectedAt: time.Now().UTC()}
	sCtx, cancel := context.WithTimeout(ctx, storageQueryTimeout)
	defer cancel()

	if err := p.db.QueryRow(sCtx, `
SELECT pg_database_size(current_database()),
       (SELECT count(*) FROM pg_stat_activity WHERE datname = current_database())`).
		Scan(&stats.PostgresSizeBytes, &stats.DBConnections); err != nil {
		return nil, fmt.Errorf("query database size: %w", err)
	}

	top, err := p.topTables(sCtx, 10)
	if err != nil {
		return nil, fmt.Errorf("query top tables: %w", err)
	}
	stats.Partitions = top

	p.valkeyMemory(sCtx, stats)

	reports := DirSizeOf(p.reportsDir)
	stats.ReportsSizeBytes = reports.TotalBytes
	stats.ReportsFileCount = reports.FileCount
	backups := DirSizeOf(p.backupsDir)
	stats.BackupsSizeBytes = backups.TotalBytes
	stats.BackupsFileCount = backups.FileCount

	total, free, err := diskUsage(p.diskPath)
	if err != nil {
		return nil, fmt.Errorf("stat disk: %w", err)
	}
	stats.DiskTotalBytes = total
	stats.DiskFreeBytes = free
	return stats, nil
}

// topTables 返回 pg_total_relation_size 最大的前 n 个用户表/分区。
func (p *StorageProbe) topTables(ctx context.Context, n int) ([]PartitionSize, error) {
	rows, err := p.db.Query(ctx, `
SELECT n.nspname || '.' || c.relname, pg_total_relation_size(c.oid)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema')
ORDER BY pg_total_relation_size(c.oid) DESC
LIMIT $1`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PartitionSize{}
	for rows.Next() {
		var t PartitionSize
		if err := rows.Scan(&t.Name, &t.SizeBytes); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// valkeyMemory 读取 Valkey 内存指标；不可达时保持零值。
func (p *StorageProbe) valkeyMemory(ctx context.Context, stats *StorageStats) {
	if p.cache == nil {
		return
	}
	info, err := p.cache.Redis().Info(ctx, "memory").Result()
	if err != nil {
		return
	}
	stats.ValkeyUsedMemoryBytes = parseInfoInt(info, "used_memory")
	stats.ValkeyMaxMemoryBytes = parseInfoInt(info, "maxmemory")
}

// DirSize 是目录占用统计。
type DirSize struct {
	Path       string `json:"path"`
	FileCount  int    `json:"file_count"`
	TotalBytes int64  `json:"total_bytes"`
	Available  bool   `json:"available"`
}

// DirSizeOf 统计目录文件数与总字节数；目录不存在/不可读时 Available=false。
func DirSizeOf(path string) DirSize {
	ds := DirSize{Path: path}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return ds
	}
	entries := 0
	err = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 跳过不可读子项
		}
		entries++
		if entries > maxDirWalkEntries {
			return filepath.SkipAll
		}
		if d.Type().IsRegular() {
			info, err := d.Info()
			if err == nil {
				ds.FileCount++
				ds.TotalBytes += info.Size()
			}
		}
		return nil
	})
	ds.Available = err == nil
	return ds
}
