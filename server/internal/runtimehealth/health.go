// Package runtimehealth 提供阶段6运行监控：组件健康采集、快照存储与查询。
// 采集结果落 system_health_snapshots 表（component/status/latency_ms/metrics/message）。
package runtimehealth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 监控组件
const (
	ComponentGateway        = "GATEWAY"
	ComponentCoraza         = "CORAZA"
	ComponentGuard          = "GUARD"
	ComponentAPI            = "API"
	ComponentPostgres       = "POSTGRES"
	ComponentValkey         = "VALKEY"
	ComponentEventCollector = "EVENT_COLLECTOR"
	ComponentUpstream       = "UPSTREAM"
	ComponentCertificate    = "CERTIFICATE"
	ComponentDisk           = "DISK"
)

// 组件状态
const (
	StatusUp       = "UP"
	StatusDown     = "DOWN"
	StatusDegraded = "DEGRADED"
	StatusUnknown  = "UNKNOWN"
)

// 指标键（供告警评估等下游消费，保持稳定）
const (
	MetricConfigHash        = "config_hash"
	MetricGoroutines        = "goroutines"
	MetricHeapAllocBytes    = "heap_alloc_bytes"
	MetricMemorySysBytes    = "memory_sys_bytes"
	MetricUptimeSeconds     = "uptime_seconds"
	MetricDatabaseSizeBytes = "database_size_bytes"
	MetricDBConnections     = "db_connections"
	MetricUsedMemoryBytes   = "used_memory_bytes"
	MetricConnectedClients  = "connected_clients"
	MetricDBSizeKeys        = "dbsize_keys"
	MetricMaxLagSeconds     = "max_lag_seconds"
	MetricCheckpoints       = "checkpoints"
	MetricUpstreamTotal     = "upstream_total"
	MetricUpstreamHealthy   = "upstream_healthy"
	MetricUpstreamUnhealthy = "upstream_unhealthy"
	MetricUpstreamFailures  = "upstream_failures"
	MetricMinDaysRemaining  = "min_days_remaining"
	MetricExpiringCount     = "expiring_count"
	MetricExpiredCount      = "expired_count"
	MetricDiskTotalBytes    = "disk_total_bytes"
	MetricDiskFreeBytes     = "disk_free_bytes"
	MetricDiskFreePercent   = "disk_free_percent"
	MetricGuardLogStaleSecs = "guard_log_stale_seconds"
	MetricDBCapacityPercent = "db_capacity_percent"
)

// AllComponents 返回采集的组件清单（固定顺序）。
func AllComponents() []string {
	return []string{
		ComponentGateway, ComponentCoraza, ComponentGuard, ComponentAPI,
		ComponentPostgres, ComponentValkey, ComponentEventCollector,
		ComponentUpstream, ComponentCertificate, ComponentDisk,
	}
}

// Snapshot 是一条组件健康快照。
type Snapshot struct {
	ID        uuid.UUID              `json:"id"`
	TakenAt   time.Time              `json:"taken_at"`
	Component string                 `json:"component"`
	Status    string                 `json:"status"`
	LatencyMs *int                   `json:"latency_ms"`
	Metrics   map[string]interface{} `json:"metrics"`
	Message   string                 `json:"message"`
}

// Store 是健康快照仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// Insert 写入一条快照。
func (s *Store) Insert(ctx context.Context, snap *Snapshot) error {
	metrics, err := json.Marshal(snap.Metrics)
	if err != nil {
		return err
	}
	if snap.TakenAt.IsZero() {
		snap.TakenAt = time.Now().UTC()
	}
	return s.db.QueryRow(ctx, `
INSERT INTO system_health_snapshots (taken_at, component, status, latency_ms, metrics, message)
VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		snap.TakenAt, snap.Component, snap.Status, snap.LatencyMs, string(metrics), truncate(snap.Message, 500),
	).Scan(&snap.ID)
}

// LatestAll 查询每个组件的最新一条快照。
func (s *Store) LatestAll(ctx context.Context) ([]Snapshot, error) {
	rows, err := s.db.Query(ctx, `
SELECT DISTINCT ON (component) id, taken_at, component, status, latency_ms, metrics, message
FROM system_health_snapshots
ORDER BY component, taken_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Snapshot
	for rows.Next() {
		snap, err := scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *snap)
	}
	return out, rows.Err()
}

// LatestByComponent 查询指定组件的最新快照；无记录返回 nil, nil。
func (s *Store) LatestByComponent(ctx context.Context, component string) (*Snapshot, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, taken_at, component, status, latency_ms, metrics, message
FROM system_health_snapshots WHERE component = $1
ORDER BY taken_at DESC LIMIT 1`, component)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		return scanSnapshot(rows)
	}
	return nil, rows.Err()
}

// DeleteOlderThan 清理历史快照（保留窗口外的数据），返回删除行数。
func (s *Store) DeleteOlderThan(ctx context.Context, keep time.Duration) (int64, error) {
	res, err := s.db.Exec(ctx,
		`DELETE FROM system_health_snapshots WHERE taken_at < now() - $1::interval`,
		keep.String())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanSnapshot(row rowScanner) (*Snapshot, error) {
	var snap Snapshot
	var metrics []byte
	if err := row.Scan(&snap.ID, &snap.TakenAt, &snap.Component, &snap.Status,
		&snap.LatencyMs, &metrics, &snap.Message); err != nil {
		return nil, err
	}
	snap.Metrics = map[string]interface{}{}
	if len(metrics) > 0 {
		if err := json.Unmarshal(metrics, &snap.Metrics); err != nil {
			return nil, err
		}
	}
	return &snap, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
