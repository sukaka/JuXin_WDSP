// lifecycle.go API 资产生命周期运营（WDSP P0-10/P0-11）：
// DEPRECATED HTTP 入口（deprecate/restore）、ZOMBIE 状态机与周期判定作业。
//
// 状态机（asset_status，迁移 000045 词表注释）：
//
//	DISCOVERED / CONFIRMED ──deprecate(人工)──▶ DEPRECATED
//	DEPRECATED ──SweepOnce(近 N 天仍有流量)──▶ ZOMBIE（zombie_since 落时 + 生命周期事件）
//	DEPRECATED / ZOMBIE ──restore(人工)──▶ CONFIRMED（confirmed_at 刷新、zombie_since 清空）
//
// 说明：ZOMBIE 连续 N 天无流量后的归档只允许人工操作，本作业不做自动归档
// （任务书 §11.2 观察语义：僵尸端点仍需运营确认处置）。
package apiassets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrInvalidTransition 资产生命周期状态迁移不允许（如对已 IGNORED 端点 deprecate）。
var ErrInvalidTransition = errors.New("invalid asset status transition")

// 生命周期迁移合法起点（任务书 §11.2/§11.3）。
var (
	// deprecateFrom 人工下线：仅 DISCOVERED/CONFIRMED 可迁移 DEPRECATED。
	deprecateFrom = map[string]bool{"DISCOVERED": true, "CONFIRMED": true}
	// restoreFrom 人工恢复：仅 DEPRECATED/ZOMBIE 可迁移 CONFIRMED。
	restoreFrom = map[string]bool{"DEPRECATED": true, "ZOMBIE": true}
)

// 生命周期作业默认参数。
const (
	// DefaultZombieWindowDays 僵尸判定观察窗口（天）：DEPRECATED 端点近 N 天仍有流量判 ZOMBIE。
	// 默认 7 与 api_endpoint_traffic_buckets 留存窗口一致（迁移 000034）。
	DefaultZombieWindowDays = 7
	// defaultSweepBatchSize 单轮僵尸判定处理上限（防爆量单轮全表）。
	defaultSweepBatchSize = 500
	// defaultValueBatchSize 单轮资产价值评分回填上限。
	defaultValueBatchSize = 200
)

// Deprecate 人工下线（DISCOVERED/CONFIRMED→DEPRECATED），写生命周期事件（事务）。
func (s *Store) Deprecate(ctx context.Context, id uuid.UUID, actor string) (*Endpoint, error) {
	return s.transitionAssetStatus(ctx, id, "DEPRECATED", deprecateFrom, actor, "人工标记下线", false)
}

// Restore 人工恢复（DEPRECATED/ZOMBIE→CONFIRMED），刷新 confirmed_at、
// 清空 zombie_since，写生命周期事件（事务）。
func (s *Store) Restore(ctx context.Context, id uuid.UUID, actor string) (*Endpoint, error) {
	return s.transitionAssetStatus(ctx, id, "CONFIRMED", restoreFrom, actor, "人工恢复为已确认", true)
}

// transitionAssetStatus 资产生命周期迁移公共路径：锁行校验起点词表 → 迁移 → 生命周期事件。
// confirm=true 时刷新 confirmed_at 并清空 zombie_since（restore 语义）。
func (s *Store) transitionAssetStatus(ctx context.Context, id uuid.UUID, target string,
	allowedFrom map[string]bool, actor, reason string, confirm bool) (*Endpoint, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var from string
	err = tx.QueryRow(ctx, `SELECT asset_status FROM api_endpoints WHERE id=$1 FOR UPDATE`, id).Scan(&from)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !allowedFrom[from] {
		return nil, fmt.Errorf("%w：%s → %s", ErrInvalidTransition, from, target)
	}
	var e *Endpoint
	if confirm {
		e, err = scanEndpoint(tx.QueryRow(ctx, `
UPDATE api_endpoints SET asset_status=$2, confirmed_at=now(), zombie_since=NULL, updated_at=now()
WHERE id=$1
RETURNING `+endpointColumns, id, target))
	} else {
		e, err = scanEndpoint(tx.QueryRow(ctx, `
UPDATE api_endpoints SET asset_status=$2, updated_at=now()
WHERE id=$1
RETURNING `+endpointColumns, id, target))
	}
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO api_lifecycle_events (endpoint_id, from_status, to_status, reason, actor)
VALUES ($1,$2,$3,$4,$5)`, id, from, target, reason, actor); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return e, nil
}

// SweepOptions 生命周期清扫参数（零值字段取默认）。
type SweepOptions struct {
	ZombieWindowDays int // 僵尸判定观察窗口（天），默认 DefaultZombieWindowDays
	BatchSize        int // 单轮僵尸判定处理上限，默认 defaultSweepBatchSize
	ValueBatchSize   int // 单轮价值评分回填上限，默认 defaultValueBatchSize
}

func (o SweepOptions) withDefaults() SweepOptions {
	out := o
	if out.ZombieWindowDays <= 0 {
		out.ZombieWindowDays = DefaultZombieWindowDays
	}
	if out.BatchSize <= 0 {
		out.BatchSize = defaultSweepBatchSize
	}
	if out.ValueBatchSize <= 0 {
		out.ValueBatchSize = defaultValueBatchSize
	}
	return out
}

// SweepResult 一轮生命周期清扫结果摘要。
type SweepResult struct {
	ZombieCandidates int `json:"zombie_candidates"` // 窗口内仍有流量的 DEPRECATED 端点数
	Zombied          int `json:"zombied"`           // 本轮迁移 ZOMBIE 数
	ValueRefreshed   int `json:"value_refreshed"`   // 本轮资产价值评分回填数
}

// SweepStore 生命周期清扫作业依赖的最小存储面（*Store 与 *MemStore 均实现，便于诚实单测）。
type SweepStore interface {
	// DeprecatedIDsWithTraffic 返回 since 起仍有流量（api_endpoint_traffic_buckets）的
	// DEPRECATED 端点 id（按 id 升序，limit 截断）。
	DeprecatedIDsWithTraffic(ctx context.Context, since time.Time, limit int) ([]uuid.UUID, error)
	// MarkZombie 条件迁移 DEPRECATED→ZOMBIE（zombie_since=now + 生命周期事件，actor=system）。
	// 端点不存在返回 ErrNotFound；已非 DEPRECATED（并发人工操作）返回 (false, nil) 跳过。
	MarkZombie(ctx context.Context, id uuid.UUID, now time.Time, reason string) (bool, error)
	// RefreshAssetValues 重算待更新端点的资产价值评分并回填（asset_value/_explain），返回处理数。
	RefreshAssetValues(ctx context.Context, limit int) (int, error)
}

var (
	_ SweepStore = (*Store)(nil)
	_ SweepStore = (*MemStore)(nil)
)

// Sweeper 资产生命周期周期作业（Zombie 判定 + 资产价值评分回填）。
// 装配方式见 main：apiassets.NewSweeper(apiAssetStore, apiassets.SweepOptions{}) 挂到周期任务。
type Sweeper struct {
	store SweepStore
	opts  SweepOptions
	now   func() time.Time
}

// NewSweeper 创建生命周期清扫作业（opts 零值取默认）。
func NewSweeper(store SweepStore, opts SweepOptions) *Sweeper {
	return &Sweeper{store: store, opts: opts.withDefaults()}
}

// SweepOnce 执行一轮清扫：
//  1. Zombie 判定：DEPRECATED 端点近 N 天仍有流量 → ZOMBIE + zombie_since + 生命周期事件；
//     ZOMBIE 连续 N 天无流量仅保持观察，不自动归档（归档须人工，见包注释）。
//  2. 资产价值评分回填：重算待更新端点（未评分或评分后又有新流量）。
//
// 任一阶段失败即返回错误（不静默吞错），已完成部分不回滚（幂等，可下轮重扫）。
func (s *Sweeper) SweepOnce(ctx context.Context) (*SweepResult, error) {
	opts := s.opts.withDefaults()
	nowFn := s.now
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	now := nowFn()
	since := now.Add(-time.Duration(opts.ZombieWindowDays) * 24 * time.Hour)
	reason := fmt.Sprintf("下线后近 %d 天仍有流量（僵尸判定）", opts.ZombieWindowDays)

	res := &SweepResult{}
	ids, err := s.store.DeprecatedIDsWithTraffic(ctx, since, opts.BatchSize)
	if err != nil {
		return nil, fmt.Errorf("僵尸判定候选查询失败: %w", err)
	}
	res.ZombieCandidates = len(ids)
	for _, id := range ids {
		marked, err := s.store.MarkZombie(ctx, id, now, reason)
		if err != nil {
			return res, fmt.Errorf("僵尸迁移失败（端点 %s）: %w", id, err)
		}
		if marked {
			res.Zombied++
		}
	}

	n, err := s.store.RefreshAssetValues(ctx, opts.ValueBatchSize)
	if err != nil {
		return res, fmt.Errorf("资产价值评分回填失败: %w", err)
	}
	res.ValueRefreshed = n
	return res, nil
}

// DeprecatedIDsWithTraffic 窗口内仍有流量的 DEPRECATED 端点（僵尸判定候选；空表安全零产出）。
func (s *Store) DeprecatedIDsWithTraffic(ctx context.Context, since time.Time, limit int) ([]uuid.UUID, error) {
	rows, err := s.db.Query(ctx, `
SELECT e.id FROM api_endpoints e
WHERE e.asset_status = 'DEPRECATED'
  AND EXISTS (
    SELECT 1 FROM api_endpoint_traffic_buckets b
    WHERE b.endpoint_id = e.id AND b.bucket_start >= $1
  )
ORDER BY e.id
LIMIT $2`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// MarkZombie 条件迁移 DEPRECATED→ZOMBIE（事务）：zombie_since 落时 + 生命周期事件。
// 端点已非 DEPRECATED（并发人工 restore/ignore）时返回 false，本轮跳过。
func (s *Store) MarkZombie(ctx context.Context, id uuid.UUID, now time.Time, reason string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var from string
	err = tx.QueryRow(ctx, `SELECT asset_status FROM api_endpoints WHERE id=$1 FOR UPDATE`, id).Scan(&from)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}
	if from != "DEPRECATED" {
		return false, tx.Commit(ctx)
	}
	tag, err := tx.Exec(ctx, `
UPDATE api_endpoints SET asset_status='ZOMBIE', zombie_since=$2, updated_at=now()
WHERE id=$1 AND asset_status='DEPRECATED'`, id, now)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, tx.Commit(ctx)
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO api_lifecycle_events (endpoint_id, from_status, to_status, reason, actor)
VALUES ($1,'DEPRECATED','ZOMBIE',$2,'system')`, id, reason); err != nil {
		return false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// DeprecatedIDsWithTraffic 内存实现：语义同 SQL（窗口内有桶即仍有流量）。
func (m *MemStore) DeprecatedIDsWithTraffic(ctx context.Context, since time.Time, limit int) ([]uuid.UUID, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []uuid.UUID{}
	for id, e := range m.byID {
		if e.AssetStatus != "DEPRECATED" {
			continue
		}
		has := false
		for b, c := range m.traffic[id] {
			if c > 0 && !b.Before(since) {
				has = true
				break
			}
		}
		if has {
			out = append(out, id)
		}
	}
	sortUUIDs(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// MarkZombie 内存实现：语义同 SQL（条件迁移 + 生命周期事件）。
func (m *MemStore) MarkZombie(ctx context.Context, id uuid.UUID, now time.Time, reason string) (bool, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[id]
	if !ok {
		return false, ErrNotFound
	}
	if e.AssetStatus != "DEPRECATED" {
		return false, nil
	}
	e.AssetStatus = "ZOMBIE"
	t := now.UTC()
	e.ZombieSince = &t
	m.appendEventLocked(id, "DEPRECATED", "ZOMBIE", reason, "system")
	return true, nil
}

// Deprecate 内存实现：DISCOVERED/CONFIRMED→DEPRECATED。
func (m *MemStore) Deprecate(ctx context.Context, id uuid.UUID, actor string) (*Endpoint, error) {
	return m.transitionAssetStatus(ctx, id, "DEPRECATED", deprecateFrom, actor, "人工标记下线", false)
}

// Restore 内存实现：DEPRECATED/ZOMBIE→CONFIRMED（confirmed_at 刷新、zombie_since 清空）。
func (m *MemStore) Restore(ctx context.Context, id uuid.UUID, actor string) (*Endpoint, error) {
	return m.transitionAssetStatus(ctx, id, "CONFIRMED", restoreFrom, actor, "人工恢复为已确认", true)
}

// transitionAssetStatus 内存实现迁移公共路径（语义同 SQL 侧）。
func (m *MemStore) transitionAssetStatus(_ context.Context, id uuid.UUID, target string,
	allowedFrom map[string]bool, actor, reason string, confirm bool) (*Endpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	from := e.AssetStatus
	if !allowedFrom[from] {
		return nil, fmt.Errorf("%w：%s → %s", ErrInvalidTransition, from, target)
	}
	e.AssetStatus = target
	if confirm {
		now := time.Now().UTC()
		e.ConfirmedAt = &now
		e.ZombieSince = nil
	}
	m.appendEventLocked(id, from, target, reason, actor)
	return cloneEP(e), nil
}

// sortUUIDs 端点 id 升序（与 SQL ORDER BY id 一致，保证清扫次序确定）。
func sortUUIDs(ids []uuid.UUID) {
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
}
