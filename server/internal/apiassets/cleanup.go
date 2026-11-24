// cleanup.go 存量静态资源与非 API 噪声扫描预览与安全清理。
//
// 安全护栏（SQL 与 MemStore 同口径，预览与执行双重强制）：
//   - 永不清理 asset_status='CONFIRMED' 的已确认正式资产；
//   - 永不清理正在学习/已完成学习（LEARNING/LEARNED）或已关联模型版本、运行时策略、
//     角色授权基线、字段权限、流程基线或接口组的端点；
//   - 命中当前过滤规则白名单（include_path_prefixes）的端点永不判为噪声。
package apiassets

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// NoiseCleanupActionDelete 彻底删除噪声端点（释放授权配额）。
	NoiseCleanupActionDelete = "DELETE"
	// NoiseCleanupActionIgnore 将噪声端点批量置为 IGNORED（软清理）。
	NoiseCleanupActionIgnore = "IGNORE"

	defaultCleanupPreviewLimit = 200
	maxCleanupPreviewLimit     = 500
	maxCleanupSampleKeys       = 20
)

// NoiseCleanupFilter 存量噪声扫描与清理范围。
type NoiseCleanupFilter struct {
	ApplicationID  *uuid.UUID
	IncludeIgnored bool
	Limit          int
	IDs            []uuid.UUID // 执行清理时可选：限制仅清理指定 ID（仍必须通过安全护栏与噪声判定）
}

// NoiseEndpointCandidate 命中噪声规则的可清理候选端点。
type NoiseEndpointCandidate struct {
	ID              uuid.UUID  `json:"id"`
	ApplicationID   *uuid.UUID `json:"application_id,omitempty"`
	ApplicationName string     `json:"application_name,omitempty"`
	HTTPMethod      string     `json:"http_method"`
	NormalizedPath  string     `json:"normalized_path"`
	DirectoryPath   string     `json:"directory_path"`
	EndpointKey     string     `json:"endpoint_key"`
	AssetStatus     string     `json:"asset_status"`
	IsAPI           bool       `json:"is_api"`
	APIConfidence   float64    `json:"api_confidence"`
	HitCount        int64      `json:"hit_count"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	Reason          string     `json:"reason"`
}

// NoiseCleanupPreview 存量噪声扫描预览结果。
type NoiseCleanupPreview struct {
	Total            int64                    `json:"total"`
	ProtectedSkipped int64                    `json:"protected_skipped"`
	ByReason         map[string]int64         `json:"by_reason"`
	Items            []NoiseEndpointCandidate `json:"items"`
}

// NoiseCleanupResult 存量噪声执行清理结果。
type NoiseCleanupResult struct {
	Action           string           `json:"action"`
	Affected         int64            `json:"affected"`
	ProtectedSkipped int64            `json:"protected_skipped"`
	ByReason         map[string]int64 `json:"by_reason"`
	SampleKeys       []string         `json:"sample_keys"`
}

type noiseScanRow struct {
	candidate NoiseEndpointCandidate
	protected bool
}

func normalizeCleanupAction(action string) (string, error) {
	act := strings.ToUpper(strings.TrimSpace(action))
	if act == "" {
		return NoiseCleanupActionDelete, nil
	}
	if act != NoiseCleanupActionDelete && act != NoiseCleanupActionIgnore {
		return "", fmt.Errorf("无效的清理动作：%q（仅支持 DELETE / IGNORE）", action)
	}
	return act, nil
}

func normalizePreviewLimit(limit int) int {
	if limit <= 0 {
		return defaultCleanupPreviewLimit
	}
	if limit > maxCleanupPreviewLimit {
		return maxCleanupPreviewLimit
	}
	return limit
}

// PreviewNoiseCleanup 扫描库中可安全清理的静态资源与非 API 噪声端点（只读，不修改数据）。
func (s *Store) PreviewNoiseCleanup(ctx context.Context, cfg DiscoveryFilterConfig, f NoiseCleanupFilter) (*NoiseCleanupPreview, error) {
	rows, err := s.scanNoiseRows(ctx, s.db, f)
	if err != nil {
		return nil, err
	}
	return buildNoisePreview(rows, cfg, f, NoiseCleanupActionDelete), nil
}

// ExecuteNoiseCleanup 在事务中执行存量噪声清理（DELETE 或 IGNORE），严格复用同一安全护栏。
func (s *Store) ExecuteNoiseCleanup(ctx context.Context, cfg DiscoveryFilterConfig, f NoiseCleanupFilter, action, actor string) (*NoiseCleanupResult, error) {
	act, err := normalizeCleanupAction(action)
	if err != nil {
		return nil, err
	}
	if actor == "" {
		actor = "system"
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := s.scanNoiseRows(ctx, tx, f)
	if err != nil {
		return nil, err
	}
	targets, protectedSkipped, byReason, sampleKeys := selectNoiseTargets(rows, cfg, f, act)
	if len(targets) == 0 {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return &NoiseCleanupResult{
			Action:           act,
			Affected:         0,
			ProtectedSkipped: protectedSkipped,
			ByReason:         byReason,
			SampleKeys:       []string{},
		}, nil
	}

	var affected int64
	if act == NoiseCleanupActionDelete {
		tag, err := tx.Exec(ctx, `DELETE FROM api_endpoints WHERE id = ANY($1::uuid[])`, targets)
		if err != nil {
			return nil, err
		}
		affected = tag.RowsAffected()
	} else {
		rowsUpdated, err := tx.Query(ctx, `
UPDATE api_endpoints
SET asset_status = 'IGNORED', zombie_since = NULL, updated_at = now()
WHERE id = ANY($1::uuid[]) AND asset_status <> 'IGNORED'
RETURNING id`, targets)
		if err != nil {
			return nil, err
		}
		updatedIDs := make([]uuid.UUID, 0, len(targets))
		for rowsUpdated.Next() {
			var id uuid.UUID
			if err := rowsUpdated.Scan(&id); err != nil {
				rowsUpdated.Close()
				return nil, err
			}
			updatedIDs = append(updatedIDs, id)
		}
		rowsUpdated.Close()
		if err := rowsUpdated.Err(); err != nil {
			return nil, err
		}
		affected = int64(len(updatedIDs))
		for _, id := range updatedIDs {
			if _, err := tx.Exec(ctx, `
INSERT INTO api_lifecycle_events (endpoint_id, from_status, to_status, reason, actor)
VALUES ($1, 'DISCOVERED', 'IGNORED', '批量清理静态/非API噪声', $2)`, id, actor); err != nil {
				return nil, err
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &NoiseCleanupResult{
		Action:           act,
		Affected:         affected,
		ProtectedSkipped: protectedSkipped,
		ByReason:         byReason,
		SampleKeys:       sampleKeys,
	}, nil
}

func (s *Store) scanNoiseRows(ctx context.Context, q DBTX, f NoiseCleanupFilter) ([]noiseScanRow, error) {
	where := "1=1"
	args := []any{}
	if f.ApplicationID != nil {
		args = append(args, *f.ApplicationID)
		where += fmt.Sprintf(" AND e.application_id = $%d", len(args))
	}
	if len(f.IDs) > 0 {
		args = append(args, f.IDs)
		where += fmt.Sprintf(" AND e.id = ANY($%d::uuid[])", len(args))
	}
	rows, err := q.Query(ctx, `
SELECT e.id, e.application_id, COALESCE(a.name, ''), e.http_method, e.normalized_path,
  e.directory_path, e.endpoint_key, e.asset_status, e.is_api, e.api_confidence,
  e.hit_count, e.last_seen_at,
  (
    e.asset_status = 'CONFIRMED'
    OR e.current_model_version_id IS NOT NULL
    OR e.learning_status IN ('LEARNING', 'LEARNED')
    OR EXISTS (SELECT 1 FROM api_model_versions mv WHERE mv.endpoint_id = e.id)
    OR EXISTS (SELECT 1 FROM api_runtime_policies rp WHERE rp.endpoint_id = e.id)
    OR EXISTS (SELECT 1 FROM api_role_baselines rb WHERE rb.endpoint_id = e.id)
    OR EXISTS (SELECT 1 FROM api_field_permissions fp WHERE fp.endpoint_id = e.id)
    OR EXISTS (SELECT 1 FROM api_flow_baseline_steps fs WHERE fs.endpoint_id = e.id)
    OR EXISTS (SELECT 1 FROM api_endpoint_group_members gm WHERE gm.endpoint_id = e.id)
  ) AS protected
FROM api_endpoints e
LEFT JOIN applications a ON a.id = e.application_id
WHERE `+where+`
ORDER BY e.last_seen_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []noiseScanRow{}
	for rows.Next() {
		var r noiseScanRow
		if err := rows.Scan(
			&r.candidate.ID, &r.candidate.ApplicationID, &r.candidate.ApplicationName,
			&r.candidate.HTTPMethod, &r.candidate.NormalizedPath, &r.candidate.DirectoryPath,
			&r.candidate.EndpointKey, &r.candidate.AssetStatus, &r.candidate.IsAPI,
			&r.candidate.APIConfidence, &r.candidate.HitCount, &r.candidate.LastSeenAt,
			&r.protected,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func buildNoisePreview(rows []noiseScanRow, cfg DiscoveryFilterConfig, f NoiseCleanupFilter, action string) *NoiseCleanupPreview {
	limit := normalizePreviewLimit(f.Limit)
	preview := &NoiseCleanupPreview{
		ByReason: map[string]int64{},
		Items:    []NoiseEndpointCandidate{},
	}
	for _, r := range rows {
		matched, reason := cfg.MatchNoiseEndpoint(r.candidate.HTTPMethod, r.candidate.NormalizedPath, r.candidate.IsAPI)
		if !matched {
			continue
		}
		if r.protected {
			preview.ProtectedSkipped++
			continue
		}
		if !f.IncludeIgnored && r.candidate.AssetStatus == "IGNORED" {
			continue
		}
		if action == NoiseCleanupActionIgnore && r.candidate.AssetStatus == "IGNORED" {
			continue
		}
		preview.Total++
		preview.ByReason[reasonBucket(reason)]++
		if len(preview.Items) < limit {
			c := r.candidate
			c.Reason = reason
			preview.Items = append(preview.Items, c)
		}
	}
	return preview
}

func selectNoiseTargets(rows []noiseScanRow, cfg DiscoveryFilterConfig, f NoiseCleanupFilter, action string) ([]uuid.UUID, int64, map[string]int64, []string) {
	byReason := map[string]int64{}
	targets := []uuid.UUID{}
	sampleKeys := []string{}
	var protectedSkipped int64
	for _, r := range rows {
		matched, reason := cfg.MatchNoiseEndpoint(r.candidate.HTTPMethod, r.candidate.NormalizedPath, r.candidate.IsAPI)
		if !matched {
			continue
		}
		if r.protected {
			protectedSkipped++
			continue
		}
		if !f.IncludeIgnored && r.candidate.AssetStatus == "IGNORED" {
			continue
		}
		if action == NoiseCleanupActionIgnore && r.candidate.AssetStatus == "IGNORED" {
			continue
		}
		targets = append(targets, r.candidate.ID)
		byReason[reasonBucket(reason)]++
		if len(sampleKeys) < maxCleanupSampleKeys {
			sampleKeys = append(sampleKeys, r.candidate.EndpointKey)
		}
	}
	return targets, protectedSkipped, byReason, sampleKeys
}

func reasonBucket(reason string) string {
	switch {
	case strings.HasPrefix(reason, "static_extension:"):
		return "static_extension"
	case strings.HasPrefix(reason, "exclude_path_prefix:"):
		return "exclude_path_prefix"
	case reason == "static_well_known":
		return "static_well_known"
	case reason == "non_api":
		return "non_api"
	default:
		return reason
	}
}

// PreviewNoiseCleanup 内存仓储实现（与 SQL 口径一致：保护 CONFIRMED / 学习中 / 已建模端点）。
func (m *MemStore) PreviewNoiseCleanup(ctx context.Context, cfg DiscoveryFilterConfig, f NoiseCleanupFilter) (*NoiseCleanupPreview, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.scanNoiseRowsLocked(f)
	return buildNoisePreview(rows, cfg, f, NoiseCleanupActionDelete), nil
}

// ExecuteNoiseCleanup 内存仓储实现（与 SQL 口径一致）。
func (m *MemStore) ExecuteNoiseCleanup(ctx context.Context, cfg DiscoveryFilterConfig, f NoiseCleanupFilter, action, actor string) (*NoiseCleanupResult, error) {
	_ = ctx
	act, err := normalizeCleanupAction(action)
	if err != nil {
		return nil, err
	}
	if actor == "" {
		actor = "system"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.scanNoiseRowsLocked(f)
	targets, protectedSkipped, byReason, sampleKeys := selectNoiseTargets(rows, cfg, f, act)
	var affected int64
	for _, id := range targets {
		e, ok := m.byID[id]
		if !ok {
			continue
		}
		if act == NoiseCleanupActionDelete {
			delete(m.byID, id)
			delete(m.byKey, endpointScopeKey(e))
			delete(m.assets, id)
			delete(m.dims, id)
			delete(m.segments, id)
			affected++
		} else if e.AssetStatus != "IGNORED" {
			from := e.AssetStatus
			e.AssetStatus = "IGNORED"
			e.ZombieSince = nil
			m.appendEventLocked(id, from, "IGNORED", "批量清理静态/非API噪声", actor)
			affected++
		}
	}
	return &NoiseCleanupResult{
		Action:           act,
		Affected:         affected,
		ProtectedSkipped: protectedSkipped,
		ByReason:         byReason,
		SampleKeys:       sampleKeys,
	}, nil
}

func (m *MemStore) scanNoiseRowsLocked(f NoiseCleanupFilter) []noiseScanRow {
	var idSet map[uuid.UUID]struct{}
	if len(f.IDs) > 0 {
		idSet = make(map[uuid.UUID]struct{}, len(f.IDs))
		for _, id := range f.IDs {
			idSet[id] = struct{}{}
		}
	}
	rows := make([]noiseScanRow, 0, len(m.byID))
	for _, e := range m.byID {
		if f.ApplicationID != nil && (e.ApplicationID == nil || *e.ApplicationID != *f.ApplicationID) {
			continue
		}
		if idSet != nil {
			if _, ok := idSet[e.ID]; !ok {
				continue
			}
		}
		protected := e.AssetStatus == "CONFIRMED" ||
			e.CurrentModelVersionID != nil ||
			e.LearningStatus == "LEARNING" ||
			e.LearningStatus == "LEARNED"
		rows = append(rows, noiseScanRow{
			candidate: NoiseEndpointCandidate{
				ID:             e.ID,
				ApplicationID:  e.ApplicationID,
				HTTPMethod:     e.HTTPMethod,
				NormalizedPath: e.NormalizedPath,
				DirectoryPath:  e.DirectoryPath,
				EndpointKey:    e.EndpointKey,
				AssetStatus:    e.AssetStatus,
				IsAPI:          e.IsAPI,
				APIConfidence:  e.APIConfidence,
				HitCount:       e.HitCount,
				LastSeenAt:     e.LastSeenAt,
			},
			protected: protected,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].candidate.LastSeenAt.After(rows[j].candidate.LastSeenAt)
	})
	return rows
}
