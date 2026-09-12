// store.go 文件资产 PostgreSQL 仓储：列表/统计只读查询（Repository 接口，
// SQL 与内存实现共用，便于诚实单测）+ 批量下载候选查询（riskStore 窄接口）。
// 过滤条件一律白名单拼接、值参数化。
package apifiles

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository 文件资产列表/统计只读仓储（SQL 与内存实现共用）。
type Repository interface {
	// ListAssets 明细分页（窗口按 last_seen 口径；last_seen 倒序）
	ListAssets(ctx context.Context, f AssetFilter) ([]FileAsset, int64, error)
	// Stats §106 统计聚合（窗口 days 天）
	Stats(ctx context.Context, days int) (*StatsData, error)
}

// riskStore 批量下载风险判定查询窄接口（SQL 与内存实现共用）。
type riskStore interface {
	// BulkDownloadCandidates 近 window 内每身份下载的不同文件数（count(DISTINCT filename)
	// 口径：同名文件按一个计，文件名即资产名），超过阈值（严格大于）的候选集合
	BulkDownloadCandidates(ctx context.Context, window time.Duration, threshold int) ([]BulkDownloadStat, error)
}

// 确保 *Store 同时实现只读与风险查询接口（*MemStore 见 mem_store.go）。
var (
	_ Repository = (*Store)(nil)
	_ riskStore  = (*Store)(nil)
)

// Store 文件资产 PostgreSQL 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// assetCols 明细查询列。
const assetCols = `id, endpoint_id, endpoint_key, direction, filename, extension, mime, size_bytes,
	sha256, identity_fingerprint, client_ip_masked, sensitive_types, first_seen, last_seen,
	transfer_count, created_at, updated_at`

// scanAsset 扫描一行文件资产（jsonb 数组列经 json.RawMessage 中转，空归一为 []）。
func scanAsset(row interface{ Scan(...any) error }) (*FileAsset, error) {
	var a FileAsset
	var sensitive json.RawMessage
	err := row.Scan(&a.ID, &a.EndpointID, &a.EndpointKey, &a.Direction, &a.FileName,
		&a.Extension, &a.MIME, &a.SizeBytes, &a.SHA256, &a.IdentityFingerprint,
		&a.ClientIPMasked, &sensitive, &a.FirstSeen, &a.LastSeen,
		&a.TransferCount, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	a.SensitiveTypes = []string{}
	if len(sensitive) > 0 && string(sensitive) != "null" {
		if err := json.Unmarshal(sensitive, &a.SensitiveTypes); err != nil {
			return nil, err
		}
	}
	return &a, nil
}

// ListAssets 明细分页（过滤条件白名单拼接，值一律参数化；last_seen 倒序）。
func (s *Store) ListAssets(ctx context.Context, f AssetFilter) ([]FileAsset, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	where := []string{`last_seen >= CURRENT_DATE - ($1::int - 1) * interval '1 day'`}
	args := []any{clampDays(f.Days)}
	if f.Direction != "" {
		args = append(args, f.Direction)
		where = append(where, fmt.Sprintf("direction = $%d", len(args)))
	}
	if f.MIME != "" {
		args = append(args, f.MIME)
		where = append(where, fmt.Sprintf("mime = $%d", len(args)))
	}
	if f.Extension != "" {
		args = append(args, f.Extension)
		where = append(where, fmt.Sprintf("extension = $%d", len(args)))
	}
	if f.EndpointKey != "" {
		args = append(args, f.EndpointKey)
		where = append(where, fmt.Sprintf("endpoint_key = $%d", len(args)))
	}
	if f.SensitiveOnly {
		where = append(where, `sensitive_types <> '[]'::jsonb`)
	}
	cond := " WHERE " + strings.Join(where, " AND ")
	var total int64
	if err := s.db.QueryRow(ctx, "SELECT count(*) FROM api_file_assets"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, `SELECT `+assetCols+` FROM api_file_assets`+cond+
		fmt.Sprintf(" ORDER BY last_seen DESC, id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []FileAsset{}
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *a)
	}
	return out, total, rows.Err()
}

// Stats §106 统计聚合（SQL 实现；窗口与列表明细同口径）。
func (s *Store) Stats(ctx context.Context, days int) (*StatsData, error) {
	days = clampDays(days)
	out := &StatsData{
		Days:        days,
		TopFiles:    []FileTopStat{},
		TopIPs:      []IPTopStat{},
		TopAccounts: []AccountTopStat{},
		TopAPIs:     []APITopStat{},
	}
	const window = `last_seen >= CURRENT_DATE - ($1::int - 1) * interval '1 day'`

	// 汇总：方向资产数/传输次数 + 敏感文件数
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE direction = 'UPLOAD'),
       count(*) FILTER (WHERE direction = 'DOWNLOAD'),
       COALESCE(sum(transfer_count) FILTER (WHERE direction = 'UPLOAD'), 0),
       COALESCE(sum(transfer_count) FILTER (WHERE direction = 'DOWNLOAD'), 0),
       count(*) FILTER (WHERE sensitive_types <> '[]'::jsonb)
FROM api_file_assets WHERE `+window, days).
		Scan(&out.Summary.UploadAssets, &out.Summary.DownloadAssets,
			&out.Summary.UploadTransfers, &out.Summary.DownloadTransfers,
			&out.Summary.SensitiveFileCount); err != nil {
		return nil, fmt.Errorf("file assets stats summary: %w", err)
	}

	// File TOP（传输次数降序；同名文件跨身份/端点归并）
	rows, err := s.db.Query(ctx, `
SELECT filename, direction, sum(transfer_count), count(DISTINCT identity_fingerprint)
FROM api_file_assets WHERE `+window+`
GROUP BY filename, direction ORDER BY sum(transfer_count) DESC, filename LIMIT $2`, days, topLimit)
	if err != nil {
		return nil, fmt.Errorf("file assets stats top files: %w", err)
	}
	for rows.Next() {
		var it FileTopStat
		if err := rows.Scan(&it.FileName, &it.Direction, &it.Transfers, &it.Identities); err != nil {
			rows.Close()
			return nil, err
		}
		out.TopFiles = append(out.TopFiles, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// IP TOP（掩码口径；空掩码 = 网关未上报客户端 IP，单列一组如实呈现）
	ipRows, err := s.db.Query(ctx, `
SELECT client_ip_masked, sum(transfer_count), count(*)
FROM api_file_assets WHERE `+window+`
GROUP BY client_ip_masked ORDER BY sum(transfer_count) DESC, client_ip_masked LIMIT $2`, days, topLimit)
	if err != nil {
		return nil, fmt.Errorf("file assets stats top ips: %w", err)
	}
	for ipRows.Next() {
		var it IPTopStat
		if err := ipRows.Scan(&it.ClientIPMasked, &it.Transfers, &it.Files); err != nil {
			ipRows.Close()
			return nil, err
		}
		out.TopIPs = append(out.TopIPs, it)
	}
	ipRows.Close()
	if err := ipRows.Err(); err != nil {
		return nil, err
	}

	// Account TOP（身份指纹；匿名空串单列一组）
	accRows, err := s.db.Query(ctx, `
SELECT identity_fingerprint, sum(transfer_count), count(*)
FROM api_file_assets WHERE `+window+`
GROUP BY identity_fingerprint ORDER BY sum(transfer_count) DESC, identity_fingerprint LIMIT $2`, days, topLimit)
	if err != nil {
		return nil, fmt.Errorf("file assets stats top accounts: %w", err)
	}
	for accRows.Next() {
		var it AccountTopStat
		if err := accRows.Scan(&it.IdentityFingerprint, &it.Transfers, &it.Files); err != nil {
			accRows.Close()
			return nil, err
		}
		out.TopAccounts = append(out.TopAccounts, it)
	}
	accRows.Close()
	if err := accRows.Err(); err != nil {
		return nil, err
	}

	// API TOP（端点维度）
	apiRows, err := s.db.Query(ctx, `
SELECT endpoint_key, sum(transfer_count), count(*)
FROM api_file_assets WHERE `+window+`
GROUP BY endpoint_key ORDER BY sum(transfer_count) DESC, endpoint_key LIMIT $2`, days, topLimit)
	if err != nil {
		return nil, fmt.Errorf("file assets stats top apis: %w", err)
	}
	for apiRows.Next() {
		var it APITopStat
		if err := apiRows.Scan(&it.EndpointKey, &it.Transfers, &it.Files); err != nil {
			apiRows.Close()
			return nil, err
		}
		out.TopAPIs = append(out.TopAPIs, it)
	}
	apiRows.Close()
	if err := apiRows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// BulkDownloadCandidates 近 window 内下载方向按身份聚合：不同文件数（DISTINCT filename
// 口径）严格大于阈值的候选（匿名身份空串不参与——无凭据主体不构成"同身份"判定）。
func (s *Store) BulkDownloadCandidates(ctx context.Context, window time.Duration, threshold int) ([]BulkDownloadStat, error) {
	rows, err := s.db.Query(ctx, `
SELECT identity_fingerprint, count(DISTINCT filename), sum(transfer_count)
FROM api_file_assets
WHERE direction = 'DOWNLOAD' AND identity_fingerprint <> ''
  AND last_seen >= now() - $1::interval
GROUP BY identity_fingerprint
HAVING count(DISTINCT filename) > $2
ORDER BY count(DISTINCT filename) DESC, identity_fingerprint`,
		fmt.Sprintf("%d seconds", int(window.Seconds())), threshold)
	if err != nil {
		return nil, fmt.Errorf("file bulk download candidates: %w", err)
	}
	defer rows.Close()
	out := []BulkDownloadStat{}
	for rows.Next() {
		var it BulkDownloadStat
		if err := rows.Scan(&it.IdentityFingerprint, &it.DistinctFiles, &it.Transfers); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}
