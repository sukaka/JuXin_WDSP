// store.go 暴露面判定引擎 PostgreSQL 仓储（Repository 接口，SQL 与内存实现共用，
// 便于诚实单测）：
//   - 写入侧：RecordSource 来源聚合 upsert（bucket 计数 + seen 盐化指纹去重明细）；
//     WriteAssessment 评估明细；ApplyVerdict 条件 upsert 分类维度
//     （WHERE source<>'MANUAL' 且端点未锁定——人工确认永不覆盖）；
//   - 读取侧：WindowStats 观察窗聚合 / EndpointContext 端点归属（域名/端口/部署模式）/
//     LatestAssessment 最近评估 / ListCandidates 待评估端点；
//   - Prune 留存清理（默认 30 天）。
package apiexposure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound 端点不存在。
var ErrNotFound = errors.New("api endpoint not found")

// DBTX 仓储方法依赖的最小查询接口（*pgxpool.Pool 与 pgx.Tx 均满足；
// 采集器批次事务窗口内经 WithDB 浅拷贝切换——与 apiruntime W22 同一手法）。
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// EndpointContext 端点归属上下文（配置证据与人工状态）。
type EndpointContext struct {
	ID                 uuid.UUID
	EndpointKey        string
	Hostname           string // 归属域名（绑定域名优先 → 应用主域名 → 观测 host；均无则空）
	HTTPPort           *int
	HTTPSPort          *int
	DeploymentMode     string  // applications.deployment_mode（未归属应用为空）
	Locked             bool    // api_endpoints.classification_locked
	ExistingValue      string  // 现存 EXPOSURE 维度值（无维度行为空）
	ExistingSource     string  // 现存 EXPOSURE 维度来源（无维度行为空）
	ExistingConfidence float64 // 现存 EXPOSURE 维度置信度数值（无维度行为 0）
}

// AssessmentRecord 一次评估明细（api_exposure_assessments）。
type AssessmentRecord struct {
	ID         uuid.UUID      `json:"id"`
	EndpointID uuid.UUID      `json:"endpoint_id"`
	Verdict    string         `json:"verdict"`
	Source     string         `json:"source"`
	Confidence string         `json:"confidence"`
	Evidence   []EvidenceItem `json:"evidence"`
	AssessedAt time.Time      `json:"assessed_at"`
}

// Repository 暴露面引擎仓储（SQL 与内存实现共用）。
type Repository interface {
	// RecordSource 来源聚合 upsert（bucket 计数 + seen 指纹去重；fingerprint 空串
	// = 匿名来源，只计桶不去重明细；scope 词表 INTERNAL/PUBLIC/PARTNER 由调用方归一）
	RecordSource(ctx context.Context, endpointID uuid.UUID, scope, fingerprint string, ts time.Time) error
	// WindowStats 观察窗内按来源范围聚合（sinceDay 起，UTC 自然日口径）
	WindowStats(ctx context.Context, endpointID uuid.UUID, sinceDay time.Time) ([]ScopeBucket, error)
	// EndpointContext 端点归属上下文（不存在返回 ErrNotFound）
	EndpointContext(ctx context.Context, endpointID uuid.UUID) (*EndpointContext, error)
	// ListCandidates 待评估端点：近窗口有流量 或 从未评估/最近评估早于 staleBefore（限量）
	ListCandidates(ctx context.Context, sinceDay, staleBefore time.Time, limit int) ([]uuid.UUID, error)
	// LatestAssessment 最近一次评估（nil, nil = 从未评估）
	LatestAssessment(ctx context.Context, endpointID uuid.UUID) (*AssessmentRecord, error)
	// WriteAssessment 写评估明细（返回行 ID）
	WriteAssessment(ctx context.Context, endpointID uuid.UUID, a Assessment, assessedAt time.Time) (uuid.UUID, error)
	// ApplyVerdict 条件 upsert EXPOSURE 分类维度：端点已锁定或现存维度为 MANUAL 时
	// 不覆盖（applied=false）；其余来源（含历史 AUTO/TRAFFIC_OBSERVED/CONFIG）被替换
	ApplyVerdict(ctx context.Context, endpointID uuid.UUID, a Assessment) (applied bool, err error)
	// Prune 留存清理：删除 retentionDays 天前的 bucket/seen/assessment 行（返回总行数）
	Prune(ctx context.Context, retentionDays int) (int64, error)
}

// 确保 *Store 实现 Repository（*MemStore 见 mem_store.go）。
var _ Repository = (*Store)(nil)

// Store 暴露面引擎 PostgreSQL 仓储。
type Store struct {
	db DBTX
}

// NewStore 创建（绑定连接池，逐语句 autocommit）。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// WithDB 切换查询句柄（采集器批次事务窗口内绑定 pgx.Tx；浅拷贝）。
func (s *Store) WithDB(db DBTX) *Store { return &Store{db: db} }

// sourceFingerprintMaxLen 来源指纹长度上限（对齐迁移 000190 列宽；
// 超限指纹不落 seen 明细——桶计数不受影响，不伪造截断键）。
const sourceFingerprintMaxLen = 128

// RecordSource 来源聚合 upsert：bucket (endpoint_id, bucket_date, scope) 计数 +1；
// 带指纹时 seen (endpoint_id, seen_date, scope, source_fingerprint) 去重明细计数 +1。
// 自然日按 UTC 截断（与 api_endpoint_traffic_buckets 的 UTC 桶口径一致）。
func (s *Store) RecordSource(ctx context.Context, endpointID uuid.UUID, scope, fingerprint string, ts time.Time) error {
	day := ts.UTC().Truncate(24 * time.Hour)
	if _, err := s.db.Exec(ctx, `
INSERT INTO api_endpoint_source_buckets (endpoint_id, bucket_date, scope, request_count, updated_at)
VALUES ($1, $2, $3, 1, now())
ON CONFLICT (endpoint_id, bucket_date, scope) DO UPDATE SET
    request_count = api_endpoint_source_buckets.request_count + 1, updated_at = now()`,
		endpointID, day, scope); err != nil {
		return fmt.Errorf("upsert source bucket: %w", err)
	}
	if fingerprint == "" || len(fingerprint) > sourceFingerprintMaxLen {
		return nil // 匿名无指纹 / 超限指纹：只计桶，不落去重明细
	}
	if _, err := s.db.Exec(ctx, `
INSERT INTO api_endpoint_source_seen
    (endpoint_id, seen_date, scope, source_fingerprint, first_seen_at, last_seen_at, request_count)
VALUES ($1, $2, $3, $4, now(), now(), 1)
ON CONFLICT (endpoint_id, seen_date, scope, source_fingerprint) DO UPDATE SET
    last_seen_at = now(), request_count = api_endpoint_source_seen.request_count + 1`,
		endpointID, day, scope, fingerprint); err != nil {
		return fmt.Errorf("upsert source seen: %w", err)
	}
	return nil
}

// WindowStats 观察窗内按来源范围聚合（scope 升序，结果确定）。
func (s *Store) WindowStats(ctx context.Context, endpointID uuid.UUID, sinceDay time.Time) ([]ScopeBucket, error) {
	rows, err := s.db.Query(ctx, `
SELECT b.scope,
       count(DISTINCT b.bucket_date),
       COALESCE(sum(b.request_count), 0),
       (SELECT count(DISTINCT sn.source_fingerprint) FROM api_endpoint_source_seen sn
        WHERE sn.endpoint_id = $1 AND sn.scope = b.scope AND sn.seen_date >= $2)
FROM api_endpoint_source_buckets b
WHERE b.endpoint_id = $1 AND b.bucket_date >= $2
GROUP BY b.scope ORDER BY b.scope`, endpointID, sinceDay.UTC().Truncate(24*time.Hour))
	if err != nil {
		return nil, fmt.Errorf("window source stats: %w", err)
	}
	defer rows.Close()
	out := []ScopeBucket{}
	for rows.Next() {
		var b ScopeBucket
		if err := rows.Scan(&b.Scope, &b.Days, &b.Requests, &b.UniqueSources); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// EndpointContext 端点归属上下文：域名取绑定域名，未绑定回落应用主域名，
// 再回落观测 host；部署模式来自归属应用；现存 EXPOSURE 维度值/来源一并带出。
func (s *Store) EndpointContext(ctx context.Context, endpointID uuid.UUID) (*EndpointContext, error) {
	var ec EndpointContext
	err := s.db.QueryRow(ctx, `
SELECT e.id, e.endpoint_key, e.classification_locked,
       COALESCE(d.hostname, pd.hostname, e.host),
       COALESCE(d.http_port, pd.http_port),
       COALESCE(d.https_port, pd.https_port),
       COALESCE(a.deployment_mode, ''),
       COALESCE((SELECT c.value FROM api_classification_dimensions c
                 WHERE c.endpoint_id = e.id AND c.dimension = 'EXPOSURE'), ''),
       COALESCE((SELECT c.source FROM api_classification_dimensions c
                 WHERE c.endpoint_id = e.id AND c.dimension = 'EXPOSURE'), ''),
       COALESCE((SELECT c.confidence FROM api_classification_dimensions c
                 WHERE c.endpoint_id = e.id AND c.dimension = 'EXPOSURE'), 0)
FROM api_endpoints e
LEFT JOIN application_domains d ON d.id = e.domain_id
LEFT JOIN applications a ON a.id = e.application_id
LEFT JOIN application_domains pd ON pd.application_id = a.id AND pd.is_primary AND e.domain_id IS NULL
WHERE e.id = $1`, endpointID).Scan(
		&ec.ID, &ec.EndpointKey, &ec.Locked, &ec.Hostname,
		&ec.HTTPPort, &ec.HTTPSPort, &ec.DeploymentMode,
		&ec.ExistingValue, &ec.ExistingSource, &ec.ExistingConfidence)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("endpoint exposure context: %w", err)
	}
	return &ec, nil
}

// ListCandidates 待评估端点：窗口内有流量，或从未评估，或最近评估早于 staleBefore。
// 按 id 升序限量（结果确定；单轮上限防长事务，余量下轮继续）。
func (s *Store) ListCandidates(ctx context.Context, sinceDay, staleBefore time.Time, limit int) ([]uuid.UUID, error) {
	rows, err := s.db.Query(ctx, `
SELECT e.id FROM api_endpoints e
WHERE EXISTS (SELECT 1 FROM api_endpoint_source_buckets b
              WHERE b.endpoint_id = e.id AND b.bucket_date >= $1)
   OR NOT EXISTS (SELECT 1 FROM api_exposure_assessments a WHERE a.endpoint_id = e.id)
   OR (SELECT max(a2.assessed_at) FROM api_exposure_assessments a2
       WHERE a2.endpoint_id = e.id) < $2
ORDER BY e.id LIMIT $3`, sinceDay.UTC().Truncate(24*time.Hour), staleBefore, limit)
	if err != nil {
		return nil, fmt.Errorf("list exposure candidates: %w", err)
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

// LatestAssessment 最近一次评估明细（从未评估返回 nil, nil）。
func (s *Store) LatestAssessment(ctx context.Context, endpointID uuid.UUID) (*AssessmentRecord, error) {
	var rec AssessmentRecord
	var evidence []byte
	err := s.db.QueryRow(ctx, `
SELECT id, endpoint_id, verdict, source, confidence, evidence, assessed_at
FROM api_exposure_assessments
WHERE endpoint_id = $1 ORDER BY assessed_at DESC, id DESC LIMIT 1`, endpointID).Scan(
		&rec.ID, &rec.EndpointID, &rec.Verdict, &rec.Source, &rec.Confidence, &evidence, &rec.AssessedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("latest exposure assessment: %w", err)
	}
	rec.Evidence = []EvidenceItem{}
	if len(evidence) > 0 && string(evidence) != "null" {
		if err := json.Unmarshal(evidence, &rec.Evidence); err != nil {
			return nil, fmt.Errorf("parse assessment evidence: %w", err)
		}
	}
	return &rec, nil
}

// WriteAssessment 写评估明细（evidence 序列化为 JSONB；空证据归一为 []）。
func (s *Store) WriteAssessment(ctx context.Context, endpointID uuid.UUID, a Assessment, assessedAt time.Time) (uuid.UUID, error) {
	evidence := a.Evidence
	if evidence == nil {
		evidence = []EvidenceItem{}
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal assessment evidence: %w", err)
	}
	var id uuid.UUID
	if err := s.db.QueryRow(ctx, `
INSERT INTO api_exposure_assessments (endpoint_id, verdict, source, confidence, evidence, assessed_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6) RETURNING id`,
		endpointID, a.Verdict, a.Source, a.Confidence, string(raw), assessedAt).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("write exposure assessment: %w", err)
	}
	return id, nil
}

// ApplyVerdict 条件 upsert EXPOSURE 分类维度：事务内行级锁复查 classification_locked
// （防读上下文与写入之间的锁定竞态），ON CONFLICT ... WHERE source<>'MANUAL'
// 兜底保护人工来源；锁定或人工来源时 applied=false。
// 仅清扫/重评路径调用（绑定连接池的 Store；非池句柄如实报错）。
func (s *Store) ApplyVerdict(ctx context.Context, endpointID uuid.UUID, a Assessment) (bool, error) {
	pool, ok := s.db.(*pgxpool.Pool)
	if !ok {
		return false, fmt.Errorf("apply exposure verdict requires pool-bound store")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin exposure verdict tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var locked bool
	if err := tx.QueryRow(ctx,
		`SELECT classification_locked FROM api_endpoints WHERE id = $1 FOR UPDATE`, endpointID).Scan(&locked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, fmt.Errorf("lock endpoint row: %w", err)
	}
	if locked {
		return false, nil
	}
	ct, err := tx.Exec(ctx, `
INSERT INTO api_classification_dimensions (endpoint_id, dimension, value, source, confidence)
VALUES ($1, 'EXPOSURE', $2, $3, $4)
ON CONFLICT (endpoint_id, dimension) DO UPDATE SET
    value = EXCLUDED.value, source = EXCLUDED.source,
    confidence = EXCLUDED.confidence, updated_at = now()
WHERE api_classification_dimensions.source <> 'MANUAL'`,
		endpointID, a.Verdict, a.Source, ConfidenceScore(a.Confidence))
	if err != nil {
		return false, fmt.Errorf("upsert exposure dimension: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit exposure verdict: %w", err)
	}
	return ct.RowsAffected() == 1, nil
}

// Prune 留存清理：删除 retentionDays 天前的聚合桶/去重明细/评估历史。
func (s *Store) Prune(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	cutoffDay := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour).Truncate(24 * time.Hour)
	cutoffTs := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	var total int64
	for _, stmt := range []struct {
		sql string
		arg any
	}{
		{`DELETE FROM api_endpoint_source_buckets WHERE bucket_date < $1`, cutoffDay},
		{`DELETE FROM api_endpoint_source_seen WHERE seen_date < $1`, cutoffDay},
		{`DELETE FROM api_exposure_assessments WHERE assessed_at < $1`, cutoffTs},
	} {
		ct, err := s.db.Exec(ctx, stmt.sql, stmt.arg)
		if err != nil {
			return total, fmt.Errorf("prune exposure tables: %w", err)
		}
		total += ct.RowsAffected()
	}
	return total, nil
}

// normalizeScope 来源范围归一（大写 trim；非法值归 INVALID 由调用方跳过）。
func normalizeScope(scope string) string {
	return strings.ToUpper(strings.TrimSpace(scope))
}
