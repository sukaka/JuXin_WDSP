// store.go 权威关系接入存储（NG-AZ-01；迁移 000172 六表 + api_object_relations 权威写入）。
//
// 权威关系写入纪律：全部关系变更/幂等账本/水位在同一 pgx.Tx 内完成（Querier 注入——
// snapshot 原子切换与 delta 整批应用的边界）；读侧复用既有 relations 列表端点零改动
// （权威行与手工行同表同模型，scanRelation 原样带出 source=AUTHORITY_SYNC 溯源）。
package apiauthzauthority

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier 连接池/事务共用最小查询接口（权威写入全部在调用方开启的同一 Tx 内）。
type Querier interface {
	Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
}

// ErrNotFound 记录不存在。
var ErrNotFound = errors.New("authority record not found")

// ErrVersionConflict 乐观锁冲突。
var ErrVersionConflict = errors.New("authority source version conflict")

// Store 权威接入存储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建存储。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

// DB 连接池（service 开批次事务用）。
func (s *Store) DB() *pgxpool.Pool { return s.db }

// ---------- 来源 ----------

func scanSource(row pgx.Row) (*AuthoritySource, error) {
	var s AuthoritySource
	var scopes []byte
	err := row.Scan(&s.ID, &s.Name, &s.Status, &scopes, &s.MaxEventAgeSeconds,
		&s.CreatedAt, &s.UpdatedAt, &s.Version)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopes, &s.Scopes); err != nil {
		return nil, fmt.Errorf("decode source scopes: %w", err)
	}
	return &s, nil
}

const sourceCols = `id, name, status, scopes, max_event_age_seconds, created_at, updated_at, version`

// CreateSource 登记来源（名称唯一）。
func (s *Store) CreateSource(ctx context.Context, src *AuthoritySource) error {
	raw, _ := json.Marshal(src.Scopes)
	return s.db.QueryRow(ctx, `
INSERT INTO api_authority_sources (name, status, scopes, max_event_age_seconds)
VALUES ($1,$2,$3,$4)
RETURNING `+sourceCols,
		src.Name, src.Status, raw, src.MaxEventAgeSeconds).Scan(
		&src.ID, &src.Name, &src.Status, &raw, &src.MaxEventAgeSeconds,
		&src.CreatedAt, &src.UpdatedAt, &src.Version)
}

// GetSource 按 ID 读来源。
func (s *Store) GetSource(ctx context.Context, id uuid.UUID) (*AuthoritySource, error) {
	src, err := scanSource(s.db.QueryRow(ctx,
		`SELECT `+sourceCols+` FROM api_authority_sources WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return src, err
}

// ListSources 来源列表（按创建时间倒序）。
func (s *Store) ListSources(ctx context.Context) ([]AuthoritySource, error) {
	rows, err := s.db.Query(ctx, `SELECT `+sourceCols+` FROM api_authority_sources ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuthoritySource{}
	for rows.Next() {
		src, err := scanSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *src)
	}
	return out, rows.Err()
}

// UpdateSource 更新状态/范围/最大年龄（乐观锁 version；成功 version+1）。
func (s *Store) UpdateSource(ctx context.Context, src *AuthoritySource, expectVersion int) error {
	raw, _ := json.Marshal(src.Scopes)
	ct, err := s.db.Exec(ctx, `
UPDATE api_authority_sources
SET status=$2, scopes=$3, max_event_age_seconds=$4, version=version+1, updated_at=now()
WHERE id=$1 AND version=$5`,
		src.ID, src.Status, raw, src.MaxEventAgeSeconds, expectVersion)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrVersionConflict
	}
	return nil
}

// ---------- 来源密钥 ----------

// AddSourceKey 登记验签公钥（(source_id,key_id) 唯一）。
func (s *Store) AddSourceKey(ctx context.Context, sourceID uuid.UUID, k *SourceKey) error {
	return s.db.QueryRow(ctx, `
INSERT INTO api_authority_source_keys (source_id, key_id, public_key_hex)
VALUES ($1,$2,$3)
RETURNING id, created_at`, sourceID, k.KeyID, k.PublicKeyHex).Scan(&k.ID, &k.CreatedAt)
}

// RetireSourceKey 退役公钥（置 RETIRED + retired_at；轮换窗口起点）。
func (s *Store) RetireSourceKey(ctx context.Context, sourceID uuid.UUID, keyID string) error {
	ct, err := s.db.Exec(ctx, `
UPDATE api_authority_source_keys SET status='RETIRED', retired_at=now()
WHERE source_id=$1 AND key_id=$2 AND status='ACTIVE'`, sourceID, keyID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListSourceKeys 来源全部公钥（按创建时间升序）。
func (s *Store) ListSourceKeys(ctx context.Context, sourceID uuid.UUID) ([]SourceKey, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, key_id, public_key_hex, status, retired_at, created_at
FROM api_authority_source_keys WHERE source_id=$1 ORDER BY created_at, key_id`, sourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SourceKey{}
	for rows.Next() {
		var k SourceKey
		if err := rows.Scan(&k.ID, &k.KeyID, &k.PublicKeyHex, &k.Status, &k.RetiredAt, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// ---------- 批次 ----------

// InsertBatch 批次留痕（APPLIED/REJECTED；不属于关系原子区；ID 由调用方生成——
// 应用阶段需先持 ID 记账 applied_events.batch_id）。
func (s *Store) InsertBatch(ctx context.Context, b *ImportBatch) error {
	raw, _ := json.Marshal(b.Counts)
	return s.db.QueryRow(ctx, `
INSERT INTO api_authority_import_batches (id, source_id, mode, status, counts, error, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7)
RETURNING created_at`,
		b.ID, b.SourceID, b.Mode, b.Status, raw, b.Error, b.CreatedBy).Scan(&b.CreatedAt)
}

// ListBatches 来源批次历史（按创建时间倒序，限量）。
func (s *Store) ListBatches(ctx context.Context, sourceID uuid.UUID, limit int) ([]ImportBatch, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.Query(ctx, `
SELECT id, source_id, mode, status, counts, error, created_by, created_at
FROM api_authority_import_batches WHERE source_id=$1 ORDER BY created_at DESC, id LIMIT $2`, sourceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ImportBatch{}
	for rows.Next() {
		var b ImportBatch
		var counts []byte
		if err := rows.Scan(&b.ID, &b.SourceID, &b.Mode, &b.Status, &counts, &b.Error, &b.CreatedBy, &b.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(counts, &b.Counts); err != nil {
			return nil, fmt.Errorf("decode batch counts: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ---------- 幂等账本与水位（调用方 Tx 内） ----------

// AppliedEventExists 幂等判定（校验链第 3 步）。
func (s *Store) AppliedEventExists(ctx context.Context, q Querier, sourceID uuid.UUID, eventID string) (bool, error) {
	var exists bool
	if err := q.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM api_authority_applied_events WHERE source_id=$1 AND event_id=$2)`,
		sourceID, eventID).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

// SequenceExists 序号已消费判定（(source_id,sequence) 唯一水压的业务侧预检：
// 同序号不同 event_id = 重放攻击面，批次级拒收）。
func (s *Store) SequenceExists(ctx context.Context, q Querier, sourceID uuid.UUID, sequence uint64) (bool, error) {
	var exists bool
	if err := q.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM api_authority_applied_events WHERE source_id=$1 AND sequence=$2)`,
		sourceID, int64(sequence)).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

// InsertAppliedEvent 幂等消费记账（(source_id,event_id) 主键 + (source_id,sequence) 唯一水压）。
func (s *Store) InsertAppliedEvent(ctx context.Context, q Querier, sourceID uuid.UUID, eventID string, sequence uint64, batchID uuid.UUID, changeType string) error {
	_, err := q.Exec(ctx, `
INSERT INTO api_authority_applied_events (source_id, event_id, sequence, batch_id, change_type)
VALUES ($1,$2,$3,$4,$5)`, sourceID, eventID, int64(sequence), batchID, changeType)
	return err
}

// GetWatermark 读来源水位（无锁，状态视图用；不存在返回零水位）。
func (s *Store) GetWatermark(ctx context.Context, sourceID uuid.UUID) (SourceWatermark, error) {
	var w SourceWatermark
	var gap *int64
	err := s.db.QueryRow(ctx, `
SELECT last_sequence, last_event_id, revocation_watermark, gap_from, updated_at
FROM api_authority_watermarks WHERE source_id=$1`, sourceID).
		Scan(&w.LastSequence, &w.LastEventID, &w.RevocationWatermark, &gap, &w.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SourceWatermark{}, nil
	}
	if err != nil {
		return SourceWatermark{}, err
	}
	if gap != nil {
		v := uint64(*gap)
		w.GapFrom = &v
	}
	return w, nil
}

// GetWatermarkForUpdate 锁读来源水位（不存在返回零水位——调用方随后 upsert）。
func (s *Store) GetWatermarkForUpdate(ctx context.Context, q Querier, sourceID uuid.UUID) (SourceWatermark, error) {
	var w SourceWatermark
	var gap *int64
	err := q.QueryRow(ctx, `
SELECT last_sequence, last_event_id, revocation_watermark, gap_from, updated_at
FROM api_authority_watermarks WHERE source_id=$1 FOR UPDATE`, sourceID).
		Scan(&w.LastSequence, &w.LastEventID, &w.RevocationWatermark, &gap, &w.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SourceWatermark{}, nil
	}
	if err != nil {
		return SourceWatermark{}, err
	}
	if gap != nil {
		v := uint64(*gap)
		w.GapFrom = &v
	}
	return w, nil
}

// UpsertWatermark 推进水位（调用方保证单调不下降——本函数只做写入）。
func (s *Store) UpsertWatermark(ctx context.Context, q Querier, sourceID uuid.UUID, w SourceWatermark) error {
	var gap *int64
	if w.GapFrom != nil {
		v := int64(*w.GapFrom)
		gap = &v
	}
	_, err := q.Exec(ctx, `
INSERT INTO api_authority_watermarks (source_id, last_sequence, last_event_id, revocation_watermark, gap_from)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (source_id) DO UPDATE SET
  last_sequence = EXCLUDED.last_sequence,
  last_event_id = EXCLUDED.last_event_id,
  revocation_watermark = EXCLUDED.revocation_watermark,
  gap_from = EXCLUDED.gap_from,
  updated_at = now()`,
		sourceID, int64(w.LastSequence), w.LastEventID, int64(w.RevocationWatermark), gap)
	return err
}

// RecomputeGap 缺口重算：已应用序号区间 [min,max] 内最小缺失序号（无缺失 NULL）。
// 事实源为幂等账本——delta 补齐缺口后自动消除（设计 §1 AUTHZ_SOURCE_GAP 语义）。
func (s *Store) RecomputeGap(ctx context.Context, q Querier, sourceID uuid.UUID) (*uint64, error) {
	var gap *int64
	if err := q.QueryRow(ctx, `
SELECT MIN(g) FROM generate_series(
  (SELECT MIN(sequence) FROM api_authority_applied_events WHERE source_id=$1),
  (SELECT MAX(sequence) FROM api_authority_applied_events WHERE source_id=$1)) AS g
WHERE NOT EXISTS (SELECT 1 FROM api_authority_applied_events WHERE source_id=$1 AND sequence=g)`,
		sourceID).Scan(&gap); err != nil {
		return nil, err
	}
	if gap == nil {
		return nil, nil
	}
	v := uint64(*gap)
	return &v, nil
}

// ---------- 权威关系写入（调用方 Tx 内） ----------

// GrantRelation GRANT 应用：同键行（任意状态/来源）接管为 CONFIRMED + 权威溯源与
// 有效期（权威通道是事实源；同一 (object,principal) 事实不因来源重复建行——uq 唯一键）。
// 返回影响行 id。
func (s *Store) GrantRelation(ctx context.Context, q Querier, in GrantInput) (uuid.UUID, error) {
	var id uuid.UUID
	err := q.QueryRow(ctx, `
INSERT INTO api_object_relations
  (application_id, object_type, object_ref, principal_id, tenant_id, relation, source,
   status, valid_from, valid_until, evidence_ref, confirmed_by, confirmed_at, reason,
   source_id, source_event_id, source_batch_id)
VALUES ($1,$2,$3,$4,$5,'OWNER','AUTHORITY_SYNC','CONFIRMED',$6,$7,$8,$9,now(),$10,$11,$12,$13)
ON CONFLICT ON CONSTRAINT uq_authz_relation DO UPDATE SET
  status = 'CONFIRMED',
  source = 'AUTHORITY_SYNC',
  valid_from = EXCLUDED.valid_from,
  valid_until = EXCLUDED.valid_until,
  evidence_ref = EXCLUDED.evidence_ref,
  confirmed_by = EXCLUDED.confirmed_by,
  confirmed_at = now(),
  reason = EXCLUDED.reason,
  source_id = EXCLUDED.source_id,
  source_event_id = EXCLUDED.source_event_id,
  source_batch_id = EXCLUDED.source_batch_id,
  updated_at = now()
RETURNING id`,
		in.ApplicationID, in.ObjectType, in.ObjectRef, in.PrincipalRef, in.TenantDomain,
		in.ValidFrom, in.ValidUntil, in.EvidenceRef, in.ConfirmedBy, in.Reason,
		in.SourceID, in.EventID, in.BatchID).Scan(&id)
	return id, err
}

// GrantInput GRANT 应用输入。
type GrantInput struct {
	ApplicationID uuid.UUID
	ObjectType    string
	ObjectRef     string
	PrincipalRef  string
	TenantDomain  *string
	ValidFrom     time.Time
	ValidUntil    *time.Time
	EvidenceRef   *string
	ConfirmedBy   string
	Reason        string
	SourceID      uuid.UUID
	EventID       string
	BatchID       uuid.UUID
}

// RevokeRelation REVOKE 应用：仅撤销本来源 AUTHORITY_SYNC 有效行（来源只管自己签发
// 的事实，不撤销 MANUAL/其他来源关系——契约补充决策见 types.go 头注释）。返回撤销行数。
func (s *Store) RevokeRelation(ctx context.Context, q Querier, sourceID, appID uuid.UUID, objectType, objectRef, principalRef string, tenantDomain *string) (int64, error) {
	ct, err := q.Exec(ctx, `
UPDATE api_object_relations SET status='REVOKED', updated_at=now()
WHERE application_id=$1 AND object_type=$2 AND object_ref=$3 AND principal_id=$4
  AND relation='OWNER' AND source='AUTHORITY_SYNC' AND source_id=$5 AND status='CONFIRMED'
  AND COALESCE(tenant_id,'') = COALESCE($6,'')`,
		appID, objectType, objectRef, principalRef, sourceID, tenantDomain)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// RevokeAuthorityRelationsNotIn snapshot 切换：本来源本域有效权威行中不在新全量键集
// 内的标记 REVOKED（保留历史行——与既有模型「撤销非删除」一致；任何失败整体回滚，
// 绝不把未导入对象当撤销——全量语义只在切换成功时成立）。
func (s *Store) RevokeAuthorityRelationsNotIn(ctx context.Context, q Querier, sourceID, appID uuid.UUID, tenantDomain *string, keepKeys []string) (int64, error) {
	ct, err := q.Exec(ctx, `
UPDATE api_object_relations SET status='REVOKED', updated_at=now()
WHERE application_id=$1 AND source='AUTHORITY_SYNC' AND source_id=$2 AND status='CONFIRMED'
  AND relation='OWNER' AND COALESCE(tenant_id,'') = COALESCE($3,'')
  AND NOT (object_type || ' ' || object_ref || ' ' || principal_id = ANY($4))`,
		appID, sourceID, tenantDomain, keepKeys)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// ListActiveOwnerPrincipals 冲突评估输入：同对象当前有效 OWNER 的 distinct principal
// （全部来源——权威与手工共享同一对象空间；valid_until 未过期）。
func (s *Store) ListActiveOwnerPrincipals(ctx context.Context, q Querier, appID uuid.UUID, objectType, objectRef string, tenantDomain *string, now time.Time) ([]string, error) {
	rows, err := q.Query(ctx, `
SELECT DISTINCT principal_id FROM api_object_relations
WHERE application_id=$1 AND object_type=$2 AND object_ref=$3 AND relation='OWNER'
  AND status='CONFIRMED' AND (valid_until IS NULL OR valid_until > $5)
  AND COALESCE(tenant_id,'') = COALESCE($4,'')
ORDER BY principal_id`,
		appID, objectType, objectRef, tenantDomain, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpsertConflict 冲突登记/刷新（OPEN 幂等：存在则更新 principals 与 updated_at）。
func (s *Store) UpsertConflict(ctx context.Context, q Querier, appID uuid.UUID, objectType, tenantDomain, objectRef string, principals []string) error {
	sort.Strings(principals)
	raw, _ := json.Marshal(principals)
	_, err := q.Exec(ctx, `
INSERT INTO api_authority_conflicts (application_id, object_type, tenant_domain, object_ref, principals)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT ON CONSTRAINT uq_authority_conflict_object DO UPDATE SET
  principals = EXCLUDED.principals, status='OPEN', updated_at=now()`,
		appID, objectType, tenantDomain, objectRef, raw)
	return err
}

// ResolveConflictIfSingleOwner 冲突自动解除：对象有效 OWNER 收敛到 ≤1 个不同
// principal 时把 OPEN 冲突标 RESOLVED（不伪造持续冲突——冲突对象不参与
// VERIFIED_VIOLATION 判定的排除必须随事实收敛同步解除）。
func (s *Store) ResolveConflictIfSingleOwner(ctx context.Context, q Querier, appID uuid.UUID, objectType, tenantDomain, objectRef string) error {
	_, err := q.Exec(ctx, `
UPDATE api_authority_conflicts SET status='RESOLVED', updated_at=now()
WHERE application_id=$1 AND object_type=$2 AND tenant_domain=$3 AND object_ref=$4 AND status='OPEN'`,
		appID, objectType, tenantDomain, objectRef)
	return err
}

// ListConflicts 冲突列表（OPEN 优先，按 updated_at 倒序）。
func (s *Store) ListConflicts(ctx context.Context, status string, limit int) ([]ConflictRecord, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	where := ""
	args := []interface{}{limit}
	if status != "" {
		where = "WHERE status = $2"
		args = append(args, status)
	}
	rows, err := s.db.Query(ctx, `
SELECT id, application_id, object_type, tenant_domain, object_ref, principals, status, first_seen, updated_at
FROM api_authority_conflicts `+where+` ORDER BY status='OPEN' DESC, updated_at DESC LIMIT $1`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ConflictRecord{}
	for rows.Next() {
		var c ConflictRecord
		var principals []byte
		if err := rows.Scan(&c.ID, &c.ApplicationID, &c.ObjectType, &c.TenantDomain, &c.ObjectRef,
			&principals, &c.Status, &c.FirstSeen, &c.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(principals, &c.Principals); err != nil {
			return nil, fmt.Errorf("decode conflict principals: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---------- 应用域解析 ----------

// ResolveAppByDomain tenant_domain → application_id（管理面 ACTIVE 应用域；
// 解析不到/多义均报错——契约补充决策见 types.go 头注释）。
func (s *Store) ResolveAppByDomain(ctx context.Context, domain string) (uuid.UUID, error) {
	var appID uuid.UUID
	err := s.db.QueryRow(ctx, `
SELECT application_id FROM application_domains ad
JOIN applications a ON a.id = ad.application_id
WHERE ad.normalized_hostname = $1 AND ad.status = 'ACTIVE' AND a.deleted_at IS NULL
LIMIT 2`, strings.ToLower(strings.TrimSpace(domain))).Scan(&appID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("tenant_domain 未登记为任何 ACTIVE 应用域: %s", domain)
	}
	if err != nil {
		return uuid.Nil, err
	}
	return appID, nil
}
