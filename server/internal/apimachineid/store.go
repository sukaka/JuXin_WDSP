// store.go 机器身份登记 PostgreSQL 仓储（NG-ID g1 批次 B1）：身份 CRUD（乐观锁 409、
// 删除先决 409）+公钥导入（PEM 解析校验）+轮换/撤销状态机（rotate 原子=新 ACTIVE+
// 旧 RETIRED+重叠窗口；revoke 与水位 seq+1 同一事务原子提交——apiauthz relations.go:356
// 同事务、:389-390 只增 upsert 先例）+绑定 CRUD。写路径全部事务化（不留半状态；
// FK 冲突映射友好哨兵）。
package apimachineid

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository 机器身份登记仓储接口（*Store 实现；包内单测注入内存 fake——
// 事务/唯一键/FK/状态机/水位语义由 PG 契约测试覆盖）。
type Repository interface {
	CreateIdentity(ctx context.Context, in IdentityInput, createdBy string) (*Identity, error)
	ListIdentities(ctx context.Context) ([]IdentitySummary, int64, error)
	GetIdentity(ctx context.Context, id uuid.UUID) (*Identity, []Key, error)
	UpdateIdentity(ctx context.Context, id uuid.UUID, in IdentityInput) (*Identity, error)
	DeleteIdentity(ctx context.Context, id uuid.UUID) error

	ImportKey(ctx context.Context, identityID uuid.UUID, in KeyInput, createdBy string) (*Key, error)
	RotateKey(ctx context.Context, identityID, keyID uuid.UUID, in KeyInput, createdBy string) (*Key, *Key, error)
	RevokeKey(ctx context.Context, identityID, keyID uuid.UUID) (*Key, error)

	CreateBinding(ctx context.Context, in BindingInput, createdBy string) (*Binding, error)
	ListBindings(ctx context.Context, applicationID uuid.UUID) ([]Binding, error)
	UpdateBinding(ctx context.Context, id uuid.UUID, in BindingInput) (*Binding, error)
	DeleteBinding(ctx context.Context, id uuid.UUID) error
}

// Store 仓储实现。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建。
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

var _ Repository = (*Store)(nil)

const identityCols = `id, identity_name, tenant_id, principal_binding, status, bot_challenge_exempt, version, COALESCE(created_by,''), created_at, updated_at`

func scanIdentity(row pgx.Row) (Identity, error) {
	var m Identity
	err := row.Scan(&m.ID, &m.IdentityName, &m.TenantID, &m.PrincipalBinding, &m.Status,
		&m.BotChallengeExempt, &m.Version, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt)
	return m, err
}

const keyCols = `id, identity_id, kid, alg, public_key_pem, status, not_before, not_after, retire_overlap_until, revoked_seq, COALESCE(created_by,''), created_at, updated_at`

func scanKey(row pgx.Row) (Key, error) {
	var k Key
	err := row.Scan(&k.ID, &k.IdentityID, &k.Kid, &k.Alg, &k.PublicKeyPEM, &k.Status,
		&k.NotBefore, &k.NotAfter, &k.RetireOverlapUntil, &k.RevokedSeq, &k.CreatedBy, &k.CreatedAt, &k.UpdatedAt)
	if err != nil {
		return k, err
	}
	// 指纹现算（不落库——四表冻结无指纹列；§1.3 管理面与事件稳定引用）
	if _, fp, perr := ParsePublicKey(k.Alg, k.PublicKeyPEM); perr == nil {
		k.KeyFingerprint = fp
	}
	return k, nil
}

func normStrPtr(p *string) *string {
	if p == nil {
		return nil
	}
	v := strings.TrimSpace(*p)
	if v == "" {
		return nil
	}
	return &v
}

func isUniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func isAppFKViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23503" && strings.Contains(pe.ConstraintName, "application_id")
}

// ---------- 身份 ----------

// CreateIdentity 创建身份（同名 409；状态缺省 ENABLED）。
func (s *Store) CreateIdentity(ctx context.Context, in IdentityInput, createdBy string) (*Identity, error) {
	status := orDefault(strings.ToUpper(strings.TrimSpace(in.Status)), StatusEnabled)
	m, err := scanIdentity(s.db.QueryRow(ctx, `INSERT INTO machine_identities
		(identity_name, tenant_id, principal_binding, status, bot_challenge_exempt, created_by)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING `+identityCols,
		strings.TrimSpace(in.IdentityName), normStrPtr(in.TenantID), normStrPtr(in.PrincipalBinding),
		status, in.BotChallengeExempt, createdBy))
	if isUniqueViolation(err) {
		return nil, ErrDuplicateName
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// ListIdentities 身份列表（含键状态摘要与撤销水位；identity_name 稳定序）。
func (s *Store) ListIdentities(ctx context.Context) ([]IdentitySummary, int64, error) {
	rows, err := s.db.Query(ctx, `SELECT `+identityCols+`,
		(SELECT count(*) FROM machine_identity_keys k WHERE k.identity_id=m.id),
		(SELECT count(*) FROM machine_identity_keys k WHERE k.identity_id=m.id AND k.status='ACTIVE'),
		(SELECT count(*) FROM machine_identity_keys k WHERE k.identity_id=m.id AND k.status='RETIRED'),
		(SELECT count(*) FROM machine_identity_keys k WHERE k.identity_id=m.id AND k.status='REVOKED')
		FROM machine_identities m ORDER BY identity_name`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []IdentitySummary{}
	for rows.Next() {
		var sm IdentitySummary
		if err := rows.Scan(&sm.ID, &sm.IdentityName, &sm.TenantID, &sm.PrincipalBinding, &sm.Status,
			&sm.BotChallengeExempt, &sm.Version, &sm.CreatedBy, &sm.CreatedAt, &sm.UpdatedAt,
			&sm.KeyCount, &sm.ActiveKeys, &sm.RetiredKeys, &sm.RevokedKeys); err != nil {
			return nil, 0, err
		}
		out = append(out, sm)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	wm, err := s.CurrentWatermark(ctx)
	if err != nil {
		return nil, 0, err
	}
	return out, wm, nil
}

// CurrentWatermark 当前撤销水位（单行种子 seq=0；行缺失按 0——迁移 000184 种子保证存在）。
func (s *Store) CurrentWatermark(ctx context.Context) (int64, error) {
	var seq int64
	err := s.db.QueryRow(ctx, `SELECT seq FROM machine_identity_revocation_watermark WHERE id=1`).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return seq, err
}

// GetIdentity 身份详情（定义+键行，kid 稳定序）。
func (s *Store) GetIdentity(ctx context.Context, id uuid.UUID) (*Identity, []Key, error) {
	m, err := scanIdentity(s.db.QueryRow(ctx, `SELECT `+identityCols+` FROM machine_identities WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	keys, err := s.listKeys(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	return &m, keys, nil
}

func (s *Store) listKeys(ctx context.Context, identityID uuid.UUID) ([]Key, error) {
	rows, err := s.db.Query(ctx, `SELECT `+keyCols+` FROM machine_identity_keys WHERE identity_id=$1 ORDER BY kid`, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Key{}
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// UpdateIdentity 改范围/状态/exempt/绑定主体（乐观锁 409；同名 409）。
func (s *Store) UpdateIdentity(ctx context.Context, id uuid.UUID, in IdentityInput) (*Identity, error) {
	status := orDefault(strings.ToUpper(strings.TrimSpace(in.Status)), StatusEnabled)
	m, err := scanIdentity(s.db.QueryRow(ctx, `UPDATE machine_identities SET
		identity_name=$3, tenant_id=$4, principal_binding=$5, status=$6, bot_challenge_exempt=$7,
		version=version+1, updated_at=now()
		WHERE id=$1 AND version=$2 RETURNING `+identityCols,
		id, in.Version, strings.TrimSpace(in.IdentityName), normStrPtr(in.TenantID),
		normStrPtr(in.PrincipalBinding), status, in.BotChallengeExempt))
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if qerr := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM machine_identities WHERE id=$1)`, id).Scan(&exists); qerr != nil {
			return nil, qerr
		}
		if !exists {
			return nil, ErrNotFound
		}
		return nil, ErrVersionConflict
	}
	if isUniqueViolation(err) {
		return nil, ErrDuplicateName
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// DeleteIdentity 删除身份（键 FK 级联；存在任一机器身份绑定 → 409 ErrIdentityInUse——
// 设计 §1.12 端点 5「FK 级联；绑定引用先决 409」：绑定不引用具体身份（登记册全局生效，
// §1.2 模型与 §1.12 发布段形状一致无身份键），删除任一身份都改变全局登记册内容，
// 故门禁=「先解绑再删除身份」（MCP ErrCatalogInUse 同纪律的全局登记册转置）。
func (s *Store) DeleteIdentity(ctx context.Context, id uuid.UUID) error {
	var refs int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM machine_identity_bindings`).Scan(&refs); err != nil {
		return err
	}
	if refs > 0 {
		return ErrIdentityInUse
	}
	ct, err := s.db.Exec(ctx, `DELETE FROM machine_identities WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- 公钥（导入/轮换/撤销状态机） ----------

// prepareKeyRow 公钥载荷→入库参数（PEM 解析校验+指纹；有效期解析——handler 已校词表）。
func prepareKeyRow(in KeyInput) (kid, alg, pemText, fp string, nb, na *time.Time, err error) {
	kid = strings.TrimSpace(in.Kid)
	alg = strings.TrimSpace(in.Alg)
	if pemText, fp, err = ParsePublicKey(alg, in.PublicKeyPEM); err != nil {
		return "", "", "", "", nil, nil, err
	}
	if nb, err = parseRFC3339Ptr(in.NotBefore); err != nil {
		return "", "", "", "", nil, nil, invalidf("not_before 须为 RFC3339 时间")
	}
	if na, err = parseRFC3339Ptr(in.NotAfter); err != nil {
		return "", "", "", "", nil, nil, invalidf("not_after 须为 RFC3339 时间")
	}
	return kid, alg, pemText, fp, nb, na, nil
}

// ImportKey 公钥静态导入（§1.3 纪律：唯一来源=管理面静态离线导入；PEM 解析校验算法
// 词表与密钥形态；身份不存在 404；kid 身份内重复 409；落库即 ACTIVE）。
func (s *Store) ImportKey(ctx context.Context, identityID uuid.UUID, in KeyInput, createdBy string) (*Key, error) {
	kid, alg, pemText, fp, nb, na, err := prepareKeyRow(in)
	if err != nil {
		return nil, err
	}
	k, err := scanKey(s.db.QueryRow(ctx, `INSERT INTO machine_identity_keys
		(identity_id, kid, alg, public_key_pem, not_before, not_after, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING `+keyCols,
		identityID, kid, alg, pemText, nb, na, createdBy))
	if isUniqueViolation(err) {
		return nil, ErrKeyDuplicate
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23503" {
		return nil, ErrNotFound // identity FK
	}
	if err != nil {
		return nil, err
	}
	k.KeyFingerprint = fp
	return &k, nil
}

// RotateKey 轮换（§1.6 冻结：原子=新键 ACTIVE+旧键 RETIRED+retire_overlap_until
// 重叠窗口终点（缺省 24h，上限 168h）；同一事务提交，不留半状态）。
// 旧键仅 ACTIVE 可轮换（RETIRED/REVOKED → 409 ErrKeyStateConflict）；新 kid 与身份内
// 既有 kid 冲突 → 409 ErrKeyDuplicate（窗口内新旧两键并存须可区分）。
func (s *Store) RotateKey(ctx context.Context, identityID, keyID uuid.UUID, in KeyInput, createdBy string) (*Key, *Key, error) {
	kid, alg, pemText, fp, nb, na, err := prepareKeyRow(in)
	if err != nil {
		return nil, nil, err
	}
	overlap := RotateOverlapDefaultHours
	if in.OverlapHours != nil {
		overlap = *in.OverlapHours
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// 旧键 ACTIVE 前提（锁行防并发双轮换）
	var oldStatus string
	err = tx.QueryRow(ctx, `SELECT status FROM machine_identity_keys WHERE id=$1 AND identity_id=$2 FOR UPDATE`,
		keyID, identityID).Scan(&oldStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if oldStatus != KeyStatusActive {
		return nil, nil, ErrKeyStateConflict
	}
	oldKey, err := scanKey(tx.QueryRow(ctx, `UPDATE machine_identity_keys SET
		status='RETIRED', retire_overlap_until=now()+make_interval(hours => $3), updated_at=now()
		WHERE id=$1 AND identity_id=$2 RETURNING `+keyCols, keyID, identityID, overlap))
	if err != nil {
		return nil, nil, err
	}
	newKey, err := scanKey(tx.QueryRow(ctx, `INSERT INTO machine_identity_keys
		(identity_id, kid, alg, public_key_pem, not_before, not_after, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING `+keyCols,
		identityID, kid, alg, pemText, nb, na, createdBy))
	if isUniqueViolation(err) {
		return nil, nil, ErrKeyDuplicate
	}
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	newKey.KeyFingerprint = fp
	return &newKey, &oldKey, nil
}

// RevokeKey 撤销（§1.6 冻结：即时生效；撤销事实与水位 seq+1 同一事务原子提交——
// apiauthz relations.go:356 同纪律；水位单行 upsert 只增——relations.go:389-390 同形；
// revoked_seq 落键行溯源）。已 REVOKED 键重复撤销 → 409 ErrKeyStateConflict。
func (s *Store) RevokeKey(ctx context.Context, identityID, keyID uuid.UUID) (*Key, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// 撤销事实（ACTIVE|RETIRED → REVOKED；已 REVOKED/不存在精确区分）
	k, err := scanKey(tx.QueryRow(ctx, `UPDATE machine_identity_keys SET
		status='REVOKED', updated_at=now()
		WHERE id=$1 AND identity_id=$2 AND status IN ('ACTIVE','RETIRED')
		RETURNING `+keyCols, keyID, identityID))
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if qerr := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM machine_identity_keys WHERE id=$1 AND identity_id=$2)`,
			keyID, identityID).Scan(&exists); qerr != nil {
			return nil, qerr
		}
		if !exists {
			return nil, ErrKeyNotFound
		}
		return nil, ErrKeyStateConflict
	}
	if err != nil {
		return nil, err
	}
	// 水位推进（同事务；只增 upsert）并回填 revoked_seq（溯源）
	var seq int64
	if err := tx.QueryRow(ctx, `
INSERT INTO machine_identity_revocation_watermark (id, seq) VALUES (1, 1)
ON CONFLICT (id) DO UPDATE SET seq = machine_identity_revocation_watermark.seq + 1
RETURNING seq`).Scan(&seq); err != nil {
		return nil, fmt.Errorf("bump machine identity revocation watermark: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE machine_identity_keys SET revoked_seq=$3 WHERE id=$1 AND identity_id=$2`,
		keyID, identityID, seq); err != nil {
		return nil, err
	}
	k.RevokedSeq = &seq
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &k, nil
}

// ---------- 绑定 ----------

const bindingCols = `id, application_id, COALESCE(path_exact,''), COALESCE(path_prefix,''), mode, proof_required, version, COALESCE(created_by,''), created_at, updated_at`

func scanBinding(row pgx.Row) (Binding, error) {
	var b Binding
	err := row.Scan(&b.ID, &b.ApplicationID, &b.PathExact, &b.PathPrefix, &b.Mode,
		&b.ProofRequired, &b.Version, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt)
	return b, err
}

// CreateBinding 新建绑定（同（应用,path）409；应用不存在 400；mode 缺省 OBSERVE）。
// 注（§1.1）：G1 排除存在路径改写（rewrite）的路由——当前管理面数据模型无 per-app
// 路径改写规则实体（唯一 rewrite 为静态资源 strip_path_prefix，非应用路由），无从
// 校验即不编造；改写规则落地后本保存路径须增补冲突拒存。
func (s *Store) CreateBinding(ctx context.Context, in BindingInput, createdBy string) (*Binding, error) {
	mode := orDefault(strings.ToUpper(strings.TrimSpace(in.Mode)), ModeObserve)
	appID, _ := uuid.Parse(strings.TrimSpace(in.ApplicationID))
	b, err := scanBinding(s.db.QueryRow(ctx, `INSERT INTO machine_identity_bindings
		(application_id, path_exact, path_prefix, mode, proof_required, created_by)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING `+bindingCols,
		appID, nilIfEmpty(strings.TrimSpace(in.PathExact)), nilIfEmpty(strings.TrimSpace(in.PathPrefix)),
		mode, in.ProofRequired, createdBy))
	if isUniqueViolation(err) {
		return nil, ErrBindingDuplicate
	}
	if isAppFKViolation(err) {
		return nil, ErrAppNotFound
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// ListBindings 绑定列表（application_id 可选过滤；应用+路径稳定序）。
func (s *Store) ListBindings(ctx context.Context, applicationID uuid.UUID) ([]Binding, error) {
	cond, args := "", []any{}
	if applicationID != uuid.Nil {
		args = append(args, applicationID)
		cond = " WHERE application_id = $1"
	}
	rows, err := s.db.Query(ctx, `SELECT `+bindingCols+` FROM machine_identity_bindings`+cond+
		` ORDER BY application_id, COALESCE(path_exact, path_prefix)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Binding{}
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// UpdateBinding 改 mode/proof_required（乐观锁 409；应用/路径为身份维度不可改——改即删建）。
func (s *Store) UpdateBinding(ctx context.Context, id uuid.UUID, in BindingInput) (*Binding, error) {
	mode := orDefault(strings.ToUpper(strings.TrimSpace(in.Mode)), ModeObserve)
	b, err := scanBinding(s.db.QueryRow(ctx, `UPDATE machine_identity_bindings SET mode=$2, proof_required=$3,
		version=version+1, updated_at=now() WHERE id=$1 AND version=$4 RETURNING `+bindingCols,
		id, mode, in.ProofRequired, in.Version))
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if qerr := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM machine_identity_bindings WHERE id=$1)`, id).Scan(&exists); qerr != nil {
			return nil, qerr
		}
		if !exists {
			return nil, ErrBindingNotFound
		}
		return nil, ErrVersionConflict
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// DeleteBinding 解绑（不存在 404）。
func (s *Store) DeleteBinding(ctx context.Context, id uuid.UUID) error {
	ct, err := s.db.Exec(ctx, `DELETE FROM machine_identity_bindings WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrBindingNotFound
	}
	return nil
}

// ---------- 内部 ----------

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func nilIfEmpty(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
