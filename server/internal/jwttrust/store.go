// store.go JWT 信任策略仓储（jwt_trust_policies 草稿行 + jwt_trust_policy_versions
// 不可变版本记录，迁移 000125）。读取侧同时供管理面接口与 guardconfig 发布下发——
// ListForGuard 实现 guardconfig.JWTTrustLister 接口（Go 隐式接口，无反向导入；
// 跨分片契约类型见 gatewayconfig.GuardJWTTrustPolicy）。
package jwttrust

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// ErrNotFound 策略草稿不存在（应用从未配置——按默认 OFF 空策略处理）。
var ErrNotFound = errors.New("jwt trust policy not found")

// ErrConflict 乐观锁冲突（expected_version 与当前版本不匹配：并发修改，需刷新后重试）。
var ErrConflict = errors.New("jwt trust policy version conflict")

// Store 是 JWT 信任策略仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// policyColumns 查询列清单（与 scanPolicy 顺序一致）。
const policyColumns = `id, application_id, mode, version, selectors, issuers, updated_by, created_at, updated_at`

// scanPolicy 扫描一行策略（JSONB 列经 []byte 中转反序列化）。
func scanPolicy(row pgx.Row) (*Policy, error) {
	var p Policy
	var selectors, issuers []byte
	var updatedBy *string
	err := row.Scan(&p.ID, &p.ApplicationID, &p.Mode, &p.Version,
		&selectors, &issuers, &updatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if updatedBy != nil {
		p.UpdatedBy = *updatedBy
	}
	p.Selectors = []Selector{}
	p.Issuers = []Issuer{}
	if err := json.Unmarshal(selectors, &p.Selectors); err != nil {
		return nil, fmt.Errorf("decode selectors: %w", err)
	}
	if err := json.Unmarshal(issuers, &p.Issuers); err != nil {
		return nil, fmt.Errorf("decode issuers: %w", err)
	}
	return &p, nil
}

// GetByApp 读取应用当前草稿策略；无记录返回 ErrNotFound（调用方映射为默认 OFF 策略）。
func (s *Store) GetByApp(ctx context.Context, appID uuid.UUID) (*Policy, error) {
	row := s.db.QueryRow(ctx, `SELECT `+policyColumns+` FROM jwt_trust_policies WHERE application_id = $1`, appID)
	return scanPolicy(row)
}

// SaveDraft 校验并保存草稿（乐观锁 + 同事务追加不可变版本记录）：
//   - 应用已有草稿：expected_version 须等于当前 version，更新后 version+1；
//   - 应用无草稿：expected_version 须为 0，创建 version=1 首版；
//   - 版本不匹配返回 ErrConflict（409）。
//
// reason 非空（变更理由，随版本记录留存并进入操作审计）。
func (s *Store) SaveDraft(ctx context.Context, p *Policy, expectedVersion int, reason, updatedBy string) error {
	if errs := ValidateStructure(p); len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	if reason == "" {
		return &ValidationError{Errors: []FieldError{{Field: "reason", Message: "变更理由不能为空"}}}
	}
	selectors, err := json.Marshal(p.Selectors)
	if err != nil {
		return err
	}
	issuers, err := json.Marshal(p.Issuers)
	if err != nil {
		return err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var newVersion int
	if expectedVersion == 0 {
		// 首版创建：并发首建由 application_id UNIQUE 兜底为冲突
		err = tx.QueryRow(ctx, `
INSERT INTO jwt_trust_policies (application_id, mode, version, selectors, issuers, updated_by)
VALUES ($1, $2, 1, $3::jsonb, $4::jsonb, $5)
RETURNING id, version`, p.ApplicationID, p.Mode, string(selectors), string(issuers), updatedBy).
			Scan(&p.ID, &newVersion)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
	} else {
		err = tx.QueryRow(ctx, `
UPDATE jwt_trust_policies SET mode=$1, selectors=$2::jsonb, issuers=$3::jsonb,
  updated_by=$4, updated_at=now(), version=version+1
WHERE application_id=$5 AND version=$6
RETURNING id, version`, p.Mode, string(selectors), string(issuers), updatedBy,
			p.ApplicationID, expectedVersion).Scan(&p.ID, &newVersion)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrConflict
			}
			return err
		}
	}

	// 不可变版本记录（同版本唯一由 UNIQUE(application_id, version) 兜底）
	if _, err := tx.Exec(ctx, `
INSERT INTO jwt_trust_policy_versions (application_id, version, mode, selectors, issuers, reason, created_by)
VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7)`,
		p.ApplicationID, newVersion, p.Mode, string(selectors), string(issuers), reason, updatedBy); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	p.Version = newVersion
	p.UpdatedBy = updatedBy
	return nil
}

// isUniqueViolation 判定唯一约束冲突（pgcode 23505，不引入 pgconn 类型断言以外的依赖）。
func isUniqueViolation(err error) bool {
	var iface interface{ SQLState() string }
	if errors.As(err, &iface) {
		return iface.SQLState() == "23505"
	}
	return false
}

// PublishedVersion 读取最近 SUCCESS 访问控制发布快照中本应用的 JWT 策略版本
// （0 = 未随发布下发或从未发布；发布整站快照含 GuardConfig.jwt_trust 段，
// 回滚发布产生新的 SUCCESS 快照，故最新 SUCCESS 即当前生效集合）。
func (s *Store) PublishedVersion(ctx context.Context, appCode string) (int, error) {
	var raw []byte
	err := s.db.QueryRow(ctx, `
SELECT config FROM access_control_versions
WHERE publish_result = 'SUCCESS'
ORDER BY version_no DESC LIMIT 1`).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	var cfg struct {
		JWTTrust map[string]struct {
			Version int `json:"version"`
		} `json:"jwt_trust"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return 0, fmt.Errorf("decode published guard config: %w", err)
	}
	if pol, ok := cfg.JWTTrust[appCode]; ok {
		return pol.Version, nil
	}
	return 0, nil
}

// ListForGuard 读取全部应用策略并映射为网关下发契约（guardconfig 发布通道注入用；
// key 为应用编码。OFF 策略同样下发——网关按 mode 关闭校验，同时覆盖旧配置中
// 可能残留的同名应用策略，避免「管理面已关、网关仍在校验」）。
func (s *Store) ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardJWTTrustPolicy, error) {
	rows, err := s.db.Query(ctx, `
SELECT p.application_id, a.code, p.mode, p.version, p.selectors, p.issuers
FROM jwt_trust_policies p
JOIN applications a ON a.id = p.application_id
WHERE a.deleted_at IS NULL
ORDER BY a.code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*gatewayconfig.GuardJWTTrustPolicy{}
	for rows.Next() {
		var (
			appID              uuid.UUID
			code, mode         string
			version            int
			selectors, issuers []byte
		)
		if err := rows.Scan(&appID, &code, &mode, &version, &selectors, &issuers); err != nil {
			return nil, err
		}
		var sel []Selector
		var iss []Issuer
		if err := json.Unmarshal(selectors, &sel); err != nil {
			return nil, fmt.Errorf("decode selectors for %s: %w", code, err)
		}
		if err := json.Unmarshal(issuers, &iss); err != nil {
			return nil, fmt.Errorf("decode issuers for %s: %w", code, err)
		}
		gp := &gatewayconfig.GuardJWTTrustPolicy{
			SchemaVersion: SchemaVersion,
			ApplicationID: appID.String(),
			Mode:          mode,
			Version:       version,
			Selectors:     make([]gatewayconfig.GuardJWTSelector, 0, len(sel)),
			Issuers:       make([]gatewayconfig.GuardJWTIssuer, 0, len(iss)),
		}
		for _, s2 := range sel {
			gp.Selectors = append(gp.Selectors, gatewayconfig.GuardJWTSelector{
				Methods:       s2.Methods,
				PathExact:     s2.PathExact,
				PathPrefix:    s2.PathPrefix,
				TokenRequired: s2.TokenRequired,
			})
		}
		for _, is2 := range iss {
			gi := gatewayconfig.GuardJWTIssuer{
				IssuerConfigID:   IssuerConfigID(appID, is2.Issuer),
				Issuer:           is2.Issuer,
				Audiences:        is2.Audiences,
				Algorithms:       is2.Algorithms,
				ClockSkewSeconds: is2.ClockSkewSeconds,
				TenantClaim:      is2.TenantClaim,
				KeySourceType:    is2.KeySource.Type,
			}
			switch is2.KeySource.Type {
			case KeySourceStaticJWKS:
				// 静态公钥是公钥可以下发（无任何秘密材料）
				gi.JWKS = json.RawMessage(is2.KeySource.JWKS)
				v, err := KeysetVersion(is2.KeySource.JWKS)
				if err != nil {
					return nil, fmt.Errorf("compute keyset version for %s: %w", code, err)
				}
				gi.KeysetVersion = v
			case KeySourceRemoteJWKS:
				gi.RemoteURL = is2.KeySource.URL
			}
			gp.Issuers = append(gp.Issuers, gi)
		}
		out[code] = gp
	}
	return out, rows.Err()
}

// IssuerConfigID 生成稳定的 issuer 配置标识（应用 + issuer 精确值派生；
// 跨发布稳定，供 VerificationResult.issuer_config_id 溯源）。
func IssuerConfigID(appID uuid.UUID, issuer string) string {
	sum := sha256.Sum256([]byte(appID.String() + "\x00" + issuer))
	return "jwtiss_" + hex.EncodeToString(sum[:8])
}
