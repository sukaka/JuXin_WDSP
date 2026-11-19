package certificates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/encryption"
)

// 证书错误
var (
	ErrNotFound       = errors.New("certificate not found")
	ErrNameExists     = errors.New("certificate name already exists")
	ErrInUse          = errors.New("certificate is in use by applications")
	ErrDomainMismatch = errors.New("certificate does not match application domains")
)

// Certificate 是证书记录（不含明文私钥）。
type Certificate struct {
	ID                 uuid.UUID       `json:"id"`
	Name               string          `json:"name"`
	CertificateType    string          `json:"certificate_type"`
	CommonName         string          `json:"common_name"`
	Subject            string          `json:"subject"`
	Issuer             string          `json:"issuer"`
	SerialNumber       string          `json:"serial_number"`
	NotBefore          *time.Time      `json:"not_before"`
	NotAfter           *time.Time      `json:"not_after"`
	FingerprintSHA256  string          `json:"fingerprint_sha256"`
	PublicKeyAlgorithm string          `json:"public_key_algorithm"`
	PublicKeyBits      int             `json:"public_key_bits"`
	SignatureAlgorithm string          `json:"signature_algorithm"`
	SANDomains         json.RawMessage `json:"san_domains"`
	Status             string          `json:"status"`
	CreatedBy          *uuid.UUID      `json:"created_by,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
	Version            int             `json:"version"`
	// 以下字段不对外返回明文（仅内部使用）
	certPEM      string
	encryptedKey string
	chainPEM     string
}

// Store 是证书仓储。
type Store struct {
	db  *pgxpool.Pool
	enc *encryption.Service
}

// NewStore 创建证书仓储。
func NewStore(db *pgxpool.Pool, enc *encryption.Service) *Store {
	return &Store{db: db, enc: enc}
}

const certColumns = `id, name, certificate_type, common_name, subject, issuer, serial_number,
not_before, not_after, fingerprint_sha256, public_key_algorithm, public_key_bits,
signature_algorithm, san_domains, status, certificate_reference, encrypted_private_key_reference,
chain_reference, created_by, created_at, updated_at, version`

// certColumnsC 是 certColumns 的 c 别名限定版本，用于与 application_certificates
// JOIN 的查询（两表存在 id/created_by/created_at/updated_at 同名列，不限定会歧义）。
const certColumnsC = `c.id, c.name, c.certificate_type, c.common_name, c.subject, c.issuer, c.serial_number,
c.not_before, c.not_after, c.fingerprint_sha256, c.public_key_algorithm, c.public_key_bits,
c.signature_algorithm, c.san_domains, c.status, c.certificate_reference, c.encrypted_private_key_reference,
c.chain_reference, c.created_by, c.created_at, c.updated_at, c.version`

func (s *Store) scanCert(row pgx.Row) (*Certificate, error) {
	var c Certificate
	err := row.Scan(&c.ID, &c.Name, &c.CertificateType, &c.CommonName, &c.Subject, &c.Issuer,
		&c.SerialNumber, &c.NotBefore, &c.NotAfter, &c.FingerprintSHA256, &c.PublicKeyAlgorithm,
		&c.PublicKeyBits, &c.SignatureAlgorithm, &c.SANDomains, &c.Status,
		&c.certPEM, &c.encryptedKey, &c.chainPEM, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &c.Version)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// UploadInput 是证书上传输入。
type UploadInput struct {
	Name      string
	CertPEM   string
	KeyPEM    string
	ChainPEM  string
	CreatedBy uuid.UUID
}

// Upload 上传证书（解析、校验、加密存储私钥）。
func (s *Store) Upload(ctx context.Context, in UploadInput) (*Certificate, error) {
	if in.Name == "" || len(in.Name) > 128 {
		return nil, fmt.Errorf("证书名称不能为空且不超过128字符")
	}
	// 大小限制
	const maxPEMSize = 64 * 1024
	if len(in.CertPEM) > maxPEMSize || len(in.KeyPEM) > maxPEMSize || len(in.ChainPEM) > maxPEMSize*2 {
		return nil, fmt.Errorf("证书或私钥文件过大")
	}

	// 解析证书
	cert, parsed, err := ParseCertificatePEM(in.CertPEM)
	if err != nil {
		return nil, err
	}
	// 证书链非空时严格校验 PEM 与 X.509 结构
	if strings.TrimSpace(in.ChainPEM) != "" {
		if _, _, err := ParseCertificateChainPEM(in.ChainPEM); err != nil {
			return nil, fmt.Errorf("证书链无效: %w", err)
		}
	}
	// 密钥强度
	if err := ValidateKeyStrength(parsed); err != nil {
		return nil, err
	}
	// 私钥匹配
	if err := ValidatePrivateKeyPEM(in.KeyPEM, cert); err != nil {
		return nil, err
	}
	// 有效期
	if err := ValidateCertValidity(cert, time.Now()); err != nil {
		return nil, err
	}
	if s.enc == nil {
		return nil, fmt.Errorf("加密服务未配置，无法安全存储私钥")
	}
	// 重复证书（指纹）
	var existingID uuid.UUID
	err = s.db.QueryRow(ctx,
		`SELECT id FROM certificates WHERE fingerprint_sha256 = $1 AND deleted_at IS NULL`,
		parsed.FingerprintSHA256).Scan(&existingID)
	if err == nil {
		return nil, fmt.Errorf("证书已存在（相同指纹）")
	}
	// 重复名称
	err = s.db.QueryRow(ctx,
		`SELECT id FROM certificates WHERE name = $1 AND deleted_at IS NULL`, in.Name).Scan(&existingID)
	if err == nil {
		return nil, ErrNameExists
	}

	// 加密私钥
	encKey, err := s.enc.Encrypt(in.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("加密私钥失败: %w", err)
	}

	status := CertStatus(parsed.NotAfter, time.Now())
	sanJSON, _ := json.Marshal(parsed.SANDomains)

	c := &Certificate{
		Name:               in.Name,
		CertificateType:    "SERVER",
		CommonName:         parsed.CommonName,
		Subject:            parsed.Subject,
		Issuer:             parsed.Issuer,
		SerialNumber:       parsed.SerialNumber,
		NotBefore:          &parsed.NotBefore,
		NotAfter:           &parsed.NotAfter,
		FingerprintSHA256:  parsed.FingerprintSHA256,
		PublicKeyAlgorithm: parsed.PublicKeyAlgorithm,
		PublicKeyBits:      parsed.PublicKeyBits,
		SignatureAlgorithm: parsed.SignatureAlgorithm,
		SANDomains:         sanJSON,
		Status:             status,
		certPEM:            in.CertPEM,
		encryptedKey:       encKey,
		chainPEM:           in.ChainPEM,
		CreatedBy:          &in.CreatedBy,
	}
	err = s.db.QueryRow(ctx, `
INSERT INTO certificates (name, certificate_type, common_name, subject, issuer, serial_number,
  not_before, not_after, fingerprint_sha256, public_key_algorithm, public_key_bits,
  signature_algorithm, san_domains, status, certificate_reference, encrypted_private_key_reference,
  chain_reference, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
RETURNING id, created_at, updated_at, version`,
		c.Name, c.CertificateType, c.CommonName, c.Subject, c.Issuer, c.SerialNumber,
		c.NotBefore, c.NotAfter, c.FingerprintSHA256, c.PublicKeyAlgorithm, c.PublicKeyBits,
		c.SignatureAlgorithm, c.SANDomains, c.Status, c.certPEM, c.encryptedKey, c.chainPEM, c.CreatedBy,
	).Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt, &c.Version)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// GetByID 查询证书（不含明文私钥）。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Certificate, error) {
	row := s.db.QueryRow(ctx,
		`SELECT `+certColumns+` FROM certificates WHERE id = $1 AND deleted_at IS NULL`, id)
	c, err := s.scanCert(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return c, nil
}

// List 分页查询证书。
func (s *Store) List(ctx context.Context, name, status string, page, pageSize int) ([]Certificate, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	where := "deleted_at IS NULL"
	args := []interface{}{}
	argIdx := 1
	if name != "" {
		where += fmt.Sprintf(" AND (name ILIKE $%d OR common_name ILIKE $%d)", argIdx, argIdx)
		args = append(args, "%"+name+"%")
		argIdx++
	}
	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + certColumns + ` FROM certificates WHERE ` + where +
		fmt.Sprintf(" ORDER BY not_after ASC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		var c Certificate
		if err := rows.Scan(&c.ID, &c.Name, &c.CertificateType, &c.CommonName, &c.Subject, &c.Issuer,
			&c.SerialNumber, &c.NotBefore, &c.NotAfter, &c.FingerprintSHA256, &c.PublicKeyAlgorithm,
			&c.PublicKeyBits, &c.SignatureAlgorithm, &c.SANDomains, &c.Status,
			&c.certPEM, &c.encryptedKey, &c.chainPEM, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &c.Version); err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// Update 更新证书名称。
func (s *Store) Update(ctx context.Context, id uuid.UUID, name string, expectedVersion int) error {
	res, err := s.db.Exec(ctx, `
UPDATE certificates SET name = $1, updated_at = now(), version = version + 1
WHERE id = $2 AND version = $3 AND deleted_at IS NULL`, name, id, expectedVersion)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete 删除证书（事务内锁定证书行并校验活动绑定，使用中的证书禁止删除）。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var lockedID uuid.UUID
	if err := tx.QueryRow(ctx,
		`SELECT id FROM certificates WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, id).Scan(&lockedID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	// 检查是否被应用活动使用
	var useCount int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM application_certificates WHERE certificate_id = $1 AND is_active = TRUE`, id).Scan(&useCount); err != nil {
		return err
	}
	if useCount > 0 {
		return ErrInUse
	}
	res, err := tx.Exec(ctx,
		`UPDATE certificates SET deleted_at = now(), updated_at = now(), version = version + 1 WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

// CountUsage 查询证书当前活动绑定的应用数。
func (s *Store) CountUsage(ctx context.Context, id uuid.UUID) (int, error) {
	var n int
	err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM application_certificates WHERE certificate_id = $1 AND is_active = TRUE`, id).Scan(&n)
	return n, err
}

// GetCertPEM 获取证书 PEM（发布用，内部）。
func (s *Store) GetCertPEM(ctx context.Context, id uuid.UUID) (certPEM, chainPEM string, err error) {
	c, err := s.GetByID(ctx, id)
	if err != nil {
		return "", "", err
	}
	return c.certPEM, c.chainPEM, nil
}

// GetDecryptedKey 解密获取私钥（仅供配置发布内部使用）。
func (s *Store) GetDecryptedKey(ctx context.Context, id uuid.UUID) (string, error) {
	if s.enc == nil {
		return "", fmt.Errorf("加密服务未配置")
	}
	c, err := s.GetByID(ctx, id)
	if err != nil {
		return "", err
	}
	return s.enc.Decrypt(c.encryptedKey)
}

// BindApplication 绑定证书到应用（校验域名匹配）。
func (s *Store) BindApplication(ctx context.Context, appID, certID, operatorID uuid.UUID, appDomains []string) error {
	c, err := s.GetByID(ctx, certID)
	if err != nil {
		return err
	}
	// 域名匹配校验
	parsed := &ParsedCertificate{
		CommonName: c.CommonName,
	}
	var sans []string
	_ = json.Unmarshal(c.SANDomains, &sans)
	parsed.SANDomains = sans
	unmatched := MatchDomains(parsed, appDomains)
	if len(unmatched) > 0 {
		return fmt.Errorf("%w: %v", ErrDomainMismatch, unmatched)
	}
	// 证书有效性
	if c.NotAfter != nil && time.Now().After(*c.NotAfter) {
		return ErrCertExpired
	}

	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// 共享锁防止并发软删该证书
	var lockedID uuid.UUID
	if err := tx.QueryRow(ctx,
		`SELECT id FROM certificates WHERE id = $1 AND deleted_at IS NULL FOR SHARE`, certID).Scan(&lockedID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	// 一个应用仅一个活动证书：先将旧证书设为非活动
	if _, err := tx.Exec(ctx,
		`UPDATE application_certificates SET is_active = FALSE, updated_at = now() WHERE application_id = $1`, appID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO application_certificates (application_id, certificate_id, is_active, created_by)
VALUES ($1, $2, TRUE, $3)
ON CONFLICT (application_id, certificate_id)
DO UPDATE SET is_active = TRUE, updated_at = now()`, appID, certID, operatorID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// UnbindApplication 解绑应用证书（解绑该应用的所有证书绑定）。
func (s *Store) UnbindApplication(ctx context.Context, appID uuid.UUID) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM application_certificates WHERE application_id = $1`, appID)
	return err
}

// UnbindCertificate 仅解绑指定应用与指定证书的绑定关系。
func (s *Store) UnbindCertificate(ctx context.Context, appID, certID uuid.UUID) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM application_certificates WHERE application_id = $1 AND certificate_id = $2`, appID, certID)
	return err
}

// GetApplicationCertificate 查询应用当前活动证书。
func (s *Store) GetApplicationCertificate(ctx context.Context, appID uuid.UUID) (*Certificate, error) {
	row := s.db.QueryRow(ctx, `
SELECT `+certColumnsC+` FROM certificates c
JOIN application_certificates ac ON ac.certificate_id = c.id
WHERE ac.application_id = $1 AND ac.is_active = TRUE AND c.deleted_at IS NULL`, appID)
	c, err := s.scanCert(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // 无绑定证书
		}
		return nil, err
	}
	return c, nil
}

// ListApplicationIDs 查询证书绑定的应用ID列表。
func (s *Store) ListApplicationIDs(ctx context.Context, certID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.db.Query(ctx,
		`SELECT application_id FROM application_certificates WHERE certificate_id = $1 AND is_active = TRUE`, certID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RefreshStatus 刷新证书状态（定时任务用）。
func (s *Store) RefreshStatus(ctx context.Context) (int, error) {
	res, err := s.db.Exec(ctx, `
UPDATE certificates SET status = CASE
  WHEN not_after < now() THEN 'EXPIRED'
  WHEN not_after < now() + interval '30 days' THEN 'EXPIRING'
  ELSE 'VALID'
END, updated_at = now()
WHERE deleted_at IS NULL AND status <> 'INVALID'`)
	if err != nil {
		return 0, err
	}
	return int(res.RowsAffected()), nil
}
