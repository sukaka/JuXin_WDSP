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
	ID                    uuid.UUID       `json:"id"`
	Name                  string          `json:"name"`
	CertificateType       string          `json:"certificate_type"`
	ProtocolType          string          `json:"protocol_type"`
	CommonName            string          `json:"common_name"`
	Subject               string          `json:"subject"`
	Issuer                string          `json:"issuer"`
	SerialNumber          string          `json:"serial_number"`
	NotBefore             *time.Time      `json:"not_before"`
	NotAfter              *time.Time      `json:"not_after"`
	FingerprintSHA256     string          `json:"fingerprint_sha256"`
	PublicKeyAlgorithm    string          `json:"public_key_algorithm"`
	PublicKeyBits         int             `json:"public_key_bits"`
	SignatureAlgorithm    string          `json:"signature_algorithm"`
	SANDomains            json.RawMessage `json:"san_domains"`
	// 国密加密证书元数据（SM_TLCP 专用；国际证书为空）
	EncCommonName        string     `json:"enc_common_name,omitempty"`
	EncSubject           string     `json:"enc_subject,omitempty"`
	EncIssuer            string     `json:"enc_issuer,omitempty"`
	EncSerialNumber      string     `json:"enc_serial_number,omitempty"`
	EncNotBefore         *time.Time `json:"enc_not_before,omitempty"`
	EncNotAfter          *time.Time `json:"enc_not_after,omitempty"`
	EncFingerprintSHA256 string     `json:"enc_fingerprint_sha256,omitempty"`
	Status               string     `json:"status"`
	ManagedBy            string     `json:"managed_by"`
	ACMEProvider         string     `json:"acme_provider"`
	ACMEDirectoryURL     string     `json:"acme_directory_url"`
	ACMEAccountID        *uuid.UUID `json:"acme_account_id,omitempty"`
	AutoRenew            bool       `json:"auto_renew"`
	RenewBeforeDays      int        `json:"renew_before_days"`
	ReplacesCertificateID *uuid.UUID `json:"replaces_certificate_id,omitempty"`
	SupersededBy          *uuid.UUID `json:"superseded_by,omitempty"`
	LastRenewedAt         *time.Time `json:"last_renewed_at,omitempty"`
	CreatedBy             *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
	Version               int        `json:"version"`
	// 以下字段不对外返回明文（仅内部使用）
	certPEM         string
	encryptedKey    string
	chainPEM        string
	encCertPEM      string
	encryptedEncKey string
}

// ApplicationCertificateBindings 应用的双槽位活动证书视图（通用国际证书 + 国密双证书）。
type ApplicationCertificateBindings struct {
	International *Certificate `json:"international"`
	GM            *Certificate `json:"gm"`
}

// GMCertMaterial 国密双证书解密材料（仅配置发布内部内存流转，绝不入审计或日志）。
type GMCertMaterial struct {
	SignCertPEM string
	SignKeyPEM  string
	EncCertPEM  string
	EncKeyPEM   string
	ChainPEM    string
}

// EffectiveProtocolType 返回规范化后的协议类型（历史空串视为 INTERNATIONAL）。
func (c *Certificate) EffectiveProtocolType() string {
	if c == nil || c.ProtocolType == "" {
		return ProtocolInternational
	}
	return c.ProtocolType
}

// EffectiveNotAfter 返回证书生效到期时间（国密双证取签名证与加密证中较早者）。
func (c *Certificate) EffectiveNotAfter() *time.Time {
	if c == nil {
		return nil
	}
	if c.EncNotAfter != nil && (c.NotAfter == nil || c.EncNotAfter.Before(*c.NotAfter)) {
		return c.EncNotAfter
	}
	return c.NotAfter
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

const certColumns = `id, name, certificate_type, protocol_type, common_name, subject, issuer, serial_number,
not_before, not_after, fingerprint_sha256, public_key_algorithm, public_key_bits,
signature_algorithm, san_domains, enc_common_name, enc_subject, enc_issuer, enc_serial_number,
enc_not_before, enc_not_after, enc_fingerprint_sha256, status, managed_by, acme_provider, acme_directory_url,
acme_account_id, auto_renew, renew_before_days, replaces_certificate_id, superseded_by,
last_renewed_at, certificate_reference, encrypted_private_key_reference,
chain_reference, enc_certificate_reference, encrypted_enc_private_key_reference,
created_by, created_at, updated_at, version`

// certColumnsC 是 certColumns 的 c 别名限定版本，用于与 application_certificates
// JOIN 的查询（两表存在 id/created_by/created_at/updated_at 同名列，不限定会歧义）。
const certColumnsC = `c.id, c.name, c.certificate_type, c.protocol_type, c.common_name, c.subject, c.issuer, c.serial_number,
c.not_before, c.not_after, c.fingerprint_sha256, c.public_key_algorithm, c.public_key_bits,
c.signature_algorithm, c.san_domains, c.enc_common_name, c.enc_subject, c.enc_issuer, c.enc_serial_number,
c.enc_not_before, c.enc_not_after, c.enc_fingerprint_sha256, c.status, c.managed_by, c.acme_provider, c.acme_directory_url,
c.acme_account_id, c.auto_renew, c.renew_before_days, c.replaces_certificate_id, c.superseded_by,
c.last_renewed_at, c.certificate_reference, c.encrypted_private_key_reference,
c.chain_reference, c.enc_certificate_reference, c.encrypted_enc_private_key_reference,
c.created_by, c.created_at, c.updated_at, c.version`

func (s *Store) scanCert(row pgx.Row) (*Certificate, error) {
	var c Certificate
	err := row.Scan(&c.ID, &c.Name, &c.CertificateType, &c.ProtocolType, &c.CommonName, &c.Subject, &c.Issuer,
		&c.SerialNumber, &c.NotBefore, &c.NotAfter, &c.FingerprintSHA256, &c.PublicKeyAlgorithm,
		&c.PublicKeyBits, &c.SignatureAlgorithm, &c.SANDomains,
		&c.EncCommonName, &c.EncSubject, &c.EncIssuer, &c.EncSerialNumber,
		&c.EncNotBefore, &c.EncNotAfter, &c.EncFingerprintSHA256, &c.Status,
		&c.ManagedBy, &c.ACMEProvider, &c.ACMEDirectoryURL, &c.ACMEAccountID,
		&c.AutoRenew, &c.RenewBeforeDays, &c.ReplacesCertificateID, &c.SupersededBy, &c.LastRenewedAt,
		&c.certPEM, &c.encryptedKey, &c.chainPEM, &c.encCertPEM, &c.encryptedEncKey,
		&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &c.Version)
	if err != nil {
		return nil, err
	}
	if c.ProtocolType == "" {
		c.ProtocolType = ProtocolInternational
	}
	return &c, nil
}

// UploadInput 是证书上传输入（INTERNATIONAL 单证或 SM_TLCP 国密签名+加密双证）。
type UploadInput struct {
	Name         string
	ProtocolType string // 缺省 INTERNATIONAL；国密为 SM_TLCP
	CertPEM      string // 国际证书 PEM 或国密签名证书 PEM
	KeyPEM       string // 国际私钥 PEM 或国密签名私钥 PEM
	EncCertPEM   string // 国密加密证书 PEM（SM_TLCP 必填）
	EncKeyPEM    string // 国密加密私钥 PEM（SM_TLCP 必填）
	ChainPEM     string
	CreatedBy    uuid.UUID
}

// Upload 上传证书（解析、校验、加密存储私钥；支持国际通用单证与国密 SM_TLCP 双证）。
func (s *Store) Upload(ctx context.Context, in UploadInput) (*Certificate, error) {
	if in.Name == "" || len(in.Name) > 128 {
		return nil, fmt.Errorf("证书名称不能为空且不超过128字符")
	}
	protoType, err := NormalizeProtocolType(in.ProtocolType)
	if err != nil {
		return nil, fmt.Errorf("证书协议类型无效，仅支持 INTERNATIONAL 或 SM_TLCP")
	}
	// 大小限制
	const maxPEMSize = 64 * 1024
	if len(in.CertPEM) > maxPEMSize || len(in.KeyPEM) > maxPEMSize ||
		len(in.EncCertPEM) > maxPEMSize || len(in.EncKeyPEM) > maxPEMSize ||
		len(in.ChainPEM) > maxPEMSize*2 {
		return nil, fmt.Errorf("证书或私钥文件过大")
	}

	now := time.Now()
	var (
		parsed          *ParsedCertificate
		encParsed       *ParsedCertificate
		encKey          string
		encEncKey       string
		effectiveExpiry time.Time
	)

	if protoType == ProtocolSMTLCP {
		gmDual, err := ParseAndValidateGMDualCert(in.CertPEM, in.KeyPEM, in.EncCertPEM, in.EncKeyPEM, in.ChainPEM, now)
		if err != nil {
			return nil, err
		}
		if s.enc == nil {
			return nil, fmt.Errorf("加密服务未配置，无法安全存储私钥")
		}
		parsed = gmDual.SignParsed
		encParsed = gmDual.EncParsed
		effectiveExpiry = gmDual.EffectiveNotAfter()

		encKey, err = s.enc.Encrypt(in.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("加密签名私钥失败: %w", err)
		}
		encEncKey, err = s.enc.Encrypt(in.EncKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("加密加密私钥失败: %w", err)
		}
	} else {
		// 国际通用证书（原有逻辑完整保留）
		cert, p, err := ParseCertificatePEM(in.CertPEM)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(in.ChainPEM) != "" {
			if _, _, err := ParseCertificateChainPEM(in.ChainPEM); err != nil {
				return nil, fmt.Errorf("证书链无效: %w", err)
			}
		}
		if err := ValidateKeyStrength(p); err != nil {
			return nil, err
		}
		if err := ValidatePrivateKeyPEM(in.KeyPEM, cert); err != nil {
			return nil, err
		}
		if err := ValidateCertValidity(cert, now); err != nil {
			return nil, err
		}
		if s.enc == nil {
			return nil, fmt.Errorf("加密服务未配置，无法安全存储私钥")
		}
		encKey, err = s.enc.Encrypt(in.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("加密私钥失败: %w", err)
		}
		parsed = p
		effectiveExpiry = p.NotAfter
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

	status := CertStatus(effectiveExpiry, now)
	sanJSON, _ := json.Marshal(parsed.SANDomains)

	c := &Certificate{
		Name:               in.Name,
		CertificateType:    "SERVER",
		ProtocolType:       protoType,
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
		ManagedBy:          ManagedByManual,
		RenewBeforeDays:    30,
		certPEM:            in.CertPEM,
		encryptedKey:       encKey,
		chainPEM:           in.ChainPEM,
		encCertPEM:         in.EncCertPEM,
		encryptedEncKey:    encEncKey,
		CreatedBy:          &in.CreatedBy,
	}
	if encParsed != nil {
		c.EncCommonName = encParsed.CommonName
		c.EncSubject = encParsed.Subject
		c.EncIssuer = encParsed.Issuer
		c.EncSerialNumber = encParsed.SerialNumber
		c.EncNotBefore = &encParsed.NotBefore
		c.EncNotAfter = &encParsed.NotAfter
		c.EncFingerprintSHA256 = encParsed.FingerprintSHA256
	}
	err = s.db.QueryRow(ctx, `
INSERT INTO certificates (name, certificate_type, protocol_type, common_name, subject, issuer, serial_number,
  not_before, not_after, fingerprint_sha256, public_key_algorithm, public_key_bits,
  signature_algorithm, san_domains, enc_common_name, enc_subject, enc_issuer, enc_serial_number,
  enc_not_before, enc_not_after, enc_fingerprint_sha256, status, certificate_reference,
  encrypted_private_key_reference, chain_reference, enc_certificate_reference,
  encrypted_enc_private_key_reference, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)
RETURNING id, created_at, updated_at, version`,
		c.Name, c.CertificateType, c.ProtocolType, c.CommonName, c.Subject, c.Issuer, c.SerialNumber,
		c.NotBefore, c.NotAfter, c.FingerprintSHA256, c.PublicKeyAlgorithm, c.PublicKeyBits,
		c.SignatureAlgorithm, c.SANDomains, c.EncCommonName, c.EncSubject, c.EncIssuer, c.EncSerialNumber,
		c.EncNotBefore, c.EncNotAfter, c.EncFingerprintSHA256, c.Status, c.certPEM,
		c.encryptedKey, c.chainPEM, c.encCertPEM, c.encryptedEncKey, c.CreatedBy,
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

// ManagedIssueInput 是 ACME 自动申请/续约证书入库并原子绑定的输入。
type ManagedIssueInput struct {
	ApplicationID    uuid.UUID
	AppDomains       []string
	NamePrefix       string
	CertPEM          string
	ChainPEM         string
	KeyPEM           string
	ACMEProvider     string
	ACMEDirectoryURL string
	ACMEAccountID    *uuid.UUID
	AutoRenew        bool
	RenewBeforeDays  int
	OperatorID       *uuid.UUID
}

// CreateManagedAndBind 校验并入库一张新的不可变 ACME 托管证书，并在同一事务中完成：
//  1. 切换 application_certificates 活动绑定指向新证书；
//  2. 若原活动证书同属 ACME 托管且不再被其他应用使用，则置为 REPLACED（保留加密私钥以支持历史版本回滚）。
func (s *Store) CreateManagedAndBind(ctx context.Context, in ManagedIssueInput) (*Certificate, *uuid.UUID, error) {
	if s.enc == nil {
		return nil, nil, fmt.Errorf("加密服务未配置，无法安全存储私钥")
	}
	const maxPEMSize = 64 * 1024
	if len(in.CertPEM) > maxPEMSize || len(in.KeyPEM) > maxPEMSize || len(in.ChainPEM) > maxPEMSize*2 {
		return nil, nil, fmt.Errorf("证书或私钥文件过大")
	}
	cert, parsed, err := ParseCertificatePEM(in.CertPEM)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(in.ChainPEM) != "" {
		if _, _, err := ParseCertificateChainPEM(in.ChainPEM); err != nil {
			return nil, nil, fmt.Errorf("证书链无效: %w", err)
		}
	}
	if err := ValidateKeyStrength(parsed); err != nil {
		return nil, nil, err
	}
	if err := ValidatePrivateKeyPEM(in.KeyPEM, cert); err != nil {
		return nil, nil, err
	}
	if err := ValidateCertValidity(cert, time.Now()); err != nil {
		return nil, nil, err
	}
	if len(in.AppDomains) > 0 {
		if unmatched := MatchDomains(parsed, in.AppDomains); len(unmatched) > 0 {
			return nil, nil, fmt.Errorf("%w: %v", ErrDomainMismatch, unmatched)
		}
	}

	encKey, err := s.enc.Encrypt(in.KeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("加密私钥失败: %w", err)
	}
	renewDays := in.RenewBeforeDays
	if renewDays < 7 || renewDays > 60 {
		renewDays = 30
	}
	now := time.Now().UTC()
	status := CertStatus(parsed.NotAfter, now)
	sanJSON, _ := json.Marshal(parsed.SANDomains)

	baseName := strings.TrimSpace(in.NamePrefix)
	if baseName == "" {
		baseName = parsed.CommonName
	}
	if baseName == "" {
		baseName = "acme-cert"
	}
	suffix := "-" + now.Format("20060102-150405")
	if len(baseName)+len(suffix) > 120 {
		baseName = baseName[:120-len(suffix)]
	}
	certName := baseName + suffix

	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 防名称重名（秒级并发重试时追加短随机后缀）
	var dupID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM certificates WHERE name = $1 AND deleted_at IS NULL`, certName).Scan(&dupID); err == nil {
		certName = certName + "-" + uuid.NewString()[:6]
	}

	// 查出当前国际槽位活动绑定证书（若有）；绝不影响同应用已绑定的 SM_TLCP 国密证书
	var prevID *uuid.UUID
	var prevManagedBy string
	{
		var existingID uuid.UUID
		err := tx.QueryRow(ctx, `
SELECT c.id, c.managed_by
FROM certificates c
JOIN application_certificates ac ON ac.certificate_id = c.id
WHERE ac.application_id = $1 AND ac.cert_slot = $2 AND ac.is_active = TRUE AND c.deleted_at IS NULL
FOR UPDATE OF c`, in.ApplicationID, ProtocolInternational).Scan(&existingID, &prevManagedBy)
		if err == nil {
			prevID = &existingID
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, err
		}
	}

	var lastRenewedAt *time.Time
	if prevID != nil {
		lastRenewedAt = &now
	}

	c := &Certificate{
		Name:                  certName,
		CertificateType:       "SERVER",
		ProtocolType:          ProtocolInternational,
		CommonName:            parsed.CommonName,
		Subject:               parsed.Subject,
		Issuer:                parsed.Issuer,
		SerialNumber:          parsed.SerialNumber,
		NotBefore:             &parsed.NotBefore,
		NotAfter:              &parsed.NotAfter,
		FingerprintSHA256:     parsed.FingerprintSHA256,
		PublicKeyAlgorithm:    parsed.PublicKeyAlgorithm,
		PublicKeyBits:         parsed.PublicKeyBits,
		SignatureAlgorithm:    parsed.SignatureAlgorithm,
		SANDomains:            sanJSON,
		Status:                status,
		ManagedBy:             ManagedByACME,
		ACMEProvider:          in.ACMEProvider,
		ACMEDirectoryURL:      in.ACMEDirectoryURL,
		ACMEAccountID:         in.ACMEAccountID,
		AutoRenew:             in.AutoRenew,
		RenewBeforeDays:       renewDays,
		ReplacesCertificateID: prevID,
		LastRenewedAt:         lastRenewedAt,
		certPEM:               in.CertPEM,
		encryptedKey:          encKey,
		chainPEM:              in.ChainPEM,
		CreatedBy:             in.OperatorID,
	}

	err = tx.QueryRow(ctx, `
INSERT INTO certificates (name, certificate_type, protocol_type, common_name, subject, issuer, serial_number,
  not_before, not_after, fingerprint_sha256, public_key_algorithm, public_key_bits,
  signature_algorithm, san_domains, status, managed_by, acme_provider, acme_directory_url,
  acme_account_id, auto_renew, renew_before_days, replaces_certificate_id, last_renewed_at,
  certificate_reference, encrypted_private_key_reference, chain_reference, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)
RETURNING id, created_at, updated_at, version`,
		c.Name, c.CertificateType, c.ProtocolType, c.CommonName, c.Subject, c.Issuer, c.SerialNumber,
		c.NotBefore, c.NotAfter, c.FingerprintSHA256, c.PublicKeyAlgorithm, c.PublicKeyBits,
		c.SignatureAlgorithm, c.SANDomains, c.Status, c.ManagedBy, c.ACMEProvider, c.ACMEDirectoryURL,
		c.ACMEAccountID, c.AutoRenew, c.RenewBeforeDays, c.ReplacesCertificateID, c.LastRenewedAt,
		c.certPEM, c.encryptedKey, c.chainPEM, c.CreatedBy,
	).Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt, &c.Version)
	if err != nil {
		return nil, nil, err
	}

	// 原子切换应用国际槽位活动绑定（不影响 SM_TLCP 槽位）
	if _, err := tx.Exec(ctx,
		`UPDATE application_certificates SET is_active = FALSE, updated_at = now() WHERE application_id = $1 AND cert_slot = $2`,
		in.ApplicationID, ProtocolInternational); err != nil {
		return nil, nil, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO application_certificates (application_id, certificate_id, cert_slot, is_active, created_by)
VALUES ($1, $2, $3, TRUE, $4)
ON CONFLICT (application_id, certificate_id)
DO UPDATE SET cert_slot = EXCLUDED.cert_slot, is_active = TRUE, updated_at = now()`,
		in.ApplicationID, c.ID, ProtocolInternational, in.OperatorID); err != nil {
		return nil, nil, err
	}

	// 若原证书为 ACME 托管且不再有其他活动应用绑定，则置为 REPLACED（保留行供回滚重注入私钥）
	if prevID != nil && prevManagedBy == ManagedByACME {
		var remain int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM application_certificates WHERE certificate_id = $1 AND is_active = TRUE`, *prevID).Scan(&remain); err != nil {
			return nil, nil, err
		}
		if remain == 0 {
			if _, err := tx.Exec(ctx, `
UPDATE certificates
SET status = $1, auto_renew = FALSE, superseded_by = $2, updated_at = now(), version = version + 1
WHERE id = $3 AND deleted_at IS NULL`, StatusReplaced, c.ID, *prevID); err != nil {
				return nil, nil, err
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	return c, prevID, nil
}

// List 分页查询证书（默认不展示已替换归档的历史续签证书，显式按 status=REPLACED 筛选除外）。
func (s *Store) List(ctx context.Context, name, status string, page, pageSize int) ([]Certificate, int64, error) {
	return s.ListWithOptions(ctx, name, status, status == StatusReplaced, page, pageSize)
}

// ListWithOptions 分页查询证书，支持控制是否包含 REPLACED 历史续签证书。
func (s *Store) ListWithOptions(ctx context.Context, name, status string, includeReplaced bool, page, pageSize int) ([]Certificate, int64, error) {
	return s.ListWithFilter(ctx, name, status, "", includeReplaced, page, pageSize)
}

// ListWithFilter 分页查询证书，支持按 protocol_type（INTERNATIONAL / SM_TLCP）筛选。
func (s *Store) ListWithFilter(ctx context.Context, name, status, protocolType string, includeReplaced bool, page, pageSize int) ([]Certificate, int64, error) {
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
	} else if !includeReplaced {
		where += fmt.Sprintf(" AND status <> $%d", argIdx)
		args = append(args, StatusReplaced)
		argIdx++
	}
	if strings.TrimSpace(protocolType) != "" {
		pt, err := NormalizeProtocolType(protocolType)
		if err != nil {
			return nil, 0, err
		}
		where += fmt.Sprintf(" AND protocol_type = $%d", argIdx)
		args = append(args, pt)
		argIdx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + certColumns + ` FROM certificates WHERE ` + where +
		fmt.Sprintf(" ORDER BY LEAST(not_after, COALESCE(enc_not_after, not_after)) ASC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		c, err := s.scanCert(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *c)
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

// GetDecryptedKey 解密获取私钥（仅供配置发布内部使用；国密证书返回签名私钥）。
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

// GetGMCertMaterial 读取并解密国密双证书完整材料（仅供配置发布与回滚内部使用）。
func (s *Store) GetGMCertMaterial(ctx context.Context, id uuid.UUID) (*GMCertMaterial, error) {
	if s.enc == nil {
		return nil, fmt.Errorf("加密服务未配置")
	}
	c, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if c.EffectiveProtocolType() != ProtocolSMTLCP {
		return nil, fmt.Errorf("证书 %s 不是国密 SM_TLCP 证书", id)
	}
	signKey, err := s.enc.Decrypt(c.encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("解密国密签名私钥失败: %w", err)
	}
	encKey, err := s.enc.Decrypt(c.encryptedEncKey)
	if err != nil {
		return nil, fmt.Errorf("解密国密加密私钥失败: %w", err)
	}
	return &GMCertMaterial{
		SignCertPEM: c.certPEM,
		SignKeyPEM:  signKey,
		EncCertPEM:  c.encCertPEM,
		EncKeyPEM:   encKey,
		ChainPEM:    c.chainPEM,
	}, nil
}

// BindApplication 绑定证书到应用对应协议槽位（校验域名匹配与有效期；同站点支持同时绑定国际证与国密双证）。
func (s *Store) BindApplication(ctx context.Context, appID, certID, operatorID uuid.UUID, appDomains []string) error {
	c, err := s.GetByID(ctx, certID)
	if err != nil {
		return err
	}
	slot := c.EffectiveProtocolType()
	// 域名匹配校验（主/签名证书）
	parsed := &ParsedCertificate{
		CommonName: c.CommonName,
	}
	var sans []string
	_ = json.Unmarshal(c.SANDomains, &sans)
	parsed.SANDomains = sans
	if unmatched := MatchDomains(parsed, appDomains); len(unmatched) > 0 {
		return fmt.Errorf("%w: %v", ErrDomainMismatch, unmatched)
	}
	// 国密双证同时校验加密证书的域名覆盖
	if slot == ProtocolSMTLCP && strings.TrimSpace(c.encCertPEM) != "" {
		if _, encParsed, err := ParseSM2CertificatePEM(c.encCertPEM); err == nil {
			if unmatched := MatchDomains(encParsed, appDomains); len(unmatched) > 0 {
				return fmt.Errorf("加密证书%w: %v", ErrDomainMismatch, unmatched)
			}
		}
	}
	// 证书有效性（国密取签名证与加密证中较早到期时间）
	now := time.Now()
	if exp := c.EffectiveNotAfter(); exp != nil && now.After(*exp) {
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
	// 仅替换同一协议槽位的旧活动证书，保留另一协议槽位（实现单站点国际+国密双证并存）
	if _, err := tx.Exec(ctx,
		`UPDATE application_certificates SET is_active = FALSE, updated_at = now() WHERE application_id = $1 AND cert_slot = $2`,
		appID, slot); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO application_certificates (application_id, certificate_id, cert_slot, is_active, created_by)
VALUES ($1, $2, $3, TRUE, $4)
ON CONFLICT (application_id, certificate_id)
DO UPDATE SET cert_slot = EXCLUDED.cert_slot, is_active = TRUE, updated_at = now()`,
		appID, certID, slot, operatorID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// UnbindApplication 解绑应用证书（解绑该应用的所有槽位证书绑定）。
func (s *Store) UnbindApplication(ctx context.Context, appID uuid.UUID) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM application_certificates WHERE application_id = $1`, appID)
	return err
}

// UnbindApplicationBySlot 仅解绑应用指定协议槽位（INTERNATIONAL / SM_TLCP）的证书绑定。
func (s *Store) UnbindApplicationBySlot(ctx context.Context, appID uuid.UUID, slot string) error {
	normSlot, err := NormalizeProtocolType(slot)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx,
		`DELETE FROM application_certificates WHERE application_id = $1 AND cert_slot = $2`, appID, normSlot)
	return err
}

// UnbindCertificate 仅解绑指定应用与指定证书的绑定关系。
func (s *Store) UnbindCertificate(ctx context.Context, appID, certID uuid.UUID) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM application_certificates WHERE application_id = $1 AND certificate_id = $2`, appID, certID)
	return err
}

// GetApplicationCertificate 查询应用当前国际通用槽位活动证书（兼容存量调用方及 ACME）。
func (s *Store) GetApplicationCertificate(ctx context.Context, appID uuid.UUID) (*Certificate, error) {
	return s.getApplicationCertificateBySlot(ctx, appID, ProtocolInternational)
}

// GetApplicationGMCertificate 查询应用当前国密 SM_TLCP 槽位活动双证书。
func (s *Store) GetApplicationGMCertificate(ctx context.Context, appID uuid.UUID) (*Certificate, error) {
	return s.getApplicationCertificateBySlot(ctx, appID, ProtocolSMTLCP)
}

// GetApplicationCertificates 查询应用双槽位全部活动证书（通用国际 + 国密双证）。
func (s *Store) GetApplicationCertificates(ctx context.Context, appID uuid.UUID) (*ApplicationCertificateBindings, error) {
	rows, err := s.db.Query(ctx, `
SELECT ac.cert_slot, `+certColumnsC+` FROM certificates c
JOIN application_certificates ac ON ac.certificate_id = c.id
WHERE ac.application_id = $1 AND ac.is_active = TRUE AND c.deleted_at IS NULL`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &ApplicationCertificateBindings{}
	for rows.Next() {
		var slot string
		var c Certificate
		err := rows.Scan(&slot, &c.ID, &c.Name, &c.CertificateType, &c.ProtocolType, &c.CommonName, &c.Subject, &c.Issuer,
			&c.SerialNumber, &c.NotBefore, &c.NotAfter, &c.FingerprintSHA256, &c.PublicKeyAlgorithm,
			&c.PublicKeyBits, &c.SignatureAlgorithm, &c.SANDomains,
			&c.EncCommonName, &c.EncSubject, &c.EncIssuer, &c.EncSerialNumber,
			&c.EncNotBefore, &c.EncNotAfter, &c.EncFingerprintSHA256, &c.Status,
			&c.ManagedBy, &c.ACMEProvider, &c.ACMEDirectoryURL, &c.ACMEAccountID,
			&c.AutoRenew, &c.RenewBeforeDays, &c.ReplacesCertificateID, &c.SupersededBy, &c.LastRenewedAt,
			&c.certPEM, &c.encryptedKey, &c.chainPEM, &c.encCertPEM, &c.encryptedEncKey,
			&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &c.Version)
		if err != nil {
			return nil, err
		}
		if c.ProtocolType == "" {
			c.ProtocolType = ProtocolInternational
		}
		copyCert := c
		if slot == ProtocolSMTLCP || copyCert.ProtocolType == ProtocolSMTLCP {
			out.GM = &copyCert
		} else {
			out.International = &copyCert
		}
	}
	return out, rows.Err()
}

func (s *Store) getApplicationCertificateBySlot(ctx context.Context, appID uuid.UUID, slot string) (*Certificate, error) {
	row := s.db.QueryRow(ctx, `
SELECT `+certColumnsC+` FROM certificates c
JOIN application_certificates ac ON ac.certificate_id = c.id
WHERE ac.application_id = $1 AND ac.cert_slot = $2 AND ac.is_active = TRUE AND c.deleted_at IS NULL`, appID, slot)
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

// RefreshStatus 刷新证书状态（定时任务用；国密双证按签名证与加密证中较早到期者判定；已替换归档与无效证书保持原态）。
func (s *Store) RefreshStatus(ctx context.Context) (int, error) {
	res, err := s.db.Exec(ctx, `
UPDATE certificates SET status = CASE
  WHEN LEAST(not_after, COALESCE(enc_not_after, not_after)) < now() THEN 'EXPIRED'
  WHEN LEAST(not_after, COALESCE(enc_not_after, not_after)) < now() + interval '30 days' THEN 'EXPIRING'
  ELSE 'VALID'
END, updated_at = now()
WHERE deleted_at IS NULL AND status NOT IN ('INVALID', 'REPLACED')`)
	if err != nil {
		return 0, err
	}
	return int(res.RowsAffected()), nil
}
