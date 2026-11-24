package acme

import (
	"context"
	"crypto"
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

// Repository 定义 ACME 配置、账户与订单持久化接口（便于单测注入内存替身）。
type Repository interface {
	GetConfig(ctx context.Context) (*Config, error)
	UpdateConfig(ctx context.Context, in ConfigUpdateInput) (*Config, error)
	GetOrCreateAccount(ctx context.Context, provider, directoryURL, email, eabKID string) (*Account, crypto.Signer, error)
	UpdateAccountURI(ctx context.Context, accountID uuid.UUID, accountURI string) error
	CreateOrder(ctx context.Context, order *Order) error
	UpdateOrderProgress(ctx context.Context, orderID uuid.UUID, status string, startedAt *time.Time) error
	FinishOrder(ctx context.Context, orderID uuid.UUID, status string, certID, prevCertID, publishTaskID *uuid.UUID, errCode, errMsg string) error
	GetOrder(ctx context.Context, orderID uuid.UUID) (*Order, error)
	HasActiveOrderForApp(ctx context.Context, appID uuid.UUID) (bool, error)
	GetLatestOrderForApp(ctx context.Context, appID uuid.UUID) (*Order, error)
	ListOrders(ctx context.Context, f OrderFilter) ([]Order, int64, error)
	MarkStaleOrdersFailed(ctx context.Context, maxAge time.Duration) (int, error)
}

// Store 是基于 PostgreSQL 的 ACME 仓储实现。
type Store struct {
	db  *pgxpool.Pool
	enc *encryption.Service
}

// NewStore 创建 ACME PostgreSQL 仓储。
func NewStore(db *pgxpool.Pool, enc *encryption.Service) *Store {
	return &Store{db: db, enc: enc}
}

// GetConfig 查询全局 ACME 配置（若单行缺失则自动补建默认关闭配置）。
func (s *Store) GetConfig(ctx context.Context) (*Config, error) {
	if _, err := s.db.Exec(ctx, `INSERT INTO acme_config (id) VALUES (1) ON CONFLICT (id) DO NOTHING`); err != nil {
		return nil, err
	}
	var cfg Config
	var encEAB string
	err := s.db.QueryRow(ctx, `
SELECT enabled, provider, directory_url, custom_directory_allowlist, email, tos_agreed,
       eab_kid, encrypted_eab_hmac_key, key_type, renew_before_days, auto_publish,
       updated_by, created_at, updated_at, version
FROM acme_config WHERE id = 1`).Scan(
		&cfg.Enabled, &cfg.Provider, &cfg.DirectoryURL, &cfg.CustomDirectoryAllowlist,
		&cfg.Email, &cfg.TOSAgreed, &cfg.EABKID, &encEAB, &cfg.KeyType,
		&cfg.RenewBeforeDays, &cfg.AutoPublish, &cfg.UpdatedBy, &cfg.CreatedAt, &cfg.UpdatedAt, &cfg.Version,
	)
	if err != nil {
		return nil, err
	}
	cfg.EABHMACConfigured = strings.TrimSpace(encEAB) != ""
	if cfg.EABHMACConfigured && s.enc != nil {
		if plain, decErr := s.enc.Decrypt(encEAB); decErr == nil {
			cfg.eabHMACKey = plain
		}
	}
	if eff, effErr := EffectiveDirectoryURL(cfg.Provider, cfg.DirectoryURL); effErr == nil {
		cfg.EffectiveDirectoryURL = eff
	}
	return &cfg, nil
}

// UpdateConfig 更新全局 ACME 配置（带乐观锁，EAB HMAC 密文加密落库）。
func (s *Store) UpdateConfig(ctx context.Context, in ConfigUpdateInput) (*Config, error) {
	cur, err := s.GetConfig(ctx)
	if err != nil {
		return nil, err
	}
	if in.ExpectedVersion > 0 && in.ExpectedVersion != cur.Version {
		return nil, ErrVersionConflict
	}

	var encEAB string
	err = s.db.QueryRow(ctx, `SELECT encrypted_eab_hmac_key FROM acme_config WHERE id = 1`).Scan(&encEAB)
	if err != nil {
		return nil, err
	}
	if in.ClearEABHMACKey {
		encEAB = ""
	} else if strings.TrimSpace(in.EABHMACKey) != "" {
		if s.enc == nil {
			return nil, fmt.Errorf("加密服务未配置，无法安全保存 EAB HMAC 密钥")
		}
		cipher, encErr := s.enc.Encrypt(strings.TrimSpace(in.EABHMACKey))
		if encErr != nil {
			return nil, fmt.Errorf("加密 EAB HMAC 密钥失败: %w", encErr)
		}
		encEAB = cipher
	}

	whereVersion := ""
	args := []interface{}{
		in.Enabled, in.Provider, strings.TrimSpace(in.DirectoryURL),
		strings.TrimSpace(in.CustomDirectoryAllowlist), strings.TrimSpace(in.Email),
		in.TOSAgreed, strings.TrimSpace(in.EABKID), encEAB, in.KeyType,
		in.RenewBeforeDays, in.AutoPublish, in.UpdatedBy,
	}
	if in.ExpectedVersion > 0 {
		whereVersion = " AND version = $13"
		args = append(args, in.ExpectedVersion)
	}

	res, err := s.db.Exec(ctx, `
UPDATE acme_config
SET enabled = $1,
    provider = $2,
    directory_url = $3,
    custom_directory_allowlist = $4,
    email = $5,
    tos_agreed = $6,
    eab_kid = $7,
    encrypted_eab_hmac_key = $8,
    key_type = $9,
    renew_before_days = $10,
    auto_publish = $11,
    updated_by = $12,
    updated_at = now(),
    version = version + 1
WHERE id = 1`+whereVersion, args...)
	if err != nil {
		return nil, err
	}
	if res.RowsAffected() == 0 {
		return nil, ErrVersionConflict
	}
	return s.GetConfig(ctx)
}

// GetOrCreateAccount 按 (directory_url, email) 原子获取或生成加密 ACME 账户私钥。
func (s *Store) GetOrCreateAccount(ctx context.Context, provider, directoryURL, email, eabKID string) (*Account, crypto.Signer, error) {
	if s.enc == nil {
		return nil, nil, fmt.Errorf("加密服务未配置，无法管理 ACME 账户私钥")
	}
	dir := strings.TrimSpace(directoryURL)
	em := strings.ToLower(strings.TrimSpace(email))

	load := func() (*Account, crypto.Signer, error) {
		var a Account
		err := s.db.QueryRow(ctx, `
SELECT id, provider, directory_url, email, account_uri, encrypted_private_key, eab_kid, status, created_at, updated_at
FROM acme_accounts
WHERE directory_url = $1 AND email = $2`, dir, em).Scan(
			&a.ID, &a.Provider, &a.DirectoryURL, &a.Email, &a.AccountURI,
			&a.EncryptedPrivateKey, &a.EABKID, &a.Status, &a.CreatedAt, &a.UpdatedAt,
		)
		if err != nil {
			return nil, nil, err
		}
		keyPEM, decErr := s.enc.Decrypt(a.EncryptedPrivateKey)
		if decErr != nil {
			return nil, nil, fmt.Errorf("解密 ACME 账户私钥失败: %w", decErr)
		}
		signer, parseErr := ParsePrivateKeyPEM(keyPEM)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("解析 ACME 账户私钥失败: %w", parseErr)
		}
		return &a, signer, nil
	}

	if acct, signer, err := load(); err == nil {
		return acct, signer, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, err
	}

	_, keyPEM, err := GenerateAccountKey()
	if err != nil {
		return nil, nil, fmt.Errorf("生成 ACME 账户私钥失败: %w", err)
	}
	encKey, err := s.enc.Encrypt(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("加密 ACME 账户私钥失败: %w", err)
	}
	_, err = s.db.Exec(ctx, `
INSERT INTO acme_accounts (provider, directory_url, email, encrypted_private_key, eab_kid)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (directory_url, email) DO NOTHING`,
		provider, dir, em, encKey, strings.TrimSpace(eabKID))
	if err != nil {
		return nil, nil, err
	}
	return load()
}

// UpdateAccountURI 回填注册成功的 ACME 账户 URI。
func (s *Store) UpdateAccountURI(ctx context.Context, accountID uuid.UUID, accountURI string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE acme_accounts SET account_uri = $1, updated_at = now() WHERE id = $2`,
		strings.TrimSpace(accountURI), accountID)
	return err
}

// CreateOrder 写入新的 ACME 订单记录。
func (s *Store) CreateOrder(ctx context.Context, order *Order) error {
	domainsJSON, err := json.Marshal(order.Domains)
	if err != nil {
		return err
	}
	if order.Status == "" {
		order.Status = OrderPending
	}
	if order.ChallengeType == "" {
		order.ChallengeType = ChallengeHTTP01
	}
	return s.db.QueryRow(ctx, `
INSERT INTO acme_cert_orders (
  application_id, trigger_type, provider, directory_url, challenge_type,
  domains, status, previous_certificate_id, requested_by, request_id
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
RETURNING id, created_at, updated_at`,
		order.ApplicationID, order.TriggerType, order.Provider, order.DirectoryURL, order.ChallengeType,
		domainsJSON, order.Status, order.PreviousCertificateID, order.RequestedBy, order.RequestID,
	).Scan(&order.ID, &order.CreatedAt, &order.UpdatedAt)
}

// UpdateOrderProgress 推进进行中订单状态。
func (s *Store) UpdateOrderProgress(ctx context.Context, orderID uuid.UUID, status string, startedAt *time.Time) error {
	if startedAt != nil {
		_, err := s.db.Exec(ctx, `
UPDATE acme_cert_orders
SET status = $1, started_at = COALESCE(started_at, $2), updated_at = now()
WHERE id = $3`, status, *startedAt, orderID)
		return err
	}
	_, err := s.db.Exec(ctx, `
UPDATE acme_cert_orders SET status = $1, updated_at = now() WHERE id = $2`, status, orderID)
	return err
}

// FinishOrder 将订单标记为终态（SUCCEEDED / PUBLISH_FAILED / FAILED）。
func (s *Store) FinishOrder(ctx context.Context, orderID uuid.UUID, status string, certID, prevCertID, publishTaskID *uuid.UUID, errCode, errMsg string) error {
	if len(errMsg) > 1000 {
		errMsg = errMsg[:1000]
	}
	_, err := s.db.Exec(ctx, `
UPDATE acme_cert_orders
SET status = $1,
    certificate_id = COALESCE($2, certificate_id),
    previous_certificate_id = COALESCE($3, previous_certificate_id),
    publish_task_id = COALESCE($4, publish_task_id),
    error_code = $5,
    error_message = $6,
    finished_at = now(),
    updated_at = now()
WHERE id = $7`,
		status, certID, prevCertID, publishTaskID, errCode, errMsg, orderID)
	return err
}

const orderSelectColumns = `
o.id, o.application_id, COALESCE(a.code, ''), COALESCE(a.name, ''),
o.trigger_type, o.provider, o.directory_url, o.challenge_type,
o.domains, o.status, o.certificate_id, o.previous_certificate_id,
o.publish_task_id, o.error_code, o.error_message, o.requested_by,
o.request_id, o.started_at, o.finished_at, o.created_at, o.updated_at`

func scanOrder(row pgx.Row) (*Order, error) {
	var o Order
	var domainsRaw []byte
	err := row.Scan(
		&o.ID, &o.ApplicationID, &o.AppCode, &o.AppName,
		&o.TriggerType, &o.Provider, &o.DirectoryURL, &o.ChallengeType,
		&domainsRaw, &o.Status, &o.CertificateID, &o.PreviousCertificateID,
		&o.PublishTaskID, &o.ErrorCode, &o.ErrorMessage, &o.RequestedBy,
		&o.RequestID, &o.StartedAt, &o.FinishedAt, &o.CreatedAt, &o.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(domainsRaw, &o.Domains)
	if o.Domains == nil {
		o.Domains = []string{}
	}
	return &o, nil
}

// GetOrder 查询单条订单详情。
func (s *Store) GetOrder(ctx context.Context, orderID uuid.UUID) (*Order, error) {
	row := s.db.QueryRow(ctx, `
SELECT `+orderSelectColumns+`
FROM acme_cert_orders o
LEFT JOIN applications a ON a.id = o.application_id
WHERE o.id = $1`, orderID)
	o, err := scanOrder(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrOrderNotFound
		}
		return nil, err
	}
	return o, nil
}

// HasActiveOrderForApp 判断应用是否已有近期进行中的订单（防重复并发下单）。
func (s *Store) HasActiveOrderForApp(ctx context.Context, appID uuid.UUID) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `
SELECT EXISTS (
  SELECT 1 FROM acme_cert_orders
  WHERE application_id = $1
    AND status IN ('PENDING','PREPARING','VALIDATING','FINALIZING','ISSUED','PUBLISHING')
    AND updated_at > now() - interval '15 minutes'
)`, appID).Scan(&exists)
	return exists, err
}

// GetLatestOrderForApp 查询应用的最新一条 ACME 订单。
func (s *Store) GetLatestOrderForApp(ctx context.Context, appID uuid.UUID) (*Order, error) {
	row := s.db.QueryRow(ctx, `
SELECT `+orderSelectColumns+`
FROM acme_cert_orders o
LEFT JOIN applications a ON a.id = o.application_id
WHERE o.application_id = $1
ORDER BY o.created_at DESC
LIMIT 1`, appID)
	o, err := scanOrder(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return o, nil
}

// ListOrders 分页查询 ACME 订单记录。
func (s *Store) ListOrders(ctx context.Context, f OrderFilter) ([]Order, int64, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 || f.PageSize > 100 {
		f.PageSize = 20
	}
	where := "1=1"
	args := []interface{}{}
	idx := 1
	if f.ApplicationID != nil {
		where += fmt.Sprintf(" AND o.application_id = $%d", idx)
		args = append(args, *f.ApplicationID)
		idx++
	}
	if strings.TrimSpace(f.Status) != "" {
		where += fmt.Sprintf(" AND o.status = $%d", idx)
		args = append(args, strings.TrimSpace(f.Status))
		idx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM acme_cert_orders o WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `SELECT ` + orderSelectColumns + `
FROM acme_cert_orders o
LEFT JOIN applications a ON a.id = o.application_id
WHERE ` + where + fmt.Sprintf(" ORDER BY o.created_at DESC LIMIT $%d OFFSET $%d", idx, idx+1)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]Order, 0)
	for rows.Next() {
		o, err := scanOrder(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *o)
	}
	return out, total, rows.Err()
}

// MarkStaleOrdersFailed 启动或巡检时收口因进程重启中断的陈旧进行中订单。
func (s *Store) MarkStaleOrdersFailed(ctx context.Context, maxAge time.Duration) (int, error) {
	if maxAge <= 0 {
		maxAge = 15 * time.Minute
	}
	cutoff := time.Now().UTC().Add(-maxAge)
	res, err := s.db.Exec(ctx, `
UPDATE acme_cert_orders
SET status = 'FAILED',
    error_code = 'INTERRUPTED',
    error_message = '服务重启或任务超时中断，系统将在下个周期自动重试',
    finished_at = now(),
    updated_at = now()
WHERE status IN ('PENDING','PREPARING','VALIDATING','FINALIZING','ISSUED','PUBLISHING')
  AND updated_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return int(res.RowsAffected()), nil
}
