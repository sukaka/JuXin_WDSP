// store.go AI 爬虫治理仓储：ai_crawler_directories、ai_crawl_policies 与
// ai_crawl_policy_versions（迁移 000245）。ListForGuard 实现 guardconfig.AICrawlLister 接口。
package aicrawl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// ErrNotFound 资源不存在。
var ErrNotFound = errors.New("ai crawl resource not found")

// ErrConflict 版本冲突或 slug 唯一约束冲突。
var ErrConflict = errors.New("ai crawl resource conflict")

// ErrBuiltinProtected 内置爬虫目录不可删除（仅允许启用/禁用或同步更新公钥）。
var ErrBuiltinProtected = errors.New("builtin crawler directory cannot be deleted")

// Store 是 AI 爬虫治理仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

const directoryColumns = `id, slug, name, category, signature_agent, directory_url, keys, is_builtin, enabled, last_synced_at, last_sync_error, created_at, updated_at`

func scanDirectory(row pgx.Row) (*Directory, error) {
	var d Directory
	var keysRaw []byte
	err := row.Scan(
		&d.ID, &d.Slug, &d.Name, &d.Category, &d.SignatureAgent, &d.DirectoryURL,
		&keysRaw, &d.IsBuiltin, &d.Enabled, &d.LastSyncedAt, &d.LastSyncError,
		&d.CreatedAt, &d.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	d.Keys = []CrawlerKey{}
	if len(keysRaw) > 0 {
		if err := json.Unmarshal(keysRaw, &d.Keys); err != nil {
			return nil, fmt.Errorf("decode crawler directory keys: %w", err)
		}
	}
	if d.Keys == nil {
		d.Keys = []CrawlerKey{}
	}
	return &d, nil
}

// ListDirectories 列出全部爬虫公钥目录（内置优先，按 slug 稳定排序）。
func (s *Store) ListDirectories(ctx context.Context) ([]Directory, error) {
	rows, err := s.db.Query(ctx, `SELECT `+directoryColumns+` FROM ai_crawler_directories ORDER BY is_builtin DESC, slug ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Directory{}
	for rows.Next() {
		d, err := scanDirectory(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// GetDirectory 按 ID 读取单个爬虫目录。
func (s *Store) GetDirectory(ctx context.Context, id uuid.UUID) (*Directory, error) {
	row := s.db.QueryRow(ctx, `SELECT `+directoryColumns+` FROM ai_crawler_directories WHERE id = $1`, id)
	return scanDirectory(row)
}

// CreateDirectory 新增爬虫目录（slug 冲突返回 ErrConflict）。
func (s *Store) CreateDirectory(ctx context.Context, d *Directory) error {
	if errs := ValidateDirectory(d); len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	keysJSON, err := json.Marshal(d.Keys)
	if err != nil {
		return err
	}
	row := s.db.QueryRow(ctx, `
INSERT INTO ai_crawler_directories (slug, name, category, signature_agent, directory_url, keys, is_builtin, enabled)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, FALSE, $7)
RETURNING `+directoryColumns,
		d.Slug, d.Name, d.Category, d.SignatureAgent, d.DirectoryURL, string(keysJSON), d.Enabled)
	created, err := scanDirectory(row)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	*d = *created
	return nil
}

// UpdateDirectory 更新爬虫目录（不存在返回 ErrNotFound，slug 冲突返回 ErrConflict）。
func (s *Store) UpdateDirectory(ctx context.Context, d *Directory) error {
	if errs := ValidateDirectory(d); len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	keysJSON, err := json.Marshal(d.Keys)
	if err != nil {
		return err
	}
	row := s.db.QueryRow(ctx, `
UPDATE ai_crawler_directories
SET slug=$1, name=$2, category=$3, signature_agent=$4, directory_url=$5, keys=$6::jsonb, enabled=$7, updated_at=now()
WHERE id=$8
RETURNING `+directoryColumns,
		d.Slug, d.Name, d.Category, d.SignatureAgent, d.DirectoryURL, string(keysJSON), d.Enabled, d.ID)
	updated, err := scanDirectory(row)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	*d = *updated
	return nil
}

// DeleteDirectory 删除非内置爬虫目录（内置目录返回 ErrBuiltinProtected）。
func (s *Store) DeleteDirectory(ctx context.Context, id uuid.UUID) error {
	existing, err := s.GetDirectory(ctx, id)
	if err != nil {
		return err
	}
	if existing.IsBuiltin {
		return ErrBuiltinProtected
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM ai_crawler_directories WHERE id = $1 AND is_builtin = FALSE`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpsertDirectories 离线 JSON 包批量导入（同事务按 slug upsert，保留已有行的 is_builtin 标志）。
func (s *Store) UpsertDirectories(ctx context.Context, dirs []Directory) ([]Directory, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	out := make([]Directory, 0, len(dirs))
	for i := range dirs {
		d := dirs[i]
		if errs := ValidateDirectory(&d); len(errs) > 0 {
			return nil, &ValidationError{Errors: errs}
		}
		keysJSON, err := json.Marshal(d.Keys)
		if err != nil {
			return nil, err
		}
		row := tx.QueryRow(ctx, `
INSERT INTO ai_crawler_directories (slug, name, category, signature_agent, directory_url, keys, is_builtin, enabled)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, FALSE, $7)
ON CONFLICT (slug) DO UPDATE SET
  name = EXCLUDED.name,
  category = EXCLUDED.category,
  signature_agent = EXCLUDED.signature_agent,
  directory_url = EXCLUDED.directory_url,
  keys = EXCLUDED.keys,
  enabled = EXCLUDED.enabled,
  last_sync_error = '',
  updated_at = now()
RETURNING `+directoryColumns,
			d.Slug, d.Name, d.Category, d.SignatureAgent, d.DirectoryURL, string(keysJSON), d.Enabled)
		saved, err := scanDirectory(row)
		if err != nil {
			return nil, err
		}
		out = append(out, *saved)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateDirectorySyncSuccess 回写远程同步成功的公钥集合与同步时间。
func (s *Store) UpdateDirectorySyncSuccess(ctx context.Context, id uuid.UUID, keys []CrawlerKey, syncedAt time.Time) (*Directory, error) {
	keysJSON, err := json.Marshal(keys)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRow(ctx, `
UPDATE ai_crawler_directories
SET keys=$1::jsonb, last_synced_at=$2, last_sync_error='', updated_at=now()
WHERE id=$3
RETURNING `+directoryColumns, string(keysJSON), syncedAt.UTC(), id)
	return scanDirectory(row)
}

// UpdateDirectorySyncError 记录最近一次远程同步失败原因（保留原有已生效公钥不清空）。
func (s *Store) UpdateDirectorySyncError(ctx context.Context, id uuid.UUID, errMsg string) error {
	if len(errMsg) > 500 {
		errMsg = errMsg[:500]
	}
	_, err := s.db.Exec(ctx, `
UPDATE ai_crawler_directories
SET last_sync_error=$1, updated_at=now()
WHERE id=$2`, errMsg, id)
	return err
}

// ---------- 应用级 AI 爬虫策略 ----------

const policyColumns = `id, application_id, mode, version, default_ai_action, content_signal,
	verify_web_bot_auth, labyrinth_enabled, labyrinth_inject_links, labyrinth_max_depth,
	labyrinth_max_concurrency, labyrinth_delay_ms, http_402, rules, updated_by, created_at, updated_at`

func scanPolicy(row pgx.Row) (*Policy, error) {
	var p Policy
	var http402Raw, rulesRaw []byte
	var updatedBy *string
	err := row.Scan(
		&p.ID, &p.ApplicationID, &p.Mode, &p.Version, &p.DefaultAIAction, &p.ContentSignal,
		&p.VerifyWebBotAuth, &p.LabyrinthEnabled, &p.LabyrinthInjectLinks, &p.LabyrinthMaxDepth,
		&p.LabyrinthMaxConcurrency, &p.LabyrinthDelayMs, &http402Raw, &rulesRaw,
		&updatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	p.SchemaVersion = SchemaVersion
	if updatedBy != nil {
		p.UpdatedBy = *updatedBy
	}
	if len(http402Raw) > 0 {
		if err := json.Unmarshal(http402Raw, &p.HTTP402); err != nil {
			return nil, fmt.Errorf("decode http_402: %w", err)
		}
	}
	p.Rules = []Rule{}
	if len(rulesRaw) > 0 {
		if err := json.Unmarshal(rulesRaw, &p.Rules); err != nil {
			return nil, fmt.Errorf("decode rules: %w", err)
		}
	}
	for i := range p.Rules {
		if p.Rules[i].UAPatterns == nil {
			p.Rules[i].UAPatterns = []string{}
		}
	}
	return &p, nil
}

// GetByApp 读取应用当前 AI 爬虫策略草稿；无记录返回 ErrNotFound。
func (s *Store) GetByApp(ctx context.Context, appID uuid.UUID) (*Policy, error) {
	row := s.db.QueryRow(ctx, `SELECT `+policyColumns+` FROM ai_crawl_policies WHERE application_id = $1`, appID)
	return scanPolicy(row)
}

// SaveDraft 校验并保存草稿（expected_version 乐观锁 + 同事务写入不可变版本历史）。
func (s *Store) SaveDraft(ctx context.Context, p *Policy, expectedVersion int, reason, updatedBy string) error {
	if errs := ValidatePolicy(p); len(errs) > 0 {
		return &ValidationError{Errors: errs}
	}
	if reason == "" {
		return &ValidationError{Errors: []FieldError{{Field: "reason", Message: "变更理由不能为空"}}}
	}
	http402JSON, err := json.Marshal(p.HTTP402)
	if err != nil {
		return err
	}
	rulesJSON, err := json.Marshal(p.Rules)
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
		err = tx.QueryRow(ctx, `
INSERT INTO ai_crawl_policies (
	application_id, mode, version, default_ai_action, content_signal,
	verify_web_bot_auth, labyrinth_enabled, labyrinth_inject_links,
	labyrinth_max_depth, labyrinth_max_concurrency, labyrinth_delay_ms,
	http_402, rules, updated_by
) VALUES ($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13)
RETURNING id, version`,
			p.ApplicationID, p.Mode, p.DefaultAIAction, p.ContentSignal,
			p.VerifyWebBotAuth, p.LabyrinthEnabled, p.LabyrinthInjectLinks,
			p.LabyrinthMaxDepth, p.LabyrinthMaxConcurrency, p.LabyrinthDelayMs,
			string(http402JSON), string(rulesJSON), updatedBy,
		).Scan(&p.ID, &newVersion)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
	} else {
		err = tx.QueryRow(ctx, `
UPDATE ai_crawl_policies SET
	mode=$1, default_ai_action=$2, content_signal=$3,
	verify_web_bot_auth=$4, labyrinth_enabled=$5, labyrinth_inject_links=$6,
	labyrinth_max_depth=$7, labyrinth_max_concurrency=$8, labyrinth_delay_ms=$9,
	http_402=$10::jsonb, rules=$11::jsonb, updated_by=$12, updated_at=now(), version=version+1
WHERE application_id=$13 AND version=$14
RETURNING id, version`,
			p.Mode, p.DefaultAIAction, p.ContentSignal,
			p.VerifyWebBotAuth, p.LabyrinthEnabled, p.LabyrinthInjectLinks,
			p.LabyrinthMaxDepth, p.LabyrinthMaxConcurrency, p.LabyrinthDelayMs,
			string(http402JSON), string(rulesJSON), updatedBy,
			p.ApplicationID, expectedVersion,
		).Scan(&p.ID, &newVersion)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrConflict
			}
			return err
		}
	}

	if _, err := tx.Exec(ctx, `
INSERT INTO ai_crawl_policy_versions (
	application_id, version, mode, default_ai_action, content_signal,
	verify_web_bot_auth, labyrinth_enabled, labyrinth_inject_links,
	labyrinth_max_depth, labyrinth_max_concurrency, labyrinth_delay_ms,
	http_402, rules, reason, created_by
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13::jsonb,$14,$15)`,
		p.ApplicationID, newVersion, p.Mode, p.DefaultAIAction, p.ContentSignal,
		p.VerifyWebBotAuth, p.LabyrinthEnabled, p.LabyrinthInjectLinks,
		p.LabyrinthMaxDepth, p.LabyrinthMaxConcurrency, p.LabyrinthDelayMs,
		string(http402JSON), string(rulesJSON), reason, updatedBy,
	); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	p.Version = newVersion
	p.UpdatedBy = updatedBy
	return nil
}

// PublishedVersion 读取最近 SUCCESS 访问控制发布快照中本应用的 AI 爬虫策略版本。
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
		AICrawlPolicy map[string]struct {
			Version int `json:"version"`
		} `json:"ai_crawl_policy"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return 0, fmt.Errorf("decode published guard config: %w", err)
	}
	if pol, ok := cfg.AICrawlPolicy[appCode]; ok {
		return pol.Version, nil
	}
	return 0, nil
}

// ListForGuard 读取全部应用 AI 爬虫策略与启用中的爬虫公钥目录，映射为网关下发冻结契约
// （实现 guardconfig.AICrawlLister 接口；key 为应用编码；labyrinth_key_hex 留空由发布密钥通道注入）。
func (s *Store) ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardAICrawlPolicy, error) {
	dirRows, err := s.db.Query(ctx, `SELECT `+directoryColumns+` FROM ai_crawler_directories WHERE enabled = TRUE ORDER BY slug ASC`)
	if err != nil {
		return nil, fmt.Errorf("list enabled crawler directories: %w", err)
	}
	defer dirRows.Close()
	dirs := []Directory{}
	for dirRows.Next() {
		d, err := scanDirectory(dirRows)
		if err != nil {
			return nil, err
		}
		dirs = append(dirs, *d)
	}
	if err := dirRows.Err(); err != nil {
		return nil, err
	}

	rows, err := s.db.Query(ctx, `
SELECT p.application_id, a.code, p.mode, p.version, p.default_ai_action, p.content_signal,
	p.verify_web_bot_auth, p.labyrinth_enabled, p.labyrinth_inject_links, p.labyrinth_max_depth,
	p.labyrinth_max_concurrency, p.labyrinth_delay_ms, p.http_402, p.rules
FROM ai_crawl_policies p
JOIN applications a ON a.id = p.application_id
WHERE a.deleted_at IS NULL
ORDER BY a.code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]*gatewayconfig.GuardAICrawlPolicy{}
	for rows.Next() {
		var (
			p                   Policy
			code                string
			http402Raw, rulesRaw []byte
		)
		if err := rows.Scan(
			&p.ApplicationID, &code, &p.Mode, &p.Version, &p.DefaultAIAction, &p.ContentSignal,
			&p.VerifyWebBotAuth, &p.LabyrinthEnabled, &p.LabyrinthInjectLinks, &p.LabyrinthMaxDepth,
			&p.LabyrinthMaxConcurrency, &p.LabyrinthDelayMs, &http402Raw, &rulesRaw,
		); err != nil {
			return nil, err
		}
		p.SchemaVersion = SchemaVersion
		if len(http402Raw) > 0 {
			if err := json.Unmarshal(http402Raw, &p.HTTP402); err != nil {
				return nil, fmt.Errorf("decode http_402 for %s: %w", code, err)
			}
		}
		if len(rulesRaw) > 0 {
			if err := json.Unmarshal(rulesRaw, &p.Rules); err != nil {
				return nil, fmt.Errorf("decode rules for %s: %w", code, err)
			}
		}
		out[code] = toGuardPolicy(&p, dirs)
	}
	return out, rows.Err()
}

// toGuardPolicy 将领域策略与启用目录映射为网关冻结下发契约（纯函数，便于单测）。
func toGuardPolicy(p *Policy, dirs []Directory) *gatewayconfig.GuardAICrawlPolicy {
	gp := &gatewayconfig.GuardAICrawlPolicy{
		SchemaVersion:           SchemaVersion,
		ApplicationID:           p.ApplicationID.String(),
		Mode:                    p.Mode,
		Version:                 p.Version,
		DefaultAIAction:         p.DefaultAIAction,
		ContentSignal:           p.ContentSignal,
		VerifyWebBotAuth:        p.VerifyWebBotAuth,
		LabyrinthEnabled:        p.LabyrinthEnabled,
		LabyrinthInjectLinks:    p.LabyrinthInjectLinks,
		LabyrinthMaxDepth:       p.LabyrinthMaxDepth,
		LabyrinthMaxConcurrency: p.LabyrinthMaxConcurrency,
		LabyrinthDelayMs:        p.LabyrinthDelayMs,
		HTTP402: gatewayconfig.GuardAICrawlHTTP402{
			Message:       p.HTTP402.Message,
			PriceHint:     p.HTTP402.PriceHint,
			ContactURL:    p.HTTP402.ContactURL,
			ReceiptHeader: p.HTTP402.ReceiptHeader,
		},
		Rules:       make([]gatewayconfig.GuardAICrawlRule, 0, len(p.Rules)),
		Directories: make([]gatewayconfig.GuardAICrawlerDirectory, 0, len(dirs)),
	}
	for _, r := range p.Rules {
		var patterns []string
		if len(r.UAPatterns) > 0 {
			patterns = append([]string(nil), r.UAPatterns...)
		} else {
			patterns = []string{}
		}
		gp.Rules = append(gp.Rules, gatewayconfig.GuardAICrawlRule{
			ID:                 r.ID,
			Name:               r.Name,
			Category:           r.Category,
			AgentID:            r.AgentID,
			UAPatterns:         patterns,
			RequireVerifiedSig: r.RequireVerifiedSig,
			Action:             r.Action,
			ExemptBotChallenge: r.ExemptBotChallenge,
			RateLimitRPM:       r.RateLimitRPM,
			Priority:           r.Priority,
		})
	}
	for _, d := range dirs {
		if !d.Enabled {
			continue
		}
		gd := gatewayconfig.GuardAICrawlerDirectory{
			ID:             d.ID.String(),
			Slug:           d.Slug,
			Name:           d.Name,
			Category:       d.Category,
			SignatureAgent: d.SignatureAgent,
			DirectoryURL:   d.DirectoryURL,
			Keys:           make([]gatewayconfig.GuardAICrawlerKey, 0, len(d.Keys)),
		}
		for _, k := range d.Keys {
			gd.Keys = append(gd.Keys, gatewayconfig.GuardAICrawlerKey{
				KID:          k.KID,
				Alg:          k.Alg,
				PublicKeyPEM: k.PublicKeyPEM,
			})
		}
		gp.Directories = append(gp.Directories, gd)
	}
	return gp
}

func isUniqueViolation(err error) bool {
	var iface interface{ SQLState() string }
	if errors.As(err, &iface) {
		return iface.SQLState() == "23505"
	}
	return false
}
