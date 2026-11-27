// store.go 自定义拦截页面模板、不可变版本历史与生效绑定 PostgreSQL 仓储（迁移 000251）。
package blockpages

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrNotFound 模板或绑定不存在。
	ErrNotFound = errors.New("block page not found")
	// ErrVersionNotFound 目标历史版本不存在。
	ErrVersionNotFound = errors.New("block page version not found")
	// ErrConflict 乐观锁版本冲突。
	ErrConflict = errors.New("block page version conflict")
	// ErrDuplicateName 模板名称已存在。
	ErrDuplicateName = errors.New("block page name already exists")
	// ErrTemplateLimitReached 模板数量已达上限。
	ErrTemplateLimitReached = errors.New("block page template limit reached")
	// ErrInUse 模板正被生效绑定引用，禁止删除。
	ErrInUse = errors.New("block page is currently bound")
	// ErrBuiltinProtected 内置预设模板不允许删除。
	ErrBuiltinProtected = errors.New("builtin block page cannot be deleted")
)

// Repository 定义自定义拦截页 HTTP 处理器依赖的仓储接口（*Store 实现，单测可注入内存桩）。
type Repository interface {
	List(ctx context.Context, filter ListFilter) ([]BlockPage, int, error)
	GetByID(ctx context.Context, id uuid.UUID) (*BlockPage, error)
	ListVersions(ctx context.Context, pageID uuid.UUID) ([]BlockPageVersion, error)
	GetVersion(ctx context.Context, pageID uuid.UUID, version int) (*BlockPageVersion, error)
	Create(ctx context.Context, in CreateInput) (*BlockPage, *BlockPageVersion, error)
	Update(ctx context.Context, in UpdateInput) (*BlockPage, *BlockPageVersion, error)
	Rollback(ctx context.Context, in RollbackInput) (*BlockPage, *BlockPageVersion, error)
	Delete(ctx context.Context, id uuid.UUID) error
	ListBindings(ctx context.Context, filter BindingFilter) ([]BlockPageBinding, error)
	ListBindingsByPage(ctx context.Context, pageID uuid.UUID) ([]BlockPageBinding, error)
	GetBindingByID(ctx context.Context, id uuid.UUID) (*BlockPageBinding, error)
	UpsertBinding(ctx context.Context, in UpsertBindingInput) (*BlockPageBinding, error)
	DeleteBinding(ctx context.Context, id uuid.UUID) error
}

// Store 是 PostgreSQL 仓储实现。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

var _ Repository = (*Store)(nil)

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

func decodeVisualConfig(raw []byte) VisualConfig {
	var vc VisualConfig
	if len(raw) == 0 {
		return vc
	}
	_ = json.Unmarshal(raw, &vc)
	return vc
}

func scanBlockPage(row pgx.Row) (*BlockPage, error) {
	var (
		p      BlockPage
		visRaw []byte
	)
	err := row.Scan(
		&p.ID, &p.Name, &p.Description, &p.EditorMode, &p.Theme,
		&visRaw, &p.HTMLContent, &p.RenderedHTML, &p.StatusCode,
		&p.JSONCode, &p.JSONMessage, &p.Version, &p.IsBuiltin,
		&p.BindingCount, &p.CreatedBy, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	p.VisualConfig = decodeVisualConfig(visRaw)
	return &p, nil
}

func scanBlockPageVersion(row pgx.Row) (*BlockPageVersion, error) {
	var (
		v      BlockPageVersion
		visRaw []byte
	)
	err := row.Scan(
		&v.ID, &v.BlockPageID, &v.Version, &v.EditorMode, &v.Theme,
		&visRaw, &v.HTMLContent, &v.RenderedHTML, &v.StatusCode,
		&v.JSONCode, &v.JSONMessage, &v.ChangeNote, &v.CreatedBy, &v.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrVersionNotFound
		}
		return nil, err
	}
	v.VisualConfig = decodeVisualConfig(visRaw)
	return &v, nil
}

const selectBlockPageCols = `
	p.id, p.name, p.description, p.editor_mode, p.theme,
	p.visual_config, p.html_content, p.rendered_html, p.status_code,
	p.json_code, p.json_message, p.version, p.is_builtin,
	(SELECT COUNT(*) FROM block_page_bindings b WHERE b.block_page_id = p.id AND b.enabled = TRUE) AS binding_count,
	p.created_by, p.updated_by, p.created_at, p.updated_at`

// List 分页查询拦截页模板列表。
func (s *Store) List(ctx context.Context, filter ListFilter) ([]BlockPage, int, error) {
	page := filter.Page
	if page < 1 {
		page = DefaultPage
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}

	var (
		conds []string
		args  []interface{}
		idx   = 1
	)
	if kw := strings.TrimSpace(filter.Keyword); kw != "" {
		like := "%" + escapeLike(kw) + "%"
		conds = append(conds, fmt.Sprintf("(p.name ILIKE $%d ESCAPE '\\' OR p.description ILIKE $%d ESCAPE '\\')", idx, idx))
		args = append(args, like)
		idx++
	}
	if filter.EditorMode != "" {
		conds = append(conds, fmt.Sprintf("p.editor_mode = $%d", idx))
		args = append(args, filter.EditorMode)
		idx++
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}

	var total int
	if err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM block_pages p`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count block pages: %w", err)
	}

	query := fmt.Sprintf(`SELECT %s FROM block_pages p%s ORDER BY p.is_builtin DESC, p.updated_at DESC, p.name ASC LIMIT $%d OFFSET $%d`,
		selectBlockPageCols, where, idx, idx+1)
	args = append(args, pageSize, (page-1)*pageSize)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list block pages: %w", err)
	}
	defer rows.Close()

	items := make([]BlockPage, 0)
	for rows.Next() {
		var (
			p      BlockPage
			visRaw []byte
		)
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.EditorMode, &p.Theme,
			&visRaw, &p.HTMLContent, &p.RenderedHTML, &p.StatusCode,
			&p.JSONCode, &p.JSONMessage, &p.Version, &p.IsBuiltin,
			&p.BindingCount, &p.CreatedBy, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan block page: %w", err)
		}
		p.VisualConfig = decodeVisualConfig(visRaw)
		items = append(items, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate block pages: %w", err)
	}
	return items, total, nil
}

// GetByID 查询单个拦截页模板。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*BlockPage, error) {
	return scanBlockPage(s.db.QueryRow(ctx,
		`SELECT `+selectBlockPageCols+` FROM block_pages p WHERE p.id = $1`, id))
}

// ListVersions 查询模板全部不可变修订版本（按版本号倒序）。
func (s *Store) ListVersions(ctx context.Context, pageID uuid.UUID) ([]BlockPageVersion, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, block_page_id, version, editor_mode, theme, visual_config,
       html_content, rendered_html, status_code, json_code, json_message,
       change_note, created_by, created_at
FROM block_page_versions
WHERE block_page_id = $1
ORDER BY version DESC`, pageID)
	if err != nil {
		return nil, fmt.Errorf("list block page versions: %w", err)
	}
	defer rows.Close()

	out := make([]BlockPageVersion, 0)
	for rows.Next() {
		var (
			v      BlockPageVersion
			visRaw []byte
		)
		if err := rows.Scan(
			&v.ID, &v.BlockPageID, &v.Version, &v.EditorMode, &v.Theme,
			&visRaw, &v.HTMLContent, &v.RenderedHTML, &v.StatusCode,
			&v.JSONCode, &v.JSONMessage, &v.ChangeNote, &v.CreatedBy, &v.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan block page version: %w", err)
		}
		v.VisualConfig = decodeVisualConfig(visRaw)
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate block page versions: %w", err)
	}
	return out, nil
}

// GetVersion 查询模板指定修订版本。
func (s *Store) GetVersion(ctx context.Context, pageID uuid.UUID, version int) (*BlockPageVersion, error) {
	return scanBlockPageVersion(s.db.QueryRow(ctx, `
SELECT id, block_page_id, version, editor_mode, theme, visual_config,
       html_content, rendered_html, status_code, json_code, json_message,
       change_note, created_by, created_at
FROM block_page_versions
WHERE block_page_id = $1 AND version = $2`, pageID, version))
}

// Create 事务新建模板并同步写入不可变 v1 版本历史。
func (s *Store) Create(ctx context.Context, in CreateInput) (*BlockPage, *BlockPageVersion, error) {
	visJSON, err := json.Marshal(in.VisualConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal visual_config: %w", err)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("begin create block page: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var total int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM block_pages`).Scan(&total); err != nil {
		return nil, nil, fmt.Errorf("count block pages: %w", err)
	}
	if total >= MaxTemplatesTotal {
		return nil, nil, ErrTemplateLimitReached
	}

	var (
		p      BlockPage
		visOut []byte
	)
	err = tx.QueryRow(ctx, `
INSERT INTO block_pages (
	name, description, editor_mode, theme, visual_config, html_content, rendered_html,
	status_code, json_code, json_message, version, is_builtin, created_by, updated_by
) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,1,FALSE,$11,$11)
RETURNING id, name, description, editor_mode, theme, visual_config, html_content, rendered_html,
          status_code, json_code, json_message, version, is_builtin, created_by, updated_by, created_at, updated_at`,
		in.Name, in.Description, in.EditorMode, in.Theme, string(visJSON), in.HTMLContent, in.RenderedHTML,
		in.StatusCode, in.JSONCode, in.JSONMessage, in.CreatedBy,
	).Scan(
		&p.ID, &p.Name, &p.Description, &p.EditorMode, &p.Theme,
		&visOut, &p.HTMLContent, &p.RenderedHTML, &p.StatusCode,
		&p.JSONCode, &p.JSONMessage, &p.Version, &p.IsBuiltin,
		&p.CreatedBy, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, nil, ErrDuplicateName
		}
		return nil, nil, fmt.Errorf("insert block page: %w", err)
	}
	p.VisualConfig = decodeVisualConfig(visOut)

	note := strings.TrimSpace(in.ChangeNote)
	if note == "" {
		note = "初始创建版本"
	}
	ver, err := scanBlockPageVersion(tx.QueryRow(ctx, `
INSERT INTO block_page_versions (
	block_page_id, version, editor_mode, theme, visual_config, html_content, rendered_html,
	status_code, json_code, json_message, change_note, created_by
) VALUES ($1,1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11)
RETURNING id, block_page_id, version, editor_mode, theme, visual_config,
          html_content, rendered_html, status_code, json_code, json_message,
          change_note, created_by, created_at`,
		p.ID, in.EditorMode, in.Theme, string(visJSON), in.HTMLContent, in.RenderedHTML,
		in.StatusCode, in.JSONCode, in.JSONMessage, note, in.CreatedBy,
	))
	if err != nil {
		return nil, nil, fmt.Errorf("insert block page version v1: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit create block page: %w", err)
	}
	return &p, ver, nil
}

// Update 乐观锁更新模板并追加新不可变修订版本（version + 1）。
func (s *Store) Update(ctx context.Context, in UpdateInput) (*BlockPage, *BlockPageVersion, error) {
	visJSON, err := json.Marshal(in.VisualConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal visual_config: %w", err)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("begin update block page: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var curVersion int
	if err := tx.QueryRow(ctx, `SELECT version FROM block_pages WHERE id = $1 FOR UPDATE`, in.ID).Scan(&curVersion); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, fmt.Errorf("lock block page: %w", err)
	}
	if curVersion != in.ExpectedVersion {
		return nil, nil, ErrConflict
	}

	nextVersion := curVersion + 1
	var (
		p      BlockPage
		visOut []byte
	)
	err = tx.QueryRow(ctx, `
UPDATE block_pages
SET name = $2, description = $3, editor_mode = $4, theme = $5,
    visual_config = $6::jsonb, html_content = $7, rendered_html = $8,
    status_code = $9, json_code = $10, json_message = $11,
    version = $12, updated_by = $13, updated_at = now()
WHERE id = $1
RETURNING id, name, description, editor_mode, theme, visual_config, html_content, rendered_html,
          status_code, json_code, json_message, version, is_builtin, created_by, updated_by, created_at, updated_at`,
		in.ID, in.Name, in.Description, in.EditorMode, in.Theme,
		string(visJSON), in.HTMLContent, in.RenderedHTML,
		in.StatusCode, in.JSONCode, in.JSONMessage,
		nextVersion, in.UpdatedBy,
	).Scan(
		&p.ID, &p.Name, &p.Description, &p.EditorMode, &p.Theme,
		&visOut, &p.HTMLContent, &p.RenderedHTML, &p.StatusCode,
		&p.JSONCode, &p.JSONMessage, &p.Version, &p.IsBuiltin,
		&p.CreatedBy, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, nil, ErrDuplicateName
		}
		return nil, nil, fmt.Errorf("update block page: %w", err)
	}
	p.VisualConfig = decodeVisualConfig(visOut)

	_ = tx.QueryRow(ctx, `SELECT COUNT(*) FROM block_page_bindings WHERE block_page_id = $1 AND enabled = TRUE`, p.ID).Scan(&p.BindingCount)

	note := strings.TrimSpace(in.ChangeNote)
	if note == "" {
		note = fmt.Sprintf("更新至版本 v%d", nextVersion)
	}
	ver, err := scanBlockPageVersion(tx.QueryRow(ctx, `
INSERT INTO block_page_versions (
	block_page_id, version, editor_mode, theme, visual_config, html_content, rendered_html,
	status_code, json_code, json_message, change_note, created_by
) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$11,$12)
RETURNING id, block_page_id, version, editor_mode, theme, visual_config,
          html_content, rendered_html, status_code, json_code, json_message,
          change_note, created_by, created_at`,
		p.ID, nextVersion, in.EditorMode, in.Theme, string(visJSON), in.HTMLContent, in.RenderedHTML,
		in.StatusCode, in.JSONCode, in.JSONMessage, note, in.UpdatedBy,
	))
	if err != nil {
		return nil, nil, fmt.Errorf("insert block page version: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit update block page: %w", err)
	}
	return &p, ver, nil
}

// Rollback 将模板回滚到目标历史版本（不可变追加为 version+1，绝不覆写旧版本）。
func (s *Store) Rollback(ctx context.Context, in RollbackInput) (*BlockPage, *BlockPageVersion, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("begin rollback block page: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var curVersion int
	if err := tx.QueryRow(ctx, `SELECT version FROM block_pages WHERE id = $1 FOR UPDATE`, in.ID).Scan(&curVersion); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, fmt.Errorf("lock block page: %w", err)
	}
	if curVersion != in.ExpectedVersion {
		return nil, nil, ErrConflict
	}

	target, err := scanBlockPageVersion(tx.QueryRow(ctx, `
SELECT id, block_page_id, version, editor_mode, theme, visual_config,
       html_content, rendered_html, status_code, json_code, json_message,
       change_note, created_by, created_at
FROM block_page_versions
WHERE block_page_id = $1 AND version = $2`, in.ID, in.TargetVersion))
	if err != nil {
		return nil, nil, err
	}

	visJSON, err := json.Marshal(target.VisualConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal target visual_config: %w", err)
	}
	nextVersion := curVersion + 1
	var (
		p      BlockPage
		visOut []byte
	)
	err = tx.QueryRow(ctx, `
UPDATE block_pages
SET editor_mode = $2, theme = $3, visual_config = $4::jsonb,
    html_content = $5, rendered_html = $6, status_code = $7,
    json_code = $8, json_message = $9, version = $10,
    updated_by = $11, updated_at = now()
WHERE id = $1
RETURNING id, name, description, editor_mode, theme, visual_config, html_content, rendered_html,
          status_code, json_code, json_message, version, is_builtin, created_by, updated_by, created_at, updated_at`,
		in.ID, target.EditorMode, target.Theme, string(visJSON),
		target.HTMLContent, target.RenderedHTML, target.StatusCode,
		target.JSONCode, target.JSONMessage, nextVersion, in.UpdatedBy,
	).Scan(
		&p.ID, &p.Name, &p.Description, &p.EditorMode, &p.Theme,
		&visOut, &p.HTMLContent, &p.RenderedHTML, &p.StatusCode,
		&p.JSONCode, &p.JSONMessage, &p.Version, &p.IsBuiltin,
		&p.CreatedBy, &p.UpdatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("update block page on rollback: %w", err)
	}
	p.VisualConfig = decodeVisualConfig(visOut)
	_ = tx.QueryRow(ctx, `SELECT COUNT(*) FROM block_page_bindings WHERE block_page_id = $1 AND enabled = TRUE`, p.ID).Scan(&p.BindingCount)

	note := strings.TrimSpace(in.ChangeNote)
	if note == "" {
		note = fmt.Sprintf("回滚至历史版本 v%d", in.TargetVersion)
	}
	ver, err := scanBlockPageVersion(tx.QueryRow(ctx, `
INSERT INTO block_page_versions (
	block_page_id, version, editor_mode, theme, visual_config, html_content, rendered_html,
	status_code, json_code, json_message, change_note, created_by
) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$11,$12)
RETURNING id, block_page_id, version, editor_mode, theme, visual_config,
          html_content, rendered_html, status_code, json_code, json_message,
          change_note, created_by, created_at`,
		p.ID, nextVersion, target.EditorMode, target.Theme, string(visJSON),
		target.HTMLContent, target.RenderedHTML, target.StatusCode,
		target.JSONCode, target.JSONMessage, note, in.UpdatedBy,
	))
	if err != nil {
		return nil, nil, fmt.Errorf("insert rollback version: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit rollback block page: %w", err)
	}
	return &p, ver, nil
}

// Delete 删除自定义拦截页模板（禁止删除内置模板或正在被生效绑定引用的模板）。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	var isBuiltin bool
	if err := s.db.QueryRow(ctx, `SELECT is_builtin FROM block_pages WHERE id = $1`, id).Scan(&isBuiltin); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("check block page: %w", err)
	}
	if isBuiltin {
		return ErrBuiltinProtected
	}
	tag, err := s.db.Exec(ctx, `DELETE FROM block_pages WHERE id = $1`, id)
	if err != nil {
		if isForeignKeyViolation(err) {
			return ErrInUse
		}
		return fmt.Errorf("delete block page: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const selectBindingCols = `
	b.id, b.application_id, COALESCE(a.code, ''), COALESCE(a.name, ''),
	b.scene, b.block_page_id, p.name, p.version, b.pinned_version,
	COALESCE(b.pinned_version, p.version) AS effective_version,
	b.enabled, b.updated_by, b.created_at, b.updated_at`

func scanBinding(row pgx.Row) (*BlockPageBinding, error) {
	var b BlockPageBinding
	err := row.Scan(
		&b.ID, &b.ApplicationID, &b.ApplicationCode, &b.ApplicationName,
		&b.Scene, &b.BlockPageID, &b.BlockPageName, &b.BlockPageLatestVersion,
		&b.PinnedVersion, &b.EffectiveVersion, &b.Enabled, &b.UpdatedBy,
		&b.CreatedAt, &b.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &b, nil
}

// ListBindings 查询生效绑定清单（全局在前，其次按应用编码与场景排序）。
func (s *Store) ListBindings(ctx context.Context, filter BindingFilter) ([]BlockPageBinding, error) {
	var (
		conds []string
		args  []interface{}
		idx   = 1
	)
	if filter.GlobalOnly {
		conds = append(conds, "b.application_id IS NULL")
	} else if filter.ApplicationID != nil {
		conds = append(conds, fmt.Sprintf("b.application_id = $%d", idx))
		args = append(args, *filter.ApplicationID)
		idx++
	}
	if filter.Scene != "" {
		conds = append(conds, fmt.Sprintf("b.scene = $%d", idx))
		args = append(args, filter.Scene)
		idx++
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	query := `SELECT ` + selectBindingCols + `
FROM block_page_bindings b
JOIN block_pages p ON p.id = b.block_page_id
LEFT JOIN applications a ON a.id = b.application_id` + where + `
ORDER BY (b.application_id IS NOT NULL) ASC, COALESCE(a.code, '') ASC, b.scene ASC`

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list block page bindings: %w", err)
	}
	defer rows.Close()

	out := make([]BlockPageBinding, 0)
	for rows.Next() {
		var b BlockPageBinding
		if err := rows.Scan(
			&b.ID, &b.ApplicationID, &b.ApplicationCode, &b.ApplicationName,
			&b.Scene, &b.BlockPageID, &b.BlockPageName, &b.BlockPageLatestVersion,
			&b.PinnedVersion, &b.EffectiveVersion, &b.Enabled, &b.UpdatedBy,
			&b.CreatedAt, &b.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan block page binding: %w", err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate block page bindings: %w", err)
	}
	return out, nil
}

// ListBindingsByPage 查询引用某模板的全部绑定。
func (s *Store) ListBindingsByPage(ctx context.Context, pageID uuid.UUID) ([]BlockPageBinding, error) {
	rows, err := s.db.Query(ctx, `SELECT `+selectBindingCols+`
FROM block_page_bindings b
JOIN block_pages p ON p.id = b.block_page_id
LEFT JOIN applications a ON a.id = b.application_id
WHERE b.block_page_id = $1
ORDER BY (b.application_id IS NOT NULL) ASC, COALESCE(a.code, '') ASC, b.scene ASC`, pageID)
	if err != nil {
		return nil, fmt.Errorf("list bindings by page: %w", err)
	}
	defer rows.Close()
	out := make([]BlockPageBinding, 0)
	for rows.Next() {
		var b BlockPageBinding
		if err := rows.Scan(
			&b.ID, &b.ApplicationID, &b.ApplicationCode, &b.ApplicationName,
			&b.Scene, &b.BlockPageID, &b.BlockPageName, &b.BlockPageLatestVersion,
			&b.PinnedVersion, &b.EffectiveVersion, &b.Enabled, &b.UpdatedBy,
			&b.CreatedAt, &b.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan binding: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// GetBindingByID 按 ID 查询单条绑定。
func (s *Store) GetBindingByID(ctx context.Context, id uuid.UUID) (*BlockPageBinding, error) {
	return scanBinding(s.db.QueryRow(ctx, `SELECT `+selectBindingCols+`
FROM block_page_bindings b
JOIN block_pages p ON p.id = b.block_page_id
LEFT JOIN applications a ON a.id = b.application_id
WHERE b.id = $1`, id))
}

// UpsertBinding 创建或更新全局/应用 × 场景的拦截页生效绑定。
func (s *Store) UpsertBinding(ctx context.Context, in UpsertBindingInput) (*BlockPageBinding, error) {
	// 校验目标模板存在，且若锁定版本则该版本必须存在
	if _, err := s.GetByID(ctx, in.BlockPageID); err != nil {
		return nil, err
	}
	if in.PinnedVersion != nil {
		if _, err := s.GetVersion(ctx, in.BlockPageID, *in.PinnedVersion); err != nil {
			return nil, err
		}
	}

	var id uuid.UUID
	if in.ApplicationID == nil {
		err := s.db.QueryRow(ctx, `
INSERT INTO block_page_bindings (application_id, scene, block_page_id, pinned_version, enabled, updated_by)
VALUES (NULL, $1, $2, $3, $4, $5)
ON CONFLICT (COALESCE(application_id, '00000000-0000-0000-0000-000000000000'::uuid), scene)
DO UPDATE SET
	block_page_id = EXCLUDED.block_page_id,
	pinned_version = EXCLUDED.pinned_version,
	enabled = EXCLUDED.enabled,
	updated_by = EXCLUDED.updated_by,
	updated_at = now()
RETURNING id`, in.Scene, in.BlockPageID, in.PinnedVersion, in.Enabled, in.UpdatedBy).Scan(&id)
		if err != nil {
			return nil, fmt.Errorf("upsert global block page binding: %w", err)
		}
	} else {
		err := s.db.QueryRow(ctx, `
INSERT INTO block_page_bindings (application_id, scene, block_page_id, pinned_version, enabled, updated_by)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (COALESCE(application_id, '00000000-0000-0000-0000-000000000000'::uuid), scene)
DO UPDATE SET
	block_page_id = EXCLUDED.block_page_id,
	pinned_version = EXCLUDED.pinned_version,
	enabled = EXCLUDED.enabled,
	updated_by = EXCLUDED.updated_by,
	updated_at = now()
RETURNING id`, *in.ApplicationID, in.Scene, in.BlockPageID, in.PinnedVersion, in.Enabled, in.UpdatedBy).Scan(&id)
		if err != nil {
			return nil, fmt.Errorf("upsert app block page binding: %w", err)
		}
	}
	return s.GetBindingByID(ctx, id)
}

// DeleteBinding 删除单条生效绑定。
func (s *Store) DeleteBinding(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM block_page_bindings WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete block page binding: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
