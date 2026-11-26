// store.go Wasm 自定义检测插件仓储：wasm_plugins 与 wasm_plugin_versions（迁移 000249）。
// 实现 Repository 与 guardconfig.WasmPluginLister 接口。
// 安全红线：List / GetByID / ListVersions 绝不查询或返回 wasm_binary 字节列。
package wasmplugins

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

var (
	// ErrNotFound 插件不存在。
	ErrNotFound = errors.New("wasm plugin not found")
	// ErrVersionNotFound 目标历史版本不存在。
	ErrVersionNotFound = errors.New("wasm plugin version not found")
	// ErrConflict 插件乐观锁版本冲突。
	ErrConflict = errors.New("wasm plugin version conflict")
	// ErrDuplicateName 同一作用域下已存在同名插件。
	ErrDuplicateName = errors.New("wasm plugin name already exists in scope")
	// ErrScopeLimitReached 当前作用域插件数量已达上限（16 个）。
	ErrScopeLimitReached = errors.New("wasm plugin scope limit reached")
	// ErrSHA256Mismatch 期望 SHA-256 与实际二进制摘要不匹配。
	ErrSHA256Mismatch = errors.New("wasm plugin sha256 mismatch")
)

// Repository 定义 Wasm 插件 HTTP 处理器所需的仓储接口（*Store 实现，单测可注入内存桩）。
type Repository interface {
	List(ctx context.Context, filter ListFilter) ([]Plugin, int, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Plugin, error)
	ListVersions(ctx context.Context, pluginID uuid.UUID) ([]PluginVersion, error)
	Create(ctx context.Context, in CreateInput) (*Plugin, error)
	Update(ctx context.Context, in UpdateInput) (*Plugin, error)
	Rollback(ctx context.Context, in RollbackInput) (*Plugin, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// Store 是 Wasm 检测插件 PostgreSQL 仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

var _ Repository = (*Store)(nil)

const pluginMetaColumns = `p.id, p.application_id, COALESCE(a.code, ''), COALESCE(a.name, ''),
	p.name, p.description, p.version, p.abi_version, p.mode, p.sha256, p.wasm_size,
	p.priority, p.timeout_ms, p.max_memory_kb, p.max_body_bytes, p.fail_policy,
	p.path_prefixes, p.updated_by, p.created_at, p.updated_at`

func scanPluginMeta(row pgx.Row) (*Plugin, error) {
	var (
		p            Plugin
		pathRaw      []byte
		updatedBy    *string
		appCode      string
		appName      string
	)
	err := row.Scan(
		&p.ID, &p.ApplicationID, &appCode, &appName,
		&p.Name, &p.Description, &p.Version, &p.ABIVersion, &p.Mode, &p.SHA256, &p.WasmSize,
		&p.Priority, &p.TimeoutMs, &p.MaxMemoryKB, &p.MaxBodyBytes, &p.FailPolicy,
		&pathRaw, &updatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	p.ApplicationCode = appCode
	p.ApplicationName = appName
	if updatedBy != nil {
		p.UpdatedBy = *updatedBy
	}
	p.PathPrefixes = decodePathPrefixes(pathRaw)
	return &p, nil
}

func decodePathPrefixes(raw []byte) []string {
	if len(raw) == 0 {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return []string{}
	}
	return out
}

func escapeLikePattern(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// List 分页查询 Wasm 插件元数据（绝不读取 wasm_binary）。
func (s *Store) List(ctx context.Context, filter ListFilter) ([]Plugin, int, error) {
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

	conds := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if filter.GlobalOnly {
		conds = append(conds, "p.application_id IS NULL")
	} else if filter.ApplicationID != nil {
		conds = append(conds, fmt.Sprintf("p.application_id = $%d", argIdx))
		args = append(args, *filter.ApplicationID)
		argIdx++
	}
	if filter.Mode != "" {
		conds = append(conds, fmt.Sprintf("p.mode = $%d", argIdx))
		args = append(args, filter.Mode)
		argIdx++
	}
	if kw := strings.TrimSpace(filter.Keyword); kw != "" {
		pattern := "%" + escapeLikePattern(kw) + "%"
		conds = append(conds, fmt.Sprintf("(p.name ILIKE $%d ESCAPE '\\' OR p.description ILIKE $%d ESCAPE '\\')", argIdx, argIdx))
		args = append(args, pattern)
		argIdx++
	}
	whereSQL := strings.Join(conds, " AND ")

	var total int
	countSQL := `SELECT COUNT(*) FROM wasm_plugins p WHERE ` + whereSQL
	if err := s.db.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listSQL := fmt.Sprintf(`
SELECT `+pluginMetaColumns+`
FROM wasm_plugins p
LEFT JOIN applications a ON a.id = p.application_id
WHERE %s
ORDER BY p.priority ASC, p.name ASC, p.created_at DESC
LIMIT $%d OFFSET $%d`, whereSQL, argIdx, argIdx+1)
	args = append(args, pageSize, (page-1)*pageSize)

	rows, err := s.db.Query(ctx, listSQL, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]Plugin, 0)
	for rows.Next() {
		p, err := scanPluginMeta(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, *p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// GetByID 按 ID 查询插件元数据（绝不读取 wasm_binary）。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Plugin, error) {
	row := s.db.QueryRow(ctx, `
SELECT `+pluginMetaColumns+`
FROM wasm_plugins p
LEFT JOIN applications a ON a.id = p.application_id
WHERE p.id = $1`, id)
	return scanPluginMeta(row)
}

// ListVersions 查询指定插件的全部不可变版本历史（按版本号降序，绝不读取 wasm_binary）。
func (s *Store) ListVersions(ctx context.Context, pluginID uuid.UUID) ([]PluginVersion, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, version, abi_version, mode, sha256, wasm_size, reason, created_by, created_at
FROM wasm_plugin_versions
WHERE plugin_id = $1
ORDER BY version DESC`, pluginID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	versions := make([]PluginVersion, 0)
	for rows.Next() {
		var (
			v         PluginVersion
			createdBy *string
		)
		if err := rows.Scan(
			&v.ID, &v.Version, &v.ABIVersion, &v.Mode, &v.SHA256,
			&v.WasmSize, &v.Reason, &createdBy, &v.CreatedAt,
		); err != nil {
			return nil, err
		}
		if createdBy != nil {
			v.CreatedBy = *createdBy
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return versions, nil
}

// Create 在单事务中校验作用域上限（<=16）、插入 wasm_plugins(v1) 与不可变 wasm_plugin_versions(v1)。
func (s *Store) Create(ctx context.Context, in CreateInput) (*Plugin, error) {
	if in.ABIVersion == "" {
		in.ABIVersion = ABIVersionWDSPV1
	}
	prefixes := NormalizePathPrefixes(in.PathPrefixes)
	prefixesJSON, err := json.Marshal(prefixes)
	if err != nil {
		return nil, err
	}
	snapJSON, err := json.Marshal(ConfigSnapshot{
		Description:  in.Description,
		Priority:     in.Priority,
		TimeoutMs:    in.TimeoutMs,
		MaxMemoryKB:  in.MaxMemoryKB,
		MaxBodyBytes: in.MaxBodyBytes,
		FailPolicy:   in.FailPolicy,
		PathPrefixes: prefixes,
	})
	if err != nil {
		return nil, err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 按作用域加事务级咨询锁，防止并发创建突破 16 个上限
	scopeKey := "global"
	if in.ApplicationID != nil {
		scopeKey = in.ApplicationID.String()
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "wasm_plugins_scope:"+scopeKey); err != nil {
		return nil, err
	}

	var scopeCount int
	if in.ApplicationID == nil {
		err = tx.QueryRow(ctx, `SELECT COUNT(*) FROM wasm_plugins WHERE application_id IS NULL`).Scan(&scopeCount)
	} else {
		err = tx.QueryRow(ctx, `SELECT COUNT(*) FROM wasm_plugins WHERE application_id = $1`, *in.ApplicationID).Scan(&scopeCount)
	}
	if err != nil {
		return nil, err
	}
	if scopeCount >= MaxPluginsPerScope {
		return nil, ErrScopeLimitReached
	}

	var pluginID uuid.UUID
	wasmSize := len(in.WasmBinary)
	err = tx.QueryRow(ctx, `
INSERT INTO wasm_plugins (
	application_id, name, description, version, abi_version, mode,
	sha256, wasm_size, wasm_binary, priority, timeout_ms,
	max_memory_kb, max_body_bytes, fail_policy, path_prefixes, updated_by
) VALUES ($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15)
RETURNING id`,
		in.ApplicationID, in.Name, in.Description, in.ABIVersion, in.Mode,
		in.SHA256, wasmSize, in.WasmBinary, in.Priority, in.TimeoutMs,
		in.MaxMemoryKB, in.MaxBodyBytes, in.FailPolicy, string(prefixesJSON), in.CreatedBy,
	).Scan(&pluginID)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrDuplicateName
		}
		return nil, err
	}

	if _, err := tx.Exec(ctx, `
INSERT INTO wasm_plugin_versions (
	plugin_id, version, abi_version, mode, sha256, wasm_size,
	wasm_binary, config_snapshot, reason, created_by
) VALUES ($1,1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)`,
		pluginID, in.ABIVersion, in.Mode, in.SHA256, wasmSize,
		in.WasmBinary, string(snapJSON), in.Reason, in.CreatedBy,
	); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetByID(ctx, pluginID)
}

// Update 在单事务中执行乐观锁更新并追加不可变版本历史（WasmBinary 为空时保留现有二进制）。
func (s *Store) Update(ctx context.Context, in UpdateInput) (*Plugin, error) {
	prefixes := NormalizePathPrefixes(in.PathPrefixes)
	prefixesJSON, err := json.Marshal(prefixes)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		curVersion     int
		curDescription string
		curABIVersion  string
		curSHA256      string
		curWasmSize    int
		curBinary      []byte
	)
	err = tx.QueryRow(ctx, `
SELECT version, description, abi_version, sha256, wasm_size, wasm_binary
FROM wasm_plugins
WHERE id = $1
FOR UPDATE`, in.ID).Scan(&curVersion, &curDescription, &curABIVersion, &curSHA256, &curWasmSize, &curBinary)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if curVersion != in.ExpectedVersion {
		return nil, ErrConflict
	}

	finalDescription := curDescription
	if in.Description != nil {
		finalDescription = *in.Description
	}
	finalBinary := curBinary
	finalSHA256 := curSHA256
	finalSize := curWasmSize
	if len(in.WasmBinary) > 0 {
		finalBinary = in.WasmBinary
		finalSHA256 = in.SHA256
		finalSize = len(in.WasmBinary)
	} else if in.ExpectedSHA256 != "" {
		if msg := VerifySHA256ConstantTime(in.ExpectedSHA256, curSHA256); msg != "" {
			return nil, ErrSHA256Mismatch
		}
	}

	snapJSON, err := json.Marshal(ConfigSnapshot{
		Description:  finalDescription,
		Priority:     in.Priority,
		TimeoutMs:    in.TimeoutMs,
		MaxMemoryKB:  in.MaxMemoryKB,
		MaxBodyBytes: in.MaxBodyBytes,
		FailPolicy:   in.FailPolicy,
		PathPrefixes: prefixes,
	})
	if err != nil {
		return nil, err
	}

	var newVersion int
	err = tx.QueryRow(ctx, `
UPDATE wasm_plugins SET
	description=$1, mode=$2, sha256=$3, wasm_size=$4, wasm_binary=$5,
	priority=$6, timeout_ms=$7, max_memory_kb=$8, max_body_bytes=$9,
	fail_policy=$10, path_prefixes=$11::jsonb, updated_by=$12,
	updated_at=now(), version=version+1
WHERE id=$13 AND version=$14
RETURNING version`,
		finalDescription, in.Mode, finalSHA256, finalSize, finalBinary,
		in.Priority, in.TimeoutMs, in.MaxMemoryKB, in.MaxBodyBytes,
		in.FailPolicy, string(prefixesJSON), in.UpdatedBy,
		in.ID, in.ExpectedVersion,
	).Scan(&newVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrConflict
		}
		return nil, err
	}

	if _, err := tx.Exec(ctx, `
INSERT INTO wasm_plugin_versions (
	plugin_id, version, abi_version, mode, sha256, wasm_size,
	wasm_binary, config_snapshot, reason, created_by
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10)`,
		in.ID, newVersion, curABIVersion, in.Mode, finalSHA256, finalSize,
		finalBinary, string(snapJSON), in.Reason, in.UpdatedBy,
	); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetByID(ctx, in.ID)
}

// Rollback 将指定历史版本的二进制与配置快照克隆为 version+1 新版本（乐观锁冲突返回 ErrConflict，绝不覆盖旧历史）。
func (s *Store) Rollback(ctx context.Context, in RollbackInput) (*Plugin, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var curVersion int
	if err := tx.QueryRow(ctx, `SELECT version FROM wasm_plugins WHERE id = $1 FOR UPDATE`, in.ID).Scan(&curVersion); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if curVersion != in.ExpectedVersion {
		return nil, ErrConflict
	}

	var (
		targetABI      string
		targetMode     string
		targetSHA256   string
		targetSize     int
		targetBinary   []byte
		targetSnapRaw  []byte
	)
	err = tx.QueryRow(ctx, `
SELECT abi_version, mode, sha256, wasm_size, wasm_binary, config_snapshot
FROM wasm_plugin_versions
WHERE plugin_id = $1 AND version = $2`, in.ID, in.TargetVersion).Scan(
		&targetABI, &targetMode, &targetSHA256, &targetSize, &targetBinary, &targetSnapRaw,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrVersionNotFound
		}
		return nil, err
	}
	if msg := VerifySHA256ConstantTime(targetSHA256, ComputeSHA256Hex(targetBinary)); msg != "" {
		return nil, fmt.Errorf("rollback target version %d integrity check failed: %s", in.TargetVersion, msg)
	}
	if err := ValidateWasmBinary(targetBinary); err != nil {
		return nil, fmt.Errorf("rollback target version %d binary invalid: %w", in.TargetVersion, err)
	}

	snap := ConfigSnapshot{
		Priority:     DefaultPriority,
		TimeoutMs:    DefaultTimeoutMs,
		MaxMemoryKB:  DefaultMaxMemoryKB,
		MaxBodyBytes: DefaultMaxBodyBytes,
		FailPolicy:   FailPolicyOpen,
		PathPrefixes: []string{},
	}
	if len(targetSnapRaw) > 0 {
		if err := json.Unmarshal(targetSnapRaw, &snap); err != nil {
			return nil, fmt.Errorf("decode target config_snapshot: %w", err)
		}
	}
	snap.PathPrefixes = NormalizePathPrefixes(snap.PathPrefixes)
	prefixesJSON, err := json.Marshal(snap.PathPrefixes)
	if err != nil {
		return nil, err
	}
	clonedSnapJSON, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}

	var newVersion int
	err = tx.QueryRow(ctx, `
UPDATE wasm_plugins SET
	description=$1, abi_version=$2, mode=$3, sha256=$4, wasm_size=$5, wasm_binary=$6,
	priority=$7, timeout_ms=$8, max_memory_kb=$9, max_body_bytes=$10,
	fail_policy=$11, path_prefixes=$12::jsonb, updated_by=$13,
	updated_at=now(), version=version+1
WHERE id=$14 AND version=$15
RETURNING version`,
		snap.Description, targetABI, targetMode, targetSHA256, len(targetBinary), targetBinary,
		snap.Priority, snap.TimeoutMs, snap.MaxMemoryKB, snap.MaxBodyBytes,
		snap.FailPolicy, string(prefixesJSON), in.UpdatedBy,
		in.ID, in.ExpectedVersion,
	).Scan(&newVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrConflict
		}
		return nil, err
	}

	if _, err := tx.Exec(ctx, `
INSERT INTO wasm_plugin_versions (
	plugin_id, version, abi_version, mode, sha256, wasm_size,
	wasm_binary, config_snapshot, reason, created_by
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10)`,
		in.ID, newVersion, targetABI, targetMode, targetSHA256, len(targetBinary),
		targetBinary, string(clonedSnapJSON), in.Reason, in.UpdatedBy,
	); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetByID(ctx, in.ID)
}

// Delete 删除指定插件（级联清理不可变版本表）。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM wasm_plugins WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AppScope 表示编译网关配置时的单个有效应用标识。
type AppScope struct {
	ID   uuid.UUID
	Code string
}

// GuardPluginRow 表示数据库中的原始 Wasm 插件记录（供纯函数 CompileForGuard 装配与单测）。
type GuardPluginRow struct {
	ID            uuid.UUID
	ApplicationID *uuid.UUID
	Name          string
	Version       int
	ABIVersion    string
	Mode          string
	SHA256        string
	WasmBinary    []byte
	Priority      int
	TimeoutMs     int
	MaxMemoryKB   int
	MaxBodyBytes  int
	FailPolicy    string
	PathPrefixes  []string
}

// ListForGuard 读取全部全局与应用级插件并按应用编译为网关冻结契约（实现 guardconfig.WasmPluginLister；
// key=应用编码，合并全局+应用级插件并按 priority 升序稳定排序，二进制以标准 Base64 编码）。
func (s *Store) ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardWasmPluginsConfig, error) {
	appRows, err := s.db.Query(ctx, `
SELECT id, code FROM applications WHERE deleted_at IS NULL ORDER BY code ASC`)
	if err != nil {
		return nil, err
	}
	defer appRows.Close()

	apps := make([]AppScope, 0)
	for appRows.Next() {
		var a AppScope
		if err := appRows.Scan(&a.ID, &a.Code); err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	if err := appRows.Err(); err != nil {
		return nil, err
	}

	pluginRows, err := s.db.Query(ctx, `
SELECT id, application_id, name, version, abi_version, mode, sha256, wasm_binary,
	priority, timeout_ms, max_memory_kb, max_body_bytes, fail_policy, path_prefixes
FROM wasm_plugins
ORDER BY priority ASC, name ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer pluginRows.Close()

	rows := make([]GuardPluginRow, 0)
	for pluginRows.Next() {
		var (
			r       GuardPluginRow
			pathRaw []byte
		)
		if err := pluginRows.Scan(
			&r.ID, &r.ApplicationID, &r.Name, &r.Version, &r.ABIVersion, &r.Mode,
			&r.SHA256, &r.WasmBinary, &r.Priority, &r.TimeoutMs, &r.MaxMemoryKB,
			&r.MaxBodyBytes, &r.FailPolicy, &pathRaw,
		); err != nil {
			return nil, err
		}
		r.PathPrefixes = decodePathPrefixes(pathRaw)
		rows = append(rows, r)
	}
	if err := pluginRows.Err(); err != nil {
		return nil, err
	}

	return CompileForGuard(apps, rows)
}

// CompileForGuard 将原始插件行按应用编译为网关冻结契约（纯函数，便于单测验证合并与排序语义）。
func CompileForGuard(apps []AppScope, rows []GuardPluginRow) (map[string]*gatewayconfig.GuardWasmPluginsConfig, error) {
	if len(rows) == 0 || len(apps) == 0 {
		return map[string]*gatewayconfig.GuardWasmPluginsConfig{}, nil
	}

	var globalPlugins []gatewayconfig.GuardWasmPlugin
	appPlugins := make(map[uuid.UUID][]gatewayconfig.GuardWasmPlugin)

	for _, r := range rows {
		actualSHA := ComputeSHA256Hex(r.WasmBinary)
		if msg := VerifySHA256ConstantTime(r.SHA256, actualSHA); msg != "" {
			return nil, fmt.Errorf("wasm plugin %s (%s) SHA-256 完整性校验失败: %s", r.Name, r.ID, msg)
		}
		gp := gatewayconfig.GuardWasmPlugin{
			ID:           r.ID.String(),
			Name:         r.Name,
			Version:      r.Version,
			ABIVersion:   r.ABIVersion,
			Mode:         r.Mode,
			SHA256:       strings.ToLower(strings.TrimSpace(r.SHA256)),
			WasmBase64:   base64.StdEncoding.EncodeToString(r.WasmBinary),
			Priority:     r.Priority,
			TimeoutMs:    r.TimeoutMs,
			MaxMemoryKB:  r.MaxMemoryKB,
			MaxBodyBytes: r.MaxBodyBytes,
			FailPolicy:   r.FailPolicy,
			PathPrefixes: NormalizePathPrefixes(r.PathPrefixes),
		}
		if r.ApplicationID == nil {
			globalPlugins = append(globalPlugins, gp)
		} else {
			appPlugins[*r.ApplicationID] = append(appPlugins[*r.ApplicationID], gp)
		}
	}

	out := make(map[string]*gatewayconfig.GuardWasmPluginsConfig, len(apps))
	for _, app := range apps {
		specific := appPlugins[app.ID]
		total := len(globalPlugins) + len(specific)
		if total == 0 {
			continue
		}
		if total > MaxPluginsPerScope {
			return nil, fmt.Errorf("应用 %s 合并全局与应用级 Wasm 插件总数 %d 超过上限 %d", app.Code, total, MaxPluginsPerScope)
		}
		merged := make([]gatewayconfig.GuardWasmPlugin, 0, total)
		for _, gp := range globalPlugins {
			cp := gp
			cp.PathPrefixes = append([]string(nil), gp.PathPrefixes...)
			merged = append(merged, cp)
		}
		for _, gp := range specific {
			cp := gp
			cp.PathPrefixes = append([]string(nil), gp.PathPrefixes...)
			merged = append(merged, cp)
		}
		sort.SliceStable(merged, func(i, j int) bool {
			if merged[i].Priority != merged[j].Priority {
				return merged[i].Priority < merged[j].Priority
			}
			if merged[i].Name != merged[j].Name {
				return merged[i].Name < merged[j].Name
			}
			return merged[i].ID < merged[j].ID
		})
		out[app.Code] = &gatewayconfig.GuardWasmPluginsConfig{
			SchemaVersion: SchemaVersion,
			ApplicationID: app.ID.String(),
			Plugins:       merged,
		}
	}
	return out, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
