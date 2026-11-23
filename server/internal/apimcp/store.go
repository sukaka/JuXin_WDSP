// store.go MCP 目录与绑定 PostgreSQL 仓储（NG-MCP G1 批次 B1）：目录 CRUD
// （整体替换语义工具行 + 语义相等判定（M02 幂等重导不重置/变更重算 tool_hash
// 重置待审核）+ 审核状态机 + catalog_hash 维护）+ 绑定 CRUD。写路径全部事务化
// （目录整体替换与绑定写操作同生共死，不留半状态；FK 冲突映射友好哨兵）。
package apimcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// Repository 目录与绑定仓储接口（*Store 实现；包内单测注入内存 fake——
// 事务/唯一键/FK 语义由 PG 契约测试覆盖）。
type Repository interface {
	CreateCatalog(ctx context.Context, in CatalogInput, createdBy string) (*Catalog, []Tool, error)
	ListCatalogs(ctx context.Context) ([]CatalogSummary, error)
	GetCatalog(ctx context.Context, id uuid.UUID) (*Catalog, []Tool, error)
	UpdateCatalog(ctx context.Context, id uuid.UUID, in CatalogInput) (*Catalog, []Tool, error)
	DeleteCatalog(ctx context.Context, id uuid.UUID) error
	ReviewTool(ctx context.Context, catalogID, toolID uuid.UUID, in ReviewInput, reviewedBy string) (*Tool, error)

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

const catalogCols = `id, name, service_identity, protocol_version, source, status, catalog_hash, version, COALESCE(created_by,''), created_at, updated_at`

func scanCatalog(row pgx.Row) (Catalog, error) {
	var c Catalog
	err := row.Scan(&c.ID, &c.Name, &c.ServiceIdentity, &c.ProtocolVersion, &c.Source,
		&c.Status, &c.CatalogHash, &c.Version, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

const toolCols = `id, catalog_id, tool_name, tool_version, description_digest, description_preview,
	input_schema, output_schema, input_schema_digest, output_schema_digest, tool_hash, capability_tags,
	risk_level, data_classification, allowed_principals, allowed_roles, allowed_tenants,
	approval_required, max_calls_per_minute, arg_constraints, review_status,
	COALESCE(reviewed_by,''), reviewed_at, created_at, updated_at`

func scanTool(rows pgx.Rows) (Tool, error) {
	var t Tool
	var inSchema, outSchema, tags, principals, roles, tenants, constraints []byte
	var reviewedAt *time.Time
	err := rows.Scan(&t.ID, &t.CatalogID, &t.ToolName, &t.ToolVersion, &t.DescriptionDigest, &t.DescriptionPreview,
		&inSchema, &outSchema, &t.InputSchemaDigest, &t.OutputSchemaDigest, &t.ToolHash, &tags,
		&t.RiskLevel, &t.DataClassification, &principals, &roles, &tenants,
		&t.ApprovalRequired, &t.MaxCallsPerMinute, &constraints, &t.ReviewStatus,
		&t.ReviewedBy, &reviewedAt, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return t, err
	}
	t.InputSchema = decodeSchema(inSchema)
	t.OutputSchema = decodeSchema(outSchema)
	t.CapabilityTags = decodeStrings(tags)
	t.AllowedPrincipals = decodeStrings(principals)
	t.AllowedRoles = decodeStrings(roles)
	t.AllowedTenants = decodeStrings(tenants)
	t.ArgConstraints = decodeConstraints(constraints)
	t.ReviewedAt = reviewedAt
	return t, nil
}

func decodeSchema(raw []byte) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil
	}
	return m
}

func decodeStrings(raw []byte) []string {
	out := []string{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

func decodeConstraints(raw []byte) []ArgConstraint {
	out := []ArgConstraint{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

// toolWriteRow 工具行入库参数（tool_hash/digests 已算好）。
type toolWriteRow struct {
	in             ToolInput
	digestDesc     string
	preview        string
	inSchema       []byte
	outSchema      []byte
	inDigest       string
	outDigest      string
	toolHash       string
	tags           []byte
	risk           string
	classification string
	principals     []byte
	roles          []byte
	tenants        []byte
	constraints    []byte
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

var emptyDescDigest = sha256Hex("")

// prepareToolRow 工具载荷→入库参数（规范化+digest+tool_hash；risk/classification 归一）。
// 当 preserve_description 为 true、in.Description 为空且存在旧行 existing 时，复用旧行的
// description_digest 与 description_preview，使未改版本/Schema 的再导入保持语义相等与审核态；
// 若版本或 Schema 发生变更且旧行存在非空描述（库内未存全文），拒绝写入不一致的 tool_hash。
func prepareToolRow(in ToolInput, existing *Tool) (toolWriteRow, error) {
	desc := strings.TrimSpace(in.Description)
	r := toolWriteRow{in: in}
	preserving := existing != nil && in.PreserveDescription && desc == ""
	if preserving {
		r.digestDesc = existing.DescriptionDigest
		r.preview = existing.DescriptionPreview
	} else {
		r.digestDesc = sha256Hex(desc)
		if len(desc) > maxPreviewLen {
			r.preview = desc[:maxPreviewLen]
		} else {
			r.preview = desc
		}
	}
	var err error
	if in.InputSchema != nil {
		if r.inSchema, err = json.Marshal(in.InputSchema); err != nil {
			return r, fmt.Errorf("input_schema 序列化失败: %w", err)
		}
		if len(r.inSchema) > maxSchemaBytes {
			return r, invalidf("tool %q input_schema 超 %d 字节", in.ToolName, maxSchemaBytes)
		}
		s := sha256.Sum256(r.inSchema)
		r.inDigest = hex.EncodeToString(s[:])
	}
	if in.OutputSchema != nil {
		if r.outSchema, err = json.Marshal(in.OutputSchema); err != nil {
			return r, fmt.Errorf("output_schema 序列化失败: %w", err)
		}
		if len(r.outSchema) > maxSchemaBytes {
			return r, invalidf("tool %q output_schema 超 %d 字节", in.ToolName, maxSchemaBytes)
		}
		s := sha256.Sum256(r.outSchema)
		r.outDigest = hex.EncodeToString(s[:])
	}
	if preserving && existing.DescriptionDigest != emptyDescDigest {
		if !toolSemanticallyEqual(*existing, strings.TrimSpace(in.ToolVersion), existing.DescriptionDigest,
			nilSchemaP(in.InputSchema), nilSchemaP(in.OutputSchema)) {
			return r, invalidf("tool %q 版本或 Schema 变更时须重新填写完整描述以重算 tool_hash", strings.TrimSpace(in.ToolName))
		}
		r.toolHash = existing.ToolHash
	} else if r.toolHash, err = ComputeToolHash(strings.TrimSpace(in.ToolName), strings.TrimSpace(in.ToolVersion), desc,
		nilSchemaP(in.InputSchema), nilSchemaP(in.OutputSchema)); err != nil {
		return r, err
	}
	if r.tags, err = json.Marshal(orEmpty(in.CapabilityTags)); err != nil {
		return r, err
	}
	r.risk = orDefault(strings.ToUpper(strings.TrimSpace(in.RiskLevel)), RiskHigh)
	r.classification = orDefault(strings.ToUpper(strings.TrimSpace(in.DataClassification)), ClassUnknown)
	if r.principals, err = json.Marshal(orEmpty(in.AllowedPrincipals)); err != nil {
		return r, err
	}
	if r.roles, err = json.Marshal(orEmpty(in.AllowedRoles)); err != nil {
		return r, err
	}
	if r.tenants, err = json.Marshal(orEmpty(in.AllowedTenants)); err != nil {
		return r, err
	}
	if r.constraints, err = json.Marshal(orEmpty(in.ArgConstraints)); err != nil {
		return r, err
	}
	return r, nil
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// replaceToolsTx 事务内整体替换工具行（语义相等判定（M02）：
// 按 (catalog_id, tool_name) 匹配存量——语义相等行保留 tool_hash/review_status/
// reviewed_*/created_at（幂等重导不重置）；语义不等/新增行落 PENDING_REVIEW
// （重算 tool_hash——旧审批不继承）；消失行删除。返回替换后全量工具行。
func (s *Store) replaceToolsTx(ctx context.Context, tx pgx.Tx, catalogID uuid.UUID, tools []ToolInput) ([]Tool, error) {
	existing := map[string]Tool{}
	rows, err := tx.Query(ctx, `SELECT `+toolCols+` FROM mcp_catalog_tools WHERE catalog_id=$1`, catalogID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		t, err := scanTool(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		existing[t.ToolName] = t
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	keep := map[string]bool{}
	for _, in := range tools {
		name := strings.TrimSpace(in.ToolName)
		keep[name] = true
		var existingPtr *Tool
		if old, ok := existing[name]; ok {
			existingPtr = &old
		}
		row, err := prepareToolRow(in, existingPtr)
		if err != nil {
			return nil, err
		}
		if existingPtr != nil &&
			toolSemanticallyEqual(*existingPtr, strings.TrimSpace(in.ToolVersion), row.digestDesc,
				nilSchemaP(in.InputSchema), nilSchemaP(in.OutputSchema)) {
			// 语义相等：更新非摘要维度（审核可调字段/标签/约束）但保留 tool_hash 与审核态
			if err := updateToolPreserved(ctx, tx, *existingPtr, row); err != nil {
				return nil, err
			}
			continue
		}
		// 新增或语义变更：upsert 为 PENDING_REVIEW（reviewed_* 清空，created_at 保留（更新时））
		if err := upsertToolPending(ctx, tx, catalogID, name, row); err != nil {
			return nil, err
		}
	}
	// 消失行删除
	for name := range existing {
		if !keep[name] {
			if _, err := tx.Exec(ctx, `DELETE FROM mcp_catalog_tools WHERE catalog_id=$1 AND tool_name=$2`, catalogID, name); err != nil {
				return nil, err
			}
		}
	}
	// 回读全量
	return s.listToolsTx(ctx, tx, catalogID)
}

func updateToolPreserved(ctx context.Context, tx pgx.Tx, old Tool, row toolWriteRow) error {
	_, err := tx.Exec(ctx, `UPDATE mcp_catalog_tools SET
		capability_tags=$3, allowed_principals=$4, allowed_roles=$5, allowed_tenants=$6,
		approval_required=$7, max_calls_per_minute=$8, arg_constraints=$9,
		description_digest=$10, description_preview=$11, updated_at=now()
		WHERE id=$1 AND catalog_id=$2`,
		old.ID, old.CatalogID, row.tags, row.principals, row.roles, row.tenants,
		row.in.ApprovalRequired, row.in.MaxCallsPerMinute, row.constraints,
		row.digestDesc, row.preview)
	return err
}

func upsertToolPending(ctx context.Context, tx pgx.Tx, catalogID uuid.UUID, name string, row toolWriteRow) error {
	_, err := tx.Exec(ctx, `INSERT INTO mcp_catalog_tools
		(catalog_id, tool_name, tool_version, description_digest, description_preview,
		 input_schema, output_schema, input_schema_digest, output_schema_digest, tool_hash,
		 capability_tags, risk_level, data_classification, allowed_principals, allowed_roles,
		 allowed_tenants, approval_required, max_calls_per_minute, arg_constraints, review_status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,'PENDING_REVIEW')
		ON CONFLICT (catalog_id, tool_name) DO UPDATE SET
			tool_version=EXCLUDED.tool_version, description_digest=EXCLUDED.description_digest,
			description_preview=EXCLUDED.description_preview,
			input_schema=EXCLUDED.input_schema, output_schema=EXCLUDED.output_schema,
			input_schema_digest=EXCLUDED.input_schema_digest, output_schema_digest=EXCLUDED.output_schema_digest,
			tool_hash=EXCLUDED.tool_hash, capability_tags=EXCLUDED.capability_tags,
			risk_level=EXCLUDED.risk_level, data_classification=EXCLUDED.data_classification,
			allowed_principals=EXCLUDED.allowed_principals, allowed_roles=EXCLUDED.allowed_roles,
			allowed_tenants=EXCLUDED.allowed_tenants, approval_required=EXCLUDED.approval_required,
			max_calls_per_minute=EXCLUDED.max_calls_per_minute, arg_constraints=EXCLUDED.arg_constraints,
			review_status='PENDING_REVIEW', reviewed_by=NULL, reviewed_at=NULL, updated_at=now()`,
		catalogID, name, strings.TrimSpace(row.in.ToolVersion), row.digestDesc, row.preview,
		bytesOrNil(row.inSchema), bytesOrNil(row.outSchema), row.inDigest, row.outDigest, row.toolHash,
		row.tags, row.risk, row.classification, row.principals, row.roles,
		row.tenants, row.in.ApprovalRequired, row.in.MaxCallsPerMinute, row.constraints)
	return err
}

func bytesOrNil(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

func (s *Store) listToolsTx(ctx context.Context, tx pgx.Tx, catalogID uuid.UUID) ([]Tool, error) {
	rows, err := tx.Query(ctx, `SELECT `+toolCols+` FROM mcp_catalog_tools WHERE catalog_id=$1 ORDER BY tool_name`, catalogID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Tool{}
	for rows.Next() {
		t, err := scanTool(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// refreshCatalogHashTx 事务内重算 catalog_hash（当前 APPROVED 集 tool_hash 排序拼接——
// 发布集摘要与 DB 始终一致（M02/审核/导入后调用）。
func refreshCatalogHashTx(ctx context.Context, tx pgx.Tx, catalogID uuid.UUID) error {
	rows, err := tx.Query(ctx, `SELECT tool_hash FROM mcp_catalog_tools
		WHERE catalog_id=$1 AND review_status='APPROVED' ORDER BY tool_hash`, catalogID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return err
		}
		hashes = append(hashes, h)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE mcp_tool_catalogs SET catalog_hash=$2, updated_at=now() WHERE id=$1`,
		catalogID, ComputeCatalogHash(hashes))
	return err
}

// CreateCatalog 显式导入目录（同事务建目录+工具行+catalog_hash；同名 409）。
func (s *Store) CreateCatalog(ctx context.Context, in CatalogInput, createdBy string) (*Catalog, []Tool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	pv := orDefault(strings.TrimSpace(in.ProtocolVersion), ProtocolVersionDefault)
	var c Catalog
	err = tx.QueryRow(ctx, `INSERT INTO mcp_tool_catalogs
		(name, service_identity, protocol_version, created_by) VALUES ($1,$2,$3,$4) RETURNING `+catalogCols,
		strings.TrimSpace(in.Name), strings.TrimSpace(in.ServiceIdentity), pv, createdBy).Scan(
		&c.ID, &c.Name, &c.ServiceIdentity, &c.ProtocolVersion, &c.Source,
		&c.Status, &c.CatalogHash, &c.Version, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return nil, nil, ErrDuplicateName
		}
		return nil, nil, err
	}
	tools, err := s.replaceToolsTx(ctx, tx, c.ID, in.Tools)
	if err != nil {
		return nil, nil, err
	}
	if err := refreshCatalogHashTx(ctx, tx, c.ID); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	c.CatalogHash = ComputeCatalogHash(approvedHashes(tools))
	return &c, tools, nil
}

func approvedHashes(tools []Tool) []string {
	var out []string
	for _, t := range tools {
		if t.ReviewStatus == ReviewApproved {
			out = append(out, t.ToolHash)
		}
	}
	return out
}

// ListCatalogs 目录列表（含审核统计；name 稳定序）。
func (s *Store) ListCatalogs(ctx context.Context) ([]CatalogSummary, error) {
	rows, err := s.db.Query(ctx, `SELECT `+catalogCols+`,
		(SELECT count(*) FROM mcp_catalog_tools t WHERE t.catalog_id=c.id),
		(SELECT count(*) FROM mcp_catalog_tools t WHERE t.catalog_id=c.id AND t.review_status='APPROVED'),
		(SELECT count(*) FROM mcp_catalog_tools t WHERE t.catalog_id=c.id AND t.review_status='PENDING_REVIEW'),
		(SELECT count(*) FROM mcp_catalog_tools t WHERE t.catalog_id=c.id AND t.review_status='REJECTED')
		FROM mcp_tool_catalogs c ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CatalogSummary{}
	for rows.Next() {
		var s2 CatalogSummary
		if err := rows.Scan(&s2.ID, &s2.Name, &s2.ServiceIdentity, &s2.ProtocolVersion, &s2.Source,
			&s2.Status, &s2.CatalogHash, &s2.Version, &s2.CreatedBy, &s2.CreatedAt, &s2.UpdatedAt,
			&s2.ToolCount, &s2.ApprovedCount, &s2.PendingCount, &s2.RejectedCount); err != nil {
			return nil, err
		}
		out = append(out, s2)
	}
	return out, rows.Err()
}

// GetCatalog 目录详情（定义+工具行）。
func (s *Store) GetCatalog(ctx context.Context, id uuid.UUID) (*Catalog, []Tool, error) {
	c, err := scanCatalog(s.db.QueryRow(ctx, `SELECT `+catalogCols+` FROM mcp_tool_catalogs WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tools, err := s.listToolsTx(ctx, tx, id)
	if err != nil {
		return nil, nil, err
	}
	return &c, tools, tx.Commit(ctx)
}

// UpdateCatalog 整体再导入/更新（乐观锁；语义相等行保留审核态，变更行重置待审核）。
func (s *Store) UpdateCatalog(ctx context.Context, id uuid.UUID, in CatalogInput) (*Catalog, []Tool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	ct, err := tx.Exec(ctx, `UPDATE mcp_tool_catalogs SET
		name=$3, service_identity=$4, protocol_version=$5, version=version+1, updated_at=now()
		WHERE id=$1 AND version=$2`,
		id, in.Version, strings.TrimSpace(in.Name), strings.TrimSpace(in.ServiceIdentity),
		orDefault(strings.TrimSpace(in.ProtocolVersion), ProtocolVersionDefault))
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" && (pe.ConstraintName == "" || pe.ConstraintName == "uq_mcp_tool_catalogs_name") {
			return nil, nil, ErrDuplicateName
		}
		return nil, nil, err
	}
	if ct.RowsAffected() == 0 {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mcp_tool_catalogs WHERE id=$1)`, id).Scan(&exists); err != nil {
			return nil, nil, err
		}
		if !exists {
			return nil, nil, ErrNotFound
		}
		return nil, nil, ErrVersionConflict
	}
	tools, err := s.replaceToolsTx(ctx, tx, id, in.Tools)
	if err != nil {
		return nil, nil, err
	}
	if err := refreshCatalogHashTx(ctx, tx, id); err != nil {
		return nil, nil, err
	}
	c, err := scanCatalog(tx.QueryRow(ctx, `SELECT `+catalogCols+` FROM mcp_tool_catalogs WHERE id=$1`, id))
	if err != nil {
		return nil, nil, err
	}
	return &c, tools, tx.Commit(ctx)
}

// DeleteCatalog 删除目录（绑定引用先决校验 409 ErrCatalogInUse——FK 级联前管理面门禁）。
func (s *Store) DeleteCatalog(ctx context.Context, id uuid.UUID) error {
	var refs int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM mcp_catalog_bindings WHERE catalog_id=$1`, id).Scan(&refs); err != nil {
		return err
	}
	if refs > 0 {
		return ErrCatalogInUse
	}
	ct, err := s.db.Exec(ctx, `DELETE FROM mcp_tool_catalogs WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ReviewTool 审核（APPROVED/REJECTED + 定级更新；同事务重算 catalog_hash）。
func (s *Store) ReviewTool(ctx context.Context, catalogID, toolID uuid.UUID, in ReviewInput, reviewedBy string) (*Tool, error) {
	action := strings.ToUpper(strings.TrimSpace(in.Action))
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// 定级字段更新（仅给出字段；risk/classification 词表在 handler 已校）
	sets := []string{"review_status=$3", "reviewed_by=$4", "reviewed_at=now()", "updated_at=now()"}
	args := []any{toolID, catalogID, action, reviewedBy}
	if v := strings.ToUpper(strings.TrimSpace(in.RiskLevel)); v != "" {
		sets = append(sets, "risk_level=$"+itoa(len(args)+1))
		args = append(args, v)
	}
	if v := strings.ToUpper(strings.TrimSpace(in.DataClassification)); v != "" {
		sets = append(sets, "data_classification=$"+itoa(len(args)+1))
		args = append(args, v)
	}
	if in.AllowedPrincipals != nil {
		raw, _ := json.Marshal(in.AllowedPrincipals)
		sets = append(sets, "allowed_principals=$"+itoa(len(args)+1))
		args = append(args, raw)
	}
	if in.AllowedRoles != nil {
		raw, _ := json.Marshal(in.AllowedRoles)
		sets = append(sets, "allowed_roles=$"+itoa(len(args)+1))
		args = append(args, raw)
	}
	if in.AllowedTenants != nil {
		raw, _ := json.Marshal(in.AllowedTenants)
		sets = append(sets, "allowed_tenants=$"+itoa(len(args)+1))
		args = append(args, raw)
	}
	if in.ApprovalRequired != nil {
		sets = append(sets, "approval_required=$"+itoa(len(args)+1))
		args = append(args, *in.ApprovalRequired)
	}
	if in.MaxCallsPerMinute != nil {
		sets = append(sets, "max_calls_per_minute=$"+itoa(len(args)+1))
		args = append(args, *in.MaxCallsPerMinute)
	}
	ct, err := tx.Exec(ctx, `UPDATE mcp_catalog_tools SET `+strings.Join(sets, ", ")+` WHERE id=$1 AND catalog_id=$2`, args...)
	if err != nil {
		return nil, err
	}
	if ct.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	if err := refreshCatalogHashTx(ctx, tx, catalogID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT `+toolCols+` FROM mcp_catalog_tools WHERE id=$1`, toolID)
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		rows.Close()
		return nil, ErrNotFound
	}
	t, err := scanTool(rows)
	rows.Close() // 提交前关闭结果集（pgx 单连接复用，开着 rows 提交报 conn busy）
	if err != nil {
		return nil, err
	}
	return &t, tx.Commit(ctx)
}

// ---------- 绑定 ----------

const bindingCols = `b.id, b.application_id, b.endpoint_path, b.catalog_id, COALESCE(c.name,''), b.mode, b.version, COALESCE(b.created_by,''), b.created_at, b.updated_at`

func scanBinding(row pgx.Row) (Binding, error) {
	var b Binding
	err := row.Scan(&b.ID, &b.ApplicationID, &b.EndpointPath, &b.CatalogID, &b.CatalogName,
		&b.Mode, &b.Version, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt)
	return b, err
}

func fkToErr(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23503" {
		if strings.Contains(pe.ConstraintName, "catalog_id") {
			return ErrCatalogNotFound
		}
		return ErrAppNotFound
	}
	return err
}

// CreateBinding 新建绑定（同（应用,endpoint_path）409；catalog FK 引用校验）。
func (s *Store) CreateBinding(ctx context.Context, in BindingInput, createdBy string) (*Binding, error) {
	mode := orDefault(strings.ToUpper(strings.TrimSpace(in.Mode)), ModeObserve)
	appID, _ := uuid.Parse(strings.TrimSpace(in.ApplicationID))
	catID, _ := uuid.Parse(strings.TrimSpace(in.CatalogID))
	var b Binding
	err := s.db.QueryRow(ctx, `INSERT INTO mcp_catalog_bindings
		(application_id, endpoint_path, catalog_id, mode, created_by) VALUES ($1,$2,$3,$4,$5)
		RETURNING id, application_id, endpoint_path, catalog_id, mode, version, created_by, created_at, updated_at`,
		appID, strings.TrimSpace(in.EndpointPath), catID, mode, createdBy).Scan(
		&b.ID, &b.ApplicationID, &b.EndpointPath, &b.CatalogID,
		&b.Mode, &b.Version, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return nil, ErrBindingDuplicate
		}
		return nil, fkToErr(err)
	}
	b.CatalogName = s.catalogName(ctx, b.CatalogID)
	return &b, nil
}

// catalogName 目录名回读（Create/Update 响应补全；失败留空不误主流程）。
func (s *Store) catalogName(ctx context.Context, id uuid.UUID) string {
	var n string
	_ = s.db.QueryRow(ctx, `SELECT COALESCE(name,'') FROM mcp_tool_catalogs WHERE id=$1`, id).Scan(&n)
	return n
}

// ListBindings 绑定列表（application_id 可选过滤；应用+路径稳定序）。
func (s *Store) ListBindings(ctx context.Context, applicationID uuid.UUID) ([]Binding, error) {
	cond, args := "", []any{}
	if applicationID != uuid.Nil {
		args = append(args, applicationID)
		cond = " WHERE b.application_id = $1"
	}
	rows, err := s.db.Query(ctx, `SELECT `+bindingCols+` FROM mcp_catalog_bindings b
		LEFT JOIN mcp_tool_catalogs c ON c.id=b.catalog_id`+cond+
		` ORDER BY b.application_id, b.endpoint_path`, args...)
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

// UpdateBinding 改 mode/目录（乐观锁；endpoint_path/application 为身份维度不可改）。
func (s *Store) UpdateBinding(ctx context.Context, id uuid.UUID, in BindingInput) (*Binding, error) {
	mode := orDefault(strings.ToUpper(strings.TrimSpace(in.Mode)), ModeObserve)
	catID, _ := uuid.Parse(strings.TrimSpace(in.CatalogID))
	var b Binding
	err := s.db.QueryRow(ctx, `UPDATE mcp_catalog_bindings SET catalog_id=$2, mode=$3,
		version=version+1, updated_at=now() WHERE id=$1 AND version=$4
		RETURNING id, application_id, endpoint_path, catalog_id, mode, version, created_by, created_at, updated_at`,
		id, catID, mode, in.Version).Scan(
		&b.ID, &b.ApplicationID, &b.EndpointPath, &b.CatalogID,
		&b.Mode, &b.Version, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mcp_catalog_bindings WHERE id=$1)`, id).Scan(&exists); err != nil {
			return nil, err
		}
		if !exists {
			return nil, ErrBindingNotFound
		}
		return nil, ErrVersionConflict
	}
	if err != nil {
		return nil, fkToErr(err)
	}
	b.CatalogName = s.catalogName(ctx, b.CatalogID)
	return &b, nil
}

// DeleteBinding 解绑（不存在 ErrBindingNotFound）。
func (s *Store) DeleteBinding(ctx context.Context, id uuid.UUID) error {
	ct, err := s.db.Exec(ctx, `DELETE FROM mcp_catalog_bindings WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrBindingNotFound
	}
	return nil
}

// itoa 小整数格式化（占位符编号用；免 strconv 重复）。
func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return fmt.Sprintf("%d", n)
}
