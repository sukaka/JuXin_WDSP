// mcp_catalogs.go MCP 工具目录与绑定下发（NG-MCP G1 批次 B1，设计
// docs/nextgen/NG-MCP-g1-toolcall.md §1.3/§1.14）：
// api_mcp_tool_catalogs 段 = mcp_tool_catalogs ENABLED 行 + 仅 APPROVED 工具行
// （catalog_hash 发布时按 APPROVED tool_hash 排序拼接重算——与 DB 维护值一致的
// 现算形态（审核/导入后 DB 值漂移防御）；catalog_hash 重算比对在网关装配期）；
// api_mcp_bindings 段 = mcp_catalog_bindings 全行稳定序（应用+endpoint_path）。
// 表缺失/查询失败 Warn 跳过（与 GRPCBindingStore 同一模式；空段=不下发
// （omitempty），NG-T-C01 零行为）。
package guardconfig

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/apimcp"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// MCPToolCatalogLister MCP 目录读取接口（包内单测可 fake 错误路径）。
type MCPToolCatalogLister interface {
	ListEnabledMCPCatalogs(ctx context.Context) ([]gatewayconfig.GuardMCPToolCatalog, error)
}

// MCPBindingLister MCP 绑定读取接口（包内单测可 fake 错误路径）。
type MCPBindingLister interface {
	ListAllMCPBindings(ctx context.Context) ([]gatewayconfig.GuardMCPBinding, error)
}

// MCPCatalogStore mcp_tool_catalogs/mcp_catalog_tools/mcp_catalog_bindings 读取
// （表由迁移 000181/000182 建立；按冻结列名读取）。
type MCPCatalogStore struct {
	db *pgxpool.Pool
}

// NewMCPCatalogStore 创建。
func NewMCPCatalogStore(db *pgxpool.Pool) *MCPCatalogStore { return &MCPCatalogStore{db: db} }

var _ MCPToolCatalogLister = (*MCPCatalogStore)(nil)
var _ MCPBindingLister = (*MCPCatalogStore)(nil)

// ListEnabledMCPCatalogs 读取 ENABLED 目录+APPROVED 工具行（catalog_hash 现算
// （按 APPROVED tool_hash 排序拼接——始终与当前 APPROVED 集一致）；
// 目录 name+工具 tool_name 稳定排序——同内容恒得同序列化，版本戳确定）。
func (s *MCPCatalogStore) ListEnabledMCPCatalogs(ctx context.Context) ([]gatewayconfig.GuardMCPToolCatalog, error) {
	catRows, err := s.db.Query(ctx, `SELECT name, service_identity, protocol_version
		FROM mcp_tool_catalogs WHERE status='ENABLED' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer catRows.Close()
	var cats []gatewayconfig.GuardMCPToolCatalog
	byName := map[string]string{} // name → catalog_id
	for catRows.Next() {
		var c gatewayconfig.GuardMCPToolCatalog
		var id string
		if err := catRows.Scan(&c.Name, &c.ServiceIdentity, &c.ProtocolVersion); err != nil {
			return nil, err
		}
		if err := s.db.QueryRow(ctx, `SELECT id::text FROM mcp_tool_catalogs WHERE name=$1`, c.Name).Scan(&id); err != nil {
			return nil, err
		}
		byName[c.Name] = id
		cats = append(cats, c)
	}
	if err := catRows.Err(); err != nil {
		return nil, err
	}
	for i := range cats {
		id := byName[cats[i].Name]
		tools, hashes, err := s.listApprovedTools(ctx, id)
		if err != nil {
			return nil, err
		}
		cats[i].Tools = tools
		cats[i].CatalogHash = apimcp.ComputeCatalogHash(hashes)
	}
	return cats, nil
}

// listApprovedTools 单目录 APPROVED 工具行（tool_name 稳定序）+ tool_hash 列表。
func (s *MCPCatalogStore) listApprovedTools(ctx context.Context, catalogID string) ([]gatewayconfig.GuardMCPTool, []string, error) {
	rows, err := s.db.Query(ctx, `SELECT tool_name, tool_version, tool_hash, risk_level, data_classification,
		capability_tags, allowed_principals, allowed_roles, allowed_tenants,
		approval_required, max_calls_per_minute, input_schema, output_schema, arg_constraints,
		pinned_definition_hash, pin_enforcement
		FROM mcp_catalog_tools WHERE catalog_id=$1 AND review_status='APPROVED' ORDER BY tool_name`, catalogID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	tools := []gatewayconfig.GuardMCPTool{}
	var hashes []string
	for rows.Next() {
		var t gatewayconfig.GuardMCPTool
		var tags, principals, roles, tenants, inSchema, outSchema, constraints []byte
		if err := rows.Scan(&t.ToolName, &t.ToolVersion, &t.ToolHash, &t.RiskLevel, &t.DataClassification,
			&tags, &principals, &roles, &tenants,
			&t.ApprovalRequired, &t.MaxCallsPerMinute, &inSchema, &outSchema, &constraints,
			&t.PinnedDefinitionHash, &t.PinEnforcement); err != nil {
			return nil, nil, err
		}
		t.CapabilityTags = decodeStrings(tags)
		t.AllowedPrincipals = decodeStrings(principals)
		t.AllowedRoles = decodeStrings(roles)
		t.AllowedTenants = decodeStrings(tenants)
		t.InputSchema = decodeSchema(inSchema)
		t.OutputSchema = decodeSchema(outSchema)
		t.ArgConstraints = decodeArgConstraints(constraints)
		tools = append(tools, t)
		hashes = append(hashes, t.ToolHash)
	}
	return tools, hashes, rows.Err()
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

func decodeArgConstraints(raw []byte) []gatewayconfig.GuardMCPArgConstraint {
	out := []gatewayconfig.GuardMCPArgConstraint{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

// ListAllMCPBindings 读取全部绑定（应用+endpoint_path 稳定排序；catalog_name JOIN 带出）。
func (s *MCPCatalogStore) ListAllMCPBindings(ctx context.Context) ([]gatewayconfig.GuardMCPBinding, error) {
	rows, err := s.db.Query(ctx, `SELECT b.application_id, b.endpoint_path, COALESCE(c.name,''), b.mode,
		b.response_guard_mode, b.require_session_binding, b.oauth_resource_metadata_url
		FROM mcp_catalog_bindings b LEFT JOIN mcp_tool_catalogs c ON c.id=b.catalog_id
		ORDER BY b.application_id, b.endpoint_path`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardMCPBinding{}
	for rows.Next() {
		var b gatewayconfig.GuardMCPBinding
		if err := rows.Scan(&b.ApplicationID, &b.EndpointPath, &b.CatalogName, &b.Mode,
			&b.ResponseGuardMode, &b.RequireSessionBinding, &b.OAuthResourceMetadataURL); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// SetMCPToolCatalogLister 注入 MCP 目录读取（nil 时不下发 api_mcp_tool_catalogs 段）。
func (p *Provider) SetMCPToolCatalogLister(l MCPToolCatalogLister) { p.mcpCatalogs = l }

// SetMCPBindingLister 注入 MCP 绑定读取（nil 时不下发 api_mcp_bindings 段）。
func (p *Provider) SetMCPBindingLister(l MCPBindingLister) { p.mcpBindings = l }

// loadAPIMCPToolCatalogs 读取 ENABLED MCP 目录（兼容旧调用方；BuildGuardConfig 走 loadAPIMCPToolCatalogsStrict）。
func (p *Provider) loadAPIMCPToolCatalogs(ctx context.Context) []gatewayconfig.GuardMCPToolCatalog {
	cats, err := p.loadAPIMCPToolCatalogsStrict(ctx)
	if err != nil {
		slog.Warn("api_mcp_tool_catalogs load failed, skipping section", "error", err)
	}
	return cats
}

// loadAPIMCPToolCatalogsStrict 仅容忍旧库未建表（42P01）；真实数据库错误中止候选发布（fail-hard）。
func (p *Provider) loadAPIMCPToolCatalogsStrict(ctx context.Context) ([]gatewayconfig.GuardMCPToolCatalog, error) {
	if p.mcpCatalogs == nil {
		return nil, nil
	}
	cats, err := p.mcpCatalogs.ListEnabledMCPCatalogs(ctx)
	if err != nil {
		if isMissingLegacyTableError(err, "mcp_tool_catalogs") ||
			isMissingLegacyTableError(err, "mcp_catalog_tools") {
			slog.Warn("optional legacy table mcp_tool_catalogs is unavailable", "error", err)
			return nil, nil
		}
		return nil, wrapLegacyLoaderError("mcp_tool_catalogs", err)
	}
	if len(cats) == 0 {
		return nil, nil
	}
	return cats, nil
}

// loadAPIMCPBindings 读取全部 MCP 绑定（兼容旧调用方；BuildGuardConfig 走 loadAPIMCPBindingsStrict）。
func (p *Provider) loadAPIMCPBindings(ctx context.Context) []gatewayconfig.GuardMCPBinding {
	bindings, err := p.loadAPIMCPBindingsStrict(ctx)
	if err != nil {
		slog.Warn("api_mcp_bindings load failed, skipping section", "error", err)
	}
	return bindings
}

// loadAPIMCPBindingsStrict 仅容忍旧库未建表（42P01）；真实数据库错误中止候选发布（fail-hard）。
func (p *Provider) loadAPIMCPBindingsStrict(ctx context.Context) ([]gatewayconfig.GuardMCPBinding, error) {
	if p.mcpBindings == nil {
		return nil, nil
	}
	bindings, err := p.mcpBindings.ListAllMCPBindings(ctx)
	if err != nil {
		if isMissingLegacyTableError(err, "mcp_catalog_bindings") ||
			isMissingLegacyTableError(err, "mcp_tool_catalogs") {
			slog.Warn("optional legacy table mcp_catalog_bindings is unavailable", "error", err)
			return nil, nil
		}
		return nil, wrapLegacyLoaderError("mcp_catalog_bindings", err)
	}
	if len(bindings) == 0 {
		return nil, nil
	}
	return bindings, nil
}
