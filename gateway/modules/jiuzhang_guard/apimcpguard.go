// apimcpguard.go MCP G1 装配置装配（NG-MCP 批次 B2，设计 §1.3/D3/§1.14）：
// api_mcp_tool_catalogs + api_mcp_bindings 发布段解析归一 + catalog_hash 重算
// 比对 + 绑定注册表。
//
// 装配纪律（apigrpcguard.go 全纪律承接）：
//   - 无目录且无绑定 = nil（mcpguard 全链零行为，NG-T-C01）；
//   - 绑定行字段空缺跳行 + Warn；mode 词表外归一 OBSERVE + Warn（fail-safe
//     不误断，与 api_admission 同纪律不拒载）；
//   - 绑定引用未知目录：行保留但无目录（运行期 SKIPPED(COV_NO_CATALOG)
//     放行不误断）——跳行会把端点错误回退到未绑定语义（零行为），方向相反；
//   - catalog_hash 重算比对：不符即整目录拒装（Warn + 其绑定行无目录——
//     不消费未验证摘要的目录；摘要算法冻结：mcp-catalog-sha256:v1: +
//     hex(sha256(排序后拼接的工具 tool_hash))）；
//   - 工具行字段空缺（tool_name/tool_hash 空）跳行 + Warn；risk_level/
//     data_classification 词表外按缺省（HIGH/UNKNOWN——未定级按高风险对待，
//     与 server 导入语义同向）；
//   - Schema 编译：缺席 nil；非法/词表外类型按缺席处理 + Warn；含不支持
//     关键字登记降级（InputDegraded——运行期 PARTIAL 如实不冒充完整校验）。
package jiuzhang_guard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/mcpguard"
	"go.uber.org/zap"
)

// catalogHashPrefix 目录摘要域（冻结：server 计算同域——网关装配重算比对）。
const catalogHashPrefix = "mcp-catalog-sha256:v1:"

// mcpCatalogJSON 工具目录（api_mcp_tool_catalogs 数组项；与 server 发布段
// 跨轨线契约——json tag 不得改名）。
type mcpCatalogJSON struct {
	Name            string        `json:"name"`
	ServiceIdentity string        `json:"service_identity"`
	ProtocolVersion string        `json:"protocol_version"`
	CatalogHash     string        `json:"catalog_hash"`
	Tools           []mcpToolJSON `json:"tools"`
}

// mcpToolJSON 目录工具行（发布段只含 APPROVED——PENDING/REJECTED 不出现在快照）。
type mcpToolJSON struct {
	ToolName           string                 `json:"tool_name"`
	ToolVersion        string                 `json:"tool_version"`
	ToolHash           string                 `json:"tool_hash"`
	RiskLevel          string                 `json:"risk_level"`
	DataClassification string                 `json:"data_classification"`
	CapabilityTags     []string               `json:"capability_tags"`
	AllowedPrincipals  []string               `json:"allowed_principals"`
	AllowedRoles       []string               `json:"allowed_roles"`
	AllowedTenants     []string               `json:"allowed_tenants"`
	ApprovalRequired   bool                   `json:"approval_required"`
	MaxCallsPerMinute  int                    `json:"max_calls_per_minute"`
	InputSchema          json.RawMessage        `json:"input_schema"`
	OutputSchema         json.RawMessage        `json:"output_schema"`
	ArgConstraints       []mcpArgConstraintJSON `json:"arg_constraints"`
	PinnedDefinitionHash string                 `json:"pinned_definition_hash,omitempty"`
	PinEnforcement       string                 `json:"pin_enforcement,omitempty"`
}

// mcpArgConstraintJSON 参数范围约束（G1 两种确定性约束）。
type mcpArgConstraintJSON struct {
	Field string   `json:"field"`
	Kind  string   `json:"kind"` // path_prefix|domain_suffix
	Allow []string `json:"allow"`
}

// mcpBindingJSON MCP 绑定（api_mcp_bindings 数组项；跨轨线契约不得改名）。
type mcpBindingJSON struct {
	ApplicationID            string `json:"application_id"`
	EndpointPath             string `json:"endpoint_path"`
	CatalogName              string `json:"catalog_name"`
	Mode                     string `json:"mode"`
	ResponseGuardMode        string `json:"response_guard_mode,omitempty"`
	RequireSessionBinding    bool   `json:"require_session_binding,omitempty"`
	OAuthResourceMetadataURL string `json:"oauth_resource_metadata_url,omitempty"`
}

// buildMCPGuardConfig mcpguard 装配置装配（Provision 调用；nil = 零行为 NG-T-C01）。
func (g *Guard) buildMCPGuardConfig() *mcpguard.Config {
	if len(g.APIMCPToolCatalogs) == 0 && len(g.APIMCPBindings) == 0 {
		return nil
	}
	// 目录编译：hash 重算比对 → 工具行归一 → Schema 编译
	catalogs := map[string]*mcpguard.Catalog{}
	for _, cj := range g.APIMCPToolCatalogs {
		name := strings.TrimSpace(cj.Name)
		if name == "" {
			g.logger.Warn("api_mcp_tool_catalogs 目录名空缺跳过")
			continue
		}
		cat := &mcpguard.Catalog{
			Name:            name,
			ServiceIdentity: cj.ServiceIdentity,
			ProtocolVersion: cj.ProtocolVersion,
			Tools:           map[string]*mcpguard.Tool{},
		}
		var hashes []string
		for i, tj := range cj.Tools {
			toolName := strings.TrimSpace(tj.ToolName)
			toolHash := strings.TrimSpace(tj.ToolHash)
			if toolName == "" || toolHash == "" {
				g.logger.Warn("api_mcp_tool_catalogs 工具行字段空缺跳过",
					zap.String("catalog", name), zap.Int("index", i))
				continue
			}
			risk := strings.ToUpper(strings.TrimSpace(tj.RiskLevel))
			if risk != "LOW" && risk != "MEDIUM" && risk != "HIGH" {
				risk = mcpguard.RiskHigh // 未定级/词表外按高风险对待（与导入缺省同向）
			}
			classification := strings.ToUpper(strings.TrimSpace(tj.DataClassification))
			if classification != "PUBLIC" && classification != "INTERNAL" &&
				classification != mcpguard.ClassificationConfidential && classification != "UNKNOWN" {
				classification = "UNKNOWN"
			}
			pinEnfRaw := strings.ToUpper(strings.TrimSpace(tj.PinEnforcement))
			pinEnf := mcpguard.NormalizePinEnforcement(pinEnfRaw)
			if pinEnfRaw != "" && pinEnfRaw != pinEnf {
				g.logger.Warn("api_mcp_tool_catalogs pin_enforcement 词表外归一 OBSERVE（fail-safe）",
					zap.String("catalog", name), zap.String("tool", toolName), zap.String("pin_enforcement", tj.PinEnforcement))
			}
			tool := &mcpguard.Tool{
				Name:                 toolName,
				Version:              tj.ToolVersion,
				Hash:                 toolHash,
				RiskLevel:            risk,
				DataClassification:   classification,
				CapabilityTags:       tj.CapabilityTags,
				AllowedPrincipals:    tj.AllowedPrincipals,
				AllowedRoles:         tj.AllowedRoles,
				AllowedTenants:       tj.AllowedTenants,
				ApprovalRequired:     tj.ApprovalRequired,
				MaxCallsPerMinute:    tj.MaxCallsPerMinute,
				PinnedDefinitionHash: strings.TrimSpace(tj.PinnedDefinitionHash),
				PinEnforcement:       pinEnf,
			}
			// Schema 编译（缺席 nil；含不支持关键字登记降级）
			tool.InputSchema = mcpguard.CompileSchema(tj.InputSchema)
			tool.InputDegraded = len(mcpguard.DetectUnsupportedKeywords(tj.InputSchema)) > 0
			if tool.InputDegraded {
				tool.InputUnsupportedKeys = mcpguard.DetectUnsupportedKeywords(tj.InputSchema)
			}
			tool.OutputSchema = mcpguard.CompileSchema(tj.OutputSchema)
			tool.OutputDegraded = len(mcpguard.DetectUnsupportedKeywords(tj.OutputSchema)) > 0
			for _, ac := range tj.ArgConstraints {
				kind := strings.TrimSpace(ac.Kind)
				if kind != mcpguard.ConstraintPathPrefix && kind != mcpguard.ConstraintDomainSuffix {
					g.logger.Warn("api_mcp_tool_catalogs arg_constraints kind 词表外跳过",
						zap.String("catalog", name), zap.String("tool", toolName), zap.String("kind", ac.Kind))
					continue
				}
				tool.ArgConstraints = append(tool.ArgConstraints, mcpguard.ArgConstraint{
					Field: strings.TrimSpace(ac.Field), Kind: kind, Allow: ac.Allow,
				})
			}
			cat.Tools[toolName] = tool
			hashes = append(hashes, toolHash)
		}
		// catalog_hash 重算比对（不符即整目录拒装——不消费未验证摘要的目录）
		sort.Strings(hashes)
		sum := sha256.Sum256([]byte(strings.Join(hashes, "")))
		recomputed := catalogHashPrefix + hex.EncodeToString(sum[:])
		if cj.CatalogHash != recomputed {
			g.logger.Warn("api_mcp_tool_catalogs catalog_hash 重算比对不符，整目录拒装（其绑定运行期 COV_NO_CATALOG 放行不误断）",
				zap.String("catalog", name))
			continue
		}
		cat.Hash = cj.CatalogHash
		catalogs[name] = cat
	}
	// 绑定归一（应用 × endpoint_path；同名后行覆盖前行——稳定序后胜与 grpcdesc 同纪律）
	cfg := &mcpguard.Config{
		Apps:          map[string]map[string]mcpguard.Endpoint{},
		IdentitySalt:  g.IdentitySalt,
		SessionBinder: mcpguard.NewSessionBinder(),
	}
	for i, bj := range g.APIMCPBindings {
		appID := strings.TrimSpace(bj.ApplicationID)
		path := strings.TrimSpace(bj.EndpointPath)
		catalogName := strings.TrimSpace(bj.CatalogName)
		if appID == "" || path == "" || catalogName == "" {
			g.logger.Warn("api_mcp_bindings 行字段空缺跳过", zap.Int("index", i))
			continue
		}
		if !strings.HasPrefix(path, "/") {
			g.logger.Warn("api_mcp_bindings endpoint_path 非 / 开头跳过", zap.Int("index", i), zap.String("endpoint_path", path))
			continue
		}
		mode := strings.ToUpper(strings.TrimSpace(bj.Mode))
		if mode == "" {
			mode = mcpguard.ModeObserve
		}
		if mode != mcpguard.ModeObserve && mode != mcpguard.ModeProtect {
			g.logger.Warn("api_mcp_bindings mode 词表外归一 OBSERVE（fail-safe）",
				zap.Int("index", i), zap.String("mode", bj.Mode))
			mode = mcpguard.ModeObserve
		}
		rgmRaw := strings.ToUpper(strings.TrimSpace(bj.ResponseGuardMode))
		rgm := mcpguard.NormalizeResponseGuardMode(rgmRaw)
		if rgmRaw != "" && rgmRaw != rgm {
			g.logger.Warn("api_mcp_bindings response_guard_mode 词表外归一 OBSERVE（fail-safe）",
				zap.Int("index", i), zap.String("response_guard_mode", bj.ResponseGuardMode))
		}
		oauthMetaURL := ""
		if rawURL := strings.TrimSpace(bj.OAuthResourceMetadataURL); rawURL != "" {
			if valid, ok := mcpguard.ValidateOAuthResourceMetadataURL(rawURL); ok {
				oauthMetaURL = valid
			} else {
				g.logger.Warn("api_mcp_bindings oauth_resource_metadata_url 非合法 https:// URL，已忽略",
					zap.Int("index", i), zap.String("endpoint_path", path))
			}
		}
		cat := catalogs[catalogName]
		if cat == nil {
			g.logger.Warn("api_mcp_bindings 引用未知/拒装目录（运行期 COV_NO_CATALOG 放行不误断）",
				zap.String("endpoint_path", path), zap.String("catalog_name", catalogName))
		}
		if cfg.Apps[appID] == nil {
			cfg.Apps[appID] = map[string]mcpguard.Endpoint{}
		}
		cfg.Apps[appID][path] = mcpguard.Endpoint{
			Catalog:                  cat,
			Mode:                     mode,
			ResponseGuardMode:        rgm,
			RequireSessionBinding:    bj.RequireSessionBinding,
			OAuthResourceMetadataURL: oauthMetaURL,
		}
	}
	return cfg
}
