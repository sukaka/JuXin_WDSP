// mcp_jwt_coverage.go MCP PROTECT 绑定 × jwt_trust 覆盖发布校验警示（NG-MCP G1
// 批次 B1，设计 docs/nextgen/NG-MCP-g1-toolcall.md §1.5/§1.14）：
// PROTECT 绑定的端点应当同时被 jwt_trust 策略 selector 覆盖（可信主体依赖）；
// 未覆盖 = 配置缺口——运行时按 §1.4-1 SKIPPED(COV_NO_TRUSTED_SUBJECT) 放行+披露
// （UNKNOWN 恒不阻断红线），发布侧此处给出显著 Warn 警示但不硬失败（strict 组合
// 属业务端点逐项批准，§4.5）。
package guardconfig

import (
	"log/slog"
	"strings"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// warnMCPJWTTrustCoverage 对每个 PROTECT MCP 绑定检查同应用 jwt_trust 策略是否
// 覆盖其 endpoint_path；未覆盖逐条 slog.Warn（非阻断，不改变发布结果）。
// 覆盖判定三条件：应用存在策略 && 策略 mode≠OFF && 至少一个 selector 覆盖路径
// （path_exact 相等或 path_prefix 按完整路径段前缀匹配——与网关
// jwtverify.prefixSegmentMatch 同语义的服务端镜像实现）。
func warnMCPJWTTrustCoverage(cfg *gatewayconfig.GuardConfig) {
	if cfg == nil {
		return
	}
	for _, b := range cfg.APIMCPBindings {
		if b.Mode != "PROTECT" {
			continue
		}
		if mcpEndpointCoveredByJWTTrust(cfg.JWTTrust, b.ApplicationID, b.EndpointPath) {
			continue
		}
		slog.Warn("mcp PROTECT binding endpoint not covered by jwt_trust policy: "+
			"运行时可信主体依赖缺席，将按 COV_NO_TRUSTED_SUBJECT 放行+披露（UNKNOWN 不阻断）"+
			"——请为该应用 jwt_trust 策略登记覆盖此端点的 selector 并确认受众",
			"application_id", b.ApplicationID,
			"endpoint_path", b.EndpointPath,
			"catalog_name", b.CatalogName)
	}
}

// mcpEndpointCoveredByJWTTrust 覆盖判定（单绑定）：应用策略存在、非 OFF、selector
// 覆盖 endpoint_path。
func mcpEndpointCoveredByJWTTrust(policies map[string]*gatewayconfig.GuardJWTTrustPolicy, applicationID, endpointPath string) bool {
	for _, pol := range policies {
		if pol == nil || pol.ApplicationID != applicationID || pol.Mode == "OFF" {
			continue
		}
		for _, s := range pol.Selectors {
			if s.PathExact != "" {
				if s.PathExact == endpointPath {
					return true
				}
				continue
			}
			if mcpPrefixSegmentMatch(s.PathPrefix, endpointPath) {
				return true
			}
		}
	}
	return false
}

// mcpPrefixSegmentMatch 按完整路径段匹配："/api" 匹配 "/api" 与 "/api/orders"，
// 不匹配 "/apix"；根前缀 "/" 匹配所有以 / 开头的路径（网关 jwtverify
// prefixSegmentMatch 同语义镜像——发布侧 advisory 判定，不引入反向依赖）。
func mcpPrefixSegmentMatch(prefix, path string) bool {
	if prefix == "" {
		return false
	}
	if prefix == "/" {
		return strings.HasPrefix(path, "/")
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || path[len(prefix)] == '/'
}
