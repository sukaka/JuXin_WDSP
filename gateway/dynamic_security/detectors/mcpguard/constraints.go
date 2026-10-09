// constraints.go 步骤 4 参数路径/域名范围约束（§1.4 第 4 项；G1 两种确定性
// 约束：path_prefix / domain_suffix——证据只含字段路径+约束种类+值长度+受控
// 摘要，不落原值）。
package mcpguard

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
)

// checkArgConstraints 逐条评估 arg_constraints（AND 语义——任一不符即违规）。
// 值缺失/非字符串跳过（存在性/类型由 Schema 层判定，约束只评字符串值——
// 不冒充类型判定）；返回违规证据（nil=全部通过）。
func (rc *chainRecorder) checkArgConstraints(tool *Tool, arguments any) *map[string]string {
	if len(tool.ArgConstraints) == 0 {
		return nil
	}
	argObj, _ := arguments.(map[string]any)
	for _, c := range tool.ArgConstraints {
		if len(c.Allow) == 0 || c.Field == "" {
			continue // 空允许集/空字段=该条不约束（不冒充判定）
		}
		v, ok := argObj[c.Field]
		if !ok {
			continue // 缺失由 Schema required 判
		}
		s, isStr := v.(string)
		if !isStr {
			continue // 非字符串由 Schema type 判
		}
		switch c.Kind {
		case ConstraintPathPrefix:
			if !hasPrefixAny(s, c.Allow) {
				return &map[string]string{
					"tool": truncateString(tool.Name, 128), "field": c.Field, "kind": c.Kind,
					"value_len": strconv.Itoa(len(s)), "value_fp": fingerprint(rc.cfg.IdentitySalt, s),
					"reason_code": "MCP_ARGUMENT_REJECTED",
				}
			}
		case ConstraintDomainSuffix:
			host := hostOfValue(s)
			if host == "" || !domainSuffixMatch(host, c.Allow) {
				return &map[string]string{
					"tool": truncateString(tool.Name, 128), "field": c.Field, "kind": c.Kind,
					"value_len": strconv.Itoa(len(s)), "value_fp": fingerprint(rc.cfg.IdentitySalt, s),
					"reason_code": "MCP_ARGUMENT_REJECTED",
				}
			}
		default:
			// 词表外约束种类：装配期已归一（词表外跳过+Warn），运行期不评不拒
			continue
		}
	}
	return nil
}

// hasPrefixAny 前缀集匹配（任一允许前缀即通过）。
func hasPrefixAny(s string, allow []string) bool {
	for _, p := range allow {
		if p != "" && strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// hostOfValue 值主机名提取（含 scheme 按 URL 解析取 Hostname；裸值按
// host[:port] 处理并去端口——example.com 测试域同口径小写归一）。
func hostOfValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil {
			return ""
		}
		return strings.ToLower(u.Hostname())
	}
	h := v
	if host, _, err := net.SplitHostPort(v); err == nil {
		h = host
	}
	return strings.ToLower(h)
}

// domainSuffixMatch 域后缀匹配（精确等值或 "."+suffix 结尾——子域合法，
// 前后缀大小写归一；suffix 前导点容忍剥离）。
func domainSuffixMatch(host string, allow []string) bool {
	for _, suffix := range allow {
		suffix = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(suffix), "."))
		if suffix == "" {
			continue
		}
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// ---------- 头观测（§1.2；pipeline 挂点在候选判定后调用） ----------

// headObsExtKey 头观测扩展键（emitMethodCoverage 合并进 mcp.coverage_v1——
// 候选请求一条纪律，不单独建明细）。
const headObsExtKey = "mcp.headobs"

// NoteHeadObservations 头观测登记（不落原值：MCP-Protocol-Version 记值截断 64；
// Mcp-Session-Id 只记存在性+盐指纹——原值类凭据不落事件，§14.3 红线）。
// pipeline 挂点在 Evaluate 前调用（r 与 parser 同一份，零新增读取）。
func NoteHeadObservations(ctx *dsctx.RequestContext, header func(string) string, cfg *Config) {
	if ctx == nil || cfg == nil || header == nil {
		return
	}
	obs := map[string]string{}
	if v := strings.TrimSpace(header("Mcp-Session-Id")); v != "" {
		obs["session_id_present"] = "true"
		obs["session_id_fp"] = fingerprint(cfg.IdentitySalt, v)
	}
	if v := strings.TrimSpace(header("MCP-Protocol-Version")); v != "" {
		obs["protocol_version"] = truncateString(v, 64)
	}
	if len(obs) > 0 {
		ctx.SetExtension(headObsExtKey, obs)
	}
}

// mergeHeadObs 头观测合并（emitMethodCoverage 统一出口）。
func mergeHeadObs(ctx *dsctx.RequestContext, evidence map[string]string) {
	v, ok := ctx.GetExtension(headObsExtKey)
	if !ok {
		return
	}
	if obs, ok := v.(map[string]string); ok {
		for k, val := range obs {
			evidence[k] = val
		}
	}
}

// 编译期锚点：coverage 包引用（Coverage 观测形态在本包统一组装）。
var _ = coverage.StatusFull
