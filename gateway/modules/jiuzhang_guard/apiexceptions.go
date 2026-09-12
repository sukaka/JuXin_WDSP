// API 受限例外（WDSP P0-04；任务书 docs/tasks/wdsp-p0/P0-04_DECISION_SCOPED_EXCEPTIONS.md，
// 契约冻结 docs/tasks/wdsp-p0/S4_DESIGN_BASELINE.md §6/§10）：
// 网关侧纯函数——api_exceptions 配置段严格解析（fail-closed）与请求范围筛选（AND 语义），
// 不依赖 guard 请求态；Provision 装配与 serveNext 接线由并行工作流负责。
//
// 纪律：
//   - api_exceptions 段是 guard 配置「容忍未知字段」惯例的显式例外（同 jwt_trust）：
//     严格解码——未知字段、不支持的 schema_version、空 methods、uri_exact/uri_prefix
//     缺失或并存、空 rule_refs、注册表外 detector_id、非法 source_ips/时间区间一律
//     返回 error（装配层 fail-closed 中止加载）；旧节点不得把不理解的内容静默忽略
//     当作安全回退。
//   - 范围各维度为 AND：domain 大小写不敏感且容忍 :端口；path 精确等值或按段前缀；
//     method 大写集合成员；clientIP 为可信代理处理后的客户端 IP（netip 解析，CIDR 支持，
//     非法字符串不匹配任何带 source_ips 的例外）；时间 UTC 秒半开区间 [from,until)。
//   - 仅豁免决策引擎 Finding 的本次执法贡献；JWT/协议底线/人工封禁/访问控制/CC/配额/
//     全局身份风险策略不经此例外跳过（EXC-11）。
package jiuzhang_guard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
)

// apiExceptionSchemaVersion 本网关支持的 api_exceptions 配置结构版本
// （与 server 侧 gatewayconfig.GuardAPIException schema_version 对应；不一致即拒绝加载）。
const apiExceptionSchemaVersion = 1

// supportedAPIExceptionDetectors 受支持 API detector 注册表（首批，Finding.RuleID 稳定；
// 契约 §3）：api_schema（schema 违例）、api_parser（参数/解析观测）。
// 其余检测器一律拒绝为例外目标（EXC-11）。
var supportedAPIExceptionDetectors = map[string]bool{
	"api_schema": true,
	"api_parser": true,
}

// APIExceptionRuleRef API 例外目标规则引用：匹配 Finding 的 detector+rule_id
// （+可选 model_version 钉版；空=不限版本）。json tag 与 server 侧
// gatewayconfig.GuardAPIRuleRef 逐字一致（跨分片契约，不得改动）。
type APIExceptionRuleRef struct {
	DetectorID   string `json:"detector_id"`
	RuleID       string `json:"rule_id"`
	ModelVersion string `json:"model_version,omitempty"`
}

// APIException 单条 API 受限例外（OBSERVE_RULE）。范围各维度为 AND，methods 非空；
// uri_exact/uri_prefix 恰一（路径不含 query；prefix 按路径段边界）；时间为 UTC epoch
// 秒半开区间 [effective_from, effective_until)，运行时判断。json tag 与 server 侧
// gatewayconfig.GuardAPIException 逐字一致（跨分片契约，不得改动）。
type APIException struct {
	SchemaVersion  int                   `json:"schema_version"`
	ExceptionID    string                `json:"exception_id"`
	Version        int                   `json:"version"`
	Domain         string                `json:"domain,omitempty"`
	URIExact       string                `json:"uri_exact,omitempty"`
	URIPrefix      string                `json:"uri_prefix,omitempty"`
	Methods        []string              `json:"methods"`
	SourceIPs      []string              `json:"source_ips,omitempty"` // 可信代理处理后的客户端 IP
	EffectiveFrom  *int64                `json:"effective_from,omitempty"`
	EffectiveUntil *int64                `json:"effective_until,omitempty"`
	RuleRefs       []APIExceptionRuleRef `json:"rule_refs"`
}

// ParseAPIExceptionsSection 严格解码 api_exceptions 段（key=应用编码）并逐条校验。
// 任何不理解或不满足基线约束的内容都返回 error（装配层 fail-closed 中止加载），
// 绝不静默忽略或降级。methods 就地标准化为大写（发布侧已标准化，此为纵深防御）。
func ParseAPIExceptionsSection(raw json.RawMessage) (map[string][]APIException, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// 显式例外：guard 其他段容忍未知字段（前向兼容），api_exceptions 不行——
	// 未知字段可能携带本网关不理解的范围/动作语义
	dec.DisallowUnknownFields()
	var sec map[string][]APIException
	if err := dec.Decode(&sec); err != nil {
		return nil, fmt.Errorf("api_exceptions: 配置结构解析失败（拒绝加载）: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("api_exceptions: 配置含多余内容（拒绝加载）")
	}
	for appCode := range sec {
		for i := range sec[appCode] {
			exc := &sec[appCode][i]
			for j, m := range exc.Methods {
				exc.Methods[j] = strings.ToUpper(strings.TrimSpace(m))
			}
			if err := validateAPIException(exc); err != nil {
				return nil, fmt.Errorf("api_exceptions[%q][%d] (exception_id=%q): %w", appCode, i, exc.ExceptionID, err)
			}
		}
	}
	return sec, nil
}

// validateAPIException 校验单条例外的基线约束（任一违反即拒绝整段加载，fail-closed）。
func validateAPIException(exc *APIException) error {
	if exc.SchemaVersion != apiExceptionSchemaVersion {
		return fmt.Errorf("不支持的 schema_version %d（本网关支持 %d；拒绝加载而非忽略强制语义）",
			exc.SchemaVersion, apiExceptionSchemaVersion)
	}
	if exc.ExceptionID == "" {
		return fmt.Errorf("exception_id 为空（例外命中必须可溯源）")
	}
	if len(exc.Methods) == 0 {
		return fmt.Errorf("methods 为空（受限例外必须限定方法集合）")
	}
	for _, m := range exc.Methods {
		if m == "" {
			return fmt.Errorf("methods 含空条目")
		}
	}
	switch {
	case exc.URIExact != "" && exc.URIPrefix != "":
		return fmt.Errorf("uri_exact 与 uri_prefix 互斥（恰一）")
	case exc.URIExact == "" && exc.URIPrefix == "":
		return fmt.Errorf("uri_exact/uri_prefix 必须配置其一（禁止无路径维度的例外）")
	}
	if exc.URIPrefix != "" && !strings.HasPrefix(exc.URIPrefix, "/") {
		return fmt.Errorf("uri_prefix %q 必须以 / 开头（按路径段前缀语义）", exc.URIPrefix)
	}
	if len(exc.RuleRefs) == 0 {
		return fmt.Errorf("rule_refs 为空（受限例外必须限定目标规则）")
	}
	for _, ref := range exc.RuleRefs {
		if !supportedAPIExceptionDetectors[ref.DetectorID] {
			return fmt.Errorf("detector_id %q 不在受支持注册表（EXC-11：JWT/协议底线/封禁/访问控制/CC/配额等不可经 API 例外豁免）", ref.DetectorID)
		}
		if ref.RuleID == "" {
			return fmt.Errorf("rule_refs 含空 rule_id（空串精确匹配会误豁免无规则标识的 Finding）")
		}
	}
	for _, ip := range exc.SourceIPs {
		if !validIPOrCIDR(ip) {
			return fmt.Errorf("source_ips 含非法 IP/CIDR 条目 %q", ip)
		}
	}
	if exc.EffectiveFrom != nil && exc.EffectiveUntil != nil && *exc.EffectiveFrom >= *exc.EffectiveUntil {
		return fmt.Errorf("effective_from(%d) 必须早于 effective_until(%d)（半开区间，相等非法）",
			*exc.EffectiveFrom, *exc.EffectiveUntil)
	}
	return nil
}

// validIPOrCIDR 条目须为合法 IP 或 CIDR（netip 解析，含 IPv6）。
func validIPOrCIDR(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// FilterAPIExceptions 按请求事实筛选适用例外，并展开为规则引用级 ExceptionRef
// （携带 ExceptionID/Version 供决策打标溯源）。范围各维度 AND；list 顺序保持
// （决策侧先入例外优先）。无任何适用例外时返回 nil。
//
// 入参纪律：domain/path/method/clientIP 必须是 guard 已规范化/可信的事实值
// （clientIP 为可信代理处理后的客户端 IP——伪造 XFF 不影响本函数判定）；
// path 不含 query；nowUnix 为当前 UTC 秒。
func FilterAPIExceptions(list []APIException, domain, path, method, clientIP string, nowUnix int64) []decision.ExceptionRef {
	var out []decision.ExceptionRef
	for _, exc := range list {
		if !apiExceptionApplies(exc, domain, path, method, clientIP, nowUnix) {
			continue
		}
		for _, ref := range exc.RuleRefs {
			out = append(out, decision.ExceptionRef{
				ExceptionID:  exc.ExceptionID,
				Version:      exc.Version,
				DetectorID:   ref.DetectorID,
				RuleID:       ref.RuleID,
				ModelVersion: ref.ModelVersion,
			})
		}
	}
	return out
}

// apiExceptionApplies 单条例外的范围 AND 判定：任一维度不满足即不适用。
func apiExceptionApplies(exc APIException, domain, path, method, clientIP string, nowUnix int64) bool {
	// 时间半开区间 [from, until)：nil 端不限；未生效/已到期即不适用（运行时判断，
	// 到期无需管理端再次发布，控制面离线也不延长新请求例外）。
	if exc.EffectiveFrom != nil && nowUnix < *exc.EffectiveFrom {
		return false
	}
	if exc.EffectiveUntil != nil && nowUnix >= *exc.EffectiveUntil {
		return false
	}
	// domain：大小写不敏感，请求侧 Host 容忍 :端口；空=不限。
	if exc.Domain != "" && normalizeExceptionHost(exc.Domain) != normalizeExceptionHost(domain) {
		return false
	}
	// path：精确等值或按段前缀（^prefix(?:/|$) 语义，纯字符串实现，不用正则）。
	if exc.URIExact != "" {
		if path != exc.URIExact {
			return false
		}
	} else if !pathSegmentPrefixMatch(path, exc.URIPrefix) {
		return false
	}
	// method：大写集合成员（请求方法就地大写后比较；配置已在解析期标准化）。
	if !apiExceptionMethodMatch(exc.Methods, method) {
		return false
	}
	// clientIP：配置了 source_ips 时，非法/空 IP 字符串不匹配任何条目（不放大范围）。
	if len(exc.SourceIPs) > 0 && !clientIPMatchesException(exc.SourceIPs, clientIP) {
		return false
	}
	return true
}

// normalizeExceptionHost 主机名规范化：小写、去空白、剥离 :端口（含 [v6]:port 形式）、
// 去 IPv6 字面量括号。非 host:port 形态（如裸主机、裸 IPv6）按原样（小写后）比较。
func normalizeExceptionHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	return h
}

// pathSegmentPrefixMatch 按路径段前缀匹配（^prefix(?:/|$) 语义）：
// "/api" 命中 "/api" 与 "/api/x"，不命中 "/apiary"。
func pathSegmentPrefixMatch(path, prefix string) bool {
	if prefix == "" {
		return false
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// apiExceptionMethodMatch 请求方法（就地大写）是否属于例外方法集合（解析期已标准化大写）。
func apiExceptionMethodMatch(methods []string, method string) bool {
	m := strings.ToUpper(strings.TrimSpace(method))
	for _, allowed := range methods {
		if allowed == m {
			return true
		}
	}
	return false
}

// clientIPMatchesException clientIP（可信值）是否命中 source_ips 任一条目
// （精确 IP 或 CIDR，IPv4/IPv6 均支持，4-in-6 映射地址归一后比较）。
func clientIPMatchesException(sourceIPs []string, clientIP string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(clientIP))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, entry := range sourceIPs {
		entry = strings.TrimSpace(entry)
		if p, err := netip.ParsePrefix(entry); err == nil {
			if p.Contains(addr) {
				return true
			}
			continue
		}
		if a, err := netip.ParseAddr(entry); err == nil && a.Unmap() == addr {
			return true
		}
	}
	return false
}
