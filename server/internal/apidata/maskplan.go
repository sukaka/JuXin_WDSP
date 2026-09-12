// maskplan.go 脱敏计划求值纯函数：GLOBAL < APPLICATION < ENDPOINT 优先级合并 + 排除生效。
// 供发布分片调用（读取 ListEnabledMaskingRules 后求值下发网关），本包同时用于单测。
package apidata

import (
	"encoding/json"
	"net/netip"
	"sort"

	"github.com/google/uuid"
)

// scopeRank 作用域优先级（数值大者覆盖小者）。
var scopeRank = map[string]int{
	ScopeGlobal:      0,
	ScopeApplication: 1,
	ScopeEndpoint:    2,
}

// MaskPlanEntry 生效脱敏计划条目。
type MaskPlanEntry struct {
	RuleID     uuid.UUID       `json:"rule_id"`
	Scope      string          `json:"scope"`
	FieldPath  string          `json:"field_path"`
	DataType   string          `json:"data_type"`
	Algorithm  string          `json:"algorithm"`
	Params     json.RawMessage `json:"params_json"`
	Exclusions *MaskExclusions `json:"exclusions"` // 已结构校验的排除对象（网关侧按请求上下文跳过）
}

// MaskRequest 请求上下文（排除求值用；nil = 不按请求排除，用于发布/预览场景）。
type MaskRequest struct {
	Identity string // 身份指纹
	Role     string // 角色码
	ClientIP string // 客户端 IP
}

// maskMergeKey 合并键：field_path 非空按字段路径，否则按数据类型整类。
func maskMergeKey(r *MaskingRule) string {
	if r.FieldPath != "" {
		return "field:" + r.FieldPath
	}
	if r.DataType != nil {
		return "data_type:" + *r.DataType
	}
	return ""
}

// maskExcluded 判断规则是否被请求上下文排除（任一排除键命中即排除）。
// exclusions 解析失败时按无排除处理（fail 向脱敏侧：宁可多脱敏不可漏脱敏；
// 写库时已做结构校验，此处仅防御）。
func maskExcluded(exclusions *MaskExclusions, req *MaskRequest) bool {
	if req == nil || exclusions == nil {
		return false
	}
	for _, v := range exclusions.Identity {
		if req.Identity != "" && v == req.Identity {
			return true
		}
	}
	for _, v := range exclusions.Role {
		if req.Role != "" && v == req.Role {
			return true
		}
	}
	if req.ClientIP != "" {
		if addr, err := netip.ParseAddr(req.ClientIP); err == nil {
			for _, v := range exclusions.IP {
				if a, err := netip.ParseAddr(v); err == nil && a == addr {
					return true
				}
				if p, err := netip.ParsePrefix(v); err == nil && p.Contains(addr) {
					return true
				}
			}
		}
	}
	return false
}

// MaskPlanForEndpoint 求值端点生效脱敏规则列表（纯函数，无 I/O）。
//
// 语义：
//   - 候选规则仅取 enabled；GLOBAL 全部适用，APPLICATION 需 applicationID 匹配，
//     ENDPOINT 需 endpoint_key 相等；
//   - 同合并键冲突时高优先级作用域覆盖低优先级（GLOBAL < APPLICATION < ENDPOINT）；
//     同优先级同键保留输入中先出现者（调用方应传入确定性排序，见 ListEnabledMaskingRules）；
//   - req 非 nil 时，exclusions 命中（identity/role 精确匹配，ip 支持精确或 CIDR 包含）
//     的规则从计划中剔除；
//   - 返回按合并键排序，结果确定。
func MaskPlanForEndpoint(endpointKey string, applicationID *uuid.UUID, rules []MaskingRule, req *MaskRequest) []MaskPlanEntry {
	merged := map[string]*MaskPlanEntry{}
	rank := map[string]int{}
	for i := range rules {
		r := &rules[i]
		if !r.Enabled {
			continue
		}
		switch r.Scope {
		case ScopeGlobal:
		case ScopeApplication:
			if applicationID == nil || r.ApplicationID == nil || *r.ApplicationID != *applicationID {
				continue
			}
		case ScopeEndpoint:
			if r.EndpointKey == nil || *r.EndpointKey != endpointKey {
				continue
			}
		default:
			continue
		}
		key := maskMergeKey(r)
		if key == "" {
			continue
		}
		exclusions, err := ParseMaskExclusions(r.Exclusions)
		if err != nil {
			exclusions = &MaskExclusions{} // 解析失败按无排除处理（fail 向脱敏侧）
		}
		if maskExcluded(exclusions, req) {
			continue
		}
		rk := scopeRank[r.Scope]
		if _, ok := merged[key]; ok && rank[key] > rk {
			continue // 已有更高优先级条目
		}
		if _, ok := merged[key]; ok && rank[key] == rk {
			continue // 同优先级保留先出现者
		}
		merged[key] = &MaskPlanEntry{
			RuleID:     r.ID,
			Scope:      r.Scope,
			FieldPath:  r.FieldPath,
			Algorithm:  r.Algorithm,
			Params:     r.Params,
			Exclusions: exclusions,
		}
		if r.DataType != nil {
			merged[key].DataType = *r.DataType
		}
		rank[key] = rk
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]MaskPlanEntry, 0, len(keys))
	for _, k := range keys {
		out = append(out, *merged[k])
	}
	return out
}
