// Package capability 节点能力契约（NG-BASE-02 §2.1）：CapabilityManifest 类型、
// 契约校验与「发布所需能力 ⊆ 节点能力」的集合包含检查。
//
// 门禁语义（契约，唯一事实源）：
//   - 发布负载携带 required_capabilities（同构子集）；节点缺任一必需项 →
//     该节点发布失败并展示缺口（CAP_MISSING:<key>），不得静默降级；
//   - 能力比较是集合/层级包含，不是产品版本字符串比较；
//   - 未知字段读取端忽略（向前兼容），但 contract_version 不一致即拒绝协商。
package capability

import (
	"fmt"
	"sort"
	"strings"
)

// ContractVersion 本契约文档版本（协商双方必须一致）。
const ContractVersion = "ngc/0.1"

// ProtocolLevels 各协议能力层级（有序，下标越大能力越强；节点层级 ≥ 需求层级即满足）。
// 层级命名与 RD_PLAN 分期一致；新增层级只准追加，不得改序。
var ProtocolLevels = map[string][]string{
	"http":    {"1.0", "1.1", "2"},
	"graphql": {"off", "parse", "cost_v1"},
	"grpc":    {"frame", "unary_g1", "stream_g2"},
	"mcp":     {"observe", "acl_v1"},
}

// Manifest 节点能力清单（契约 §2.1 CapabilityManifest）。
type Manifest struct {
	ContractVersion string            `json:"contract_version"`
	NodeID          string            `json:"node_id"`
	ProductVersion  string            `json:"product_version"` // 信息性，不作为能力判定依据
	BuildDigest     string            `json:"build_digest"`
	Protocols       map[string]string `json:"protocols"`  // 协议 → 节点当前最高层级（如 {"graphql":"cost_v1"}）
	Detectors       []DetectorCap     `json:"detectors"`  // 检测器能力（命名空间+契约版本）
	Actions         []string          `json:"actions"`    // 支持动作集合
	Limits          map[string]int64  `json:"limits"`     // 节点硬上限（如 max_grpc_frame_bytes）
	GeneratedAt     string            `json:"generated_at"`
}

// DetectorCap 检测器能力项。
type DetectorCap struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Missing 能力缺口（发布失败时逐条展示）。
type Missing struct {
	Key      string `json:"key"`      // CAP_MISSING:<key> 的 key 部分（protocols.graphql / detectors.authzdecide / actions.grpc_error / limits.max_grpc_frame_bytes / contract_version）
	Required string `json:"required"` // 需求值
	Actual   string `json:"actual"`   // 节点实际值（缺失时为空）
}

// Validate 契约级校验（节点自报侧）：版本一致、层级合法、字段完备。
func (m Manifest) Validate() string {
	if m.ContractVersion != ContractVersion {
		return fmt.Sprintf("contract_version 不一致: %q（本端 %q）", m.ContractVersion, ContractVersion)
	}
	if m.NodeID == "" {
		return "node_id 必填"
	}
	for proto, level := range m.Protocols {
		levels, ok := ProtocolLevels[proto]
		if !ok {
			continue // 未知协议键忽略（向前兼容）
		}
		if levelIndex(levels, level) < 0 {
			return fmt.Sprintf("protocols.%s 层级非法: %q", proto, level)
		}
	}
	return ""
}

// CheckRequirements 集合包含校验：required 的每一项都被 manifest 满足时返回 nil，
// 否则按维度逐条返回缺口（稳定排序：先 contract_version，再 protocols/detectors/actions/limits）。
func CheckRequirements(required Manifest, node Manifest) []Missing {
	var out []Missing
	// contract_version 不一致即拒绝协商（唯一顶层缺口，继续列出细节便于一次性修复）
	if required.ContractVersion != node.ContractVersion {
		out = append(out, Missing{Key: "contract_version", Required: required.ContractVersion, Actual: node.ContractVersion})
	}
	for proto, reqLevel := range required.Protocols {
		levels, ok := ProtocolLevels[proto]
		if !ok {
			continue // 需求侧未知键忽略（与读取端同口径）
		}
		act := node.Protocols[proto]
		if levelIndex(levels, act) < levelIndex(levels, reqLevel) {
			out = append(out, Missing{Key: "protocols." + proto, Required: reqLevel, Actual: act})
		}
	}
	for _, d := range required.Detectors {
		found := ""
		for _, nd := range node.Detectors {
			if nd.Name == d.Name {
				found = nd.Version
				break
			}
		}
		if found == "" || !versionSatisfies(found, d.Version) {
			out = append(out, Missing{Key: "detectors." + d.Name, Required: d.Version, Actual: found})
		}
	}
	for _, a := range required.Actions {
		if !contains(node.Actions, a) {
			out = append(out, Missing{Key: "actions." + a, Required: a, Actual: ""})
		}
	}
	for _, lk := range sortedKeys(required.Limits) {
		reqV := required.Limits[lk]
		if reqV <= 0 {
			continue // 需求 0/负值 = 无约束（即使节点未上报该项）
		}
		actV, ok := node.Limits[lk]
		// 节点硬上限必须不低于需求配置上限
		if !ok || actV < reqV {
			out = append(out, Missing{Key: "limits." + lk, Required: fmt.Sprintf("%d", reqV), Actual: fmt.Sprintf("%d", actV)})
		}
	}
	return out
}

// levelIndex 层级在有序表中的位置（未知返回 -1，使任何已知层级都高于未知）。
func levelIndex(levels []string, level string) int {
	for i, l := range levels {
		if l == level {
			return i
		}
	}
	return -1
}

// versionSatisfies 检测器版本满足判定：命名空间一致且节点版本序数不低于需求。
// 版本形如 "az/1"、"cost_v1"；主版本段（/前）必须一致，序数（/后数字）节点 ≥ 需求。
func versionSatisfies(actual, required string) bool {
	if actual == required {
		return true
	}
	aNs, aNum := splitVersion(actual)
	rNs, rNum := splitVersion(required)
	if rNs == "" {
		return true // 需求无版本约束
	}
	return aNs == rNs && aNum >= rNum
}

func splitVersion(v string) (ns string, num int) {
	parts := strings.SplitN(v, "/", 2)
	if len(parts) != 2 {
		return v, 0
	}
	n := 0
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			return parts[0], n
		}
		n = n*10 + int(c-'0')
	}
	return parts[0], n
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
