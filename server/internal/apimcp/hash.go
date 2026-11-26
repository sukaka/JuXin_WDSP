// hash.go 目录摘要算法（NG-MCP §1.3 冻结）：
// tool_hash = "mcp-tool-sha256:v1:" + hex(sha256(canonical))——canonical 为五元组
// （tool_name, tool_version, 规范化描述全文, input_schema, output_schema）的确定性
// 序列化（Go encoding/json 对 map[string]any 键排序 marshaling、无空白；
// **产品内部规范化，不宣称 JCS/RFC 8785 等价**）；
// catalog_hash = "mcp-catalog-sha256:v1:" + hex(sha256(排序后**无分隔符直接拼接**的
// APPROVED 工具 tool_hash))——发布集摘要（server 导入/审核时维护，网关装配期
// 重算比对，不符整目录拒装不误断）。
// 分隔符裁决（批次 C 联调修正登记）：设计 §1.3「排序后拼接」未逐字冻结分隔符，
// B1 初实现取 "\n"、B2 网关侧取 ""——跨轨不一致导致装配期整目录拒装
// （COV_NO_CATALOG 全放行，联调实证）；以已复核网关侧为准对齐 ""（排序定长
// 摘要串直接拼接即单射，安全语义等价）。后续跨轨算法应在设计线契约逐字冻结分隔符。
package apimcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// ToolHashPrefix / CatalogHashPrefix / ToolDefinitionHashPrefix 摘要域分隔前缀（版本化词表——算法升级须换前缀）。
const (
	ToolHashPrefix           = "mcp-tool-sha256:v1:"
	CatalogHashPrefix        = "mcp-catalog-sha256:v1:"
	ToolDefinitionHashPrefix = "mcp-def-sha256:v1:"
)

// canonicalDefinitionSchema 将工具 inputSchema JSON 规范化为无空白且对象键递归排序的紧凑 JSON；
// 空字节或 JSON null 统一归一为 "null"（与网关 mcpguard/tool_pinning.go 逐字节一致）。
func canonicalDefinitionSchema(raw json.RawMessage) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return []byte("null")
	}
	var v any
	if err := json.Unmarshal(trimmed, &v); err != nil {
		return trimmed
	}
	if v == nil {
		return []byte("null")
	}
	canon, err := json.Marshal(v)
	if err != nil {
		return trimmed
	}
	return canon
}

// ComputeToolDefinitionHash 计算工具定义钉扎摘要（Phase 9C-1 Rug Pull 防护）：
// "mcp-def-sha256:v1:" + hex(sha256(name + "\x00" + description + "\x00" + canonicalJSON(inputSchema)))。
// name 与 description 按原文入算（不做 TrimSpace），确保尾随空格或隐形字符篡改必然触发漂移告警；
// 与网关 gateway/dynamic_security/detectors/mcpguard.ComputeToolDefinitionHash 逐字节一致。
func ComputeToolDefinitionHash(name, description string, inputSchema json.RawMessage) string {
	canon := canonicalDefinitionSchema(inputSchema)
	h := sha256.New()
	_, _ = h.Write([]byte(name))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(description))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(canon)
	return ToolDefinitionHashPrefix + hex.EncodeToString(h.Sum(nil))
}

// schemaCanonical schema 规范化序列化（nil → JSON null；map 键排序由
// encoding/json 保证（Go 对 map[string]any 的 marshaling 键序确定）；无空白）。
func schemaCanonical(schema *map[string]any) ([]byte, error) {
	if schema == nil {
		return []byte("null"), nil
	}
	return json.Marshal(*schema)
}

// ComputeToolHash 计算工具不可变摘要（五元组确定性序列化；同输入恒同输出）。
func ComputeToolHash(toolName, toolVersion, description string, inputSchema, outputSchema *map[string]any) (string, error) {
	inRaw, err := schemaCanonical(inputSchema)
	if err != nil {
		return "", err
	}
	outRaw, err := schemaCanonical(outputSchema)
	if err != nil {
		return "", err
	}
	canonical, err := json.Marshal(map[string]any{
		"description":   description,
		"input_schema":  json.RawMessage(inRaw),
		"output_schema": json.RawMessage(outRaw),
		"tool_name":     toolName,
		"tool_version":  toolVersion,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return ToolHashPrefix + hex.EncodeToString(sum[:]), nil
}

// ComputeCatalogHash 计算发布集摘要（APPROVED 工具 tool_hash 排序后**无分隔符
// 直接拼接**的 sha256——分隔符以网关装配侧重算算法为准（批次 C 联调对齐裁决，
// 见包注释）；空 APPROVED 集 = 空串拼接的 sha256（确定性，网关同算法可重算比对）。
func ComputeCatalogHash(approvedToolHashes []string) string {
	sorted := append([]string(nil), approvedToolHashes...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "")))
	return CatalogHashPrefix + hex.EncodeToString(sum[:])
}

// toolSemanticallyEqual 工具语义相等判定（M02：同名任何描述/Schema/版本变更即不等
// ——描述经 description_digest（sha256 原文）比较、tool_version 精确、双 schema
// 规范化 JSON 逐字节比较（与 canonical 同源）。相等行保持原 tool_hash 与
// review_status（幂等重导不重置审核）；不等行重算 tool_hash+重置 PENDING_REVIEW
// （旧审批不继承）。
func toolSemanticallyEqual(t Tool, toolVersion, descriptionDigest string, inputSchema, outputSchema *map[string]any) bool {
	if t.ToolVersion != toolVersion || t.DescriptionDigest != descriptionDigest {
		return false
	}
	inRaw, err := schemaCanonical(inputSchema)
	if err != nil {
		return false
	}
	outRaw, err := schemaCanonical(outputSchema)
	if err != nil {
		return false
	}
	inDB, err := schemaCanonical(nilSchemaP(&t.InputSchema))
	if err != nil {
		return false
	}
	outDB, err := schemaCanonical(nilSchemaP(&t.OutputSchema))
	if err != nil {
		return false
	}
	return string(inRaw) == string(inDB) && string(outRaw) == string(outDB)
}

// nilSchemaP schema 归一（nil 指针/空 map 同义归一为 nil——导入 nil 与再导入 {}
// 的规范化一致性（map[]{} 与 null 不混判变更）。
func nilSchemaP(m *map[string]any) *map[string]any {
	if m == nil || len(*m) == 0 {
		return nil
	}
	return m
}
