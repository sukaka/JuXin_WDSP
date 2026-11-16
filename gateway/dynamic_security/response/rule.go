// Package response API 响应侧安全：脱敏规则（MaskRule）、transform plan 生成、
// JSON 字段级 Response Transformer、错误签名提取。
//
// 数据最小化：本包不输出响应明文值；脱敏算法（MASK/HASH/ENCRYPT/MAP/REMOVE）在内存中对
// 解码后的 JSON 树执行，结果经重新编码写回，证据/事件只含字段路径与数据类型标签。
package response

import (
	"fmt"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// Algorithm 脱敏算法。
type Algorithm string

const (
	// AlgorithmMask 保留前后各 keep_head/keep_tail 字符（默认 3/4），中间按原长度替换为星号；
	// 短于 keep_head+keep_tail 的值整体替换为 "****"（不泄露精确长度与残留字符）。
	AlgorithmMask Algorithm = "MASK"
	// AlgorithmHash sha256 hex（对标量的字符串形式取摘要，不可逆、可跨响应关联）。
	AlgorithmHash Algorithm = "HASH"
	// AlgorithmRemove 删除字段（对象成员删键；数组元素从数组中移除）。
	AlgorithmRemove Algorithm = "REMOVE"
	// AlgorithmEncrypt AES-256-GCM 加密，需 key_id。
	AlgorithmEncrypt Algorithm = "ENCRYPT"
	// AlgorithmMap 带密钥的稳定映射，需 map_id。
	AlgorithmMap Algorithm = "MAP"
)

// MASK 算法参数默认值与上限。
const (
	DefaultKeepHead = 3
	DefaultKeepTail = 4
	maxKeepChars    = 64
)

// 规则与路径上限（防超大配置撑爆内存与日志）。
const (
	MaxRules          = 512
	maxFieldPathLen   = 256
	maxDataTypeLen    = 64
	maxEndpointKeyLen = 560
)

// MaskRule 单条响应脱敏规则（由 api_mask_rules 配置解析；EndpointKey 为归组键）。
//
// FieldPath 语义（点路径）：
//   - 段以 "." 分隔，逐层进入对象成员，如 user.address.phone；
//   - 段名以 "[]" 结尾表示数组通配：对数组每个元素继续匹配剩余路径，
//     如 users[].phone 命中每个元素的 phone 字段；users[] 命中数组每个标量元素本身；
//   - 路径与解析产物的字段路径同构（数组段记 []），逐字符精确匹配；
//   - JSON 键名本身含 "." 的字段无法寻址（点路径 DSL 的既定限制）。
type MaskRule struct {
	EndpointKey string
	FieldPath   string
	DataType    string // 数据类型标签（描述性元数据，写入计划与证据，不参与匹配）
	Algorithm   Algorithm
	KeepHead    int
	KeepTail    int
	KeyID       string // ENCRYPT 密钥标识（仅标识，不含密钥）
	MapID       string // MAP 映射标识（仅标识，不含密钥）
}

// ParseMaskRule 解析并校验单条规则（params 支持 keep_head/keep_tail/key_id/map_id）。
// key_id/map_id 均为 1-64 位 [A-Za-z0-9_-]；ENCRYPT 必须 key_id，MAP 必须 map_id。
// 校验失败返回错误（配置错误必须显式暴露，不静默吞错）。
func ParseMaskRule(endpointKey, fieldPath, dataType, algorithm string, params map[string]any) (MaskRule, error) {
	var rule MaskRule
	if endpointKey == "" || len(endpointKey) > maxEndpointKeyLen {
		return rule, fmt.Errorf("endpoint_key required and must be <= %d chars", maxEndpointKeyLen)
	}
	if err := validateFieldPath(fieldPath); err != nil {
		return rule, err
	}
	if len(dataType) > maxDataTypeLen {
		return rule, fmt.Errorf("data_type must be <= %d chars", maxDataTypeLen)
	}
	switch Algorithm(algorithm) {
	case AlgorithmMask, AlgorithmHash, AlgorithmRemove, AlgorithmEncrypt, AlgorithmMap:
		rule.Algorithm = Algorithm(algorithm)
	default:
		return rule, fmt.Errorf("algorithm must be MASK, HASH, REMOVE, ENCRYPT or MAP, got %q", algorithm)
	}
	rule.EndpointKey = endpointKey
	rule.FieldPath = fieldPath
	rule.DataType = dataType
	rule.KeepHead = DefaultKeepHead
	rule.KeepTail = DefaultKeepTail
	for k, v := range params {
		switch k {
		case "keep_head", "keep_tail":
			n, err := paramNonNegativeInt(k, v)
			if err != nil {
				return rule, err
			}
			if n > maxKeepChars {
				return rule, fmt.Errorf("params.%s must be <= %d", k, maxKeepChars)
			}
			if k == "keep_head" {
				rule.KeepHead = n
			} else {
				rule.KeepTail = n
			}
		case "key_id", "map_id":
			value, err := paramMaskIdentifier(k, v)
			if err != nil {
				return rule, err
			}
			if k == "key_id" {
				rule.KeyID = value
			} else {
				rule.MapID = value
			}
		default:
			return rule, fmt.Errorf("unknown params key %q", k)
		}
	}
	if rule.Algorithm == AlgorithmEncrypt && rule.KeyID == "" {
		return rule, fmt.Errorf("params.key_id is required for ENCRYPT")
	}
	if rule.Algorithm == AlgorithmMap && rule.MapID == "" {
		return rule, fmt.Errorf("params.map_id is required for MAP")
	}
	return rule, nil
}

func paramMaskIdentifier(key string, value any) (string, error) {
	s, ok := value.(string)
	if !ok || len(s) == 0 || len(s) > 64 {
		return "", fmt.Errorf("params.%s must be 1-64 chars of [A-Za-z0-9_-]", key)
	}
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return "", fmt.Errorf("params.%s must be 1-64 chars of [A-Za-z0-9_-]", key)
	}
	return s, nil
}

// validateFieldPath 校验点路径形态：段非空、数组段以 [] 结尾、无空段。
func validateFieldPath(p string) error {
	if p == "" || len(p) > maxFieldPathLen {
		return fmt.Errorf("field_path required and must be <= %d chars", maxFieldPathLen)
	}
	for _, seg := range strings.Split(p, ".") {
		name := strings.TrimSuffix(seg, "[]")
		if name == "" {
			return fmt.Errorf("field_path %q: empty segment", p)
		}
	}
	return nil
}

// paramNonNegativeInt 解析非负整数参数（JSON 解码为 float64；接受整型族群）。
func paramNonNegativeInt(key string, v any) (int, error) {
	switch t := v.(type) {
	case float64:
		if t < 0 || t != float64(int(t)) {
			return 0, fmt.Errorf("params.%s must be a non-negative integer", key)
		}
		return int(t), nil
	case int:
		if t < 0 {
			return 0, fmt.Errorf("params.%s must be a non-negative integer", key)
		}
		return t, nil
	case int64:
		if t < 0 {
			return 0, fmt.Errorf("params.%s must be a non-negative integer", key)
		}
		return int(t), nil
	default:
		return 0, fmt.Errorf("params.%s must be a non-negative integer", key)
	}
}

// BuildTransformPlan 由端点规则与响应解析产物生成 transform plan：
// 仅收录字段路径在解析产物中真实存在、且算法对该类型可执行的规则
// （object/array 目标仅 REMOVE 可执行，MASK/HASH/ENCRYPT/MAP 空转项在生成期剔除，
// 保证"plan 非空"对决策引擎是有执行含义的信号）。规则顺序即计划顺序。
func BuildTransformPlan(rules []MaskRule, fields map[string]string) []dsctx.FieldTransform {
	var plan []dsctx.FieldTransform
	for _, rl := range rules {
		typ, ok := fields[rl.FieldPath]
		if !ok {
			continue
		}
		if (typ == "object" || typ == "array") && rl.Algorithm != AlgorithmRemove {
			continue
		}
		plan = append(plan, dsctx.FieldTransform{
			FieldPath: rl.FieldPath,
			DataType:  rl.DataType,
			Algorithm: string(rl.Algorithm),
			KeepHead:  rl.KeepHead,
			KeepTail:  rl.KeepTail,
			KeyID:     rl.KeyID,
			MapID:     rl.MapID,
		})
	}
	return plan
}
