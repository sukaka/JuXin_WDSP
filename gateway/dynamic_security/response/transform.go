package response

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// TransformResult 转换结果。
type TransformResult struct {
	Body          []byte // 重新编码后的响应体
	AppliedFields int    // 实际执行脱敏的字段数（数组逐元素计）
	SkippedFields int    // 目标为非标量等不适用而跳过的字段数（MASK/HASH/ENCRYPT/MAP 仅适用标量）
}

// ApplyJSON 对 JSON 响应体执行 transform plan（字段级脱敏）并重新编码。
// 旧调用不携带密钥；ENCRYPT/MAP 会明确报错，其他算法行为不变。
func ApplyJSON(body []byte, plan []dsctx.FieldTransform) (*TransformResult, error) {
	return ApplyJSONWithKey(body, plan, nil)
}

// ApplyJSONWithKey 对 JSON 响应体执行 transform plan，并为 ENCRYPT/MAP 提供密钥。
// 仅处理可安全重编码的完整 JSON；解析失败返回错误（调用方按失败策略处理，不得 panic）。
// 数字经 UseNumber 保留字面量；输出不转义 HTML（JSON API 语义不变、减小字节漂移）。
func ApplyJSONWithKey(body []byte, plan []dsctx.FieldTransform, crypto *MaskCrypto) (*TransformResult, error) {
	res := &TransformResult{}
	if len(plan) == 0 {
		res.Body = body
		return res, nil
	}
	// 同路径多规则：首条生效（规则顺序即优先级，确定性）
	byPath := make(map[string]dsctx.FieldTransform, len(plan))
	for _, tr := range plan {
		if tr.FieldPath == "" {
			continue
		}
		if _, ok := byPath[tr.FieldPath]; !ok {
			byPath[tr.FieldPath] = tr
		}
	}
	for path, tr := range byPath {
		switch Algorithm(tr.Algorithm) {
		case AlgorithmEncrypt:
			if crypto == nil || crypto.aead == nil {
				return nil, fmt.Errorf("ENCRYPT at %s requires mask crypto", path)
			}
			if tr.KeyID == "" || tr.KeyID != crypto.KeyID {
				return nil, fmt.Errorf("ENCRYPT at %s key_id does not match configured kid", path)
			}
		case AlgorithmMap:
			if crypto == nil || crypto.aead == nil {
				return nil, fmt.Errorf("MAP at %s requires mask crypto", path)
			}
			if tr.MapID == "" {
				return nil, fmt.Errorf("MAP at %s requires map_id", path)
			}
		}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("decode response json: %w", err)
	}
	if err := ensureSingleJSONValue(dec); err != nil {
		return nil, fmt.Errorf("decode response json: %w", err)
	}
	out, _, err := transformNode(v, "", byPath, res, crypto)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return nil, fmt.Errorf("re-encode response json: %w", err)
	}
	res.Body = bytes.TrimRight(buf.Bytes(), "\n")
	return res, nil
}

// ensureSingleJSONValue 探测首个 JSON 值之后的尾随数据：仅余空白为合法（第二次
// Decode 返回 io.EOF）；存在第二个值或垃圾字节即报错。改写路径重编码只输出第一个
// 值，尾随字节会被静默丢弃（{"a":1} <任意尾部> 解码成功但尾部不外发），故必须
// 按解析失败处理，由调用方走既有失败策略（FAIL_OPEN 直通原响应）。
func ensureSingleJSONValue(dec *json.Decoder) error {
	var trailing any
	switch err := dec.Decode(&trailing); {
	case err == io.EOF:
		return nil
	case err != nil:
		return err
	default:
		return fmt.Errorf("unexpected trailing data after first JSON value")
	}
}

// transformNode 递归执行计划；removed=true 表示该节点按 REMOVE 删除（由父容器摘除）。
func transformNode(v any, path string, plan map[string]dsctx.FieldTransform, res *TransformResult, crypto *MaskCrypto) (out any, removed bool, err error) {
	if path != "" {
		if tr, ok := plan[path]; ok {
			switch Algorithm(tr.Algorithm) {
			case AlgorithmRemove:
				res.AppliedFields++
				return nil, true, nil
			case AlgorithmMask, AlgorithmHash, AlgorithmEncrypt, AlgorithmMap:
				s, ok := scalarString(v)
				if !ok {
					// 非标量目标（object/array/null）：不适用，跳过（生成期已剔除，此处兜底）
					res.SkippedFields++
					return v, false, nil
				}
				var value string
				switch Algorithm(tr.Algorithm) {
				case AlgorithmMask:
					value = maskValue(s, tr.KeepHead, tr.KeepTail)
				case AlgorithmHash:
					value = hashValue(s)
				case AlgorithmEncrypt:
					value, err = crypto.encrypt(tr.KeyID, s)
				case AlgorithmMap:
					value, err = crypto.mapValue(tr.MapID, s)
				}
				if err != nil {
					return nil, false, fmt.Errorf("%s at %s: %w", tr.Algorithm, path, err)
				}
				res.AppliedFields++
				return value, false, nil
			default:
				// 未知算法（校验期已拦截，此处兜底不执行、不静默）
				res.SkippedFields++
				return v, false, nil
			}
		}
	}
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			childPath := k
			if path != "" {
				childPath = path + "." + k
			}
			newChild, rm, childErr := transformNode(child, childPath, plan, res, crypto)
			if childErr != nil {
				return nil, false, childErr
			}
			if rm {
				delete(t, k)
			} else {
				t[k] = newChild
			}
		}
		return t, false, nil
	case []any:
		elemPath := path + "[]"
		out := make([]any, 0, len(t))
		for _, el := range t {
			newEl, rm, childErr := transformNode(el, elemPath, plan, res, crypto)
			if childErr != nil {
				return nil, false, childErr
			}
			if !rm {
				out = append(out, newEl)
			}
		}
		return out, false, nil
	default:
		return v, false, nil
	}
}

// scalarString 取标量的字符串形式（string 原样；number 保留字面量；bool 转字面量）。
func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case json.Number:
		return t.String(), true
	case bool:
		return strconv.FormatBool(t), true
	default:
		return "", false
	}
}

// maskValue 保留前后各 keepHead/keepTail 字符，中间按原字符数替换为 *。
// 值过短（≤ keepHead+keepTail）时整体替换为 "****"，避免泄露精确长度与残留字符。
func maskValue(s string, keepHead, keepTail int) string {
	r := []rune(s)
	n := len(r)
	if n == 0 {
		return s
	}
	if keepHead < 0 {
		keepHead = 0
	}
	if keepTail < 0 {
		keepTail = 0
	}
	if n <= keepHead+keepTail {
		return "****"
	}
	return string(r[:keepHead]) + strings.Repeat("*", n-keepHead-keepTail) + string(r[n-keepTail:])
}

// hashValue sha256 hex（不可逆，可跨响应关联同一值）。
func hashValue(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
