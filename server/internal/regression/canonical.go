// canonical.go 确定字节编码：固定 schema 的字节级规范形。
//
// 规范形定义（版本化，随 manifest schema v1 冻结）：
//   - UTF-8、无 BOM、无行尾空白之外的冗余——即 encoding/json 紧凑编码；
//   - 对象键按字典序（Go encoding/json 对 map[string]any 的默认排序）；
//   - 数字经 UseNumber 保留原文（避免 1e2 与 100 规范化歧义，签名字节即原文字节）；
//   - 同一对象内重复键直接拒绝（Go 默认解码会静默取后者，必须显式拦截）。
//
// 校验方式：流式 token 遍历拒绝重复键 → UseNumber 解码 → 再编码与原文字节
// 逐字节比较。签名以原文字节为准，因此「确定编码」不满足即拒绝验签。
package regression

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// ValidateCanonicalJSON 校验 data 为无重复键的规范 JSON 字节，返回解码值
// （map[string]any，数字为 json.Number）。
func ValidateCanonicalJSON(data []byte) (map[string]any, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing content", ErrInvalidManifest)
	}
	re, err := canonicalReencode(v)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(re, data) {
		return nil, ErrNonCanonical
	}
	return v, nil
}

// ValidateCanonicalJSONArray 同 ValidateCanonicalJSON，顶层为数组（用例分块内
// cases 字段之外的独立分块文件不强制对象顶层，保留给数组型对象）。
func ValidateCanonicalJSONArray(data []byte) ([]any, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v []any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing content", ErrInvalidManifest)
	}
	re, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(re, data) {
		return nil, ErrNonCanonical
	}
	return v, nil
}

// canonicalReencode 按规范形再编码（json.Marshal 对 map 键排序、紧凑无空白；
// 关闭 HTML 转义以保证「再编码 == 原文」判定不受 <>& 影响——签名字节为原文，
// 转义差异只会导致拒绝而非误放行，但固定口径可减少正常文件被误拒）。
func canonicalReencode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// rejectDuplicateKeys 流式遍历 JSON token，任一对象内出现重复键即拒绝。
func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var walk func(depth int) error
	walk = func(depth int) error {
		if depth > 200 {
			return fmt.Errorf("%w: nesting too deep", ErrInvalidManifest)
		}
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok.(type) {
		case json.Delim:
			d := tok.(json.Delim)
			switch d {
			case '{':
				seen := map[string]struct{}{}
				for dec.More() {
					kt, err := dec.Token()
					if err != nil {
						return err
					}
					key, ok := kt.(string)
					if !ok {
						return fmt.Errorf("%w: non-string key", ErrInvalidManifest)
					}
					if _, dup := seen[key]; dup {
						return fmt.Errorf("%w: key %q", ErrDuplicateKeys, key)
					}
					seen[key] = struct{}{}
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
				if _, err := dec.Token(); err != nil { // consume '}'
					return err
				}
			case '[':
				for dec.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
				if _, err := dec.Token(); err != nil { // consume ']'
					return err
				}
			default:
				return fmt.Errorf("%w: unexpected delimiter %q", ErrInvalidManifest, d)
			}
		}
		return nil
	}
	if err := walk(0); err != nil {
		if err == io.EOF {
			return fmt.Errorf("%w: empty document", ErrInvalidManifest)
		}
		return err
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing content", ErrInvalidManifest)
	}
	return nil
}
