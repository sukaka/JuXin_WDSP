package jwtverify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// 严格 JSON 解析（§5.2）：拒绝任意层级重复键、限制深度与 token 数。
// encoding/json 对重复键采取“后者覆盖”，不满足验证严格性，因此在常规
// 反序列化前先做一次 token 级校验。
const (
	maxJSONDepth  = 8
	maxJSONTokens = 4096
)

var (
	errJSONTrailing = errors.New("JSON 存在多余尾部数据")
	errJSONDepth    = errors.New("JSON 嵌套过深")
	errJSONTooMany  = errors.New("JSON token 数超限")
	errJSONDupKey   = errors.New("JSON 存在重复键")
	errJSONNotObj   = errors.New("JSON 顶层不是对象")
)

// strictJSONObject 严格解析 JSON 对象：任意层级重复键即拒绝，
// 深度/规模有界，顶层必须为对象。
func strictJSONObject(data []byte) (map[string]json.RawMessage, error) {
	if err := validateJSONStrict(data); err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errJSONNotObj
	}
	return m, nil
}

func validateJSONStrict(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	count := 0
	if err := walkJSON(dec, 0, &count); err != nil {
		return err
	}
	if dec.More() {
		return errJSONTrailing
	}
	return nil
}

func walkJSON(dec *json.Decoder, depth int, count *int) error {
	if depth > maxJSONDepth {
		return errJSONDepth
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	*count++
	if *count > maxJSONTokens {
		return errJSONTooMany
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{}, 8)
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := kt.(string)
			if !ok {
				return fmt.Errorf("JSON 对象键非字符串")
			}
			*count++
			if *count > maxJSONTokens {
				return errJSONTooMany
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("%w: %q", errJSONDupKey, key)
			}
			seen[key] = struct{}{}
			if err := walkJSON(dec, depth+1, count); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // 读取 '}'
			return err
		}
	case '[':
		for dec.More() {
			if err := walkJSON(dec, depth+1, count); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil { // 读取 ']'
			return err
		}
	default:
		return fmt.Errorf("非法 JSON 分隔符: %v", delim)
	}
	return nil
}
