package accesscontrolversions

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// DiffConfigs 对两份 guard 配置（JSON 对象）做顶层浅层对比，返回人类可读摘要行。
// 对比规则：顶层键的新增/移除；共有键按数组长度、对象哈希、标量值对比。
// 不做逐字段递归对比。返回空切片表示无差异。
func DiffConfigs(oldConfig, newConfig json.RawMessage) ([]string, error) {
	var oldObj, newObj map[string]interface{}
	if err := json.Unmarshal(oldConfig, &oldObj); err != nil {
		return nil, fmt.Errorf("parse base config: %w", err)
	}
	if err := json.Unmarshal(newConfig, &newObj); err != nil {
		return nil, fmt.Errorf("parse target config: %w", err)
	}

	keys := map[string]bool{}
	for k := range oldObj {
		keys[k] = true
	}
	for k := range newObj {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	lines := []string{}
	for _, k := range sorted {
		oldV, inOld := oldObj[k]
		newV, inNew := newObj[k]
		switch {
		case !inOld:
			lines = append(lines, fmt.Sprintf("%s: 新增（%s）", k, describeValue(newV)))
		case !inNew:
			lines = append(lines, fmt.Sprintf("%s: 移除（原%s）", k, describeValue(oldV)))
		default:
			if line := describeChange(k, oldV, newV); line != "" {
				lines = append(lines, line)
			}
		}
	}
	return lines, nil
}

// describeChange 描述共有键的变化；无变化返回空串。
func describeChange(key string, oldV, newV interface{}) string {
	if canonicalEqual(oldV, newV) {
		return ""
	}
	oldArr, oldIsArr := oldV.([]interface{})
	newArr, newIsArr := newV.([]interface{})
	if oldIsArr && newIsArr {
		if len(oldArr) != len(newArr) {
			return fmt.Sprintf("%s: %d -> %d 项", key, len(oldArr), len(newArr))
		}
		return fmt.Sprintf("%s: 数组内容已修改（%d 项）", key, len(newArr))
	}
	_, oldIsObj := oldV.(map[string]interface{})
	_, newIsObj := newV.(map[string]interface{})
	if oldIsObj && newIsObj {
		return fmt.Sprintf("%s: 配置已修改", key)
	}
	if oldIsArr != newIsArr || oldIsObj != newIsObj {
		return fmt.Sprintf("%s: 类型变化（%s -> %s）", key, typeName(oldV), typeName(newV))
	}
	return fmt.Sprintf("%s: %s -> %s", key, scalarStr(oldV), scalarStr(newV))
}

// canonicalEqual 通过规范化 JSON（encoding/json 对 map 键排序）比较两个值。
func canonicalEqual(a, b interface{}) bool {
	ba, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bb, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(ba) == string(bb)
}

// describeValue 简要描述一个值（用于新增/移除摘要）。
func describeValue(v interface{}) string {
	switch vv := v.(type) {
	case []interface{}:
		return fmt.Sprintf("%d 项数组", len(vv))
	case map[string]interface{}:
		return fmt.Sprintf("%d 个键的对象", len(vv))
	default:
		return scalarStr(v)
	}
}

func typeName(v interface{}) string {
	switch v.(type) {
	case []interface{}:
		return "数组"
	case map[string]interface{}:
		return "对象"
	case string:
		return "字符串"
	case bool:
		return "布尔"
	case nil:
		return "null"
	default:
		return "数值"
	}
}

func scalarStr(v interface{}) string {
	s := fmt.Sprintf("%v", v)
	if len(s) > 64 {
		s = s[:64] + "..."
	}
	return strings.ReplaceAll(s, "\n", " ")
}
