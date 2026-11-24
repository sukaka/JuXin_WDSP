// spec_asyncapi.go AsyncAPI 2.x / 3.x（.yaml/.yml/.json）规范导入解析。
// 支持 AsyncAPI 2.x（channels.<name>.publish / subscribe）与 AsyncAPI 3.x（operations + channels），
// 支持解析文档内 #/components/... 与 #/channels/... 本地 JSON Pointer 引用（外部 $ref 在上层统一拒绝）。
// 解析为纯逻辑（不依赖 DB），由 spec_formats_test.go 覆盖。
package apisecurity

import (
	"fmt"
	"strings"
)

// ParseAsyncAPI 解析 AsyncAPI 2.x / 3.x 文档为操作清单。
func ParseAsyncAPI(doc map[string]any) ([]SpecOperation, error) {
	ver, _ := doc["asyncapi"].(string)
	ver = strings.TrimSpace(ver)
	switch {
	case strings.HasPrefix(ver, "2."):
		return parseAsyncAPI2(doc)
	case strings.HasPrefix(ver, "3."):
		return parseAsyncAPI3(doc)
	default:
		return nil, fmt.Errorf("%w: 仅支持 AsyncAPI 2.x 与 3.x（asyncapi=%q）", ErrSpecInvalidAsyncAPI, truncateRefValue(ver))
	}
}

func parseAsyncAPI2(doc map[string]any) ([]SpecOperation, error) {
	channels, ok := doc["channels"].(map[string]any)
	if !ok || len(channels) == 0 {
		return nil, fmt.Errorf("%w: AsyncAPI 2.x 缺少有效的 channels 定义", ErrSpecInvalidAsyncAPI)
	}
	ops := []SpecOperation{}
	for chName, chRaw := range channels {
		chObj := resolveInternalMap(doc, chRaw, 0)
		if chObj == nil {
			continue
		}
		path := normalizeAsyncChannelPath(chName)
		chParams := asyncChannelParams(doc, chObj, path)
		matched := false
		for _, verb := range []string{"publish", "subscribe"} {
			opRaw, has := chObj[verb]
			if !has {
				continue
			}
			opObj := resolveInternalMap(doc, opRaw, 0)
			if opObj == nil {
				continue
			}
			matched = true
			params := append([]SpecParam{}, chParams...)
			params = append(params, asyncMessageParams(doc, opObj["message"])...)
			method := strings.ToUpper(verb)
			ops = append(ops, SpecOperation{
				Method: method,
				Path:   path,
				Key:    method + " " + path,
				Params: sortAndDedupeSpecParams(params),
			})
		}
		if !matched {
			// channel 未声明 publish/subscribe 时仍登记为事件通道（EVENT）
			ops = append(ops, SpecOperation{
				Method: "EVENT",
				Path:   path,
				Key:    "EVENT " + path,
				Params: sortAndDedupeSpecParams(chParams),
			})
		}
	}
	ops = sortAndDedupeSpecOps(ops)
	if len(ops) == 0 {
		return nil, fmt.Errorf("%w: 未在 channels 中解析出有效操作", ErrSpecInvalidAsyncAPI)
	}
	return ops, nil
}

func parseAsyncAPI3(doc map[string]any) ([]SpecOperation, error) {
	ops := []SpecOperation{}
	channels, _ := doc["channels"].(map[string]any)
	operations, _ := doc["operations"].(map[string]any)

	if len(operations) > 0 {
		for opName, opRaw := range operations {
			opObj := resolveInternalMap(doc, opRaw, 0)
			if opObj == nil {
				continue
			}
			action := strings.ToUpper(strings.TrimSpace(stringOrEmpty(opObj["action"])))
			if action != "SEND" && action != "RECEIVE" {
				action = "EVENT"
			}
			chObj := resolveInternalMap(doc, opObj["channel"], 0)
			addr := ""
			if chObj != nil {
				addr = strings.TrimSpace(stringOrEmpty(chObj["address"]))
			}
			if addr == "" {
				if chMap, ok := opObj["channel"].(map[string]any); ok {
					if ref, ok := chMap["$ref"].(string); ok {
						parts := strings.Split(strings.TrimPrefix(ref, "#/"), "/")
						addr = unescapeJSONPointer(parts[len(parts)-1])
					}
				}
			}
			if addr == "" {
				addr = opName
			}
			path := normalizeAsyncChannelPath(addr)
			params := asyncChannelParams(doc, chObj, path)
			// AsyncAPI 3.x：优先读取 operation.messages，否则回退 channel.messages
			if msgs, ok := opObj["messages"].([]any); ok && len(msgs) > 0 {
				for _, m := range msgs {
					params = append(params, asyncMessageParams(doc, m)...)
				}
			} else if chObj != nil {
				if chMsgs, ok := chObj["messages"].(map[string]any); ok {
					for _, m := range chMsgs {
						params = append(params, asyncMessageParams(doc, m)...)
					}
				}
			}
			ops = append(ops, SpecOperation{
				Method: action,
				Path:   path,
				Key:    action + " " + path,
				Params: sortAndDedupeSpecParams(params),
			})
		}
	} else if len(channels) > 0 {
		// 仅声明 channels 未声明 operations 的 AsyncAPI 3.x
		for chName, chRaw := range channels {
			chObj := resolveInternalMap(doc, chRaw, 0)
			if chObj == nil {
				continue
			}
			addr := strings.TrimSpace(stringOrEmpty(chObj["address"]))
			if addr == "" {
				addr = chName
			}
			path := normalizeAsyncChannelPath(addr)
			params := asyncChannelParams(doc, chObj, path)
			if chMsgs, ok := chObj["messages"].(map[string]any); ok {
				for _, m := range chMsgs {
					params = append(params, asyncMessageParams(doc, m)...)
				}
			}
			ops = append(ops, SpecOperation{
				Method: "EVENT",
				Path:   path,
				Key:    "EVENT " + path,
				Params: sortAndDedupeSpecParams(params),
			})
		}
	}

	ops = sortAndDedupeSpecOps(ops)
	if len(ops) == 0 {
		return nil, fmt.Errorf("%w: AsyncAPI 3.x 缺少有效的 operations 或 channels 定义", ErrSpecInvalidAsyncAPI)
	}
	return ops, nil
}

func normalizeAsyncChannelPath(ch string) string {
	ch = strings.TrimSpace(ch)
	if ch == "" {
		return "/"
	}
	if !strings.HasPrefix(ch, "/") {
		return "/" + ch
	}
	return ch
}

func asyncChannelParams(doc, chObj map[string]any, path string) []SpecParam {
	params := []SpecParam{}
	if chObj != nil {
		if pm, ok := chObj["parameters"].(map[string]any); ok {
			for name, raw := range pm {
				pObj := resolveInternalMap(doc, raw, 0)
				pType := "string"
				if pObj != nil {
					if sch := resolveInternalMap(doc, pObj["schema"], 0); sch != nil {
						if t, ok := sch["type"].(string); ok && t != "" {
							pType = t
						}
					}
				}
				params = append(params, SpecParam{Name: name, In: "PATH", Type: pType, Required: true})
			}
		}
	}
	for _, m := range specPathPlaceholderPattern.FindAllStringSubmatch(path, -1) {
		params = append(params, SpecParam{Name: m[1], In: "PATH", Type: "string", Required: true})
	}
	return params
}

func asyncMessageParams(doc map[string]any, raw any) []SpecParam {
	msg := resolveInternalMap(doc, raw, 0)
	if msg == nil {
		return nil
	}
	// oneOf 多消息合并提取
	if oneOf, ok := msg["oneOf"].([]any); ok {
		out := []SpecParam{}
		for _, sub := range oneOf {
			out = append(out, asyncMessageParams(doc, sub)...)
		}
		return out
	}
	out := []SpecParam{}
	if payload := resolveInternalMap(doc, msg["payload"], 0); payload != nil {
		out = append(out, asyncSchemaObjectParams(doc, payload, "BODY")...)
	}
	if headers := resolveInternalMap(doc, msg["headers"], 0); headers != nil {
		out = append(out, asyncSchemaObjectParams(doc, headers, "HEADER")...)
	}
	return out
}

func asyncSchemaObjectParams(doc, schema map[string]any, in string) []SpecParam {
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return nil
	}
	reqSet := map[string]bool{}
	for _, r := range stringSlice(schema["required"]) {
		reqSet[r] = true
	}
	out := make([]SpecParam, 0, len(props))
	for name, propRaw := range props {
		pObj := resolveInternalMap(doc, propRaw, 0)
		pType := ""
		if pObj != nil {
			pType, _ = pObj["type"].(string)
		}
		out = append(out, SpecParam{
			Name:     name,
			In:       in,
			Type:     pType,
			Required: reqSet[name],
		})
	}
	return out
}

// resolveInternalMap 解析文档内 #/... 本地引用（有深度限制防自引用循环）。
func resolveInternalMap(doc map[string]any, raw any, depth int) map[string]any {
	if depth > 16 || raw == nil {
		return nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	if ref, ok := m["$ref"].(string); ok && strings.HasPrefix(ref, "#/") {
		target := lookupJSONPointer(doc, ref)
		if tm, ok := target.(map[string]any); ok {
			return resolveInternalMap(doc, tm, depth+1)
		}
	}
	return m
}

func lookupJSONPointer(root any, ref string) any {
	if ref == "#" || ref == "#/" {
		return root
	}
	trimmed := strings.TrimPrefix(ref, "#/")
	cur := root
	for _, seg := range strings.Split(trimmed, "/") {
		key := unescapeJSONPointer(seg)
		switch node := cur.(type) {
		case map[string]any:
			var ok bool
			cur, ok = node[key]
			if !ok {
				return nil
			}
		default:
			return nil
		}
	}
	return cur
}

func unescapeJSONPointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~1", "/"), "~0", "~")
}
