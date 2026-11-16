package apidata

import (
	"encoding/json"
	"fmt"
)

func validateMaskAlgorithmParams(algorithm string, raw json.RawMessage) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("params_json 必须是 JSON 对象")
	}
	var identifierKey string
	switch algorithm {
	case AlgorithmEncrypt:
		identifierKey = "key_id"
	case AlgorithmMap:
		identifierKey = "map_id"
	default:
		return nil
	}
	if len(obj) != 1 {
		return fmt.Errorf("%s params_json 必须且仅允许 %s", algorithm, identifierKey)
	}
	rawIdentifier, ok := obj[identifierKey]
	if !ok {
		return fmt.Errorf("%s params_json 必须且仅允许 %s", algorithm, identifierKey)
	}
	var identifier string
	if err := json.Unmarshal(rawIdentifier, &identifier); err != nil || len(identifier) == 0 || len(identifier) > 64 {
		return fmt.Errorf("params.%s 须为 1-64 位 [A-Za-z0-9_-]", identifierKey)
	}
	for _, r := range identifier {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return fmt.Errorf("params.%s 须为 1-64 位 [A-Za-z0-9_-]", identifierKey)
	}
	return nil
}
