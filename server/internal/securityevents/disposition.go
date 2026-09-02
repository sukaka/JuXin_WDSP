package securityevents

import "fmt"

const defaultDispositionStatus = "UNPROCESSED"

// ValidateDispositionTransition 校验事件处置状态流转。
// 终态只允许重复提交同一状态（幂等），避免误报/攻击结论被静默覆盖。
func ValidateDispositionTransition(current, target string) (idempotent bool, err error) {
	if current == "" {
		current = defaultDispositionStatus
	}
	if current == target {
		return true, nil
	}
	allowed := map[string]map[string]bool{
		"UNPROCESSED": {
			"ANALYZING": true, "CONFIRMED_ATTACK": true, "CONFIRMED_FALSE_POSITIVE": true,
			"IGNORED": true, "RESOLVED": true,
		},
		"ANALYZING": {
			"CONFIRMED_ATTACK": true, "CONFIRMED_FALSE_POSITIVE": true, "IGNORED": true, "RESOLVED": true,
		},
	}
	if allowed[current][target] {
		return false, nil
	}
	return false, fmt.Errorf("disposition transition %s -> %s is not allowed", current, target)
}
