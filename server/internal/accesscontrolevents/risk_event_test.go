package accesscontrolevents

import (
	"testing"
)

// TestParseRiskPolicyEventBlock RISK_POLICY_BLOCK：details 证据载荷完整 +
// action_taken=blocked → action=REJECT（网关顶层 action 原文不沿用）；不产生封禁字段。
func TestParseRiskPolicyEventBlock(t *testing.T) {
	evt, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "RISK_POLICY_BLOCK",
		"action":     "blocked", // 网关顶层 action 为动作原文，落库动作列须映射 REJECT
		"policy_id":  "",
		"risk": map[string]interface{}{
			"identity_key":   "ik-risk-1",
			"score":          85,
			"risk_level":     "CRITICAL",
			"threshold":      80,
			"signals":        []interface{}{map[string]interface{}{"type": "URI_ENUMERATION", "score": 15}, map[string]interface{}{"type": "SQLI", "score": 50}},
			"mode":           "PROTECT",
			"policy_version": 3,
			"action_taken":   "blocked",
			"reason":         "identity_risk_policy",
		},
	}), "default-node")
	if err != nil {
		t.Fatalf("valid risk block line rejected: %v", err)
	}
	if evt.EventType != EventTypeRiskPolicyBlock || evt.Action != ActionReject {
		t.Errorf("event_type/action = %s/%s, want RISK_POLICY_BLOCK/REJECT", evt.EventType, evt.Action)
	}
	if evt.BlockExpiresAt != nil {
		t.Errorf("risk event must not carry block_expires_at: %+v", evt.BlockExpiresAt)
	}
	d := evt.Details
	if d["identity_key"] != "ik-risk-1" || d["risk_level"] != "CRITICAL" || d["mode"] != "PROTECT" ||
		d["action_taken"] != "blocked" || d["reason"] != "identity_risk_policy" {
		t.Errorf("details = %+v", d)
	}
	if d["score"] != 85 || d["threshold"] != 80 {
		t.Errorf("details score/threshold = %v/%v, want 85/80", d["score"], d["threshold"])
	}
	if d["policy_version"] != float64(3) {
		t.Errorf("details policy_version = %v, want 3", d["policy_version"])
	}
	signals, ok := d["signals"].([]interface{})
	if !ok || len(signals) != 2 {
		t.Fatalf("details signals = %+v, want 2 items", d["signals"])
	}
}

// TestParseRiskPolicyEventRateLimitObserve OBSERVE 模式限速：would_rate_limit → action=OBSERVE。
func TestParseRiskPolicyEventRateLimitObserve(t *testing.T) {
	evt, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "RISK_POLICY_RATE_LIMIT",
		"action":     "would_rate_limit",
		"policy_id":  "",
		"risk": map[string]interface{}{
			"identity_key":   "ik-risk-2",
			"score":          45,
			"risk_level":     "HIGH",
			"threshold":      40,
			"signals":        []interface{}{},
			"mode":           "OBSERVE",
			"policy_version": "2",
			"action_taken":   "would_rate_limit",
			"reason":         "identity_risk_policy",
		},
	}), "default-node")
	if err != nil {
		t.Fatalf("valid risk rate limit line rejected: %v", err)
	}
	if evt.Action != ActionObserve {
		t.Errorf("action = %s, want OBSERVE", evt.Action)
	}
	if isRejected(evt) {
		t.Errorf("would_rate_limit must not count as rejected")
	}
	if evt.Details["policy_version"] != "2" {
		t.Errorf("policy_version string tolerated, got %v", evt.Details["policy_version"])
	}
}

// TestParseRiskPolicyEventInvalid 缺 risk 对象 / 缺 identity_key / 非法 action_taken / 坏 signals → 解析失败。
func TestParseRiskPolicyEventInvalid(t *testing.T) {
	if _, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "RISK_POLICY_BLOCK", "action": "blocked",
	}), "default-node"); err == nil {
		t.Errorf("missing risk object must fail")
	}
	if _, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "RISK_POLICY_BLOCK", "action": "blocked",
		"risk": map[string]interface{}{"action_taken": "blocked"},
	}), "default-node"); err == nil {
		t.Errorf("missing identity_key must fail")
	}
	if _, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "RISK_POLICY_BLOCK", "action": "killed",
		"risk": map[string]interface{}{"identity_key": "ik-1", "action_taken": "killed"},
	}), "default-node"); err == nil {
		t.Errorf("invalid action_taken must fail")
	}
	bad := []byte(`{"request_id":"r","occurred_at":"2026-07-21T08:00:00Z","client_ip":"192.168.1.10",` +
		`"event_type":"RISK_POLICY_BLOCK","risk":{"identity_key":"ik-1","action_taken":"blocked","signals":"oops"}}` + "\n")
	if _, err := ParseEventLine(bad, "default-node"); err == nil {
		t.Errorf("non-array signals must fail")
	}
}

// TestParseCCEventUnaffected CC 事件不带扩展字段：details 为空、既有行为不变。
func TestParseCCEventUnaffected(t *testing.T) {
	evt, err := ParseEventLine(validLine(t, nil), "default-node")
	if err != nil {
		t.Fatalf("valid cc line rejected: %v", err)
	}
	if len(evt.Details) != 0 {
		t.Errorf("cc event details = %+v, want empty", evt.Details)
	}
	if !isRejected(evt) {
		t.Errorf("CC_REQUEST_REJECTED must stay rejected")
	}
}
