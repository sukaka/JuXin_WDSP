package accesscontrolevents

import (
	"testing"
)

// TestParseJWTEventAuthFailed JWT_AUTH_FAILED（PROTECT 401）：jwt_verification
// 摘要完整落 details；action 沿用网关上报 REJECT；计入 rejected 汇总。
func TestParseJWTEventAuthFailed(t *testing.T) {
	evt, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "JWT_AUTH_FAILED",
		"action":     "REJECT",
		"policy_id":  "",
		"jwt_verification": map[string]interface{}{
			"status":           "INVALID",
			"reason_code":      "SIGNATURE_INVALID",
			"policy_version":   "3",
			"issuer_config_id": "iss-abc123",
			"keyset_version":   "ks-v2",
			"evaluated_at":     "2026-09-06T12:00:00Z",
		},
	}), "default-node")
	if err != nil {
		t.Fatalf("valid jwt auth failed line rejected: %v", err)
	}
	if evt.EventType != EventTypeJWTAuthFailed || evt.Action != ActionReject {
		t.Errorf("event_type/action = %s/%s, want JWT_AUTH_FAILED/REJECT", evt.EventType, evt.Action)
	}
	if !isRejected(evt) {
		t.Errorf("JWT_AUTH_FAILED must count as rejected")
	}
	jwt, ok := evt.Details["jwt_verification"].(map[string]interface{})
	if !ok {
		t.Fatalf("details.jwt_verification = %+v", evt.Details)
	}
	if jwt["status"] != "INVALID" || jwt["reason_code"] != "SIGNATURE_INVALID" ||
		jwt["policy_version"] != "3" || jwt["issuer_config_id"] != "iss-abc123" ||
		jwt["keyset_version"] != "ks-v2" || jwt["evaluated_at"] != "2026-09-06T12:00:00Z" {
		t.Errorf("jwt_verification = %+v", jwt)
	}
}

// TestParseJWTEventUnavailable JWT_UNAVAILABLE（PROTECT 503）与 JWT_OBSERVED
// （OBSERVE 放行记录）：动作语义区分，OBSERVE 不计 rejected。
func TestParseJWTEventUnavailable(t *testing.T) {
	evt, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "JWT_UNAVAILABLE",
		"action":     "REJECT",
		"jwt_verification": map[string]interface{}{
			"status":      "UNAVAILABLE",
			"reason_code": "KEYSET_UNAVAILABLE",
		},
	}), "default-node")
	if err != nil {
		t.Fatalf("valid jwt unavailable line rejected: %v", err)
	}
	if evt.Action != ActionReject || !isRejected(evt) {
		t.Errorf("JWT_UNAVAILABLE must be REJECT/rejected: %+v", evt)
	}

	obs, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "JWT_OBSERVED",
		"action":     "OBSERVE",
		"jwt_verification": map[string]interface{}{
			"status":      "INVALID",
			"reason_code": "EXPIRED",
		},
	}), "default-node")
	if err != nil {
		t.Fatalf("valid jwt observed line rejected: %v", err)
	}
	if obs.Action != ActionObserve || isRejected(obs) {
		t.Errorf("JWT_OBSERVED must be OBSERVE/not-rejected: %+v", obs)
	}
}

// TestParseJWTEventInvalid JWT_* 事件缺 jwt_verification 对象或缺
// status/reason_code → 解析失败入错误文件（不静默落库）。
func TestParseJWTEventInvalid(t *testing.T) {
	if _, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "JWT_AUTH_FAILED", "action": "REJECT",
	}), "default-node"); err == nil {
		t.Errorf("missing jwt_verification object must fail")
	}
	if _, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "JWT_AUTH_FAILED", "action": "REJECT",
		"jwt_verification": map[string]interface{}{"status": "INVALID"},
	}), "default-node"); err == nil {
		t.Errorf("missing reason_code must fail")
	}
}

// TestParseJWTEventLegacyTolerant 历史/其他类型事件无 jwt_verification 键：
// 解析零变化（JWT-17 旧事件兼容，不回填）。
func TestParseJWTEventLegacyTolerant(t *testing.T) {
	evt, err := ParseEventLine(validLine(t, nil), "default-node")
	if err != nil {
		t.Fatalf("legacy line rejected: %v", err)
	}
	if _, ok := evt.Details["jwt_verification"]; ok {
		t.Errorf("legacy event must not carry jwt_verification: %+v", evt.Details)
	}
}
