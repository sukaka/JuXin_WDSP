package accesscontrolevents

import (
	"encoding/json"
	"strings"
	"testing"
)

// botDetailFixture 合法 BOT_* 事件 bot 明细基线（各用例在其上做最小变异）。
func botDetailFixture() map[string]interface{} {
	return map[string]interface{}{
		"policy_version": 2,
		"policy_epoch":   2,
		"mode":           "PROTECT",
		"reason":         "signal_threshold_met",
		"flow_id":        "9f2ab41cd7658e31",
		"key_id":         "bot-hmac-2026",
	}
}

// TestParseBotEventChallengeOffered BOT_CHALLENGE_OFFERED（PROTECT 403 挑战页）：
// bot 明细完整落 details.bot；action 沿用网关上报 CHALLENGE；不计入 CC rejected 汇总
// （event_type 独立取值，各 CC 消费方按 CC_* 精确匹配，互不污染）。
func TestParseBotEventChallengeOffered(t *testing.T) {
	evt, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type":      "BOT_CHALLENGE_OFFERED",
		"action":          "CHALLENGE",
		"response_status": 403,
		"bot":             botDetailFixture(),
	}), "default-node")
	if err != nil {
		t.Fatalf("valid bot offered line rejected: %v", err)
	}
	if evt.EventType != EventTypeBotChallengeOffered || evt.Action != "CHALLENGE" {
		t.Errorf("event_type/action = %s/%s, want BOT_CHALLENGE_OFFERED/CHALLENGE", evt.EventType, evt.Action)
	}
	if isRejected(evt) {
		t.Error("CHALLENGE action must not count as CC rejected")
	}
	bot, ok := evt.Details["bot"].(map[string]interface{})
	if !ok {
		t.Fatalf("details.bot = %+v", evt.Details)
	}
	if bot["mode"] != "PROTECT" || bot["reason"] != "signal_threshold_met" ||
		bot["policy_version"] != 2 || bot["policy_epoch"] != 2 ||
		bot["flow_id"] != "9f2ab41cd7658e31" || bot["key_id"] != "bot-hmac-2026" {
		t.Errorf("details.bot = %+v", bot)
	}
}

// TestParseBotEventVerifyOutcome 验证结果与通行事件：verify_success 携带 attempts
// 与 note；clearance_accepted 为 PASS 动作；均完整落 details.bot。
func TestParseBotEventVerifyOutcome(t *testing.T) {
	d := botDetailFixture()
	d["attempts"] = 2
	d["note"] = "pow_accepted"
	evt, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type":      "BOT_VERIFY_SUCCESS",
		"action":          "PASS",
		"response_status": 204,
		"bot":             d,
	}), "default-node")
	if err != nil {
		t.Fatalf("valid verify success line rejected: %v", err)
	}
	bot := evt.Details["bot"].(map[string]interface{})
	if bot["attempts"] != 2 || bot["note"] != "pow_accepted" {
		t.Errorf("details.bot = %+v", bot)
	}

	evt, err = ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "BOT_CLEARANCE_ACCEPTED",
		"action":     "PASS",
		"bot":        botDetailFixture(),
	}), "default-node")
	if err != nil || evt.Action != "PASS" {
		t.Fatalf("clearance accepted: %+v err=%v", evt, err)
	}
}

// TestParseBotEventTolerance 容忍性：bot 对象携带未来新增字段（unknown_field/
// signals 等）不报错；未知 BOT 事件类型（新网关 + 旧采集端）走通用字段落库，
// 不崩、不进错误文件。
func TestParseBotEventTolerance(t *testing.T) {
	d := botDetailFixture()
	d["unknown_future_field"] = "x"
	d["signals"] = []string{"ua_class"}
	evt, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "BOT_CHALLENGE_OFFERED",
		"action":     "CHALLENGE",
		"bot":        d,
	}), "default-node")
	if err != nil {
		t.Fatalf("unknown bot fields must be tolerated: %v", err)
	}
	bot := evt.Details["bot"].(map[string]interface{})
	if _, ok := bot["unknown_future_field"]; ok {
		t.Errorf("undeclared field must be dropped: %+v", bot)
	}
	if _, ok := bot["signals"]; ok {
		t.Errorf("undeclared field must be dropped: %+v", bot)
	}

	// 未知事件类型：通用落库，无 details 分支
	evt, err = ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "BOT_FUTURE_TYPE",
		"action":     "OBSERVE",
		"bot":        botDetailFixture(),
	}), "default-node")
	if err != nil {
		t.Fatalf("unknown event type must be tolerated: %v", err)
	}
	if _, ok := evt.Details["bot"]; ok {
		t.Error("unknown event type must not populate details.bot")
	}
}

// TestParseBotEventRedaction 脱敏断言：即使网关火线异常在 bot 对象中携带
// nonce/solution/通行 Cookie/会话 Cookie/签名材料，采集端类型系统不解码这些
// 字段——落库 details 序列化后不含任何相关材料。
func TestParseBotEventRedaction(t *testing.T) {
	d := botDetailFixture()
	d["nonce"] = "nonce-secret-value-001"
	d["solution"] = "12345678"
	d["clearance_cookie"] = "v1.clearance-secret"
	d["session_cookie"] = "session-secret"
	d["key_material"] = "ab01cd23ef456789ab01cd23ef456789"
	evt, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "BOT_VERIFY_SUCCESS",
		"action":     "PASS",
		"bot":        d,
	}), "default-node")
	if err != nil {
		t.Fatalf("valid line rejected: %v", err)
	}
	blob, err := json.Marshal(evt.Details)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"nonce-secret-value-001", "12345678", "v1.clearance-secret",
		"session-secret", "ab01cd23ef456789", "nonce", "solution", "cookie", "key_material"} {
		if strings.Contains(string(blob), leak) {
			t.Errorf("details must not contain %q: %s", leak, blob)
		}
	}
}

// TestParseBotEventInvalid BOT_* 事件缺 bot 对象或缺 mode/reason →
// 解析失败入错误文件（不静默落库；与 applyJWTEvent 同一纪律）。
func TestParseBotEventInvalid(t *testing.T) {
	if _, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "BOT_CHALLENGE_OFFERED",
		"action":     "CHALLENGE",
	}), "default-node"); err == nil {
		t.Error("missing bot object must fail parse")
	}
	d := botDetailFixture()
	delete(d, "mode")
	if _, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "BOT_CHALLENGE_OFFERED",
		"action":     "CHALLENGE",
		"bot":        d,
	}), "default-node"); err == nil {
		t.Error("missing bot.mode must fail parse")
	}
	d = botDetailFixture()
	delete(d, "reason")
	if _, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "BOT_CHALLENGE_OFFERED",
		"action":     "CHALLENGE",
		"bot":        d,
	}), "default-node"); err == nil {
		t.Error("missing bot.reason must fail parse")
	}
}

// TestParseBotEventFinalDecisionMerge BOT 终止事件携带 final_decision 时
// 与 details.bot 并存（合并而非覆盖——P0-04 统一落点口径）。
func TestParseBotEventFinalDecisionMerge(t *testing.T) {
	evt, err := ParseEventLine(validLine(t, map[string]interface{}{
		"event_type": "BOT_CHALLENGE_OFFERED",
		"action":     "CHALLENGE",
		"bot":        botDetailFixture(),
		"final_decision": map[string]interface{}{
			"schema_version": 1,
			"action":         "CHALLENGE",
		},
	}), "default-node")
	if err != nil {
		t.Fatalf("valid line rejected: %v", err)
	}
	if _, ok := evt.Details["bot"]; !ok {
		t.Error("details.bot missing")
	}
	if _, ok := evt.Details["final_decision"]; !ok {
		t.Error("details.final_decision missing")
	}
}
