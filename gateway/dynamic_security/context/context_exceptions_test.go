package context

import (
	"encoding/json"
	"strings"
	"testing"
)

// MarkMatchExcepted 基本打标：字段写回、返回 true，其余明细不受影响。
func TestMarkMatchExceptedBasic(t *testing.T) {
	rc := New("req-exc-1", ParseLimits{})
	rc.AddMatch(DetectorMatch{Detector: "api_schema", RuleID: "schema.extra_field", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50})
	rc.AddMatch(DetectorMatch{Detector: "waf", RuleID: "942100", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50})

	if !rc.MarkMatchExcepted(0, "api_schema", "schema.extra_field", "exc-uuid-1", 2) {
		t.Fatal("first mark must succeed")
	}
	matches := rc.CopyMatches()
	if !matches[0].Excepted || matches[0].ExceptionID != "exc-uuid-1" || matches[0].ExceptionVersion != 2 {
		t.Fatalf("match[0] not marked: %+v", matches[0])
	}
	if matches[1].Excepted {
		t.Fatalf("match[1] must stay unmarked: %+v", matches[1])
	}
	// 打标不回溯 RiskScore（豁免只取消定案贡献，风险分事实保留）
	if rc.RiskScore != 100 {
		t.Fatalf("risk score must not be rewound, got %d", rc.RiskScore)
	}
}

// MarkMatchExcepted 幂等：重复打标不产生变化，先入例外优先（不覆盖既有标记）。
func TestMarkMatchExceptedIdempotent(t *testing.T) {
	rc := New("req-exc-2", ParseLimits{})
	rc.AddMatch(DetectorMatch{Detector: "api_schema", RuleID: "schema.type_mismatch"})

	if !rc.MarkMatchExcepted(0, "api_schema", "schema.type_mismatch", "exc-first", 1) {
		t.Fatal("first mark must succeed")
	}
	if rc.MarkMatchExcepted(0, "api_schema", "schema.type_mismatch", "exc-second", 9) {
		t.Fatal("second mark must be a no-op")
	}
	m := rc.CopyMatches()[0]
	if m.ExceptionID != "exc-first" || m.ExceptionVersion != 1 {
		t.Fatalf("first exception must win, got id=%q version=%d", m.ExceptionID, m.ExceptionVersion)
	}
	if rc.MatchCount() != 1 {
		t.Fatalf("marking must not duplicate records, count=%d", rc.MatchCount())
	}
}

// MarkMatchExcepted 快照过期防护：detector/ruleID 不一致或下标越界时拒绝写回。
func TestMarkMatchExceptedStaleSnapshotRejected(t *testing.T) {
	rc := New("req-exc-3", ParseLimits{})
	rc.AddMatch(DetectorMatch{Detector: "api_schema", RuleID: "schema.extra_field"})

	if rc.MarkMatchExcepted(0, "api_parser", "schema.extra_field", "exc-x", 1) {
		t.Fatal("detector mismatch must be rejected")
	}
	if rc.MarkMatchExcepted(0, "api_schema", "schema.other_rule", "exc-x", 1) {
		t.Fatal("rule_id mismatch must be rejected")
	}
	if rc.MarkMatchExcepted(-1, "api_schema", "schema.extra_field", "exc-x", 1) {
		t.Fatal("negative index must be rejected")
	}
	if rc.MarkMatchExcepted(1, "api_schema", "schema.extra_field", "exc-x", 1) {
		t.Fatal("out-of-range index must be rejected")
	}
	if rc.CopyMatches()[0].Excepted {
		t.Fatal("match must stay unmarked after rejected attempts")
	}
}

// MarkMatchExcepted nil 接收者安全（与既有方法同口径）。
func TestMarkMatchExceptedNilReceiver(t *testing.T) {
	var rc *RequestContext
	if rc.MarkMatchExcepted(0, "api_schema", "r", "exc", 1) {
		t.Fatal("nil receiver must return false")
	}
}

// DetectorMatch 豁免字段序列化：未打标零变化（omitempty），打标后携带 exception_id/version。
func TestDetectorMatchExceptedJSON(t *testing.T) {
	plain, err := json.Marshal(DetectorMatch{Detector: "api_schema", RuleID: "r1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"excepted", "exception_id", "exception_version"} {
		if strings.Contains(string(plain), key) {
			t.Fatalf("unmarked match must not serialize %q: %s", key, plain)
		}
	}

	marked, err := json.Marshal(DetectorMatch{
		Detector: "api_schema", RuleID: "r1",
		Excepted: true, ExceptionID: "exc-uuid", ExceptionVersion: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(marked)
	if !strings.Contains(s, `"excepted":true`) ||
		!strings.Contains(s, `"exception_id":"exc-uuid"`) ||
		!strings.Contains(s, `"exception_version":3`) {
		t.Fatalf("marked match missing exception fields: %s", s)
	}
}
