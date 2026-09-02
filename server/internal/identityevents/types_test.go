package identityevents

import (
	"fmt"
	"testing"
	"time"
)

// TestParseObservation 身份观测行解析（含凭据列表与派生列提取）。
func TestParseObservation(t *testing.T) {
	line := `{"record_type":"identity_observation","request_id":"req-1","occurred_at":"2026-09-01T10:00:00Z",
"gateway_node":"gw-01","app_id":"app-1","app_code":"shop","domain":"shop.example.com","method":"GET","path":"/api/orders",
"identity_key":"ik-abc","identity_type":"HUMAN","client_ip":"203.0.113.10","user_agent":"Mozilla/5.0",
"tls_fingerprint":"tls123","browser_fingerprint":"br456",
"credentials":[{"type":"JWT","hash":"h1","account_id":"acc-1","jwt_subject":"user-42"},
{"type":"API_KEY","hash":"ak-9"},{"type":"OAUTH","hash":"h3","oauth_client_id":"oc-7"}]}`
	rec, err := parseRecordLine([]byte(line))
	if err != nil {
		t.Fatalf("parse observation: %v", err)
	}
	if rec.RecordType != RecordTypeObservation || rec.IdentityKey != "ik-abc" || rec.IdentityType != "HUMAN" {
		t.Errorf("unexpected record: %+v", rec)
	}
	accountID, jwtSubject, apiKeyHash, oauthClientID := derivedIdentityFields(rec.Credentials)
	if accountID != "acc-1" || jwtSubject != "user-42" || apiKeyHash != "ak-9" || oauthClientID != "oc-7" {
		t.Errorf("derived fields = (%q,%q,%q,%q)", accountID, jwtSubject, apiKeyHash, oauthClientID)
	}
}

func TestParseObservationMTLSCredential(t *testing.T) {
	line := `{"record_type":"identity_observation","occurred_at":"2026-09-01T10:00:00Z","identity_key":"ik-mtls","identity_type":"SERVICE","identity_confidence":95,"credentials":[{"type":"MTLS","hash":"cert-hash"}]}`
	rec, err := parseRecordLine([]byte(line))
	if err != nil {
		t.Fatalf("parse mTLS observation: %v", err)
	}
	if len(rec.Credentials) != 1 || rec.Credentials[0].Type != "MTLS" || rec.Credentials[0].Hash != "cert-hash" {
		t.Fatalf("mTLS credential: %+v", rec.Credentials)
	}
}

// TestParseObservationIdentityTypeNormalize 非法身份类型归一为 UNKNOWN。
func TestParseObservationIdentityTypeNormalize(t *testing.T) {
	line := `{"record_type":"identity_observation","occurred_at":"2026-09-01T10:00:00Z","identity_key":"ik-1","identity_type":"ROBOT"}`
	rec, err := parseRecordLine([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.IdentityType != IdentityTypeUnknown {
		t.Errorf("identity_type = %q, want UNKNOWN", rec.IdentityType)
	}
}

func TestParseObservationV11IdentityContract(t *testing.T) {
	line := `{"record_type":"identity_observation","occurred_at":"2026-09-01T10:00:00Z","identity_key":"ik-agent","identity_type":"AGENT","identity_confidence":82,"identity_evidence":["credential:oauth"]}`
	rec, err := parseRecordLine([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.IdentityType != IdentityTypeAgent || rec.IdentityConfidence != 82 || len(rec.IdentityEvidence) != 1 || rec.IdentityEvidence[0] != "credential:oauth" {
		t.Fatalf("v1.1 identity contract: %+v", rec)
	}
}

// TestParseSnapshot 行为快照行解析（多窗口计数）。
func TestParseSnapshot(t *testing.T) {
	line := `{"record_type":"behavior_snapshot","request_id":"req-2","occurred_at":"2026-09-01T10:05:00Z",
"identity_key":"ik-abc","identity_type":"UNKNOWN","client_ip":"203.0.113.10",
"windows":{"1m":{"window_start":"2026-09-01T10:04:00Z","request_count":30,"unique_uri_count":12,"new_uri_count":9,
"status_401_count":1,"status_403_count":0,"status_404_count":5,"status_405_count":0,"status_500_count":0,
"auth_fail_count":1,"parameter_mutation_count":2,"sensitive_path_hits":0},
"5m":{"window_start":"2026-09-01T10:00:00Z","request_count":120,"unique_uri_count":40,"new_uri_count":20,
"status_401_count":2,"status_403_count":1,"status_404_count":10,"status_405_count":0,"status_500_count":1,
"auth_fail_count":3,"parameter_mutation_count":4,"sensitive_path_hits":1,"account_enum_count":2,"object_enum_count":3}}}`
	rec, err := parseRecordLine([]byte(line))
	if err != nil {
		t.Fatalf("parse snapshot: %v", err)
	}
	if len(rec.Windows) != 2 {
		t.Fatalf("windows len = %d, want 2", len(rec.Windows))
	}
	w := rec.Windows["1m"]
	if w.RequestCount != 30 || w.UniqueURICount != 12 || w.Status404Count != 5 || w.ParameterMutationCount != 2 {
		t.Errorf("1m window counters = %+v", w)
	}
	if rec.Windows["5m"].AccountEnumCount != 2 || rec.Windows["5m"].ObjectEnumCount != 3 {
		t.Errorf("5m enumeration counters = %+v", rec.Windows["5m"])
	}
	wantStart := time.Date(2026, 9, 1, 10, 4, 0, 0, time.UTC)
	if !w.WindowStart.Equal(wantStart) {
		t.Errorf("window_start = %v, want %v", w.WindowStart, wantStart)
	}
}

// TestParseSignal 侦察信号行解析（mode 缺省回落 OBSERVE）。
func TestParseSignal(t *testing.T) {
	line := `{"record_type":"recon_signal","request_id":"req-3","occurred_at":"2026-09-01T10:06:00Z",
"identity_key":"ik-abc","client_ip":"203.0.113.10","method":"GET","path":"/.git/config",
"rule_code":"JR-RECON-003","rule_version":"1","signal":"SENSITIVE_PATH_PROBE","risk_score_delta":15,
"reason":"命中敏感路径 /.git","window":"5m","metadata":{"path":"/.git/config","hit_count":3}}`
	rec, err := parseRecordLine([]byte(line))
	if err != nil {
		t.Fatalf("parse signal: %v", err)
	}
	if rec.Signal != SignalSensitivePathProbe || rec.RiskScoreDelta != 15 || rec.Mode != "OBSERVE" {
		t.Errorf("unexpected signal record: %+v", rec)
	}
	if rec.Metadata["hit_count"].(float64) != 3 {
		t.Errorf("metadata hit_count = %v", rec.Metadata["hit_count"])
	}
}

func TestParseV11EnumerationSignals(t *testing.T) {
	for _, signal := range []string{SignalHeadless, SignalAccountEnumeration, SignalObjectEnumeration} {
		line := fmt.Sprintf(`{"record_type":"recon_signal","occurred_at":"2026-09-01T10:06:00Z","identity_key":"ik-1","rule_code":"R1","signal":"%s"}`, signal)
		if rec, err := parseRecordLine([]byte(line)); err != nil || rec.Signal != signal {
			t.Fatalf("parse %s: rec=%+v err=%v", signal, rec, err)
		}
	}
}

// TestParseBadLines 坏行拒绝：未知 record_type / 缺 identity_key / 缺 occurred_at /
// 快照缺 windows / 信号缺 rule_code / 未知 signal / 坏 JSON。
func TestParseBadLines(t *testing.T) {
	base := `"occurred_at":"2026-09-01T10:00:00Z","identity_key":"ik-1"`
	bad := []string{
		`{"record_type":"mystery",` + base + `}`,
		`{"record_type":"identity_observation","occurred_at":"2026-09-01T10:00:00Z"}`,
		`{"record_type":"identity_observation","identity_key":"ik-1"}`,
		`{"record_type":"behavior_snapshot",` + base + `}`,
		`{"record_type":"recon_signal",` + base + `,"signal":"URI_ENUMERATION"}`,
		`{"record_type":"recon_signal",` + base + `,"rule_code":"R1","signal":"NOPE"}`,
		`{not json`,
	}
	for i, line := range bad {
		if _, err := parseRecordLine([]byte(line)); err == nil {
			t.Errorf("bad line %d unexpectedly parsed: %s", i, line)
		}
	}
}

// TestRiskLevelForScore 风险分级阈值（0-19 LOW / 20-39 MEDIUM / 40-69 HIGH / 70+ CRITICAL）。
func TestRiskLevelForScore(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, "LOW"}, {19, "LOW"}, {20, "MEDIUM"}, {39, "MEDIUM"},
		{40, "HIGH"}, {69, "HIGH"}, {70, "CRITICAL"}, {100, "CRITICAL"},
	}
	for _, c := range cases {
		if got := RiskLevelForScore(c.score); got != c.want {
			t.Errorf("RiskLevelForScore(%d) = %q, want %q", c.score, got, c.want)
		}
	}
}

// TestClampRiskScore 风险分截断 [0,100]（负增量求和可能为负）。
func TestClampRiskScore(t *testing.T) {
	if got := clampRiskScore(-5); got != 0 {
		t.Errorf("clamp(-5) = %d, want 0", got)
	}
	if got := clampRiskScore(150); got != 100 {
		t.Errorf("clamp(150) = %d, want 100", got)
	}
	if got := clampRiskScore(55); got != 55 {
		t.Errorf("clamp(55) = %d, want 55", got)
	}
}
