package apiruntime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

type fakeFindingSaver struct{ batches [][]FindingInput }

func (f *fakeFindingSaver) SaveFindings(_ context.Context, in []FindingInput) error {
	cp := make([]FindingInput, len(in))
	copy(cp, in)
	f.batches = append(f.batches, cp)
	return nil
}

// finding_type 映射：语义覆盖表 + 机械大写下划线化 + detector 兜底。
func TestFindingTypeOf(t *testing.T) {
	cases := []struct {
		detector, ruleID, want string
	}{
		{"lifecycle", "lifecycle.new_endpoint", "SHADOW"},            // 覆盖表：Shadow 词表
		{"lifecycle", "lifecycle.deprecated_api_call", "DEPRECATED"}, // 覆盖表：Deprecated 词表
		{"resource_access", "resource.unauthenticated_object_access", "BOLA_UNAUTHENTICATED_OBJECT_ACCESS"},
		{"api_schema", "schema.param_length", "SCHEMA_PARAM_LENGTH"}, // 机械映射
		{"authentication", "auth.jwt_alg_none", "AUTH_JWT_ALG_NONE"},
		{"waf", "942100", "WAF_942100"}, // 数字规则号加 detector 前缀
		{"behavior", "", "BEHAVIOR"},    // 无规则号回退 detector
		{"", "", "UNKNOWN"},             // 全空兜底
	}
	for _, c := range cases {
		got := findingTypeOf(&dsctx.DetectorMatch{Detector: c.detector, RuleID: c.ruleID})
		if got != c.want {
			t.Errorf("findingTypeOf(%q,%q) = %q, want %q", c.detector, c.ruleID, got, c.want)
		}
	}
}

// 物化规则 v1：severity≥MEDIUM 或事件 final_action≠ALLOW；其余不物化。
func TestMaterializable(t *testing.T) {
	cases := []struct {
		severity, action string
		want             bool
	}{
		{"CRITICAL", "ALLOW", true},
		{"HIGH", "ALLOW", true},
		{"MEDIUM", "ALLOW", true},
		{"LOW", "ALLOW", false},
		{"INFO", "ALLOW", false},
		{"", "ALLOW", false}, // severity 缺失且放行：不物化
		{"", "", false},      // final_action 缺失视同放行
		{"INFO", "BLOCK", true},
		{"LOW", "OBSERVE", true},
		{"", "RATE_LIMIT", true},
	}
	for _, c := range cases {
		got := materializable(&dsctx.DetectorMatch{Severity: c.severity}, c.action)
		if got != c.want {
			t.Errorf("materializable(severity=%q, action=%q) = %v, want %v", c.severity, c.action, got, c.want)
		}
	}
}

// 主体映射：身份指纹优先（IDENTITY），其次来源指纹（IP），皆无则空。
func TestFindingSubject(t *testing.T) {
	st, sid := findingSubject(&Record{IdentityFingerprint: "fp-1", SourceFingerprint: "src-1"})
	if st != "IDENTITY" || sid != "fp-1" {
		t.Fatalf("identity first: got %q/%q", st, sid)
	}
	st, sid = findingSubject(&Record{SourceFingerprint: "src-1"})
	if st != "IP" || sid != "src-1" {
		t.Fatalf("ip fallback: got %q/%q", st, sid)
	}
	st, sid = findingSubject(&Record{})
	if st != "" || sid != "" {
		t.Fatalf("anonymous must stay empty: got %q/%q", st, sid)
	}
}

// 证据脱敏：白名单键留值，其余键只留键名；键名排序稳定。
func TestSanitizeEvidence(t *testing.T) {
	out := sanitizeEvidence(map[string]string{
		"field":      "password",
		"want":       "string",
		"raw_value":  "secret-plaintext", // 非白名单：值必须被丢弃
		"constraint": "max_len",
	})
	if out["field"] != "password" || out["want"] != "string" || out["constraint"] != "max_len" {
		t.Fatalf("safe keys must keep values: %v", out)
	}
	if _, leaked := out["raw_value"]; leaked {
		t.Fatalf("non-whitelisted value must be dropped: %v", out)
	}
	keys, ok := out["keys"].([]string)
	if !ok || len(keys) != 4 || keys[0] != "constraint" || keys[3] != "want" {
		t.Fatalf("keys must be sorted names only: %v", out["keys"])
	}
	// 空证据仍带空 keys 列表（审计可知网关未上报证据维度）
	out = sanitizeEvidence(nil)
	if keys, ok := out["keys"].([]string); !ok || len(keys) != 0 {
		t.Fatalf("nil evidence: %v", out)
	}
}

// 去重指纹：同输入稳定、维度敏感（端点/类型/主体任一变化即不同）、非空。
func TestDedupFingerprint(t *testing.T) {
	base := dedupFingerprint(nil, "GET /a/{id}", "SHADOW", "fp-1")
	if base == "" || base != dedupFingerprint(nil, "GET /a/{id}", "SHADOW", "fp-1") {
		t.Fatal("fingerprint must be deterministic and non-empty")
	}
	if dedupFingerprint(nil, "GET /a/{id}", "SHADOW", "fp-2") == base {
		t.Fatal("subject must affect fingerprint")
	}
	if dedupFingerprint(nil, "GET /a/{id}", "DEPRECATED", "fp-1") == base {
		t.Fatal("finding_type must affect fingerprint")
	}
	if dedupFingerprint(nil, "GET /b", "SHADOW", "fp-1") == base {
		t.Fatal("endpoint must affect fingerprint")
	}
}

// 采集器物化：BLOCK 事件的明细物化为 FindingInput（subject/证据脱敏/版本透传），
// INFO 级 + 放行不物化；saver 未注入时零开销跳过。
func TestRecordFindings(t *testing.T) {
	saver := &fakeFindingSaver{}
	c := NewCollector(&fakeSaver{}, "test-findings", filepath.Join(t.TempDir(), "x.log"), "", "node-1")
	c.SetFindingSaver(saver)
	ctx := context.Background()

	// 1) BLOCK 事件：LOW 明细也物化（动作非 ALLOW）；severity 缺失落 INFO
	c.recordFindings(ctx, &Record{
		RequestID: "r-f1", EndpointKey: "GET /v1/users/{id}", FinalAction: "BLOCK",
		RiskScore: 90, RiskLevel: "HIGH",
		IdentityFingerprint: "fp-abc", ModelVersion: "v3", PolicyVersion: "p-12",
		Details: []dsctx.DetectorMatch{
			{Detector: "lifecycle", RuleID: "lifecycle.new_endpoint", Severity: "LOW",
				Message: "new endpoint observed", Evidence: map[string]string{"field": "id", "raw": "plaintext"}},
			{Detector: "waf", RuleID: "942100", Message: "sqli"}, // severity 缺失
		},
	})
	if len(saver.batches) != 1 || len(saver.batches[0]) != 2 {
		t.Fatalf("want 1 batch of 2 findings, got %+v", saver.batches)
	}
	f := saver.batches[0][0]
	if f.FindingType != "SHADOW" || f.Severity != "LOW" || f.Title != "new endpoint observed" {
		t.Fatalf("bad finding: %+v", f)
	}
	if f.SubjectType != "IDENTITY" || f.SubjectID != "fp-abc" {
		t.Fatalf("subject not mapped: %+v", f)
	}
	if f.ModelVersion != "v3" || f.PolicyVersion != "p-12" || f.RiskScore != 90 {
		t.Fatalf("versions/score not propagated: %+v", f)
	}
	if _, leaked := f.Evidence["raw"]; leaked {
		t.Fatalf("evidence leaked raw value: %+v", f.Evidence)
	}
	if f.Evidence["field"] != "id" {
		t.Fatalf("evidence safe key missing: %+v", f.Evidence)
	}
	if g := saver.batches[0][1]; g.FindingType != "WAF_942100" || g.Severity != "INFO" {
		t.Fatalf("severity fallback / numeric rule mapping broken: %+v", g)
	}

	// 2) INFO 级 + ALLOW：不物化（降噪）
	c.recordFindings(ctx, &Record{
		RequestID: "r-f2", EndpointKey: "GET /v1/ok", FinalAction: "ALLOW",
		Details: []dsctx.DetectorMatch{{Detector: "identity", RuleID: "identity.token_present", Severity: "INFO"}},
	})
	if len(saver.batches) != 1 {
		t.Fatalf("INFO+ALLOW must not materialize: %+v", saver.batches)
	}

	// 3) MEDIUM 级 + ALLOW：物化（severity 达标）
	c.recordFindings(ctx, &Record{
		RequestID: "r-f3", EndpointKey: "GET /v1/x", FinalAction: "ALLOW",
		SourceFingerprint: "src-9",
		Details:           []dsctx.DetectorMatch{{Detector: "authentication", RuleID: "auth.jwt_alg_none", Severity: "MEDIUM"}},
	})
	if len(saver.batches) != 2 || len(saver.batches[1]) != 1 {
		t.Fatalf("MEDIUM+ALLOW must materialize: %+v", saver.batches)
	}
	if g := saver.batches[1][0]; g.SubjectType != "IP" || g.SubjectID != "src-9" {
		t.Fatalf("ip subject fallback broken: %+v", g)
	}

	// 4) saver 为 nil：不 panic、零开销跳过
	c2 := NewCollector(&fakeSaver{}, "test-findings-nil", filepath.Join(t.TempDir(), "y.log"), "", "node-1")
	c2.recordFindings(ctx, &Record{
		RequestID: "r-f4", EndpointKey: "GET /v1/y", FinalAction: "BLOCK",
		Details: []dsctx.DetectorMatch{{Detector: "waf", RuleID: "942100", Severity: "HIGH"}},
	})
}

// 物化与采集主流程联动：含明细的 notable 事件触发物化，纯放行记录不触发；
// 物化失败（saver 报错）不阻断主采集（行仍计入 processed，主事件仍入库）。
type errFindingSaver struct{}

func (errFindingSaver) SaveFindings(context.Context, []FindingInput) error { return os.ErrPermission }

func TestCollectOnce_FindingsHook(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	hit := Record{
		RequestID: "r-fh-1", EndpointKey: "GET /v1/orders", Method: "GET", PathTemplate: "/v1/orders",
		IsAPI: true, FinalAction: "BLOCK", RiskLevel: "HIGH", RiskScore: 80,
		Details:    []dsctx.DetectorMatch{{Detector: "api_schema", RuleID: "schema.type_mismatch", Severity: "HIGH"}},
		OccurredAt: time.Now().UTC(),
	}
	pass := Record{
		RequestID: "r-fh-2", EndpointKey: "GET /v1/ping", Method: "GET", PathTemplate: "/v1/ping",
		IsAPI: true, FinalAction: "ALLOW", OccurredAt: time.Now().UTC(),
	}
	writeLines(t, logPath, []string{mustJSON(t, hit), mustJSON(t, pass)})

	saver := &fakeSaver{}
	fs := &fakeFindingSaver{}
	c := NewCollector(saver, "test-fh", logPath, filepath.Join(dir, "cp"), "node-1")
	c.SetFindingSaver(fs)
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if len(fs.batches) != 1 || fs.batches[0][0].FindingType != "SCHEMA_TYPE_MISMATCH" {
		t.Fatalf("findings hook not fired exactly once: %+v", fs.batches)
	}

	// 物化报错不阻断采集：主事件仍入库、断点仍前移
	writeLines(t, logPath, []string{mustJSON(t, hit)})
	c2 := NewCollector(saver, "test-fh-err", logPath, filepath.Join(dir, "cp2"), "node-1")
	c2.SetFindingSaver(errFindingSaver{})
	n, err := c2.CollectOnce(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("finding save error must not break collection: n=%d err=%v", n, err)
	}
	if len(saver.saved) != 2 { // 第一次 1 条 + 第二次 1 条
		t.Fatalf("primary events saved = %d, want 2", len(saver.saved))
	}
}

// FindingInput.Detail 可 JSON 序列化（落库 detail 列）。
func TestFindingInputDetailSerializable(t *testing.T) {
	saver := &fakeFindingSaver{}
	c := NewCollector(&fakeSaver{}, "test-fjson", filepath.Join(t.TempDir(), "z.log"), "", "node-1")
	c.SetFindingSaver(saver)
	c.recordFindings(context.Background(), &Record{
		RequestID: "r-fj", EndpointKey: "GET /v1/z", FinalAction: "BLOCK",
		Details: []dsctx.DetectorMatch{{Detector: "waf", RuleID: "942100", Severity: "HIGH", Message: "sqli", ScoreDelta: 50}},
	})
	if len(saver.batches) != 1 {
		t.Fatal("no finding captured")
	}
	if _, err := json.Marshal(saver.batches[0][0].Detail); err != nil {
		t.Fatalf("detail must be json-marshalable: %v", err)
	}
}

// Parser 歧义检测契约（detector=api_parser，Category=OBSERVE，Severity=MEDIUM，
// final_action=ALLOW）：走完整 ingest（JSON 日志行 → CollectOnce）→ 物化路径，
// severity≥MEDIUM 达标即落库（不依赖事件动作）；evidence 白名单键
// （parameter_name/location/value_count/rule_code/path）留值，raw_value 等原始值键剥除。
func TestCollectOnce_ParserAmbiguityFinding(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	dupJSONKey := Record{
		RequestID: "r-pa-1", EndpointKey: "POST /v1/orders", Method: "POST", PathTemplate: "/v1/orders",
		IsAPI: true, FinalAction: "ALLOW", RiskLevel: "LOW", RiskScore: 10,
		Details: []dsctx.DetectorMatch{{
			Detector: "api_parser", RuleID: "parser.duplicate_json_key",
			Category: "OBSERVE", Severity: "MEDIUM",
			Message: "duplicate JSON key in request body",
			Evidence: map[string]string{
				"parameter_name": "order_id", "location": "json", "path": "order.items",
				"value_count": "2", "rule_code": "PARSER-DUP-JSON-001",
			},
		}},
		OccurredAt: time.Now().UTC(),
	}
	// 契约防线：网关若误上报原始值键，物化侧必须剥除（值丢弃，仅键名入 keys 列表）
	dupQueryParam := Record{
		RequestID: "r-pa-2", EndpointKey: "GET /v1/orders", Method: "GET", PathTemplate: "/v1/orders",
		IsAPI: true, FinalAction: "ALLOW",
		Details: []dsctx.DetectorMatch{{
			Detector: "api_parser", RuleID: "parser.duplicate_query_param",
			Category: "OBSERVE", Severity: "MEDIUM",
			Message: "duplicate query parameter",
			Evidence: map[string]string{
				"parameter_name": "id", "location": "query", "value_count": "3",
				"raw_value": "id=1&id=2&id=3", "normalized_value": "1|2|3",
			},
		}},
		OccurredAt: time.Now().UTC(),
	}
	writeLines(t, logPath, []string{mustJSON(t, dupJSONKey), mustJSON(t, dupQueryParam)})

	fs := &fakeFindingSaver{}
	c := NewCollector(&fakeSaver{}, "test-parser-amb", logPath, filepath.Join(dir, "cp"), "node-1")
	c.SetFindingSaver(fs)
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}

	// 两条 ALLOW 事件均因 severity=MEDIUM 达标而物化（final_action=ALLOW 不阻断落库）
	if len(fs.batches) != 2 || len(fs.batches[0]) != 1 || len(fs.batches[1]) != 1 {
		t.Fatalf("parser ambiguity findings must materialize under ALLOW: %+v", fs.batches)
	}

	// 1) 白名单键留值：finding_type 机械映射 / severity 原样 / category 透传 / 证据仅白名单键
	f := fs.batches[0][0]
	if f.FindingType != "PARSER_DUPLICATE_JSON_KEY" || f.Severity != "MEDIUM" {
		t.Fatalf("bad parser finding: %+v", f)
	}
	if f.Detail["detector"] != "api_parser" || f.Detail["category"] != "OBSERVE" ||
		f.Detail["rule_id"] != "parser.duplicate_json_key" || f.Detail["final_action"] != "ALLOW" {
		t.Fatalf("detail contract broken: %+v", f.Detail)
	}
	for k, want := range map[string]string{
		"parameter_name": "order_id", "location": "json", "path": "order.items",
		"value_count": "2", "rule_code": "PARSER-DUP-JSON-001",
	} {
		if f.Evidence[k] != want {
			t.Fatalf("whitelisted evidence key %q missing: %+v", k, f.Evidence)
		}
	}
	if len(f.Evidence) != 6 { // 5 个白名单键 + keys 列表，无其他键
		t.Fatalf("evidence must contain whitelist keys only: %+v", f.Evidence)
	}

	// 2) 原始值键剥除：raw_value/normalized_value 值丢弃，仅键名留在 keys 列表
	g := fs.batches[1][0]
	if g.FindingType != "PARSER_DUPLICATE_QUERY_PARAM" {
		t.Fatalf("bad query param finding type: %+v", g)
	}
	if _, leaked := g.Evidence["raw_value"]; leaked {
		t.Fatalf("raw_value must be stripped: %+v", g.Evidence)
	}
	if _, leaked := g.Evidence["normalized_value"]; leaked {
		t.Fatalf("normalized_value must be stripped: %+v", g.Evidence)
	}
	if g.Evidence["parameter_name"] != "id" || g.Evidence["location"] != "query" || g.Evidence["value_count"] != "3" {
		t.Fatalf("whitelisted keys must keep values: %+v", g.Evidence)
	}
	keys, ok := g.Evidence["keys"].([]string)
	if !ok || len(keys) != 5 || keys[0] != "location" || keys[2] != "parameter_name" || keys[4] != "value_count" {
		t.Fatalf("stripped keys must remain as names in sorted keys list: %+v", g.Evidence["keys"])
	}
}
