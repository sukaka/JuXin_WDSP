package apiassets

import (
	"math"
	"strings"
	"testing"
)

// TestClassifyActionVocabulary §34.2 操作动作词表抽样覆盖：每个有规则的词表项至少一个命中样例。
func TestClassifyActionVocabulary(t *testing.T) {
	cases := []struct {
		method, path, want string
	}{
		{"POST", "/api/v1/users", "CREATE"},
		{"GET", "/api/v1/users", "READ_LIST"},
		{"GET", "/api/v1/users/{id}", "READ_DETAIL"},
		{"GET", "/api/v1/users/42", "READ_DETAIL"},
		{"GET", "/api/v1/users/list", "READ_LIST"},
		{"GET", "/api/v1/orders/search", "SEARCH"},
		{"POST", "/api/v1/orders/search", "SEARCH"},
		{"GET", "/api/v1/orders/count", "COUNT"},
		{"PUT", "/api/v1/users/{id}", "UPDATE"},
		{"PATCH", "/api/v1/users/{id}", "PATCH"},
		{"DELETE", "/api/v1/users/{id}", "DELETE"},
		{"POST", "/api/v1/users/batch", "BATCH_CREATE"},
		{"POST", "/api/v1/bulk-import/users", "BATCH_CREATE"},
		{"PUT", "/api/v1/users/batch", "BATCH_UPDATE"},
		{"DELETE", "/api/v1/users/batch", "BATCH_DELETE"},
		{"POST", "/api/v1/accounts/register", "REGISTER"},
		{"POST", "/api/v1/auth/login", "LOGIN"},
		{"POST", "/api/v1/auth/signin", "LOGIN"},
		{"POST", "/api/v1/auth/logout", "LOGOUT"},
		{"POST", "/api/v1/oauth/token", "TOKEN_ISSUE"},
		{"POST", "/api/v1/oauth/token/refresh", "TOKEN_REFRESH"},
		{"POST", "/api/v1/oauth/revoke", "TOKEN_REVOKE"},
		{"POST", "/api/v1/captcha/verify", "VERIFY"},
		{"POST", "/api/v1/orders/{id}/submit", "SUBMIT"},
		{"POST", "/api/v1/tickets/{id}/approve", "APPROVE"},
		{"POST", "/api/v1/tickets/{id}/reject", "REJECT"},
		{"POST", "/api/v1/orders/{id}/withdraw", "WITHDRAW"},
		{"POST", "/api/v1/tickets/{id}/assign", "ASSIGN"},
		{"POST", "/api/v1/accounts/transfer", "TRANSFER"},
		{"POST", "/api/v1/articles/{id}/publish", "PUBLISH"},
		{"POST", "/api/v1/articles/{id}/unpublish", "UNPUBLISH"},
		{"POST", "/api/v1/users/{id}/enable", "ENABLE"},
		{"POST", "/api/v1/users/{id}/disable", "DISABLE"},
		{"POST", "/api/v1/users/{id}/lock", "LOCK"},
		{"POST", "/api/v1/users/{id}/unlock", "UNLOCK"},
		{"POST", "/api/v1/data/import", "IMPORT"},
		{"GET", "/api/v1/data/export", "EXPORT"},
		{"POST", "/api/v1/files/upload", "UPLOAD"},
		{"GET", "/api/v1/files/{id}/download", "DOWNLOAD"},
		{"GET", "/api/v1/files/{id}/preview", "PREVIEW"},
		{"POST", "/api/v1/devices/sync", "SYNC"},
		{"POST", "/api/v1/pay/callback", "CALLBACK"},
		{"POST", "/api/v1/jobs/{id}/start", "START"},
		{"POST", "/api/v1/jobs/{id}/stop", "STOP"},
		{"POST", "/api/v1/jobs/{id}/retry", "RETRY"},
		{"POST", "/api/v1/system/backup", "BACKUP"},
		{"POST", "/api/v1/system/restore", "RESTORE"},
		{"POST", "/api/v1/tasks/{id}/execute", "EXECUTE"},
	}
	for _, c := range cases {
		got, conf := classifyAction(c.method, c.path)
		if got != c.want {
			t.Errorf("%s %s: got %s want %s", c.method, c.path, got, c.want)
			continue
		}
		if conf < 0.5 || conf > 1 {
			t.Errorf("%s %s: conf=%v 超出规则/方法映射置信区间", c.method, c.path, conf)
		}
	}
}

// TestClassifyActionNoMisfire 不误伤：方法约束不达成、子串非 token、兜底语义正确。
func TestClassifyActionNoMisfire(t *testing.T) {
	cases := []struct {
		method, path, want string
	}{
		// GET /tokens 是令牌资源列表，不是签发（TOKEN_ISSUE 限定 POST）
		{"GET", "/api/v1/tokens", "READ_LIST"},
		// publisher 与 publish 是不同 token，不命中 PUBLISH
		{"GET", "/api/v1/publishers/{id}", "READ_DETAIL"},
		// 驼峰段拆分：refreshToken → refresh + token
		{"POST", "/api/v1/auth/refreshToken", "TOKEN_REFRESH"},
		// 路径含 refresh 但无 token 上下文，不判 TOKEN_REFRESH，落方法兜底
		{"POST", "/api/v1/cache/refresh", "CREATE"},
		// GET 审批列表是读操作，不是 APPROVE（限定写方法）
		{"GET", "/api/v1/approvals", "READ_LIST"},
		// 根路径与空路径不 panic，落 READ_LIST
		{"GET", "/", "READ_LIST"},
		{"GET", "", "READ_LIST"},
		// 非常规方法兜底 CUSTOM
		{"OPTIONS", "/api/v1/users", "CUSTOM"},
	}
	for _, c := range cases {
		got, _ := classifyAction(c.method, c.path)
		if got != c.want {
			t.Errorf("%s %s: got %s want %s", c.method, c.path, got, c.want)
		}
	}
}

// TestClassifyBusinessDomain §34.1 业务领域映射：种子编码命中与低置信不打标。
func TestClassifyBusinessDomain(t *testing.T) {
	cases := []struct {
		path     string
		wantCode string
		wantOK   bool
	}{
		{"/api/v1/auth/login", "IDENTITY_AUTH", true},
		{"/api/v1/users/{id}/profile", "USER_ACCOUNT", true},
		{"/api/v1/roles/{id}/permissions", "ORG_PERMISSION", true},
		{"/api/v1/orders/{id}", "TRANSACTION_FUND", true},
		{"/api/v1/files/upload", "FILE_CONTENT", true},
		{"/api/v1/reports/dashboard", "QUERY_ANALYTICS", true},
		{"/api/v1/data/import", "IMPORT_EXPORT", true},
		{"/api/v1/messages/sms", "MESSAGE_NOTIFICATION", true},
		{"/api/v1/webhooks/callback", "EXTERNAL_INTEGRATION", true},
		{"/api/v1/system/settings", "SYSTEM_CONFIG", true},
		{"/api/v1/ops/jobs/{id}", "SYSTEM_OPS", true},
		{"/api/v1/devices/{id}/telemetry", "DEVICE_IOT", true},
		{"/api/v1/ai/models/{id}", "AI_INTELLIGENCE", true},
		{"/api/v1/privacy/consents", "PRIVACY_COMPLIANCE", true},
		{"/api/v1/tickets/{id}/approve", "PROCESS_APPROVAL", true},
		// 无关键词命中：不打标
		{"/api/v1/foobar/{id}", "", false},
		// 多领域各命中 1 次并列：低置信不打标
		{"/api/v1/users/{id}/orders", "", false},
		// 变量段与纯数字段不参与命中
		{"/api/v1/{resource}/123", "", false},
	}
	for _, c := range cases {
		code, conf, ok := classifyBusinessDomain(c.path)
		if ok != c.wantOK || code != c.wantCode {
			t.Errorf("%s: got (%s,%v) want (%s,%v)", c.path, code, ok, c.wantCode, c.wantOK)
			continue
		}
		if ok && conf < 0.5 {
			t.Errorf("%s: conf=%v 低于打标阈值", c.path, conf)
		}
	}
}

// TestClassifyByPathDimensions 自动分类维度组合：ACTION 恒产出，BUSINESS_DOMAIN 条件产出。
func TestClassifyByPathDimensions(t *testing.T) {
	dims := classifyByPath("POST", "/api/v1/auth/login")
	got := map[string]string{}
	for _, d := range dims {
		if d.Source != "AUTO" {
			t.Fatalf("dim source: %+v", d)
		}
		got[d.Dimension] = d.Value
	}
	if got["PURPOSE"] != "AUTH" || got["ACCESS"] != "WRITE" || got["EXPOSURE"] != "INTERNAL" {
		t.Fatalf("legacy dims: %v", got)
	}
	if got["ACTION"] != "LOGIN" {
		t.Fatalf("ACTION=%s", got["ACTION"])
	}
	if got["BUSINESS_DOMAIN"] != "IDENTITY_AUTH" {
		t.Fatalf("BUSINESS_DOMAIN=%s", got["BUSINESS_DOMAIN"])
	}
	// 无领域命中时维度数为 4，不编造 BUSINESS_DOMAIN
	dims = classifyByPath("GET", "/api/v1/widgets/{id}")
	if len(dims) != 4 {
		t.Fatalf("dims=%v", dims)
	}
	for _, d := range dims {
		if d.Dimension == "BUSINESS_DOMAIN" {
			t.Fatalf("unexpected domain dim: %+v", d)
		}
	}
}

func TestClassifyByProtocolVocabulary(t *testing.T) {
	cases := []struct {
		protocol, technical, interaction string
	}{
		{"REST", "REST", "REQUEST_RESPONSE"},
		{"REST_JSON", "REST_JSON", "REQUEST_RESPONSE"},
		{"REST_XML", "REST_XML", "REQUEST_RESPONSE"},
		{"FORM_API", "FORM_API", "REQUEST_RESPONSE"},
		{"GRAPHQL", "GRAPHQL", "REQUEST_RESPONSE"},
		{"JSON_RPC", "JSON_RPC", "RPC"},
		{"XML_RPC", "XML_RPC", "RPC"},
		{"SOAP", "SOAP", "RPC"},
		{"WEBHOOK", "WEBHOOK", "EVENT_CALLBACK"},
		{"FILE_UPLOAD", "FILE_UPLOAD", "FILE_TRANSFER"},
		{"FILE_DOWNLOAD", "FILE_DOWNLOAD", "FILE_TRANSFER"},
		{"WEBSOCKET_HANDSHAKE", "WEBSOCKET_HANDSHAKE", "BIDIRECTIONAL_STREAM"},
		{"SERVER_SENT_EVENTS", "SERVER_SENT_EVENTS", "SERVER_PUSH"},
		{"GRPC", "GRPC", "RPC"},
		{"WEBSOCKET", "WEBSOCKET", "BIDIRECTIONAL_STREAM"},
		{"UNKNOWN_HTTP_API", "UNKNOWN_HTTP_API", ""},
		{"NOT_A_PROTOCOL", "UNKNOWN_HTTP_API", ""},
		{"", "", ""},
		{" \t\n ", "", ""},
		{"  rest_json  ", "REST_JSON", "REQUEST_RESPONSE"},
		{"wEbSoCkEt", "WEBSOCKET", "BIDIRECTIONAL_STREAM"},
	}
	for _, c := range cases {
		dims := classifyByProtocol(c.protocol)
		wantLen := 0
		if c.technical != "" {
			wantLen++
		}
		if c.interaction != "" {
			wantLen++
		}
		if len(dims) != wantLen {
			t.Errorf("protocol %q: dims=%v, want len=%d", c.protocol, dims, wantLen)
			continue
		}
		got := map[string]string{}
		for _, d := range dims {
			if d.Source != "AUTO" {
				t.Errorf("protocol %q: source=%q, want AUTO", c.protocol, d.Source)
			}
			got[d.Dimension] = d.Value
		}
		if got["TECHNICAL_PROTOCOL"] != c.technical {
			t.Errorf("protocol %q: TECHNICAL_PROTOCOL=%q, want %q", c.protocol, got["TECHNICAL_PROTOCOL"], c.technical)
		}
		if got["INTERACTION_MODE"] != c.interaction {
			t.Errorf("protocol %q: INTERACTION_MODE=%q, want %q", c.protocol, got["INTERACTION_MODE"], c.interaction)
		}
	}
}

func TestClassifyDataSensitivity(t *testing.T) {
	cases := []struct {
		name           string
		parameters     []parameterSensitivity
		wantLevel      string
		wantConfidence float64
		wantOK         bool
	}{
		{
			name: "highest_level_then_max_confidence",
			parameters: []parameterSensitivity{
				{level: "LOW", confidence: 1},
				{level: "MEDIUM", confidence: 0.99},
				{level: "HIGH", confidence: 0.2},
				{level: "HIGH", confidence: 0.8},
			},
			wantLevel: "HIGH", wantConfidence: 0.8, wantOK: true,
		},
		{
			name: "low_outranks_unknown",
			parameters: []parameterSensitivity{
				{level: "UNKNOWN", confidence: 1},
				{level: "LOW", confidence: 0.3},
			},
			wantLevel: "LOW", wantConfidence: 0.3, wantOK: true,
		},
		{
			name: "unknown_uses_max_confidence",
			parameters: []parameterSensitivity{
				{level: "UNKNOWN", confidence: 0.2},
				{level: "UNKNOWN", confidence: 0.7},
			},
			wantLevel: "UNKNOWN", wantConfidence: 0.7, wantOK: true,
		},
		{name: "confidence_above_one", parameters: []parameterSensitivity{{level: "HIGH", confidence: 1.8}}, wantLevel: "HIGH", wantConfidence: 1, wantOK: true},
		{name: "negative_confidence", parameters: []parameterSensitivity{{level: "LOW", confidence: -0.2}}, wantLevel: "LOW", wantConfidence: 0, wantOK: true},
		{name: "nan_confidence", parameters: []parameterSensitivity{{level: "MEDIUM", confidence: math.NaN()}}, wantLevel: "MEDIUM", wantConfidence: 0, wantOK: true},
		{name: "level_normalized", parameters: []parameterSensitivity{{level: " high ", confidence: 0.3}}, wantLevel: "HIGH", wantConfidence: 0.3, wantOK: true},
		{name: "invalid_level_is_unknown", parameters: []parameterSensitivity{{level: "SECRET", confidence: 0.4}}, wantLevel: "UNKNOWN", wantConfidence: 0.4, wantOK: true},
		{name: "no_parameters", wantOK: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dim, ok := classifyDataSensitivity(c.parameters)
			if ok != c.wantOK {
				t.Fatalf("ok=%v, want %v (dim=%+v)", ok, c.wantOK, dim)
			}
			if !ok {
				return
			}
			if dim.Dimension != "DATA_SENSITIVITY" || dim.Source != "AUTO" || dim.Value != c.wantLevel || dim.Confidence != c.wantConfidence {
				t.Fatalf("dim=%+v, want level=%q confidence=%v source=AUTO", dim, c.wantLevel, c.wantConfidence)
			}
			if dim.Confidence < 0 || dim.Confidence > 1 || math.IsNaN(dim.Confidence) {
				t.Fatalf("confidence not normalized: %v", dim.Confidence)
			}
		})
	}
}

func TestClassifyIdentityRequirement(t *testing.T) {
	cases := []struct {
		name      string
		obs       identityObservation
		wantValue string
		wantOK    bool
	}{
		{name: "no_effective_events", obs: identityObservation{}, wantOK: false},
		{name: "authenticated_only", obs: identityObservation{authenticatedSuccess: true}, wantValue: "AUTHENTICATED_OBSERVED", wantOK: true},
		{name: "anonymous_rejected_only", obs: identityObservation{anonymousRejected: true}, wantValue: "ANONYMOUS_REJECTED", wantOK: true},
		{name: "required", obs: identityObservation{anonymousRejected: true, authenticatedSuccess: true}, wantValue: "AUTH_REQUIRED", wantOK: true},
		{name: "anonymous_success_only", obs: identityObservation{anonymousSuccess: true}, wantValue: "ANONYMOUS_ALLOWED", wantOK: true},
		{name: "optional", obs: identityObservation{anonymousSuccess: true, authenticatedSuccess: true}, wantValue: "AUTH_OPTIONAL", wantOK: true},
		{
			name:      "anonymous_success_precedes_rejection",
			obs:       identityObservation{anonymousSuccess: true, anonymousRejected: true},
			wantValue: "ANONYMOUS_ALLOWED", wantOK: true,
		},
		{
			name:      "optional_precedes_required",
			obs:       identityObservation{anonymousSuccess: true, anonymousRejected: true, authenticatedSuccess: true},
			wantValue: "AUTH_OPTIONAL", wantOK: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dim, ok := classifyIdentityRequirement(c.obs)
			if ok != c.wantOK {
				t.Fatalf("ok=%v, want %v (dim=%+v)", ok, c.wantOK, dim)
			}
			if !ok {
				return
			}
			if dim.Dimension != "IDENTITY_REQUIREMENT" || dim.Value != c.wantValue || dim.Source != "AUTO" || dim.Confidence != 0.7 {
				t.Fatalf("dim=%+v, want value=%q source=AUTO confidence=0.7", dim, c.wantValue)
			}
		})
	}
}

func TestClassifyBusinessFlowStage(t *testing.T) {
	cases := []struct {
		name      string
		steps     []flowStepObservation
		wantValue string
		wantOK    bool
	}{
		{name: "no_enabled_flow_steps", wantOK: false},
		{
			name:      "start_and_terminal",
			steps:     []flowStepObservation{{flowID: "f1", terminal: true, minSequence: true, noPredecessors: true}},
			wantValue: "START_AND_TERMINAL", wantOK: true,
		},
		{
			name:      "terminal",
			steps:     []flowStepObservation{{flowID: "f1", terminal: true, minSequence: false, noPredecessors: true}},
			wantValue: "TERMINAL", wantOK: true,
		},
		{
			name:      "terminal_at_min_sequence_with_predecessor",
			steps:     []flowStepObservation{{flowID: "f1", terminal: true, minSequence: true, noPredecessors: false}},
			wantValue: "TERMINAL", wantOK: true,
		},
		{
			name:      "start",
			steps:     []flowStepObservation{{flowID: "f1", minSequence: true, noPredecessors: true}},
			wantValue: "START", wantOK: true,
		},
		{
			name:      "min_sequence_with_predecessor_is_intermediate",
			steps:     []flowStepObservation{{flowID: "f1", minSequence: true, noPredecessors: false}},
			wantValue: "INTERMEDIATE", wantOK: true,
		},
		{
			name:      "no_predecessor_without_min_sequence_is_intermediate",
			steps:     []flowStepObservation{{flowID: "f1", minSequence: false, noPredecessors: true}},
			wantValue: "INTERMEDIATE", wantOK: true,
		},
		{
			name: "same_role_across_flows_deduplicated",
			steps: []flowStepObservation{
				{flowID: "f1", minSequence: true, noPredecessors: true},
				{flowID: "f2", minSequence: true, noPredecessors: true},
			},
			wantValue: "START", wantOK: true,
		},
		{
			name: "different_roles_are_multi_stage",
			steps: []flowStepObservation{
				{flowID: "f1", minSequence: true, noPredecessors: true},
				{flowID: "f2", terminal: true},
			},
			wantValue: "MULTI_STAGE", wantOK: true,
		},
		{
			name: "row_order_does_not_change_multi_stage",
			steps: []flowStepObservation{
				{flowID: "f2", terminal: true},
				{flowID: "f1", minSequence: true, noPredecessors: true},
			},
			wantValue: "MULTI_STAGE", wantOK: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dim, ok := classifyBusinessFlowStage(c.steps)
			if ok != c.wantOK {
				t.Fatalf("ok=%v, want %v (dim=%+v)", ok, c.wantOK, dim)
			}
			if !ok {
				return
			}
			if dim.Dimension != "BUSINESS_FLOW_STAGE" || dim.Value != c.wantValue || dim.Source != "AUTO" || dim.Confidence != 1 {
				t.Fatalf("dim=%+v, want value=%q source=AUTO confidence=1", dim, c.wantValue)
			}
		})
	}
}

func TestClassifyRiskLabel(t *testing.T) {
	cases := []struct {
		name           string
		findings       []runtimeFinding
		wantValue      string
		wantConfidence float64
		wantOK         bool
	}{
		{name: "no_active_findings", wantOK: false},
		{name: "info_and_open_type_normalized", findings: []runtimeFinding{{severity: "INFO", findingType: "  vendor_rule_9  "}}, wantValue: "VENDOR_RULE_9", wantConfidence: 0.2, wantOK: true},
		{name: "low", findings: []runtimeFinding{{severity: "LOW", findingType: "LOW_RISK"}}, wantValue: "LOW_RISK", wantConfidence: 0.4, wantOK: true},
		{name: "medium", findings: []runtimeFinding{{severity: "MEDIUM", findingType: "MEDIUM_RISK"}}, wantValue: "MEDIUM_RISK", wantConfidence: 0.6, wantOK: true},
		{name: "high", findings: []runtimeFinding{{severity: "HIGH", findingType: "HIGH_RISK"}}, wantValue: "HIGH_RISK", wantConfidence: 0.8, wantOK: true},
		{name: "critical", findings: []runtimeFinding{{severity: "CRITICAL", findingType: "CRITICAL_RISK"}}, wantValue: "CRITICAL_RISK", wantConfidence: 1, wantOK: true},
		{
			name: "highest_severity_wins",
			findings: []runtimeFinding{
				{severity: "LOW", findingType: "LOW_RISK"},
				{severity: "CRITICAL", findingType: "CRITICAL_RISK"},
				{severity: "HIGH", findingType: "HIGH_RISK"},
			},
			wantValue: "CRITICAL_RISK", wantConfidence: 1, wantOK: true,
		},
		{
			name: "multiple_types_at_highest_severity",
			findings: []runtimeFinding{
				{severity: "HIGH", findingType: "BOLA"},
				{severity: "LOW", findingType: "LOW_RISK"},
				{severity: "HIGH", findingType: "BFLA"},
			},
			wantValue: "MULTI_RISK", wantConfidence: 0.8, wantOK: true,
		},
		{
			name: "row_order_does_not_change_multi_risk",
			findings: []runtimeFinding{
				{severity: "HIGH", findingType: "BFLA"},
				{severity: "HIGH", findingType: "BOLA"},
			},
			wantValue: "MULTI_RISK", wantConfidence: 0.8, wantOK: true,
		},
		{
			name: "normalized_duplicate_type_deduplicated",
			findings: []runtimeFinding{
				{severity: "HIGH", findingType: " bola "},
				{severity: "HIGH", findingType: "BOLA"},
			},
			wantValue: "BOLA", wantConfidence: 0.8, wantOK: true,
		},
		{name: "single_character_type", findings: []runtimeFinding{{severity: "INFO", findingType: "A"}}, wantValue: "A", wantConfidence: 0.2, wantOK: true},
		{name: "maximum_length_type", findings: []runtimeFinding{{severity: "INFO", findingType: strings.Repeat("A", 64)}}, wantValue: strings.Repeat("A", 64), wantConfidence: 0.2, wantOK: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dim, ok, err := classifyRiskLabel(c.findings)
			if err != nil {
				t.Fatalf("classifyRiskLabel: %v", err)
			}
			if ok != c.wantOK {
				t.Fatalf("ok=%v, want %v (dim=%+v)", ok, c.wantOK, dim)
			}
			if !ok {
				return
			}
			if dim.Dimension != "RISK_LABEL" || dim.Value != c.wantValue || dim.Source != "AUTO" || dim.Confidence != c.wantConfidence {
				t.Fatalf("dim=%+v, want value=%q source=AUTO confidence=%v", dim, c.wantValue, c.wantConfidence)
			}
		})
	}
}

func TestClassifyRiskLabelRejectsInvalidRows(t *testing.T) {
	for _, findingType := range []string{"", "   ", "BAD-TYPE", "BAD TYPE", "类型", strings.Repeat("A", 65)} {
		t.Run("invalid_finding_type_"+findingType, func(t *testing.T) {
			if _, _, err := classifyRiskLabel([]runtimeFinding{{severity: "INFO", findingType: findingType}}); err == nil {
				t.Fatalf("finding_type %q should fail", findingType)
			}
		})
	}
	t.Run("invalid_lower_severity_type_still_fails", func(t *testing.T) {
		findings := []runtimeFinding{
			{severity: "CRITICAL", findingType: "BOLA"},
			{severity: "INFO", findingType: "bad-type"},
		}
		if _, _, err := classifyRiskLabel(findings); err == nil {
			t.Fatal("invalid lower-severity active finding should fail")
		}
	})
	t.Run("invalid_severity", func(t *testing.T) {
		if _, _, err := classifyRiskLabel([]runtimeFinding{{severity: "SEVERE", findingType: "BOLA"}}); err == nil {
			t.Fatal("invalid severity should fail")
		}
	})
}

func TestClassifyBusinessObject(t *testing.T) {
	cases := []struct {
		name           string
		models         []objectModelObservation
		segments       []PathSegment
		wantValue      string
		wantConfidence float64
		wantOK         bool
	}{
		{name: "no_models", wantOK: false},
		{name: "query_normalized", models: []objectModelObservation{{segment: "query: account_id "}}, wantValue: "ACCOUNT_ID", wantConfidence: 0.65, wantOK: true},
		{name: "query_publishable", models: []objectModelObservation{{segment: "query:order_id", publishable: true}}, wantValue: "ORDER_ID", wantConfidence: 0.9, wantOK: true},
		{
			name:   "nearest_previous_static_segment",
			models: []objectModelObservation{{segment: "path:3"}},
			segments: []PathSegment{
				{Position: 0, LiteralValue: "api"},
				{Position: 1, LiteralValue: "orders"},
				{Position: 2, IsVariable: true, VariableName: "order_id"},
				{Position: 3, IsVariable: true, VariableName: "item_id"},
			},
			wantValue: "ORDERS", wantConfidence: 0.65, wantOK: true,
		},
		{
			name:   "variable_name_fallback",
			models: []objectModelObservation{{segment: "path:1"}},
			segments: []PathSegment{
				{Position: 0, LiteralValue: "  "},
				{Position: 1, IsVariable: true, VariableName: " order_id "},
			},
			wantValue: "ORDER_ID", wantConfidence: 0.65, wantOK: true,
		},
		{
			name:     "missing_segment_skipped",
			models:   []objectModelObservation{{segment: "path:4", publishable: true}},
			segments: []PathSegment{{Position: 0, LiteralValue: "orders"}},
			wantOK:   false,
		},
		{
			name:     "empty_fallback_has_no_valid_derivation",
			models:   []objectModelObservation{{segment: "path:0"}},
			segments: []PathSegment{{Position: 0, IsVariable: true, VariableName: "  "}},
			wantOK:   false,
		},
		{
			name:   "multiple_objects_and_publishable_confidence",
			models: []objectModelObservation{{segment: "path:1"}, {segment: "query:account_id", publishable: true}},
			segments: []PathSegment{
				{Position: 0, LiteralValue: "orders"},
				{Position: 1, IsVariable: true, VariableName: "id"},
			},
			wantValue: "MULTI_OBJECT", wantConfidence: 0.9, wantOK: true,
		},
		{
			name:   "row_order_does_not_change_multi_object",
			models: []objectModelObservation{{segment: "query:account_id", publishable: true}, {segment: "path:1"}},
			segments: []PathSegment{
				{Position: 1, IsVariable: true, VariableName: "id"},
				{Position: 0, LiteralValue: "orders"},
			},
			wantValue: "MULTI_OBJECT", wantConfidence: 0.9, wantOK: true,
		},
		{
			name:   "same_object_deduplicated",
			models: []objectModelObservation{{segment: "path:1"}, {segment: "query:order", publishable: true}},
			segments: []PathSegment{
				{Position: 0, LiteralValue: " order "},
				{Position: 1, IsVariable: true, VariableName: "id"},
			},
			wantValue: "ORDER", wantConfidence: 0.9, wantOK: true,
		},
		{
			name:      "publishable_missing_derivation_does_not_raise_confidence",
			models:    []objectModelObservation{{segment: "path:9", publishable: true}, {segment: "query:order_id"}},
			wantValue: "ORDER_ID", wantConfidence: 0.65, wantOK: true,
		},
		{name: "unicode_128_characters", models: []objectModelObservation{{segment: "query:" + strings.Repeat("界", 128)}}, wantValue: strings.Repeat("界", 128), wantConfidence: 0.65, wantOK: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dim, ok, err := classifyBusinessObject(c.models, c.segments)
			if err != nil {
				t.Fatalf("classifyBusinessObject: %v", err)
			}
			if ok != c.wantOK {
				t.Fatalf("ok=%v, want %v (dim=%+v)", ok, c.wantOK, dim)
			}
			if !ok {
				return
			}
			if dim.Dimension != "BUSINESS_OBJECT" || dim.Value != c.wantValue || dim.Source != "AUTO" || dim.Confidence != c.wantConfidence {
				t.Fatalf("dim=%+v, want value=%q source=AUTO confidence=%v", dim, c.wantValue, c.wantConfidence)
			}
		})
	}
}

func TestClassifyBusinessObjectRejectsInvalidShapes(t *testing.T) {
	for _, segment := range []string{"body:id", "path:", "path:x", "path:-1", "path:1.5", "query:", "query:   "} {
		t.Run("invalid_segment_"+segment, func(t *testing.T) {
			if _, _, err := classifyBusinessObject([]objectModelObservation{{segment: segment}}, nil); err == nil {
				t.Fatalf("object_segment %q should fail", segment)
			}
		})
	}
	t.Run("path_target_must_be_variable", func(t *testing.T) {
		models := []objectModelObservation{{segment: "path:0"}}
		segments := []PathSegment{{Position: 0, LiteralValue: "orders"}}
		if _, _, err := classifyBusinessObject(models, segments); err == nil {
			t.Fatal("static path target should fail")
		}
	})
	t.Run("control_character", func(t *testing.T) {
		if _, _, err := classifyBusinessObject([]objectModelObservation{{segment: "query:bad\nname"}}, nil); err == nil {
			t.Fatal("control character should fail")
		}
	})
	t.Run("value_over_128_characters", func(t *testing.T) {
		if _, _, err := classifyBusinessObject([]objectModelObservation{{segment: "query:" + strings.Repeat("界", 129)}}, nil); err == nil {
			t.Fatal("value over 128 characters should fail")
		}
	})
}
