package jiuzhang_guard

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/pipeline"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"go.uber.org/zap"
)

type nextFunc func(http.ResponseWriter, *http.Request) error

func (f nextFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error { return f(w, r) }

// newAPITestGuard 构造仅启用 API 动态防护所需字段的 Guard（不经过 Provision）。
func newAPITestGuard(t *testing.T, mode string, schemas map[string]map[string]string) (*Guard, string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "api-runtime-events.log")
	al, err := apievents.NewLogger(logPath, "test-node")
	if err != nil {
		t.Fatalf("new api events logger: %v", err)
	}
	t.Cleanup(func() { _ = al.Close() })
	g := &Guard{
		AppID:                "app-1",
		AppCode:              "shop",
		APIDynamicProtection: true,
		APIProtectionMode:    mode,
		APIFormalSchemas:     schemas,
		apiEvents:            al,
		logger:               zap.NewNop(),
	}
	return g, logPath
}

func readAPIRecords(t *testing.T, path string) []apievents.Record {
	t.Helper()
	var data []byte
	for attempt := 0; attempt < 50; attempt++ {
		current, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			t.Fatalf("read api events log: %v", err)
		}
		if len(current) > 0 && attempt > 0 && bytes.Equal(data, current) {
			data = current
			break
		}
		data = current
		time.Sleep(5 * time.Millisecond)
	}
	var out []apievents.Record
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var rec apievents.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad json line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// 关闭时：零行为变化，不产事件、不进管线。
func TestServeNext_DisabledPassthrough(t *testing.T) {
	g := &Guard{APIDynamicProtection: false, logger: zap.NewNop()}
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called {
		t.Fatal("next handler not called when API protection disabled")
	}
	if RequestContextFrom(req) != nil {
		t.Fatal("request context should not carry RequestContext when disabled")
	}
}

// OBSERVE 模式 + 模型偏离：放行、上下文注入、事件落盘且含 type_mismatch 明细。
func TestServeNext_ObserveModeRecordsDeviation(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"id": "number"}}
	g, logPath := newAPITestGuard(t, "OBSERVE", schemas)

	var gotBody string
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-observe-1")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if gotBody != `{"id":"abc"}` {
		t.Fatalf("downstream body corrupted: %q", gotBody)
	}
	rc := RequestContextFrom(req)
	if rc == nil {
		t.Fatal("RequestContext not injected into request context")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	rec := recs[0]
	if rec.RequestID != "req-observe-1" || rec.EndpointKey != "POST /v1/orders" {
		t.Fatalf("bad record identity: %+v", rec)
	}
	if !rec.IsAPI || rec.Method != "POST" || rec.PathTemplate != "/v1/orders" {
		t.Fatalf("bad discovery fields: %+v", rec)
	}
	found := false
	for _, d := range rec.Details {
		if d.RuleID == "schema.type_mismatch" && d.Category == "BLOCK" {
			found = true
		}
	}
	if !found {
		t.Fatalf("type_mismatch detail missing: %+v", rec.Details)
	}
	if rec.FinalAction == "BLOCK" {
		t.Fatal("OBSERVE mode must not finalize BLOCK")
	}
}

// AUTHZ-01 组合验收：真实 Guard → API 管线 → API 事件出口。
// BOLA 观测命中必须放行下游，并且事件只保留 HMAC 对象引用。
func TestServeNext_AuthzBOLAObserveRecordsHMACAndPassthrough(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	rawObjectID := "order-78231"
	objectRef := detectors.ObjectRefHMAC(key, rawObjectID)
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	g.APIPolicyVersion = "authz-v3"
	g.APIAuthzObjectHMACKey = key
	g.APIAuthzModels = []detectors.ObjectModel{{
		ApplicationID:          "app-1",
		EndpointKey:            "GET /v1/orders/{id}",
		PathTemplate:           "/v1/orders/{orderId}",
		ObjectType:             "ORDER",
		Identifiers:            []detectors.ObjectIdentifier{{Location: "path", Name: "orderId", Primary: true}},
		RequiredRelation:       "OWNER",
		OwnerExclusive:         true,
		Publishable:            true,
		UniqueEndpointTemplate: true,
		ModelVersion:           "model-v7",
	}}
	g.APIAuthzRelations = []detectors.ObjectRelation{{
		ApplicationID: "app-1",
		PrincipalID:   "user-owner",
		ObjectType:    "ORDER",
		ObjectRef:     objectRef,
		Relation:      "OWNER",
		Status:        "CONFIRMED",
	}}

	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "origin-ok")
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/orders/"+rawObjectID, nil)
	req.Header.Set("X-Request-Id", "req-authz-bola-1")
	verified := jwtverify.VerificationResult{
		Status:              jwtverify.StatusVerified,
		VerifiedPrincipalID: "user-other",
		PolicyVersion:       "authz-v3",
	}
	*req = *req.WithContext(context.WithValue(req.Context(), jwtResultKey{}, verified))
	res := httptest.NewRecorder()
	if err := g.serveNext(res, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called {
		t.Fatal("OBSERVE BOLA violation must pass through to origin")
	}
	if res.Code != http.StatusOK || res.Body.String() != "origin-ok" {
		t.Fatalf("unexpected origin response: status=%d body=%q", res.Code, res.Body.String())
	}

	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	decision := recs[0].AuthzDecision
	if decision == nil || decision.Decision != detectors.AuthorizationObserveViolation || len(decision.Checks) != 1 {
		t.Fatalf("unexpected authz decision: %+v", decision)
	}
	check := decision.Checks[0]
	if check.Type != "BOLA" || check.ReasonCode != "AUTHZ-BOLA-001" || check.ObjectRef != objectRef {
		t.Fatalf("unexpected BOLA check: %+v", check)
	}
	if check.ObjectRef == rawObjectID {
		t.Fatal("authz event must not retain the raw object identifier")
	}
	decisionJSON, err := json.Marshal(decision)
	if err != nil {
		t.Fatalf("marshal authz decision: %v", err)
	}
	if strings.Contains(string(decisionJSON), rawObjectID) {
		t.Fatalf("authz decision contains raw object identifier: %s", decisionJSON)
	}
}

// Provider/Guard/网关 PreviousValid 端到端验收：发布器下发的 JSON 经 Guard
// Provision 解码后，当前快照过期时应选用上一份可用快照完成 BOLA 观测。
// 该测试不直接注入 Guard 的内部字段，覆盖发布配置序列化、装配和真实 API 管线。
func TestProvisionedGuard_AuthzPreviousValidFallbackE2E(t *testing.T) {
	currentKey := []byte("01234567890123456789012345678901")
	previousKey := []byte("12345678901234567890123456789012")
	rawObjectID := "order-previous-valid-1"
	previousRef := detectors.ObjectRefHMAC(previousKey, rawObjectID)
	expired := time.Now().UTC().Add(-time.Minute)

	model := func(version string) detectors.ObjectModel {
		return detectors.ObjectModel{
			ApplicationID:          "app-1",
			EndpointKey:            "GET /v1/orders/{id}",
			PathTemplate:           "/v1/orders/{orderId}",
			ObjectType:             "ORDER",
			Identifiers:            []detectors.ObjectIdentifier{{Location: "path", Name: "orderId", Primary: true}},
			RequiredRelation:       "OWNER",
			OwnerExclusive:         true,
			Publishable:            true,
			UniqueEndpointTemplate: true,
			ModelVersion:           version,
		}
	}

	// Marshal/unmarshal 模拟 Provider 生成并交给 Guard 的配置 JSON；当前快照只
	// 作为过期快照存在，PreviousValid 才包含可匹配的已确认关系。
	input := &Guard{
		AppID:                     "app-1",
		EventsLog:                 filepath.Join(t.TempDir(), "events.log"),
		GatewayNode:               "gateway-e2e",
		CounterBackend:            "memory",
		APIDynamicProtection:      true,
		APIProtectionMode:         "OBSERVE",
		APIPolicyVersion:          "current-policy",
		APIAuthzModels:            []detectors.ObjectModel{model("current-model")},
		APIAuthzObjectHMACKeyHex:  hex.EncodeToString(currentKey),
		APIAuthzSnapshotExpiresAt: &expired,
		APIAuthzPreviousValid: &authzSnapshotJSON{
			Models: []detectors.ObjectModel{model("previous-model")},
			Relations: []detectors.ObjectRelation{{
				ApplicationID: "app-1",
				PrincipalID:   "user-owner",
				ObjectType:    "ORDER",
				ObjectRef:     previousRef,
				Relation:      "OWNER",
				Status:        "CONFIRMED",
			}},
			ObjectHMACKeyHex: hex.EncodeToString(previousKey),
			PolicyVersion:    "previous-policy",
		},
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal provider config: %v", err)
	}
	var g Guard
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("unmarshal provider config: %v", err)
	}
	resetSharedEngineForTest()
	t.Cleanup(resetSharedEngineForTest)
	if err := g.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision provider config: %v", err)
	}
	t.Cleanup(func() { _ = g.Cleanup() })
	if g.apiAuthzPreviousValid == nil || !bytes.Equal(g.apiAuthzPreviousValid.ObjectRefHMACKey, previousKey) {
		t.Fatalf("previous valid snapshot was not decoded: %+v", g.apiAuthzPreviousValid)
	}

	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "origin-ok")
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/orders/"+rawObjectID, nil)
	req.Header.Set("X-Request-Id", "req-authz-previous-valid-e2e")
	verified := jwtverify.VerificationResult{
		Status:              jwtverify.StatusVerified,
		VerifiedPrincipalID: "user-owner",
		PolicyVersion:       "current-policy",
	}
	*req = *req.WithContext(context.WithValue(req.Context(), jwtResultKey{}, verified))
	res := httptest.NewRecorder()
	if err := g.serveNext(res, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called || res.Code != http.StatusOK || res.Body.String() != "origin-ok" {
		t.Fatalf("previous-valid OBSERVE request must reach origin: called=%v status=%d body=%q", called, res.Code, res.Body.String())
	}
	recs := readAPIRecords(t, filepath.Join(filepath.Dir(g.EventsLog), "api-runtime-events.log"))
	if len(recs) != 1 || recs[0].AuthzDecision == nil {
		t.Fatalf("want one API event with authz decision, got %+v", recs)
	}
	decision := recs[0].AuthzDecision
	if decision.PolicyVersion != "current-policy" {
		t.Fatalf("decision policy version = %q, want current-policy", decision.PolicyVersion)
	}
	var policyUnknown, bolaAllow bool
	for _, check := range decision.Checks {
		if check.Type == "POLICY" && check.ReasonCode == "AUTHZ-POLICY-002" && check.Decision == detectors.AuthorizationUnknown {
			policyUnknown = true
		}
		if check.Type == "BOLA" && check.ModelVersion == "previous-model" && check.PolicyVersion == "previous-policy" && check.Decision == detectors.AuthorizationAllow && check.ObjectRef == previousRef {
			bolaAllow = true
		}
	}
	if !policyUnknown || !bolaAllow {
		t.Fatalf("fallback checks missing policy_unknown=%v bola_allow=%v: %+v", policyUnknown, bolaAllow, decision.Checks)
	}
}

func TestProvisionAuthzPreviousValidRejectsMissingOrInvalidHMAC(t *testing.T) {
	model := detectors.ObjectModel{
		ApplicationID: "app-1", EndpointKey: "GET /v1/orders/{id}", ObjectType: "ORDER",
		Identifiers:      []detectors.ObjectIdentifier{{Location: "path", Name: "id", Primary: true}},
		RequiredRelation: "OWNER", Publishable: true, UniqueEndpointTemplate: true,
	}
	tests := []struct {
		name string
		key  string
		want string
	}{
		{name: "invalid hex", key: "not-hex", want: "api_authz_previous_valid.object_hmac_key_hex must be 32-byte hex"},
		{name: "missing key", want: "api_authz_previous_valid.object_hmac_key_hex is required when models are configured"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &Guard{
				AppID:                "app-1",
				AppCode:              "shop",
				EventsLog:            filepath.Join(t.TempDir(), "events.log"),
				APIDynamicProtection: true,
				APIAuthzPreviousValid: &authzSnapshotJSON{
					Models:           []detectors.ObjectModel{model},
					ObjectHMACKeyHex: tt.key,
				},
			}
			err := g.Provision(caddy.Context{Context: context.Background()})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Provision error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestProvisionAuthzPreviousValidAnyOfDeepCopy(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	previous := &authzSnapshotJSON{
		Schema: detectors.AuthzSnapshotSchemaV2,
		Models: []detectors.ObjectModel{{
			ApplicationID: "app-1", EndpointKey: "GET /v1/orders/{id}", ObjectType: "ORDER",
			Identifiers:      []detectors.ObjectIdentifier{{Location: "path", Name: "id", Primary: true}},
			RequiredRelation: "ANY_OF", RequiredRelations: []string{"OWNER", "SHARED_WITH"},
			OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true,
		}},
		Relations: []detectors.ObjectRelation{{
			ApplicationID: "app-1", PrincipalID: "user-owner", ObjectType: "ORDER",
			ObjectRef: "objref:previous", Relation: "OWNER", Status: "CONFIRMED",
		}},
		ObjectHMACKeyHex: hex.EncodeToString(key),
	}
	g := &Guard{
		AppID: "app-1", EventsLog: filepath.Join(t.TempDir(), "events.log"), CounterBackend: "memory",
		APIDynamicProtection: true, APIProtectionMode: "OBSERVE", APIAuthzPreviousValid: previous,
	}
	t.Setenv(capDisabledEnv, "1")
	resetSharedEngineForTest()
	t.Cleanup(resetSharedEngineForTest)
	if err := g.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = g.Cleanup() })
	if g.apiAuthzPreviousValid == nil || len(g.apiAuthzPreviousValid.Models) != 1 || len(g.apiAuthzPreviousValid.Relations) != 1 {
		t.Fatalf("previous valid was not restored: %+v", g.apiAuthzPreviousValid)
	}
	restored := g.apiAuthzPreviousValid
	if restored.Schema != detectors.AuthzSnapshotSchemaV2 || restored.Models[0].RequiredRelation != "ANY_OF" ||
		len(restored.Models[0].RequiredRelations) != 2 || restored.Models[0].RequiredRelations[1] != "SHARED_WITH" {
		t.Fatalf("previous valid lost ANY_OF fields: %+v", restored.Models[0])
	}
	previous.Models[0].Identifiers[0].Name = "changed"
	previous.Models[0].RequiredRelations[0] = "CHANGED"
	previous.Relations[0].PrincipalID = "changed"
	if restored.Models[0].Identifiers[0].Name != "id" || restored.Models[0].RequiredRelations[0] != "OWNER" ||
		restored.Relations[0].PrincipalID != "user-owner" {
		t.Fatalf("restored snapshot shares source arrays: %+v", restored)
	}
}

// PROTECT 模式 + 类型偏离：403 拦截且事件落盘。
func TestServeNext_ProtectModeBlocks(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"id": "number"}}
	g, logPath := newAPITestGuard(t, "PROTECT", schemas)

	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-protect-1")
	err := g.serveNext(httptest.NewRecorder(), req, next)
	if err == nil {
		t.Fatal("expect block error")
	}
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 HandlerError, got %v", err)
	}
	if called {
		t.Fatal("next handler must not run when blocked")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 || recs[0].FinalAction != "BLOCK" {
		t.Fatalf("want 1 BLOCK event, got %+v", recs)
	}
}

// 无冻结模型 + 正常请求：放行且不阻断（缺失字段不抬升至 BLOCK）。
func TestServeNext_NoSchemaPassthrough(t *testing.T) {
	g, _ := newAPITestGuard(t, "PROTECT", nil)
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called {
		t.Fatal("next handler not called")
	}
}

// 非 API 的 GET 请求：放行且不产事件（由访问日志/WAF 事件覆盖）。
func TestServeNext_NonAPIGETNoEvent(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if recs := readAPIRecords(t, logPath); len(recs) != 0 {
		t.Fatalf("want no events for plain GET, got %+v", recs)
	}
}

// 生命周期检测：端点不在发布下发的已知基线中 → NEW_ENDPOINT（OBSERVE 放行，事件含明细）。
func TestServeNext_LifecycleNewEndpoint(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.APIKnownEndpoints = map[string]string{"GET /v1/known": "CONFIRMED"}
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/new-thing", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-lifecycle-1")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called {
		t.Fatal("NEW_ENDPOINT is OBSERVE class: next handler must be called")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	found := false
	for _, d := range recs[0].Details {
		if d.RuleID == "lifecycle.new_endpoint" && d.Category == "OBSERVE" && d.Severity == "LOW" {
			found = true
		}
	}
	if !found {
		t.Fatalf("lifecycle.new_endpoint detail missing: %+v", recs[0].Details)
	}
}

// preserveRequestBody：Content-Length 超限不读入内存、跳过管线并说明原因；限内完整可读可还原，
// 体样本与原文一致（webshell C2 请求相位观测样本由此供给）。
func TestPreserveRequestBodyCap(t *testing.T) {
	// 超限 Content-Length：不读 body，返回 nil（跳过管线）并给出原因
	over := httptest.NewRequest(http.MethodPost, "/v1/x", strings.NewReader("payload"))
	over.ContentLength = maxBodyPreserveBytes + 1
	if restore, _, reason := preserveRequestBody(over); restore != nil || reason == "" {
		t.Fatalf("oversized Content-Length must skip preserve with reason, reason=%q", reason)
	}
	// 限内：可读且 restore 可还原，体样本与原文一致
	body := `{"id":1}`
	okReq := httptest.NewRequest(http.MethodPost, "/v1/x", strings.NewReader(body))
	restore, sample, reason := preserveRequestBody(okReq)
	if restore == nil {
		t.Fatalf("in-limit body must be preserved, reason=%q", reason)
	}
	if string(sample) != body {
		t.Fatalf("body sample = %q, want %q", sample, body)
	}
	got, err := io.ReadAll(okReq.Body)
	if err != nil || string(got) != body {
		t.Fatalf("first read = %q err=%v", got, err)
	}
	restore()
	got, err = io.ReadAll(okReq.Body)
	if err != nil || string(got) != body {
		t.Fatalf("restored read = %q err=%v", got, err)
	}
}

// parser 上限（1MiB）与 guard 保全上限（4MiB）之间的报文：不再整体跳过——管线执行且
// parser 截断+采样路径真正生效（BodyTruncated=true），下游仍拿到完整请求体
// （code-review HIGH-7：两处上限同为 1MiB 时该路径为死代码）。
func TestServeNext_BodyBetweenParserAndGuardLimit(t *testing.T) {
	g, _ := newAPITestGuard(t, "PROTECT", nil)
	full := `{"pad":"` + strings.Repeat("x", (1<<20)+(1<<19)) + `"}` // ≈1.5MiB：超 parser 上限、在 guard 上限内
	var gotLen int
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		b, _ := io.ReadAll(r.Body)
		gotLen = len(b)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/big", strings.NewReader(full))
	req.Header.Set("Content-Type", "application/json")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if gotLen != len(full) {
		t.Fatalf("downstream body must stay intact: %d, want %d", gotLen, len(full))
	}
	rc := RequestContextFrom(req)
	if rc == nil {
		t.Fatal("pipeline must run for bodies within guard preserve limit")
	}
	if !rc.BodyTruncated {
		t.Fatal("parser truncation+sampling path must engage for bodies over parser limit")
	}
}

// 超 guard 保全上限的报文：fail-open 放行且下游体完整；跳过必须可见——
// OBSERVE 明细事件落盘（request.body_preserve_skipped），不再零日志零事件
// （code-review HIGH-7）。Content-Length 已知超限与未知长度（chunked）两种路径均覆盖。
func TestServeNext_OversizedBodySkipVisible(t *testing.T) {
	full := strings.Repeat("y", maxBodyPreserveBytes+1)
	run := func(t *testing.T, contentLength int64, wantReason string) {
		g, logPath := newAPITestGuard(t, "PROTECT", nil)
		var gotLen int
		next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			b, _ := io.ReadAll(r.Body)
			gotLen = len(b)
			return nil
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/upload", strings.NewReader(full))
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-Request-Id", "req-big-skip")
		req.ContentLength = contentLength
		if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
			t.Fatalf("serveNext: %v", err)
		}
		if gotLen != len(full) {
			t.Fatalf("downstream must receive full body on skip: %d, want %d", gotLen, len(full))
		}
		recs := readAPIRecords(t, logPath)
		if len(recs) != 1 {
			t.Fatalf("want 1 skip-marker event, got %d: %+v", len(recs), recs)
		}
		rec := recs[0]
		if rec.RequestID != "req-big-skip" || rec.FinalAction != "OBSERVE" || rec.ResponseStatus != 0 {
			t.Fatalf("bad skip event: %+v", rec)
		}
		found := false
		for _, d := range rec.Details {
			if d.RuleID == "request.body_preserve_skipped" && d.Category == "OBSERVE" && d.Severity == "HIGH" {
				found = true
				if d.Evidence["reason"] != wantReason {
					t.Fatalf("skip reason = %q, want %q", d.Evidence["reason"], wantReason)
				}
			}
		}
		if !found {
			t.Fatalf("skip detail missing: %+v", rec.Details)
		}
	}
	t.Run("content-length known", func(t *testing.T) {
		run(t, int64(len(full)), "content_length_exceeds_preserve_limit")
	})
	t.Run("chunked unknown length", func(t *testing.T) {
		run(t, -1, "body_exceeds_preserve_limit")
	})
}

// 事件携带响应状态码与来源/身份指纹：阻断按决策映射 403（阻断时输出）；
// API 放行流量在响应完成后输出，携带真实状态码（空响应归一 200）与 client_ip/raw_path。
// 身份指纹语义（新）：仅凭据派生（auth:/key:/sess: 前缀），匿名请求置空；IP 只属于来源指纹。
func TestServeNext_EventStatusAndFingerprints(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"id": "number"}}
	g, logPath := newAPITestGuard(t, "PROTECT", schemas)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	// 阻断请求：类型偏离 → BLOCK/403
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer token-abc")
	req.RemoteAddr = "203.0.113.7:4321"
	if err := g.serveNext(httptest.NewRecorder(), req, next); err == nil {
		t.Fatal("expect block")
	}
	// 放行请求：符合模型 → ALLOW，状态码未采集置 0（无凭据：匿名）
	req2 := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":1}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.RemoteAddr = "203.0.113.8:4321"
	if err := g.serveNext(httptest.NewRecorder(), req2, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}

	recs := readAPIRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("want 2 api events, got %d: %+v", len(recs), recs)
	}
	blocked, allow := recs[0], recs[1]
	if blocked.FinalAction != "BLOCK" || blocked.ResponseStatus != http.StatusForbidden {
		t.Fatalf("blocked event status: %+v", blocked)
	}
	// 测试 Guard 未配置 identity_salt → 指纹走固定域分隔前缀（salt=""）
	if blocked.SourceFingerprint != detectors.Fingerprint("", "203.0.113.7") {
		t.Fatalf("source fingerprint mismatch: %q", blocked.SourceFingerprint)
	}
	if !strings.HasPrefix(blocked.IdentityFingerprint, "auth:") {
		t.Fatalf("identity fingerprint should be credential-derived (auth:), got %q", blocked.IdentityFingerprint)
	}
	if strings.Contains(blocked.IdentityFingerprint, "token-abc") {
		t.Fatal("identity fingerprint must not contain raw credential")
	}
	if blocked.AuthType != "bearer_or_basic" {
		t.Fatalf("auth_type = %q, want bearer_or_basic", blocked.AuthType)
	}
	if allow.FinalAction != "ALLOW" && allow.FinalAction != "OBSERVE" {
		t.Fatalf("request should pass, got final_action=%q", allow.FinalAction)
	}
	// 事件时机修正：API 流量事件在响应完成后输出，携带真实状态码（下游空响应归一为 200）
	if allow.ResponseStatus != http.StatusOK {
		t.Fatalf("pass-through event should carry real response_status=200: %+v", allow)
	}
	// 新增事件字段：真实客户端 IP 与归一化前路径
	if allow.ClientIP != "203.0.113.8" {
		t.Fatalf("client_ip = %q", allow.ClientIP)
	}
	if allow.RawPath != "/v1/orders" {
		t.Fatalf("raw_path = %q", allow.RawPath)
	}
	if allow.SourceFingerprint != detectors.Fingerprint("", "203.0.113.8") {
		t.Fatalf("source fingerprint mismatch: %q", allow.SourceFingerprint)
	}
	// 匿名事件：身份指纹为空（IP 不得冒充身份），auth_type 为空
	if allow.IdentityFingerprint != "" {
		t.Fatalf("anonymous event must not carry identity fingerprint, got %q", allow.IdentityFingerprint)
	}
	if allow.AuthType != "" {
		t.Fatalf("anonymous event auth_type must be empty, got %q", allow.AuthType)
	}
}

// cookie 会话身份：sess: 指纹进事件且 auth_type=cookie_session；Cookie 明文不出事件。
func TestServeNext_CookieSessionIdentity(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"id": "number"}}
	g, logPath := newAPITestGuard(t, "PROTECT", schemas)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "sid=secret-session-cookie")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err == nil {
		t.Fatal("expect block")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	rec := recs[0]
	if !strings.HasPrefix(rec.IdentityFingerprint, "sess:") {
		t.Fatalf("want sess: identity fingerprint, got %q", rec.IdentityFingerprint)
	}
	if strings.Contains(rec.IdentityFingerprint, "secret-session-cookie") {
		t.Fatal("cookie plaintext must not appear in identity fingerprint")
	}
	if rec.AuthType != "cookie_session" {
		t.Fatalf("auth_type = %q, want cookie_session", rec.AuthType)
	}
}

// 同凭据跨 IP 跳变接线：credential_ip_spread_limit 透传管线，同凭据第二来源 IP 命中 OBSERVE 信号。
func TestServeNext_CredentialIPSpread(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	g.CredentialIPSpreadLimit = 2

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	mk := func(remoteAddr string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":1}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer env-spread-token")
		req.RemoteAddr = remoteAddr
		return req
	}
	// 第一个来源 IP：distinct 1，不报
	if err := g.serveNext(httptest.NewRecorder(), mk("203.0.113.50:1001"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	// 第二个来源 IP：distinct 2 达阈值 → auth.credential_ip_spread（OBSERVE 放行）
	if err := g.serveNext(httptest.NewRecorder(), mk("203.0.113.51:1002"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("want 2 api events, got %d: %+v", len(recs), recs)
	}
	for _, d := range recs[0].Details {
		if d.RuleID == "auth.credential_ip_spread" {
			t.Fatalf("first request below threshold must not match: %+v", recs[0].Details)
		}
	}
	found := false
	for _, d := range recs[1].Details {
		if d.RuleID == "auth.credential_ip_spread" {
			found = true
			if d.Category != "OBSERVE" || d.Severity != "MEDIUM" {
				t.Fatalf("bad spread detail attrs: %+v", d)
			}
			for _, v := range d.Evidence {
				if strings.Contains(v, "203.0.113.") {
					t.Fatalf("ip leaked into evidence: %+v", d.Evidence)
				}
			}
		}
	}
	if !found {
		t.Fatalf("credential_ip_spread detail missing: %+v", recs[1].Details)
	}
	// 事件身份指纹不含凭据明文
	if strings.Contains(recs[1].IdentityFingerprint, "env-spread-token") {
		t.Fatal("identity fingerprint must not contain raw credential")
	}
}

// 同凭据并发度接线：credential_concurrency_limit 透传管线；serveNext 入口并发记账生效
// （手动预占一个 in-flight 名额模拟另一在途请求，第二个同凭据请求命中 OBSERVE 信号）。
func TestServeNext_CredentialConcurrency(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	g.CredentialConcurrencyLimit = 2

	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer env-concurrency-token")
	req.RemoteAddr = "203.0.113.60:1001"
	// 模拟另一在途同凭据请求（serveNext 外已有一个 in-flight）
	_, release := detectors.AcquireCredentialInFlight(detectors.CredentialKey(req, g.IdentitySalt))
	defer release()

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d: %+v", len(recs), recs)
	}
	found := false
	for _, d := range recs[0].Details {
		if d.RuleID == "auth.credential_concurrency" {
			found = true
			if d.Category != "OBSERVE" || d.Severity != "LOW" {
				t.Fatalf("bad concurrency detail attrs: %+v", d)
			}
		}
	}
	if !found {
		t.Fatalf("credential_concurrency detail missing: %+v", recs[0].Details)
	}
	// serveNext 出口已释放自身记账：仅剩手动预占的 1
	if n, rel := detectors.AcquireCredentialInFlight(detectors.CredentialKey(req, g.IdentitySalt)); n != 2 {
		rel()
		t.Fatalf("serveNext must release its in-flight slot, acquired count=%d (want 2 = manual + this probe)", n)
	} else {
		rel()
	}
}

// §8.2 四级识别标签随事件上报：OBSERVE 模式 JSON 写请求经真实管线产出
// CONFIRMED_API；api_confidence 沿用既有 0..1 口径（与 confidence100 同源同分）。
func TestServeNext_APILevelEmitted(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	rec := recs[0]
	if rec.APILevel != "CONFIRMED_API" {
		t.Fatalf("api_level = %q, want CONFIRMED_API: %+v", rec.APILevel, rec)
	}
	if rec.APIConfidence != 0.9 {
		t.Fatalf("api_confidence = %v, want 0.9", rec.APIConfidence)
	}
}

// 管线未写 api.classification（合成结果 / fail-open 旁路）：api_level 省略，不编造。
func TestEmitAPIEvent_APILevelOmittedWithoutExtension(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	syn := httptest.NewRequest(http.MethodGet, "http://waf-test.local/ping", nil)
	syn.RemoteAddr = "203.0.113.10:0"
	res := &pipeline.Result{Context: dsctx.New("req-noext", dsctx.DefaultParseLimits())}
	res.Context.AddMatch(dsctx.DetectorMatch{
		Detector: "waf", RuleID: "waf.downstream_intercept", Category: "BLOCK",
		Severity: "HIGH", ScoreDelta: 50, Message: "synthetic",
	})
	g.emitAPIEvent(syn, res, nil)
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	if recs[0].APILevel != "" {
		t.Fatalf("api_level must stay empty without extension: %+v", recs[0])
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if strings.Contains(string(data), "api_level") {
		t.Fatalf("api_level key must be omitted: %s", data)
	}
}

// C-10 回归：
// 1. >4MiB 请求体不得跳过请求侧元数据检查（准入/BOLA 等）或响应侧 MASK_RESPONSE；
// 2. >1MiB 截断体或 >4MiB 未保全请求体在含体依赖 PROTECT 策略（Schema/ForbiddenField/GraphQL/FAIL_CLOSED）
//    的端点上必须 fail-closed 413/阻断，不得静默放行。
func TestC10OversizedAndTruncatedBodyNoBypass(t *testing.T) {
	t.Run(">4MiB 请求仍执行响应侧 MASK_RESPONSE", func(t *testing.T) {
		g, _ := newAPIResponseTestGuard(t, "PROTECT", []maskRuleJSON{
			{EndpointKey: "POST /v1/users", FieldPath: "phone", Algorithm: "MASK"},
		})
		big := strings.Repeat("a", maxBodyPreserveBytes+32)
		var gotLen int
		next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			b, _ := io.ReadAll(r.Body)
			gotLen = len(b)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"phone":"13800138000"}`)
			return nil
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(big))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		if err := g.serveNext(rec, req, next); err != nil {
			t.Fatalf("serveNext: %v", err)
		}
		if gotLen != len(big) {
			t.Fatalf("下游请求体应保持完整: %d != %d", gotLen, len(big))
		}
		if strings.Contains(rec.Body.String(), "13800138000") {
			t.Fatalf(">4MiB 请求不得绕过响应脱敏: %s", rec.Body.String())
		}
	})

	t.Run(">1MiB 截断体命中 FormalSchema PROTECT 返回 413 阻断", func(t *testing.T) {
		g, _ := newAPITestGuard(t, "PROTECT", nil)
		g.APIFormalSchemas = map[string]map[string]string{
			"POST /v1/orders": {"amount": "number"},
		}
		overParser := `{"pad":"` + strings.Repeat("x", (1<<20)+1024) + `"}`
		called := false
		next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			called = true
			return nil
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(overParser))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		if err := g.serveNext(rec, req, next); err != nil {
			t.Fatalf("serveNext: %v", err)
		}
		if called || rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("Schema PROTECT 截断体必须 413 阻断: called=%v code=%d body=%s", called, rec.Code, rec.Body.String())
		}
	})

	t.Run(">4MiB 请求体命中 FAIL_CLOSED 策略返回 413 阻断", func(t *testing.T) {
		g, _ := newAPITestGuard(t, "PROTECT", nil)
		g.APIResponseFailPolicy = "FAIL_CLOSED"
		big := strings.Repeat("z", maxBodyPreserveBytes+64)
		called := false
		next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			called = true
			return nil
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/items", strings.NewReader(big))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		if err := g.serveNext(rec, req, next); err != nil {
			t.Fatalf("serveNext: %v", err)
		}
		if called || rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("FAIL_CLOSED >4MiB 必须 413 阻断: called=%v code=%d body=%s", called, rec.Code, rec.Body.String())
		}
	})

	t.Run(">1MiB 截断体命中 GraphQL PROTECT 阻断", func(t *testing.T) {
		g, _ := newAPITestGuard(t, "PROTECT", nil)
		g.AppID = "app-gql-c10"
		g.apiGraphQL = map[string]*pipeline.GraphQLPolicy{
			"app-gql-c10": {Enabled: true},
		}
		overParser := `{"query":"` + strings.Repeat("a", (1<<20)+512) + `"}`
		called := false
		next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			called = true
			return nil
		})
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(overParser))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		if err := g.serveNext(rec, req, next); err != nil {
			t.Fatalf("serveNext: %v", err)
		}
		if called || rec.Code != http.StatusForbidden {
			t.Fatalf("GraphQL PROTECT 截断体必须阻断: called=%v code=%d body=%s", called, rec.Code, rec.Body.String())
		}
	})
}
