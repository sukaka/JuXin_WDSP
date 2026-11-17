// apiauthz_az3_e2e_test.go NG-AZ-03 端到端验收（真实 Guard → API 管线 → 事件出口）：
// ① PROTECT 双闸可信违规 403 AUTHZ_VIOLATION_DENIED 统一 JSON + 源站零到达 +
//
//	final_action=BLOCK + final_decision.authz_enforcement 八因子全真；
//
// ② UNKNOWN 不误断（红线：未验证主体在 PROTECT 配置下恒放行）；
// ③ 决策引擎 OBSERVE 形态降级放行 + 拟动作保留。
package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

// az3E2EGuard PROTECT 模式 Guard + enforcement=PROTECT 排他所有权模型 +
// user-owner 已确认 OWNER 关系（请求主体 user-other → OTHER_OWNER）。
func az3E2EGuard(t *testing.T, mode string) (*Guard, string, string) {
	t.Helper()
	key := []byte("01234567890123456789012345678901")
	rawObjectID := "order-78231"
	g, logPath := newAPITestGuard(t, mode, nil)
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
		ModelVersion:           "model-v9",
		Enforcement:            "PROTECT",
		EnforcementOwner:       "zhang.lei@example.com",
		EvidenceSource:         "AUTHORITY_SYNC",
		OnUnknown:              "ALLOW_UNKNOWN",
	}}
	g.APIAuthzRelations = []detectors.ObjectRelation{{
		ApplicationID: "app-1",
		PrincipalID:   "user-owner",
		ObjectType:    "ORDER",
		ObjectRef:     detectors.ObjectRefHMAC(key, rawObjectID),
		Relation:      "OWNER",
		Status:        "CONFIRMED",
	}}
	return g, logPath, rawObjectID
}

func az3Request(t *testing.T, rawObjectID, requestID string, jwt jwtverify.VerificationResult) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/orders/"+rawObjectID, nil)
	req.Header.Set("X-Request-Id", requestID)
	ctx, _ := WithDisposition(req.Context(), "test-node")
	ctx = context.WithValue(ctx, jwtResultKey{}, jwt)
	*req = *req.WithContext(ctx)
	return req
}

// ① PROTECT 实断：403 统一 JSON 精确匹配、源站零到达、事件 BLOCK +
// authz_enforcement 证据随 final_decision 落库。
func TestServeNext_AuthzVerifiedViolationBlocksWithUniformJSON(t *testing.T) {
	g, logPath, rawObjectID := az3E2EGuard(t, "PROTECT")

	originCalls := 0
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		originCalls++
		return nil
	})
	req := az3Request(t, rawObjectID, "req-az3-1", jwtverify.VerificationResult{
		Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-other", PolicyVersion: "authz-v3",
	})
	res := httptest.NewRecorder()
	if err := g.serveNext(res, req, next); err != nil {
		t.Fatalf("authz-denied response is written directly, err must be nil, got %v", err)
	}
	if originCalls != 0 {
		t.Fatalf("可信违规不得到达源站（源站零到达）: calls=%d", originCalls)
	}
	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", res.Code)
	}
	wantBody := `{"code":"AUTHZ_VIOLATION_DENIED","message":"无权访问该对象","request_id":"req-az3-1"}`
	if got := res.Body.String(); got != wantBody {
		t.Fatalf("body = %q, want %q", got, wantBody)
	}
	if ct := res.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}
	if rid := res.Header().Get("X-Jiuzhang-Request-ID"); rid != "req-az3-1" {
		t.Fatalf("X-Jiuzhang-Request-ID = %q", rid)
	}

	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	rec := recs[0]
	if rec.FinalAction != "BLOCK" || rec.ResponseStatus != http.StatusForbidden {
		t.Fatalf("event = %+v", rec)
	}
	var blockDetail bool
	for _, m := range rec.Details {
		if m.Detector == "api_authz" && m.RuleID == "AUTHZ-BOLA-001" && m.Category == "BLOCK" && m.Evidence["enforced"] == "true" {
			blockDetail = true
		}
	}
	if !blockDetail {
		t.Fatalf("event must carry api_authz AUTHZ-BOLA-001 BLOCK detail: %+v", rec.Details)
	}
	if rec.AuthzDecision == nil || rec.AuthzDecision.Decision != detectors.AuthorizationVerifiedViolation {
		t.Fatalf("authz_decision 应为 VERIFIED_VIOLATION: %+v", rec.AuthzDecision)
	}
	// final_decision.authz_enforcement 证据（§1.4 随事件落库）
	var fd map[string]any
	if err := json.Unmarshal(rec.FinalDecision, &fd); err != nil {
		t.Fatalf("final_decision 非 JSON: %v", err)
	}
	az, ok := fd["authz_enforcement"].(map[string]any)
	if !ok {
		t.Fatalf("final_decision 缺 authz_enforcement: %s", rec.FinalDecision)
	}
	if az["decision"] != "VERIFIED_VIOLATION" || az["reason_code"] != "AUTHZ-BOLA-001" || az["enforced"] != true {
		t.Fatalf("证据决策头不符: %v", az)
	}
	if az["endpoint_key"] != "GET /v1/orders/{id}" || az["model_version"] != "model-v9" ||
		az["enforcement_owner"] != "zhang.lei@example.com" || az["evidence_source"] != "AUTHORITY_SYNC" {
		t.Fatalf("证据端点/版本/四要素不符: %v", az)
	}
	elig, ok := az["eligibility"].(map[string]any)
	if !ok || len(elig) != 8 {
		t.Fatalf("eligibility 八因子缺失: %v", az["eligibility"])
	}
	for k, v := range elig {
		if v != true {
			t.Fatalf("eligibility.%s 应为 true: %v", k, elig)
		}
	}
}

// ② UNKNOWN 不误断（红线）：未验证主体在 PROTECT 配置（端点+引擎双 PROTECT）
// 下恒 AUTHZ-IDENTITY-001 UNKNOWN 放行到达源站，绝不实断。
func TestServeNext_AuthzProtectUnknownNeverBlocked(t *testing.T) {
	g, logPath, rawObjectID := az3E2EGuard(t, "PROTECT")

	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "origin-ok")
		return nil
	})
	req := az3Request(t, rawObjectID, "req-az3-2", jwtverify.VerificationResult{
		Status: jwtverify.StatusUnverified, VerifiedPrincipalID: "user-other",
	})
	res := httptest.NewRecorder()
	if err := g.serveNext(res, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called || res.Code != http.StatusOK || res.Body.String() != "origin-ok" {
		t.Fatalf("UNKNOWN 必须放行到达源站（不误断红线）: called=%v status=%d body=%q", called, res.Code, res.Body.String())
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	if recs[0].FinalAction == "BLOCK" {
		t.Fatalf("UNKNOWN 绝不映射 BLOCK: %+v", recs[0])
	}
	if recs[0].AuthzDecision == nil || recs[0].AuthzDecision.Decision != detectors.AuthorizationUnknown {
		t.Fatalf("authz_decision 应为 UNKNOWN: %+v", recs[0].AuthzDecision)
	}
	for _, m := range recs[0].Details {
		if m.Category == "BLOCK" {
			t.Fatalf("UNKNOWN 不得产 BLOCK 明细: %+v", m)
		}
	}
	var fd map[string]any
	if err := json.Unmarshal(recs[0].FinalDecision, &fd); err == nil {
		if _, present := fd["authz_enforcement"]; present {
			t.Fatalf("非实断路径不得挂 authz_enforcement: %s", recs[0].FinalDecision)
		}
	}
}

// ③ 决策引擎 OBSERVE 降级：端点 enforcement=PROTECT 但引擎 OBSERVE 时
// VERIFIED_VIOLATION 降级 OBSERVE_VIOLATION 同语义记录（拟动作保留），放行到达源站。
func TestServeNext_AuthzEngineObserveDowngradesAndPasses(t *testing.T) {
	g, logPath, rawObjectID := az3E2EGuard(t, "OBSERVE")

	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "origin-ok")
		return nil
	})
	req := az3Request(t, rawObjectID, "req-az3-3", jwtverify.VerificationResult{
		Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-other", PolicyVersion: "authz-v3",
	})
	res := httptest.NewRecorder()
	if err := g.serveNext(res, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called || res.Code != http.StatusOK {
		t.Fatalf("OBSERVE 形态必须放行: called=%v status=%d", called, res.Code)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	if recs[0].FinalAction == "BLOCK" {
		t.Fatalf("引擎 OBSERVE 不得实断: %+v", recs[0])
	}
	decision := recs[0].AuthzDecision
	if decision == nil || decision.Decision != detectors.AuthorizationObserveViolation || len(decision.Checks) != 1 {
		t.Fatalf("应降级 OBSERVE_VIOLATION: %+v", decision)
	}
	if decision.Checks[0].ProposedDecision != detectors.AuthorizationVerifiedViolation {
		t.Fatalf("拟动作保留缺失（资格全真+端点 PROTECT）: %+v", decision.Checks[0])
	}
	var fd map[string]any
	if err := json.Unmarshal(recs[0].FinalDecision, &fd); err == nil {
		if _, present := fd["authz_enforcement"]; present {
			t.Fatalf("降级路径不得挂 authz_enforcement: %s", recs[0].FinalDecision)
		}
	}
}

func az4E2EGuard(t *testing.T, mode string) (*Guard, string, string) {
	t.Helper()
	g, logPath, rawObjectID := az3E2EGuard(t, mode)
	g.APIPolicyVersion = "authz-v4"
	g.APIAuthzModels[0].RequiredRelation = "ANY_OF"
	g.APIAuthzModels[0].RequiredRelations = []string{"SHARED_WITH", "OWNER"}
	g.APIAuthzRelations = append(g.APIAuthzRelations, detectors.ObjectRelation{
		ApplicationID: "app-1", PrincipalID: "user-shared", ObjectType: "ORDER",
		ObjectRef: detectors.ObjectRefHMAC(g.APIAuthzObjectHMACKey, rawObjectID),
		Relation:  "SHARED_WITH", Status: "CONFIRMED",
	})
	return g, logPath, rawObjectID
}

func TestServeNext_AuthzAnyOfSharedGuardModes(t *testing.T) {
	cases := []struct {
		name         string
		mode         string
		principal    string
		mutate       func(*Guard)
		wantStatus   int
		wantOrigin   bool
		wantDecision detectors.AuthorizationDecision
		wantReason   string
		wantState    string
	}{
		{name: "PROTECT valid share allows", mode: "PROTECT", principal: "user-shared", wantStatus: http.StatusOK, wantOrigin: true, wantDecision: detectors.AuthorizationAllow, wantState: "EFFECTIVE_SHARED_WITH"},
		{name: "PROTECT missing recipient share blocks other owner", mode: "PROTECT", principal: "user-other", wantStatus: http.StatusForbidden, wantDecision: detectors.AuthorizationVerifiedViolation, wantReason: "AUTHZ-BOLA-001", wantState: "OTHER_OWNER"},
		{name: "OBSERVE missing recipient share passes and records", mode: "OBSERVE", principal: "user-other", wantStatus: http.StatusOK, wantOrigin: true, wantDecision: detectors.AuthorizationObserveViolation, wantReason: "AUTHZ-BOLA-001", wantState: "OTHER_OWNER"},
		{name: "PROTECT share without owner anchor is unknown", mode: "PROTECT", principal: "user-shared", mutate: func(g *Guard) {
			g.APIAuthzRelations = g.APIAuthzRelations[1:]
		}, wantStatus: http.StatusOK, wantOrigin: true, wantDecision: detectors.AuthorizationUnknown, wantReason: "AUTHZ-RELATION-001", wantState: "NONE"},
		{name: "PROTECT malformed any_of is unknown", mode: "PROTECT", principal: "user-shared", mutate: func(g *Guard) {
			g.APIAuthzModels[0].RequiredRelations = []string{"SHARED_WITH"}
		}, wantStatus: http.StatusOK, wantOrigin: true, wantDecision: detectors.AuthorizationUnknown, wantReason: "AUTHZ-POLICY-001"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, logPath, rawObjectID := az4E2EGuard(t, tc.mode)
			if tc.mutate != nil {
				tc.mutate(g)
			}
			originCalls := 0
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				originCalls++
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "origin-ok")
				return nil
			})
			req := az3Request(t, rawObjectID, "req-az4-"+string(rune('1'+i)), jwtverify.VerificationResult{
				Status: jwtverify.StatusVerified, VerifiedPrincipalID: tc.principal, PolicyVersion: "authz-v4",
			})
			res := httptest.NewRecorder()
			if err := g.serveNext(res, req, next); err != nil {
				t.Fatalf("serveNext: %v", err)
			}
			if res.Code != tc.wantStatus || (originCalls > 0) != tc.wantOrigin {
				t.Fatalf("status=%d originCalls=%d, want status=%d origin=%v", res.Code, originCalls, tc.wantStatus, tc.wantOrigin)
			}
			rc := RequestContextFrom(req)
			if rc == nil {
				t.Fatal("missing API request context")
			}
			rawDecision, ok := rc.GetExtension("authz.decision_group")
			decision, ok2 := rawDecision.(*detectors.AuthorizationDecisionGroup)
			if !ok || !ok2 || decision.Decision != tc.wantDecision || len(decision.Checks) != 1 {
				t.Fatalf("decision=%+v, want %s", decision, tc.wantDecision)
			}
			check := decision.Checks[0]
			if check.ReasonCode != tc.wantReason || check.RelationState != tc.wantState {
				t.Fatalf("check=%+v, want reason=%s state=%s", check, tc.wantReason, tc.wantState)
			}
			if tc.wantDecision == detectors.AuthorizationAllow {
				return
			}
			recs := readAPIRecords(t, logPath)
			if len(recs) != 1 || recs[0].AuthzDecision == nil || recs[0].AuthzDecision.Decision != tc.wantDecision {
				t.Fatalf("want one %s authorization event: %+v", tc.wantDecision, recs)
			}
			if tc.wantDecision == detectors.AuthorizationVerifiedViolation {
				if recs[0].FinalAction != "BLOCK" {
					t.Fatalf("verified violation must block in PROTECT: %+v", recs[0])
				}
			} else if recs[0].FinalAction == "BLOCK" {
				t.Fatalf("OBSERVE/UNKNOWN must not block: %+v", recs[0])
			}
		})
	}
}
