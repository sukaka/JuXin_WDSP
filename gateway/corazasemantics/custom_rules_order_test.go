package corazasemantics

import (
	"strconv"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// customOrderDirectives 按 buildWAFDirectivesWithPolicy 的新加载顺序构造真实 Coraza 指令栈：
// coraza.conf → crs-setup → before-crs → ruleOverrides → customRules → crs/rules/*.conf → contrib → post-contrib-blocking.conf。
func customOrderDirectives(ruleOverrides, customRules string) string {
	return crsDirectives(ruleOverrides + customRules)
}

// legacyCustomAfterCRSDirectives 复现旧顺序（管理面自定义规则置于 CRS 之后），仅用作对照组证明
// 本测试所用的 SQLi 载荷在 CRS 中得分 >= 5，旧顺序下会被 CRS 949110 抢占而轮不到 phase:2 自定义规则。
func legacyCustomAfterCRSDirectives(customRules string) string {
	return `SecRuleEngine On
Include ../rules/coraza.conf
SecAuditEngine RelevantOnly
SecAuditLogParts ABIJDEFHZ
SecAuditLog /tmp/coraza-semantics-audit.log
SecAction "id:900001,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=1,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"
Include ../rules/crs/crs-setup.conf
Include ../rules/crs/plugins/*/plugins/*-config.conf
Include ../rules/crs/plugins/*/plugins/*-before.conf
Include ../rules/exclusions/before-crs.conf
Include ../rules/crs/rules/*.conf
Include ../rules/contrib/*/*.conf
Include ../rules/crs/plugins/*/plugins/*-after.conf
Include ../rules/exclusions/after-crs.conf
Include ../rules/jiuzhang/jiuzhang-custom.conf
` + customRules + `Include ../rules/jiuzhang/post-contrib-blocking.conf
`
}

type customTxResult struct {
	interruption *types.Interruption
	matchedIDs   []int
}

func runCustomOrderTx(t *testing.T, waf coraza.WAF, method, uri, contentType, body string) customTxResult {
	t.Helper()
	tx := waf.NewTransaction()
	defer tx.ProcessLogging()
	tx.ProcessConnection("192.0.2.88", 52345, "10.10.0.1", 8080)
	tx.ProcessURI(uri, method, "HTTP/1.1")
	tx.AddRequestHeader("Host", "custom-order.local")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
	tx.SetServerName("custom-order.local")
	if contentType != "" {
		tx.AddRequestHeader("Content-Type", contentType)
	}
	if body != "" {
		tx.AddRequestHeader("Content-Length", strconv.Itoa(len(body)))
	}

	var it *types.Interruption
	it = tx.ProcessRequestHeaders()
	if it == nil && body != "" {
		if writeIt, _, err := tx.WriteRequestBody([]byte(body)); err != nil {
			t.Fatalf("WriteRequestBody: %v", err)
		} else if writeIt != nil {
			it = writeIt
		}
	}
	if it == nil {
		bodyIt, err := tx.ProcessRequestBody()
		if err != nil {
			t.Fatalf("ProcessRequestBody: %v", err)
		}
		it = bodyIt
	}

	var matched []int
	for _, mr := range tx.MatchedRules() {
		matched = append(matched, mr.Rule().ID())
	}
	return customTxResult{interruption: it, matchedIDs: matched}
}

func containsRuleID(ids []int, target int) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}

// TestCustomRulesLoadedBeforeCRS 真实 Coraza v3.7.0 + OWASP CRS 完整规则栈语义验证：
//  1. phase:2 自定义 BLOCK 规则（REQUEST_BODY / ARGS_POST）置于 CRS 之前时，
//     含高分 SQLi 载荷的 POST（application/x-www-form-urlencoded 与 application/json）
//     必须由自定义规则 ID 直接 403 阻断，不被 CRS 949110 抢占；
//  2. phase:1 自定义 BLOCK 规则（REQUEST_URI）在请求头阶段立即 403 阻断，优先于 CRS；
//  3. 置于自定义规则之前的 ruleOverride（ctl:ruleRemoveById=<customRuleID>）仍可精准摘除该自定义规则。
func TestCustomRulesLoadedBeforeCRS(t *testing.T) {
	const (
		customPhase2BodyRuleID      = 7100101
		customPhase2ArgsPostRuleID  = 7100102
		customPhase1URIRuleID       = 7100103
		customPhase2CombinedRuleID  = 7100106
		customPhase2ArgsRuleID      = 7100107
		crsBlockingRuleID           = 949110
	)

	// 典型 SQLi 载荷：在真实 OWASP CRS (PL1, threshold=5) 下会命中多条 CRITICAL SQLi 规则（总分 >= 5）。
	const (
		formBody = "comment=1 UNION SELECT username,password FROM users--"
		jsonBody = `{"comment":"1 UNION SELECT username,password FROM users--"}`
	)

	customPhase2BodyRule := `SecRule REQUEST_BODY "@rx (?i)union\s+select" "id:7100101,phase:2,deny,status:403,log,msg:'custom body sqli block',severity:'CRITICAL',tag:'jiuzhang-custom',tag:'SQL_INJECTION'"` + "\n"
	customPhase2ArgsPostRule := `SecRule ARGS_POST "@rx (?i)union\s+select" "id:7100102,phase:2,deny,status:403,log,msg:'custom args_post sqli block',severity:'CRITICAL',tag:'jiuzhang-custom',tag:'SQL_INJECTION'"` + "\n"
	customPhase1URIRule := `SecRule REQUEST_URI "@rx (?i)union(?:\s|%20)+select" "id:7100103,phase:1,deny,status:403,log,msg:'custom uri sqli block',severity:'CRITICAL',tag:'jiuzhang-custom',tag:'SQL_INJECTION'"` + "\n"
	customPhase2CombinedRule := `SecRule REQUEST_BODY|ARGS_POST "@rx (?i)union\s+select" "id:7100106,phase:2,deny,status:403,log,msg:'custom body_or_args_post sqli block',severity:'CRITICAL',tag:'jiuzhang-custom',tag:'SQL_INJECTION'"` + "\n"
	customPhase2ArgsRule := `SecRule ARGS "@rx (?i)union\s+select" "id:7100107,phase:2,deny,status:403,log,msg:'custom args sqli block',severity:'CRITICAL',tag:'jiuzhang-custom',tag:'SQL_INJECTION'"` + "\n"

	// 对照前提：确认上述 form 与 JSON SQLi 载荷在旧顺序下确实会被 CRS 949110 抢占（得分 >= 5）。
	t.Run("control_legacy_after_crs_preempted_by_949110", func(t *testing.T) {
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(legacyCustomAfterCRSDirectives(customPhase2ArgsPostRule)))
		if err != nil {
			t.Fatalf("build legacy waf: %v", err)
		}
		for _, tc := range []struct {
			name string
			ct   string
			body string
		}{
			{"form-urlencoded", "application/x-www-form-urlencoded", formBody},
			{"json", "application/json", jsonBody},
		} {
			res := runCustomOrderTx(t, waf, "POST", "/api/orders", tc.ct, tc.body)
			if res.interruption == nil || res.interruption.Status != 403 {
				t.Fatalf("%s: expected 403 interruption, got %+v", tc.name, res.interruption)
			}
			if res.interruption.RuleID != crsBlockingRuleID {
				t.Fatalf("%s: control group expected CRS 949110 preemption, got rule %d (matched=%v)",
					tc.name, res.interruption.RuleID, res.matchedIDs)
			}
		}
	})

	// (a) phase:2 自定义 BLOCK 规则置于 CRS 之前：form-urlencoded 与 JSON POST 均由自定义规则直接 403 阻断，不被 949110 抢占。
	// 注：Coraza v3.7.0 中 urlencoded 解析器同时填充 REQUEST_BODY 与 ARGS_POST/ARGS；
	// JSON 解析器（coraza.conf 200001）填充 ARGS_POST/ARGS（flattened json.<key>）而非 REQUEST_BODY，
	// 因此下方分别验证 REQUEST_BODY（form）、ARGS_POST（form+JSON）、REQUEST_BODY|ARGS_POST（form+JSON）与 ARGS（form+JSON）。
	t.Run("phase2_custom_block_before_crs_wins_over_949110", func(t *testing.T) {
		assertCustomBlocks := func(t *testing.T, directives string, wantRuleID int, ct, body string) {
			t.Helper()
			waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
			if err != nil {
				t.Fatalf("build waf: %v", err)
			}
			res := runCustomOrderTx(t, waf, "POST", "/api/orders", ct, body)
			if res.interruption == nil || res.interruption.Status != 403 {
				t.Fatalf("expected 403 interruption, got %+v (matched=%v)", res.interruption, res.matchedIDs)
			}
			if res.interruption.RuleID != wantRuleID {
				t.Fatalf("expected interruption by custom rule %d, got %d (matched=%v)",
					wantRuleID, res.interruption.RuleID, res.matchedIDs)
			}
			if containsRuleID(res.matchedIDs, crsBlockingRuleID) {
				t.Errorf("CRS 949110 must not fire when custom rule already blocked (matched=%v)", res.matchedIDs)
			}
		}

		t.Run("REQUEST_BODY_form-urlencoded", func(t *testing.T) {
			assertCustomBlocks(t, customOrderDirectives("", customPhase2BodyRule), customPhase2BodyRuleID, "application/x-www-form-urlencoded", formBody)
		})
		t.Run("ARGS_POST_form-urlencoded", func(t *testing.T) {
			assertCustomBlocks(t, customOrderDirectives("", customPhase2ArgsPostRule), customPhase2ArgsPostRuleID, "application/x-www-form-urlencoded", formBody)
		})
		t.Run("ARGS_POST_json", func(t *testing.T) {
			assertCustomBlocks(t, customOrderDirectives("", customPhase2ArgsPostRule), customPhase2ArgsPostRuleID, "application/json", jsonBody)
		})
		t.Run("REQUEST_BODY_or_ARGS_POST_form-urlencoded", func(t *testing.T) {
			assertCustomBlocks(t, customOrderDirectives("", customPhase2CombinedRule), customPhase2CombinedRuleID, "application/x-www-form-urlencoded", formBody)
		})
		t.Run("REQUEST_BODY_or_ARGS_POST_json", func(t *testing.T) {
			assertCustomBlocks(t, customOrderDirectives("", customPhase2CombinedRule), customPhase2CombinedRuleID, "application/json", jsonBody)
		})
		t.Run("ARGS_form-urlencoded", func(t *testing.T) {
			assertCustomBlocks(t, customOrderDirectives("", customPhase2ArgsRule), customPhase2ArgsRuleID, "application/x-www-form-urlencoded", formBody)
		})
		t.Run("ARGS_json", func(t *testing.T) {
			assertCustomBlocks(t, customOrderDirectives("", customPhase2ArgsRule), customPhase2ArgsRuleID, "application/json", jsonBody)
		})
	})

	// (b) phase:1 自定义 BLOCK 规则（REQUEST_URI）在请求头阶段立即 403 阻断，早于 CRS。
	t.Run("phase1_custom_block_on_request_uri_before_crs", func(t *testing.T) {
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(customOrderDirectives("", customPhase1URIRule)))
		if err != nil {
			t.Fatalf("build waf (phase 1): %v", err)
		}
		res := runCustomOrderTx(t, waf, "GET", "/search?q=1%20UNION%20SELECT%201,2--", "", "")
		if res.interruption == nil || res.interruption.Status != 403 {
			t.Fatalf("expected 403 interruption, got %+v", res.interruption)
		}
		if res.interruption.RuleID != customPhase1URIRuleID {
			t.Fatalf("expected interruption by custom phase:1 rule %d, got %d (matched=%v)",
				customPhase1URIRuleID, res.interruption.RuleID, res.matchedIDs)
		}
		if containsRuleID(res.matchedIDs, crsBlockingRuleID) {
			t.Errorf("CRS 949110 must not fire when phase:1 custom rule already blocked (matched=%v)", res.matchedIDs)
		}
	})

	// (c) ruleOverride（ctl:ruleRemoveById=<customRuleID>）置于 customRules 之前时，仍可禁用该自定义规则。
	t.Run("rule_override_before_custom_rules_disables_custom_rule", func(t *testing.T) {
		// 使用仅命中自定义规则、不触发 CRS 的业务关键词，以精确证明 custom rule 确实被摘除且请求放行；
		// 同时对 phase:1 自定义规则也验证 ruleOverride 生效。
		customKeywordPhase2 := `SecRule ARGS_POST|REQUEST_BODY "@contains jz-custom-canary" "id:7100104,phase:2,deny,status:403,log,msg:'custom keyword phase2',tag:'jiuzhang-custom'"` + "\n"
		customKeywordPhase1 := `SecRule REQUEST_URI "@contains /jz-custom-canary" "id:7100105,phase:1,deny,status:403,log,msg:'custom keyword phase1',tag:'jiuzhang-custom'"` + "\n"

		overridePhase2 := `SecRule REQUEST_URI "@rx .*" "id:7200001,phase:1,pass,nolog,ctl:ruleRemoveById=7100104,tag:'jiuzhang-rule-override'"` + "\n"
		overridePhase1 := `SecRule REQUEST_URI "@rx .*" "id:7200002,phase:1,pass,nolog,ctl:ruleRemoveById=7100105,tag:'jiuzhang-rule-override'"` + "\n"

		// 无 override 时：两条自定义规则分别阻断
		wafNoOverride, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(
			customOrderDirectives("", customKeywordPhase2+customKeywordPhase1),
		))
		if err != nil {
			t.Fatalf("build waf without override: %v", err)
		}
		r1 := runCustomOrderTx(t, wafNoOverride, "POST", "/api/items", "application/x-www-form-urlencoded", "note=jz-custom-canary")
		if r1.interruption == nil || r1.interruption.RuleID != 7100104 {
			t.Fatalf("without override phase2 rule should block with 7100104, got %+v", r1.interruption)
		}
		r2 := runCustomOrderTx(t, wafNoOverride, "GET", "/jz-custom-canary", "", "")
		if r2.interruption == nil || r2.interruption.RuleID != 7100105 {
			t.Fatalf("without override phase1 rule should block with 7100105, got %+v", r2.interruption)
		}

		// 有 override（置于 customRules 之前）时：两条自定义规则均被禁用、请求放行
		wafWithOverride, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(
			customOrderDirectives(overridePhase2+overridePhase1, customKeywordPhase2+customKeywordPhase1),
		))
		if err != nil {
			t.Fatalf("build waf with override: %v", err)
		}
		r3 := runCustomOrderTx(t, wafWithOverride, "POST", "/api/items", "application/x-www-form-urlencoded", "note=jz-custom-canary")
		if r3.interruption != nil || containsRuleID(r3.matchedIDs, 7100104) {
			t.Fatalf("ruleOverride must disable phase2 custom rule 7100104: interruption=%+v matched=%v", r3.interruption, r3.matchedIDs)
		}
		r4 := runCustomOrderTx(t, wafWithOverride, "GET", "/jz-custom-canary", "", "")
		if r4.interruption != nil || containsRuleID(r4.matchedIDs, 7100105) {
			t.Fatalf("ruleOverride must disable phase1 custom rule 7100105: interruption=%+v matched=%v", r4.interruption, r4.matchedIDs)
		}

		// 并且当 SQLi 载荷命中且 custom rule 被 ruleOverride 禁用后，CRS 949110 仍接管防护（不破坏 CRS）
		overrideSQLi := `SecRule REQUEST_URI "@rx .*" "id:7200003,phase:1,pass,nolog,ctl:ruleRemoveById=7100102,tag:'jiuzhang-rule-override'"` + "\n"
		wafFallbackCRS, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(
			customOrderDirectives(overrideSQLi, customPhase2ArgsPostRule),
		))
		if err != nil {
			t.Fatalf("build waf fallback CRS: %v", err)
		}
		r5 := runCustomOrderTx(t, wafFallbackCRS, "POST", "/api/orders", "application/x-www-form-urlencoded", formBody)
		if r5.interruption == nil || r5.interruption.RuleID != crsBlockingRuleID {
			t.Fatalf("when custom rule 7100102 is disabled by ruleOverride, CRS 949110 must still block SQLi: interruption=%+v matched=%v",
				r5.interruption, r5.matchedIDs)
		}
		if containsRuleID(r5.matchedIDs, customPhase2ArgsPostRuleID) {
			t.Errorf("disabled custom rule 7100102 must not match (matched=%v)", r5.matchedIDs)
		}
	})
}
