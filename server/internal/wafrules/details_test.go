package wafrules

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestAllGatewayRulesHaveChineseDetails(t *testing.T) {
	sources := BuildSyncSources(repoCRSDir)
	templateFiles := map[string]bool{
		"scanner-fingerprints-ext.conf": true,
		"ai-crawler-control.conf":       true,
		"fake-bot-claims.conf":          true,
	}
	forbidden := []string{"阶段8", "任务要求", "TODO", "PayloadsAllTheThings", "BAS "}

	total := 0
	nonTemplateCount := 0

	for _, sd := range sources {
		files, err := filepath.Glob(filepath.Join(sd.Dir, "*.conf"))
		if err != nil {
			t.Fatalf("glob %s: %v", sd.Dir, err)
		}
		for _, f := range files {
			base := filepath.Base(f)
			if strings.HasSuffix(base, ".example") || strings.Contains(base, "EXCLUSION") {
				continue
			}
			rules, failed, err := ParseCRSFile(f, sd.Source)
			if err != nil {
				t.Fatalf("ParseCRSFile(%s): %v", f, err)
			}
			if len(failed) > 0 {
				t.Fatalf("parse failures in %s: %v", base, failed)
			}
			for _, r := range rules {
				total++
				if !templateFiles[base] {
					nonTemplateCount++
					if !HasRuleSpec(r.RuleID) {
						t.Errorf("non-template rule %d (%s/%s) missing from rule_specs_zh.json", r.RuleID, sd.Source, base)
					}
				}
				d := DescribeRule(RuleDescribeInput{
					RuleID:       r.RuleID,
					RuleSource:   r.RuleSource,
					FileName:     r.FileName,
					Name:         r.Name,
					Message:      r.Message,
					Severity:     r.Severity,
					Phase:        r.Phase,
					AttackType:   r.AttackType,
					DefaultState: r.DefaultState,
					CRSVersion:   "4.28.0",
					Tags:         ParseTagsJSON(r.Tags),
				})
				fields := map[string]string{
					"RuleType":         d.RuleType,
					"RuleTypeLabel":    d.RuleTypeLabel,
					"Summary":          d.Summary,
					"DetectionLogic":   d.DetectionLogic,
					"RiskImpact":       d.RiskImpact,
					"TuningAdvice":     d.TuningAdvice,
					"PhaseDescription": d.PhaseDescription,
					"ParanoiaLevel":    d.ParanoiaLevel,
					"ActionBehavior":   d.ActionBehavior,
				}
				for fname, val := range fields {
					if strings.TrimSpace(val) == "" {
						t.Errorf("rule %d (%s/%s) empty %s", r.RuleID, sd.Source, base, fname)
						continue
					}
					if !utf8.ValidString(val) {
						t.Errorf("rule %d (%s/%s) invalid UTF-8 in %s", r.RuleID, sd.Source, base, fname)
					}
					if fname != "RuleType" && !HasCJK(val) {
						t.Errorf("rule %d (%s/%s) %s not Chinese: %q", r.RuleID, sd.Source, base, fname, val)
					}
					for _, bad := range forbidden {
						if strings.Contains(val, bad) {
							t.Errorf("rule %d (%s/%s) %s contains internal token %q: %q", r.RuleID, sd.Source, base, fname, bad, val)
						}
					}
				}
				if len([]rune(d.Summary)) < 20 {
					t.Errorf("rule %d (%s/%s) summary too short (%d runes): %q", r.RuleID, sd.Source, base, len([]rune(d.Summary)), d.Summary)
				}
				if strings.TrimRight(d.Summary, "。") == strings.TrimRight(r.Name, "。") {
					t.Errorf("rule %d (%s/%s) summary merely repeats rule name: %q", r.RuleID, sd.Source, base, d.Summary)
				}
			}
		}
	}

	if total < 3400 {
		t.Fatalf("total rules = %d, want >= 3400", total)
	}
	if LookupRuleSpecCount() != nonTemplateCount {
		t.Errorf("rule_specs_zh.json count = %d, want exact non-template rule count %d", LookupRuleSpecCount(), nonTemplateCount)
	}
	t.Logf("verified detailed Chinese descriptions for all %d rules (%d specs + %d template)", total, nonTemplateCount, total-nonTemplateCount)
}

func TestDescribeRuleRepresentativeCases(t *testing.T) {
	// 1) OWASP CRS 911100 请求方法白名单
	d911100 := DescribeRule(RuleDescribeInput{
		RuleID:     911100,
		RuleSource: SourceCRS,
		FileName:   "REQUEST-911-METHOD-ENFORCEMENT.conf",
		Name:       "请求方法不被策略允许",
		Message:    "请求方法不被策略允许",
		Severity:   "CRITICAL",
		Phase:      1,
		AttackType: "OTHER",
		CRSVersion: "4.28.0",
		Tags:       []string{"paranoia-level/1", "OWASP_CRS", "capec/1000/210/272/220/274"},
	})
	if d911100.RuleType != "DETECTION" || d911100.RuleTypeLabel != "安全检测规则" {
		t.Errorf("911100 rule_type = %s/%s", d911100.RuleType, d911100.RuleTypeLabel)
	}
	if !strings.Contains(d911100.Summary, "HTTP 请求方法") || !strings.Contains(d911100.TuningAdvice, "RESTful API") {
		t.Errorf("911100 summary/tuning unexpected: %+v", d911100)
	}
	if len(d911100.Targets) == 0 || !strings.Contains(d911100.Targets[0], "REQUEST_METHOD") {
		t.Errorf("911100 targets = %v", d911100.Targets)
	}
	if !containsSubstr(d911100.References, "CAPEC-274") {
		t.Errorf("911100 references missing CAPEC-274: %v", d911100.References)
	}

	// 2) OWASP CRS 913011 / 913012 扫描器检测内部规则（阶段 1 vs 阶段 2）
	d913011 := DescribeRule(RuleDescribeInput{
		RuleID:     913011,
		RuleSource: SourceCRS,
		FileName:   "REQUEST-913-SCANNER-DETECTION.conf",
		Name:       "扫描器检测内部规则",
		Severity:   "NOTICE",
		Phase:      1,
		AttackType: "OTHER",
		CRSVersion: "4.28.0",
	})
	d913012 := DescribeRule(RuleDescribeInput{
		RuleID:     913012,
		RuleSource: SourceCRS,
		FileName:   "REQUEST-913-SCANNER-DETECTION.conf",
		Name:       "扫描器检测内部规则",
		Severity:   "NOTICE",
		Phase:      2,
		AttackType: "OTHER",
		CRSVersion: "4.28.0",
	})
	if d913011.RuleType != "INTERNAL" || !strings.Contains(d913011.Summary, "PL1") || !strings.Contains(d913011.Summary, "阶段 1") {
		t.Errorf("913011 detail unexpected: %+v", d913011)
	}
	if d913012.RuleType != "INTERNAL" || !strings.Contains(d913012.Summary, "阶段 2") {
		t.Errorf("913012 detail unexpected: %+v", d913012)
	}
	if d913011.Summary == d913012.Summary {
		t.Errorf("913011 and 913012 should distinguish phase 1 vs phase 2")
	}

	// 3) CUSTOM_PACK 模板规则：AI 爬虫
	dAI := DescribeRule(RuleDescribeInput{
		RuleID:     1010062,
		RuleSource: SourceCustomPack,
		FileName:   "ai-crawler-control.conf",
		Name:       "AI 爬虫 UA：GPTBot",
		Message:    "AI 爬虫 UA：GPTBot",
		Severity:   "WARNING",
		Phase:      1,
		AttackType: "SCANNER_DETECTION",
		Tags:       []string{"attack-scanner", "ai-crawler", "CUSTOM_PACK"},
	})
	if dAI.RuleType != "OBSERVE" || !strings.Contains(dAI.Summary, "GPTBot") || !strings.Contains(dAI.ActionBehavior, "仅观测记录") {
		t.Errorf("1010062 AI crawler detail unexpected: %+v", dAI)
	}

	// 4) CUSTOM_PACK Log4Shell CVE 规则
	dLog4j := DescribeRule(RuleDescribeInput{
		RuleID:     1000001,
		RuleSource: SourceCustomPack,
		FileName:   "cve-emergency.conf",
		Name:       "Log4Shell JNDI 注入攻击（CVE-2021-44228）",
		Severity:   "CRITICAL",
		Phase:      2,
		AttackType: "COMMAND_INJECTION",
		Tags:       []string{"attack-rce", "cve/CVE-2021-44228", "CUSTOM_PACK"},
	})
	if !containsSubstr(dLog4j.References, "CVE-2021-44228") {
		t.Errorf("1000001 missing CVE reference: %v", dLog4j.References)
	}

	// 5) THIRD_PARTY 排除规则
	dWP := DescribeRule(RuleDescribeInput{
		RuleID:     9507100,
		RuleSource: SourceThirdParty,
		FileName:   "wordpress-rule-exclusions-before.conf",
		Name:       "WordPress 排除规则：用户登录与跳转 wp-admin",
		Severity:   "NOTICE",
		Phase:      1,
		AttackType: "EXCLUSION",
	})
	if dWP.RuleType != "EXCLUSION" || !strings.Contains(dWP.Summary, "WordPress") || !strings.Contains(dWP.DetectionLogic, "ctl") && !strings.Contains(dWP.DetectionLogic, "放行") {
		t.Errorf("9507100 exclusion detail unexpected: %+v", dWP)
	}

	// 6) 未知用户自定义规则兜底
	dCustom := DescribeRule(RuleDescribeInput{
		RuleID:     7100001,
		RuleSource: SourceCustom,
		Name:       "拦截恶意管理路径扫描",
		Message:    "拦截恶意管理路径扫描",
		Severity:   "WARNING",
		Phase:      1,
		AttackType: "SCANNER_DETECTION",
	})
	if dCustom.RuleType != "DETECTION" || !HasCJK(dCustom.Summary) || !HasCJK(dCustom.RiskImpact) || !HasCJK(dCustom.TuningAdvice) {
		t.Errorf("7100001 custom fallback unexpected: %+v", dCustom)
	}
}

func containsSubstr(items []string, sub string) bool {
	for _, it := range items {
		if strings.Contains(it, sub) {
			return true
		}
	}
	return false
}

// TestPlanAParsedSpecForBrandNewRules 验证方案 A：热投递新规则（未收录在内置 JSON）
// 在同步解析时自动提取结构化目标/变换/算子与中文注释，免改代码即可生成精准中文详述。
func TestPlanAParsedSpecForBrandNewRules(t *testing.T) {
	hotDropConf := `
# 说明：检测新型零日漏洞 CVE-2026-99999 的特制 X-Api-Version 头与参数命令注入载荷
# 风险：攻击者可利用该接口头注入直接触发服务端远程代码执行
# 调优：仅在灰度演练接口出现误报时针对路径做局部例外，切勿全局停用
SecRule REQUEST_HEADERS:X-Api-Version|ARGS "@rx (?i)\$\{exec:" \
    "id:1099001,\
    phase:2,\
    block,\
    t:none,t:urlDecodeUni,t:lowercase,\
    msg:'ZeroDay X-Api-Version RCE (CVE-2026-99999)',\
    tag:'attack-rce',\
    tag:'cve/CVE-2026-99999',\
    tag:'CUSTOM_PACK',\
    severity:'CRITICAL',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 3" "id:942019,phase:2,pass,nolog,tag:'OWASP_CRS',skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI"
`
	rules, failed, err := ParseCRSRules(hotDropConf, "hot-cve-2026.conf", SourceCustomPack)
	if err != nil {
		t.Fatalf("ParseCRSRules: %v", err)
	}
	if len(failed) > 0 || len(rules) != 2 {
		t.Fatalf("parsed=%d failed=%v", len(rules), failed)
	}

	// 1) 带显式中文标注的新 CVE 规则
	r0 := rules[0]
	d0 := DescribeRule(RuleDescribeInput{
		RuleID:     r0.RuleID,
		RuleSource: r0.RuleSource,
		FileName:   r0.FileName,
		Name:       r0.Name,
		Message:    r0.Message,
		Severity:   r0.Severity,
		Phase:      r0.Phase,
		AttackType: r0.AttackType,
		Tags:       ParseTagsJSON(r0.Tags),
		ParsedSpec: r0.ParsedSpec,
	})
	if d0.Source != "PARSED" || d0.SourceLabel != "规则文件自动解析" || d0.Customized {
		t.Errorf("expected PARSED source, got %s/%s customized=%v", d0.Source, d0.SourceLabel, d0.Customized)
	}
	if !strings.Contains(d0.Summary, "CVE-2026-99999") {
		t.Errorf("summary did not extract Chinese @desc/说明 comment: %q", d0.Summary)
	}
	if !strings.Contains(d0.RiskImpact, "远程代码执行") {
		t.Errorf("risk did not extract Chinese 风险 comment: %q", d0.RiskImpact)
	}
	if !strings.Contains(d0.TuningAdvice, "灰度演练接口") {
		t.Errorf("tuning did not extract Chinese 调优 comment: %q", d0.TuningAdvice)
	}
	if !containsSubstr(d0.Targets, "X-Api-Version") || !containsSubstr(d0.Targets, "ARGS") {
		t.Errorf("targets missing parsed variables: %v", d0.Targets)
	}
	if !strings.Contains(d0.DetectionLogic, "Unicode URL 解码") || !strings.Contains(d0.DetectionLogic, "转小写归一化") {
		t.Errorf("detection_logic missing transforms: %q", d0.DetectionLogic)
	}
	if !containsSubstr(d0.References, "CVE-2026-99999") {
		t.Errorf("references missing CVE: %v", d0.References)
	}

	// 2) 无注释的 CRS 升级新增 PL 跳过控制规则
	r1 := rules[1]
	d1 := DescribeRule(RuleDescribeInput{
		RuleID:     r1.RuleID,
		RuleSource: SourceCRS,
		FileName:   "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
		Name:       r1.Name,
		Severity:   r1.Severity,
		Phase:      r1.Phase,
		AttackType: r1.AttackType,
		Tags:       ParseTagsJSON(r1.Tags),
		ParsedSpec: r1.ParsedSpec,
	})
	if d1.Source != "PARSED" || !strings.Contains(d1.Summary, "PL3") {
		t.Errorf("new CRS skip rule detail unexpected: %+v", d1)
	}

	// 3) JSONB 键序与空白重排后 parsedSpecEqual 保持幂等
	reformatted := json.RawMessage(`{  "op": "@rx", "k": "det", "t": ["REQUEST_HEADERS:X-Api-Version", "ARGS"], "tf": ["urlDecodeUni", "lowercase"], "act": "score_in", "s": "检测新型零日漏洞 CVE-2026-99999 的特制 X-Api-Version 头与参数命令注入载荷。", "r": "攻击者可利用该接口头注入直接触发服务端远程代码执行。", "a": "仅在灰度演练接口出现误报时针对路径做局部例外，切勿全局停用。" }`)
	if !parsedSpecEqual(r0.ParsedSpec, reformatted) {
		t.Errorf("parsedSpecEqual should ignore JSON key ordering/whitespace")
	}
}

// TestPlanBCustomOverridePrecedenceAndValidation 验证方案 B：人工维护覆盖优先级、局部覆盖、校验与接口错误码。
func TestPlanBCustomOverridePrecedenceAndValidation(t *testing.T) {
	now := time.Now().UTC()
	// 1) 对内置规则做局部覆盖（仅修改 tuning_advice，其余字段沿用内置中文精编）
	ov := &RuleDescriptionOverride{
		TuningAdvice:  "本司订单开放接口支持 PUT 更新，已在策略中放行 PUT 方法。",
		UpdatedByName: "sec_admin",
		UpdatedAt:     &now,
	}
	d := DescribeRule(RuleDescribeInput{
		RuleID:         911100,
		RuleSource:     SourceCRS,
		FileName:       "REQUEST-911-METHOD-ENFORCEMENT.conf",
		Name:           "请求方法不被策略允许",
		Severity:       "CRITICAL",
		Phase:          1,
		AttackType:     "OTHER",
		CRSVersion:     "4.28.0",
		Tags:           []string{"paranoia-level/1", "OWASP_CRS"},
		CustomOverride: ov,
	})
	if !d.Customized || d.Source != "CUSTOM" || d.SourceLabel != "人工维护说明" {
		t.Fatalf("expected CUSTOM override metadata, got %+v", d)
	}
	if d.TuningAdvice != ov.TuningAdvice {
		t.Errorf("tuning_advice not overridden: %q", d.TuningAdvice)
	}
	if !strings.Contains(d.Summary, "HTTP 请求方法") {
		t.Errorf("non-overridden summary should inherit builtin, got %q", d.Summary)
	}
	if d.CustomFields == nil || d.CustomFields.UpdatedByName != "sec_admin" || d.CustomFields.Summary != "" {
		t.Errorf("custom_fields mismatch: %+v", d.CustomFields)
	}

	// 2) 对模板型规则同样支持人工覆盖
	dAI := DescribeRule(RuleDescribeInput{
		RuleID:         1010062,
		RuleSource:     SourceCustomPack,
		FileName:       "ai-crawler-control.conf",
		Name:           "AI 爬虫 UA：GPTBot",
		Severity:       "WARNING",
		Phase:          1,
		AttackType:     "SCANNER_DETECTION",
		CustomOverride: &RuleDescriptionOverride{TuningAdvice: "公司内容策略禁止 GPTBot 抓取，已联动 L7 拦截。"},
	})
	if !dAI.Customized || dAI.Source != "CUSTOM" || !strings.Contains(dAI.Summary, "GPTBot") || !strings.Contains(dAI.TuningAdvice, "L7 拦截") {
		t.Errorf("template rule custom override failed: %+v", dAI)
	}

	// 3) 输入校验矩阵
	if err := ValidateDescriptionOverrideInput(&RuleDescriptionOverride{}); err == nil {
		t.Error("empty override should be rejected")
	}
	if err := ValidateDescriptionOverrideInput(&RuleDescriptionOverride{Summary: "   \n\t "}); err == nil {
		t.Error("whitespace-only override should be rejected")
	}
	if err := ValidateDescriptionOverrideInput(&RuleDescriptionOverride{Summary: strings.Repeat("中", 2001)}); err == nil {
		t.Error("overlong field (>2000 runes) should be rejected")
	}
	if err := ValidateDescriptionOverrideInput(&RuleDescriptionOverride{Summary: "含非法空字节\x00内容"}); err == nil {
		t.Error("control char should be rejected")
	}
	valid := &RuleDescriptionOverride{Summary: "  本条规则用于防护内部报表导出接口。\n支持换行。 "}
	if err := ValidateDescriptionOverrideInput(valid); err != nil {
		t.Fatalf("valid override rejected: %v", err)
	}
	if valid.Summary != "本条规则用于防护内部报表导出接口。\n支持换行。" {
		t.Errorf("expected trimmed summary, got %q", valid.Summary)
	}

	// 4) Handler 路径参数与请求体校验
	h := NewHandler(nil, nil, t.TempDir(), "4.28.0")
	reqBadID := httptest.NewRequest(http.MethodPut, "/api/v1/waf-rules/abc/description", strings.NewReader(`{"summary":"x"}`))
	reqBadID.SetPathValue("rule_id", "abc")
	rec := httptest.NewRecorder()
	h.UpdateDescription(rec, reqBadID)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad rule_id status = %d, want 400", rec.Code)
	}

	reqEmpty := httptest.NewRequest(http.MethodPut, "/api/v1/waf-rules/911100/description", strings.NewReader(`{"summary":"   "}`))
	reqEmpty.SetPathValue("rule_id", "911100")
	rec2 := httptest.NewRecorder()
	h.UpdateDescription(rec2, reqEmpty)
	if rec2.Code != http.StatusBadRequest {
		t.Errorf("empty body status = %d, want 400", rec2.Code)
	}

	reqBadReset := httptest.NewRequest(http.MethodDelete, "/api/v1/waf-rules/0/description", nil)
	reqBadReset.SetPathValue("rule_id", "0")
	rec3 := httptest.NewRecorder()
	h.ResetDescription(rec3, reqBadReset)
	if rec3.Code != http.StatusBadRequest {
		t.Errorf("bad reset rule_id status = %d, want 400", rec3.Code)
	}
}

