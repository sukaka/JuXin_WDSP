package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestThreatIntelImportReconcile 威胁情报导入（WDSP P2-C1）集成用例：
// 登录安全管理员 → 文本样本导入（RFC5737 IP）→ 断言 ip_access_rules 出现
// ACTIVE TEMPORARY GLOBAL DENY 且 reason 前缀正确 → 二次导入（一个 IP 消失、
// 一个新 IP）→ 断言消失者 EXPIRED、新者 added、旧的 refreshed。
func TestThreatIntelImportReconcile(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "tisec", "SECURITY_ADMIN")
	ctx := context.Background()

	// 首次导入：文本样本（含注释行与坏行，验证坏行计数不阻断）
	body1 := `{"format":"text","ttl_days":30,"feed":"feodo","content":` +
		fmt.Sprintf("%q", "# 测试样本\n192.0.2.10\n198.51.100.20\nnot-an-ip\n") + `}`
	resp := env.post(t, "/api/v1/threat-intel/import", body1, cookies, csrf)
	res1 := s5OK(t, resp, "threat intel import #1")
	batch1, _ := res1.Data["batch_id"].(string)
	if batch1 == "" {
		t.Fatalf("batch_id missing: %+v", res1.Data)
	}
	if got := s5Num(t, res1.Data, "added"); got != 2 {
		t.Fatalf("added=%v, want 2: %+v", got, res1.Data)
	}
	if got := s5Num(t, res1.Data, "invalid"); got != 1 {
		t.Fatalf("invalid=%v, want 1 (not-an-ip): %+v", got, res1.Data)
	}

	// DB 断言：ACTIVE TEMPORARY GLOBAL DENY，reason 前缀「威胁情报 feodo 批次<batch1>」
	assertRule := func(address, wantStatus, wantValidity, batch string) {
		t.Helper()
		var status, validity, reason, sourceType, scopeType string
		var until *time.Time
		err := env.db.QueryRow(ctx, `
SELECT status, validity_type, reason, source_type, scope_type, effective_until
FROM ip_access_rules
WHERE deleted_at IS NULL AND address = $1 AND rule_type = 'DENY' AND scope_type = 'GLOBAL'`,
			address).Scan(&status, &validity, &reason, &sourceType, &scopeType, &until)
		if err != nil {
			t.Fatalf("rule %s query: %v", address, err)
		}
		if status != wantStatus {
			t.Errorf("rule %s status=%s, want %s", address, status, wantStatus)
		}
		if validity != wantValidity {
			t.Errorf("rule %s validity=%s, want %s", address, validity, wantValidity)
		}
		if sourceType != "IMPORT" {
			t.Errorf("rule %s source_type=%s, want IMPORT", address, sourceType)
		}
		if !strings.HasPrefix(reason, "威胁情报 feodo 批次"+batch) {
			t.Errorf("rule %s reason=%q, want prefix 威胁情报 feodo 批次%s", address, reason, batch)
		}
		if wantValidity == "TEMPORARY" && (until == nil || until.Before(time.Now().Add(29*24*time.Hour))) {
			t.Errorf("rule %s effective_until out of ~30d window: %v", address, until)
		}
	}
	assertRule("192.0.2.10", "ACTIVE", "TEMPORARY", batch1)
	assertRule("198.51.100.20", "ACTIVE", "TEMPORARY", batch1)

	// 二次导入：.10 仍在册、198.51.100.20 消失、203.0.113.30 新增
	body2 := `{"format":"text","ttl_days":30,"feed":"feodo","content":"192.0.2.10\n203.0.113.30\n"}`
	resp = env.post(t, "/api/v1/threat-intel/import", body2, cookies, csrf)
	res2 := s5OK(t, resp, "threat intel import #2")
	if got := s5Num(t, res2.Data, "added"); got != 1 {
		t.Errorf("import#2 added=%v, want 1", got)
	}
	if got := s5Num(t, res2.Data, "refreshed"); got != 1 {
		t.Errorf("import#2 refreshed=%v, want 1", got)
	}
	if got := s5Num(t, res2.Data, "expired"); got != 1 {
		t.Errorf("import#2 expired=%v, want 1", got)
	}
	batch2, _ := res2.Data["batch_id"].(string)
	if batch2 == "" || batch2 == batch1 {
		t.Fatalf("batch2 should be a fresh id: %q vs %q", batch2, batch1)
	}
	assertRule("192.0.2.10", "ACTIVE", "TEMPORARY", batch2)     // refreshed（reason 记最近批次）
	assertRule("203.0.113.30", "ACTIVE", "TEMPORARY", batch2)   // added
	assertRule("198.51.100.20", "EXPIRED", "TEMPORARY", batch1) // 消失者 EXPIRED 保留历史
}

// TestThreatIntelImportCSV 与冲突/权限/参数校验边界。
func TestThreatIntelImportCSVAndGuards(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "tisec", "SECURITY_ADMIN")
	ctx := context.Background()

	// CSV 导入（Feodo 真实表头形态），family 列写入 reason
	csvContent := "# Feodo sample\n" +
		"\"first_seen_utc\",\"dst_ip\",\"dst_port\",\"c2_status\",\"last_online\",\"malware\"\n" +
		"\"2026-01-01 00:00:00\",\"192.0.2.44\",\"443\",\"online\",\"2026-10-01\",\"Emotet\"\n"
	resp := env.post(t, "/api/v1/threat-intel/import",
		fmt.Sprintf(`{"format":"csv","ttl_days":7,"content":%q}`, csvContent), cookies, csrf)
	res := s5OK(t, resp, "threat intel csv import")
	if got := s5Num(t, res.Data, "added"); got != 1 {
		t.Fatalf("csv added=%v, want 1: %+v", got, res.Data)
	}
	var reason string
	if err := env.db.QueryRow(ctx,
		`SELECT reason FROM ip_access_rules WHERE deleted_at IS NULL AND address = '192.0.2.44'`).
		Scan(&reason); err != nil {
		t.Fatalf("query csv rule: %v", err)
	}
	if !strings.Contains(reason, "（Emotet）") {
		t.Errorf("csv family not in reason: %q", reason)
	}

	// 冲突：同址已存在 MANUAL GLOBAL DENY ACTIVE → skipped_conflict，manual 行不被触碰
	resp = env.post(t, "/api/v1/access-rules",
		`{"name":"manual-ti-conflict","rule_type":"DENY","scope_type":"GLOBAL","address":"192.0.2.66","validity_type":"PERMANENT","reason":"人工封禁"}`,
		cookies, csrf)
	s5OK(t, resp, "create manual deny")
	resp = env.post(t, "/api/v1/threat-intel/import",
		`{"format":"text","content":"192.0.2.66\n192.0.2.44\n"}`, cookies, csrf)
	res = s5OK(t, resp, "threat intel import with manual conflict")
	if got := s5Num(t, res.Data, "skipped_conflict"); got != 1 {
		t.Errorf("skipped_conflict=%v, want 1: %+v", got, res.Data)
	}
	var manualReason string
	if err := env.db.QueryRow(ctx,
		`SELECT reason FROM ip_access_rules WHERE deleted_at IS NULL AND address = '192.0.2.66'`).
		Scan(&manualReason); err != nil {
		t.Fatalf("query manual rule: %v", err)
	}
	if manualReason != "人工封禁" {
		t.Errorf("manual rule touched: %q", manualReason)
	}

	// 参数校验：空内容 / 非法格式 / 非法 feed / 负 TTL → 400
	for _, tc := range []struct{ name, body string }{
		{"empty content", `{"format":"text","content":""}`},
		{"bad format", `{"format":"xml","content":"192.0.2.1"}`},
		{"bad feed", `{"format":"text","content":"192.0.2.1","feed":"bad feed!"}`},
		{"negative ttl", `{"format":"text","content":"192.0.2.1","ttl_days":-1}`},
		{"csv missing ip column", fmt.Sprintf(`{"format":"csv","content":%q}`, "foo,bar\n1,2\n")},
	} {
		resp := env.post(t, "/api/v1/threat-intel/import", tc.body, cookies, csrf)
		s5Expect(t, resp, http.StatusBadRequest, "validate "+tc.name)
	}

	// 权限：审计管理员（无 access_rules.import）→ 403
	auditCookies, auditCSRF := env.s5Login(t, "tiaudit", "AUDIT_ADMIN")
	resp = env.post(t, "/api/v1/threat-intel/import",
		`{"format":"text","content":"192.0.2.1"}`, auditCookies, auditCSRF)
	s5Expect(t, resp, http.StatusForbidden, "AUDIT_ADMIN import denied")

	// 认证与 CSRF：匿名 POST 先被 CSRF 前置拦截（403，与既有认证链顺序一致）；有会话缺 CSRF → 403
	resp = env.post(t, "/api/v1/threat-intel/import", `{"format":"text","content":"192.0.2.1"}`, nil, "")
	s5Expect(t, resp, http.StatusForbidden, "anonymous import denied")
	resp = env.post(t, "/api/v1/threat-intel/import", `{"format":"text","content":"192.0.2.1"}`, cookies, "")
	s5Expect(t, resp, http.StatusForbidden, "missing CSRF denied")

	// 审计落库：threat_intel_import 动作有成功记录（本用例成功导入 2 次）
	var auditCount int
	if err := env.db.QueryRow(ctx,
		`SELECT count(*) FROM operation_audits WHERE module='access_control' AND action='threat_intel_import' AND result='SUCCESS'`).
		Scan(&auditCount); err != nil {
		t.Fatalf("query audits: %v", err)
	}
	if auditCount < 2 {
		t.Errorf("operation_audits threat_intel_import SUCCESS count=%d, want >=2", auditCount)
	}
}
