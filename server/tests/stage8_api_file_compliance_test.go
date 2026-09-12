// stage8_api_file_compliance_test.go API 文件合规规则 + 文件签名（W13-FSIG-COMP / P2-03 管理面 /
// P2-02 验证面）集成测试。
// 覆盖：迁移 000071 表结构/CHECK/去重键/种子与 000081 webshell 脚本后缀种子追加；
// ComplianceStore SQL CRUD 与冲突映射；
// HTTP 接线（权限矩阵/校验/CRUD/审计落库）；签名密钥轮换（密文落库/kid 递增）、
// 验证 503/正反/过期语义与操作审计（摘要不含 token 与密钥材料）。
package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/apifiles"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/encryption"
	"github.com/jiuzhang-waf/server/internal/settings"
)

// fcEncryptor 集成测试用真实加密服务（固定测试主密钥，与生产同算法）。
func fcEncryptor(t *testing.T) *encryption.Service {
	t.Helper()
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(0xA0 + i)
	}
	enc, err := encryption.NewWithKey(master)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// TestStage8FileComplianceMigration 迁移 000071 落位：表结构 / CHECK / 去重键 / 种子
// （含 000081 webshell 可执行脚本后缀上传阻断追加种子）。
func TestStage8FileComplianceMigration(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	if n := s8Count(t, env, `SELECT count(*) FROM information_schema.tables WHERE table_name='api_file_compliance_rules'`); n != 1 {
		t.Fatalf("api_file_compliance_rules missing")
	}
	for _, col := range []string{"id", "direction", "match_type", "match_value", "action",
		"reason", "enabled", "created_by", "created_at", "updated_at"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
			WHERE table_name='api_file_compliance_rules' AND column_name=$1`, col); n != 1 {
			t.Fatalf("api_file_compliance_rules column %s missing", col)
		}
	}
	// CHECK：非法 direction/match_type/action 拒绝
	for _, stmt := range []string{
		`INSERT INTO api_file_compliance_rules (direction, match_type, match_value, action) VALUES ('SIDEWAYS','EXT','exe','BLOCK')`,
		`INSERT INTO api_file_compliance_rules (direction, match_type, match_value, action) VALUES ('UPLOAD','SIZE','exe','BLOCK')`,
		`INSERT INTO api_file_compliance_rules (direction, match_type, match_value, action) VALUES ('UPLOAD','EXT','exe','DENY')`,
	} {
		if _, err := env.db.Exec(ctx, stmt); err == nil {
			t.Fatalf("bad row unexpectedly accepted: %s", stmt)
		}
	}
	// 初始建议种子：18 条（000071 UPLOAD exe/bat/sh BLOCK + DOWNLOAD sql/bak OBSERVE；
	// 000081 UPLOAD webshell 可执行脚本后缀 13 条 BLOCK），默认启用
	if n := s8Count(t, env, `SELECT count(*) FROM api_file_compliance_rules`); n != 18 {
		t.Fatalf("seed rules = %d, want 18", n)
	}
	for _, want := range [][4]string{
		{"UPLOAD", "EXT", "exe", "BLOCK"},
		{"UPLOAD", "EXT", "bat", "BLOCK"},
		{"UPLOAD", "EXT", "sh", "BLOCK"},
		{"DOWNLOAD", "EXT", "sql", "OBSERVE"},
		{"DOWNLOAD", "EXT", "bak", "OBSERVE"},
		{"UPLOAD", "EXT", "jsp", "BLOCK"},
		{"UPLOAD", "EXT", "jspx", "BLOCK"},
		{"UPLOAD", "EXT", "asp", "BLOCK"},
		{"UPLOAD", "EXT", "aspx", "BLOCK"},
		{"UPLOAD", "EXT", "ashx", "BLOCK"},
		{"UPLOAD", "EXT", "asmx", "BLOCK"},
		{"UPLOAD", "EXT", "php", "BLOCK"},
		{"UPLOAD", "EXT", "phtml", "BLOCK"},
		{"UPLOAD", "EXT", "cer", "BLOCK"},
		{"UPLOAD", "EXT", "asa", "BLOCK"},
		{"UPLOAD", "EXT", "shtml", "BLOCK"},
		{"UPLOAD", "EXT", "war", "BLOCK"},
		{"UPLOAD", "EXT", "jar", "BLOCK"},
	} {
		if n := s8Count(t, env, `SELECT count(*) FROM api_file_compliance_rules
			WHERE direction=$1 AND match_type=$2 AND match_value=$3 AND action=$4 AND enabled`,
			want[0], want[1], want[2], want[3]); n != 1 {
			t.Fatalf("seed rule %v missing", want)
		}
	}
	// 去重键：同方向同类型同匹配值重复拒绝
	if _, err := env.db.Exec(ctx, `INSERT INTO api_file_compliance_rules
		(direction, match_type, match_value, action) VALUES ('UPLOAD','EXT','exe','OBSERVE')`); err == nil {
		t.Fatalf("duplicate dedup key should fail")
	}
	// 签名有效期设置种子（默认 30）
	if n := s8Count(t, env, `SELECT count(*) FROM system_settings
		WHERE setting_group='api_data' AND setting_key='file_signature_max_age_days' AND setting_value='30'::jsonb`); n != 1 {
		t.Fatalf("file_signature_max_age_days seed missing")
	}
}

// TestStage8FileComplianceStoreCRUD SQL 仓储：CRUD 往返 / 去重冲突映射 / updated_at 刷新。
func TestStage8FileComplianceStoreCRUD(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	store := apifiles.NewComplianceStore(env.db)

	rule := &apifiles.ComplianceRule{
		Direction: "UPLOAD", MatchType: "EXT", MatchValue: "z" + rid,
		Action: "BLOCK", Reason: "集成测试", Enabled: true,
	}
	if err := store.CreateComplianceRule(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}
	if rule.ID.String() == "" || rule.CreatedAt.IsZero() || rule.UpdatedAt.IsZero() {
		t.Fatalf("create did not backfill id/timestamps: %+v", rule)
	}
	// 去重冲突 → ErrComplianceConflict
	dup := &apifiles.ComplianceRule{Direction: "UPLOAD", MatchType: "EXT", MatchValue: "z" + rid, Action: "OBSERVE"}
	if err := store.CreateComplianceRule(ctx, dup); err != apifiles.ErrComplianceConflict {
		t.Fatalf("duplicate: err=%v, want ErrComplianceConflict", err)
	}
	// Get + List 过滤
	got, err := store.GetComplianceRule(ctx, rule.ID)
	if err != nil || got.MatchValue != "z"+rid {
		t.Fatalf("get: %+v err=%v", got, err)
	}
	list, total, err := store.ListComplianceRules(ctx, apifiles.ComplianceFilter{MatchType: "EXT", Action: "BLOCK", Page: 1, PageSize: 100})
	if err != nil || total < 4 { // 种子 16 条 EXT BLOCK（000071 exe/bat/sh + 000081 webshell 13 条）+ 本行
		t.Fatalf("list: total=%d err=%v", total, err)
	}
	var found bool
	for _, it := range list {
		if it.ID == rule.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("created rule not in list (total=%d)", total)
	}
	// 更新（含值与 enabled）；updated_at 不早于 created_at
	rule.Action = "OBSERVE"
	rule.Enabled = false
	if err := store.UpdateComplianceRule(ctx, rule); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err = store.GetComplianceRule(ctx, rule.ID)
	if err != nil || got.Action != "OBSERVE" || got.Enabled {
		t.Fatalf("after update: %+v err=%v", got, err)
	}
	if got.UpdatedAt.Before(got.CreatedAt) {
		t.Fatalf("updated_at %v before created_at %v", got.UpdatedAt, got.CreatedAt)
	}
	// 更新撞他行去重键 → ErrComplianceConflict（种子 UPLOAD/EXT/exe 已存在）
	got.MatchValue = "exe"
	if err := store.UpdateComplianceRule(ctx, got); err != apifiles.ErrComplianceConflict {
		t.Fatalf("conflicting update: err=%v, want ErrComplianceConflict", err)
	}
	// 未找到语义
	if err := store.DeleteComplianceRule(ctx, rule.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.GetComplianceRule(ctx, rule.ID); err != apifiles.ErrComplianceNotFound {
		t.Fatalf("get deleted: err=%v, want ErrComplianceNotFound", err)
	}
}

// fcComplianceMux 装配合规路由（真实 SQL Store + 真实审计服务）。
func fcComplianceMux(env *testEnv, authzFn func(http.Handler) http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	apifiles.RegisterComplianceRoutes(mux, authzFn,
		apifiles.NewComplianceHandler(apifiles.NewComplianceStore(env.db), audits.NewService(env.db)))
	return mux
}

// TestStage8FileComplianceHTTP HTTP 接线：权限矩阵 / 校验 / CRUD / 操作审计落库。
func TestStage8FileComplianceHTTP(t *testing.T) {
	env := setupStage8Env(t)
	rid := s5Rand()
	url := "/api/v1/api-security/file-compliance-rules"
	createBody := map[string]any{
		"direction": "UPLOAD", "match_type": "EXT", "match_value": "w" + rid,
		"action": "BLOCK", "reason": "集成测试规则",
	}

	// 权限矩阵：匿名 401 / 无权限 403 / 持权可达
	if rr := apidataDo(t, fcComplianceMux(env, xbInjectAnon), http.MethodGet, url, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anon: status=%d, want 401", rr.Code)
	}
	if rr := apidataDo(t, fcComplianceMux(env, faInjectNoPerm), http.MethodGet, url, nil); rr.Code != http.StatusForbidden {
		t.Fatalf("noperm: status=%d, want 403", rr.Code)
	}
	mux := fcComplianceMux(env, apidataInjectPrincipal)

	// 创建（audit 落库）
	rr := apidataDo(t, mux, http.MethodPost, url, createBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("create: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var created struct {
		Data struct {
			ID        string `json:"id"`
			Enabled   bool   `json:"enabled"`
			CreatedBy string `json:"created_by"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil || created.Data.ID == "" {
		t.Fatalf("decode create: %v body=%s", err, rr.Body.String())
	}
	if !created.Data.Enabled || created.Data.CreatedBy == "" {
		t.Fatalf("create defaults: %+v", created.Data)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM operation_audits
		WHERE module='api_files' AND action='create' AND object_type='api_file_compliance_rule' AND object_id=$1`,
		created.Data.ID); n != 1 {
		t.Fatalf("create audit missing")
	}
	// 重复创建 409
	if rr := apidataDo(t, mux, http.MethodPost, url, createBody); rr.Code != http.StatusConflict {
		t.Fatalf("duplicate: status=%d, want 409", rr.Code)
	}
	// 列表（EXT+BLOCK 过滤：种子 16 条 + 本行）
	rr = apidataDo(t, mux, http.MethodGet, url+"?match_type=EXT&action=BLOCK&page_size=100", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: status=%d", rr.Code)
	}
	var listBody struct {
		Data struct {
			Total int64 `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listBody); err != nil || listBody.Data.Total != 17 {
		t.Fatalf("list total=%d, want 17 (16 seed BLOCK + 1)", listBody.Data.Total)
	}
	// 部分更新 + 审计
	rr = apidataDo(t, mux, http.MethodPatch, url+"/"+created.Data.ID, map[string]any{"enabled": false})
	if rr.Code != http.StatusOK {
		t.Fatalf("patch: status=%d body=%s", rr.Code, rr.Body.String())
	}
	if n := s8Count(t, env, `SELECT count(*) FROM operation_audits
		WHERE module='api_files' AND action='update' AND object_id=$1`, created.Data.ID); n != 1 {
		t.Fatalf("update audit missing")
	}
	// 删除 + 审计
	if rr := apidataDo(t, mux, http.MethodDelete, url+"/"+created.Data.ID, nil); rr.Code != http.StatusOK {
		t.Fatalf("delete: status=%d", rr.Code)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM operation_audits
		WHERE module='api_files' AND action='delete' AND object_id=$1`, created.Data.ID); n != 1 {
		t.Fatalf("delete audit missing")
	}
	// 校验 400：RE2 不可编译
	if rr := apidataDo(t, mux, http.MethodPost, url, map[string]any{
		"direction": "UPLOAD", "match_type": "FILENAME_REGEX", "match_value": "[bad", "action": "BLOCK",
	}); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad regex: status=%d, want 400", rr.Code)
	}
}

// TestStage8FileSignature 签名验证面：缺失 503/404 → 轮换（密文落库 + kid 递增 + 审计）→
// 真实签名串正反/过期验证 → 审计摘要不含 token。
func TestStage8FileSignature(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	enc := fcEncryptor(t)
	settingsSvc := settings.NewService(env.db)
	newMux := func(authzFn func(http.Handler) http.Handler) *http.ServeMux {
		mux := http.NewServeMux()
		apifiles.RegisterSignatureRoutes(mux, authzFn,
			apifiles.NewSignatureHandler(settingsSvc, enc, audits.NewService(env.db)))
		return mux
	}
	verifyURL := "/api/v1/api-security/file-signature/verify"
	shaHex := strings.Repeat("ab", 32)

	// 权限矩阵：匿名 401 / 无权限 403
	if rr := apidataDo(t, newMux(xbInjectAnon), http.MethodPost, verifyURL, map[string]any{}); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anon: status=%d, want 401", rr.Code)
	}
	if rr := apidataDo(t, newMux(faInjectNoPerm), http.MethodPost, verifyURL, map[string]any{}); rr.Code != http.StatusForbidden {
		t.Fatalf("noperm: status=%d, want 403", rr.Code)
	}
	mux := newMux(apidataInjectPrincipal)

	// 未轮换：verify 503 / key 404
	verifyBody := func(token string) map[string]any {
		return map[string]any{"filename": "report.pdf", "content_sha256_hex": shaHex, "token": token}
	}
	if rr := apidataDo(t, mux, http.MethodPost, verifyURL, verifyBody("jzsig1.1.1700000000."+strings.Repeat("a", 64))); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("verify without key: status=%d, want 503 (%s)", rr.Code, rr.Body.String())
	}
	if rr := apidataDo(t, mux, http.MethodGet, "/api/v1/api-security/file-signature/key", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("key without rotate: status=%d, want 404", rr.Code)
	}

	// 轮换：kid=1；密钥落库为密文；审计落库
	rr := apidataDo(t, mux, http.MethodPost, "/api/v1/api-security/file-signature/key/rotate", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("rotate: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var kidBody struct {
		Data struct {
			Kid string `json:"kid"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &kidBody); err != nil || kidBody.Data.Kid != "1" {
		t.Fatalf("rotate resp: %v body=%s", err, rr.Body.String())
	}
	rawKey := settingsSvc.GetString(ctx, "gateway_runtime", "api_file_signature_key", "")
	if rawKey == "" || len(rawKey) == 64 {
		t.Fatalf("stored key missing or plaintext hex: %q", rawKey)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM operation_audits
		WHERE module='api_files' AND action='rotate' AND object_type='api_file_signature_key'`); n != 1 {
		t.Fatalf("rotate audit missing")
	}
	// 再次轮换：kid=2（递增）
	if rr := apidataDo(t, mux, http.MethodPost, "/api/v1/api-security/file-signature/key/rotate", nil); rr.Code != http.StatusOK {
		t.Fatalf("second rotate: status=%d", rr.Code)
	}
	key, kid, err := apifiles.LoadFileSignatureKey(ctx, settingsSvc, enc)
	if err != nil || kid != "2" {
		t.Fatalf("load after rotates: kid=%q err=%v", kid, err)
	}
	// GET key 返回当前 kid
	rr = apidataDo(t, mux, http.MethodGet, "/api/v1/api-security/file-signature/key", nil)
	if err := json.Unmarshal(rr.Body.Bytes(), &kidBody); err != nil || kidBody.Data.Kid != "2" {
		t.Fatalf("get key: %v body=%s", err, rr.Body.String())
	}

	// 真实签名串（落库密钥复算）→ valid；审计落库且摘要不含 token
	now := time.Now().UTC()
	token := apifiles.SignFileToken(key, kid, "report.pdf", shaHex, now.Unix(), "")
	rr = apidataDo(t, mux, http.MethodPost, verifyURL, verifyBody(token))
	if rr.Code != http.StatusOK {
		t.Fatalf("verify: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var verifyResp struct {
		Data apifiles.VerifyResult `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("decode verify: %v", err)
	}
	if !verifyResp.Data.Valid || verifyResp.Data.Kid != "2" || verifyResp.Data.SignedAt == "" {
		t.Fatalf("verify resp: %+v", verifyResp.Data)
	}
	var auditSummary string
	if err := env.db.QueryRow(ctx, `SELECT after_summary FROM operation_audits
		WHERE module='api_files' AND action='verify' ORDER BY occurred_at DESC LIMIT 1`).Scan(&auditSummary); err != nil {
		t.Fatalf("verify audit missing: %v", err)
	}
	if strings.Contains(auditSummary, token) {
		t.Fatalf("verify audit leaks token: %s", auditSummary)
	}
	if !strings.Contains(auditSummary, "report.pdf") {
		t.Fatalf("verify audit summary missing filename: %s", auditSummary)
	}
	// 篡改 → valid=false
	bad := apifiles.SignFileToken(key, kid, "evil.pdf", shaHex, now.Unix(), "")
	if err := json.Unmarshal(apidataDo(t, mux, http.MethodPost, verifyURL, verifyBody(bad)).Body.Bytes(), &verifyResp); err != nil {
		t.Fatal(err)
	}
	if verifyResp.Data.Valid {
		t.Fatalf("tampered token accepted: %+v", verifyResp.Data)
	}
	// 过期（有效期设置改 1 天，签名 2 天前）
	if _, err := env.db.Exec(ctx, `UPDATE system_settings SET setting_value='1'::jsonb
		WHERE setting_group='api_data' AND setting_key='file_signature_max_age_days'`); err != nil {
		t.Fatalf("set max age: %v", err)
	}
	old := apifiles.SignFileToken(key, kid, "report.pdf", shaHex, now.AddDate(0, 0, -2).Unix(), "")
	if err := json.Unmarshal(apidataDo(t, mux, http.MethodPost, verifyURL, verifyBody(old)).Body.Bytes(), &verifyResp); err != nil {
		t.Fatal(err)
	}
	if verifyResp.Data.Valid || !strings.Contains(verifyResp.Data.Reason, "已过期") {
		t.Fatalf("expired token: %+v", verifyResp.Data)
	}
}
