// stage8_param_sensitivity_test.go 参数敏感级别自动标注与语义类型编辑通路。
// 覆盖：
//
//	a) 语义推断词典扩充（statistics.go 1c：captcha/username/id_card/bank_card +
//	   token/secret/phone 的 LIKE 变体），user_id→id 回归不破；
//	b) PropagateSensitivityLevels：敏感字段台账（api_sensitive_fields）回写
//	   （末段名 + 首段位置映射 + data_type→级别映射 + 多命中取最高级），
//	   人工已定级别不覆盖，semantic_type 语义兜底，幂等可重跑；
//	c) PATCH /api/v1/api-security/parameters/{id} 支持 semantic_type：
//	   携带落库 / 省略保留 / 显式空串清空。
package tests

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apimodels"
)

// s8SemanticOf 读取指定参数行的 semantic_type（直查库断言）。
func s8SemanticOf(t *testing.T, env *testEnv, versionID uuid.UUID, name string) string {
	t.Helper()
	var sem string
	if err := env.db.QueryRow(context.Background(), `
SELECT semantic_type FROM api_parameter_models
WHERE model_version_id=$1 AND parameter_name=$2`, versionID, name).Scan(&sem); err != nil {
		t.Fatalf("read semantic_type of %s: %v", name, err)
	}
	return sem
}

// s8LevelOf 读取指定参数行的 sensitivity_level（直查库断言）。
func s8LevelOf(t *testing.T, env *testEnv, versionID uuid.UUID, name string) string {
	t.Helper()
	var lv string
	if err := env.db.QueryRow(context.Background(), `
SELECT sensitivity_level FROM api_parameter_models
WHERE model_version_id=$1 AND parameter_name=$2`, versionID, name).Scan(&lv); err != nil {
		t.Fatalf("read sensitivity_level of %s: %v", name, err)
	}
	return lv
}

// TestStage8SemanticTypeDictionary 语义推断词典扩充（statistics.go 1c）。
func TestStage8SemanticTypeDictionary(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	models := apimodels.NewStore(env.db)
	ep := s8SeedEndpoint(t, env, "POST", "/s8sem-"+s5Rand()+"/dict", 0.8)
	v1, err := models.CreateCandidateWithReason(ctx, ep.ID, ep.EndpointKey, "dict v1",
		apimodels.CreatedReasonManual, map[string]string{
			"captchaCode": "string",
			"captchaKey":  "string",
			"username":    "string",
			"idcardNo":    "string",
			"cardNo":      "string",
			"myToken":     "string",
			"mobileNo":    "string",
			"user_id":     "string",
		}, uuid.Nil)
	if err != nil {
		t.Fatalf("create candidate: %v", err)
	}
	if _, err := models.Confirm(ctx, v1.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	s8Exec(t, env, `UPDATE api_endpoints SET learning_status='LEARNED' WHERE id=$1`, ep.ID)
	// 样本：≥100 accepted（对齐 recommended 门槛；词典推断只需 EXISTS accepted 样本）
	for i := 0; i < 100; i++ {
		s8Exec(t, env, `
INSERT INTO api_learning_samples (api_endpoint_id, request_id, sample_hash, source_fingerprint, response_status, accepted, exclude_reason)
VALUES ($1,$2,$3,'src',200,true,'')`, ep.ID, "r-"+s5Rand(), "h-"+s5Rand())
	}

	n, err := models.RefreshParameterStatistics(ctx)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if n != 8 {
		t.Fatalf("refreshed = %d, want 8", n)
	}

	cases := map[string]string{
		"captchaCode": "captcha",   // %captcha%（必须先于 token/key 类分支）
		"captchaKey":  "captcha",   // 同上：不得落入 token/key
		"username":    "username",  // IN 精确词表
		"idcardNo":    "id_card",   // %idcard%
		"cardNo":      "bank_card", // %cardno%
		"myToken":     "token",     // %token% LIKE 变体
		"mobileNo":    "phone",     // %mobile% LIKE 变体
		"user_id":     "id",        // 回归：既有 id 分支不受影响
	}
	for name, want := range cases {
		if got := s8SemanticOf(t, env, v1.ID, name); got != want {
			t.Errorf("%s semantic_type = %q, want %q", name, got, want)
		}
	}
}

// TestStage8PropagateSensitivityLevels 敏感级别自动标注（台账回写 + 语义兜底 + 幂等）。
func TestStage8PropagateSensitivityLevels(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	models := apimodels.NewStore(env.db)
	ep := s8SeedEndpoint(t, env, "POST", "/s8sens-"+s5Rand()+"/pay", 0.8)
	v1, err := models.CreateCandidateWithReason(ctx, ep.ID, ep.EndpointKey, "sens v1",
		apimodels.CreatedReasonManual, map[string]string{
			"password":     "string",
			"note":         "string",
			"access_token": "string",
		}, uuid.Nil)
	if err != nil {
		t.Fatalf("create candidate: %v", err)
	}
	if _, err := models.Confirm(ctx, v1.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	// BODY 物化参数 structured_path 为 schema 字段路径本体（无 json. 前缀，
	// 见 parameters.go materializeRequestParameters）；台账侧 structured_path
	// 带首段前缀（json.password），匹配按末段名 + 首段位置映射进行。

	// 敏感字段台账：password（credential→HIGH）、note（phone→MEDIUM）
	s8Exec(t, env, `
INSERT INTO api_sensitive_fields (endpoint_id, direction, structured_path, data_type, confidence)
VALUES ($1,'REQUEST','json.password','credential',1.0)`, ep.ID)
	s8Exec(t, env, `
INSERT INTO api_sensitive_fields (endpoint_id, direction, structured_path, data_type, confidence)
VALUES ($1,'REQUEST','json.note','phone',0.9)`, ep.ID)
	// note 人工已定 LOW：台账回写只补 UNKNOWN，不得覆盖
	s8Exec(t, env, `
UPDATE api_parameter_models SET sensitivity_level='LOW'
WHERE model_version_id=$1 AND parameter_name='note'`, v1.ID)

	n, err := models.PropagateSensitivityLevels(ctx)
	if err != nil {
		t.Fatalf("propagate: %v", err)
	}
	if n != 1 {
		t.Fatalf("propagated = %d, want 1（仅 password）", n)
	}
	if got := s8LevelOf(t, env, v1.ID, "password"); got != "HIGH" {
		t.Errorf("password sensitivity = %q, want HIGH（credential 台账回写）", got)
	}
	if got := s8LevelOf(t, env, v1.ID, "note"); got != "LOW" {
		t.Errorf("note sensitivity = %q, want LOW（人工已定级不被覆盖）", got)
	}
	if got := s8LevelOf(t, env, v1.ID, "access_token"); got != "UNKNOWN" {
		t.Errorf("access_token sensitivity = %q, want UNKNOWN（无台账行、语义未推断）", got)
	}

	// 语义兜底：统计推断 access_token → token，再回写 → HIGH
	s8Exec(t, env, `UPDATE api_endpoints SET learning_status='LEARNED' WHERE id=$1`, ep.ID)
	for i := 0; i < 3; i++ {
		s8Exec(t, env, `
INSERT INTO api_learning_samples (api_endpoint_id, request_id, sample_hash, source_fingerprint, response_status, accepted, exclude_reason)
VALUES ($1,$2,$3,'src',200,true,'')`, ep.ID, "r-"+s5Rand(), "h-"+s5Rand())
	}
	if _, err := models.RefreshParameterStatistics(ctx); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := s8SemanticOf(t, env, v1.ID, "access_token"); got != "token" {
		t.Fatalf("access_token semantic_type = %q, want token", got)
	}
	n, err = models.PropagateSensitivityLevels(ctx)
	if err != nil {
		t.Fatalf("propagate 2: %v", err)
	}
	if n != 1 {
		t.Fatalf("propagated 2 = %d, want 1（仅 access_token 语义兜底）", n)
	}
	if got := s8LevelOf(t, env, v1.ID, "access_token"); got != "HIGH" {
		t.Errorf("access_token sensitivity = %q, want HIGH（semantic_type=token 兜底）", got)
	}

	// 幂等：无 UNKNOWN 待补行，重跑更新 0 行且级别不回头
	n, err = models.PropagateSensitivityLevels(ctx)
	if err != nil {
		t.Fatalf("propagate 3: %v", err)
	}
	if n != 0 {
		t.Errorf("propagate 3 = %d, want 0（幂等）", n)
	}
	if got := s8LevelOf(t, env, v1.ID, "note"); got != "LOW" {
		t.Errorf("note sensitivity after rerun = %q, want LOW", got)
	}
}

// TestStage8ParameterPatchSemanticType PATCH 支持 semantic_type：携带落库 / 省略保留 / 空串清空。
func TestStage8ParameterPatchSemanticType(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8patchsem", "SECURITY_ADMIN")
	ctx := context.Background()

	models := apimodels.NewStore(env.db)
	ep := s8SeedEndpoint(t, env, "POST", "/s8patch-"+s5Rand()+"/profile", 0.8)
	v1, err := models.CreateCandidateWithReason(ctx, ep.ID, ep.EndpointKey, "patch v1",
		apimodels.CreatedReasonManual, map[string]string{"contact": "string"}, uuid.Nil)
	if err != nil {
		t.Fatalf("create candidate: %v", err)
	}
	if _, err := models.Confirm(ctx, v1.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	var paramID string
	if err := env.db.QueryRow(ctx, `
SELECT id FROM api_parameter_models WHERE model_version_id=$1 AND parameter_name='contact'`, v1.ID).Scan(&paramID); err != nil {
		t.Fatalf("read parameter id: %v", err)
	}
	patchPath := "/api/v1/api-security/parameters/" + paramID

	// 1) 携带 semantic_type='email' → 落库
	resp := env.do(t, http.MethodPatch, patchPath,
		`{"required":false,"nullable":true,"empty_allowed":true,"sensitivity_level":"LOW","semantic_type":"email"}`,
		cookies, csrf)
	result := s5OK(t, resp, "patch semantic_type=email")
	if got := s5Obj(t, result, "parameter")["semantic_type"]; got != "email" {
		t.Errorf("patch response semantic_type = %v, want email", got)
	}
	if got := s8SemanticOf(t, env, v1.ID, "contact"); got != "email" {
		t.Errorf("db semantic_type = %q, want email", got)
	}

	// 2) 不携带 semantic_type → 原值不变
	resp = env.do(t, http.MethodPatch, patchPath,
		`{"required":true,"nullable":true,"empty_allowed":true,"sensitivity_level":"LOW"}`,
		cookies, csrf)
	result = s5OK(t, resp, "patch without semantic_type")
	if got := s5Obj(t, result, "parameter")["semantic_type"]; got != "email" {
		t.Errorf("patch response semantic_type = %v, want email（省略保留）", got)
	}
	if got := s8SemanticOf(t, env, v1.ID, "contact"); got != "email" {
		t.Errorf("db semantic_type = %q, want email（省略保留）", got)
	}

	// 3) 显式空串 → 清空
	resp = env.do(t, http.MethodPatch, patchPath,
		`{"required":true,"nullable":true,"empty_allowed":true,"sensitivity_level":"LOW","semantic_type":""}`,
		cookies, csrf)
	result = s5OK(t, resp, "patch semantic_type empty")
	if got := s5Obj(t, result, "parameter")["semantic_type"]; got != "" {
		t.Errorf("patch response semantic_type = %v, want 空串（显式清空）", got)
	}
	if got := s8SemanticOf(t, env, v1.ID, "contact"); got != "" {
		t.Errorf("db semantic_type = %q, want 空串（显式清空）", got)
	}
}
