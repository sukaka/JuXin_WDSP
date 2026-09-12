// stage8_api_action_vocabulary_test.go §34 用途多维识别扩展集成测试（迁移 000148 +
// AutoClassify 实库 ACTION/BUSINESS_DOMAIN 维度产出）。
package tests

import (
	"context"
	"os"
	"testing"

	"github.com/jiuzhang-waf/server/internal/apiassets"
)

// actionVocabularySeeds §34.2 操作动作 43 项词表（迁移 000148 ACTION 目录）。
var actionVocabularySeeds = []string{
	"CREATE", "READ_LIST", "READ_DETAIL", "SEARCH", "COUNT", "UPDATE", "PATCH", "DELETE",
	"BATCH_CREATE", "BATCH_UPDATE", "BATCH_DELETE",
	"REGISTER", "LOGIN", "LOGOUT", "TOKEN_ISSUE", "TOKEN_REFRESH", "TOKEN_REVOKE", "VERIFY",
	"SUBMIT", "APPROVE", "REJECT", "WITHDRAW", "ASSIGN", "TRANSFER",
	"PUBLISH", "UNPUBLISH", "ENABLE", "DISABLE", "LOCK", "UNLOCK",
	"IMPORT", "EXPORT", "UPLOAD", "DOWNLOAD", "PREVIEW", "SYNC", "CALLBACK",
	"START", "STOP", "RETRY", "BACKUP", "RESTORE", "EXECUTE", "CUSTOM",
}

// businessDomainSeeds §34.1 业务领域 16 项种子编码（迁移 000148 BUSINESS_DOMAIN 目录，
// 与 api_classifications 内置种子编码对齐）。
var businessDomainSeeds = []string{
	"IDENTITY_AUTH", "USER_ACCOUNT", "ORG_PERMISSION", "DATA_RESOURCE",
	"PROCESS_APPROVAL", "FILE_CONTENT", "QUERY_ANALYTICS", "IMPORT_EXPORT",
	"TRANSACTION_FUND", "MESSAGE_NOTIFICATION", "EXTERNAL_INTEGRATION", "SYSTEM_CONFIG",
	"SYSTEM_OPS", "DEVICE_IOT", "AI_INTELLIGENCE", "PRIVACY_COMPLIANCE",
}

func TestStage8APIActionVocabularyMigration(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	assertActionVocabularySeeds(t, env)

	// 种子迁移允许安全重放，且不会产生重复条目。
	raw, err := os.ReadFile("../migrations/000148_api_action_vocabulary_seed.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := env.db.Exec(ctx, string(raw)); err != nil {
		t.Fatalf("replay migration 000148: %v", err)
	}
	assertActionVocabularySeeds(t, env)
}

func assertActionVocabularySeeds(t *testing.T, env *testEnv) {
	t.Helper()
	for _, want := range actionVocabularySeeds {
		if n := s8Count(t, env, `SELECT count(*) FROM api_custom_taxonomies
			WHERE dimension='ACTION' AND value=$1 AND description <> ''`, want); n != 1 {
			t.Fatalf("ACTION catalog seed %s count=%d want 1", want, n)
		}
	}
	for _, want := range businessDomainSeeds {
		if n := s8Count(t, env, `SELECT count(*) FROM api_custom_taxonomies
			WHERE dimension='BUSINESS_DOMAIN' AND value=$1 AND description <> ''`, want); n != 1 {
			t.Fatalf("BUSINESS_DOMAIN catalog seed %s count=%d want 1", want, n)
		}
	}
}

// TestStage8AutoClassifyActionDomain 实库验证 AutoClassify 产出 §34 扩展维度：
// ACTION 恒产出并落库，BUSINESS_DOMAIN 领域关键词置信达标才落库。
func TestStage8AutoClassifyActionDomain(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	store := apiassets.NewStore(env.db)

	// 令牌端点：ACTION=TOKEN_ISSUE（POST+token），BUSINESS_DOMAIN=IDENTITY_AUTH（oauth+token 双命中）
	tok := s8SeedEndpoint(t, env, "POST", "/s8av-"+s5Rand()+"/oauth/token", 0.9)
	dims, err := store.AutoClassify(ctx, tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range dims {
		got[d.Dimension] = d.Value
	}
	if got["ACTION"] != "TOKEN_ISSUE" {
		t.Fatalf("ACTION=%s want TOKEN_ISSUE（dims=%v）", got["ACTION"], dims)
	}
	if got["BUSINESS_DOMAIN"] != "IDENTITY_AUTH" {
		t.Fatalf("BUSINESS_DOMAIN=%s want IDENTITY_AUTH（dims=%v）", got["BUSINESS_DOMAIN"], dims)
	}
	// 落库核验（source=AUTO）
	if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
		WHERE endpoint_id=$1 AND dimension='ACTION' AND value='TOKEN_ISSUE' AND source='AUTO'`, tok.ID); n != 1 {
		t.Fatalf("ACTION row count=%d want 1", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
		WHERE endpoint_id=$1 AND dimension='BUSINESS_DOMAIN' AND value='IDENTITY_AUTH' AND source='AUTO'`, tok.ID); n != 1 {
		t.Fatalf("BUSINESS_DOMAIN row count=%d want 1", n)
	}

	// 普通详情读端点：ACTION=READ_DETAIL（GET 末段变量），无领域命中不落 BUSINESS_DOMAIN
	det := s8SeedEndpoint(t, env, "GET", "/s8av-"+s5Rand()+"/widgets/{id}", 0.9)
	dims, err = store.AutoClassify(ctx, det.ID)
	if err != nil {
		t.Fatal(err)
	}
	got = map[string]string{}
	for _, d := range dims {
		got[d.Dimension] = d.Value
	}
	if got["ACTION"] != "READ_DETAIL" {
		t.Fatalf("ACTION=%s want READ_DETAIL（dims=%v）", got["ACTION"], dims)
	}
	if _, ok := got["BUSINESS_DOMAIN"]; ok {
		t.Fatalf("低置信不应打标 BUSINESS_DOMAIN（dims=%v）", dims)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
		WHERE endpoint_id=$1 AND dimension='BUSINESS_DOMAIN'`, det.ID); n != 0 {
		t.Fatalf("BUSINESS_DOMAIN row count=%d want 0", n)
	}
}
