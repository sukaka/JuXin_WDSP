// object_models_update_integration_test.go 对象模型 enforcement 管理写入的 PG 契约测试
// （NG-AZ-03 D3/D8）：切换 PROTECT 四要素落库；切回 OBSERVE 无前置且历史值保留供审计；
// 审计摘要含四要素全值。Opt-in（AUTHZ_TEST_PG_DSN）——单元运行不需要活动数据库。
package apisecurity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/apiauthzwizard"
	"github.com/jiuzhang-waf/server/internal/database"
)

func openObjectModelPG(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("AUTHZ_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_PG_DSN not set, skipping object model enforcement PG test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("create pg pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping pg: %v", err)
	}
	return pool, ctx
}

func strp(v string) *string { return &v }

func TestObjectModelEnforcementPatchPostgresContract(t *testing.T) {
	pool, ctx := openObjectModelPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	code := fmt.Sprintf("omp174-%d", time.Now().UnixNano())
	var applicationID, endpointID, modelID string
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&applicationID); err != nil {
		t.Fatalf("insert application: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_endpoints(application_id,http_method,normalized_path,endpoint_key) VALUES ($1,'GET','/orders/{id}',$2) RETURNING id`, applicationID, code+":GET:/orders/{id}").Scan(&endpointID); err != nil {
		t.Fatalf("insert endpoint: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_object_models(endpoint_id,object_segment) VALUES ($1,'path:1') RETURNING id`, endpointID).Scan(&modelID); err != nil {
		t.Fatalf("insert object model: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_object_models WHERE endpoint_id=$1`, endpointID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_endpoints WHERE id=$1`, endpointID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM applications WHERE id=$1`, applicationID)
	})

	store := NewStore(pool)
	id := uuid.MustParse(modelID)

	// ① 初始态：缺省 OBSERVE/空值（NG-T-C01 未配置与历史版本一致）
	m, err := store.GetObjectModel(ctx, id)
	if err != nil {
		t.Fatalf("GetObjectModel: %v", err)
	}
	if m.Enforcement != "OBSERVE" || m.EnforcementOwner != "" || m.EvidenceSource != "" || m.OnUnknown != "ALLOW_UNKNOWN" {
		t.Fatalf("initial enforcement fields=(%q,%q,%q,%q), want (OBSERVE,'','',ALLOW_UNKNOWN)",
			m.Enforcement, m.EnforcementOwner, m.EvidenceSource, m.OnUnknown)
	}

	// ② 切换 PROTECT（NG-AZ-04 起系统约束升级：四要素 + 确认单 confirm_token——
	// 先经影响评估签发并签署，再 PATCH 消费）：四列落库；三要素归一（大小写/空白）
	wiz := apiauthzwizard.NewStore(pool)
	token, _, err := wiz.IssueConfirmation(ctx, uuid.MustParse(applicationID), uuid.MustParse(endpointID), "path:1", 7, []byte(`{}`), time.Now().UTC())
	if err != nil {
		t.Fatalf("issue confirmation: %v", err)
	}
	if _, err := wiz.SignConfirmation(ctx, token, "zhang.lei@example.com", "AUTHORITY_SYNC", "ALLOW_UNKNOWN", "text", uuid.New(), "tester", time.Now().UTC()); err != nil {
		t.Fatalf("sign confirmation: %v", err)
	}
	patch := ObjectModelPatch{
		Enforcement:      strp("protect"),
		EnforcementOwner: strp("  zhang.lei@example.com  "),
		EvidenceSource:   strp("authority_sync"),
		OnUnknown:        strp("allow_unknown"),
		ConfirmToken:     strp(token.String()),
	}
	if msg := patch.validate(); msg != "" {
		t.Fatalf("PROTECT patch validate: %s", msg)
	}
	if err := store.UpdateObjectModel(ctx, id, patch, "req-it-1"); err != nil {
		t.Fatalf("UpdateObjectModel PROTECT: %v", err)
	}
	m, err = store.GetObjectModel(ctx, id)
	if err != nil {
		t.Fatalf("GetObjectModel after PROTECT: %v", err)
	}
	if m.Enforcement != "PROTECT" || m.EnforcementOwner != "zhang.lei@example.com" ||
		m.EvidenceSource != "AUTHORITY_SYNC" || m.OnUnknown != "ALLOW_UNKNOWN" {
		t.Fatalf("PROTECT fields=(%q,%q,%q,%q)", m.Enforcement, m.EnforcementOwner, m.EvidenceSource, m.OnUnknown)
	}

	// 审计摘要含四要素全值（D8：after 摘要可完整回答「谁决定、凭什么证据、UNKNOWN 怎么办」）
	summary := objectModelSummary(m)
	for _, want := range []string{"enforcement=PROTECT", "enforcement_owner=zhang.lei@example.com",
		"evidence_source=AUTHORITY_SYNC", "on_unknown=ALLOW_UNKNOWN"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("audit summary missing %q: %s", want, summary)
		}
	}

	// ③ 切回 OBSERVE（无前置要素要求）：enforcement 变更，三要素历史值保留供审计
	backPatch := ObjectModelPatch{Enforcement: strp("OBSERVE")}
	if msg := backPatch.validate(); msg != "" {
		t.Fatalf("OBSERVE patch validate: %s", msg)
	}
	if err := store.UpdateObjectModel(ctx, id, backPatch, "req-it-2"); err != nil {
		t.Fatalf("UpdateObjectModel OBSERVE: %v", err)
	}
	m, err = store.GetObjectModel(ctx, id)
	if err != nil {
		t.Fatalf("GetObjectModel after OBSERVE: %v", err)
	}
	if m.Enforcement != "OBSERVE" {
		t.Fatalf("enforcement after OBSERVE=%q", m.Enforcement)
	}
	if m.EnforcementOwner != "zhang.lei@example.com" || m.EvidenceSource != "AUTHORITY_SYNC" || m.OnUnknown != "ALLOW_UNKNOWN" {
		t.Fatalf("切回 OBSERVE 历史值须保留供审计: (%q,%q,%q)", m.EnforcementOwner, m.EvidenceSource, m.OnUnknown)
	}

	// ④ 不存在行 404 哨兵
	if err := store.UpdateObjectModel(ctx, uuid.New(), backPatch, "req-it-3"); err != ErrObjectModelNotFound {
		t.Fatalf("missing row error=%v, want ErrObjectModelNotFound", err)
	}
}

// TestObjectModelProtectConfirmTokenTxContract PATCH enforcement=PROTECT 强制
// confirm_token 同事务契约（NG-AZ-04 D4/D9）：全流程（签发→签署→PATCH 消费成功）+
// 五类 400 精确消息 + 失败回滚不留半切换（绑定不符时 enforcement 保持 OBSERVE）+
// 审计 after 含 confirm_token。Opt-in（AUTHZ_TEST_PG_DSN）。
func TestObjectModelProtectConfirmTokenTxContract(t *testing.T) {
	pool, ctx := openObjectModelPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	code := fmt.Sprintf("omtx-%d", time.Now().UnixNano())
	var applicationID, endpointID, modelID string
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&applicationID); err != nil {
		t.Fatalf("insert application: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_endpoints(application_id,http_method,normalized_path,endpoint_key) VALUES ($1,'GET','/tx/{id}',$2) RETURNING id`, applicationID, code+":GET:/tx/{id}").Scan(&endpointID); err != nil {
		t.Fatalf("insert endpoint: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_object_models(endpoint_id,object_segment,publishable,required_relation,owner_exclusive) VALUES ($1,'path:1',true,'OWNER',true) RETURNING id`, endpointID).Scan(&modelID); err != nil {
		t.Fatalf("insert object model: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM api_authz_enforcement_confirmations WHERE application_id=$1`, applicationID)
		_, _ = pool.Exec(bg, `DELETE FROM api_object_models WHERE endpoint_id=$1`, endpointID)
		_, _ = pool.Exec(bg, `DELETE FROM api_endpoints WHERE id=$1`, endpointID)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, applicationID)
	})

	store := NewStore(pool)
	wiz := apiauthzwizard.NewStore(pool)
	id := uuid.MustParse(modelID)
	now := time.Now().UTC()
	protectPatch := func(token string) ObjectModelPatch {
		return ObjectModelPatch{
			Enforcement:      strp("PROTECT"),
			EnforcementOwner: strp("zhang.lei@example.com"),
			EvidenceSource:   strp("MANUAL_CONFIRMED"),
			OnUnknown:        strp("ALLOW_UNKNOWN"),
			ConfirmToken:     strp(token),
		}
	}
	enforcementOf := func() string {
		var v string
		if err := pool.QueryRow(ctx, `SELECT enforcement FROM api_object_models WHERE id=$1`, id).Scan(&v); err != nil {
			t.Fatalf("read enforcement: %v", err)
		}
		return v
	}

	// ① validate 层：缺 confirm_token 切换 PROTECT 400
	p := protectPatch("")
	p.ConfirmToken = nil
	if msg := p.validate(); !strings.Contains(msg, "confirm_token") {
		t.Fatalf("缺 token 应词表拒绝: %q", msg)
	}

	// ② 不存在 token → ErrInvalidTokenID
	err := store.UpdateObjectModel(ctx, id, protectPatch(uuid.NewString()), "req-tx-1")
	if !errors.Is(err, apiauthzwizard.ErrInvalidTokenID) {
		t.Fatalf("不存在 token 应 ErrInvalidTokenID: %v", err)
	}
	if enforcementOf() != "OBSERVE" {
		t.Fatal("失败后 enforcement 必须保持 OBSERVE（不留半切换）")
	}

	// ③ 签发未签署 → ErrNotSigned
	token, _, err := wiz.IssueConfirmation(ctx, uuid.MustParse(applicationID), uuid.MustParse(endpointID), "path:1", 7, []byte(`{}`), now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := store.UpdateObjectModel(ctx, id, protectPatch(token.String()), "req-tx-2"); !errors.Is(err, apiauthzwizard.ErrNotSigned) {
		t.Fatalf("未签署应 ErrNotSigned: %v", err)
	}
	if enforcementOf() != "OBSERVE" {
		t.Fatal("失败后 enforcement 必须保持 OBSERVE")
	}

	// ④ 签署后绑定不符（另一对象模型行 PATCH）→ ErrTokenMismatch 且回滚
	var cid uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM api_authz_enforcement_confirmations WHERE confirm_token=$1`, token).Scan(&cid); err != nil {
		t.Fatalf("read cid: %v", err)
	}
	if _, err := wiz.SignConfirmation(ctx, token, "zhang.lei@example.com", "MANUAL_CONFIRMED", "ALLOW_UNKNOWN", "text", uuid.New(), "tester", now); err != nil {
		t.Fatalf("sign: %v", err)
	}
	var otherModelID string
	if err := pool.QueryRow(ctx, `INSERT INTO api_object_models(endpoint_id,object_segment) VALUES ($1,'query:oid') RETURNING id`, endpointID).Scan(&otherModelID); err != nil {
		t.Fatalf("insert other model: %v", err)
	}
	err = store.UpdateObjectModel(ctx, uuid.MustParse(otherModelID), protectPatch(token.String()), "req-tx-3")
	if !errors.Is(err, apiauthzwizard.ErrTokenMismatch) {
		t.Fatalf("绑定不符应 ErrTokenMismatch: %v", err)
	}
	if enforcementOf() != "OBSERVE" {
		t.Fatal("绑定不符失败后目标行 enforcement 必须保持 OBSERVE（事务回滚）")
	}
	// 确认单未被消费（回滚）
	var consumedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT consumed_at FROM api_authz_enforcement_confirmations WHERE id=$1`, cid).Scan(&consumedAt); err != nil {
		t.Fatalf("read consumed_at: %v", err)
	}
	if consumedAt != nil {
		t.Fatal("失败回滚后确认单不得被消费")
	}

	// ⑤ 全流程成功：PATCH 消费 → PROTECT 生效 + consumed_at/audit_id 落库
	if err := store.UpdateObjectModel(ctx, id, protectPatch(token.String()), "req-tx-4"); err != nil {
		t.Fatalf("全流程切换应成功: %v", err)
	}
	if enforcementOf() != "PROTECT" {
		t.Fatalf("切换后 enforcement=%s want PROTECT", enforcementOf())
	}
	var auditID string
	if err := pool.QueryRow(ctx, `SELECT consumed_audit_id FROM api_authz_enforcement_confirmations WHERE id=$1`, cid).Scan(&auditID); err != nil {
		t.Fatalf("read audit id: %v", err)
	}
	if auditID != "req-tx-4" {
		t.Fatalf("consumed_audit_id=%q want req-tx-4", auditID)
	}

	// ⑥ 复用同 token → ErrConsumed（即使目标是切回后再切 PROTECT）
	if err := store.UpdateObjectModel(ctx, id, ObjectModelPatch{Enforcement: strp("OBSERVE")}, "req-tx-5"); err != nil {
		t.Fatalf("切回 OBSERVE 应成功（免 token）: %v", err)
	}
	if err := store.UpdateObjectModel(ctx, id, protectPatch(token.String()), "req-tx-6"); !errors.Is(err, apiauthzwizard.ErrConsumed) {
		t.Fatalf("复用应 ErrConsumed: %v", err)
	}
	if enforcementOf() != "OBSERVE" {
		t.Fatal("复用失败后 enforcement 必须保持 OBSERVE")
	}
}

func TestObjectModelAnyOfAndRequiredRelationsPostgresContract(t *testing.T) {
	pool, ctx := openObjectModelPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	code := fmt.Sprintf("omany-%d", time.Now().UnixNano())
	var applicationID, endpointID, modelID string
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&applicationID); err != nil {
		t.Fatalf("insert application: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_endpoints(application_id,http_method,normalized_path,endpoint_key) VALUES ($1,'GET','/docs/{id}',$2) RETURNING id`, applicationID, code+":GET:/docs/{id}").Scan(&endpointID); err != nil {
		t.Fatalf("insert endpoint: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_object_models(endpoint_id,object_segment) VALUES ($1,'path:1') RETURNING id`, endpointID).Scan(&modelID); err != nil {
		t.Fatalf("insert object model: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM api_object_models WHERE endpoint_id=$1`, endpointID)
		_, _ = pool.Exec(bg, `DELETE FROM api_endpoints WHERE id=$1`, endpointID)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, applicationID)
	})

	store := NewStore(pool)
	id := uuid.MustParse(modelID)
	rels := []string{"shared_with", "owner"}
	if err := store.UpdateObjectModel(ctx, id, ObjectModelPatch{
		RequiredRelation:  strp("ANY_OF"),
		RequiredRelations: &rels,
	}, "req-anyof-1"); err != nil {
		t.Fatalf("UpdateObjectModel ANY_OF: %v", err)
	}
	m, err := store.GetObjectModel(ctx, id)
	if err != nil {
		t.Fatalf("GetObjectModel ANY_OF: %v", err)
	}
	if m.RequiredRelation != "ANY_OF" || len(m.RequiredRelations) != 2 || m.RequiredRelations[0] != "OWNER" || m.RequiredRelations[1] != "SHARED_WITH" {
		t.Fatalf("GetObjectModel ANY_OF mismatch: %+v", m)
	}
	list, _, err := store.ListObjectModels(ctx, endpointID, "", "", "", 1, 20)
	if err != nil || len(list) != 1 || len(list[0].RequiredRelations) != 2 {
		t.Fatalf("ListObjectModels ANY_OF mismatch: err=%v list=%+v", err, list)
	}
	if err := store.UpdateObjectModel(ctx, id, ObjectModelPatch{RequiredRelation: strp("OWNER")}, "req-owner-2"); err != nil {
		t.Fatalf("UpdateObjectModel switch back to OWNER: %v", err)
	}
	var isNull bool
	if err := pool.QueryRow(ctx, `SELECT required_relations IS NULL FROM api_object_models WHERE id=$1`, id).Scan(&isNull); err != nil || !isNull {
		t.Fatalf("switching back to OWNER must clear required_relations=NULL, isNull=%v err=%v", isNull, err)
	}
}
