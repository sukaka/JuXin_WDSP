// machine_identities_pg_test.go 机器身份登记册发布段 PG 契约（NG-ID g1 批次 B1，Opt-in
// AUTHZ_TEST_PG_DSN——单元运行不需要活动数据库）：
// ListEnabledMachineIdentities 只含 ENABLED 身份（DISABLED 及其键不出现——发布面安全语义
// 锚定）且键行全状态下发（ACTIVE/RETIRED/REVOKED+retire_overlap_until+revoked_seq 溯源）、
// identity_name/kid 稳定序、RFC3339 时间形状；ListAllMachineIdentityBindings 全行稳定序；
// LoadMachineIdentityMeta 撤销水位=单行 seq、registry_version=身份+键两表 max(updated_at)
// Unix 毫秒（确定性与空登记册=0 断言）。
// 数据经 apimachineid.Store 真事务构造（轮换/撤销状态机语义由 apimachineid_pg_test.go 覆盖）。
package guardconfig

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/apimachineid"
	"github.com/jiuzhang-waf/server/internal/database"
)

func openMIDPublishPG(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("AUTHZ_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_PG_DSN not set, skipping machine identity publish segment PG test")
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

// 测试用公钥 PEM（合法 ed25519 PKIX 形态；发布段原样透传不做密码学校验——
// 导入侧 apimachineid.Store 已按 §1.3 解析校验）。
const midPubTestPEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n"

func TestMachineIdentityPublishSegmentPostgresContract(t *testing.T) {
	pool, ctx := openMIDPublishPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	code := fmt.Sprintf("midpub-%d", time.Now().UnixNano())
	var appID string
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	// 两个 ENABLED 身份（名称序 aaa<zzz）+ 一个 DISABLED 身份
	nameA := fmt.Sprintf("midpub-aaa-%d", time.Now().UnixNano())
	nameZ := fmt.Sprintf("midpub-zzz-%d", time.Now().UnixNano())
	nameOff := fmt.Sprintf("midpub-off-%d", time.Now().UnixNano())
	store := apimachineid.NewStore(pool)
	pubStore := NewMachineIdentityStore(pool)
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM machine_identities WHERE identity_name LIKE 'midpub-%'`)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, appID)
	})

	baseWM, err := pubStore.LoadMachineIdentityMeta(ctx)
	if err != nil {
		t.Fatalf("baseline meta: %v", err)
	}

	if _, err := store.CreateIdentity(ctx, apimachineid.IdentityInput{IdentityName: nameZ}, "tester"); err != nil {
		t.Fatal(err)
	}
	idnA, err := store.CreateIdentity(ctx, apimachineid.IdentityInput{IdentityName: nameA,
		TenantID: strPtrMID("tenant-a"), PrincipalBinding: strPtrMID("fp:principal-1"), BotChallengeExempt: true}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	idnOff, err := store.CreateIdentity(ctx, apimachineid.IdentityInput{IdentityName: nameOff, Status: "DISABLED"}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	// 身份 A 键矩阵：k1 import ACTIVE → rotate k1→k2（k1 RETIRED+窗口）→ revoke k1
	// （REVOKED+revoked_seq 回填）→ import k3 ACTIVE
	k1, err := store.ImportKey(ctx, idnA.ID, apimachineid.KeyInput{Kid: "k1", Alg: "ed25519",
		PublicKeyPEM: midPubTestPEM, NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2028-01-01T00:00:00Z"}, "tester")
	if err != nil {
		t.Fatalf("import k1: %v", err)
	}
	if _, _, err := store.RotateKey(ctx, idnA.ID, k1.ID, apimachineid.KeyInput{Kid: "k2", Alg: "ed25519",
		PublicKeyPEM: midPubTestPEM}, "tester"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	rk, err := store.RevokeKey(ctx, idnA.ID, k1.ID)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := store.ImportKey(ctx, idnA.ID, apimachineid.KeyInput{Kid: "k3", Alg: "ed25519",
		PublicKeyPEM: midPubTestPEM}, "tester"); err != nil {
		t.Fatalf("import k3: %v", err)
	}
	// DISABLED 身份挂键（不得随发布段出现）
	if _, err := store.ImportKey(ctx, idnOff.ID, apimachineid.KeyInput{Kid: "k9", Alg: "ed25519",
		PublicKeyPEM: midPubTestPEM}, "tester"); err != nil {
		t.Fatalf("import disabled key: %v", err)
	}
	// 绑定（PROTECT+proof_required 与 OBSERVE 各一）
	if _, err := store.CreateBinding(ctx, apimachineid.BindingInput{ApplicationID: appID, PathPrefix: "/api",
		Mode: "PROTECT", ProofRequired: true}, "tester"); err != nil {
		t.Fatalf("binding1: %v", err)
	}
	if _, err := store.CreateBinding(ctx, apimachineid.BindingInput{ApplicationID: appID, PathExact: "/health"}, "tester"); err != nil {
		t.Fatalf("binding2: %v", err)
	}

	// ① 发布段身份：ENABLED-only（nameOff 不出现）+identity_name 稳定序+全状态键行
	ids, err := pubStore.ListEnabledMachineIdentities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var idxA, idxZ = -1, -1
	for i := range ids {
		switch ids[i].IdentityName {
		case nameA:
			idxA = i
		case nameZ:
			idxZ = i
		case nameOff:
			t.Fatal("DISABLED 身份不得出现在发布段")
		}
	}
	if idxA < 0 || idxZ < 0 || idxA > idxZ {
		t.Fatalf("ENABLED 身份稳定序（%s 应先于 %s）: idxA=%d idxZ=%d", nameA, nameZ, idxA, idxZ)
	}
	ga := ids[idxA]
	if ga.Status != "ENABLED" || ga.TenantID == nil || *ga.TenantID != "tenant-a" ||
		ga.PrincipalBinding == nil || *ga.PrincipalBinding != "fp:principal-1" || !ga.BotChallengeExempt {
		t.Fatalf("身份头形状: %+v", ga)
	}
	if len(ga.Keys) != 3 || ga.Keys[0].Kid != "k1" || ga.Keys[1].Kid != "k2" || ga.Keys[2].Kid != "k3" {
		t.Fatalf("键行 kid 稳定序: %+v", ga.Keys)
	}
	gk1 := ga.Keys[0]
	if gk1.Status != "REVOKED" || gk1.RevokedSeq == nil || *gk1.RevokedSeq != *rk.RevokedSeq ||
		gk1.RetireOverlapUntil == nil {
		t.Fatalf("k1 REVOKED+revoked_seq+窗口残留（溯源）: %+v", gk1)
	}
	if gk1.NotBefore == nil || *gk1.NotBefore != "2026-01-01T00:00:00Z" ||
		gk1.NotAfter == nil || *gk1.NotAfter != "2028-01-01T00:00:00Z" {
		t.Fatalf("k1 有效期 RFC3339 形状: %+v", gk1)
	}
	if gk1.Alg != "ed25519" || gk1.PublicKeyPEM == "" {
		t.Fatalf("k1 alg/PEM 透传: %+v", gk1)
	}
	if ga.Keys[1].Status != "ACTIVE" || ga.Keys[1].RetireOverlapUntil != nil || ga.Keys[1].RevokedSeq != nil ||
		ga.Keys[1].NotBefore != nil {
		t.Fatalf("k2 ACTIVE 形状（可空键 nil）: %+v", ga.Keys[1])
	}
	if ga.Keys[2].Status != "ACTIVE" {
		t.Fatalf("k3 ACTIVE: %+v", ga.Keys[2])
	}
	if len(ids[idxZ].Keys) != 0 {
		t.Fatalf("无键身份 keys 应为空集（非 nil——冻结形状键恒在）: %+v", ids[idxZ].Keys)
	}
	// ② 发布段绑定：全行（含 PROTECT 行）+稳定序（/api 先于 /health? COALESCE 序按路径串）
	bindings, err := pubStore.ListAllMachineIdentityBindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var foundP, foundH bool
	for _, x := range bindings {
		if x.ApplicationID != appID {
			continue
		}
		switch {
		case x.PathPrefix == "/api":
			foundP = true
			if x.Mode != "PROTECT" || !x.ProofRequired || x.PathExact != "" {
				t.Fatalf("PROTECT 绑定行形状: %+v", x)
			}
		case x.PathExact == "/health":
			foundH = true
			if x.Mode != "OBSERVE" || x.ProofRequired || x.PathPrefix != "" {
				t.Fatalf("OBSERVE 绑定行形状: %+v", x)
			}
		}
	}
	if !foundP || !foundH {
		t.Fatalf("发布段应含两条绑定: %+v", bindings)
	}
	// ③ meta：水位=撤销推进后 seq；registry_version=两表 max(updated_at) Unix 毫秒现算一致
	meta, err := pubStore.LoadMachineIdentityMeta(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if meta.RevocationWatermark != baseWM.RevocationWatermark+1 {
		t.Fatalf("水位应推进 +1: base=%d got=%d", baseWM.RevocationWatermark, meta.RevocationWatermark)
	}
	var wantRegistry int64
	if err := pool.QueryRow(ctx, `SELECT COALESCE((
		SELECT max(ms) FROM (
			SELECT (extract(epoch from updated_at)*1000)::bigint AS ms FROM machine_identities
			UNION ALL
			SELECT (extract(epoch from updated_at)*1000)::bigint FROM machine_identity_keys
		) t), 0)`).Scan(&wantRegistry); err != nil {
		t.Fatal(err)
	}
	if meta.RegistryVersion != wantRegistry || meta.RegistryVersion <= 0 {
		t.Fatalf("registry_version 推导一致性: got=%d want=%d", meta.RegistryVersion, wantRegistry)
	}
	// 空登记册=0：清空测试身份后（两表无行）registry_version 归零——用独立空库语义
	// 折算：删除全部本测试身份与键后直查推导式
	if _, err := pool.Exec(ctx, `DELETE FROM machine_identities WHERE identity_name LIKE 'midpub-%'`); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM machine_identities`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining == 0 {
		var zeroRegistry int64
		if err := pool.QueryRow(ctx, `SELECT COALESCE((
			SELECT max(ms) FROM (
				SELECT (extract(epoch from updated_at)*1000)::bigint AS ms FROM machine_identities
				UNION ALL
				SELECT (extract(epoch from updated_at)*1000)::bigint FROM machine_identity_keys
			) t), 0)`).Scan(&zeroRegistry); err != nil {
			t.Fatal(err)
		}
		if zeroRegistry != 0 {
			t.Fatalf("空登记册 registry_version 应=0: %d", zeroRegistry)
		}
	}
}

func strPtrMID(v string) *string { return &v }
