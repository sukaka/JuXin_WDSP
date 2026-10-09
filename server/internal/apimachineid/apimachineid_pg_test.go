// apimachineid_pg_test.go 机器身份登记 PG 契约（NG-ID g1 批次 B1，Opt-in
// AUTHZ_TEST_PG_DSN——单元运行不需要活动数据库）：
// 迁移 000183/000184 up/up/down×3/up 幂等与词表 CHECK（身份 status / 键 alg / 键 status /
// 有效期窗口 / 绑定 mode / selector 二选一 / path 形态 / 水位哨兵与 seq 非负）；唯一键
// （identity_name、(identity_id,kid)、(application_id,COALESCE(path_exact,path_prefix))）拒收；
// FK 拒收与级联（删身份级联键、删应用级联绑定）；水位种子 seq=0（down/up 后断言）；
// store 真事务语义（rotate 原子=新 ACTIVE+旧 RETIRED+重叠窗口；revoke 与水位 seq+1
// 同一事务原子提交+revoked_seq 回填+水位只增单调）。
package apimachineid

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func openMIDPG(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("AUTHZ_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_PG_DSN not set, skipping machine identity PG test")
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

func mkMIDApp(t *testing.T, pool *pgxpool.Pool, ctx context.Context, prefix string) string {
	t.Helper()
	code := fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	var id string
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestMachineIdentityMigrationPostgresContract(t *testing.T) {
	pool, ctx := openMIDPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("rerun migrations: %v", err)
	}
	for _, v := range []int{183, 184} {
		var applied int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=$1`, v).Scan(&applied); err != nil {
			t.Fatal(err)
		}
		if applied != 1 {
			t.Fatalf("migration %d records=%d, want 1", v, applied)
		}
	}
	appID := mkMIDApp(t, pool, ctx, "mid183")
	idName := fmt.Sprintf("mid183-id-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM machine_identities WHERE identity_name LIKE 'mid183-%'`)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, appID)
	})
	var identityID string
	if err := pool.QueryRow(ctx, `INSERT INTO machine_identities(identity_name) VALUES ($1) RETURNING id`, idName).Scan(&identityID); err != nil {
		t.Fatal(err)
	}
	// 身份词表 CHECK：status 词表外拒收
	if _, err := pool.Exec(ctx, `INSERT INTO machine_identities(identity_name,status) VALUES ('mid183-x','SUSPENDED')`); err == nil {
		t.Fatal("status=SUSPENDED 应被 CHECK 拒收")
	}
	// identity_name 唯一
	if _, err := pool.Exec(ctx, `INSERT INTO machine_identities(identity_name) VALUES ($1)`, idName); err == nil {
		t.Fatal("同名身份应被唯一约束拒收")
	}
	// 键合法行
	var keyID string
	if err := pool.QueryRow(ctx, `INSERT INTO machine_identity_keys(identity_id,kid,alg,public_key_pem)
		VALUES ($1,'k1','ed25519','-----BEGIN PUBLIC KEY-----\\nx\\n-----END PUBLIC KEY-----') RETURNING id`, identityID).Scan(&keyID); err != nil {
		t.Fatalf("合法键行应通过: %v", err)
	}
	// 键词表 CHECK 矩阵
	for name, sql := range map[string]string{
		"alg 词表（hmac-sha256 排除）":     `INSERT INTO machine_identity_keys(identity_id,kid,alg,public_key_pem) VALUES ($1,'t1','hmac-sha256','p')`,
		"alg 词表（rsa-v1_5-sha256 排除）": `INSERT INTO machine_identity_keys(identity_id,kid,alg,public_key_pem) VALUES ($1,'t2','rsa-v1_5-sha256','p')`,
		"键 status 词表":                `INSERT INTO machine_identity_keys(identity_id,kid,alg,public_key_pem,status) VALUES ($1,'t3','ed25519','p','BOGUS')`,
		"有效期窗口倒置":                    `INSERT INTO machine_identity_keys(identity_id,kid,alg,public_key_pem,not_before,not_after) VALUES ($1,'t4','ed25519','p','2027-01-01T00:00:00Z','2026-01-01T00:00:00Z')`,
	} {
		if _, err := pool.Exec(ctx, sql, identityID); err == nil {
			t.Fatalf("%s 应被 CHECK 拒收", name)
		}
	}
	// (identity_id, kid) 唯一
	if _, err := pool.Exec(ctx, `INSERT INTO machine_identity_keys(identity_id,kid,alg,public_key_pem) VALUES ($1,'k1','ed25519','p')`, identityID); err == nil {
		t.Fatal("同（身份,kid）应被唯一约束拒收")
	}
	// 键 FK：身份不存在拒收
	if _, err := pool.Exec(ctx, `INSERT INTO machine_identity_keys(identity_id,kid,alg,public_key_pem) VALUES ($1,'ghost','ed25519','p')`, uuid.New()); err == nil {
		t.Fatal("引用不存在身份应被 FK 拒收")
	}
	// 绑定词表 CHECK：mode / selector 二缺一 / path 形态
	if _, err := pool.Exec(ctx, `INSERT INTO machine_identity_bindings(application_id,path_prefix,mode) VALUES ($1,'/api','BLOCK')`, appID); err == nil {
		t.Fatal("mode=BLOCK 应被 CHECK 拒收")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO machine_identity_bindings(application_id,path_exact,path_prefix) VALUES ($1,'/a','/a')`, appID); err == nil {
		t.Fatal("selector 两者都给应被 CHECK 拒收")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO machine_identity_bindings(application_id) VALUES ($1)`, appID); err == nil {
		t.Fatal("selector 两者都空应被 CHECK 拒收")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO machine_identity_bindings(application_id,path_exact) VALUES ($1,'api')`, appID); err == nil {
		t.Fatal("path_exact 非 / 开头应被 CHECK 拒收")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO machine_identity_bindings(application_id,path_prefix) VALUES ($1,'/a?x=1')`, appID); err == nil {
		t.Fatal("path 含 query 应被 CHECK 拒收")
	}
	if err := pool.QueryRow(ctx, `INSERT INTO machine_identity_bindings(application_id,path_prefix,mode,proof_required)
		VALUES ($1,'/api','PROTECT',true) RETURNING id`, appID).Scan(new(string)); err != nil {
		t.Fatalf("合法绑定应通过: %v", err)
	}
	// (application_id, COALESCE(path_exact,path_prefix)) 唯一——path_exact='/api' 与
	// 既有 path_prefix='/api' 归一为同键拒收（exact/prefix 语义不同但同路径恰一条绑定）
	if _, err := pool.Exec(ctx, `INSERT INTO machine_identity_bindings(application_id,path_exact) VALUES ($1,'/api')`, appID); err == nil {
		t.Fatal("同（应用,归一路径）应被唯一索引拒收")
	}
	// 绑定 FK：应用不存在拒收
	if _, err := pool.Exec(ctx, `INSERT INTO machine_identity_bindings(application_id,path_prefix) VALUES ($1,'/ghost')`, uuid.New()); err == nil {
		t.Fatal("引用不存在应用应被 FK 拒收")
	}
	// 水位：单行种子存在；哨兵 id=1 CHECK；seq 非负 CHECK
	var seeded int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM machine_identity_revocation_watermark WHERE id=1`).Scan(&seeded); err != nil {
		t.Fatal(err)
	}
	if seeded != 1 {
		t.Fatalf("水位种子行应恰一条: %d", seeded)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO machine_identity_revocation_watermark(id,seq) VALUES (2,0)`); err == nil {
		t.Fatal("哨兵 id≠1 应被 CHECK 拒收")
	}
	if _, err := pool.Exec(ctx, `UPDATE machine_identity_revocation_watermark SET seq=-1 WHERE id=1`); err == nil {
		t.Fatal("seq 负数应被 CHECK 拒收")
	}
	// 级联：删身份 → 键级联删除
	if _, err := pool.Exec(ctx, `DELETE FROM machine_identities WHERE id=$1`, identityID); err != nil {
		t.Fatal(err)
	}
	var keyRemain int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM machine_identity_keys WHERE identity_id=$1`, identityID).Scan(&keyRemain); err != nil {
		t.Fatal(err)
	}
	if keyRemain != 0 {
		t.Fatalf("身份删除应级联清空键行: %d", keyRemain)
	}
	// 级联：删应用 → 绑定级联删除
	if _, err := pool.Exec(ctx, `DELETE FROM applications WHERE id=$1`, appID); err != nil {
		t.Fatal(err)
	}
	var bindRemain int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM machine_identity_bindings WHERE application_id=$1`, appID).Scan(&bindRemain); err != nil {
		t.Fatal(err)
	}
	if bindRemain != 0 {
		t.Fatalf("应用删除应级联删绑定: %d", bindRemain)
	}
	// down 三步（185 → 184 → 183）：先回滚 000185（升级任务 executor_deadline 列，
	// NG-REL-02 F7）再回滚 184/183——四表消失；复 up 恢复且水位种子 seq=0 重建
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 185: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 184: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 183: %v", err)
	}
	for _, table := range []string{"machine_identity_bindings", "machine_identity_revocation_watermark",
		"machine_identity_keys", "machine_identities"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Fatalf("down 后 %s 应被移除", table)
		}
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("migrate up again: %v", err)
	}
	var seq int64
	if err := pool.QueryRow(ctx, `SELECT seq FROM machine_identity_revocation_watermark WHERE id=1`).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	if seq != 0 {
		t.Fatalf("复 up 后水位种子应 seq=0: %d", seq)
	}
}

func TestMachineIdentityStorePostgresContract(t *testing.T) {
	pool, ctx := openMIDPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	appID := mkMIDApp(t, pool, ctx, "midcrud")
	name := fmt.Sprintf("midcrud-%d", time.Now().UnixNano())
	store := NewStore(pool)
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM machine_identities WHERE identity_name=$1`, name)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, appID)
	})

	// ① 身份 Create：缺省 ENABLED/version=1；同名 ErrDuplicateName
	idn, err := store.CreateIdentity(ctx, IdentityInput{IdentityName: name, TenantID: strPtr("tenant-a"),
		PrincipalBinding: strPtr("fp:principal-1"), BotChallengeExempt: true}, "tester")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if idn.Status != StatusEnabled || idn.Version != 1 || idn.CreatedBy != "tester" ||
		idn.TenantID == nil || *idn.TenantID != "tenant-a" || !idn.BotChallengeExempt {
		t.Fatalf("身份归一: %+v", idn)
	}
	if _, err := store.CreateIdentity(ctx, IdentityInput{IdentityName: name}, "tester"); err != ErrDuplicateName {
		t.Fatalf("同名应 ErrDuplicateName: %v", err)
	}
	// ② 公钥导入：ACTIVE+指纹现算；kid 重 ErrKeyDuplicate；身份缺失 ErrNotFound；
	//    alg 与 PEM 键型不符 ValidationError（§1.3 一致性核对）
	pem1 := mustPublicKeyPEM(t, AlgEd25519)
	k1, err := store.ImportKey(ctx, idn.ID, KeyInput{Kid: "k1", Alg: AlgEd25519, PublicKeyPEM: pem1,
		NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2028-01-01T00:00:00Z"}, "tester")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	_, wantFP, err := ParsePublicKey(AlgEd25519, pem1)
	if err != nil {
		t.Fatal(err)
	}
	if k1.Status != KeyStatusActive || k1.KeyFingerprint != wantFP || k1.NotBefore == nil || k1.NotAfter == nil {
		t.Fatalf("导入落账（指纹现算+有效期）: %+v", k1)
	}
	if _, err := store.ImportKey(ctx, idn.ID, KeyInput{Kid: "k1", Alg: AlgEd25519, PublicKeyPEM: pem1}, "tester"); err != ErrKeyDuplicate {
		t.Fatalf("kid 重应 ErrKeyDuplicate: %v", err)
	}
	if _, err := store.ImportKey(ctx, uuid.New(), KeyInput{Kid: "k9", Alg: AlgEd25519, PublicKeyPEM: pem1}, "tester"); err != ErrNotFound {
		t.Fatalf("身份缺失应 ErrNotFound: %v", err)
	}
	var ve *ValidationError
	if _, err := store.ImportKey(ctx, idn.ID, KeyInput{Kid: "k2", Alg: AlgRSAPSSSHA512, PublicKeyPEM: pem1}, "tester"); !errors.As(err, &ve) {
		t.Fatalf("alg/键型不符应 ValidationError: %v", err)
	}
	// ③ 轮换（§1.6 原子）：新 ACTIVE+旧 RETIRED+重叠窗口（显式 48h）；DB 复核同事务落账
	pem2 := mustPublicKeyPEM(t, AlgEd25519)
	overlap := 48
	newK, oldK, err := store.RotateKey(ctx, idn.ID, k1.ID, KeyInput{Kid: "k2", Alg: AlgEd25519,
		PublicKeyPEM: pem2, OverlapHours: &overlap}, "tester")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if newK.Status != KeyStatusActive || newK.Kid != "k2" {
		t.Fatalf("新键形态: %+v", newK)
	}
	if oldK.Status != KeyStatusRetired || oldK.RetireOverlapUntil == nil {
		t.Fatalf("旧键 RETIRED+窗口: %+v", oldK)
	}
	if d := time.Until(*oldK.RetireOverlapUntil); d < 47*time.Hour || d > 49*time.Hour {
		t.Fatalf("重叠窗口应约 48h: %v", d)
	}
	var dbOldStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM machine_identity_keys WHERE id=$1`, k1.ID).Scan(&dbOldStatus); err != nil {
		t.Fatal(err)
	}
	if dbOldStatus != KeyStatusRetired {
		t.Fatalf("DB 旧键状态: %s", dbOldStatus)
	}
	// RETIRED 再轮换 → ErrKeyStateConflict；ghost → ErrKeyNotFound；新 kid 冲突 → ErrKeyDuplicate
	if _, _, err := store.RotateKey(ctx, idn.ID, k1.ID, KeyInput{Kid: "k3", Alg: AlgEd25519, PublicKeyPEM: pem1}, "tester"); err != ErrKeyStateConflict {
		t.Fatalf("RETIRED 再轮换应 ErrKeyStateConflict: %v", err)
	}
	if _, _, err := store.RotateKey(ctx, idn.ID, uuid.New(), KeyInput{Kid: "k3", Alg: AlgEd25519, PublicKeyPEM: pem1}, "tester"); err != ErrKeyNotFound {
		t.Fatalf("ghost 轮换应 ErrKeyNotFound: %v", err)
	}
	if _, _, err := store.RotateKey(ctx, idn.ID, newK.ID, KeyInput{Kid: "k1", Alg: AlgEd25519, PublicKeyPEM: pem1}, "tester"); err != ErrKeyDuplicate {
		t.Fatalf("新 kid 冲突应 ErrKeyDuplicate: %v", err)
	}
	// ④ 撤销（§1.6 原子）：撤销事实与水位 seq+1 同一事务；revoked_seq 回填溯源；水位只增单调
	base, err := store.CurrentWatermark(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := store.RevokeKey(ctx, idn.ID, k1.ID) // RETIRED → REVOKED
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if rk.Status != KeyStatusRevoked || rk.RevokedSeq == nil || *rk.RevokedSeq != base+1 {
		t.Fatalf("撤销落账（水位回填）: %+v base=%d", rk, base)
	}
	wm, err := store.CurrentWatermark(ctx)
	if err != nil || wm != base+1 {
		t.Fatalf("水位应推进 %d→%d: wm=%d err=%v", base, base+1, wm, err)
	}
	var dbSeq int64
	if err := pool.QueryRow(ctx, `SELECT revoked_seq FROM machine_identity_keys WHERE id=$1`, k1.ID).Scan(&dbSeq); err != nil {
		t.Fatal(err)
	}
	if dbSeq != base+1 {
		t.Fatalf("DB revoked_seq 溯源: %d, want %d", dbSeq, base+1)
	}
	if _, err := store.RevokeKey(ctx, idn.ID, k1.ID); err != ErrKeyStateConflict {
		t.Fatalf("重复撤销应 ErrKeyStateConflict: %v", err)
	}
	if _, err := store.RevokeKey(ctx, idn.ID, uuid.New()); err != ErrKeyNotFound {
		t.Fatalf("ghost 撤销应 ErrKeyNotFound: %v", err)
	}
	rk2, err := store.RevokeKey(ctx, idn.ID, newK.ID) // ACTIVE → REVOKED，水位只增
	if err != nil {
		t.Fatalf("revoke2: %v", err)
	}
	if rk2.RevokedSeq == nil || *rk2.RevokedSeq != base+2 {
		t.Fatalf("水位单调: %+v, want seq=%d", rk2, base+2)
	}
	// ⑤ 列表：键状态摘要+水位随列表带出
	list, listWM, err := store.ListIdentities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if listWM != base+2 {
		t.Fatalf("列表水位: %d, want %d", listWM, base+2)
	}
	var found *IdentitySummary
	for i := range list {
		if list[i].ID == idn.ID {
			found = &list[i]
		}
	}
	if found == nil || found.KeyCount != 2 || found.RevokedKeys != 2 || found.ActiveKeys != 0 {
		t.Fatalf("列表摘要: %+v", found)
	}
	// ⑥ 身份 Update 乐观锁两态；Get 详情键行 kid 稳定序
	if _, err := store.UpdateIdentity(ctx, idn.ID, IdentityInput{IdentityName: name, Version: 9}); err != ErrVersionConflict {
		t.Fatalf("乐观锁冲突应 ErrVersionConflict: %v", err)
	}
	upd, err := store.UpdateIdentity(ctx, idn.ID, IdentityInput{IdentityName: name, Status: "DISABLED", Version: 1})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if upd.Version != 2 || upd.Status != StatusDisabled || upd.TenantID != nil {
		t.Fatalf("更新落账（可空字段归 nil）: %+v", upd)
	}
	_, keys, err := store.GetIdentity(ctx, idn.ID)
	if err != nil || len(keys) != 2 || keys[0].Kid != "k1" || keys[1].Kid != "k2" {
		t.Fatalf("详情键行（kid 稳定序）: %+v err=%v", keys, err)
	}
	if _, _, err := store.GetIdentity(ctx, uuid.New()); err != ErrNotFound {
		t.Fatalf("ghost 详情应 ErrNotFound: %v", err)
	}
	// ⑦ 绑定 CRUD：同（应用,path）ErrBindingDuplicate；应用缺失 ErrAppNotFound；乐观锁两态
	b, err := store.CreateBinding(ctx, BindingInput{ApplicationID: appID, PathPrefix: "/api", Mode: "PROTECT", ProofRequired: true}, "tester")
	if err != nil {
		t.Fatalf("binding create: %v", err)
	}
	if b.Mode != ModeProtect || !b.ProofRequired || b.Version != 1 || b.PathPrefix != "/api" || b.PathExact != "" {
		t.Fatalf("绑定归一: %+v", b)
	}
	if _, err := store.CreateBinding(ctx, BindingInput{ApplicationID: appID, PathPrefix: "/api"}, "tester"); err != ErrBindingDuplicate {
		t.Fatalf("同键应 ErrBindingDuplicate: %v", err)
	}
	if _, err := store.CreateBinding(ctx, BindingInput{ApplicationID: uuid.NewString(), PathPrefix: "/ghost"}, "tester"); err != ErrAppNotFound {
		t.Fatalf("应用缺失应 ErrAppNotFound: %v", err)
	}
	if _, err := store.UpdateBinding(ctx, b.ID, BindingInput{Mode: "OBSERVE", Version: 9}); err != ErrVersionConflict {
		t.Fatalf("绑定乐观锁冲突应 ErrVersionConflict: %v", err)
	}
	b2, err := store.UpdateBinding(ctx, b.ID, BindingInput{Mode: "OBSERVE", Version: 1})
	if err != nil {
		t.Fatalf("binding update: %v", err)
	}
	if b2.Mode != ModeObserve || b2.ProofRequired || b2.Version != 2 {
		t.Fatalf("绑定更新: %+v", b2)
	}
	blist, err := store.ListBindings(ctx, b.ApplicationID)
	if err != nil || len(blist) != 1 {
		t.Fatalf("绑定列表过滤: %+v err=%v", blist, err)
	}
	// ⑧ 身份删除：存在任一绑定 → ErrIdentityInUse（先解绑再删除）；解绑后删除；键 FK 级联清空
	if err := store.DeleteIdentity(ctx, idn.ID); err != ErrIdentityInUse {
		t.Fatalf("存在绑定删除应 ErrIdentityInUse: %v", err)
	}
	if err := store.DeleteBinding(ctx, b.ID); err != nil {
		t.Fatalf("binding delete: %v", err)
	}
	if err := store.DeleteBinding(ctx, b.ID); err != ErrBindingNotFound {
		t.Fatalf("重复 delete 应 ErrBindingNotFound: %v", err)
	}
	if err := store.DeleteIdentity(ctx, idn.ID); err != nil {
		t.Fatalf("identity delete: %v", err)
	}
	if err := store.DeleteIdentity(ctx, idn.ID); err != ErrNotFound {
		t.Fatalf("重复 delete 应 ErrNotFound: %v", err)
	}
	var keyRemain int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM machine_identity_keys WHERE identity_id=$1`, idn.ID).Scan(&keyRemain); err != nil {
		t.Fatal(err)
	}
	if keyRemain != 0 {
		t.Fatalf("身份删除应 FK 级联清空键行: %d", keyRemain)
	}
}
