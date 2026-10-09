// service_integration_test.go 权威关系接入真实 PG 集成测试（NG-AZ-01；迁移 000172 契约）。
// 依赖一次性 PostgreSQL：AUTHORITY_TEST_PG_DSN 未设置时 t.Skip（环境不可用如实跳过）。
// 覆盖：登记→delta 导入→relations 溯源可见→重放幂等→缺口与补齐→冲突状态→
// 撤销水位与冲突自动解除→snapshot 原子切换（坏行零变更）→snapshot 域内替换→
// 乱序/陈旧拒收→停用来源拒收。
package apiauthzauthority

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func authorityTestDSN() string { return os.Getenv("AUTHORITY_TEST_PG_DSN") }

func openAuthorityPostgres(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := authorityTestDSN()
	if dsn == "" {
		t.Skip("AUTHORITY_TEST_PG_DSN not set, skipping authority PG integration test")
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
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	var applied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version = 172`).Scan(&applied); err != nil {
		t.Fatalf("check migration record: %v", err)
	}
	if applied != 1 {
		t.Fatalf("migration 172 records=%d, want 1", applied)
	}
	return pool, ctx
}

// seedApp 建测试应用 + ACTIVE 域（tenant_domain 解析前提）。
func seedApp(t *testing.T, ctx context.Context, pool *pgxpool.Pool, domain string) uuid.UUID {
	t.Helper()
	var appID uuid.UUID
	err := pool.QueryRow(ctx, `
INSERT INTO applications (code, name, status, protection_mode)
VALUES ($1, 'az-it-app', 'ACTIVE', 'OFF')
RETURNING id`, "azit"+uuid.NewString()[:8]).Scan(&appID)
	if err != nil {
		t.Fatalf("create app: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO application_domains (application_id, hostname, normalized_hostname, domain_type, is_primary, status)
VALUES ($1, $2, $2, 'EXACT', true, 'ACTIVE')`, appID, domain); err != nil {
		t.Fatalf("create app domain: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM applications WHERE id = $1`, appID)
	})
	return appID
}

func mkSource(t *testing.T, svc *Service, name, domain string, k *testKey) *AuthoritySource {
	t.Helper()
	// 名称加唯一后缀：集成套件共享一次性库（重复运行不撞 UNIQUE 约束）
	src, err := svc.CreateSource(context.Background(), name+"-"+uuid.NewString()[:8], SourceScopes{
		TenantDomains: []string{domain}, ObjectTypes: []string{"document"},
	}, nil, []SourceKey{{KeyID: k.keyID, PublicKeyHex: k.pubHex()}})
	if err != nil {
		t.Fatalf("CreateSource: %v", err)
	}
	return src
}

// itEvent 构造事件（objectRef 由调用方给定——同对象多 OWNER 是冲突语义，测试按对象维度隔离）。
func itEvent(t *testing.T, src *AuthoritySource, k *testKey, domain string, seq uint64, eventID, principal, changeType, objectRef string, now time.Time) ChangeEvent {
	t.Helper()
	e := ChangeEvent{
		SourceID: src.ID.String(), EventID: eventID, KeyID: k.keyID, Sequence: seq,
		ObjectType: "document", TenantDomain: domain,
		PrincipalRef: principal, ObjectRef: objectRef,
		Relation: "OWNER", ChangeType: changeType,
		ValidFrom: now.Add(-time.Hour).Format(time.RFC3339),
		IssuedAt:  now.Format(time.RFC3339),
	}
	return k.signEvent(t, e)
}

func itBatch(t *testing.T, src *AuthoritySource, k *testKey, mode string, events ...ChangeEvent) []byte {
	t.Helper()
	p := ImportBatchPayload{
		BatchID: "b-" + uuid.NewString()[:8], SourceID: src.ID.String(), Mode: mode, KeyID: k.keyID,
		Items: events,
	}
	p = k.signBatch(t, p)
	return payloadBody(t, p)
}

func relationOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, appID uuid.UUID, objectRef, principal string) (source, status string, traceSourceID uuid.NullUUID, eventID string) {
	t.Helper()
	var sid *uuid.UUID
	err := pool.QueryRow(ctx, `
SELECT source, status, source_id, source_event_id FROM api_object_relations
WHERE application_id=$1 AND object_type='document' AND object_ref=$2 AND principal_id=$3
ORDER BY created_at DESC LIMIT 1`, appID, objectRef, principal).Scan(&source, &status, &sid, &eventID)
	if err != nil {
		t.Fatalf("relationOf(%s): %v", principal, err)
	}
	if sid != nil {
		traceSourceID = uuid.NullUUID{UUID: *sid, Valid: true}
	}
	return source, status, traceSourceID, eventID
}

func TestAuthorityImportEndToEnd(t *testing.T) {
	pool, ctx := openAuthorityPostgres(t)
	domain := "az-it-" + uuid.NewString()[:6] + ".local"
	appID := seedApp(t, ctx, pool, domain)
	svc := NewService(NewStore(pool))
	k1 := newTestKey(t, "k1")
	src := mkSource(t, svc, "crm-it", domain, k1)
	now := time.Now().UTC()

	// 1) delta GRANT 导入 → relations 溯源可见
	objMain := "objref:main-" + uuid.NewString()[:8]
	e1 := itEvent(t, src, k1, domain, 1, "evt-1", "subj:alice", "GRANT", objMain, now)
	batch, err := svc.Import(ctx, src.ID, itBatch(t, src, k1, ModeDelta, e1), uuid.New())
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if batch.Status != BatchApplied || batch.Counts.Applied != 1 || batch.Counts.Grants != 1 {
		t.Fatalf("批次不符: %+v", batch)
	}
	source, status, traceSrc, evtID := relationOf(t, ctx, pool, appID, objMain, "subj:alice")
	if source != "AUTHORITY_SYNC" || status != "CONFIRMED" || !traceSrc.Valid || traceSrc.UUID != src.ID || evtID != "evt-1" {
		t.Fatalf("溯源不符: source=%s status=%s trace=%+v evt=%s", source, status, traceSrc, evtID)
	}

	// 2) 重发同批 → applied=0 / skipped_duplicate=1（重放幂等）
	batch2, err := svc.Import(ctx, src.ID, itBatch(t, src, k1, ModeDelta, e1), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if batch2.Status != BatchApplied || batch2.Counts.Applied != 0 || batch2.Counts.SkippedDuplicate != 1 {
		t.Fatalf("重放幂等不符: %+v", batch2.Counts)
	}

	// 3) sequence 跳号（2→5）→ AUTHZ_SOURCE_GAP + gap_from=3
	e2 := itEvent(t, src, k1, domain, 2, "evt-2", "subj:bob", "GRANT", "objref:o2-"+uuid.NewString()[:8], now)
	e5 := itEvent(t, src, k1, domain, 5, "evt-5", "subj:carol", "GRANT", "objref:o5-"+uuid.NewString()[:8], now)
	if _, err := svc.Import(ctx, src.ID, itBatch(t, src, k1, ModeDelta, e2), uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Import(ctx, src.ID, itBatch(t, src, k1, ModeDelta, e5), uuid.New()); err != nil {
		t.Fatal(err)
	}
	wm, err := svc.GetWatermark(ctx, src.ID)
	if err != nil {
		t.Fatal(err)
	}
	if wm.GapFrom == nil || *wm.GapFrom != 3 {
		t.Fatalf("缺口应 gap_from=3: %+v", wm)
	}
	// 补齐 3、4 → 缺口自动消除
	e3 := itEvent(t, src, k1, domain, 3, "evt-3", "subj:dave", "GRANT", "objref:o3-"+uuid.NewString()[:8], now)
	e4 := itEvent(t, src, k1, domain, 4, "evt-4", "subj:erin", "GRANT", "objref:o4-"+uuid.NewString()[:8], now)
	if _, err := svc.Import(ctx, src.ID, itBatch(t, src, k1, ModeDelta, e3, e4), uuid.New()); err != nil {
		t.Fatal(err)
	}
	wm, _ = svc.GetWatermark(ctx, src.ID)
	if wm.GapFrom != nil {
		t.Fatalf("补齐后缺口应消除: %+v", wm)
	}
	if wm.LastSequence != 5 {
		t.Fatalf("水位应推进到 5: %+v", wm)
	}

	// 4) 同序号重放（sequence 已消费、event_id 全新）→ 整批拒收；
	//    缺口补齐（序号在缺口、event_id 未消费）属合法新事实（上面 3/4 已实证消除缺口）
	eDup := itEvent(t, src, k1, domain, 5, "evt-99", "subj:mallory", "GRANT", "objref:o99-"+uuid.NewString()[:8], now)
	batchDup, err := svc.Import(ctx, src.ID, itBatch(t, src, k1, ModeDelta, eDup), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if batchDup.Status != BatchRejected || !strings.Contains(batchDup.Error, "同序号重放拒收") {
		t.Fatalf("同序号重放应拒收: %+v", batchDup)
	}
	// 批内乱序（sequence 降序）→ 拒收展示
	e6 := itEvent(t, src, k1, domain, 6, "evt-6", "subj:frank", "GRANT", "objref:o6-"+uuid.NewString()[:8], now)
	e7 := itEvent(t, src, k1, domain, 7, "evt-7", "subj:grace", "GRANT", "objref:o7-"+uuid.NewString()[:8], now)
	batchUnsorted, err := svc.Import(ctx, src.ID, itBatch(t, src, k1, ModeDelta, e7, e6), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if batchUnsorted.Status != BatchRejected || !strings.Contains(batchUnsorted.Error, "升序") {
		t.Fatalf("批内乱序应拒收: %+v", batchUnsorted)
	}
}

func TestAuthorityConflictAndRevokeWatermark(t *testing.T) {
	pool, ctx := openAuthorityPostgres(t)
	domain := "az-cf-" + uuid.NewString()[:6] + ".local"
	appID := seedApp(t, ctx, pool, domain)
	svc := NewService(NewStore(pool))
	kA := newTestKey(t, "kA")
	kB := newTestKey(t, "kB")
	srcA := mkSource(t, svc, "crm-a", domain, kA)
	srcB := mkSource(t, svc, "crm-b", domain, kB)
	now := time.Now().UTC()

	// A 授 alice；B 对同对象签 bob（不同 principal）→ 冲突，不落 bob 行，alice 不被覆盖
	objShared := "objref:cf-" + uuid.NewString()[:8]
	eA := itEvent(t, srcA, kA, domain, 1, "evt-a1", "subj:alice", "GRANT", objShared, now)
	if _, err := svc.Import(ctx, srcA.ID, itBatch(t, srcA, kA, ModeDelta, eA), uuid.New()); err != nil {
		t.Fatal(err)
	}
	eB := itEvent(t, srcB, kB, domain, 1, "evt-b1", "subj:bob", "GRANT", objShared, now)
	bB, err := svc.Import(ctx, srcB.ID, itBatch(t, srcB, kB, ModeDelta, eB), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if bB.Status != BatchApplied || bB.Counts.Conflicts != 1 || bB.Counts.Grants != 0 {
		t.Fatalf("冲突批次不符: %+v", bB.Counts)
	}
	conflicts, err := svc.ListConflicts(ctx, ConflictOpen, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range conflicts {
		if c.ObjectRef == objShared && len(c.Principals) == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("冲突列表应出现该对象: %+v", conflicts)
	}
	// alice 不被覆盖（仍是 CONFIRMED）；bob 无 CONFIRMED 行
	_, statusA, _, _ := relationOf(t, ctx, pool, appID, objShared, "subj:alice")
	if statusA != "CONFIRMED" {
		t.Fatalf("冲突不得覆盖既有 OWNER: %s", statusA)
	}
	var bobRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM api_object_relations
		WHERE application_id=$1 AND principal_id='subj:bob' AND status='CONFIRMED'`, appID).Scan(&bobRows); err != nil {
		t.Fatal(err)
	}
	if bobRows != 0 {
		t.Fatal("冲突 GRANT 不落关系行")
	}

	// A 撤销 alice → 撤销水位推进 + 冲突自动解除（单 owner 收敛）
	eRev := itEvent(t, srcA, kA, domain, 2, "evt-a2", "subj:alice", "REVOKE", objShared, now)
	if _, err := svc.Import(ctx, srcA.ID, itBatch(t, srcA, kA, ModeDelta, eRev), uuid.New()); err != nil {
		t.Fatal(err)
	}
	wm, _ := svc.GetWatermark(ctx, srcA.ID)
	if wm.RevocationWatermark != 2 {
		t.Fatalf("撤销水位应推进到 2: %+v", wm)
	}
	conflicts, _ = svc.ListConflicts(ctx, ConflictOpen, 10)
	for _, c := range conflicts {
		if c.ObjectRef == objShared {
			t.Fatalf("撤销后冲突应自动解除: %+v", c)
		}
	}
	// 撤销水位单调不下降（后续无 REVOKE 批次不拉低）
	eA3 := itEvent(t, srcA, kA, domain, 3, "evt-a3", "subj:zoe", "GRANT", "objref:z1-"+uuid.NewString()[:8], now)
	if _, err := svc.Import(ctx, srcA.ID, itBatch(t, srcA, kA, ModeDelta, eA3), uuid.New()); err != nil {
		t.Fatal(err)
	}
	wm, _ = svc.GetWatermark(ctx, srcA.ID)
	if wm.RevocationWatermark != 2 {
		t.Fatalf("撤销水位不得下降: %+v", wm)
	}
}

func TestAuthoritySnapshotAtomicAndSwitch(t *testing.T) {
	pool, ctx := openAuthorityPostgres(t)
	domain := "az-sn-" + uuid.NewString()[:6] + ".local"
	appID := seedApp(t, ctx, pool, domain)
	svc := NewService(NewStore(pool))
	k := newTestKey(t, "k1")
	src := mkSource(t, svc, "crm-snap", domain, k)
	now := time.Now().UTC()

	// 先行 delta 建立两行（两对象隔离，避免互相冲突）
	objA := "objref:sa-" + uuid.NewString()[:8]
	objB := "objref:sb-" + uuid.NewString()[:8]
	objC := "objref:sc-" + uuid.NewString()[:8]
	e1 := itEvent(t, src, k, domain, 1, "evt-d1", "subj:alice", "GRANT", objA, now)
	e2 := itEvent(t, src, k, domain, 2, "evt-d2", "subj:bob", "GRANT", objB, now)
	if _, err := svc.Import(ctx, src.ID, itBatch(t, src, k, ModeDelta, e1, e2), uuid.New()); err != nil {
		t.Fatal(err)
	}

	// snapshot 中途坏行（relation 非法）→ 整批拒绝且 relations 零变化（原子性）
	bad := itEvent(t, src, k, domain, 3, "evt-s1", "subj:carol", "GRANT", objC, now)
	bad.Relation = "SHARED_WITH"
	bad = k.signEvent(t, bad)
	snapBad, err := svc.Import(ctx, src.ID, itBatch(t, src, k, ModeSnapshot, bad), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if snapBad.Status != BatchRejected {
		t.Fatalf("坏行 snapshot 应整批拒绝: %+v", snapBad)
	}
	var cnt int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM api_object_relations
		WHERE application_id=$1 AND source='AUTHORITY_SYNC' AND status='CONFIRMED'`, appID).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 2 {
		t.Fatalf("原子性：拒绝后应仍为 2 行（零变更）, got %d", cnt)
	}

	// 合法 snapshot（只含 carol）→ 域内原子替换：alice/bob 权威行被撤销、carol 落位
	s1 := itEvent(t, src, k, domain, 4, "evt-s4", "subj:carol", "GRANT", objC, now)
	snap, err := svc.Import(ctx, src.ID, itBatch(t, src, k, ModeSnapshot, s1), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Status != BatchApplied {
		t.Fatalf("snapshot 应应用: %+v", snap)
	}
	var alive int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM api_object_relations
		WHERE application_id=$1 AND source='AUTHORITY_SYNC' AND status='CONFIRMED'`, appID).Scan(&alive); err != nil {
		t.Fatal(err)
	}
	if alive != 1 {
		t.Fatalf("snapshot 切换后应仅剩 carol 一行有效: %d", alive)
	}
	_, st, _, _ := relationOf(t, ctx, pool, appID, objC, "subj:carol")
	if st != "CONFIRMED" {
		t.Fatalf("carol 应 CONFIRMED: %s", st)
	}
	// 陈旧 snapshot（最大 sequence ≤ 水位）→ 拒收
	stale := itEvent(t, src, k, domain, 2, "evt-s9", "subj:dave", "GRANT", "objref:sd-"+uuid.NewString()[:8], now)
	snapStale, err := svc.Import(ctx, src.ID, itBatch(t, src, k, ModeSnapshot, stale), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if snapStale.Status != BatchRejected || !strings.Contains(snapStale.Error, "陈旧快照") {
		t.Fatalf("陈旧快照应拒收: %+v", snapStale)
	}
}

func TestAuthorityDisabledSourceRejected(t *testing.T) {
	pool, ctx := openAuthorityPostgres(t)
	domain := "az-ds-" + uuid.NewString()[:6] + ".local"
	seedApp(t, ctx, pool, domain)
	svc := NewService(NewStore(pool))
	k := newTestKey(t, "k1")
	src := mkSource(t, svc, "crm-disabled", domain, k)
	now := time.Now().UTC()
	// 停用来源
	if _, _, err := svc.PatchSource(ctx, src.ID, SourcePatch{
		Status: strPtr(SourceStatusDisabled), Version: src.Version}); err != nil {
		t.Fatal(err)
	}
	e := itEvent(t, src, k, domain, 1, "evt-x1", "subj:alice", "GRANT", "objref:x1-"+uuid.NewString()[:8], now)
	batch, err := svc.Import(ctx, src.ID, itBatch(t, src, k, ModeDelta, e), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if batch.Status != BatchRejected || !strings.Contains(batch.Error, "停用") {
		t.Fatalf("停用来源应拒收: %+v", batch)
	}
	// 未登记来源 → 第 1 步拒收（handler 映射前 service 已拒）
	b2, err := svc.Import(ctx, uuid.New(), itBatch(t, src, k, ModeDelta, e), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if b2.Status != BatchRejected {
		t.Fatalf("未登记来源应拒收: %+v", b2)
	}
}

func strPtr(s string) *string { return &s }

var _ = fmt.Sprintf
