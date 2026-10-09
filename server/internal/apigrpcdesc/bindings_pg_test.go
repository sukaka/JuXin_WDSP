// bindings_pg_test.go gRPC 描述符 per-app 绑定 PG 契约（NG-GRPC G1 批次 B1，
// Opt-in AUTHZ_TEST_PG_DSN——单元运行不需要活动数据库）：
// 迁移 000179 up/up/down/up 幂等与词表 CHECK；唯一键（应用,服务）拒收；FK
// （描述符集名/应用）拒收与级联删除；CRUD 真事务语义（乐观锁两态）；发布段
// 读取（全行稳定排序）；未登记服务差集（绑定应用按绑定集判定、无绑定应用
// 按全局 ENABLED 集判定、绑定应用未绑定服务按未登记）。
package apigrpcdesc

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
	"github.com/jiuzhang-waf/server/internal/guardconfig"
)

func openBindingsPG(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("AUTHZ_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_PG_DSN not set, skipping grpc bindings PG test")
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

func TestGrpcBindingsMigration179PostgresContract(t *testing.T) {
	pool, ctx := openBindingsPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("rerun migrations: %v", err)
	}
	var applied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=179`).Scan(&applied); err != nil {
		t.Fatalf("check migration record: %v", err)
	}
	if applied != 1 {
		t.Fatalf("migration 179 records=%d, want 1", applied)
	}
	// 词表 CHECK：mode 词表外拒收、service 形态拒收（大写开头/连字符/空段/超长）
	var appID, setID string
	code := fmt.Sprintf("gb179-%d", time.Now().UnixNano())
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_grpc_descriptors(name,content,content_hash,services) VALUES ('gb179-set','\x00','`+strings.Repeat("a", 64)+`','[]') RETURNING id`).Scan(&setID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM api_grpc_bindings WHERE application_id=$1`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_grpc_descriptors WHERE id=$1`, setID)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, appID)
	})
	mk := func(service, mode string) error {
		_, err := pool.Exec(ctx, `INSERT INTO api_grpc_bindings(application_id,service,descriptor_name,mode) VALUES ($1,$2,'gb179-set',$3)`, appID, service, mode)
		return err
	}
	if err := mk("pkg.svc", "BLOCK"); err == nil {
		t.Fatal("mode=BLOCK 应被 CHECK 拒收")
	}
	for _, bad := range []string{"Pkg.svc", "pkg-orders.svc", "pkg..svc", "pkg.svc."} {
		if err := mk(bad, "OBSERVE"); err == nil {
			t.Fatalf("service %q 应被 CHECK 拒收", bad)
		}
	}
	if err := mk("pkg.svc", "OBSERVE"); err != nil {
		t.Fatalf("合法绑定应通过: %v", err)
	}
	// 唯一键（应用,服务）：同键拒收
	if err := mk("pkg.svc", "PROTECT"); err == nil {
		t.Fatal("同（应用,服务）重复绑定应被唯一索引拒收")
	}
	// FK：描述符集名不存在拒收
	if _, err := pool.Exec(ctx, `INSERT INTO api_grpc_bindings(application_id,service,descriptor_name) VALUES ($1,'pkg.ghost','ghost-set')`, appID); err == nil {
		t.Fatal("引用不存在描述符集应被 FK 拒收")
	}
	// FK：应用不存在拒收
	if _, err := pool.Exec(ctx, `INSERT INTO api_grpc_bindings(application_id,service,descriptor_name) VALUES ($1,'pkg.ghost2','gb179-set')`, uuid.New()); err == nil {
		t.Fatal("引用不存在应用应被 FK 拒收")
	}
	// 级联：删描述符集 → 绑定级联删除
	if _, err := pool.Exec(ctx, `DELETE FROM api_grpc_descriptors WHERE id=$1`, setID); err != nil {
		t.Fatal(err)
	}
	var remain int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM api_grpc_bindings WHERE application_id=$1`, appID).Scan(&remain); err != nil {
		t.Fatal(err)
	}
	if remain != 0 {
		t.Fatalf("描述符集删除应级联删绑定: %d", remain)
	}
	// down 七步：先回滚 000185（升级任务 executor_deadline 列，NG-REL-02 F7）、
	// 000184/000183（NG-ID 机器身份四表）、000182/000181（NG-MCP 批次 B1 两表），
	// 再回滚 000180（批次 C 词表放宽），再回滚 000179 到 178 基线（表消失）；复 up
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 185: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 184: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 183: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 182: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 181: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 180: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 179: %v", err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('api_grpc_bindings') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("down 后绑定表应被移除")
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("migrate up again: %v", err)
	}
}

// TestGrpcBindingsCRUDPostgresContract CRUD 真事务语义 + 发布段读取 + 差集。
func TestGrpcBindingsCRUDPostgresContract(t *testing.T) {
	pool, ctx := openBindingsPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	code := fmt.Sprintf("gbcrud-%d", time.Now().UnixNano())
	var appA, appB string
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&appA); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code+"b", code+"b").Scan(&appB); err != nil {
		t.Fatal(err)
	}
	summary := `[{"service":"pkg.orders.payment","methods":[{"name":"Pay","input_type":".pkg.Req","output_type":".pkg.Resp"}]},{"service":"pkg.echo","methods":[{"name":"Ping","input_type":".pkg.Req","output_type":".pkg.Resp"}]}]`
	if _, err := pool.Exec(ctx, `INSERT INTO api_grpc_descriptors(name,content,content_hash,services) VALUES ('set-a','\x00','`+strings.Repeat("b", 64)+`',$1)`, summary); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM api_grpc_bindings WHERE application_id IN ($1,$2)`, appA, appB)
		_, _ = pool.Exec(bg, `DELETE FROM api_endpoints WHERE application_id IN ($1,$2)`, appA, appB)
		_, _ = pool.Exec(bg, `DELETE FROM api_grpc_descriptors WHERE name='set-a'`)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id IN ($1,$2)`, appA, appB)
	})
	store := NewStore(pool)

	// ① Create + mode 缺省归一 + 稳定排序（ListAllGRPCBindings 发布段形状）
	b, err := store.CreateBinding(ctx, BindingInput{ApplicationID: appA, Service: "pkg.orders.payment", DescriptorName: "set-a", Mode: ""}, "tester")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if b.Mode != ModeObserve || b.Version != 1 {
		t.Fatalf("缺省归一: %+v", b)
	}
	// 同键 409 哨兵
	if _, err := store.CreateBinding(ctx, BindingInput{ApplicationID: appA, Service: "pkg.orders.payment", DescriptorName: "set-a", Mode: "PROTECT"}, "tester"); err != ErrBindingDuplicate {
		t.Fatalf("同键应 ErrBindingDuplicate: %v", err)
	}
	// ② Update 乐观锁两态
	if _, err := store.UpdateBinding(ctx, b.ID, BindingInput{DescriptorName: "set-a", Mode: "PROTECT", Version: 9}); err != ErrBindingVersionConflict {
		t.Fatalf("版本冲突应 ErrBindingVersionConflict: %v", err)
	}
	b2, err := store.UpdateBinding(ctx, b.ID, BindingInput{DescriptorName: "set-a", Mode: "PROTECT", Version: 1})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if b2.Mode != ModeProtect || b2.Version != 2 {
		t.Fatalf("update 结果: %+v", b2)
	}
	// ③ 发布段读取（guardconfig 仓储：全行稳定排序；GuardGRPCBinding 形状）
	pub, err := guardconfig.NewGRPCBindingStore(pool).ListAllGRPCBindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range pub {
		if x.ApplicationID == appA && x.Service == "pkg.orders.payment" {
			found = true
			if x.DescriptorName != "set-a" || x.Mode != ModeProtect {
				t.Fatalf("发布段行: %+v", x)
			}
		}
	}
	if !found {
		t.Fatalf("发布段应含绑定: %+v", pub)
	}

	// ④ 未登记服务差集（种 api_endpoints protocol_type='GRPC'）：
	//    appA（绑定应用）：pkg.orders.payment 已绑定且 set-a 含 Pay → 已登记；
	//    pkg.unknown 未绑定 → 未登记（绑定应用不再享全局集）；
	//    appB（无绑定）：pkg.echo/Ping 在全局集 → 已登记；pkg.other/Do 不在 → 未登记。
	mkEP := func(appID, ek string) {
		if _, err := pool.Exec(ctx, `INSERT INTO api_endpoints(application_id,http_method,normalized_path,endpoint_key,asset_status,protocol_type)
			VALUES ($1,'POST',substring($2 from 6),$2,'CONFIRMED','GRPC')`, appID, ek); err != nil {
			t.Fatal(err)
		}
	}
	mkEP(appA, "POST /pkg.orders.payment/Pay")
	mkEP(appA, "POST /pkg.unknown/Go")
	mkEP(appB, "POST /pkg.echo/Ping")
	mkEP(appB, "POST /pkg.other/Do")
	undoc, err := store.ListUndocumentedServices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, u := range undoc {
		got[u.ApplicationID.String()+"/"+u.Service] = u.Methods
	}
	if len(got) != 2 {
		t.Fatalf("差集应恰两条（appA/pkg.unknown + appB/pkg.other）: %+v", got)
	}
	if got[appA+"/pkg.unknown"] == nil || got[appA+"/pkg.unknown"][0] != "Go" {
		t.Fatalf("绑定应用未绑定服务应按未登记: %+v", got)
	}
	if got[appB+"/pkg.other"] == nil || got[appB+"/pkg.other"][0] != "Do" {
		t.Fatalf("无绑定应用未覆盖方法应按未登记: %+v", got)
	}

	// ⑤ Delete 200/404
	if err := store.DeleteBinding(ctx, b.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := store.DeleteBinding(ctx, b.ID); err != ErrBindingNotFound {
		t.Fatalf("重复 delete 应 ErrBindingNotFound: %v", err)
	}
}

// TestGrpcBindingServiceVocabMigration180PostgresContract 词表裁决 PG 契约
// （批次 C，Opt-in）：迁移 000180 up 后大写驼峰服务名 CHECK 通过（echo.EchoService/
// pkg.orders.PaymentService）；包段大写仍拒（Pkg.svc——包段小写 snake 保留收紧）；
// down 恢复全小写 CHECK（大写行清理后回缩成功）。
func TestGrpcBindingServiceVocabMigration180PostgresContract(t *testing.T) {
	pool, ctx := openBindingsPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	var applied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=180`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("migration 180 records=%d, want 1", applied)
	}
	var appID, setID string
	code := fmt.Sprintf("gb180-%d", time.Now().UnixNano())
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_grpc_descriptors(name,content,content_hash,services) VALUES ('gb180-set','\x00','`+strings.Repeat("c", 64)+`','[]') RETURNING id`).Scan(&setID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM api_grpc_bindings WHERE application_id=$1`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_grpc_descriptors WHERE id=$1`, setID)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, appID)
	})
	// 大写驼峰服务名通过（裁决对齐 protobuf 实际规则）
	for _, svc := range []string{"echo.EchoService", "pkg.orders.PaymentService", "Echo"} {
		if _, err := pool.Exec(ctx, `INSERT INTO api_grpc_bindings(application_id,service,descriptor_name) VALUES ($1,$2,'gb180-set')`, appID, svc); err != nil {
			t.Fatalf("大写服务名 %q 应通过: %v", svc, err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM api_grpc_bindings WHERE application_id=$1 AND service=$2`, appID, svc); err != nil {
			t.Fatal(err)
		}
	}
	// 包段大写仍拒（包段小写 snake 保留收紧）；空白/连字符/空段仍拒
	for _, bad := range []string{"Pkg.svc", "pkg-orders.svc", "pkg..svc", " pkg.svc", "pkg.svc "} {
		if _, err := pool.Exec(ctx, `INSERT INTO api_grpc_bindings(application_id,service,descriptor_name) VALUES ($1,$2,'gb180-set')`, appID, bad); err == nil {
			t.Fatalf("service %q 应被 CHECK 拒收", bad)
		}
	}
	// down 六步：先回滚 000185（升级任务 executor_deadline 列，NG-REL-02 F7）、
	// 000184/000183（NG-ID 机器身份四表）、000182/000181（NG-MCP 批次 B1 两表），
	// 再回滚 000180 恢复全小写 CHECK（大写行已清→回缩成功；再次插入大写应拒）
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 185: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 184: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 183: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 182: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 181: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 180: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO api_grpc_bindings(application_id,service,descriptor_name) VALUES ($1,'echo.EchoService','gb180-set')`, appID); err == nil {
		t.Fatal("down 后大写服务名应被 CHECK 拒收")
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("migrate up again: %v", err)
	}
}
