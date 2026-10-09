// strongflow_integration_test.go 强流程定义 PG 契约测试（NG-FLOW-01 D9）：
// 迁移 000176 up/up/down/up 幂等与约束；版本冻结真事务语义（同名新草稿 version+1、
// 激活即冻结、activate 同事务 RETIRED 旧 ACTIVE、部分唯一索引恰一个 ACTIVE、
// RETIRED 单向）；activate 端点归属核对（绑定前缀+CONFIRMED 拒收路径）。
// Opt-in（AUTHZ_TEST_PG_DSN）——单元运行不需要活动数据库。
package strongflow

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
	"github.com/jiuzhang-waf/server/internal/database"
)

func openStrongFlowPG(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("AUTHZ_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_PG_DSN not set, skipping strongflow PG test")
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

func TestStrongFlowMigration176PostgresContract(t *testing.T) {
	pool, ctx := openStrongFlowPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("rerun migrations: %v", err)
	}
	var applied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=176`).Scan(&applied); err != nil {
		t.Fatalf("check migration record: %v", err)
	}
	if applied != 1 {
		t.Fatalf("migration 176 records=%d, want 1", applied)
	}
	for _, table := range []string{"api_strong_flow_definitions", "api_strong_flow_steps"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if !exists {
			t.Fatalf("table %s missing after migration", table)
		}
	}
	// 词表 CHECK：status/mode/retry_semantics 词表外拒收
	var appID string
	code := fmt.Sprintf("sf176-%d", time.Now().UnixNano())
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&appID); err != nil {
		t.Fatalf("insert application: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_strong_flow_steps WHERE definition_id IN (SELECT id FROM api_strong_flow_definitions WHERE application_id=$1)`, appID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_strong_flow_definitions WHERE application_id=$1`, appID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM applications WHERE id=$1`, appID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO api_strong_flow_definitions(application_id,name,version,binding_path_prefix,instance_key_param,status) VALUES ($1,'f',1,'/a','query:x','PENDING')`, appID); err == nil {
		t.Fatal("status=PENDING must be rejected by CHECK")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO api_strong_flow_definitions(application_id,name,version,binding_path_prefix,instance_key_param,mode) VALUES ($1,'f',1,'/a','query:x','BLOCK')`, appID); err == nil {
		t.Fatal("mode=BLOCK must be rejected by CHECK")
	}
	// down 十步：先回滚 000185（升级任务 executor_deadline 列，NG-REL-02 F7）、
	// 000184/000183（NG-ID 机器身份四表）、000182/000181（NG-MCP 批次 B1 两表）、
	// 000180/000179（NG-GRPC 绑定两迁移）、000178（NG-FLOW-03 RESOLVE 词表放宽）
	// 与 000177（NG-FLOW-02 实例表，本测试不覆盖其结构——177/178 契约见各自
	// 测试组），再回滚 176 到 175 基线
	for _, v := range []int{185, 184, 183, 182, 181, 180, 179, 178, 177, 176} {
		if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
			t.Fatalf("migrate down %d: %v", v, err)
		}
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('api_strong_flow_definitions') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatalf("check after down: %v", err)
	}
	if exists {
		t.Fatal("table must be dropped after down")
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("migrate up again: %v", err)
	}
}

// TestStrongFlowVersionFreezePostgresContract 版本冻结真事务语义（D1）。
func TestStrongFlowVersionFreezePostgresContract(t *testing.T) {
	pool, ctx := openStrongFlowPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	code := fmt.Sprintf("sffrz-%d", time.Now().UnixNano())
	var appID, endpointID string
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&appID); err != nil {
		t.Fatalf("insert application: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_endpoints(application_id,http_method,normalized_path,endpoint_key,asset_status) VALUES ($1,'POST','/api/v1/orders','POST /api/v1/orders','CONFIRMED') RETURNING id`, appID).Scan(&endpointID); err != nil {
		t.Fatalf("insert endpoint: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_steps WHERE definition_id IN (SELECT id FROM api_strong_flow_definitions WHERE application_id=$1)`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_definitions WHERE application_id=$1`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_endpoints WHERE id=$1`, endpointID)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, appID)
	})

	store := NewStore(pool)
	in := DefinitionInput{
		ApplicationID: appID, Name: "下单支付", BindingPathPrefix: "/api/v1/orders",
		InstanceKeyParam: "query:order_id", Mode: "OBSERVE",
		Steps: []StepInput{{StepKey: "create", EndpointKey: "POST /api/v1/orders", Sequence: 1,
			SuccessRule: &SuccessRule{StatusCodes: []int{200}}, TimeoutSeconds: 30,
			RetrySemantics: "IDEMPOTENT", LeaseSeconds: 60}},
	}

	// ① 新建 version=1 DRAFT
	d1, err := store.Create(ctx, in, uuid.New(), "tester")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if d1.Version != 1 || d1.Status != StatusDraft {
		t.Fatalf("v1=(%d,%s) want (1,DRAFT)", d1.Version, d1.Status)
	}
	// ② 同名再创 → version=2 新草稿（D1 编辑产新草稿承载）
	d2, err := store.Create(ctx, in, uuid.New(), "tester")
	if err != nil {
		t.Fatalf("create v2: %v", err)
	}
	if d2.Version != 2 || d2.Status != StatusDraft {
		t.Fatalf("v2=(%d,%s) want (2,DRAFT)", d2.Version, d2.Status)
	}
	// ③ activate v1：DRAFT→ACTIVE（端点归属核对通过）
	a1, err := store.Activate(ctx, d1.ID)
	if err != nil {
		t.Fatalf("activate v1: %v", err)
	}
	if a1.Status != StatusActive || a1.ActivatedAt == nil {
		t.Fatalf("activate v1 status=%s activated_at=%v", a1.Status, a1.ActivatedAt)
	}
	// ④ ACTIVE 后编辑 409 哨兵（激活即冻结）
	if _, err := store.Update(ctx, d1.ID, in); err != ErrNotDraft {
		t.Fatalf("ACTIVE 编辑应 ErrNotDraft: %v", err)
	}
	// ⑤ 再激活 ACTIVE → ErrNotDraft
	if _, err := store.Activate(ctx, d1.ID); err != ErrNotDraft {
		t.Fatalf("再激活应 ErrNotDraft: %v", err)
	}
	// ⑥ activate v2 → v1 同事务 RETIRED（恰一个 ACTIVE 由部分唯一索引兜底）
	if _, err := store.Activate(ctx, d2.ID); err != nil {
		t.Fatalf("activate v2: %v", err)
	}
	var v1Status, v2Status string
	if err := pool.QueryRow(ctx, `SELECT status FROM api_strong_flow_definitions WHERE id=$1`, d1.ID).Scan(&v1Status); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM api_strong_flow_definitions WHERE id=$1`, d2.ID).Scan(&v2Status); err != nil {
		t.Fatal(err)
	}
	if v1Status != StatusRetired || v2Status != StatusActive {
		t.Fatalf("activate v2 后 v1=%s v2=%s, want RETIRED/ACTIVE", v1Status, v2Status)
	}
	// ⑦ retire ACTIVE → RETIRED；再 retire ErrInvalidTransition（单向终态）
	if err := store.Retire(ctx, d2.ID); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if err := store.Retire(ctx, d2.ID); err != ErrInvalidTransition {
		t.Fatalf("重复 retire 应 ErrInvalidTransition: %v", err)
	}
	// ⑧ RETIRED 编辑/激活均拒
	if _, err := store.Update(ctx, d2.ID, in); err != ErrNotDraft {
		t.Fatalf("RETIRED 编辑应 ErrNotDraft: %v", err)
	}
	if _, err := store.Activate(ctx, d2.ID); err != ErrNotDraft {
		t.Fatalf("RETIRED 激活应 ErrNotDraft: %v", err)
	}
}

// TestStrongFlowActivateEndpointCheckContract activate 端点归属核对拒收路径
// （绑定前缀外/未 CONFIRMED 端点 400 语义 ValidationError）。
func TestStrongFlowActivateEndpointCheckContract(t *testing.T) {
	pool, ctx := openStrongFlowPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	code := fmt.Sprintf("sfep-%d", time.Now().UnixNano())
	var appID string
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&appID); err != nil {
		t.Fatalf("insert application: %v", err)
	}
	var epOK, epCandidate string
	if err := pool.QueryRow(ctx, `INSERT INTO api_endpoints(application_id,http_method,normalized_path,endpoint_key,asset_status) VALUES ($1,'POST','/api/v1/orders','POST /api/v1/orders','CONFIRMED') RETURNING id`, appID).Scan(&epOK); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_endpoints(application_id,http_method,normalized_path,endpoint_key,asset_status) VALUES ($1,'POST','/api/v1/orders/pay','POST /api/v1/orders/pay','CANDIDATE') RETURNING id`, appID).Scan(&epCandidate); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_steps WHERE definition_id IN (SELECT id FROM api_strong_flow_definitions WHERE application_id=$1)`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_definitions WHERE application_id=$1`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_endpoints WHERE id IN ($1,$2)`, epOK, epCandidate)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, appID)
	})
	store := NewStore(pool)

	// 前缀外端点 → 激活拒绝
	inBad := DefinitionInput{
		ApplicationID: appID, Name: "坏流程", BindingPathPrefix: "/api/v1/orders",
		InstanceKeyParam: "query:order_id", Steps: []StepInput{{StepKey: "x", EndpointKey: "POST /api/v1/users", Sequence: 1,
			SuccessRule: &SuccessRule{StatusCodes: []int{200}}, TimeoutSeconds: 30, RetrySemantics: "IDEMPOTENT", LeaseSeconds: 60}},
	}
	d, err := store.Create(ctx, inBad, uuid.New(), "tester")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := store.Activate(ctx, d.ID); err == nil || !isValidationErr(err, "不属于绑定前缀") {
		t.Fatalf("前缀外端点应拒绝: %v", err)
	}

	// 未 CONFIRMED 端点 → 激活拒绝
	inCandidate := DefinitionInput{
		ApplicationID: appID, Name: "候选端点流程", BindingPathPrefix: "/api/v1/orders",
		InstanceKeyParam: "query:order_id", Steps: []StepInput{{StepKey: "pay", EndpointKey: "POST /api/v1/orders/pay", Sequence: 1,
			SuccessRule: &SuccessRule{StatusCodes: []int{200}}, TimeoutSeconds: 30, RetrySemantics: "IDEMPOTENT", LeaseSeconds: 60}},
	}
	d2, err := store.Create(ctx, inCandidate, uuid.New(), "tester")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := store.Activate(ctx, d2.ID); err == nil || !isValidationErr(err, "CONFIRMED") {
		t.Fatalf("未 CONFIRMED 端点应拒绝: %v", err)
	}

	// 空步骤定义 → 激活拒绝（ErrNoSteps）
	inEmpty := DefinitionInput{
		ApplicationID: appID, Name: "空流程", BindingPathPrefix: "/api/v1/orders",
		InstanceKeyParam: "query:order_id", Steps: []StepInput{{StepKey: "tmp", EndpointKey: "POST /api/v1/orders", Sequence: 1,
			SuccessRule: &SuccessRule{StatusCodes: []int{200}}, TimeoutSeconds: 30, RetrySemantics: "IDEMPOTENT", LeaseSeconds: 60}},
	}
	d3, err := store.Create(ctx, inEmpty, uuid.New(), "tester")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM api_strong_flow_steps WHERE definition_id=$1`, d3.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(ctx, d3.ID); err != ErrNoSteps {
		t.Fatalf("空步骤激活应 ErrNoSteps: %v", err)
	}
}

func isValidationErr(err error, substr string) bool {
	var ve *ValidationError
	if !errors.As(err, &ve) {
		return false
	}
	return substr == "" || containsStr(ve.Msg, substr)
}

func containsStr(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOfStr(s, sub) >= 0)
}

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestStrongFlowEventConsumePostgresContract 强流程事件消费（NG-FLOW-02 D9）：
// 全 action 词表落库、幂等去重、状态机合法推进与非法如实记录（REJECTED/FLOW-STATE-001）、
// UNKNOWN 披露落库、步骤事件先于实例创建的乱序自愈建行。
func TestStrongFlowEventConsumePostgresContract(t *testing.T) {
	pool, ctx := openStrongFlowPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	code := fmt.Sprintf("sfev-%d", time.Now().UnixNano())
	var appID, defID string
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&appID); err != nil {
		t.Fatalf("insert application: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_strong_flow_definitions(application_id,name,version,status,binding_path_prefix,instance_key_param) VALUES ($1,'下单支付',3,'ACTIVE','/api/v1/orders','query:order_id') RETURNING id`, appID).Scan(&defID); err != nil {
		t.Fatalf("insert definition: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_step_events WHERE instance_id IN (SELECT id FROM api_strong_flow_instances WHERE application_id=$1)`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_instances WHERE application_id=$1`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_definitions WHERE application_id=$1`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, appID)
	})

	store := NewStrongFlowEventStore(pool)
	now := time.Now().UTC()
	sfref := InstanceRefHMAC([]byte(strings.Repeat("ef", 32)), "order-42")
	mk := func(action, result, reason string, fencing int64, stepKey string) *StrongFlowEvent {
		return &StrongFlowEvent{
			DefinitionID: defID, DefinitionVersion: 3, InstanceID: sfref,
			StepKey: stepKey, Action: action, FencingToken: fencing, LeaseSeconds: 60,
			Result: result, ReasonCode: reason, RequestID: "req-" + action,
			ApplicationID: appID, TenantRef: "tref:aa", PrincipalRef: "pref:bb",
			OccurredAt: now,
		}
	}

	// ① INSTANCE_NEW 建实例行（五态初始 ACTIVE）+ 事件落行
	if err := store.RecordStrongFlow(ctx, mk(ActionInstanceNew, ResultOK, "", 0, "")); err != nil {
		t.Fatalf("INSTANCE_NEW: %v", err)
	}
	var instID uuid.UUID
	var status string
	var version int
	if err := pool.QueryRow(ctx, `SELECT id, status, version FROM api_strong_flow_instances
		WHERE definition_id=$1 AND definition_version=3 AND instance_key=$2`, defID, sfref).Scan(&instID, &status, &version); err != nil {
		t.Fatalf("read instance: %v", err)
	}
	if status != "ACTIVE" || version != 1 {
		t.Fatalf("initial=(%s,%d) want (ACTIVE,1)", status, version)
	}

	// ② 步骤事件四词落库（RESERVE/COMMIT/RELEASE/EXPIRE）+ 幂等去重（同键重发不重复）
	for i, action := range []string{ActionReserve, ActionCommit, ActionRelease, ActionExpire} {
		ev := mk(action, ResultOK, "", int64(i+1), "create")
		if err := store.RecordStrongFlow(ctx, ev); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		// 重放（同 fencing 同动作）——去重
		if err := store.RecordStrongFlow(ctx, ev); err != nil {
			t.Fatalf("%s replay: %v", action, err)
		}
	}
	var stepEvents int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM api_strong_flow_step_events WHERE instance_id=$1`, instID).Scan(&stepEvents); err != nil {
		t.Fatal(err)
	}
	if stepEvents != 5 { // INSTANCE_NEW + 四词各一（重放去重）
		t.Fatalf("step_events=%d want 5（重放去重）", stepEvents)
	}

	// ③ 合法推进：ACTIVE→INDETERMINATE（UNKNOWN 披露如实落库）
	evUnknown := mk(ActionInstanceIndeterminate, ResultUnknown, "FLOW-TIMEOUT-001", 0, "")
	if err := store.RecordStrongFlow(ctx, evUnknown); err != nil {
		t.Fatalf("INSTANCE_INDETERMINATE: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT status, version FROM api_strong_flow_instances WHERE id=$1`, instID).Scan(&status, &version); err != nil {
		t.Fatal(err)
	}
	if status != "INDETERMINATE" || version != 2 {
		t.Fatalf("after indeterminate=(%s,%d) want (INDETERMINATE,2)", status, version)
	}
	var reason string
	if err := pool.QueryRow(ctx, `SELECT reason_code FROM api_strong_flow_step_events WHERE instance_id=$1 AND action='INSTANCE_INDETERMINATE'`, instID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "FLOW-TIMEOUT-001" {
		t.Fatalf("UNKNOWN 披露 reason=%q want FLOW-TIMEOUT-001", reason)
	}

	// ④ 非法转换：INDETERMINATE→CANCELLED（不在合法表）——实例不动 + REJECTED/FLOW-STATE-001 留痕
	if err := store.RecordStrongFlow(ctx, mk(ActionInstanceCancelled, ResultOK, "", 0, "")); err != nil {
		t.Fatalf("illegal transition record: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT status, version FROM api_strong_flow_instances WHERE id=$1`, instID).Scan(&status, &version); err != nil {
		t.Fatal(err)
	}
	if status != "INDETERMINATE" || version != 2 {
		t.Fatalf("非法转换后实例不得动: (%s,%d)", status, version)
	}
	var rejResult, rejReason string
	if err := pool.QueryRow(ctx, `SELECT result, reason_code FROM api_strong_flow_step_events WHERE instance_id=$1 AND action='INSTANCE_CANCELLED'`, instID).Scan(&rejResult, &rejReason); err != nil {
		t.Fatal(err)
	}
	if rejResult != ResultRejected || rejReason != "FLOW-STATE-001" {
		t.Fatalf("非法转换留痕=(%s,%s) want (REJECTED,FLOW-STATE-001)", rejResult, rejReason)
	}

	// ⑤ 对账恢复：INDETERMINATE→CONFIRMED（合法）→ 终态 terminated_at 落
	if err := store.RecordStrongFlow(ctx, mk(ActionInstanceConfirmed, ResultOK, "", 0, "")); err != nil {
		t.Fatalf("INSTANCE_CONFIRMED: %v", err)
	}
	var terminated *time.Time
	if err := pool.QueryRow(ctx, `SELECT status, terminated_at FROM api_strong_flow_instances WHERE id=$1`, instID).Scan(&status, &terminated); err != nil {
		t.Fatal(err)
	}
	if status != "CONFIRMED" || terminated == nil {
		t.Fatalf("confirmed=(%s,terminated=%v)", status, terminated)
	}
	// 终态后任何推进非法
	if err := store.RecordStrongFlow(ctx, mk(ActionInstanceFailed, ResultOK, "", 0, "")); err != nil {
		t.Fatalf("terminal transition record: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM api_strong_flow_instances WHERE id=$1`, instID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "CONFIRMED" {
		t.Fatalf("终态不得被覆盖: %s", status)
	}

	// ⑥ 边界校验拒收：词表外 action / 非 sfref 形态 instance_id
	bad := mk(ActionReserve, ResultOK, "", 1, "create")
	bad.InstanceID = "order-42"
	if err := store.RecordStrongFlow(ctx, bad); err == nil || !strings.Contains(err.Error(), "sfref") {
		t.Fatalf("非 sfref 形态应拒收: %v", err)
	}
	bad2 := mk("HACK", ResultOK, "", 1, "create")
	if err := store.RecordStrongFlow(ctx, bad2); err == nil || !strings.Contains(err.Error(), "action") {
		t.Fatalf("action 词表外应拒收: %v", err)
	}

	// ⑦ instances 列表查询（应用过滤+状态过滤+分页）
	items, total, err := NewStore(pool).ListInstances(ctx, uuid.MustParse(appID), "CONFIRMED", nil, 1, 20)
	if err != nil {
		t.Fatalf("list instances: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Status != "CONFIRMED" || items[0].DefinitionName != "下单支付" {
		t.Fatalf("instances=(%d,%+v)", total, items)
	}
	_, totalFiltered, err := NewStore(pool).ListInstances(ctx, uuid.MustParse(appID), "ACTIVE", nil, 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	if totalFiltered != 0 {
		t.Fatalf("status 过滤应为空: %d", totalFiltered)
	}
}
