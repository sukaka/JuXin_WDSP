// sflow_valkey_it_test.go 强流程 Lua 原子操作真实 Valkey 集成测试（NG-FLOW-02
// F02/F03/F05 语义矩阵；env 门控：SFLOW_VALKEY_IT_ADDR 未设置即跳过——任务纪律
// 不引 miniredis，一次性 Valkey 容器承载真实脚本执行）。
//
// 覆盖：
//   - reserve 全矩阵：新建实例/幂等重放/同键异摘要冲突/异键槽冲突/前置未确认违规/
//     并行组合法并行/终态拒入；
//   - fencing（F05）：lease 过期接管得新 token、旧 token commit 拒绝不覆盖新状态、
//     事件链两次 fencing 值可核对；
//   - commit：错误 token 拒、正确 token 接受、幂等重放、全步骤确认 → 实例 CONFIRMED；
//   - release：同 token 校验、释放后 commit 拒、再预留得新 token；
//   - 幂等（F03）：同键同摘要重试幂等返回、同键异摘要 IDEMPOTENT-CONFLICT-001、
//     不同键重走已 CONFIRMED 步骤违规。
package jiuzhang_guard

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/flowguard"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
)

// sflowITStore 接真实 Valkey 的强流程存储（addr 为空跳过）。
func sflowITStore(t *testing.T) (*flowguard.Store, string) {
	t.Helper()
	addr := os.Getenv("SFLOW_VALKEY_IT_ADDR")
	if addr == "" {
		t.Skip("SFLOW_VALKEY_IT_ADDR 未设置，跳过 Valkey 集成测试")
	}
	cli, err := counters.NewValkeyClient(counters.ValkeyConfig{Address: addr})
	if err != nil {
		t.Fatalf("valkey client: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	// 每用例独立实例键（免 flush 跨用例/跨运行隔离）
	iid := fmt.Sprintf("sfref:it-%d", time.Now().UnixNano())
	return flowguard.NewStore(cli, nil), iid
}

func TestStrongFlowITReserveMatrix(t *testing.T) {
	s, iid := sflowITStore(t)

	// 1. 首步新建实例：OK + token=1 + instance_new
	r1 := s.Reserve(iid, "create", nil, 15, "idem-1", "dig-1", true)
	if r1.Outcome != "OK" || r1.Token != 1 || !r1.InstanceNew {
		t.Fatalf("首步新建 = %+v", r1)
	}
	// 2. 同键同摘要重试：幂等重放既有 token（F03）
	r2 := s.Reserve(iid, "create", nil, 15, "idem-1", "dig-1", true)
	if r2.Outcome != "OK" || !r2.IdempotentReplay || r2.Token != 1 {
		t.Fatalf("幂等重放 = %+v", r2)
	}
	// 3. 同键异摘要：冲突拒绝 IDEMPOTENT-CONFLICT-001（F03）
	r3 := s.Reserve(iid, "create", nil, 15, "idem-1", "dig-2", true)
	if r3.Outcome != "CONFLICT" || r3.Reason != flowguard.ReasonIdempotentConflict {
		t.Fatalf("同键异摘要 = %+v", r3)
	}
	// 4. 异键占槽冲突（另一操作的合法重试不得变成成功）
	r4 := s.Reserve(iid, "create", nil, 15, "idem-9", "dig-1", true)
	if r4.Outcome != "CONFLICT" || r4.Reason != flowguard.ReasonReserveDenied || r4.Detail != "reserve_conflict" {
		t.Fatalf("异键占槽 = %+v", r4)
	}
	// 5. 依赖步骤前置未确认：违规 FLOW-RESERVE-001
	r5 := s.Reserve(iid, "pay", []string{"create"}, 15, "idem-2", "dig-2", true)
	if r5.Outcome != "REJECTED" || r5.Reason != flowguard.ReasonReserveDenied || r5.Detail != "predecessor_unconfirmed" {
		t.Fatalf("前置未确认 = %+v", r5)
	}
	// 6. 错误 token 提交：FENCE-001
	c1 := s.Commit(iid, "create", []string{"create", "pay"}, 99, "idem-1", "dig-1")
	if c1.Outcome != "REJECTED" || c1.Reason != flowguard.ReasonFenceStale {
		t.Fatalf("错 token commit = %+v", c1)
	}
	// 7. 正确 token 提交：OK；随后依赖步骤预留成功（token 前移）
	c2 := s.Commit(iid, "create", []string{"create", "pay"}, 1, "idem-1", "dig-1")
	if c2.Outcome != "OK" || c2.InstanceConfirmed {
		t.Fatalf("commit create = %+v", c2)
	}
	r6 := s.Reserve(iid, "pay", []string{"create"}, 15, "idem-2", "dig-2", true)
	if r6.Outcome != "OK" || r6.Token != 2 {
		t.Fatalf("依赖步骤预留 = %+v", r6)
	}
	// 8. 不同键重走已 CONFIRMED 步骤：违规（D6/F03）
	r7 := s.Reserve(iid, "create", nil, 15, "idem-7", "dig-7", true)
	if r7.Outcome != "REJECTED" || r7.Detail != "already_confirmed" {
		t.Fatalf("重走已确认 = %+v", r7)
	}
	// 9. commit 幂等重放（同 token 同键同摘要）
	c3 := s.Commit(iid, "create", []string{"create", "pay"}, 1, "idem-1", "dig-1")
	if c3.Outcome != "OK" || !c3.IdempotentReplay {
		t.Fatalf("commit 重放 = %+v", c3)
	}
	// 10. 全步骤确认 → 实例 CONFIRMED；此后任何预留 = 终态拒入
	c4 := s.Commit(iid, "pay", []string{"create", "pay"}, 2, "idem-2", "dig-2")
	if c4.Outcome != "OK" || !c4.InstanceConfirmed {
		t.Fatalf("commit pay = %+v", c4)
	}
	r8 := s.Reserve(iid, "create", nil, 15, "idem-8", "dig-8", true)
	if r8.Outcome != "REJECTED" || r8.Detail != "instance_terminal" {
		t.Fatalf("终态拒入 = %+v", r8)
	}
}

func TestStrongFlowITFenceExpiry(t *testing.T) {
	s, iid := sflowITStore(t)
	// lease=0 → 立即过期（装配层校验保证生产 15~300s；Store 层不重复夹紧，
	// 集成测试借 0 值压缩等待——F05 语义与等待时长无关）
	r1 := s.Reserve(iid, "create", nil, 0, "idem-1", "dig-1", true)
	if r1.Outcome != "OK" || r1.Token != 1 {
		t.Fatalf("reserve = %+v", r1)
	}
	// 过期后新 reserve（异键）：接管得新 token，事件链可核对两次 fencing 值
	r2 := s.Reserve(iid, "create", nil, 15, "idem-2", "dig-2", true)
	if r2.Outcome != "OK" || r2.Token != 2 || !r2.ExpiredTakeover || r2.ExpiredToken != 1 {
		t.Fatalf("过期接管 = %+v", r2)
	}
	// 旧 token commit 一律拒绝（迟到响应不覆盖新状态，F05；§8.4-2 裁决：事件
	// fencing_token=被拒旧 token=1，当前 fence 读数 2 在 FenceCurrent——与同步骤
	// 后续 COMMIT OK(f=2) 不再同键碰撞）
	c1 := s.Commit(iid, "create", []string{"create"}, 1, "idem-1", "dig-1")
	if c1.Outcome != "REJECTED" || c1.Reason != flowguard.ReasonFenceStale || c1.Token != 1 || c1.FenceCurrent != 2 {
		t.Fatalf("旧 token commit = %+v（Token 应为被拒旧 token=1，FenceCurrent=2）", c1)
	}
	// 新 token commit 接受
	c2 := s.Commit(iid, "create", []string{"create"}, 2, "idem-2", "dig-2")
	if c2.Outcome != "OK" || !c2.InstanceConfirmed {
		t.Fatalf("新 token commit = %+v", c2)
	}
}

func TestStrongFlowITRelease(t *testing.T) {
	s, iid := sflowITStore(t)
	r1 := s.Reserve(iid, "create", nil, 15, "idem-1", "dig-1", true)
	if r1.Outcome != "OK" {
		t.Fatalf("reserve = %+v", r1)
	}
	// 错 token release 拒
	if rel := s.Release(iid, "create", 99); rel.Outcome != "REJECTED" || rel.Reason != flowguard.ReasonFenceStale {
		t.Fatalf("错 token release = %+v", rel)
	}
	// 正确 token release OK；释放后 commit 拒（槽非 PENDING）
	if rel := s.Release(iid, "create", 1); rel.Outcome != "OK" {
		t.Fatalf("release = %+v", rel)
	}
	if c := s.Commit(iid, "create", []string{"create"}, 1, "idem-1", "dig-1"); c.Outcome != "REJECTED" {
		t.Fatalf("释放后 commit = %+v", c)
	}
	// 释放后再预留得新 token（fence 前移）
	r2 := s.Reserve(iid, "create", nil, 15, "idem-3", "dig-3", true)
	if r2.Outcome != "OK" || r2.Token != 2 {
		t.Fatalf("释放后再预留 = %+v", r2)
	}
}

func TestStrongFlowITParallelGroup(t *testing.T) {
	s, iid := sflowITStore(t)
	// 组外前置 create(1) 确认后，同组 reserve(2)/pay(3) 可合法并行
	// （组内成员互不为前置——predecessorStepKeys 口径；本测试直接传前置键模拟）
	if r := s.Reserve(iid, "create", nil, 15, "i1", "d1", true); r.Outcome != "OK" {
		t.Fatalf("create reserve = %+v", r)
	}
	if c := s.Commit(iid, "create", []string{"create", "reserve", "pay"}, 1, "i1", "d1"); c.Outcome != "OK" {
		t.Fatalf("create commit = %+v", c)
	}
	// 同组 reserve(2) PENDING 时 pay(3) 仍合法（前置只看序 < 组起点）
	r2 := s.Reserve(iid, "reserve", []string{"create"}, 15, "i2", "d2", true)
	if r2.Outcome != "OK" || r2.Token != 2 {
		t.Fatalf("reserve 步 = %+v", r2)
	}
	r3 := s.Reserve(iid, "pay", []string{"create"}, 15, "i3", "d3", true)
	if r3.Outcome != "OK" || r3.Token != 3 {
		t.Fatalf("并行 pay 步 = %+v", r3)
	}
	// 反向印证：若把同组步骤误作前置（序 2 < pay 序 3），PENDING 未确认即违规
	r4 := s.Reserve(iid, "pay", []string{"create", "reserve"}, 15, "i4", "d4", true)
	if r4.Outcome != "REJECTED" || r4.Detail != "predecessor_unconfirmed" {
		t.Fatalf("误前置应违规 = %+v", r4)
	}
}

func TestStrongFlowITNoIdemKeySemantics(t *testing.T) {
	s, iid := sflowITStore(t)
	// 无幂等键（空串）：同摘要重放幂等去重；异摘要按槽冲突（不升级 IDEMPOTENT-CONFLICT）
	r1 := s.Reserve(iid, "create", nil, 15, "", "dig-1", true)
	if r1.Outcome != "OK" {
		t.Fatalf("reserve = %+v", r1)
	}
	r2 := s.Reserve(iid, "create", nil, 15, "", "dig-1", true)
	if r2.Outcome != "OK" || !r2.IdempotentReplay {
		t.Fatalf("无键同摘要重放 = %+v", r2)
	}
	r3 := s.Reserve(iid, "create", nil, 15, "", "dig-2", true)
	if r3.Outcome != "CONFLICT" || r3.Reason != flowguard.ReasonReserveDenied {
		t.Fatalf("无键异摘要 = %+v（应槽冲突而非幂等冲突）", r3)
	}
}

func TestStrongFlowITMarkAccepted(t *testing.T) {
	s, iid := sflowITStore(t)
	if r := s.Reserve(iid, "create", nil, 15, "i1", "d1", true); r.Outcome != "OK" {
		t.Fatalf("reserve = %+v", r)
	}
	// 错 token 标记拒（FENCE-001；事件携被拒 token=99，当前 fence=1 在 FenceCurrent）
	if m := s.MarkAccepted(iid, "create", 99, 15); m.Outcome != "REJECTED" || m.Reason != flowguard.ReasonFenceStale ||
		m.Token != 99 || m.FenceCurrent != 1 {
		t.Fatalf("错 token mark = %+v", m)
	}
	// 同 token 标记 OK（§8.4-2 裁决：受理即预留轮换——INCR fence 取新 token=2，
	// 事件携新 token 与首 RESERVE(token=1) 不再同键碰撞）
	m := s.MarkAccepted(iid, "create", 1, 15)
	if m.Outcome != "OK" || m.Detail != "accepted_202" || m.Token != 2 {
		t.Fatalf("mark accepted = %+v（want OK/accepted_202/轮换新 token=2）", m)
	}
	// 旧 token=1 commit 迟到 → FENCE-001（事件携被拒 token=1，fence_current=2）
	if c := s.Commit(iid, "create", []string{"create"}, 1, "i1", "d1"); c.Outcome != "REJECTED" ||
		c.Reason != flowguard.ReasonFenceStale || c.Token != 1 || c.FenceCurrent != 2 {
		t.Fatalf("旧 token 受理后 commit = %+v", c)
	}
	// 新 token=2 commit → OK + InstanceConfirmed（受理后确证完成仍可走 commit 链）
	if c := s.Commit(iid, "create", []string{"create"}, 2, "i1", "d1"); c.Outcome != "OK" || !c.InstanceConfirmed {
		t.Fatalf("新 token commit = %+v", c)
	}
	// 已 CONFIRMED 槽再标记 = FENCE-001 not_pending（携被拒 token=2，fence_current=2）
	if m := s.MarkAccepted(iid, "create", 2, 15); m.Outcome != "REJECTED" || m.Detail != "not_pending" ||
		m.Token != 2 || m.FenceCurrent != 2 {
		t.Fatalf("确认后再标记 = %+v", m)
	}
}

func TestStrongFlowITMarkIndeterminate(t *testing.T) {
	s, iid := sflowITStore(t)
	// 热状态缺失：不伪造 → UNKNOWN state_missing
	if m := s.MarkIndeterminate(iid); m.Outcome != "UNKNOWN" || m.Detail != "state_missing" {
		t.Fatalf("缺失标记 = %+v", m)
	}
	if r := s.Reserve(iid, "create", nil, 15, "i1", "d1", true); r.Outcome != "OK" {
		t.Fatalf("reserve = %+v", r)
	}
	// ACTIVE → INDETERMINATE；重复标记幂等重放
	if m := s.MarkIndeterminate(iid); m.Outcome != "OK" || m.Detail != "marked" {
		t.Fatalf("标记 = %+v", m)
	}
	if m := s.MarkIndeterminate(iid); m.Outcome != "OK" || !m.IdempotentReplay {
		t.Fatalf("重复标记应幂等: %+v", m)
	}
	// INDETERMINATE 实例上新预留：不可服务 UNKNOWN（实例冻结待对账）
	if r := s.Reserve(iid, "pay", nil, 15, "i2", "d2", true); r.Outcome != "UNKNOWN" || r.Detail != "instance_indeterminate" {
		t.Fatalf("INDETERMINATE 上预留 = %+v", r)
	}
	// 步骤槽保持 PENDING：迟到证据仍可 commit（不阻断后续事实；实例状态不伪造回 ACTIVE）
	if c := s.Commit(iid, "create", []string{"create"}, 1, "i1", "d1"); c.Outcome != "OK" || !c.InstanceConfirmed {
		t.Fatalf("INDETERMINATE 后 commit = %+v", c)
	}
}

// TestStrongFlowITRetiredPublishWindow 育龄窗（§8.4-1 裁决）原子域语义：
// RETIRED 下发版本（allowNewInstance=false）——存量实例（state 键存在）续跑
// 正常 reserve；全新实例键 definition_retired 拒入（新实例必须按 ACTIVE 版本键）。
func TestStrongFlowITRetiredPublishWindow(t *testing.T) {
	s, iid := sflowITStore(t)
	// 存量实例在 ACTIVE 版本下创建并走完首步
	if r := s.Reserve(iid, "create", nil, 15, "i1", "d1", true); r.Outcome != "OK" {
		t.Fatalf("reserve = %+v", r)
	}
	if c := s.Commit(iid, "create", []string{"create", "pay"}, 1, "i1", "d1"); c.Outcome != "OK" {
		t.Fatalf("commit = %+v", c)
	}
	// 版本切换（RETIRED）：同实例后续步骤按旧版本续跑放行
	if r := s.Reserve(iid, "pay", []string{"create"}, 15, "i2", "d2", false); r.Outcome != "OK" || r.Token != 2 {
		t.Fatalf("RETIRED 存量续跑 = %+v", r)
	}
	// RETIRED 版本对全新实例键拒入（definition_retired）
	r := s.Reserve(iid+"-new", "create", nil, 15, "i3", "d3", false)
	if r.Outcome != "REJECTED" || r.Reason != flowguard.ReasonReserveDenied || r.Detail != "definition_retired" {
		t.Fatalf("RETIRED 新实例应拒 = %+v", r)
	}
	// ACTIVE 版本对全新实例键放行（对照）
	if r := s.Reserve(iid+"-new", "create", nil, 15, "i3", "d3", true); r.Outcome != "OK" {
		t.Fatalf("ACTIVE 新实例 = %+v", r)
	}
}
