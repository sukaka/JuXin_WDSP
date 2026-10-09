// reserve_test.go Store 封装单测（接口 fake 驱动：键形/参数编组/结果映射/故障
// UNKNOWN——不验证 Lua 语法本身；Lua 全矩阵语义由 jiuzhang_guard 模块的
// env 门控 Valkey 集成测试承载，任务纪律不引 miniredis）。
package flowguard

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeEval 可编程 Eval 替身（记录调用、返回罐装结果/注入故障）。
type fakeEval struct {
	lastScript string
	lastKeys   []string
	lastArgs   []string
	reply      []interface{}
	err        error
	hook       func(script string, keys, args []string) ([]interface{}, error)
}

func (f *fakeEval) Eval(_ context.Context, script string, keys []string, args []string) ([]interface{}, error) {
	f.lastScript, f.lastKeys, f.lastArgs = script, keys, args
	if f.hook != nil {
		return f.hook(script, keys, args)
	}
	return f.reply, f.err
}

func TestStoreKeysHashTagShape(t *testing.T) {
	fe := &fakeEval{reply: []interface{}{int64(0), "", int64(7), "reserved", int64(1), int64(0)}}
	s := NewStore(fe, nil)
	res := s.Reserve("sfref:ab12", "pay", []string{"create"}, 30, "idemh", "dig", true)
	if res.Outcome != "OK" || res.Token != 7 || !res.InstanceNew {
		t.Fatalf("reserve = %+v", res)
	}
	// 键模式冻结：sflow:v1: 前缀 + {instance_id} hash tag 同槽
	wantKeys := []string{
		"sflow:v1:{sfref:ab12}:fence",
		"sflow:v1:{sfref:ab12}:state",
		"sflow:v1:{sfref:ab12}:step:pay",
		"sflow:v1:{sfref:ab12}:step:create", // 前置槽同 hash tag
	}
	if len(fe.lastKeys) != len(wantKeys) {
		t.Fatalf("keys = %v", fe.lastKeys)
	}
	for i, k := range wantKeys {
		if fe.lastKeys[i] != k {
			t.Fatalf("keys[%d] = %q, want %q", i, fe.lastKeys[i], k)
		}
	}
	// 参数编组：step_key/lease_ms/idem/digest/ttl_ms
	if fe.lastArgs[0] != "pay" || fe.lastArgs[1] != "30000" || fe.lastArgs[2] != "idemh" || fe.lastArgs[3] != "dig" {
		t.Fatalf("args = %v", fe.lastArgs)
	}
	if fe.lastArgs[4] != strconv.FormatInt(DefaultInstanceTTL.Milliseconds(), 10) {
		t.Fatalf("ttl arg = %q", fe.lastArgs[4])
	}
}

func TestStoreNilClientUnknown(t *testing.T) {
	s := NewStore(nil, nil)
	for name, res := range map[string]OpResult{
		"reserve": s.Reserve("sfref:x", "pay", nil, 30, "", "", true),
		"commit":  s.Commit("sfref:x", "pay", []string{"pay"}, 1, "", ""),
		"release": s.Release("sfref:x", "pay", 1),
	} {
		if res.Outcome != "UNKNOWN" || res.Reason != ReasonUnknown || res.Detail != "valkey_unconfigured" {
			t.Errorf("%s: nil client = %+v，应 UNKNOWN/valkey_unconfigured", name, res)
		}
	}
}

func TestStoreEvalErrorUnknownAndThrottle(t *testing.T) {
	var warns int
	fe := &fakeEval{err: errors.New("connection refused")}
	s := NewStore(fe, func(op string, err error) { warns++ })
	s.now = func() time.Time { return time.Unix(1000, 0) } // 固定时钟
	res := s.Reserve("sfref:x", "pay", nil, 30, "", "", true)
	if res.Outcome != "UNKNOWN" || res.Detail != "valkey_error" {
		t.Fatalf("eval error = %+v", res)
	}
	res = s.Commit("sfref:x", "pay", []string{"pay"}, 1, "", "")
	if res.Outcome != "UNKNOWN" {
		t.Fatalf("commit error = %+v", res)
	}
	// 告警节流：同分钟内两次故障只告警一次
	if warns != 1 {
		t.Fatalf("warns = %d，应 1（每分钟节流）", warns)
	}
}

func TestStoreEmptyReplyUnknown(t *testing.T) {
	fe := &fakeEval{reply: []interface{}{}}
	s := NewStore(fe, nil)
	if res := s.Reserve("sfref:x", "pay", nil, 30, "", "", true); res.Outcome != "UNKNOWN" || res.Detail != "eval_protocol_error" {
		t.Fatalf("空返回 = %+v", res)
	}
	// 未知结果码（防御）
	fe.reply = []interface{}{int64(99), "", int64(0), "", int64(0)}
	if res := s.Reserve("sfref:x", "pay", nil, 30, "", "", true); res.Outcome != "UNKNOWN" {
		t.Fatalf("未知码 = %+v", res)
	}
}

func TestStoreResultMapping(t *testing.T) {
	cases := []struct {
		name  string
		reply []interface{}
		want  OpResult
	}{
		{"OK 新建实例", []interface{}{int64(0), "", int64(5), "reserved", int64(1), int64(0)},
			OpResult{Outcome: "OK", Token: 5, Detail: "reserved", InstanceNew: true}},
		{"OK 接管过期槽", []interface{}{int64(0), "", int64(9), "reserved", int64(2), int64(4)},
			OpResult{Outcome: "OK", Token: 9, Detail: "reserved", ExpiredTakeover: true, ExpiredToken: 4}},
		{"幂等重放", []interface{}{int64(1), "", int64(5), "idempotent_replay", int64(0), int64(0)},
			OpResult{Outcome: "OK", Token: 5, Detail: "idempotent_replay", IdempotentReplay: true}},
		{"幂等冲突", []interface{}{int64(2), "IDEMPOTENT-CONFLICT-001", int64(5), "digest_mismatch", int64(0), int64(0)},
			OpResult{Outcome: "CONFLICT", Reason: ReasonIdempotentConflict, Token: 5, Detail: "digest_mismatch"}},
		{"预留冲突", []interface{}{int64(2), "FLOW-RESERVE-001", int64(5), "reserve_conflict", int64(0), int64(0)},
			OpResult{Outcome: "CONFLICT", Reason: ReasonReserveDenied, Token: 5, Detail: "reserve_conflict"}},
		{"前置未确认违规", []interface{}{int64(3), "FLOW-RESERVE-001", int64(0), "predecessor_unconfirmed", int64(0), int64(0)},
			OpResult{Outcome: "REJECTED", Reason: ReasonReserveDenied, Detail: "predecessor_unconfirmed"}},
		{"fencing 过期（§8.4-2：token=被拒 token，当前 fence 在 FenceCurrent）", []interface{}{int64(3), "FENCE-001", int64(2), "stale_token", int64(0), int64(8)},
			OpResult{Outcome: "REJECTED", Reason: ReasonFenceStale, Token: 2, Detail: "stale_token", FenceCurrent: 8}},
		{"实例 INDETERMINATE", []interface{}{int64(4), "UNKNOWN-001", int64(0), "instance_indeterminate", int64(0), int64(0)},
			OpResult{Outcome: "UNKNOWN", Reason: ReasonUnknown, Detail: "instance_indeterminate"}},
		{"实例确认完成", []interface{}{int64(0), "", int64(6), "instance_confirmed", int64(4), int64(0)},
			OpResult{Outcome: "OK", Token: 6, Detail: "instance_confirmed", InstanceConfirmed: true}},
	}
	for _, tc := range cases {
		fe := &fakeEval{reply: tc.reply}
		s := NewStore(fe, nil)
		got := s.Reserve("sfref:x", "pay", nil, 30, "", "", true)
		if got != tc.want {
			t.Errorf("%s: got %+v want %+v", tc.name, got, tc.want)
		}
	}
}

func TestCommitKeyExcludesTargetDuplicate(t *testing.T) {
	fe := &fakeEval{reply: []interface{}{int64(0), "", int64(3), "committed", int64(0), int64(0)}}
	s := NewStore(fe, nil)
	res := s.Commit("sfref:x", "pay", []string{"create", "pay", "notify"}, 3, "i", "d")
	if res.Outcome != "OK" {
		t.Fatalf("commit = %+v", res)
	}
	// KEYS[3]=目标槽，其余步骤槽各一份（目标不重复）
	var slots int
	for _, k := range fe.lastKeys[3:] {
		if strings.Contains(k, ":step:") {
			slots++
			if strings.HasSuffix(k, ":step:pay") {
				t.Fatalf("目标步骤槽重复入 KEYS: %v", fe.lastKeys)
			}
		}
	}
	if slots != 2 {
		t.Fatalf("其余步骤槽数 = %d: %v", slots, fe.lastKeys)
	}
	if fe.lastArgs[1] != "3" {
		t.Fatalf("token arg = %q", fe.lastArgs[1])
	}
}

func TestReleaseArgsShape(t *testing.T) {
	fe := &fakeEval{reply: []interface{}{int64(0), "", int64(3), "released", int64(0), int64(0)}}
	s := NewStore(fe, nil)
	if res := s.Release("sfref:x", "pay", 3); res.Outcome != "OK" {
		t.Fatalf("release = %+v", res)
	}
	if len(fe.lastKeys) != 3 || fe.lastArgs[0] != "pay" || fe.lastArgs[1] != "3" {
		t.Fatalf("release keys/args = %v %v", fe.lastKeys, fe.lastArgs)
	}
}

// TestStoreReserveAllowNewInstanceArg 育龄窗闸参数编组（§8.4-1 裁决）：
// allowNewInstance=false（RETIRED 下发版本）→ ARGV[6]="0"；true → "1"。
func TestStoreReserveAllowNewInstanceArg(t *testing.T) {
	fe := &fakeEval{reply: []interface{}{int64(3), "FLOW-RESERVE-001", int64(0), "definition_retired", int64(0), int64(0)}}
	s := NewStore(fe, nil)
	res := s.Reserve("sfref:x", "pay", nil, 30, "", "", false)
	if res.Outcome != "REJECTED" || res.Detail != "definition_retired" {
		t.Fatalf("retired reserve = %+v", res)
	}
	if fe.lastArgs[5] != "0" {
		t.Fatalf("allow_new arg（RETIRED）= %q, want \"0\"", fe.lastArgs[5])
	}
	fe.reply = []interface{}{int64(0), "", int64(1), "reserved", int64(1), int64(0)}
	if res := s.Reserve("sfref:y", "pay", nil, 30, "", "", true); res.Outcome != "OK" {
		t.Fatalf("active reserve = %+v", res)
	}
	if fe.lastArgs[5] != "1" {
		t.Fatalf("allow_new arg（ACTIVE）= %q, want \"1\"", fe.lastArgs[5])
	}
}
