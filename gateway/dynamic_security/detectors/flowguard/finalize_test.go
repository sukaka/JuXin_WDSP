// finalize_test.go 响应回程收口矩阵：commit 命中/实例确认/fencing 过期拒绝/
// F04 UNKNOWN-INDETERMINATE 不自动 release/allows_202 受理待完成/依赖不可用披露。
package flowguard

import (
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
)

// finalizeFixture 收口测试夹具（fake store 按脚本特征分派罐装结果）。
type finalizeFixture struct {
	ctx        *dsctx.RequestContext
	rt         *Runtime
	fe         *fakeEval
	res        *Reservation
	called     map[string]int // 脚本类调用计数（reserve/commit/accepted/indeterminate/release）
	repliesMap map[string][]interface{}
	now        time.Time
}

func newFinalizeFixture(t *testing.T) *finalizeFixture {
	t.Helper()
	ctx := dsctx.New("req-fin-1", dsctx.DefaultParseLimits())
	fx := &finalizeFixture{
		ctx:    ctx,
		called: map[string]int{},
		now:    time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC),
	}
	fx.fe = &fakeEval{}
	fx.fe.hook = func(script string, keys, args []string) ([]interface{}, error) {
		switch {
		case strings.Contains(script, "accepted_ms"):
			fx.called["accepted"]++
			return fx.replyFor("accepted"), nil
		case strings.Contains(script, "indeterminate_ms"):
			fx.called["indeterminate"]++
			return fx.replyFor("indeterminate"), nil
		case strings.Contains(script, "released_ms"):
			fx.called["release"]++
			return fx.replyFor("release"), nil
		case strings.Contains(script, "confirmed_ms"):
			fx.called["commit"]++
			return fx.replyFor("commit"), nil
		default:
			fx.called["reserve"]++
			return fx.replyFor("reserve"), nil
		}
	}
	fx.rt = &Runtime{Store: NewStore(fx.fe, nil), HMACKey: []byte("0123456789abcdef0123456789abcdef")}
	fx.res = &Reservation{
		DefinitionID: "d-1", DefinitionVersion: 2, InstanceID: "sfref:aa",
		StepKey: "pay", FencingToken: 7, LeaseSeconds: 30,
		SuccessRule: &SuccessRule{StatusCodes: []int{200}, BodyJSONPathEquals: &JSONPathEquals{Path: "$.status", Value: "PAID"}},
		AllStepKeys: []string{"create", "pay"}, IdemHash: "ih", Digest: "dg",
	}
	ctx.SetExtension(extReservation, fx.res)
	return fx
}

// replies 按脚本类覆盖罐装结果。
func (fx *finalizeFixture) replies(m map[string][]interface{}) {
	fx.repliesMap = m
}

func (fx *finalizeFixture) replyFor(kind string) []interface{} {
	if fx.repliesMap != nil {
		if r, ok := fx.repliesMap[kind]; ok {
			return r
		}
	}
	switch kind {
	case "commit":
		return []interface{}{int64(0), "", int64(7), "committed", int64(0), int64(0)}
	case "accepted":
		return []interface{}{int64(0), "", int64(7), "accepted_202", int64(0), int64(0)}
	case "indeterminate":
		return []interface{}{int64(0), "", int64(0), "marked", int64(0), int64(0)}
	default:
		return []interface{}{int64(0), "", int64(7), "reserved", int64(0), int64(0)}
	}
}

func acts(ctx *dsctx.RequestContext) []*dsevents.StrongFlowAction {
	return ActionsFromContext(ctx)
}

func TestFinalizeCommitOK(t *testing.T) {
	fx := newFinalizeFixture(t)
	facts := ResponseFacts{Status: 200, Body: []byte(`{"status":"PAID"}`)}
	fx.rt.FinalizeResponse(fx.ctx, facts, fx.now)
	if fx.called["commit"] != 1 || fx.called["indeterminate"] != 0 {
		t.Fatalf("调用 = %v", fx.called)
	}
	a := acts(fx.ctx)
	if len(a) != 1 || a[0].Action != dsevents.SFlowActionCommit || a[0].Result != dsevents.SFlowResultOK ||
		a[0].FencingToken != 7 || a[0].DefinitionVersion != 2 || a[0].ReasonCode != "" {
		t.Fatalf("COMMIT 条目 = %+v", a)
	}
	m := findMatch(fx.ctx, "flowguard.step_confirmed")
	if m == nil || m.Category != "INFO" || m.Evidence["jsonpath_actual"] != "PAID" {
		t.Fatalf("确认明细 = %+v", m)
	}
}

func TestFinalizeInstanceConfirmed(t *testing.T) {
	fx := newFinalizeFixture(t)
	fx.replies(map[string][]interface{}{
		"commit": {int64(0), "", int64(7), "instance_confirmed", int64(4), int64(0)},
	})
	fx.rt.FinalizeResponse(fx.ctx, ResponseFacts{Status: 200, Body: []byte(`{"status":"PAID"}`)}, fx.now)
	a := acts(fx.ctx)
	if len(a) != 2 || a[0].Action != dsevents.SFlowActionCommit || a[1].Action != dsevents.SFlowActionInstanceConfirmed {
		t.Fatalf("条目 = %+v", a)
	}
}

func TestFinalizeCommitFenceStaleRejected(t *testing.T) {
	fx := newFinalizeFixture(t)
	fx.replies(map[string][]interface{}{
		"commit": {int64(3), "FENCE-001", int64(9), "stale_token", int64(0), int64(0)},
	})
	fx.rt.FinalizeResponse(fx.ctx, ResponseFacts{Status: 200, Body: []byte(`{"status":"PAID"}`)}, fx.now)
	// fencing 过期拒绝：如实记录 COMMIT REJECTED；不入 INDETERMINATE（不调用标记）
	if fx.called["indeterminate"] != 0 {
		t.Fatalf("FENCE 拒绝不得入 INDETERMINATE: %v", fx.called)
	}
	a := acts(fx.ctx)
	if len(a) != 1 || a[0].Action != dsevents.SFlowActionCommit || a[0].Result != dsevents.SFlowResultRejected ||
		a[0].ReasonCode != ReasonFenceStale || a[0].FencingToken != 9 {
		t.Fatalf("REJECTED 条目 = %+v", a)
	}
	m := findMatch(fx.ctx, "flowguard.commit_rejected")
	if m == nil || m.Evidence["reason_code"] != ReasonFenceStale {
		t.Fatalf("拒绝明细 = %+v", m)
	}
}

func TestFinalizeRuleMissIndeterminateNoAutoRelease(t *testing.T) {
	cases := []struct {
		name  string
		facts ResponseFacts
		want  string
	}{
		{"状态码不命中", ResponseFacts{Status: 500, Body: []byte(`{"status":"PAID"}`)}, "status_mismatch"},
		{"判定值不等", ResponseFacts{Status: 200, Body: []byte(`{"status":"PENDING"}`)}, "jsonpath_mismatch"},
		{"体超限", ResponseFacts{Status: 200, BodyTruncated: true}, "body_over_limit"},
		{"体未捕获", ResponseFacts{Status: 200}, "body_unavailable"},
		{"体非法", ResponseFacts{Status: 200, Body: []byte(`{`)}, "body_unparseable"},
		{"下游超时/连接失败", ResponseFacts{DownstreamErr: true}, "downstream_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFinalizeFixture(t)
			fx.rt.FinalizeResponse(fx.ctx, tc.facts, fx.now)
			// F04：INDETERMINATE 标记 + 事件；绝不自动 release；不 commit
			if fx.called["indeterminate"] != 1 || fx.called["release"] != 0 || fx.called["commit"] != 0 {
				t.Fatalf("调用 = %v（commit/release 必须为 0）", fx.called)
			}
			a := acts(fx.ctx)
			if len(a) != 1 || a[0].Action != dsevents.SFlowActionInstanceIndeterminate ||
				a[0].Result != dsevents.SFlowResultUnknown || a[0].ReasonCode != ReasonUnknown {
				t.Fatalf("INDETERMINATE 条目 = %+v", a)
			}
			m := findMatch(fx.ctx, "flowguard.step_unknown")
			if m == nil || m.Evidence["detail"] != tc.want || m.Evidence["indeterminate_marked"] != "true" {
				t.Fatalf("明细 = %+v（detail 应 %q）", m, tc.want)
			}
		})
	}
}

func TestFinalizeRuleMissingUnknown(t *testing.T) {
	fx := newFinalizeFixture(t)
	fx.res.SuccessRule = nil // 运行期防御分支（装配校验已保证必填）
	fx.rt.FinalizeResponse(fx.ctx, ResponseFacts{Status: 200, Body: []byte(`{}`)}, fx.now)
	if fx.called["commit"] != 0 || fx.called["indeterminate"] != 1 {
		t.Fatalf("调用 = %v", fx.called)
	}
	m := findMatch(fx.ctx, "flowguard.step_unknown")
	if m == nil || m.Evidence["detail"] != "rule_missing" {
		t.Fatalf("明细 = %+v", m)
	}
}

func TestFinalizeAccepted202(t *testing.T) {
	fx := newFinalizeFixture(t)
	fx.res.Allows202 = true
	fx.rt.FinalizeResponse(fx.ctx, ResponseFacts{Status: 202, Body: []byte(`{"status":"PENDING"}`)}, fx.now)
	// 受理待完成：MarkAccepted 调用；不 commit、不入 INDETERMINATE、实例保持 ACTIVE
	if fx.called["accepted"] != 1 || fx.called["commit"] != 0 || fx.called["indeterminate"] != 0 {
		t.Fatalf("调用 = %v", fx.called)
	}
	a := acts(fx.ctx)
	if len(a) != 1 || a[0].Action != dsevents.SFlowActionReserve || a[0].Result != dsevents.SFlowResultOK ||
		a[0].ReasonCode != ReasonAccepted202 {
		t.Fatalf("受理条目 = %+v", a)
	}
	if m := findMatch(fx.ctx, "flowguard.step_accepted_202"); m == nil || m.Category != "INFO" {
		t.Fatalf("受理明细 = %+v", m)
	}
	// allows_202=false 时 202 走判定式（202 不在 status_codes → 不命中 UNKNOWN）
	fx2 := newFinalizeFixture(t)
	fx2.rt.FinalizeResponse(fx2.ctx, ResponseFacts{Status: 202, Body: []byte(`{"status":"PAID"}`)}, fx2.now)
	if fx2.called["accepted"] != 0 || fx2.called["indeterminate"] != 1 {
		t.Fatalf("未声明 allows_202 的 202 应按判定式: %v", fx2.called)
	}
}

func TestFinalizeAccepted202FenceStale(t *testing.T) {
	fx := newFinalizeFixture(t)
	fx.res.Allows202 = true
	fx.replies(map[string][]interface{}{
		"accepted": {int64(3), "FENCE-001", int64(9), "stale_token", int64(0), int64(0)},
	})
	fx.rt.FinalizeResponse(fx.ctx, ResponseFacts{Status: 202}, fx.now)
	a := acts(fx.ctx)
	if len(a) != 1 || a[0].Result != dsevents.SFlowResultRejected || a[0].ReasonCode != ReasonFenceStale {
		t.Fatalf("条目 = %+v", a)
	}
}

func TestFinalizeDependencyUnavailableDisclosed(t *testing.T) {
	// commit 依赖不可用 → F04 同一语义披露（INDETERMINATE 条目 + dependency_unavailable）
	fx := newFinalizeFixture(t)
	fx.replies(map[string][]interface{}{
		"commit":        {int64(4), "UNKNOWN-001", int64(0), "valkey_error", int64(0), int64(0)},
		"indeterminate": {int64(4), "UNKNOWN-001", int64(0), "state_missing", int64(0), int64(0)},
	})
	fx.rt.FinalizeResponse(fx.ctx, ResponseFacts{Status: 200, Body: []byte(`{"status":"PAID"}`)}, fx.now)
	m := findMatch(fx.ctx, "flowguard.step_unknown")
	if m == nil || m.Evidence["dependency_unavailable"] != "true" || m.Evidence["indeterminate_marked"] != "false" {
		t.Fatalf("披露 = %+v", m)
	}
	a := acts(fx.ctx)
	if len(a) != 1 || a[0].Action != dsevents.SFlowActionInstanceIndeterminate {
		t.Fatalf("条目 = %+v", a)
	}
}

func TestFinalizeNoReservationZeroBehavior(t *testing.T) {
	fx := newFinalizeFixture(t)
	ctx := dsctx.New("req-none", dsctx.DefaultParseLimits()) // 无 reservation
	fx.rt.FinalizeResponse(ctx, ResponseFacts{Status: 200, Body: []byte(`{"status":"PAID"}`)}, fx.now)
	if fx.called["commit"] != 0 || fx.called["indeterminate"] != 0 || len(ctx.CopyMatches()) != 0 {
		t.Fatal("无预留必须零行为")
	}
	// nil Runtime 同样零行为
	var rt *Runtime
	rt.FinalizeResponse(fx.ctx, ResponseFacts{Status: 200}, fx.now)
}
