// store_test.go MemStore 业务语义测试（与 SQL Store 同语义：流转/派生 upsert/列表过滤）。
package apiweakness

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// seedDerived 构造一条派生弱点（含 DERIVED 历史）。
func seedDerived(t *testing.T, m *MemStore, endpointID uuid.UUID, code string, now time.Time) *Weakness {
	t.Helper()
	name, category, severity, ok := WeaknessMeta(code)
	if !ok {
		t.Fatalf("code %s meta missing", code)
	}
	res, err := m.UpsertDerived(context.Background(), DerivedInput{
		EndpointID: endpointID, WeaknessCode: code, WeaknessName: name,
		Category: category, Severity: severity, Evidence: []byte(`{"rule":"` + code + `"}`), Now: now,
	})
	if err != nil || !res.Inserted {
		t.Fatalf("seed upsert: inserted=%v err=%v", res.Inserted, err)
	}
	w, err := m.GetByID(context.Background(), res.ID)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// TestMemStoreTransitionLifecycle 全生命周期：NEW→CONFIRMED→TO_FIX→FIXED→REPRODUCED→TO_FIX→FIXED→ARCHIVED，
// 逐动作断言副作用字段与历史轨迹。
func TestMemStoreTransitionLifecycle(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	ep := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	w := seedDerived(t, m, ep, CodeSensitiveInQuery, now)

	// 非法迁移：NEW 不能直接整改完成 / 复测 / 归档
	for _, action := range []string{ActionMarkFixed, ActionRetestPass, ActionRetestFail, ActionArchive} {
		if _, err := m.Transition(ctx, w.ID, action, TransitionInput{Actor: "tester"}); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("%s from NEW err=%v, want ErrInvalidTransition", action, err)
		}
	}
	// 不存在弱点 → ErrNotFound
	if _, err := m.Transition(ctx, uuid.New(), ActionConfirm, TransitionInput{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing id err=%v, want ErrNotFound", err)
	}

	// NEW → CONFIRMED
	w, err := m.Transition(ctx, w.ID, ActionConfirm, TransitionInput{Actor: "tester", Note: "确认真实", Now: now.Add(time.Minute)})
	if err != nil || w.Status != StatusConfirmed {
		t.Fatalf("confirm: status=%s err=%v", w.Status, err)
	}

	// CONFIRMED → TO_FIX（指派写 owner/due_date）
	due := now.Add(72 * time.Hour)
	w, err = m.Transition(ctx, w.ID, ActionAssign, TransitionInput{Actor: "tester", Owner: "zhangsan", DueDate: &due, Now: now.Add(2 * time.Minute)})
	if err != nil || w.Status != StatusToFix || w.Owner != "zhangsan" || w.DueDate == nil || !w.DueDate.Equal(due) {
		t.Fatalf("assign: %+v err=%v", w, err)
	}

	// TO_FIX → FIXED（写 fixed_at）
	w, err = m.Transition(ctx, w.ID, ActionMarkFixed, TransitionInput{Actor: "zhangsan", Now: now.Add(3 * time.Minute)})
	if err != nil || w.Status != StatusFixed || w.FixedAt == nil {
		t.Fatalf("fixed: %+v err=%v", w, err)
	}

	// FIXED 复测未通过 → REPRODUCED（写 retested_at）
	w, err = m.Transition(ctx, w.ID, ActionRetestFail, TransitionInput{Actor: "tester", Note: "仍复现", Now: now.Add(4 * time.Minute)})
	if err != nil || w.Status != StatusReproduced || w.RetestedAt == nil {
		t.Fatalf("retest fail: %+v err=%v", w, err)
	}

	// REPRODUCED → TO_FIX（重新指派）→ FIXED → 复测通过 → ARCHIVED
	if w, err = m.Transition(ctx, w.ID, ActionAssign, TransitionInput{Actor: "tester", Owner: "lisi", Now: now.Add(5 * time.Minute)}); err != nil || w.Status != StatusToFix {
		t.Fatalf("re-assign: %+v err=%v", w, err)
	}
	if w, err = m.Transition(ctx, w.ID, ActionMarkFixed, TransitionInput{Actor: "lisi", Now: now.Add(6 * time.Minute)}); err != nil || w.Status != StatusFixed {
		t.Fatalf("re-fixed: %+v err=%v", w, err)
	}
	if w, err = m.Transition(ctx, w.ID, ActionRetestPass, TransitionInput{Actor: "tester", Now: now.Add(7 * time.Minute)}); err != nil || w.Status != StatusArchived {
		t.Fatalf("retest pass: %+v err=%v", w, err)
	}

	// ARCHIVED 终态：任何操作非法
	for _, action := range allActions {
		if _, err := m.Transition(ctx, w.ID, action, TransitionInput{Actor: "tester"}); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("%s from ARCHIVED err=%v, want ErrInvalidTransition", action, err)
		}
	}

	// 历史轨迹：DERIVED + 7 次人工流转（倒序）
	actions, total, err := m.ListActions(ctx, w.ID, 1, 50)
	if err != nil || total != 8 || len(actions) != 8 {
		t.Fatalf("actions total=%d len=%d err=%v", total, len(actions), err)
	}
	wantOrder := []string{ActionRetestPass, ActionMarkFixed, ActionAssign, ActionRetestFail, ActionMarkFixed, ActionAssign, ActionConfirm, ActionDerived}
	for i, want := range wantOrder {
		if actions[i].Action != want {
			t.Fatalf("actions[%d]=%s, want %s（全轨迹 %v）", i, actions[i].Action, want, actions)
		}
	}
	// 最新一条由 tester 操作，最早一条由 system 派生
	if actions[0].Actor != "tester" || actions[7].Actor != "system" {
		t.Fatalf("actors: %+v / %+v", actions[0], actions[7])
	}
}

// TestMemStoreUpsertDerived 派生 upsert：计数/证据刷新/FIXED 回 REPRODUCED/IGNORED 与 ARCHIVED 不复活。
func TestMemStoreUpsertDerived(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	ep := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	name, category, severity, _ := WeaknessMeta(CodeDeprecatedStillCalled)
	in := DerivedInput{
		EndpointID: ep, WeaknessCode: CodeDeprecatedStillCalled, WeaknessName: name,
		Category: category, Severity: severity, Evidence: []byte(`{"sample_count":1}`), Now: now,
	}

	// 首次：Inserted，NEW，trigger_count=1
	res, err := m.UpsertDerived(ctx, in)
	if err != nil || !res.Inserted || res.Reproduced {
		t.Fatalf("first upsert: %+v err=%v", res, err)
	}
	w, _ := m.GetByID(ctx, res.ID)
	if w.Status != StatusNew || w.TriggerCount != 1 || !w.FirstSeen.Equal(now) || !w.LastSeen.Equal(now) {
		t.Fatalf("first weakness: %+v", w)
	}

	// 再次命中：计数 +1、last_seen/证据刷新、状态不变
	in.Now = now.Add(time.Hour)
	in.Evidence = []byte(`{"sample_count":5}`)
	res, err = m.UpsertDerived(ctx, in)
	if err != nil || res.Inserted || res.Reproduced {
		t.Fatalf("second upsert: %+v err=%v", res, err)
	}
	w, _ = m.GetByID(ctx, res.ID)
	if w.TriggerCount != 2 || !w.LastSeen.Equal(in.Now) || string(w.Evidence) != `{"sample_count":5}` || w.Status != StatusNew {
		t.Fatalf("second weakness: %+v", w)
	}

	// 置为 FIXED 后再命中 → REPRODUCED + REPRODUCED 历史
	for _, step := range []struct{ action string }{{ActionConfirm}, {ActionAssign}, {ActionMarkFixed}} {
		if _, err := m.Transition(ctx, w.ID, step.action, TransitionInput{Actor: "tester", Owner: "zhangsan"}); err != nil {
			t.Fatalf("%s: %v", step.action, err)
		}
	}
	res, err = m.UpsertDerived(ctx, in)
	if err != nil || !res.Reproduced {
		t.Fatalf("reproduced upsert: %+v err=%v", res, err)
	}
	w, _ = m.GetByID(ctx, res.ID)
	if w.Status != StatusReproduced || w.TriggerCount != 3 {
		t.Fatalf("reproduced weakness: %+v", w)
	}
	actions, _, _ := m.ListActions(ctx, w.ID, 1, 50)
	found := false
	for _, a := range actions {
		if a.Action == ActionReproduced && a.Actor == "system" {
			found = true
		}
	}
	if !found {
		t.Fatalf("REPRODUCED action missing: %+v", actions)
	}

	// IGNORED 不复活（计数仍增加）
	w2 := seedDerived(t, m, ep, CodeSensitiveInQuery, now)
	if _, err := m.Transition(ctx, w2.ID, ActionIgnore, TransitionInput{Actor: "tester"}); err != nil {
		t.Fatal(err)
	}
	res2, err := m.UpsertDerived(ctx, DerivedInput{
		EndpointID: ep, WeaknessCode: CodeSensitiveInQuery, WeaknessName: "敏感数据出现在 URL 查询串",
		Category: CategorySensitive, Severity: SeverityHigh, Evidence: []byte(`{}`), Now: now,
	})
	if err != nil || res2.Reproduced || res2.Inserted {
		t.Fatalf("ignored upsert: %+v err=%v", res2, err)
	}
	w2, _ = m.GetByID(ctx, res2.ID)
	if w2.Status != StatusIgnored || w2.TriggerCount != 2 {
		t.Fatalf("ignored weakness should stay IGNORED: %+v", w2)
	}
}

// TestMemStoreList 列表过滤与分页。
func TestMemStoreList(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	now := time.Now().UTC().Truncate(time.Second)
	ep1, ep2 := uuid.New(), uuid.New()
	seedDerived(t, m, ep1, CodeSensitiveInQuery, now)                             // SENSITIVE/HIGH/NEW
	w2 := seedDerived(t, m, ep1, CodeDeprecatedStillCalled, now.Add(time.Minute)) // LIFECYCLE/MEDIUM/NEW
	seedDerived(t, m, ep2, CodeSchemaDriftPersistent, now.Add(2*time.Minute))     // SCHEMA/MEDIUM/NEW
	if _, err := m.Transition(ctx, w2.ID, ActionConfirm, TransitionInput{Actor: "tester"}); err != nil {
		t.Fatal(err)
	}

	// 全量
	list, total, err := m.List(ctx, ListFilter{Page: 1, PageSize: 20})
	if err != nil || total != 3 || len(list) != 3 {
		t.Fatalf("all: total=%d len=%d err=%v", total, len(list), err)
	}
	// 按 last_seen 倒序（最先返回 SCHEMA 漂移）
	if list[0].WeaknessCode != CodeSchemaDriftPersistent {
		t.Fatalf("order: %+v", list[0])
	}
	// status 过滤
	list, total, _ = m.List(ctx, ListFilter{Status: StatusConfirmed, Page: 1, PageSize: 20})
	if total != 1 || list[0].ID != w2.ID {
		t.Fatalf("status filter: total=%d %+v", total, list)
	}
	// category 过滤
	_, total, _ = m.List(ctx, ListFilter{Category: CategorySensitive, Page: 1, PageSize: 20})
	if total != 1 {
		t.Fatalf("category filter: total=%d", total)
	}
	// severity 过滤（MEDIUM 两条）
	_, total, _ = m.List(ctx, ListFilter{Severity: SeverityMedium, Page: 1, PageSize: 20})
	if total != 2 {
		t.Fatalf("severity filter: total=%d", total)
	}
	// endpoint 过滤
	_, total, _ = m.List(ctx, ListFilter{EndpointID: &ep2, Page: 1, PageSize: 20})
	if total != 1 {
		t.Fatalf("endpoint filter: total=%d", total)
	}
	// 分页
	list, total, _ = m.List(ctx, ListFilter{Page: 2, PageSize: 2})
	if total != 3 || len(list) != 1 {
		t.Fatalf("page2: total=%d len=%d", total, len(list))
	}
}
