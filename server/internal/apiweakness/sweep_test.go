// sweep_test.go 派生扫描测试：fake 信号源 + MemStore，覆盖四条 v1 规则的
// upsert 期望、FIXED 再触发 REPRODUCED、空表安全、证据脱敏与错误不静默。
package apiweakness

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeSignals 内存信号源（字段为各规则命中；err 非空时全部返回错误）。
type fakeSignals struct {
	unauth []EndpointSignal
	dep    []EndpointSignal
	inq    []EndpointSignal
	drift  []EndpointSignal
	err    error
}

func (f *fakeSignals) UnauthenticatedSensitive(ctx context.Context, since time.Time, minSamples int) ([]EndpointSignal, error) {
	if f.err != nil {
		return nil, f.err
	}
	// 模拟 PG HAVING：低于样本量阈值的信号不下发
	out := f.unauth[:0:0]
	for _, s := range f.unauth {
		if s.Hits >= minSamples {
			out = append(out, s)
		}
	}
	return out, nil
}

func (f *fakeSignals) DeprecatedCalls(ctx context.Context, since time.Time) ([]EndpointSignal, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.dep, nil
}

func (f *fakeSignals) SensitiveInQuery(ctx context.Context, since time.Time) ([]EndpointSignal, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.inq, nil
}

func (f *fakeSignals) SchemaDriftPersistent(ctx context.Context, persistBefore, activeSince time.Time) ([]EndpointSignal, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.drift, nil
}

// newTestSweeper 装配测试派生器（固定 now，窗口默认 24h）。
func newTestSweeper(src SignalSource, store Repository, now time.Time) *Sweeper {
	return &Sweeper{
		source: src, store: store,
		opts: SweepOptions{}.withDefaults(),
		now:  func() time.Time { return now },
	}
}

func sigFor(endpointID uuid.UUID, key string, hits int, now time.Time) EndpointSignal {
	return EndpointSignal{
		EndpointID: endpointID, EndpointKey: key, Hits: hits,
		FirstSeen: now.Add(-time.Hour), LastSeen: now,
	}
}

// TestSweepOnceDerivesAllRules 四条规则各命中一个端点 → 四条 NEW 弱点，元数据与证据正确。
func TestSweepOnceDerivesAllRules(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ep1, ep2, ep3, ep4 := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	src := &fakeSignals{
		unauth: []EndpointSignal{
			sigFor(ep1, "GET /api/users/{id}", 5, now),
			sigFor(ep1, "GET /api/users/{id}", 1, now), // 低于样本量阈值，被过滤
		},
		dep:   []EndpointSignal{sigFor(ep2, "GET /api/old/orders", 2, now)},
		inq:   []EndpointSignal{sigFor(ep3, "POST /api/login", 1, now)},
		drift: []EndpointSignal{sigFor(ep4, "GET /api/items", 9, now)},
	}
	mem := NewMemStore()
	for id, key := range map[uuid.UUID]string{ep1: "GET /api/users/{id}", ep2: "GET /api/old/orders", ep3: "POST /api/login", ep4: "GET /api/items"} {
		mem.SetEndpointKey(id, key)
	}
	res, err := newTestSweeper(src, mem, now).SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Inserted != 4 || res.Updated != 0 || res.Reproduced != 0 {
		t.Fatalf("result: %+v", res)
	}
	wantByCode := map[string]int{
		CodeUnauthenticatedSensitiveAPI: 1, CodeDeprecatedStillCalled: 1,
		CodeSensitiveInQuery: 1, CodeSchemaDriftPersistent: 1,
	}
	for code, want := range wantByCode {
		if res.ByCode[code] != want {
			t.Fatalf("by_code[%s]=%d, want %d（%+v）", code, res.ByCode[code], want, res.ByCode)
		}
	}

	list, total, err := mem.List(context.Background(), ListFilter{Page: 1, PageSize: 20})
	if err != nil || total != 4 {
		t.Fatalf("list total=%d err=%v", total, err)
	}
	byCode := map[string]Weakness{}
	for _, w := range list {
		byCode[w.WeaknessCode] = w
		if w.Status != StatusNew || w.TriggerCount != 1 {
			t.Fatalf("weakness not NEW/count=1: %+v", w)
		}
	}
	// 元数据落库正确
	if w := byCode[CodeUnauthenticatedSensitiveAPI]; w.Category != CategoryAuthn || w.Severity != SeverityHigh || w.EndpointKey != "GET /api/users/{id}" {
		t.Fatalf("unauth weakness: %+v", w)
	}
	if w := byCode[CodeSchemaDriftPersistent]; w.Category != CategorySchema || w.Severity != SeverityMedium {
		t.Fatalf("drift weakness: %+v", w)
	}
	// 证据为脱敏摘要：只含规则/计数/窗口/时间键，无任何原始请求数据
	var ev map[string]any
	if err := json.Unmarshal(byCode[CodeSensitiveInQuery].Evidence, &ev); err != nil {
		t.Fatal(err)
	}
	wantKeys := map[string]bool{"rule": true, "endpoint_key": true, "sample_count": true, "window_hours": true, "first_seen": true, "last_seen": true}
	for k := range ev {
		if !wantKeys[k] {
			t.Fatalf("evidence contains unexpected key %q: %v", k, ev)
		}
	}
	if ev["rule"] != CodeSensitiveInQuery || ev["sample_count"].(float64) != 1 || ev["window_hours"].(float64) != 24 {
		t.Fatalf("evidence content: %v", ev)
	}
	// 每条弱点都有 DERIVED 历史（actor=system）
	for _, w := range list {
		actions, n, _ := mem.ListActions(context.Background(), w.ID, 1, 10)
		if n != 1 || actions[0].Action != ActionDerived || actions[0].Actor != "system" {
			t.Fatalf("derived action missing for %s: %+v", w.WeaknessCode, actions)
		}
	}
}

// TestSweepOnceUpsertAndReproduced 重复扫描计数 +1；FIXED 弱点再触发回 REPRODUCED。
func TestSweepOnceUpsertAndReproduced(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	ep := uuid.New()
	src := &fakeSignals{inq: []EndpointSignal{sigFor(ep, "POST /api/login", 3, now)}}
	mem := NewMemStore()
	sweeper := newTestSweeper(src, mem, now)

	// 第一轮：插入
	res, err := sweeper.SweepOnce(ctx)
	if err != nil || res.Inserted != 1 {
		t.Fatalf("first sweep: %+v err=%v", res, err)
	}
	// 第二轮（窗口滑动一小时）：同端点同码 → 计数 +1，不重复插入
	src.inq = []EndpointSignal{sigFor(ep, "POST /api/login", 4, now.Add(time.Hour))}
	sweeper.now = func() time.Time { return now.Add(time.Hour) }
	res, err = sweeper.SweepOnce(ctx)
	if err != nil || res.Updated != 1 || res.Inserted != 0 {
		t.Fatalf("second sweep: %+v err=%v", res, err)
	}
	list, total, _ := mem.List(ctx, ListFilter{Page: 1, PageSize: 20})
	if total != 1 || list[0].TriggerCount != 2 {
		t.Fatalf("after second sweep: total=%d %+v", total, list)
	}

	// 人工流转到 FIXED，再扫中 → REPRODUCED
	id := list[0].ID
	for _, action := range []string{ActionConfirm, ActionAssign, ActionMarkFixed} {
		if _, err := mem.Transition(ctx, id, action, TransitionInput{Actor: "tester", Owner: "zhangsan"}); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
	res, err = sweeper.SweepOnce(ctx)
	if err != nil || res.Reproduced != 1 {
		t.Fatalf("third sweep: %+v err=%v", res, err)
	}
	w, _ := mem.GetByID(ctx, id)
	if w.Status != StatusReproduced || w.TriggerCount != 3 {
		t.Fatalf("reproduced weakness: %+v", w)
	}
}

// TestSweepOnceEmptySafe 空信号源（对应空 api_runtime_events / api_runtime_findings 表）安全无错、零产出。
func TestSweepOnceEmptySafe(t *testing.T) {
	res, err := newTestSweeper(&fakeSignals{}, NewMemStore(), time.Now().UTC()).SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("empty sweep err=%v", err)
	}
	if res.Inserted != 0 || res.Updated != 0 || res.Reproduced != 0 || len(res.ByCode) != 0 {
		t.Fatalf("empty sweep result: %+v", res)
	}
}

// TestSweepOnceSourceError 信号源错误必须向上返回（不静默吞错）。
func TestSweepOnceSourceError(t *testing.T) {
	_, err := newTestSweeper(&fakeSignals{err: errors.New("db down")}, NewMemStore(), time.Now().UTC()).SweepOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("source error should propagate, got %v", err)
	}
}
