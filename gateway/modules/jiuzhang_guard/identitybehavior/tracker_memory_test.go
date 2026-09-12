package identitybehavior

import (
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// memTestClock 可推进时钟。
type memTestClock struct{ now time.Time }

func (c *memTestClock) Now() time.Time          { return c.now }
func (c *memTestClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newMemTestStore(clk *memTestClock) (*MemoryStore, *observer.ObservedLogs) {
	core, logs := observer.New(zap.WarnLevel)
	s := NewMemoryStore(0, zap.New(core))
	s.now = clk.Now
	return s, logs
}

func baseInput(id string) ObserveInput {
	return ObserveInput{IdentityKey: id, Method: "GET", URI: "/index"}
}

func TestMemoryStoreCountsAccumulate(t *testing.T) {
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 20, 0, time.UTC)}
	s, _ := newMemTestStore(clk)
	for i := 0; i < 3; i++ {
		snap, err := s.Observe(baseInput("id-1"))
		if err != nil {
			t.Fatal(err)
		}
		if i == 2 {
			for w := Window1m; w < NumWindows; w++ {
				if got := snap.Windows[w].RequestCount; got != 3 {
					t.Fatalf("window %s request_count = %v, want 3", w.Name(), got)
				}
			}
			if snap.Windows[Window1m].UniqueURICount != 1 {
				t.Fatalf("unique uri = %d, want 1", snap.Windows[Window1m].UniqueURICount)
			}
		}
	}
	// 不同 identity 互不影响
	snap, _ := s.Observe(baseInput("id-2"))
	if snap.Windows[Window1m].RequestCount != 1 {
		t.Fatalf("identity isolation: %v", snap.Windows[Window1m].RequestCount)
	}
}

func TestMemoryStoreStatusCounters(t *testing.T) {
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)}
	s, _ := newMemTestStore(clk)
	statuses := []int{401, 403, 404, 405, 500}
	for _, st := range statuses {
		in := baseInput("id-1")
		in.Status = st
		s.Observe(in)
	}
	snap, _ := s.Observe(baseInput("id-1"))
	w := snap.Windows[Window5m]
	if w.Status401Count != 1 || w.Status403Count != 1 || w.Status404Count != 1 || w.Status405Count != 1 || w.Status500Count != 1 {
		t.Fatalf("status counters: %+v", w)
	}
	// auth_fail_count 语义 = 401 数
	if w.AuthFailCount != 1 {
		t.Fatalf("auth_fail = %v, want 1", w.AuthFailCount)
	}
	if w.AttackHitCount != 0 {
		t.Fatalf("attack_hit reserved must be 0: %v", w.AttackHitCount)
	}
}

// 双桶轮转：跨桶后估值 = current + previous×(1-elapsed/window)。
func TestMemoryStoreBucketRotationEstimate(t *testing.T) {
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)} // 整分钟桶起点
	s, _ := newMemTestStore(clk)
	for i := 0; i < 10; i++ {
		s.Observe(baseInput("id-1"))
	}
	clk.Advance(61 * time.Second) // 进入下一 1m 桶，elapsed=1s
	snap, _ := s.Observe(baseInput("id-1"))
	// est = 1 + 10×(1-1/60) ≈ 10.833
	want := 1 + 10*(1-1.0/60.0)
	if got := snap.Windows[Window1m].RequestCount; got < want-0.01 || got > want+0.01 {
		t.Fatalf("rotation estimate = %v, want ≈%v", got, want)
	}
	// 跨多桶无活动：previous 清空不污染
	clk.Advance(5 * time.Minute)
	snap, _ = s.Observe(baseInput("id-1"))
	if got := snap.Windows[Window1m].RequestCount; got != 1 {
		t.Fatalf("stale previous must be dropped: %v", got)
	}
}

func TestMemoryStoreDistinctMethods(t *testing.T) {
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)}
	s, _ := newMemTestStore(clk)
	methods := []string{"GET", "POST", "PUT", "GET", "DELETE"}
	var snap *Snapshot
	for _, m := range methods {
		in := baseInput("id-1")
		in.Method = m
		snap, _ = s.Observe(in)
	}
	if snap.DistinctMethods != 4 {
		t.Fatalf("distinct methods = %d, want 4", snap.DistinctMethods)
	}
	// 不同 URI 独立计数
	in := baseInput("id-1")
	in.URI = "/other"
	snap, _ = s.Observe(in)
	if snap.DistinctMethods != 1 {
		t.Fatalf("per-uri method isolation: %d", snap.DistinctMethods)
	}
}

func TestMemoryStoreParamSignatureNewOld(t *testing.T) {
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)}
	s, _ := newMemTestStore(clk)
	in := baseInput("id-1")
	in.ParamSignature = "id=n"
	snap, _ := s.Observe(in)
	if !snap.ParamSigNew {
		t.Fatal("first signature must be new")
	}
	snap, _ = s.Observe(in)
	if snap.ParamSigNew {
		t.Fatal("repeated signature must not be new")
	}
	if got := snap.Windows[Window5m].ParameterMutationCount; got != 1 {
		t.Fatalf("mutation count = %v, want 1", got)
	}
	in.ParamSignature = "id=s:1-8"
	snap, _ = s.Observe(in)
	if !snap.ParamSigNew {
		t.Fatal("changed signature must be new")
	}
	if got := snap.Windows[Window5m].ParameterMutationCount; got != 2 {
		t.Fatalf("mutation count = %v, want 2", got)
	}
	// 空签名不参与
	in.ParamSignature = ""
	snap, _ = s.Observe(in)
	if snap.ParamSigNew {
		t.Fatal("empty signature must not count as new")
	}
}

func TestMemoryStoreKnownURIAndUnique(t *testing.T) {
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)}
	s, _ := newMemTestStore(clk)
	in := baseInput("id-1")
	snap, _ := s.Observe(in)
	if got := snap.Windows[Window5m].NewURICount; got != 1 {
		t.Fatalf("first uri must be new: %v", got)
	}
	snap, _ = s.Observe(in)
	if got := snap.Windows[Window5m].NewURICount; got != 1 {
		t.Fatalf("known uri must not recount new: %v", got)
	}
	in.URI = "/second"
	snap, _ = s.Observe(in)
	if got := snap.Windows[Window5m].NewURICount; got != 2 {
		t.Fatalf("second uri must be new: %v", got)
	}
	if got := snap.Windows[Window5m].UniqueURICount; got != 2 {
		t.Fatalf("unique uri = %d, want 2", got)
	}
}

func TestMemoryStoreSensitivePathHits(t *testing.T) {
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)}
	s, _ := newMemTestStore(clk)
	in := baseInput("id-1")
	in.SensitivePath = true
	s.Observe(in)
	snap, _ := s.Observe(in)
	for w := Window1m; w < NumWindows; w++ {
		if got := snap.Windows[w].SensitivePathHits; got != 2 {
			t.Fatalf("window %s sensitive hits = %v, want 2", w.Name(), got)
		}
	}
}

func TestMemoryStoreEnumerationDeduplicatesAndRotates(t *testing.T) {
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)}
	s, _ := newMemTestStore(clk)
	in := baseInput("id-1")
	in.AccountKey = "account-a"
	in.ObjectKey = "object-1"
	s.Observe(in)
	s.Observe(in)
	in.AccountKey = "account-b"
	in.ObjectKey = "object-2"
	snap, _ := s.Observe(in)
	if got := snap.Windows[Window5m].AccountEnumCount; got != 2 {
		t.Fatalf("account enum count = %d, want 2", got)
	}
	if got := snap.Windows[Window5m].ObjectEnumCount; got != 2 {
		t.Fatalf("object enum count = %d, want 2", got)
	}
	clk.Advance(61 * time.Second)
	in.AccountKey = "account-c"
	in.ObjectKey = "object-3"
	snap, _ = s.Observe(in)
	if got := snap.Windows[Window5m].AccountEnumCount; got != 3 {
		t.Fatalf("rotated account enum count = %d, want 3", got)
	}
}

// LRU 有界：超出 maxKeys 淘汰最久未用 identity（计数重置）。
func TestMemoryStoreLRUBound(t *testing.T) {
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)}
	s := NewMemoryStore(2, nil)
	s.now = clk.Now
	s.Observe(baseInput("id-a"))
	s.Observe(baseInput("id-b"))
	s.Observe(baseInput("id-c")) // 淘汰 id-a
	snap, _ := s.Observe(baseInput("id-a"))
	if got := snap.Windows[Window1m].RequestCount; got != 1 {
		t.Fatalf("evicted identity must restart counting: %v", got)
	}
}

// distinct URI 集合上限：超 1 万停止新增（unique 封顶）并记一次 Warn。
func TestMemoryStoreURICap(t *testing.T) {
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)}
	s, logs := newMemTestStore(clk)
	in := baseInput("id-1")
	var snap *Snapshot
	for i := 0; i < maxURIsPerWindow+5; i++ {
		in.URI = fmt.Sprintf("/u/%d", i)
		snap, _ = s.Observe(in)
	}
	if got := snap.Windows[Window1m].UniqueURICount; got != maxURIsPerWindow {
		t.Fatalf("unique must cap at %d, got %d", maxURIsPerWindow, got)
	}
	// request_count 不受上限影响
	if got := snap.Windows[Window1m].RequestCount; got != maxURIsPerWindow+5 {
		t.Fatalf("request count must keep counting: %v", got)
	}
	if logs.Len() == 0 {
		t.Fatal("cap warn expected")
	}
}

// 窗口桶起点对齐（事件 window_start 字段来源）。
func TestMemoryStoreWindowStartAlignment(t *testing.T) {
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 7, 33, 0, time.UTC)}
	s, _ := newMemTestStore(clk)
	snap, _ := s.Observe(baseInput("id-1"))
	want1m := time.Date(2026, 9, 1, 10, 7, 0, 0, time.UTC)
	want5m := time.Date(2026, 9, 1, 10, 5, 0, 0, time.UTC)
	if !snap.Windows[Window1m].WindowStart.Equal(want1m) {
		t.Fatalf("1m bucket start: %v", snap.Windows[Window1m].WindowStart)
	}
	if !snap.Windows[Window5m].WindowStart.Equal(want5m) {
		t.Fatalf("5m bucket start: %v", snap.Windows[Window5m].WindowStart)
	}
	if got := snap.Windows[Window24h].WindowStart; got.Hour() != 0 {
		t.Fatalf("24h bucket must align to day: %v", got)
	}
}

// 完成桶回放：CompletedWindow = 上一 1m 桶原始整数计数（首桶全 0；跨多桶空闲后清零不陈旧）。
func TestMemoryStoreCompletedWindow(t *testing.T) {
	clk := &memTestClock{now: time.Date(2026, 9, 1, 10, 0, 10, 0, time.UTC)}
	s, _ := newMemTestStore(clk)
	// 首桶：无上一桶数据 → 全 0，window_start 仍为当前桶起点-1m
	snap, _ := s.Observe(baseInput("id-1"))
	if snap.CompletedWindow.RequestCount != 0 {
		t.Fatalf("first bucket completed window must be zero: %+v", snap.CompletedWindow)
	}
	if want := clk.now.Truncate(time.Minute).Add(-time.Minute); !snap.CompletedWindow.WindowStart.Equal(want) {
		t.Fatalf("completed window start: %v, want %v", snap.CompletedWindow.WindowStart, want)
	}
	// 同桶再突发 9 个（含 2 个 404 + 1 个敏感路径）→ 桶内累计 10
	for i := 0; i < 9; i++ {
		in := baseInput("id-1")
		if i < 2 {
			in.Status = 404
		}
		if i == 8 {
			in.SensitivePath = true
		}
		snap, _ = s.Observe(in)
	}
	clk.Advance(51 * time.Second) // 进入下一 1m 桶（10:01:01）
	snap, _ = s.Observe(baseInput("id-1"))
	cw := snap.CompletedWindow
	if cw.RequestCount != 10 || cw.Status404Count != 2 || cw.SensitivePathHits != 1 {
		t.Fatalf("completed window raw counts: %+v", cw)
	}
	if cw.UniqueURICount != 1 {
		t.Fatalf("completed window unique: %d", cw.UniqueURICount)
	}
	if want := clk.now.Truncate(time.Minute).Add(-time.Minute); !cw.WindowStart.Equal(want) {
		t.Fatalf("completed window start after rotation: %v, want %v", cw.WindowStart, want)
	}
	// 原始整数计数，非滑窗估值（估值会含当前桶 + prev 加权 ≈10.83）
	if snap.Windows[Window1m].RequestCount == cw.RequestCount {
		t.Fatalf("completed window must be raw bucket count, not sliding estimate: %v", cw.RequestCount)
	}
	// 跨多桶空闲：上一桶清零（不陈旧回放）
	clk.Advance(5 * time.Minute)
	snap, _ = s.Observe(baseInput("id-1"))
	if snap.CompletedWindow.RequestCount != 0 {
		t.Fatalf("stale completed window must be zero: %+v", snap.CompletedWindow)
	}
}
