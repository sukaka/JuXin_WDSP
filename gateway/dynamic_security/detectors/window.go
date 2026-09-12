package detectors

import (
	"container/list"
	"sync"
	"time"
)

// 进程内滑动窗口与游标状态（behavior/ratelimit/resource 共用基础设施）。
//
// 单节点限制：状态仅存在于本网关进程内存，多网关部署时各节点独立计数，
// 不共享基线；配置重载不重置，进程重启清零。
// 演进：计数存储已抽象为可插拔接口（store.go），默认仍为本文件内存实现；
// Valkey 实现见 jiuzhang_guard/behaviorstore。

// windowSize 行为/限速统计窗口。
const windowSize = time.Minute

// lru 定容 LRU（string 键；非线程安全，由持有方加锁）。
type lru struct {
	cap   int
	ll    *list.List
	items map[string]*list.Element
}

type lruItem struct {
	key string
	val any
}

func newLRU(capacity int) *lru {
	if capacity <= 0 {
		capacity = 1
	}
	return &lru{cap: capacity, ll: list.New(), items: map[string]*list.Element{}}
}

func (l *lru) get(key string) (any, bool) {
	e, ok := l.items[key]
	if !ok {
		return nil, false
	}
	l.ll.MoveToFront(e)
	return e.Value.(lruItem).val, true
}

func (l *lru) set(key string, v any) {
	if e, ok := l.items[key]; ok {
		l.ll.MoveToFront(e)
		e.Value = lruItem{key: key, val: v}
		return
	}
	e := l.ll.PushFront(lruItem{key: key, val: v})
	l.items[key] = e
	if l.ll.Len() > l.cap {
		if back := l.ll.Back(); back != nil {
			delete(l.items, back.Value.(lruItem).key)
			l.ll.Remove(back)
		}
	}
}

// windowEntry 单键窗口状态：当前窗口计数 + 最近已完成窗口样本。
type windowEntry struct {
	windowStart time.Time
	count       int
	history     []int // 已完成窗口计数（追加序，封顶 maxHistoryWindows）
}

// maxHistoryWindows 每键保留的历史窗口样本上限。
const maxHistoryWindows = 10

// windowTracker 进程内 1 分钟滑动窗口计数器（identity+endpoint 维度，LRU 定容）。
type windowTracker struct {
	mu      sync.Mutex
	entries *lru
	now     func() time.Time
}

func newWindowTracker(capacity int, now func() time.Time) *windowTracker {
	if now == nil {
		now = time.Now
	}
	return &windowTracker{entries: newLRU(capacity), now: now}
}

// add 记录一次命中，返回当前窗口计数与已完成窗口样本副本。
// 窗口按自然分钟对齐；跨窗口时归档上一活跃窗口计数（空窗不补零，样本即活跃窗口）。
func (t *windowTracker) add(key string) (int, []int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cur := t.now().UTC().Truncate(windowSize)
	var e *windowEntry
	if v, ok := t.entries.get(key); ok {
		e = v.(*windowEntry)
	} else {
		e = &windowEntry{windowStart: cur}
		t.entries.set(key, e)
	}
	if !e.windowStart.Equal(cur) {
		e.history = append(e.history, e.count)
		if len(e.history) > maxHistoryWindows {
			e.history = e.history[len(e.history)-maxHistoryWindows:]
		}
		e.windowStart = cur
		e.count = 0
	}
	e.count++
	hist := make([]int, len(e.history))
	copy(hist, e.history)
	return e.count, hist
}
