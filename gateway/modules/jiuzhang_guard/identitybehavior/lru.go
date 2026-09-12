package identitybehavior

import "container/list"

// lru 定容 LRU（string 键；非线程安全，由持有方加锁）。
// 与 dynamic_security/detectors window.go 内部 lru 同一形态（本包不可见其未导出实现，自带一份）。
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

func (l *lru) len() int { return l.ll.Len() }
