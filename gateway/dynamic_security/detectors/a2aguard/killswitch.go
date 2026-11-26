package a2aguard

import (
	"container/list"
	"sync"
	"time"
)

// LoopTracker A2A 递归调用循环检测器：有界 LRU 内存滑动窗口（默认最大 8192 键，并发安全）。
// 按 (appID, callerKey, taskID_or_path) 严格隔离，防止跨应用或跨主体串扰。
type LoopTracker struct {
	mu      sync.Mutex
	maxKeys int
	order   *list.List
	entries map[string]*list.Element
}

type loopEntry struct {
	key        string
	timestamps []time.Time
	lastSeen   time.Time
}

// NewLoopTracker 创建有界循环滑动窗口追踪器。
func NewLoopTracker(maxKeys int) *LoopTracker {
	if maxKeys <= 0 {
		maxKeys = DefaultLoopMaxKeys
	}
	return &LoopTracker{
		maxKeys: maxKeys,
		order:   list.New(),
		entries: make(map[string]*list.Element),
	}
}

// RecordAndCheck 记录一次调用并判定窗口内调用次数是否超过 maxCalls（> maxCalls 触发熔断）。
func (t *LoopTracker) RecordAndCheck(appID, callerKey, taskOrPath string, window time.Duration, maxCalls int, now time.Time) (count int, exceeded bool) {
	if t == nil || maxCalls <= 0 || window <= 0 {
		return 0, false
	}
	key := appID + "\x00" + callerKey + "\x00" + taskOrPath
	cutoff := now.Add(-window)

	t.mu.Lock()
	defer t.mu.Unlock()

	if el, ok := t.entries[key]; ok {
		ent := el.Value.(*loopEntry)
		ent.timestamps = pruneTimestamps(ent.timestamps, cutoff)
		ent.lastSeen = now
		t.order.MoveToFront(el)
		count = len(ent.timestamps) + 1
		if count > maxCalls {
			return count, true
		}
		ent.timestamps = append(ent.timestamps, now)
		return count, false
	}

	// 淘汰已超出窗口的冷键，必要时按 LRU 淘汰确保总键数 <= maxKeys。
	for i := 0; i < 4 && t.order.Len() >= t.maxKeys; i++ {
		back := t.order.Back()
		if back == nil {
			break
		}
		ent := back.Value.(*loopEntry)
		if !ent.lastSeen.Before(cutoff) {
			break
		}
		t.order.Remove(back)
		delete(t.entries, ent.key)
	}
	for t.order.Len() >= t.maxKeys {
		back := t.order.Back()
		if back == nil {
			break
		}
		ent := back.Value.(*loopEntry)
		t.order.Remove(back)
		delete(t.entries, ent.key)
	}

	ent := &loopEntry{
		key:        key,
		timestamps: []time.Time{now},
		lastSeen:   now,
	}
	el := t.order.PushFront(ent)
	t.entries[key] = el
	return 1, 1 > maxCalls
}

// Len 返回当前活跃追踪键数量（供单测验证有界上限）。
func (t *LoopTracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

func pruneTimestamps(ts []time.Time, cutoff time.Time) []time.Time {
	keep := 0
	for keep < len(ts) && ts[keep].Before(cutoff) {
		keep++
	}
	if keep == 0 {
		return ts
	}
	if keep >= len(ts) {
		return ts[:0]
	}
	n := copy(ts, ts[keep:])
	return ts[:n]
}

// TaintTracker Lethal Trifecta 污点追踪器：有界 LRU 内存表（默认最大 8192 键、120s TTL，并发安全）。
// 按 (appID, callerKey) 严格隔离，记录主体读取机密数据后的污染状态。
type TaintTracker struct {
	mu      sync.Mutex
	maxKeys int
	ttl     time.Duration
	order   *list.List
	entries map[string]*list.Element
}

type taintEntry struct {
	key       string
	source    string
	expiresAt time.Time
}

// NewTaintTracker 创建有界 Lethal Trifecta 污点追踪器。
func NewTaintTracker(maxKeys int, ttl time.Duration) *TaintTracker {
	if maxKeys <= 0 {
		maxKeys = DefaultTaintMaxKeys
	}
	if ttl <= 0 {
		ttl = DefaultTaintTTL
	}
	return &TaintTracker{
		maxKeys: maxKeys,
		ttl:     ttl,
		order:   list.New(),
		entries: make(map[string]*list.Element),
	}
}

// MarkTainted 标记 (appID, callerKey) 已被机密数据读取污染（续期 120s TTL）。
func (t *TaintTracker) MarkTainted(appID, callerKey, source string, now time.Time) {
	if t == nil || callerKey == "" {
		return
	}
	key := appID + "\x00" + callerKey
	exp := now.Add(t.ttl)

	t.mu.Lock()
	defer t.mu.Unlock()

	if el, ok := t.entries[key]; ok {
		ent := el.Value.(*taintEntry)
		ent.source = source
		ent.expiresAt = exp
		t.order.MoveToFront(el)
		return
	}

	for i := 0; i < 4 && t.order.Len() >= t.maxKeys; i++ {
		back := t.order.Back()
		if back == nil {
			break
		}
		ent := back.Value.(*taintEntry)
		if now.Before(ent.expiresAt) {
			break
		}
		t.order.Remove(back)
		delete(t.entries, ent.key)
	}
	for t.order.Len() >= t.maxKeys {
		back := t.order.Back()
		if back == nil {
			break
		}
		ent := back.Value.(*taintEntry)
		t.order.Remove(back)
		delete(t.entries, ent.key)
	}

	el := t.order.PushFront(&taintEntry{
		key:       key,
		source:    source,
		expiresAt: exp,
	})
	t.entries[key] = el
}

// IsTainted 查询 (appID, callerKey) 在当前时刻是否处于未过期的污点状态。
func (t *TaintTracker) IsTainted(appID, callerKey string, now time.Time) (source string, tainted bool) {
	if t == nil || callerKey == "" {
		return "", false
	}
	key := appID + "\x00" + callerKey

	t.mu.Lock()
	defer t.mu.Unlock()

	el, ok := t.entries[key]
	if !ok {
		return "", false
	}
	ent := el.Value.(*taintEntry)
	if !now.Before(ent.expiresAt) {
		t.order.Remove(el)
		delete(t.entries, key)
		return "", false
	}
	t.order.MoveToFront(el)
	return ent.source, true
}

// Len 返回当前污点条目数量（供单测验证有界上限）。
func (t *TaintTracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}
