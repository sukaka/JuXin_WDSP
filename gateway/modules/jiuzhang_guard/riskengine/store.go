package riskengine

import (
	"sync"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
	"go.uber.org/zap"
)

// SignalEntry 单条风险信号明细（signal_type、score、reason、时间戳——事件可解释性载体）。
type SignalEntry struct {
	Type   string    `json:"type"`
	Score  int       `json:"score"`
	Reason string    `json:"reason,omitempty"`
	At     time.Time `json:"at"`
}

// Store 身份风险累加存储（Valkey / 进程内存实现；实现内 fail-open，error 返回值仅为防御性兜底）。
type Store interface {
	// Add 追加信号明细（同调用多条一次原子往返/单锁临界区）。
	Add(identityKey string, entries ...SignalEntry) error
	// State 滑窗内求和并截断 [0,100]，返回窗口内完整明细（按时间升序）。
	State(identityKey string) (score int, entries []SignalEntry, err error)
	// Close 释放资源（内存实现为 no-op；Valkey 实现不关闭共享连接——连接归共享引擎所有）。
	Close() error
}

// MemoryStore 进程内风险累加（identity 键 LRU 有界；单节点语义——多节点部署各节点独立
// 累计，跨节点共享用 Valkey 实现）。
type MemoryStore struct {
	ids    *counters.MemoryMap
	window time.Duration
	now    func() time.Time
}

type memRisk struct {
	mu      sync.Mutex
	entries []SignalEntry
}

// NewMemoryStore 构造内存存储（window<=0 取默认 24h；maxKeys<=0 取计数器默认上限）。
func NewMemoryStore(window time.Duration, maxKeys int, logger *zap.Logger) *MemoryStore {
	if window <= 0 {
		window = time.Duration(DefaultSignalWindowSeconds) * time.Second
	}
	return &MemoryStore{
		ids:    counters.NewMemoryMap(maxKeys),
		window: window,
		now:    time.Now,
	}
}

// Add 追加信号：先淘汰窗口外明细再入账，超 MaxEntriesPerIdentity 淘汰最旧（有界内存纪律）。
func (s *MemoryStore) Add(identityKey string, entries ...SignalEntry) error {
	if len(entries) == 0 {
		return nil
	}
	v := s.ids.GetOrCreate(identityKey, func() interface{} { return &memRisk{} })
	r := v.(*memRisk)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = pruneExpired(r.entries, s.now().Add(-s.window))
	r.entries = append(r.entries, entries...)
	if len(r.entries) > MaxEntriesPerIdentity {
		r.entries = append([]SignalEntry(nil), r.entries[len(r.entries)-MaxEntriesPerIdentity:]...)
	}
	return nil
}

// State 滑窗求和并截断 [0,100]（返回明细副本，调用方只读）。
// 使用只读 Get 避免未建档良性身份触发 GetOrCreate 插入并挤出高风险受罚身份（H-08）。
func (s *MemoryStore) State(identityKey string) (int, []SignalEntry, error) {
	v, ok := s.ids.Get(identityKey)
	if !ok || v == nil {
		return 0, nil, nil
	}
	r := v.(*memRisk)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = pruneExpired(r.entries, s.now().Add(-s.window))
	sum := 0
	for _, e := range r.entries {
		sum += e.Score
	}
	out := make([]SignalEntry, len(r.entries))
	copy(out, r.entries)
	return clampScore(sum), out, nil
}

// Close 内存实现无资源释放（no-op）。
func (s *MemoryStore) Close() error { return nil }

// pruneExpired 淘汰窗口外明细（条目按时间近似有序，前缀淘汰后即返回）。
func pruneExpired(entries []SignalEntry, cutoff time.Time) []SignalEntry {
	i := 0
	for i < len(entries) && entries[i].At.Before(cutoff) {
		i++
	}
	if i == 0 {
		return entries
	}
	return append([]SignalEntry(nil), entries[i:]...)
}

// clampScore 风险分截断 [0,100]（契约）。
func clampScore(sum int) int {
	if sum < 0 {
		return 0
	}
	if sum > maxScore {
		return maxScore
	}
	return sum
}
