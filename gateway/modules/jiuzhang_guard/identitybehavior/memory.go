package identitybehavior

import (
	"sync"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
	"go.uber.org/zap"
)

// 内存实现容量纪律（防随机 identity/URI 耗尽内存）：
//   - identity 键 LRU 有界（默认 5 万，可配 max_counter_keys 复用）；
//   - 每窗口 distinct URI 集合有界（超 1 万停止新增并记一次 Warn）；
//   - 全局 known-URI 集合同样有界（同上限同告警）；
//   - (identity,uri) method/参数签名跟踪 LRU 有界（512 条/identity）。
const (
	// DefaultMaxIdentityKeys 内存存储默认 identity 键上限。
	DefaultMaxIdentityKeys = 50000
	maxURIsPerWindow       = 10000
	maxKnownURIs           = 10000
	maxTrackedURIs         = 512
	maxMethodsPerURI       = 16
	maxParamSigsPerURI     = 256
	maxEnumValuesPerWindow = 10000
)

// 计数槽位（双桶计数数组索引；attack 预留位不落存储——恒 0 直接写快照）。
const (
	cReq = iota
	c401
	c403
	c404
	c405
	c500
	cAuthFail
	cParamMut
	cSensitive
	cNewURI
	numCounters
)

// MemoryStore 进程内行为滑窗统计（LRU 有界；单节点语义——多节点部署各节点独立计数，
// 跨节点共享用 Valkey 实现）。
type MemoryStore struct {
	ids      *counters.MemoryMap
	logger   *zap.Logger
	now      func() time.Time
	warnOnce sync.Once // URI 集合上限告警（每实例一次，防日志洪泛）
}

// NewMemoryStore 构造内存存储（maxKeys<=0 取 DefaultMaxIdentityKeys；logger 可为 nil——
// 上限告警静默降级，装配层必须传 logger）。
func NewMemoryStore(maxKeys int, logger *zap.Logger) *MemoryStore {
	if maxKeys <= 0 {
		maxKeys = DefaultMaxIdentityKeys
	}
	return &MemoryStore{
		ids:    counters.NewMemoryMap(maxKeys),
		logger: logger,
		now:    time.Now,
	}
}

type memIdentity struct {
	mu        sync.Mutex
	windows   [NumWindows]memWindow
	knownURIs map[string]struct{}
	uris      *lru // uriHash -> *memURI（method/参数签名跟踪）
}

type memWindow struct {
	curStart       time.Time
	cur            [numCounters]int64
	prev           [numCounters]int64
	uriSet         map[string]struct{}
	prevURISet     map[string]struct{}
	accountSet     map[string]struct{}
	prevAccountSet map[string]struct{}
	objectSet      map[string]struct{}
	prevObjectSet  map[string]struct{}
}

type memURI struct {
	methods   map[string]struct{}
	paramSigs map[string]struct{}
}

func newMemIdentity() *memIdentity {
	return &memIdentity{
		knownURIs: map[string]struct{}{},
		uris:      newLRU(maxTrackedURIs),
	}
}

// Observe 记账并返回快照（单 identity 锁临界区；跨 identity 无共享态）。
func (s *MemoryStore) Observe(in ObserveInput) (*Snapshot, error) {
	now := s.now().UTC()
	v := s.ids.GetOrCreate(in.IdentityKey, func() interface{} { return newMemIdentity() })
	id := v.(*memIdentity)
	id.mu.Lock()
	defer id.mu.Unlock()

	uriHash := counters.HashParts(in.URI)

	// (identity,uri) 维度：distinct method 与参数签名新旧（30m 语义由跟踪集近似——
	// 集合随 identity LRU 存活，超时由窗口桶自然淘汰；内存实现语义见包文档）。
	st := s.uriState(id, uriHash)
	if len(st.methods) < maxMethodsPerURI {
		st.methods[in.Method] = struct{}{}
	}
	paramNew := false
	if in.ParamSignature != "" {
		if _, ok := st.paramSigs[in.ParamSignature]; !ok && len(st.paramSigs) < maxParamSigsPerURI {
			st.paramSigs[in.ParamSignature] = struct{}{}
			paramNew = true
		}
	}

	// 全局 known-URI（48h 语义由 identity 存活期近似）：首次出现即 new
	knownNew := false
	if _, ok := id.knownURIs[uriHash]; !ok {
		if len(id.knownURIs) < maxKnownURIs {
			id.knownURIs[uriHash] = struct{}{}
			knownNew = true
		} else {
			s.warnCap()
		}
	}

	snap := &Snapshot{DistinctMethods: len(st.methods), ParamSigNew: paramNew}
	for w := Window1m; w < NumWindows; w++ {
		mw := &id.windows[w]
		mw.rotate(now, w.Duration())
		mw.cur[cReq]++
		switch in.Status {
		case 401:
			mw.cur[c401]++
			mw.cur[cAuthFail]++
		case 403:
			mw.cur[c403]++
		case 404:
			mw.cur[c404]++
		case 405:
			mw.cur[c405]++
		case 500:
			mw.cur[c500]++
		}
		if paramNew {
			mw.cur[cParamMut]++
		}
		if in.SensitivePath {
			mw.cur[cSensitive]++
		}
		if in.AccountKey != "" {
			if mw.accountSet == nil {
				mw.accountSet = map[string]struct{}{}
			}
			if _, exists := mw.accountSet[in.AccountKey]; !exists {
				if len(mw.accountSet) < maxEnumValuesPerWindow {
					mw.accountSet[in.AccountKey] = struct{}{}
				} else {
					s.warnCap()
				}
			}
		}
		if in.ObjectKey != "" {
			if mw.objectSet == nil {
				mw.objectSet = map[string]struct{}{}
			}
			if _, exists := mw.objectSet[in.ObjectKey]; !exists {
				if len(mw.objectSet) < maxEnumValuesPerWindow {
					mw.objectSet[in.ObjectKey] = struct{}{}
				} else {
					s.warnCap()
				}
			}
		}
		if knownNew {
			mw.cur[cNewURI]++
		}
		if _, ok := mw.uriSet[uriHash]; !ok {
			if len(mw.uriSet) < maxURIsPerWindow {
				if mw.uriSet == nil {
					mw.uriSet = map[string]struct{}{}
				}
				mw.uriSet[uriHash] = struct{}{}
			} else {
				s.warnCap()
			}
		}
		est := mw.estimate(now, w.Duration())
		snap.Windows[w] = WindowCounts{
			WindowStart:            mw.curStart,
			RequestCount:           est[cReq],
			UniqueURICount:         int64(mw.unique()),
			NewURICount:            est[cNewURI],
			Status401Count:         est[c401],
			Status403Count:         est[c403],
			Status404Count:         est[c404],
			Status405Count:         est[c405],
			Status500Count:         est[c500],
			AuthFailCount:          est[cAuthFail],
			ParameterMutationCount: est[cParamMut],
			SensitivePathHits:      est[cSensitive],
			AccountEnumCount:       int64(mw.uniqueSet(mw.accountSet, mw.prevAccountSet)),
			ObjectEnumCount:        int64(mw.uniqueSet(mw.objectSet, mw.prevObjectSet)),
			// AttackHitCount 预留恒 0
		}
		if w == Window1m {
			// 完成桶回放：上一 1m 桶原始整数计数（首桶/跨多桶空闲时 prev 已清零 → 全 0，
			// window_start 仍确定性地取当前桶起点-1m）。
			snap.CompletedWindow = WindowCounts{
				WindowStart:            mw.curStart.Add(-w.Duration()),
				RequestCount:           float64(mw.prev[cReq]),
				UniqueURICount:         int64(len(mw.prevURISet)),
				NewURICount:            float64(mw.prev[cNewURI]),
				Status401Count:         float64(mw.prev[c401]),
				Status403Count:         float64(mw.prev[c403]),
				Status404Count:         float64(mw.prev[c404]),
				Status405Count:         float64(mw.prev[c405]),
				Status500Count:         float64(mw.prev[c500]),
				AuthFailCount:          float64(mw.prev[cAuthFail]),
				ParameterMutationCount: float64(mw.prev[cParamMut]),
				SensitivePathHits:      float64(mw.prev[cSensitive]),
				AccountEnumCount:       int64(len(mw.prevAccountSet)),
				ObjectEnumCount:        int64(len(mw.prevObjectSet)),
			}
		}
	}
	return snap, nil
}

// uriState 取 (identity,uri) 跟踪状态（LRU 定容；逐出后 method/参数签名重新学习——
// 内存实现的有界近似，防随机 URI 泛洪）。
func (s *MemoryStore) uriState(id *memIdentity, uriHash string) *memURI {
	if v, ok := id.uris.get(uriHash); ok {
		return v.(*memURI)
	}
	st := &memURI{
		methods:   map[string]struct{}{},
		paramSigs: map[string]struct{}{},
	}
	id.uris.set(uriHash, st)
	return st
}

// rotate 双桶轮转：进入新桶时上一桶归档为 previous（跨多桶无活动时 previous 清空，
// 防陈旧计数污染估值）。
func (mw *memWindow) rotate(now time.Time, d time.Duration) {
	cur := now.Truncate(d)
	if mw.curStart.Equal(cur) {
		return
	}
	if mw.curStart.Equal(cur.Add(-d)) {
		mw.prev = mw.cur
		mw.prevURISet = mw.uriSet
		mw.prevAccountSet = mw.accountSet
		mw.prevObjectSet = mw.objectSet
	} else {
		mw.prev = [numCounters]int64{}
		mw.prevURISet = nil
		mw.prevAccountSet = nil
		mw.prevObjectSet = nil
	}
	mw.cur = [numCounters]int64{}
	mw.uriSet = nil
	mw.accountSet = nil
	mw.objectSet = nil
	mw.curStart = cur
}

// estimate 滑窗估值：current + previous×(1-elapsed/window)。
func (mw *memWindow) estimate(now time.Time, d time.Duration) [numCounters]float64 {
	frac := 1 - now.Sub(mw.curStart).Seconds()/d.Seconds()
	if frac < 0 {
		frac = 0
	}
	var out [numCounters]float64
	for i := range out {
		out[i] = float64(mw.cur[i]) + float64(mw.prev[i])*frac
	}
	return out
}

// unique distinct URI 估计：|current ∪ previous|（内存实现为精确集合）。
func (mw *memWindow) unique() int {
	n := len(mw.uriSet)
	for u := range mw.prevURISet {
		if _, ok := mw.uriSet[u]; !ok {
			n++
		}
	}
	return n
}

func (mw *memWindow) uniqueSet(cur, prev map[string]struct{}) int {
	n := len(cur)
	for k := range prev {
		if _, ok := cur[k]; !ok {
			n++
		}
	}
	return n
}

// warnCap URI 集合达上限告警（每实例一次；计数仍继续，仅 distinct 集合停止增长——
// 超限时 unique/new 低估，OBSERVE 级信号可接受，防内存攻击优先）。
func (s *MemoryStore) warnCap() {
	s.warnOnce.Do(func() {
		if s.logger != nil {
			s.logger.Warn("identitybehavior: distinct URI set reached cap, stop tracking new URIs (memory protection)")
		}
	})
}

// Close 内存实现无资源释放（no-op）。
func (s *MemoryStore) Close() error { return nil }
