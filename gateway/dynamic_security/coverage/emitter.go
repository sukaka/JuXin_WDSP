package coverage

import (
	"sync"
	"sync/atomic"
	"time"
)

// Sink 观测消费端（由装配层实现：批量写事件通道/文件契约/统计存储）。
// 实现必须非阻塞；本包对 Sink 的全部调用位于独立 goroutine。
type Sink interface {
	Store(obs []Observation)
}

// Emitter 有界非阻断发射器：Emit 永不阻塞请求路径；
// 队列满时丢弃新记录并按计数器累计（dropped），丢弃事实本身入聚合展示。
type Emitter struct {
	queue   chan Observation
	sink    Sink
	batch   int
	dropped atomic.Uint64
	emitted atomic.Uint64
	stop    chan struct{}
	wg      sync.WaitGroup
	started atomic.Bool
}

// NewEmitter 创建发射器。capacity 为队列上限（>0），batch 为每次 flush 批大小（>0）。
// sink 为 nil 时记录仅计数不落盘（用于缺省 OFF 与测试）。
func NewEmitter(capacity, batch int, sink Sink) *Emitter {
	if capacity <= 0 {
		capacity = 1024
	}
	if batch <= 0 {
		batch = 128
	}
	return &Emitter{
		queue: make(chan Observation, capacity),
		sink:  sink,
		batch: batch,
		stop:  make(chan struct{}),
	}
}

// Emit 非阻断发射：记录先经契约校验（非法记录丢弃并按 invalid 计数），
// 随后尝试入队；队列满立即丢弃（绝不阻塞请求）。occurred_at 缺省取当前 UTC。
func (e *Emitter) Emit(o Observation) {
	if o.OccurredAt.IsZero() {
		o.OccurredAt = time.Now().UTC()
	}
	if msg := o.Validate(); msg != "" {
		e.dropped.Add(1)
		return
	}
	select {
	case e.queue <- o:
		e.emitted.Add(1)
	default:
		e.dropped.Add(1)
	}
}

// Dropped 累计丢弃数（含非法记录与溢出丢弃）。
func (e *Emitter) Dropped() uint64 { return e.dropped.Load() }

// Emitted 累计入队数。
func (e *Emitter) Emitted() uint64 { return e.emitted.Load() }

// Start 启动后台消费 goroutine（幂等）；批量子时间窗 flush 到 Sink。
// flush 间隔固定 200ms（与现有事件通道量级一致，不引入新旋钮）。
func (e *Emitter) Start() {
	if !e.started.CompareAndSwap(false, true) {
		return
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		buf := make([]Observation, 0, e.batch)
		flush := func() {
			if len(buf) == 0 {
				return
			}
			if e.sink != nil {
				out := make([]Observation, len(buf))
				copy(out, buf)
				e.sink.Store(out)
			}
			buf = buf[:0]
		}
		for {
			select {
			case o := <-e.queue:
				buf = append(buf, o)
				if len(buf) >= e.batch {
					flush()
				}
			case <-ticker.C:
				flush()
			case <-e.stop:
				for {
					select {
					case o := <-e.queue:
						buf = append(buf, o)
						if len(buf) >= e.batch {
							flush()
						}
					default:
						flush()
						return
					}
				}
			}
		}
	}()
}

// Stop 停止消费并尽力排空队列（等待 goroutine 退出）。
func (e *Emitter) Stop() {
	if !e.started.CompareAndSwap(true, false) {
		return
	}
	close(e.stop)
	e.wg.Wait()
}
