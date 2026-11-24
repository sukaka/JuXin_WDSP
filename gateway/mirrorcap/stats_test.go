package mirrorcap

import (
	"sync/atomic"
	"testing"
	"time"
)

// Linux PACKET_STATISTICS 每次读取后由内核清零（返回周期增量），Stats.Logger 应直接累加，
// 不得减去上周期值（否则连续两个周期相同丢包数会被漏算为 0）。
func TestStatsLoggerAccumulatesKernelDeltaDrops(t *testing.T) {
	st := &Stats{}
	deltas := []uint32{10, 10, 15}
	var idx atomic.Int32
	done := make(chan struct{})
	stop := make(chan struct{})

	go func() {
		st.Logger(5*time.Millisecond, func() (uint32, uint32, error) {
			i := int(idx.Add(1) - 1)
			if i >= len(deltas) {
				return 0, 0, nil
			}
			return 100, deltas[i], nil
		}, stop)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for idx.Load() < int32(len(deltas)) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(15 * time.Millisecond)
	close(stop)
	<-done

	if got := st.PacketsDropped.Load(); got != 35 {
		t.Fatalf("PacketsDropped = %d, want 35 (10+10+15)", got)
	}
}
