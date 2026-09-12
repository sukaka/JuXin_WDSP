// metrics_test.go 进程内指标包单测：耗时累计/快照/渲染与内存采样。
package metrics

import (
	"strings"
	"testing"
	"time"
)

// TestObserveAccumulates 耗时序列累计 count/sum/max；未注册名与非正时长忽略。
func TestObserveAccumulates(t *testing.T) {
	base := ReadSnapshot().Durations[ParseRequestDuration]

	Observe(ParseRequestDuration, 10*time.Millisecond)
	Observe(ParseRequestDuration, 30*time.Millisecond)
	Observe("no_such_series", time.Second) // 未注册名忽略
	Observe(ParseRequestDuration, 0)       // 非正时长忽略
	Observe(ParseRequestDuration, -time.Millisecond)

	got := ReadSnapshot().Durations[ParseRequestDuration]
	if got.Count-base.Count != 2 {
		t.Errorf("count 增量 = %d, want 2", got.Count-base.Count)
	}
	if got.Sum-base.Sum != 40*time.Millisecond {
		t.Errorf("sum 增量 = %v, want 40ms", got.Sum-base.Sum)
	}
	if got.Max < 30*time.Millisecond {
		t.Errorf("max = %v, want >= 30ms", got.Max)
	}
}

// TestTrack Track 收尾函数登记正时长观测。
func TestTrack(t *testing.T) {
	base := ReadSnapshot().Durations[ParseRequestDuration]
	done := Track(ParseRequestDuration)
	done()
	if got := ReadSnapshot().Durations[ParseRequestDuration]; got.Count != base.Count+1 {
		t.Errorf("Track 后 count = %d, want %d", got.Count, base.Count+1)
	}
}

// TestRenderSnapshot 渲染含耗时三段与内存四项，值与快照一致。
func TestRenderSnapshot(t *testing.T) {
	out := RenderSnapshot(Snapshot{
		Durations: map[string]DurationStat{
			ParseRequestDuration: {Count: 3, Sum: 1500 * time.Millisecond, Max: 800 * time.Millisecond},
		},
		MemAllocBytes:  1024,
		HeapInuseBytes: 2048,
		SysBytes:       4096,
		Goroutines:     7,
	})
	for _, want := range []string{
		"# TYPE api_parse_request_duration_seconds_count counter\n",
		"api_parse_request_duration_seconds_count 3\n",
		"api_parse_request_duration_seconds_sum 1.5\n",
		"api_parse_request_duration_seconds_max 0.8\n",
		"process_memory_alloc_bytes 1024\n",
		"process_memory_heap_inuse_bytes 2048\n",
		"process_memory_sys_bytes 4096\n",
		"process_goroutines 7\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("输出缺少 %q", strings.TrimSpace(want))
		}
	}
}

// TestRenderLive 实时渲染：内存采样非零（当前进程必然占有内存）。
func TestRenderLive(t *testing.T) {
	snap := ReadSnapshot()
	if snap.MemAllocBytes == 0 || snap.SysBytes == 0 || snap.Goroutines == 0 {
		t.Errorf("内存/goroutine 采样为零: %+v", snap)
	}
	out := Render()
	if !strings.Contains(out, "process_memory_alloc_bytes ") {
		t.Error("Render 缺少内存指标")
	}
}

// TestNewDurationSeriesRegistered 检测耗时与响应解析耗时序列已注册（Observe 生效、Render 输出三段）。
func TestNewDurationSeriesRegistered(t *testing.T) {
	for _, name := range []string{DetectDuration, ResponseParseDuration} {
		base := ReadSnapshot().Durations[name]
		Observe(name, 5*time.Millisecond)
		got := ReadSnapshot().Durations[name]
		if got.Count != base.Count+1 {
			t.Errorf("%s Observe 后 count 未增: %+v → %+v", name, base, got)
		}
	}
	out := Render()
	for _, want := range []string{
		"api_detect_duration_seconds_count ",
		"api_detect_duration_seconds_sum ",
		"api_detect_duration_seconds_max ",
		"api_response_parse_duration_seconds_count ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Render 缺少 %q", strings.TrimSpace(want))
		}
	}
}

// TestEventBacklogGauge setter 挂接前不输出该序列（不报假值）；挂接后快照/渲染携带深度。
func TestEventBacklogGauge(t *testing.T) {
	snap := ReadSnapshot()
	if snap.EventBacklogMounted {
		// 同包其他测试可能已挂接：只能断言渲染与快照一致
		if !strings.Contains(RenderSnapshot(snap), "api_event_backlog ") {
			t.Error("已挂接时 Render 必须输出 api_event_backlog")
		}
	} else if strings.Contains(RenderSnapshot(snap), "api_event_backlog") {
		t.Error("未挂接时 Render 不得输出 api_event_backlog（不报假值）")
	}

	SetEventBacklog(7)
	snap = ReadSnapshot()
	if !snap.EventBacklogMounted || snap.EventBacklog != 7 {
		t.Fatalf("SetEventBacklog 后快照 = %+v, want mounted depth 7", snap)
	}
	if !strings.Contains(RenderSnapshot(snap), "api_event_backlog 7\n") {
		t.Error("Render 缺少 api_event_backlog 7")
	}
	SetEventBacklog(-3) // 负值按 0 计
	if got := ReadSnapshot().EventBacklog; got != 0 {
		t.Errorf("负深度应按 0 计, got %d", got)
	}
}
