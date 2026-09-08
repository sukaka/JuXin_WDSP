package selfmon

import "testing"

func TestDegradeAfterThreeOver(t *testing.T) {
	m := NewMonitor(20, 512)
	over := Sample{CPUPercent: 25, MemoryMB: 100}
	for i := 0; i < 2; i++ {
		d, changed, _ := m.Check(over)
		if d || changed {
			t.Fatalf("第 %d 次不应降级", i+1)
		}
	}
	d, changed, reason := m.Check(over)
	if !d || !changed || reason == "" {
		t.Fatalf("连续 3 次超阈值应降级: d=%v changed=%v", d, changed)
	}
	if !m.Degraded() {
		t.Fatal("状态应为 degraded")
	}
}

func TestMemoryOnlyTriggers(t *testing.T) {
	m := NewMonitor(20, 512)
	over := Sample{CPUPercent: 1, MemoryMB: 600}
	for i := 0; i < 3; i++ {
		m.Check(over)
	}
	if !m.Degraded() {
		t.Fatal("内存超阈值同样应降级")
	}
}

func TestOverCounterResetsOnNormal(t *testing.T) {
	m := NewMonitor(20, 512)
	m.Check(Sample{CPUPercent: 25})
	m.Check(Sample{CPUPercent: 25})
	m.Check(Sample{CPUPercent: 5, MemoryMB: 100}) // 正常 → 计数清零
	m.Check(Sample{CPUPercent: 25})
	m.Check(Sample{CPUPercent: 25})
	if m.Degraded() {
		t.Fatal("中间回落后不应凑满 3 次")
	}
}

func TestRecoverAfterThreeUnder80Percent(t *testing.T) {
	m := NewMonitor(20, 512) // 80% 线：cpu 16%、mem 409.6MB
	for i := 0; i < 3; i++ {
		m.Check(Sample{CPUPercent: 30})
	}
	if !m.Degraded() {
		t.Fatal("应先进入降级")
	}
	// 高于 80% 线：不计恢复
	d, _, _ := m.Check(Sample{CPUPercent: 18, MemoryMB: 100})
	if !d {
		t.Fatal("18% > 16% 不应恢复")
	}
	under := Sample{CPUPercent: 10, MemoryMB: 200}
	m.Check(under)
	m.Check(under)
	d, changed, _ := m.Check(under)
	if d || !changed {
		t.Fatalf("连续 3 次低于 80%% 应恢复: d=%v changed=%v", d, changed)
	}
	if m.Degraded() {
		t.Fatal("状态应恢复")
	}
}

func TestRecoverCounterResets(t *testing.T) {
	m := NewMonitor(20, 512)
	for i := 0; i < 3; i++ {
		m.Check(Sample{CPUPercent: 30})
	}
	m.Check(Sample{CPUPercent: 10})
	m.Check(Sample{CPUPercent: 10})
	m.Check(Sample{CPUPercent: 18}) // 超 80% 线 → 恢复计数清零
	m.Check(Sample{CPUPercent: 10})
	m.Check(Sample{CPUPercent: 10})
	if !m.Degraded() {
		t.Fatal("恢复计数被清零，不应恢复")
	}
}

func TestSetLimits(t *testing.T) {
	m := NewMonitor(0, 0) // 默认 20/512
	m.SetLimits(50, 1024)
	for i := 0; i < 3; i++ {
		m.Check(Sample{CPUPercent: 30, MemoryMB: 600})
	}
	if m.Degraded() {
		t.Fatal("阈值提高后 30%/600MB 不应降级")
	}
}

// fakeSampler 注入假采样（Run 级联调用路径验证）。
type fakeSampler struct {
	samples []Sample
	idx     int
}

func (f *fakeSampler) Sample() (Sample, error) {
	s := f.samples[f.idx%len(f.samples)]
	f.idx++
	return s, nil
}

func TestFakeSamplerDrivesMonitor(t *testing.T) {
	f := &fakeSampler{samples: []Sample{{CPUPercent: 90}, {CPUPercent: 90}, {CPUPercent: 90}, {CPUPercent: 1}, {CPUPercent: 1}, {CPUPercent: 1}}}
	m := NewMonitor(20, 512)
	states := make([]bool, 0, 6)
	for i := 0; i < 6; i++ {
		s, _ := f.Sample()
		d, _, _ := m.Check(s)
		states = append(states, d)
	}
	want := []bool{false, false, true, true, true, false}
	for i := range want {
		if states[i] != want[i] {
			t.Fatalf("第 %d 次: got %v want %v (全序列 %v)", i, states[i], want[i], states)
		}
	}
}
