// health_test.go 健康评分公式单测（health.go 分档表全覆盖：固定分档、
// 每档边界两侧、叠加下限 0、metrics/时钟缺省跳过；公式与 PHASE2 契约 §4 一致）。
package agents

import (
	"testing"
)

func int64Ptr(v int64) *int64 { return &v }

// TestComputeHealthFixedScores DISABLED/OFFLINE 固定低分短路。
func TestComputeHealthFixedScores(t *testing.T) {
	score, reasons := ComputeHealth(HealthInput{Status: StatusDisabled})
	if score != 0 || len(reasons) != 1 || reasons[0] != "agent_disabled" {
		t.Errorf("DISABLED = %d %v, want 0 [agent_disabled]", score, reasons)
	}
	// DISABLED 下即使 metrics 恶劣也不叠加（短路）
	score, _ = ComputeHealth(HealthInput{Status: StatusDisabled, Metrics: &Metrics{CPUPercent: 99}})
	if score != 0 {
		t.Errorf("DISABLED 短路 = %d, want 0", score)
	}
	score, reasons = ComputeHealth(HealthInput{Status: StatusOffline})
	if score != 10 || len(reasons) != 1 || reasons[0] != "agent_offline" {
		t.Errorf("OFFLINE = %d %v, want 10 [agent_offline]", score, reasons)
	}
}

// TestComputeHealthBands 各扣分档边界（恰在阈值不扣，超过阈值即扣——公式统一为严格大于）。
func TestComputeHealthBands(t *testing.T) {
	cases := []struct {
		name    string
		in      HealthInput
		want    int
		reasons []string
	}{
		{
			name: "全正常满分",
			in: HealthInput{Status: StatusOnline, Metrics: &Metrics{
				CPUPercent: 10, MemoryMB: 100, PacketsReceived: 10000, PacketsDropped: 10,
				QueueDepth: 5, BufferBytes: 1 << 20,
			}, ClockOffsetMS: int64Ptr(120), ConfigVersion: 3, AppliedConfigVersion: 3,
				CPULimitPercent: 20, MemoryLimitMB: 512, BufferLimitMB: 512},
			want:    100,
			reasons: nil,
		},
		{
			name:    "自报 ERROR −20",
			in:      HealthInput{Status: StatusError},
			want:    80,
			reasons: []string{"status_error"},
		},
		{
			name:    "自报 DEGRADED −10",
			in:      HealthInput{Status: StatusDegraded},
			want:    90,
			reasons: []string{"status_degraded"},
		},
		{
			name:    "CPU 恰等于默认阈值落入偏高档 −10",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{CPUPercent: 80}},
			want:    90,
			reasons: []string{"cpu_high"},
		},
		{
			name:    "CPU 恰在偏高阈值（80%×阈值）不扣",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{CPUPercent: 64}},
			want:    100,
			reasons: nil,
		},
		{
			name:    "CPU 超默认阈值 −25",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{CPUPercent: 80.1}},
			want:    75,
			reasons: []string{"cpu_over_limit"},
		},
		{
			name:    "CPU 超策略阈值 −25",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{CPUPercent: 21}, CPULimitPercent: 20},
			want:    75,
			reasons: []string{"cpu_over_limit"},
		},
		{
			name:    "CPU 偏高（>80%×阈值）−10",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{CPUPercent: 17}, CPULimitPercent: 20},
			want:    90,
			reasons: []string{"cpu_high"},
		},
		{
			name:    "CPU 恰在 80%×阈值不扣",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{CPUPercent: 16}, CPULimitPercent: 20},
			want:    100,
			reasons: nil,
		},
		{
			name:    "内存超限 −25",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{MemoryMB: 513}, MemoryLimitMB: 512},
			want:    75,
			reasons: []string{"memory_over_limit"},
		},
		{
			name:    "内存偏高 −10",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{MemoryMB: 410}, MemoryLimitMB: 512},
			want:    90,
			reasons: []string{"memory_high"},
		},
		{
			name:    "内存恰等于阈值落入偏高档 −10",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{MemoryMB: 512}, MemoryLimitMB: 512},
			want:    90,
			reasons: []string{"memory_high"},
		},
		{
			name:    "无内存限制跳过内存档",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{MemoryMB: 999999}},
			want:    100,
			reasons: nil,
		},
		{
			name:    "丢包率严重（>10%）−25",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{PacketsReceived: 100, PacketsDropped: 11}},
			want:    75,
			reasons: []string{"drop_rate_critical"},
		},
		{
			name:    "丢包率偏高（>1%）−10",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{PacketsReceived: 1000, PacketsDropped: 11}},
			want:    90,
			reasons: []string{"drop_rate_high"},
		},
		{
			name:    "丢包率恰 1% 不扣",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{PacketsReceived: 999, PacketsDropped: 10}},
			want:    100,
			reasons: nil,
		},
		{
			name:    "received 为 0 时分母 +1 不除零",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{PacketsReceived: 0, PacketsDropped: 0}},
			want:    100,
			reasons: nil,
		},
		{
			name:    "队列积压严重（>5000）−20",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{QueueDepth: 5001}},
			want:    80,
			reasons: []string{"queue_overflow"},
		},
		{
			name:    "队列积压（>1000）−10",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{QueueDepth: 1001}},
			want:    90,
			reasons: []string{"queue_high"},
		},
		{
			name:    "队列恰 1000 不扣",
			in:      HealthInput{Status: StatusOnline, Metrics: &Metrics{QueueDepth: 1000}},
			want:    100,
			reasons: nil,
		},
		{
			name: "缓存接近上限（>90%）−20",
			in: HealthInput{Status: StatusOnline,
				Metrics: &Metrics{BufferBytes: 461 << 20}, BufferLimitMB: 512}, // 461/512 ≈ 90.04%
			want:    80,
			reasons: []string{"buffer_near_full"},
		},
		{
			name: "缓存偏高（>75%）−10",
			in: HealthInput{Status: StatusOnline,
				Metrics: &Metrics{BufferBytes: 385 << 20}, BufferLimitMB: 512}, // 385/512 ≈ 75.2%
			want:    90,
			reasons: []string{"buffer_high"},
		},
		{
			name: "缓存恰 75% 不扣",
			in: HealthInput{Status: StatusOnline,
				Metrics: &Metrics{BufferBytes: 384 << 20}, BufferLimitMB: 512},
			want:    100,
			reasons: nil,
		},
		{
			name: "无策略时按默认缓存上限 512MB",
			in: HealthInput{Status: StatusOnline,
				Metrics: &Metrics{BufferBytes: 461 << 20}},
			want:    80,
			reasons: []string{"buffer_near_full"},
		},
		{
			name:    "时钟偏移超阈（>5000ms）−15",
			in:      HealthInput{Status: StatusOnline, ClockOffsetMS: int64Ptr(5001)},
			want:    85,
			reasons: []string{"clock_drift"},
		},
		{
			name:    "时钟偏移负值取绝对值",
			in:      HealthInput{Status: StatusOnline, ClockOffsetMS: int64Ptr(-5001)},
			want:    85,
			reasons: []string{"clock_drift"},
		},
		{
			name:    "时钟偏移偏大（>2000ms）−5",
			in:      HealthInput{Status: StatusOnline, ClockOffsetMS: int64Ptr(2001)},
			want:    95,
			reasons: []string{"clock_skew"},
		},
		{
			name:    "时钟偏移恰 2000ms 不扣",
			in:      HealthInput{Status: StatusOnline, ClockOffsetMS: int64Ptr(2000)},
			want:    100,
			reasons: nil,
		},
		{
			name:    "时钟偏移缺省跳过时钟档",
			in:      HealthInput{Status: StatusOnline},
			want:    100,
			reasons: nil,
		},
		{
			name:    "配置未同步 −15",
			in:      HealthInput{Status: StatusOnline, ConfigVersion: 5, AppliedConfigVersion: 4},
			want:    85,
			reasons: []string{"config_not_synced"},
		},
		{
			name:    "metrics 缺省跳过资源类档位",
			in:      HealthInput{Status: StatusOnline, ConfigVersion: 1, AppliedConfigVersion: 1},
			want:    100,
			reasons: nil,
		},
		{
			name: "叠加扣分下限 0",
			in: HealthInput{Status: StatusError, Metrics: &Metrics{
				CPUPercent: 99, MemoryMB: 9999, PacketsReceived: 1, PacketsDropped: 100,
				QueueDepth: 9999, BufferBytes: 1 << 40,
			}, ClockOffsetMS: int64Ptr(99999), ConfigVersion: 2, AppliedConfigVersion: 1,
				CPULimitPercent: 20, MemoryLimitMB: 512, BufferLimitMB: 512},
			want: 0,
			reasons: []string{"status_error", "cpu_over_limit", "memory_over_limit",
				"drop_rate_critical", "queue_overflow", "buffer_near_full", "clock_drift", "config_not_synced"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			score, reasons := ComputeHealth(tc.in)
			if score != tc.want {
				t.Errorf("score = %d, want %d", score, tc.want)
			}
			if len(reasons) != len(tc.reasons) {
				t.Fatalf("reasons = %v, want %v", reasons, tc.reasons)
			}
			for i := range reasons {
				if reasons[i] != tc.reasons[i] {
					t.Fatalf("reasons = %v, want %v", reasons, tc.reasons)
				}
			}
		})
	}
}

// TestComputeHealthAllNormal 全正常 100 分且无扣分原因（reasons 非 nil）。
func TestComputeHealthAllNormal(t *testing.T) {
	score, reasons := ComputeHealth(HealthInput{
		Status: StatusOnline,
		Metrics: &Metrics{
			CPUPercent: 3.2, MemoryMB: 128.5, PacketsReceived: 900000, PacketsDropped: 100,
			QueueDepth: 12, BufferBytes: 10 << 20,
		},
		ClockOffsetMS:        int64Ptr(150),
		ConfigVersion:        12,
		AppliedConfigVersion: 12,
		CPULimitPercent:      20,
		MemoryLimitMB:        512,
		BufferLimitMB:        512,
	})
	if score != 100 {
		t.Errorf("score = %d, want 100 (reasons=%v)", score, reasons)
	}
	if reasons == nil {
		t.Error("reasons 不得为 nil（契约 health_reasons 恒为数组）")
	}
	if len(reasons) != 0 {
		t.Errorf("reasons = %v, want []", reasons)
	}
}

// TestAgentFillHealth FillHealth 端到端：last_metrics JSON 解析 + 评分填充。
func TestAgentFillHealth(t *testing.T) {
	a := &Agent{
		Status:               StatusOnline,
		LastMetrics:          []byte(`{"cpu_percent":95,"memory_mb":128}`),
		ConfigVersion:        3,
		AppliedConfigVersion: 2,
	}
	a.cpuLimitPercent = 20
	a.FillHealth()
	// cpu_over_limit(−25) + config_not_synced(−15) = 60
	if a.HealthScore != 60 {
		t.Errorf("health_score = %d, want 60", a.HealthScore)
	}
	if len(a.HealthReasons) != 2 || a.HealthReasons[0] != "cpu_over_limit" || a.HealthReasons[1] != "config_not_synced" {
		t.Errorf("health_reasons = %v", a.HealthReasons)
	}

	// last_metrics 非法 JSON → 视为无快照（跳过资源类档位）
	b := &Agent{Status: StatusOnline, LastMetrics: []byte(`{bad`), ConfigVersion: 1, AppliedConfigVersion: 1}
	b.FillHealth()
	if b.HealthScore != 100 {
		t.Errorf("非法 metrics health_score = %d, want 100", b.HealthScore)
	}
}
