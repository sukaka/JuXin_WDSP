// health.go Agent 健康评分（Phase 2，设计 §54 健康评分 / §23 时间同步阈值）。
//
// 评分在管理端查询时计算（不落库），公式确定、可测，分档与扣分值冻结如下
// （与 docs/agents/WDSP_AGENT_PHASE2_CONTRACT.md §4 分档表一致，改动必须同步文档）：
//
//   - 派生状态 DISABLED → 固定 0 分，原因 agent_disabled；
//
//   - 派生状态 OFFLINE  → 固定 10 分，原因 agent_offline；
//
//   - 其余以 100 起扣（可叠加，下限 0）：
//
//     档位                    条件                                                        扣分  原因码
//     自报 ERROR              last_status=ERROR                                           −20   status_error
//     自报 DEGRADED           last_status=DEGRADED                                        −10   status_degraded
//     CPU 超限                cpu_percent > CPU 阈值                                       −25   cpu_over_limit
//     CPU 偏高                cpu_percent > 80% × CPU 阈值                                 −10   cpu_high
//     内存超限                memory_mb > limits.memory_mb（无绑定策略不评内存档）          −25   memory_over_limit
//     内存偏高                memory_mb > 80% × limits.memory_mb                           −10   memory_high
//     丢包率严重              dropped/(received+1) > 10%                                   −25   drop_rate_critical
//     丢包率偏高              dropped/(received+1) > 1%                                    −10   drop_rate_high
//     队列积压严重            queue_depth > 5000                                           −20   queue_overflow
//     队列积压                queue_depth > 1000                                           −10   queue_high
//     缓存接近上限            buffer_bytes > 90% × 缓存上限                                 −20   buffer_near_full
//     缓存偏高                buffer_bytes > 75% × 缓存上限                                 −10   buffer_high
//     时钟偏移超阈            |clock_offset_ms| > 5000（设计 §23）                         −15   clock_drift
//     时钟偏移偏大            |clock_offset_ms| > 2000                                     −5    clock_skew
//     配置未同步              applied_config_version != config_version                     −15   config_not_synced
//
//     CPU 阈值：绑定策略 limits.cpu_percent，无绑定/缺省取 80（%）。
//     缓存上限：绑定策略 buffer.max_size_mb，无绑定/缺省取 512（契约 §6 磁盘缓存默认上限）。
//     metrics 快照缺省时跳过 CPU/内存/丢包/队列/缓存档位（无从评估不扣分）。
package agents

// 健康评分阈值常量（公式事实源；改动须同步 PHASE2 契约文档 §4）。
const (
	healthScoreDisabled = 0  // DISABLED 固定分
	healthScoreOffline  = 10 // OFFLINE 固定分

	defaultCPULimitPercent = 80.0 // 无绑定策略时的 CPU 阈值（%）
	defaultBufferLimitMB   = 512  // 无绑定策略时的磁盘缓存上限（MB，契约 §6 默认）

	dropRateCritical = 0.10 // 丢包率严重档
	dropRateHigh     = 0.01 // 丢包率偏高档

	queueDepthOverflow = 5000 // 队列积压严重档（内存队列硬上限 10000 的 50%，契约 §6）
	queueDepthHigh     = 1000 // 队列积压档

	bufferNearFullRatio = 0.90 // 缓存接近上限档
	bufferHighRatio     = 0.75 // 缓存偏高档
	highUsageRatio      = 0.80 // CPU/内存「偏高」档（占阈值比例）

	clockDriftMS = 5000 // 时钟偏移超阈（设计 §23：>5s）
	clockSkewMS  = 2000 // 时钟偏移偏大

	deductStatusError    = 20
	deductStatusDegraded = 10
	deductCPUOverLimit   = 25
	deductCPUHigh        = 10
	deductMemOverLimit   = 25
	deductMemHigh        = 10
	deductDropCritical   = 25
	deductDropHigh       = 10
	deductQueueOverflow  = 20
	deductQueueHigh      = 10
	deductBufferNearFull = 20
	deductBufferHigh     = 10
	deductClockDrift     = 15
	deductClockSkew      = 5
	deductConfigNotSync  = 15
)

// HealthInput 健康评分输入（派生状态 + 最近 metrics 快照 + 时钟偏移 + 配置同步态 +
// 绑定策略限制；限制为 0 表示无绑定/缺省，按默认阈值或跳过对应档位）。
type HealthInput struct {
	Status               string   // 派生状态（契约 §5）
	Metrics              *Metrics // 最近一次心跳 metrics 快照（nil → 跳过资源类档位）
	ClockOffsetMS        *int64   // 最近心跳时钟偏移（nil → 跳过时钟档位）
	ConfigVersion        int64
	AppliedConfigVersion int64
	CPULimitPercent      float64 // 绑定策略 limits.cpu_percent（0 → 默认 80）
	MemoryLimitMB        float64 // 绑定策略 limits.memory_mb（0 → 跳过内存档）
	BufferLimitMB        float64 // 绑定策略 buffer.max_size_mb（0 → 默认 512）
}

// ComputeHealth 计算健康评分（0-100）与扣分原因码（机读，前端映射展示文案）。
// reasons 保证非 nil；DISABLED/OFFLINE 为固定低分短路（不再评估其余档位）。
func ComputeHealth(in HealthInput) (int, []string) {
	if in.Status == StatusDisabled {
		return healthScoreDisabled, []string{"agent_disabled"}
	}
	if in.Status == StatusOffline {
		return healthScoreOffline, []string{"agent_offline"}
	}

	score := 100
	reasons := []string{}
	deduct := func(points int, reason string) {
		score -= points
		reasons = append(reasons, reason)
	}

	switch in.Status {
	case StatusError:
		deduct(deductStatusError, "status_error")
	case StatusDegraded:
		deduct(deductStatusDegraded, "status_degraded")
	}

	if in.Metrics != nil {
		m := in.Metrics
		cpuLimit := in.CPULimitPercent
		if cpuLimit <= 0 {
			cpuLimit = defaultCPULimitPercent
		}
		switch {
		case m.CPUPercent > cpuLimit:
			deduct(deductCPUOverLimit, "cpu_over_limit")
		case m.CPUPercent > highUsageRatio*cpuLimit:
			deduct(deductCPUHigh, "cpu_high")
		}
		if in.MemoryLimitMB > 0 {
			switch {
			case m.MemoryMB > in.MemoryLimitMB:
				deduct(deductMemOverLimit, "memory_over_limit")
			case m.MemoryMB > highUsageRatio*in.MemoryLimitMB:
				deduct(deductMemHigh, "memory_high")
			}
		}
		dropRate := float64(m.PacketsDropped) / float64(m.PacketsReceived+1)
		switch {
		case dropRate > dropRateCritical:
			deduct(deductDropCritical, "drop_rate_critical")
		case dropRate > dropRateHigh:
			deduct(deductDropHigh, "drop_rate_high")
		}
		switch {
		case m.QueueDepth > queueDepthOverflow:
			deduct(deductQueueOverflow, "queue_overflow")
		case m.QueueDepth > queueDepthHigh:
			deduct(deductQueueHigh, "queue_high")
		}
		bufferLimitMB := in.BufferLimitMB
		if bufferLimitMB <= 0 {
			bufferLimitMB = defaultBufferLimitMB
		}
		if bufferLimitMB > 0 {
			bufferMB := float64(m.BufferBytes) / (1 << 20)
			switch {
			case bufferMB > bufferNearFullRatio*bufferLimitMB:
				deduct(deductBufferNearFull, "buffer_near_full")
			case bufferMB > bufferHighRatio*bufferLimitMB:
				deduct(deductBufferHigh, "buffer_high")
			}
		}
	}

	if in.ClockOffsetMS != nil {
		offset := *in.ClockOffsetMS
		if offset < 0 {
			offset = -offset
		}
		switch {
		case offset > clockDriftMS:
			deduct(deductClockDrift, "clock_drift")
		case offset > clockSkewMS:
			deduct(deductClockSkew, "clock_skew")
		}
	}

	if in.AppliedConfigVersion != in.ConfigVersion {
		deduct(deductConfigNotSync, "config_not_synced")
	}

	if score < 0 {
		score = 0
	}
	return score, reasons
}
