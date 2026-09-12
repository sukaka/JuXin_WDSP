// Package selfmon 进程自我保护（契约 §6 / 设计 §19）。
//
//   - 每 10s 采样进程 CPU%（/proc/self/stat utime+stime 差值/墙钟/核数）与
//     RSS（/proc/self/status VmRSS）；
//   - 连续 3 次超 limits（默认 cpu 20%、mem 512MB）→ 判定应降级（停抓，
//     心跳继续，状态 DEGRADED）；
//   - 回落到阈值 80% 以下连续 3 次 → 自动恢复；
//   - 采样器可注入（测试用假采样驱动状态机）。
package selfmon

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Sample 一次采样结果。
type Sample struct {
	CPUPercent float64 // 进程 CPU 占用百分比（单核=100 归一化到全核）
	MemoryMB   float64 // RSS
}

// Sampler 采样器接口（测试注入假采样）。
type Sampler interface {
	Sample() (Sample, error)
}

// 默认阈值与状态机参数（契约 §6）。
const (
	DefaultInterval    = 10 * time.Second
	DefaultCPUPercent  = 20.0
	DefaultMemoryMB    = 512.0
	overThresholdHits  = 3
	underThresholdHits = 3
	recoverFactor      = 0.8
	hertz              = 100 // Linux USER_HZ（CLK_TCK 通用值）
)

// Monitor 阈值状态机（纯逻辑，无 IO，可直接单测）。
type Monitor struct {
	cpuLimit float64
	memLimit float64
	over     int
	under    int
	degraded bool
	reason   string
}

// NewMonitor 创建状态机；cpu/mem <=0 用契约默认。
func NewMonitor(cpuPercent, memoryMB float64) *Monitor {
	if cpuPercent <= 0 {
		cpuPercent = DefaultCPUPercent
	}
	if memoryMB <= 0 {
		memoryMB = DefaultMemoryMB
	}
	return &Monitor{cpuLimit: cpuPercent, memLimit: memoryMB}
}

// SetLimits 热更新阈值。
func (m *Monitor) SetLimits(cpuPercent, memoryMB float64) {
	if cpuPercent > 0 {
		m.cpuLimit = cpuPercent
	}
	if memoryMB > 0 {
		m.memLimit = memoryMB
	}
}

// Check 喂入一次采样，推进状态机；返回 (是否降级, 状态是否本次发生变化, 原因)。
func (m *Monitor) Check(s Sample) (degraded bool, changed bool, reason string) {
	over := s.CPUPercent > m.cpuLimit || s.MemoryMB > m.memLimit
	under := s.CPUPercent < m.cpuLimit*recoverFactor && s.MemoryMB < m.memLimit*recoverFactor

	if !m.degraded {
		if over {
			m.over++
			if m.over >= overThresholdHits {
				m.degraded = true
				m.under = 0
				m.reason = fmt.Sprintf("资源超阈值: cpu=%.1f%%(限 %.1f) mem=%.1fMB(限 %.1f)",
					s.CPUPercent, m.cpuLimit, s.MemoryMB, m.memLimit)
				return true, true, m.reason
			}
		} else {
			m.over = 0
		}
		return false, false, ""
	}
	// 已降级：连续低于 80% 阈值恢复
	if under {
		m.under++
		if m.under >= underThresholdHits {
			m.degraded = false
			m.over = 0
			m.reason = ""
			return false, true, "资源回落至阈值 80% 以下，自动恢复"
		}
	} else {
		m.under = 0
	}
	return true, false, ""
}

// Degraded 当前是否降级态。
func (m *Monitor) Degraded() bool { return m.degraded }

// ProcSampler /proc 采样器（Linux；非 Linux 或读取失败返回错误，上层跳过本次采样）。
type ProcSampler struct {
	lastTicks uint64
	lastTime  time.Time
	numCPU    float64
}

// NewProcSampler 创建 /proc 采样器。
func NewProcSampler() *ProcSampler {
	return &ProcSampler{numCPU: float64(runtime.NumCPU())}
}

// Sample 采样 CPU% 与 RSS MB。
func (p *ProcSampler) Sample() (Sample, error) {
	ticks, err := readProcStatTicks()
	if err != nil {
		return Sample{}, err
	}
	rssMB, err := readProcStatusRSS()
	if err != nil {
		return Sample{}, err
	}
	now := time.Now()
	var cpu float64
	if !p.lastTime.IsZero() {
		wall := now.Sub(p.lastTime).Seconds()
		if wall > 0 {
			delta := float64(ticks-p.lastTicks) / hertz // 进程消耗的 CPU 秒
			cpu = delta / wall / p.numCPU * 100
			if cpu < 0 {
				cpu = 0
			}
		}
	}
	p.lastTicks = ticks
	p.lastTime = now
	return Sample{CPUPercent: cpu, MemoryMB: rssMB}, nil
}

// readProcStatTicks 读 /proc/self/stat 的 utime+stime（clock ticks）。
// 注意 comm 字段可含空格与括号，须取最后一个 ')' 之后的字段：
// ')' 后第 1 个字段为 state（field 3），utime 为 field 14 → 下标 11。
func readProcStatTicks() (uint64, error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, fmt.Errorf("读 /proc/self/stat: %w", err)
	}
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx < 0 {
		return 0, fmt.Errorf("/proc/self/stat 格式异常")
	}
	fields := strings.Fields(s[idx+1:])
	if len(fields) < 13 {
		return 0, fmt.Errorf("/proc/self/stat 字段不足: %d", len(fields))
	}
	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("解析 utime: %w", err)
	}
	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("解析 stime: %w", err)
	}
	return utime + stime, nil
}

// readProcStatusRSS 读 /proc/self/status VmRSS（kB）→ MB。
func readProcStatusRSS() (float64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, fmt.Errorf("读 /proc/self/status: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				break
			}
			kb, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				return 0, fmt.Errorf("解析 VmRSS: %w", err)
			}
			return kb / 1024, nil
		}
	}
	return 0, fmt.Errorf("/proc/self/status 缺少 VmRSS")
}
