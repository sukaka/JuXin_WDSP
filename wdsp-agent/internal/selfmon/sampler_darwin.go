//go:build darwin

package selfmon

import (
	"fmt"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// DarwinSampler macOS 进程资源采样器（零 CGO）。
// CPU% 取自 unix.Getrusage(RUSAGE_SELF) 的用户态+内核态时间差值/墙钟/核数；
// MemoryMB 在零 CGO 下取 Go runtime 映射常驻内存近似值（Sys - HeapReleased，
// 非内核级完整 VmRSS，但涵盖全部 Go 堆/栈/运行时常驻开销，足够驱动自我保护）。
type DarwinSampler struct {
	lastCPU  float64
	lastTime time.Time
	numCPU   float64
}

// NewDarwinSampler 创建 macOS 采样器。
func NewDarwinSampler() *DarwinSampler {
	return &DarwinSampler{numCPU: float64(runtime.NumCPU())}
}

// NewDefaultSampler 返回 macOS 默认采样器。
func NewDefaultSampler() Sampler {
	return NewDarwinSampler()
}

// Sample 采样进程 CPU% 与常驻内存近似值（MB）。
func (d *DarwinSampler) Sample() (Sample, error) {
	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
		return Sample{}, fmt.Errorf("getrusage: %w", err)
	}
	cpuSec := float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6 +
		float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6

	now := time.Now()
	var cpu float64
	if !d.lastTime.IsZero() {
		wall := now.Sub(d.lastTime).Seconds()
		if wall > 0 && d.numCPU > 0 {
			delta := cpuSec - d.lastCPU
			if delta > 0 {
				cpu = delta / wall / d.numCPU * 100
			}
		}
	}
	d.lastCPU = cpuSec
	d.lastTime = now

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	bytes := ms.Sys
	if ms.Sys > ms.HeapReleased {
		bytes = ms.Sys - ms.HeapReleased
	}
	memMB := float64(bytes) / (1024 * 1024)
	return Sample{CPUPercent: cpu, MemoryMB: memMB}, nil
}
