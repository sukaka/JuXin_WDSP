//go:build windows

package selfmon

import (
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// processMemoryCounters 对应 Win32 PROCESS_MEMORY_COUNTERS 结构（兼容 amd64/arm64）。
type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

var (
	modKernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procK32GetProcessMemInfo  = modKernel32.NewProc("K32GetProcessMemoryInfo")
	modPsapi                  = windows.NewLazySystemDLL("psapi.dll")
	procPsapiGetProcessMemInf = modPsapi.NewProc("GetProcessMemoryInfo")
)

// WindowsSampler Windows 进程资源采样器（零 CGO）。
// CPU% 取自 GetProcessTimes（Kernel+User）；MemoryMB 取自 K32GetProcessMemoryInfo WorkingSetSize。
type WindowsSampler struct {
	lastCPU100ns uint64
	lastTime     time.Time
	numCPU       float64
}

// NewWindowsSampler 创建 Windows 采样器。
func NewWindowsSampler() *WindowsSampler {
	return &WindowsSampler{numCPU: float64(runtime.NumCPU())}
}

// NewDefaultSampler 返回 Windows 默认采样器。
func NewDefaultSampler() Sampler {
	return NewWindowsSampler()
}

func filetimeTo100ns(ft windows.Filetime) uint64 {
	return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
}

// Sample 采样进程 CPU% 与 WorkingSetSize（MB）。
func (w *WindowsSampler) Sample() (Sample, error) {
	handle := windows.CurrentProcess()
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return Sample{}, fmt.Errorf("GetProcessTimes: %w", err)
	}
	cpu100ns := filetimeTo100ns(kernel) + filetimeTo100ns(user)

	now := time.Now()
	var cpu float64
	if !w.lastTime.IsZero() {
		wall := now.Sub(w.lastTime).Seconds()
		if wall > 0 && w.numCPU > 0 && cpu100ns >= w.lastCPU100ns {
			deltaSec := float64(cpu100ns-w.lastCPU100ns) / 1e7
			cpu = deltaSec / wall / w.numCPU * 100
		}
	}
	w.lastCPU100ns = cpu100ns
	w.lastTime = now

	memMB, err := readWindowsWorkingSetMB(handle)
	if err != nil {
		return Sample{}, err
	}
	return Sample{CPUPercent: cpu, MemoryMB: memMB}, nil
}

func readWindowsWorkingSetMB(handle windows.Handle) (float64, error) {
	var pmc processMemoryCounters
	pmc.CB = uint32(unsafe.Sizeof(pmc))
	if err := procK32GetProcessMemInfo.Find(); err == nil {
		r1, _, callErr := procK32GetProcessMemInfo.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&pmc)),
			uintptr(pmc.CB),
		)
		if r1 != 0 {
			return float64(pmc.WorkingSetSize) / (1024 * 1024), nil
		}
		return 0, fmt.Errorf("K32GetProcessMemoryInfo: %w", callErr)
	}
	if err := procPsapiGetProcessMemInf.Find(); err == nil {
		r1, _, callErr := procPsapiGetProcessMemInf.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&pmc)),
			uintptr(pmc.CB),
		)
		if r1 != 0 {
			return float64(pmc.WorkingSetSize) / (1024 * 1024), nil
		}
		return 0, fmt.Errorf("GetProcessMemoryInfo: %w", callErr)
	}
	return 0, fmt.Errorf("未找到可用的 Windows 进程内存查询 API")
}
