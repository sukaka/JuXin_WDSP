package jiuzhang_guard

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultProcStatPath    = "/proc/stat"
	defaultProcMeminfoPath = "/proc/meminfo"
	defaultProcLoadavgPath = "/proc/loadavg"
	defaultProcSelfFDPath  = "/proc/self/fd"
	defaultProcLimitsPath  = "/proc/self/limits"
	defaultProcNetTCPPath  = "/proc/net/tcp"
	defaultProcNetTCP6Path = "/proc/net/tcp6"
)

type resourceSample struct {
	takenAt              time.Time
	cpuPercent           float64
	cpuAvailable         bool
	memoryPercent        float64
	memoryAvailable      bool
	memoryUsedBytes      uint64
	memoryTotalBytes     uint64
	memoryBytesAvailable bool
	load1                float64
	load5                float64
	load15               float64
	loadAvailable        bool
	fdOpen               int
	fdOpenAvailable      bool
	fdMax                uint64
	fdMaxAvailable       bool
	fdUsagePercent       float64
	fdUsageAvailable     bool
	tcpStates            *TCPStateSnapshot
	err                  string
}

type resourceSampler interface {
	Sample() resourceSample
}

type procResourceSampler struct {
	statPath    string
	meminfoPath string
	loadavgPath string
	fdDirPath   string
	limitsPath  string
	tcpPath     string
	tcp6Path    string
	lastCPU     *cpuCounters
}

func newProcResourceSampler() *procResourceSampler {
	return &procResourceSampler{
		statPath:    defaultProcStatPath,
		meminfoPath: defaultProcMeminfoPath,
		loadavgPath: defaultProcLoadavgPath,
		fdDirPath:   defaultProcSelfFDPath,
		limitsPath:  defaultProcLimitsPath,
		tcpPath:     defaultProcNetTCPPath,
		tcp6Path:    defaultProcNetTCP6Path,
	}
}

func (s *procResourceSampler) Sample() resourceSample {
	sample := resourceSample{takenAt: time.Now().UTC()}
	var errs []string
	if raw, err := os.ReadFile(s.statPath); err != nil {
		errs = append(errs, "CPU: "+err.Error())
	} else if current, err := parseCPUCounters(string(raw)); err != nil {
		errs = append(errs, "CPU: "+err.Error())
	} else {
		if s.lastCPU != nil && current.total >= s.lastCPU.total && current.idle >= s.lastCPU.idle {
			totalDelta := current.total - s.lastCPU.total
			idleDelta := current.idle - s.lastCPU.idle
			if totalDelta > 0 && idleDelta <= totalDelta {
				sample.cpuPercent = float64(totalDelta-idleDelta) * 100 / float64(totalDelta)
				sample.cpuAvailable = true
			}
		}
		s.lastCPU = &current
	}
	if raw, err := os.ReadFile(s.meminfoPath); err != nil {
		errs = append(errs, "memory: "+err.Error())
	} else if stats, err := parseMemoryStats(string(raw)); err != nil {
		errs = append(errs, "memory: "+err.Error())
	} else {
		sample.memoryPercent = stats.percent
		sample.memoryAvailable = true
		sample.memoryUsedBytes = stats.usedBytes
		sample.memoryTotalBytes = stats.totalBytes
		sample.memoryBytesAvailable = true
	}
	// Extended Linux /proc metrics gracefully degrade on non-Linux hosts or
	// restricted containers without polluting the CPU/memory error field.
	if s.loadavgPath != "" {
		if raw, err := os.ReadFile(s.loadavgPath); err == nil {
			if l1, l5, l15, err := parseLoadAvg(string(raw)); err == nil {
				sample.load1 = l1
				sample.load5 = l5
				sample.load15 = l15
				sample.loadAvailable = true
			}
		}
	}
	if s.fdDirPath != "" {
		if openFDs, err := countOpenFDs(s.fdDirPath); err == nil {
			sample.fdOpen = openFDs
			sample.fdOpenAvailable = true
		}
	}
	if s.limitsPath != "" {
		if raw, err := os.ReadFile(s.limitsPath); err == nil {
			if maxFDs, err := parseMaxOpenFiles(string(raw)); err == nil {
				sample.fdMax = maxFDs
				sample.fdMaxAvailable = true
			}
		}
	}
	if sample.fdOpenAvailable && sample.fdMaxAvailable && sample.fdMax > 0 {
		sample.fdUsagePercent = float64(sample.fdOpen) * 100 / float64(sample.fdMax)
		sample.fdUsageAvailable = true
	}
	sample.tcpStates = readProcNetTCPStates(s.tcpPath, s.tcp6Path)
	sample.err = strings.Join(errs, "; ")
	return sample
}

type cpuCounters struct {
	total uint64
	idle  uint64
}

func parseCPUCounters(raw string) (cpuCounters, error) {
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "cpu" {
			continue
		}
		if len(fields) < 9 {
			return cpuCounters{}, fmt.Errorf("aggregate cpu line has %d fields", len(fields)-1)
		}
		values := make([]uint64, 8)
		for i := range values {
			value, err := strconv.ParseUint(fields[i+1], 10, 64)
			if err != nil {
				return cpuCounters{}, fmt.Errorf("invalid cpu counter %q: %w", fields[i+1], err)
			}
			values[i] = value
		}
		var total uint64
		for _, value := range values {
			total += value
		}
		return cpuCounters{total: total, idle: values[3] + values[4]}, nil
	}
	return cpuCounters{}, fmt.Errorf("aggregate cpu line not found")
}

type memoryStats struct {
	percent    float64
	usedBytes  uint64
	totalBytes uint64
}

func parseMemoryStats(raw string) (memoryStats, error) {
	var totalKB, availableKB uint64
	var haveTotal, haveAvailable bool
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var target *uint64
		switch fields[0] {
		case "MemTotal:":
			target, haveTotal = &totalKB, true
		case "MemAvailable:":
			target, haveAvailable = &availableKB, true
		default:
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return memoryStats{}, fmt.Errorf("invalid %s value %q: %w", fields[0], fields[1], err)
		}
		*target = value
	}
	if !haveTotal || !haveAvailable || totalKB == 0 {
		return memoryStats{}, fmt.Errorf("MemTotal or MemAvailable missing")
	}
	totalBytes := totalKB * 1024
	if totalKB > math.MaxUint64/1024 {
		totalBytes = math.MaxUint64
	}
	if availableKB >= totalKB {
		return memoryStats{percent: 0, usedBytes: 0, totalBytes: totalBytes}, nil
	}
	usedKB := totalKB - availableKB
	usedBytes := usedKB * 1024
	if usedKB > math.MaxUint64/1024 {
		usedBytes = math.MaxUint64
	}
	return memoryStats{
		percent:    float64(usedKB) * 100 / float64(totalKB),
		usedBytes:  usedBytes,
		totalBytes: totalBytes,
	}, nil
}

func parseMemoryUsage(raw string) (float64, error) {
	stats, err := parseMemoryStats(raw)
	if err != nil {
		return 0, err
	}
	return stats.percent, nil
}

func parseLoadAvg(raw string) (load1, load5, load15 float64, err error) {
	fields := strings.Fields(raw)
	if len(fields) < 3 {
		return 0, 0, 0, fmt.Errorf("loadavg has %d fields, want at least 3", len(fields))
	}
	values := make([]float64, 3)
	for i := 0; i < 3; i++ {
		v, parseErr := strconv.ParseFloat(fields[i], 64)
		if parseErr != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return 0, 0, 0, fmt.Errorf("invalid loadavg field %d (%q)", i+1, fields[i])
		}
		values[i] = v
	}
	return values[0], values[1], values[2], nil
}

func countOpenFDs(dirPath string) (int, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

func parseMaxOpenFiles(raw string) (uint64, error) {
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "Max open files") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "Max open files"))
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0, fmt.Errorf("Max open files soft limit missing")
		}
		if strings.EqualFold(fields[0], "unlimited") {
			return 0, fmt.Errorf("Max open files soft limit is unlimited")
		}
		val, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || val == 0 {
			return 0, fmt.Errorf("invalid Max open files soft limit %q", fields[0])
		}
		return val, nil
	}
	return 0, fmt.Errorf("Max open files line not found")
}

func parseProcNetTCP(r io.Reader, dst *TCPStateSnapshot) error {
	if dst == nil {
		return fmt.Errorf("nil tcp state destination")
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] == "sl" || !strings.HasSuffix(fields[0], ":") {
			continue
		}
		code, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			continue
		}
		switch code {
		case 0x01:
			dst.Established++
		case 0x03:
			dst.SynRecv++
		case 0x04, 0x05:
			dst.FinWait++
		case 0x06:
			dst.TimeWait++
		case 0x08:
			dst.CloseWait++
		case 0x0A:
			dst.Listen++
		default:
			dst.Other++
		}
	}
	return scanner.Err()
}

func readProcNetTCPStates(tcpPath, tcp6Path string) *TCPStateSnapshot {
	var states TCPStateSnapshot
	anyOK := false
	for _, path := range []string{tcpPath, tcp6Path} {
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		parseErr := parseProcNetTCP(f, &states)
		_ = f.Close()
		if parseErr == nil {
			anyOK = true
		}
	}
	if !anyOK {
		return nil
	}
	return &states
}
