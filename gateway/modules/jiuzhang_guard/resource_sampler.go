package jiuzhang_guard

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultProcStatPath    = "/proc/stat"
	defaultProcMeminfoPath = "/proc/meminfo"
)

type resourceSample struct {
	takenAt         time.Time
	cpuPercent      float64
	cpuAvailable    bool
	memoryPercent   float64
	memoryAvailable bool
	err             string
}

type resourceSampler interface {
	Sample() resourceSample
}

type procResourceSampler struct {
	statPath    string
	meminfoPath string
	lastCPU     *cpuCounters
}

func newProcResourceSampler() *procResourceSampler {
	return &procResourceSampler{statPath: defaultProcStatPath, meminfoPath: defaultProcMeminfoPath}
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
	} else if percent, err := parseMemoryUsage(string(raw)); err != nil {
		errs = append(errs, "memory: "+err.Error())
	} else {
		sample.memoryPercent = percent
		sample.memoryAvailable = true
	}
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

func parseMemoryUsage(raw string) (float64, error) {
	var total, available uint64
	var haveTotal, haveAvailable bool
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var target *uint64
		switch fields[0] {
		case "MemTotal:":
			target, haveTotal = &total, true
		case "MemAvailable:":
			target, haveAvailable = &available, true
		default:
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid %s value %q: %w", fields[0], fields[1], err)
		}
		*target = value
	}
	if !haveTotal || !haveAvailable || total == 0 {
		return 0, fmt.Errorf("MemTotal or MemAvailable missing")
	}
	if available >= total {
		return 0, nil
	}
	return float64(total-available) * 100 / float64(total), nil
}
