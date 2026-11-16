package jiuzhang_guard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCPUCounters(t *testing.T) {
	counters, err := parseCPUCounters("cpu0 1 0 1 1 0 0 0 0 0 0\ncpu 100 0 100 600 100 20 20 60 0 0\n")
	if err != nil {
		t.Fatal(err)
	}
	if counters.total != 1000 || counters.idle != 700 {
		t.Fatalf("counters = %+v, want total=1000 idle=700", counters)
	}
	if _, err := parseCPUCounters("cpu 1 2 3\n"); err == nil {
		t.Fatal("short CPU line must fail")
	}
}

func TestParseMemoryUsage(t *testing.T) {
	percent, err := parseMemoryUsage("MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 250 kB\n")
	if err != nil {
		t.Fatal(err)
	}
	if percent != 75 {
		t.Fatalf("memory usage = %v, want 75", percent)
	}
	if _, err := parseMemoryUsage("MemTotal: 1000 kB\n"); err == nil {
		t.Fatal("missing MemAvailable must fail")
	}
}

func TestProcResourceSamplerUsesCounterDelta(t *testing.T) {
	dir := t.TempDir()
	statPath := filepath.Join(dir, "stat")
	meminfoPath := filepath.Join(dir, "meminfo")
	if err := os.WriteFile(meminfoPath, []byte("MemTotal: 1000 kB\nMemAvailable: 250 kB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeStat := func(raw string) {
		t.Helper()
		if err := os.WriteFile(statPath, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sampler := &procResourceSampler{statPath: statPath, meminfoPath: meminfoPath}
	writeStat("cpu 100 0 100 600 100 20 20 60 0 0\n")
	first := sampler.Sample()
	if first.cpuAvailable {
		t.Fatal("first CPU sample is only a baseline")
	}
	if !first.memoryAvailable || first.memoryPercent != 75 {
		t.Fatalf("first memory sample = %+v", first)
	}
	writeStat("cpu 400 0 200 1000 200 40 40 120 0 0\n")
	second := sampler.Sample()
	if !second.cpuAvailable || second.cpuPercent != 50 {
		t.Fatalf("second CPU sample = %+v, want 50%%", second)
	}
}
