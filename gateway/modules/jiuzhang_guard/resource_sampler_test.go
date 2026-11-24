package jiuzhang_guard

import (
	"math"
	"os"
	"path/filepath"
	"strings"
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

func TestParseMemoryStats(t *testing.T) {
	stats, err := parseMemoryStats("MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 250 kB\n")
	if err != nil {
		t.Fatal(err)
	}
	if stats.percent != 75 {
		t.Fatalf("percent = %v, want 75", stats.percent)
	}
	if stats.usedBytes != 750*1024 || stats.totalBytes != 1000*1024 {
		t.Fatalf("bytes = used %d total %d, want %d/%d", stats.usedBytes, stats.totalBytes, 750*1024, 1000*1024)
	}
	clamped, err := parseMemoryStats("MemTotal: 1000 kB\nMemAvailable: 1200 kB\n")
	if err != nil {
		t.Fatal(err)
	}
	if clamped.percent != 0 || clamped.usedBytes != 0 || clamped.totalBytes != 1000*1024 {
		t.Fatalf("available>=total stats = %+v, want 0%%/0/%d", clamped, 1000*1024)
	}
}

func TestParseLoadAvg(t *testing.T) {
	l1, l5, l15, err := parseLoadAvg("0.42 1.25 2.50 2/314 9876\n")
	if err != nil {
		t.Fatal(err)
	}
	if l1 != 0.42 || l5 != 1.25 || l15 != 2.50 {
		t.Fatalf("loadavg = (%v, %v, %v), want (0.42, 1.25, 2.50)", l1, l5, l15)
	}
	for _, invalid := range []string{"0.1 0.2", "abc 0.2 0.3", "-0.1 0.2 0.3", "NaN 0.2 0.3"} {
		if _, _, _, err := parseLoadAvg(invalid); err == nil {
			t.Fatalf("expected error for invalid loadavg %q", invalid)
		}
	}
}

func TestParseMaxOpenFiles(t *testing.T) {
	sample := `Limit                     Soft Limit           Hard Limit           Units
Max cpu time              unlimited            unlimited            seconds
Max processes             63195                63195                processes
Max open files            65536                1048576              files
Max locked memory         65536                65536                bytes
`
	maxFDs, err := parseMaxOpenFiles(sample)
	if err != nil {
		t.Fatal(err)
	}
	if maxFDs != 65536 {
		t.Fatalf("maxFDs = %d, want 65536", maxFDs)
	}
	if _, err := parseMaxOpenFiles("Max open files            unlimited            unlimited            files\n"); err == nil {
		t.Fatal("unlimited soft limit must return error so fd_max is omitted")
	}
	if _, err := parseMaxOpenFiles("Max cpu time unlimited unlimited seconds\n"); err == nil {
		t.Fatal("missing Max open files line must fail")
	}
}

func TestParseProcNetTCP(t *testing.T) {
	rawV4 := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 10001 1
   1: 0100007F:0050 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 10002 1
   2: 0100007F:0050 0100007F:C351 02 00000000:00000000 00:00000000 00000000     0        0 10003 1
   3: 0100007F:0050 0100007F:C352 03 00000000:00000000 00:00000000 00000000     0        0 10004 1
   4: 0100007F:0050 0100007F:C353 04 00000000:00000000 00:00000000 00000000     0        0 10005 1
   5: 0100007F:0050 0100007F:C354 05 00000000:00000000 00:00000000 00000000     0        0 10006 1
   6: 0100007F:0050 0100007F:C355 06 00000000:00000000 00:00000000 00000000     0        0 10007 1
   7: 0100007F:0050 0100007F:C356 07 00000000:00000000 00:00000000 00000000     0        0 10008 1
   8: 0100007F:0050 0100007F:C357 08 00000000:00000000 00:00000000 00000000     0        0 10009 1
   9: 0100007F:0050 0100007F:C358 09 00000000:00000000 00:00000000 00000000     0        0 10010 1
  10: 0100007F:0050 0100007F:C359 0B 00000000:00000000 00:00000000 00000000     0        0 10011 1
`
	rawV6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0a 00000000:00000000 00:00000000 00000000     0        0 20001 1
   1: 00000000000000000000000000000001:01BB 00000000000000000000000000000001:9000 01 00000000:00000000 00:00000000 00000000     0        0 20002 1
`
	var states TCPStateSnapshot
	if err := parseProcNetTCP(strings.NewReader(rawV4), &states); err != nil {
		t.Fatal(err)
	}
	if err := parseProcNetTCP(strings.NewReader(rawV6), &states); err != nil {
		t.Fatal(err)
	}
	want := TCPStateSnapshot{
		Established: 2, // 01 in v4 + 01 in v6
		TimeWait:    1, // 06
		CloseWait:   1, // 08
		SynRecv:     1, // 03
		FinWait:     2, // 04 + 05
		Listen:      2, // 0A in v4 + 0a in v6
		Other:       4, // 02 + 07 + 09 + 0B
	}
	if states != want {
		t.Fatalf("tcp states = %+v, want %+v", states, want)
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
	if !first.memoryBytesAvailable || first.memoryUsedBytes != 750*1024 || first.memoryTotalBytes != 1000*1024 {
		t.Fatalf("first memory bytes = %+v", first)
	}
	writeStat("cpu 400 0 200 1000 200 40 40 120 0 0\n")
	second := sampler.Sample()
	if !second.cpuAvailable || second.cpuPercent != 50 {
		t.Fatalf("second CPU sample = %+v, want 50%%", second)
	}
}

func TestProcResourceSamplerExtendedMetricsAndGracefulDegradation(t *testing.T) {
	dir := t.TempDir()
	statPath := filepath.Join(dir, "stat")
	meminfoPath := filepath.Join(dir, "meminfo")
	loadavgPath := filepath.Join(dir, "loadavg")
	fdDir := filepath.Join(dir, "fd")
	limitsPath := filepath.Join(dir, "limits")
	tcpPath := filepath.Join(dir, "tcp")
	tcp6Path := filepath.Join(dir, "tcp6")

	if err := os.WriteFile(statPath, []byte("cpu 100 0 100 600 100 20 20 60 0 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(meminfoPath, []byte("MemTotal: 4096 kB\nMemAvailable: 1024 kB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(loadavgPath, []byte("1.20 0.85 0.50 1/200 4321\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fdDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"0", "1", "2", "3", "4"} {
		if err := os.WriteFile(filepath.Join(fdDir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(limitsPath, []byte("Max open files            200                  1024                 files\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tcpPath, []byte("  sl local rem st\n   0: A B 01\n   1: A B 06\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tcp6Path, []byte("  sl local rem st\n   0: A B 0A\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sampler := &procResourceSampler{
		statPath:    statPath,
		meminfoPath: meminfoPath,
		loadavgPath: loadavgPath,
		fdDirPath:   fdDir,
		limitsPath:  limitsPath,
		tcpPath:     tcpPath,
		tcp6Path:    tcp6Path,
	}
	sample := sampler.Sample()
	if sample.err != "" {
		t.Fatalf("unexpected sample error: %q", sample.err)
	}
	if !sample.loadAvailable || sample.load1 != 1.20 || sample.load5 != 0.85 || sample.load15 != 0.50 {
		t.Fatalf("load sample = %+v", sample)
	}
	if !sample.fdOpenAvailable || sample.fdOpen != 5 || !sample.fdMaxAvailable || sample.fdMax != 200 {
		t.Fatalf("fd sample = open:%v(%d) max:%v(%d)", sample.fdOpenAvailable, sample.fdOpen, sample.fdMaxAvailable, sample.fdMax)
	}
	if !sample.fdUsageAvailable || math.Abs(sample.fdUsagePercent-2.5) > 1e-9 {
		t.Fatalf("fdUsagePercent = %v (avail=%v), want 2.5", sample.fdUsagePercent, sample.fdUsageAvailable)
	}
	if sample.tcpStates == nil || sample.tcpStates.Established != 1 || sample.tcpStates.TimeWait != 1 || sample.tcpStates.Listen != 1 {
		t.Fatalf("tcpStates = %+v", sample.tcpStates)
	}

	// Non-Linux / missing extended /proc files must degrade to nil/unavailable without polluting sample.err.
	degradedSampler := &procResourceSampler{
		statPath:    statPath,
		meminfoPath: meminfoPath,
		loadavgPath: filepath.Join(dir, "missing-loadavg"),
		fdDirPath:   filepath.Join(dir, "missing-fd"),
		limitsPath:  filepath.Join(dir, "missing-limits"),
		tcpPath:     filepath.Join(dir, "missing-tcp"),
		tcp6Path:    filepath.Join(dir, "missing-tcp6"),
	}
	degraded := degradedSampler.Sample()
	if degraded.err != "" {
		t.Fatalf("extended /proc absence must not pollute sample.err, got %q", degraded.err)
	}
	if degraded.loadAvailable || degraded.fdOpenAvailable || degraded.fdMaxAvailable || degraded.fdUsageAvailable || degraded.tcpStates != nil {
		t.Fatalf("degraded sample should omit unavailable extended metrics: %+v", degraded)
	}
}
