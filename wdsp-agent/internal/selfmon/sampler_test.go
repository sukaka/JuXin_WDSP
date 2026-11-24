package selfmon

import (
	"runtime"
	"testing"
	"time"
)

func TestDefaultSamplerLive(t *testing.T) {
	s := NewDefaultSampler()
	if s == nil {
		t.Fatal("NewDefaultSampler returned nil")
	}
	first, err := s.Sample()
	if err != nil {
		t.Fatalf("first Sample failed on %s: %v", runtime.GOOS, err)
	}
	if first.MemoryMB <= 0 {
		t.Fatalf("expected positive MemoryMB, got %v", first.MemoryMB)
	}
	if first.CPUPercent < 0 {
		t.Fatalf("expected non-negative CPUPercent, got %v", first.CPUPercent)
	}
	time.Sleep(10 * time.Millisecond)
	second, err := s.Sample()
	if err != nil {
		t.Fatalf("second Sample failed on %s: %v", runtime.GOOS, err)
	}
	if second.MemoryMB <= 0 || second.CPUPercent < 0 {
		t.Fatalf("unexpected second sample: %+v", second)
	}
}
