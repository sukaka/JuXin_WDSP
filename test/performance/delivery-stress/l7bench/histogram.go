package main

import (
	"math"
	"sync/atomic"
	"time"
)

// 无锁 O(1) 内存多段高精度微秒级延迟直方图（841 个桶 ≈ 6.7 KiB 内存，可支撑亿级请求零 GC 压力）：
//   [0, 10ms)        步长 0.05ms (50µs)   -> 200 桶 (0..199)
//   [10ms, 100ms)    步长 0.5ms           -> 180 桶 (200..379)
//   [100ms, 1000ms)  步长 5ms             -> 180 桶 (380..559)
//   [1000ms, 10000ms)步长 50ms            -> 180 桶 (560..739)
//   [10000ms, 60000ms)步长 500ms          -> 100 桶 (740..839)
//   >= 60000ms       溢出桶               -> 1 桶   (840)
const histTotalBuckets = 841

type LatencyHist struct {
	buckets [histTotalBuckets]atomic.Uint64
	count   atomic.Uint64
	sumNs   atomic.Uint64
	minNs   atomic.Int64
	maxNs   atomic.Int64
}

func newLatencyHist() *LatencyHist {
	h := &LatencyHist{}
	h.minNs.Store(math.MaxInt64)
	return h
}

func bucketIndex(d time.Duration) int {
	us := d.Microseconds()
	if us < 0 {
		us = 0
	}
	switch {
	case us < 10_000: // < 10ms, step 50us
		return int(us / 50)
	case us < 100_000: // < 100ms, step 500us
		return 200 + int((us-10_000)/500)
	case us < 1_000_000: // < 1s, step 5ms
		return 380 + int((us-100_000)/5_000)
	case us < 10_000_000: // < 10s, step 50ms
		return 560 + int((us-1_000_000)/50_000)
	case us < 60_000_000: // < 60s, step 500ms
		return 740 + int((us-10_000_000)/500_000)
	default:
		return histTotalBuckets - 1
	}
}

func bucketUpperBoundMs(idx int) float64 {
	switch {
	case idx < 200:
		return float64(idx+1) * 0.05
	case idx < 380:
		return 10.0 + float64(idx-200+1)*0.5
	case idx < 560:
		return 100.0 + float64(idx-380+1)*5.0
	case idx < 740:
		return 1000.0 + float64(idx-560+1)*50.0
	case idx < 840:
		return 10000.0 + float64(idx-740+1)*500.0
	default:
		return 60000.0
	}
}

func (h *LatencyHist) Record(d time.Duration) {
	if d < 0 {
		d = 0
	}
	ns := d.Nanoseconds()
	idx := bucketIndex(d)
	h.buckets[idx].Add(1)
	h.count.Add(1)
	h.sumNs.Add(uint64(ns))

	for {
		cur := h.minNs.Load()
		if ns >= cur || h.minNs.CompareAndSwap(cur, ns) {
			break
		}
	}
	for {
		cur := h.maxNs.Load()
		if ns <= cur || h.maxNs.CompareAndSwap(cur, ns) {
			break
		}
	}
}

type LatencySummary struct {
	Count uint64  `json:"count"`
	MinMs float64 `json:"min_ms"`
	AvgMs float64 `json:"avg_ms"`
	P50Ms float64 `json:"p50_ms"`
	P90Ms float64 `json:"p90_ms"`
	P95Ms float64 `json:"p95_ms"`
	P99Ms float64 `json:"p99_ms"`
	P999Ms float64 `json:"p999_ms"`
	MaxMs float64 `json:"max_ms"`
}

func round3(v float64) float64 {
	return math.Round(v*1000.0) / 1000.0
}

func (h *LatencyHist) QuantileMs(p float64) float64 {
	total := h.count.Load()
	if total == 0 {
		return 0
	}
	target := uint64(math.Ceil((p / 100.0) * float64(total)))
	if target < 1 {
		target = 1
	}
	var acc uint64
	for i := 0; i < histTotalBuckets; i++ {
		acc += h.buckets[i].Load()
		if acc >= target {
			ub := bucketUpperBoundMs(i)
			maxMs := float64(h.maxNs.Load()) / 1e6
			if ub > maxMs && maxMs > 0 {
				return round3(maxMs)
			}
			return round3(ub)
		}
	}
	return round3(float64(h.maxNs.Load()) / 1e6)
}

func (h *LatencyHist) Summary() LatencySummary {
	n := h.count.Load()
	if n == 0 {
		return LatencySummary{}
	}
	minMs := float64(h.minNs.Load()) / 1e6
	maxMs := float64(h.maxNs.Load()) / 1e6
	avgMs := float64(h.sumNs.Load()) / float64(n) / 1e6
	return LatencySummary{
		Count:  n,
		MinMs:  round3(minMs),
		AvgMs:  round3(avgMs),
		P50Ms:  h.QuantileMs(50),
		P90Ms:  h.QuantileMs(90),
		P95Ms:  h.QuantileMs(95),
		P99Ms:  h.QuantileMs(99),
		P999Ms: h.QuantileMs(99.9),
		MaxMs:  round3(maxMs),
	}
}
