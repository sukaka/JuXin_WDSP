package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryTokenBucket(t *testing.T) {
	l := NewMemoryLimiter(100)
	now := time.Now()
	l.now = func() time.Time { return now }
	ctx := context.Background()
	// 容量=突发 3，前 3 个放行
	for i := 0; i < 3; i++ {
		res, err := l.Allow(ctx, "k1", TokenBucket, 3, time.Minute, 3)
		if err != nil || !res.Allowed {
			t.Fatalf("token %d should pass: %+v %v", i, res, err)
		}
	}
	// 第 4 个拒绝且有 RetryAfter
	res, _ := l.Allow(ctx, "k1", TokenBucket, 3, time.Minute, 3)
	if res.Allowed || res.RetryAfter <= 0 {
		t.Fatalf("should reject with retry-after: %+v", res)
	}
	// 20 秒（1 个令牌）后放行
	now = now.Add(20 * time.Second)
	res, _ = l.Allow(ctx, "k1", TokenBucket, 3, time.Minute, 3)
	if !res.Allowed {
		t.Fatalf("refill should allow: %+v", res)
	}
}

func TestMemorySlidingWindow(t *testing.T) {
	l := NewMemoryLimiter(100)
	now := time.Now()
	l.now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		res, _ := l.Allow(ctx, "k1", SlidingWindow, 5, time.Minute, 0)
		if !res.Allowed {
			t.Fatalf("req %d should pass", i)
		}
	}
	res, _ := l.Allow(ctx, "k1", SlidingWindow, 5, time.Minute, 0)
	if res.Allowed {
		t.Fatal("should reject at limit")
	}
	// 窗口过半：旧窗口权重 0.5，5*0.5=2 + 当前5 > 5 仍拒绝
	now = now.Add(30 * time.Second)
	if res, _ := l.Allow(ctx, "k1", SlidingWindow, 5, time.Minute, 0); res.Allowed {
		t.Fatal("weighted window should still reject")
	}
	// 完全过窗后放行
	now = now.Add(61 * time.Second)
	if res, _ := l.Allow(ctx, "k1", SlidingWindow, 5, time.Minute, 0); !res.Allowed {
		t.Fatal("new window should allow")
	}
}

func TestMemoryKeyIsolation(t *testing.T) {
	l := NewMemoryLimiter(100)
	ctx := context.Background()
	l.Allow(ctx, "a", TokenBucket, 1, time.Minute, 1)
	if res, _ := l.Allow(ctx, "a", TokenBucket, 1, time.Minute, 1); res.Allowed {
		t.Fatal("key a should be limited")
	}
	if res, _ := l.Allow(ctx, "b", TokenBucket, 1, time.Minute, 1); !res.Allowed {
		t.Fatal("key b independent")
	}
}

func TestInvalidParams(t *testing.T) {
	l := NewMemoryLimiter(100)
	if _, err := l.Allow(context.Background(), "k", TokenBucket, 0, time.Minute, 0); err == nil {
		t.Fatal("zero limit should error")
	}
	if _, err := l.Allow(context.Background(), "k", TokenBucket, 1, 0, 0); err == nil {
		t.Fatal("zero window should error")
	}
	if _, err := l.Allow(context.Background(), "k", "NOPE", 1, time.Minute, 0); err == nil {
		t.Fatal("unknown algorithm should error")
	}
}

// fakeValkey 测试替身。
type fakeValkey struct {
	evalOut []interface{}
	evalErr error
}

func (f *fakeValkey) Eval(_ context.Context, _ string, _ []string, _ []string) ([]interface{}, error) {
	return f.evalOut, f.evalErr
}
func (f *fakeValkey) HSet(_ context.Context, _, _, _ string) error { return nil }
func (f *fakeValkey) HGetAll(_ context.Context, _ string) (map[string]string, error) {
	return map[string]string{}, nil
}
func (f *fakeValkey) HDel(_ context.Context, _ string, _ ...string) error { return nil }
func (f *fakeValkey) Ping(_ context.Context) error                        { return nil }
func (f *fakeValkey) Close() error                                        { return nil }

func TestValkeyLimiterParsing(t *testing.T) {
	fk := &fakeValkey{evalOut: []interface{}{int64(1), int64(4), int64(0)}}
	l := NewValkeyLimiter(fk, "")
	res, err := l.Allow(context.Background(), "k", TokenBucket, 5, time.Minute, 5)
	if err != nil || !res.Allowed || res.Current != 4 {
		t.Fatalf("parse token bucket: %+v %v", res, err)
	}
	fk.evalOut = []interface{}{int64(0), int64(6), int64(1500)}
	res, _ = l.Allow(context.Background(), "k", SlidingWindow, 5, time.Minute, 0)
	if res.Allowed || res.RetryAfter != 1500*time.Millisecond {
		t.Fatalf("parse sliding window: %+v", res)
	}
	fk.evalErr = errors.New("valkey down")
	if _, err := l.Allow(context.Background(), "k", TokenBucket, 5, time.Minute, 5); err == nil {
		t.Fatal("error should propagate (fail strategy by caller)")
	}
}
