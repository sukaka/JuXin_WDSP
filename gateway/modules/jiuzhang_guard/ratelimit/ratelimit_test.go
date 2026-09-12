package ratelimit

import (
	"context"
	"errors"
	"strings"
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

// 记录 Eval 入参的测试替身（滑动窗口 member 断言用）。
type recValkey struct {
	args [][]string
}

func (f *recValkey) Eval(_ context.Context, _ string, _ []string, args []string) ([]interface{}, error) {
	f.args = append(f.args, append([]string(nil), args...))
	return []interface{}{int64(1), int64(1), int64(0)}, nil
}
func (f *recValkey) HSet(_ context.Context, _, _, _ string) error { return nil }
func (f *recValkey) HGetAll(_ context.Context, _ string) (map[string]string, error) {
	return map[string]string{}, nil
}
func (f *recValkey) HDel(_ context.Context, _ string, _ ...string) error { return nil }
func (f *recValkey) Ping(_ context.Context) error                        { return nil }
func (f *recValkey) Close() error                                        { return nil }

// 多节点同毫秒同序号时滑动窗口 member 必须仍唯一（实例随机前缀），防 ZADD 互相覆盖少计。
func TestValkeySlidingWindowMemberNodeUnique(t *testing.T) {
	fk := &recValkey{}
	now := time.Now()
	l1, l2 := NewValkeyLimiter(fk, ""), NewValkeyLimiter(fk, "")
	l1.now = func() time.Time { return now }
	l2.now = func() time.Time { return now }
	ctx := context.Background()
	if l1.inst == l2.inst {
		t.Fatal("instance ids must differ across limiters")
	}
	// 两节点（两 limiter）同一毫秒、同起始序号各发一请求
	if _, err := l1.Allow(ctx, "k", SlidingWindow, 5, time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := l2.Allow(ctx, "k", SlidingWindow, 5, time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	m1, m2 := fk.args[0][3], fk.args[1][3]
	if m1 == m2 {
		t.Fatalf("members must not collide across nodes: %q", m1)
	}
	// member 结构：<实例前缀>-<毫秒>-<序号>
	for _, m := range []string{m1, m2} {
		if parts := strings.Split(m, "-"); len(parts) != 3 || parts[0] == "" {
			t.Fatalf("member format: %q", m)
		}
	}
	// 同节点连续请求 member 也因序号自增而不同
	if _, err := l1.Allow(ctx, "k", SlidingWindow, 5, time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	if fk.args[2][3] == m1 {
		t.Fatal("same-node members must differ by seq")
	}
}

// Peek 只读查询：计数与 Allow 同口径、不建键、不改变后续 Allow 判定。
func TestMemoryPeek(t *testing.T) {
	l := NewMemoryLimiter(100)
	now := time.Now()
	l.now = func() time.Time { return now }
	ctx := context.Background()

	// 键不存在：found=false 且不建键
	if n, found, err := l.Peek(ctx, "nope", TokenBucket, 3, time.Minute, 3); err != nil || found || n != 0 {
		t.Fatalf("missing key peek = %d,%v,%v", n, found, err)
	}
	if l.KeysCount() != 0 {
		t.Fatalf("Peek must not create keys, KeysCount=%d", l.KeysCount())
	}

	// 令牌桶：2 次放行后已用量 2；Peek 不消费令牌（随后第 3 次仍放行、第 4 次拒绝）
	l.Allow(ctx, "tb", TokenBucket, 3, time.Minute, 3)
	l.Allow(ctx, "tb", TokenBucket, 3, time.Minute, 3)
	if n, found, _ := l.Peek(ctx, "tb", TokenBucket, 3, time.Minute, 3); !found || n != 2 {
		t.Fatalf("tb peek = %d,%v, want 2,true", n, found)
	}
	if res, _ := l.Allow(ctx, "tb", TokenBucket, 3, time.Minute, 3); !res.Allowed {
		t.Fatal("peek must not consume tokens")
	}
	if res, _ := l.Allow(ctx, "tb", TokenBucket, 3, time.Minute, 3); res.Allowed {
		t.Fatal("bucket should be exhausted after 3 allows")
	}

	// 滑动窗口：5 次放行后窗口计数 5；过窗后按权重回落
	for i := 0; i < 5; i++ {
		l.Allow(ctx, "sw", SlidingWindow, 5, time.Minute, 0)
	}
	if n, found, _ := l.Peek(ctx, "sw", SlidingWindow, 5, time.Minute, 0); !found || n != 5 {
		t.Fatalf("sw peek = %d,%v, want 5,true", n, found)
	}
	now = now.Add(2 * time.Minute)
	if n, _, _ := l.Peek(ctx, "sw", SlidingWindow, 5, time.Minute, 0); n != 0 {
		t.Fatalf("sw peek after window = %d, want 0", n)
	}

	// 非法参数与未知算法如实报错
	if _, _, err := l.Peek(ctx, "k", TokenBucket, 0, time.Minute, 0); err == nil {
		t.Fatal("zero limit should error")
	}
	if _, _, err := l.Peek(ctx, "k", "NOPE", 1, time.Minute, 0); err == nil {
		t.Fatal("unknown algorithm should error")
	}
}

func TestValkeyPeekParsing(t *testing.T) {
	fk := &fakeValkey{evalOut: []interface{}{int64(1), int64(3)}}
	l := NewValkeyLimiter(fk, "")
	n, found, err := l.Peek(context.Background(), "k", TokenBucket, 5, time.Minute, 5)
	if err != nil || !found || n != 3 {
		t.Fatalf("tb peek = %d,%v,%v, want 3,true,nil", n, found, err)
	}
	fk.evalOut = []interface{}{int64(0), int64(0)}
	if n, found, _ = l.Peek(context.Background(), "k", SlidingWindow, 5, time.Minute, 0); found || n != 0 {
		t.Fatalf("missing sw key peek = %d,%v, want 0,false", n, found)
	}
	fk.evalErr = errors.New("valkey down")
	if _, _, err := l.Peek(context.Background(), "k", TokenBucket, 5, time.Minute, 5); err == nil {
		t.Fatal("error should propagate (fail strategy by caller)")
	}
}
