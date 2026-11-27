package ratelimit

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestValkeyLimiterTokenBucketArgsAndMalformedReplyGuards 验证：
// 1) TokenBucket Lua 传入 ARGV[5]=limit 且脚本口径返回已用量 used（与 MemoryLimiter/Peek 一致）；
// 2) Valkey 返回长度不足切片时 Allow/Peek 返回显式错误而非 index-out-of-range panic。
func TestValkeyLimiterTokenBucketArgsAndMalformedReplyGuards(t *testing.T) {
	if !strings.Contains(tokenBucketLua, "local used = burst - math.floor(tokens)") ||
		!strings.Contains(tokenBucketLua, "if allowed == 0 and limit ~= nil and used < limit then used = limit end") {
		t.Fatalf("tokenBucketLua must return consumed count 'used' consistent with MemoryLimiter/Peek")
	}

	rec := &recValkey{}
	l := NewValkeyLimiter(rec, "test")
	if _, err := l.Allow(context.Background(), "k1", TokenBucket, 10, time.Minute, 12); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if len(rec.args) != 1 || len(rec.args[0]) != 5 || rec.args[0][4] != "10" {
		t.Fatalf("expected 5 args with ARGV[5]=limit(10), got %+v", rec.args)
	}

	short := &fakeValkey{evalOut: []interface{}{int64(1)}}
	lShort := NewValkeyLimiter(short, "test")
	if _, err := lShort.Allow(context.Background(), "k1", TokenBucket, 10, time.Minute, 10); err == nil {
		t.Fatal("Allow(TokenBucket) must reject short valkey reply instead of panicking")
	}
	if _, err := lShort.Allow(context.Background(), "k1", SlidingWindow, 10, time.Minute, 10); err == nil {
		t.Fatal("Allow(SlidingWindow) must reject short valkey reply instead of panicking")
	}
	if _, _, err := lShort.Peek(context.Background(), "k1", TokenBucket, 10, time.Minute, 10); err == nil {
		t.Fatal("Peek(TokenBucket) must reject short valkey reply instead of panicking")
	}
	if _, _, err := lShort.Peek(context.Background(), "k1", SlidingWindow, 10, time.Minute, 10); err == nil {
		t.Fatal("Peek(SlidingWindow) must reject short valkey reply instead of panicking")
	}
}
