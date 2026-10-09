// replay_test.go 重放 Store 契约矩阵（假 Evaluator 桩：首次 false、重复 true、
// Eval 错误透传、TTL 传递正确、键形态、存储缺席、防御归一）。
package httpsig

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeReplayEval 可编程 Eval 桩（记录调用；键集合模拟 SET NX 语义）。
type fakeReplayEval struct {
	mu       sync.Mutex
	seen     map[string]bool
	lastKeys []string
	lastArgs []string
	err      error
}

func (f *fakeReplayEval) Eval(_ context.Context, _ string, keys []string, args []string) ([]interface{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastKeys, f.lastArgs = keys, args
	if f.err != nil {
		return nil, f.err
	}
	if f.seen[keys[0]] {
		return []interface{}{int64(0)}, nil // 已存在 = 重放
	}
	f.seen[keys[0]] = true
	return []interface{}{int64(1)}, nil
}

func TestReplayStoreMatrix(t *testing.T) {
	fe := &fakeReplayEval{seen: map[string]bool{}}
	s := NewReplayStore(fe)
	// 首次登记：非重放
	isReplay, err := s.CheckAndSet(context.Background(), "fp-a", "digest-a", 90*time.Second)
	if err != nil || isReplay {
		t.Fatalf("首次应 (false,nil): %v %v", isReplay, err)
	}
	// 键形态：mid:v1:nonce:{identityFP}:{nonceDigestHex32}（hash tag 同槽）
	if want := "mid:v1:nonce:{fp-a}:digest-a"; fe.lastKeys[0] != want {
		t.Fatalf("键形态 = %q，应 %q", fe.lastKeys[0], want)
	}
	// TTL 传递：PX 毫秒
	if fe.lastArgs[1] != "90000" {
		t.Fatalf("TTL arg = %q，应 90000", fe.lastArgs[1])
	}
	// 重复：重放检出
	isReplay, err = s.CheckAndSet(context.Background(), "fp-a", "digest-a", 90*time.Second)
	if err != nil || !isReplay {
		t.Fatalf("重复应 (true,nil): %v %v", isReplay, err)
	}
	// 异身份同 nonce 不串键
	isReplay, err = s.CheckAndSet(context.Background(), "fp-b", "digest-a", 90*time.Second)
	if err != nil || isReplay {
		t.Fatalf("异身份应非重放: %v %v", isReplay, err)
	}
	// Eval 错误透传（不静默——B2 UNAVAILABLE 处置语义消费）
	fe.err = errors.New("valkey down")
	_, err = s.CheckAndSet(context.Background(), "fp-c", "digest-c", 90*time.Second)
	if err == nil || err.Error() != "valkey down" {
		t.Fatalf("故障应透传: %v", err)
	}
	// 协议异常（空返回/多元素/未知值）
	fe.err = nil
	fe2 := &fakeReplayEval{seen: map[string]bool{}}
	fe2.err = nil
	bad := &badReplyEval{reply: []interface{}{}}
	if _, err := NewReplayStore(bad).CheckAndSet(context.Background(), "x", "y", time.Second); !errors.Is(err, errReplayProtocol) {
		t.Fatalf("空返回应协议错误: %v", err)
	}
	bad2 := &badReplyEval{reply: []interface{}{int64(1), int64(2)}}
	if _, err := NewReplayStore(bad2).CheckAndSet(context.Background(), "x", "y", time.Second); !errors.Is(err, errReplayProtocol) {
		t.Fatalf("多元素应协议错误: %v", err)
	}
	bad3 := &badReplyEval{reply: []interface{}{"weird"}}
	if _, err := NewReplayStore(bad3).CheckAndSet(context.Background(), "x", "y", time.Second); !errors.Is(err, errReplayProtocol) {
		t.Fatalf("未知值应协议错误: %v", err)
	}
	// 字符串形态（"1"/"0"）兼容
	str := &badReplyEval{reply: []interface{}{"1"}}
	if replay, err := NewReplayStore(str).CheckAndSet(context.Background(), "x", "y", time.Second); err != nil || replay {
		t.Fatalf("字符串 1 应 (false,nil): %v %v", replay, err)
	}
	// 存储缺席：错误（errStoreUnconfigured——不判无效不本机去重）
	if _, err := NewReplayStore(nil).CheckAndSet(context.Background(), "x", "y", time.Second); !errors.Is(err, errStoreUnconfigured) {
		t.Fatalf("缺席应 errStoreUnconfigured: %v", err)
	}
	var nilStore *ReplayStore
	if _, err := nilStore.CheckAndSet(context.Background(), "x", "y", time.Second); !errors.Is(err, errStoreUnconfigured) {
		t.Fatalf("nil store 应 errStoreUnconfigured: %v", err)
	}
	// 零/负 TTL 防御归一 1s
	fe3 := &fakeReplayEval{seen: map[string]bool{}}
	if _, err := NewReplayStore(fe3).CheckAndSet(context.Background(), "x", "y", 0); err != nil || fe3.lastArgs[1] != "1000" {
		t.Fatalf("零 TTL 应归一 1000ms: %v %v", err, fe3.lastArgs)
	}
	// Lua 脚本形态断言（SET NX PX 单次原子往返）
	if !strings.Contains(replaySetNXLua, "'NX'") || !strings.Contains(replaySetNXLua, "'PX'") || !strings.Contains(replaySetNXLua, "'SET'") {
		t.Fatal("脚本应 SET NX PX")
	}
}

// badReplyEval 协议异常桩。
type badReplyEval struct{ reply []interface{} }

func (b *badReplyEval) Eval(context.Context, string, []string, []string) ([]interface{}, error) {
	return b.reply, nil
}

// TestReplayStoreConcurrent 并发登记唯一性（同一键并发 N 次恰一次非重放——
// SET NX 原子语义在桩上模拟；真实多节点原子性由 Valkey 承载）。
func TestReplayStoreConcurrent(t *testing.T) {
	fe := &fakeReplayEval{seen: map[string]bool{}}
	s := NewReplayStore(fe)
	var wg sync.WaitGroup
	var okCount int64
	var mu sync.Mutex
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			replay, err := s.CheckAndSet(context.Background(), "fp-x", "digest-x", time.Minute)
			if err == nil && !replay {
				mu.Lock()
				okCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if okCount != 1 {
		t.Fatalf("并发同键应恰一次非重放: %d", okCount)
	}
}
