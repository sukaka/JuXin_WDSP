// leak_test.go goroutine 泄漏断言（httpsig 全部计算在调用方 goroutine——
// 无后台任务的证明形态；重放 Store 并发无泄漏）。
package httpsig

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestNoGoroutineLeak 并发解析+验签+重放登记后 goroutine 回归基线。
func TestNoGoroutineLeak(t *testing.T) {
	base := runtime.NumGoroutine()
	k := genTestKeys(t)
	body := []byte(`{"hello": "world"}`)
	r, p, key := signTestRequest(t, k, AlgEd25519, "POST", "/foo?param=Value&Pet=dog", body, nil)
	fe := &fakeReplayEval{seen: map[string]bool{}}
	s := NewReplayStore(fe)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = VerifySignatureBase(r, p, body, key)
			_, _ = s.CheckAndSet(context.Background(), "fp", "dg", time.Minute)
		}()
	}
	wg.Wait()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= base+1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutine 数未回归基线: base=%d now=%d", base, runtime.NumGoroutine())
}
