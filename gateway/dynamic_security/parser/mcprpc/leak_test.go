// leak_test.go goroutine 泄漏与取消释放断言（grpcframe R06 纪律承接：
// 解析全在调用方 goroutine、无后台任务——并发解析+cancel 后 goroutine
// 数回归基线）。
package mcprpc

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// blockingSource 可取消阻塞源（数据耗尽后阻塞至 ctx 取消——模拟客户端
// RST_STREAM/超时：读取器随数据源错误返回即释放）。
type blockingSource struct {
	ctx  context.Context
	data []byte
}

func (s *blockingSource) Read(p []byte) (int, error) {
	if len(s.data) > 0 {
		n := copy(p, s.data)
		s.data = s.data[n:]
		return n, nil
	}
	<-s.ctx.Done()
	return 0, s.ctx.Err()
}

// TestNoGoroutineLeakOnCancel R06 同规格断言：并发 SSE 解析 + cancel →
// 全部终止、goroutine 回归基线（读取器无后台 goroutine 的证明形态）。
func TestNoGoroutineLeakOnCancel(t *testing.T) {
	base := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := NewSSEReader(&blockingSource{ctx: ctx, data: []byte("data: x\n\n")}, 0)
			for {
				if _, err := r.Next(); err != nil {
					return
				}
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
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

// TestParseMessageNoBackgroundTask 消息解析无后台任务（大输入同步完成即释放——
// 解析 goroutine 即调用方 goroutine）。
func TestParseMessageNoBackgroundTask(t *testing.T) {
	base := runtime.NumGoroutine()
	big := `{"jsonrpc":"2.0","method":"x","params":{"s":"` + strings.Repeat("a", 400<<10) + `","arr":[` +
		strings.TrimSuffix(strings.Repeat("1,", 4095), ",") + `]}}`
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ParseMessage([]byte(big), Budgets{}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if now := runtime.NumGoroutine(); now > base+1 {
		t.Fatalf("goroutine 数未回归基线: base=%d now=%d", base, now)
	}
}
