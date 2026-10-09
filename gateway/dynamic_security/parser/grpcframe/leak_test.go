// leak_test.go goroutine 泄漏与取消释放断言（NG-T-R06 首期：并发解析 + cancel
// 后 goroutine 数回归基线、全局预算零驻留——读取器无后台 goroutine、全部解析
// 在请求 goroutine 内完成的证明形态）。
package grpcframe

import (
	"bytes"
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

// cancelFrameSource 可取消的无限帧源流：持续产帧直到 ctx 取消
// （阻塞在 ctx.Done() 后返回 ctx.Err()——模拟客户端 RST_STREAM/超时）。
type cancelFrameSource struct {
	ctx    context.Context
	buf    []byte
	offset int
}

func newCancelFrameSource(ctx context.Context) *cancelFrameSource {
	return &cancelFrameSource{ctx: ctx, buf: frameBytes(false, []byte("x"))}
}

func (s *cancelFrameSource) Read(p []byte) (int, error) {
	if s.offset < len(s.buf) {
		n := copy(p, s.buf[s.offset:])
		s.offset += n
		return n, nil
	}
	select {
	case <-s.ctx.Done():
		return 0, s.ctx.Err()
	case <-time.After(time.Millisecond):
		// 慢速产帧（保活）
		s.buf = frameBytes(false, []byte("x"))
		s.offset = 0
		return 0, nil
	}
}

// TestNoGoroutineLeakOnCancel R06 首期断言：32 并发解析 + cancel → 全部终止、
// goroutine 回归基线、全局预算归零。
func TestNoGoroutineLeakOnCancel(t *testing.T) {
	base := runtime.NumGoroutine()
	g := NewGlobalBudget(0)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rd := NewReader(newCancelFrameSource(ctx), Config{Global: g})
			for {
				if _, err := rd.Next(); err != nil {
					break
				}
			}
			_ = rd.Close()
		}()
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	wg.Wait() // 读取器无后台 goroutine：源错误即 Next 返回，解析随请求 goroutine 终止

	if used := g.Used(); used != 0 {
		t.Fatalf("cancel 后全局预算驻留 %d", used)
	}
	// goroutine 数回归基线（等 GC 收尾窗口）
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= base+1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutine 数未回归基线: base=%d now=%d", base, runtime.NumGoroutine())
}

// TestBudgetReleasedOnAllPaths 全路径预算释放矩阵：正常读完/中途畸形/源错误/
// 未读即 Close——终态全局持有归零。
func TestBudgetReleasedOnAllPaths(t *testing.T) {
	body := frameBytes(false, []byte("0123456789"))
	cases := []struct {
		name   string
		stream []byte
		reads  int // 主动 Next 次数（-1 = 读到底）
	}{
		{"正常读完", append(body, body...), -1},
		{"中途畸形", append(body, forgedFrame(0xFF, 0, nil)...), -1},
		{"声明伪造", forgedFrame(0, 100, []byte{1}), -1},
		{"读一帧即弃", append(body, body...), 1},
		{"未读即 Close", append(body, body...), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewGlobalBudget(0)
			rd := NewReader(newStepReader(bytes.NewReader(tc.stream), 3), Config{Global: g})
			if tc.reads < 0 {
				_, _ = readAll(rd)
			} else {
				for i := 0; i < tc.reads; i++ {
					_, _ = rd.Next()
				}
			}
			_ = rd.Close()
			if g.Used() != 0 {
				t.Fatalf("持有 = %d", g.Used())
			}
			// Close 幂等
			_ = rd.Close()
			if g.Used() != 0 {
				t.Fatalf("重复 Close 后持有 = %d", g.Used())
			}
		})
	}
}
