package middleware

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// fakeValkey 是最小 RESP 协议假服务器，用于在无真实 Valkey 的情况下
// 对限速中间件做故障注入回归测试（仅实现 INCR/EXPIRE/DEL/TTL）。
type fakeValkey struct {
	t  *testing.T
	ln net.Listener

	mu         sync.Mutex
	counters   map[string]int64
	expireSet  map[string]bool
	delKeys    []string
	failIncr   bool // INCR 一律报错（模拟 Valkey 故障）
	failExpire bool // EXPIRE 一律报错（模拟 Incr 成功后 Expire 抖动）
	ttlValue   int64
}

func newFakeValkey(t *testing.T) *fakeValkey {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake valkey: %v", err)
	}
	f := &fakeValkey{
		t:         t,
		ln:        ln,
		counters:  map[string]int64{},
		expireSet: map[string]bool{},
		ttlValue:  -1, // 默认模拟无 TTL 键
	}
	go f.serve()
	t.Cleanup(func() { _ = f.ln.Close() })
	return f
}

func (f *fakeValkey) addr() string { return f.ln.Addr().String() }

func (f *fakeValkey) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

// readCommand 解析一条 RESP 数组命令，返回命令参数列表。
func readCommand(br *bufio.Reader) ([]string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("unexpected resp line: %q", line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		head, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		head = strings.TrimRight(head, "\r\n")
		if !strings.HasPrefix(head, "$") {
			return nil, fmt.Errorf("unexpected bulk head: %q", head)
		}
		l, err := strconv.Atoi(head[1:])
		if err != nil {
			return nil, err
		}
		buf := make([]byte, l+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:l]))
	}
	return args, nil
}

func (f *fakeValkey) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		args, err := readCommand(br)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		f.mu.Lock()
		var reply string
		switch strings.ToUpper(args[0]) {
		case "HELLO":
			// go-redis 建连握手：报错使其回退 RESP2（错误被协议层容忍）
			reply = "-ERR unknown command 'HELLO'\r\n"
		case "INCR":
			if f.failIncr {
				reply = "-ERR simulated valkey failure\r\n"
			} else {
				f.counters[args[1]]++
				reply = fmt.Sprintf(":%d\r\n", f.counters[args[1]])
			}
		case "EXPIRE":
			if f.failExpire {
				reply = "-ERR simulated expire failure\r\n"
			} else {
				f.expireSet[args[1]] = true
				reply = ":1\r\n"
			}
		case "DEL":
			f.delKeys = append(f.delKeys, args[1:]...)
			delete(f.counters, args[1])
			reply = ":1\r\n"
		case "TTL":
			reply = fmt.Sprintf(":%d\r\n", f.ttlValue)
		default:
			reply = "+OK\r\n"
		}
		f.mu.Unlock()
		if _, err := conn.Write([]byte(reply)); err != nil {
			return
		}
	}
}

func (f *fakeValkey) deleted(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.delKeys {
		if k == key {
			return true
		}
	}
	return false
}

// newTestLimiter 构造直连假 Valkey 的限速器。
func newTestLimiter(t *testing.T, f *fakeValkey) *RateLimiter {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: f.addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return &RateLimiter{rdb: rdb}
}

func okHandler(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	})
}

func newRateLimitRequest() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	req.RemoteAddr = "192.0.2.10:5000"
	return req
}

// TestRateLimitExpireFailureFailsClosed 回归 MED-9：count==1 时 Expire 失败不得吞错
// 留下无 TTL 计数键（该来源会被永久 429）；必须删除计数键并按 Incr 失败同口径返回 503。
func TestRateLimitExpireFailureFailsClosed(t *testing.T) {
	fake := newFakeValkey(t)
	fake.failExpire = true
	limiter := newTestLimiter(t, fake)

	nextCalled := false
	h := limiter.Limit("login", 5, time.Minute, IPKey)(okHandler(&nextCalled))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newRateLimitRequest())

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s, want 503", rr.Code, rr.Body.String())
	}
	if nextCalled {
		t.Fatal("next handler must not run when Expire fails")
	}
	key := "jiuzhang:ratelimit:login:192.0.2.10"
	if !fake.deleted(key) {
		t.Fatalf("counter key %q not deleted after Expire failure (would stay TTL-less)", key)
	}
}

// TestRateLimitIncrFailureFailsClosed Incr 失败同样安全失败：503 且不放行。
func TestRateLimitIncrFailureFailsClosed(t *testing.T) {
	fake := newFakeValkey(t)
	fake.failIncr = true
	limiter := newTestLimiter(t, fake)

	nextCalled := false
	h := limiter.Limit("login", 5, time.Minute, IPKey)(okHandler(&nextCalled))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newRateLimitRequest())

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rr.Code)
	}
	if nextCalled {
		t.Fatal("next handler must not run when Incr fails")
	}
}

// TestRateLimitRetryAfterNeverNegative 回归 MED-9：键无 TTL（TTL 返回 -1）时
// 不得输出非法的 Retry-After 负值，应退化为窗口长度。
func TestRateLimitRetryAfterNeverNegative(t *testing.T) {
	fake := newFakeValkey(t)
	fake.ttlValue = -1 // 模拟无 TTL 键
	limiter := newTestLimiter(t, fake)

	window := 30 * time.Second
	h := limiter.Limit("login", 1, window, IPKey)(okHandler(new(bool)))

	// 第一次请求放行
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newRateLimitRequest())
	if rr.Code != http.StatusOK {
		t.Fatalf("first request status=%d, want 200", rr.Code)
	}

	// 第二次超限：Retry-After 必须是正整数（退化为窗口长度）
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, newRateLimitRequest())
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status=%d, want 429", rr.Code)
	}
	retryAfter := rr.Header().Get("Retry-After")
	if retryAfter != strconv.Itoa(int(window.Seconds())) {
		t.Fatalf("Retry-After=%q, want %q (window fallback, never negative)", retryAfter, "30")
	}
	if v, err := strconv.Atoi(retryAfter); err != nil || v <= 0 {
		t.Fatalf("Retry-After=%q must be a positive integer", retryAfter)
	}
}

// TestRateLimitRetryAfterUsesPositiveTTL 键有正常 TTL 时 Retry-After 取真实剩余秒数。
func TestRateLimitRetryAfterUsesPositiveTTL(t *testing.T) {
	fake := newFakeValkey(t)
	fake.ttlValue = 17
	limiter := newTestLimiter(t, fake)

	h := limiter.Limit("login", 1, time.Minute, IPKey)(okHandler(new(bool)))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newRateLimitRequest())
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, newRateLimitRequest())
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want 429", rr.Code)
	}
	if got := rr.Header().Get("Retry-After"); got != "17" {
		t.Fatalf("Retry-After=%q, want 17", got)
	}
}
