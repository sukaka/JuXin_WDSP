package security

import (
	"bytes"
	"context"
	"errors"
	"image/png"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRandomCodeAndRandInt 验证码随机源回归：randInt/randomCode 如实返回错误，
// 正常路径必须落在字符集与取值范围内（配合 LOW-S6 错误传播改造）。
func TestRandomCodeAndRandInt(t *testing.T) {
	code, err := randomCode(6)
	if err != nil {
		t.Fatalf("randomCode: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("code length=%d, want 6", len(code))
	}
	for _, ch := range code {
		if !strings.ContainsRune(captchaCharset, ch) {
			t.Fatalf("code %q contains char %q outside captcha charset", code, ch)
		}
	}
	for i := 0; i < 100; i++ {
		v, err := randInt(7)
		if err != nil {
			t.Fatalf("randInt: %v", err)
		}
		if v < 0 || v >= 7 {
			t.Fatalf("randInt(7)=%d out of range", v)
		}
	}
}

// TestRenderPNG 验证码图片生成回归：输出必须是可解码的 PNG。
func TestRenderPNG(t *testing.T) {
	img, err := renderPNG("AB23")
	if err != nil {
		t.Fatalf("renderPNG: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(img)); err != nil {
		t.Fatalf("renderPNG output not a valid png: %v", err)
	}
}

type memCaptchaStore struct {
	mu        sync.Mutex
	m         map[string]string
	getDelErr error
}

func (s *memCaptchaStore) Set(_ context.Context, key, value string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[string]string)
	}
	s.m[key] = value
	return nil
}

func (s *memCaptchaStore) GetDel(_ context.Context, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getDelErr != nil {
		return "", s.getDelErr
	}
	v, ok := s.m[key]
	if !ok {
		return "", ErrCaptchaNotFound
	}
	delete(s.m, key)
	return v, nil
}

// TestH19CaptchaVerifyAtomicSingleUseAndFailClosed 验证验证码消费原子性（并发仅一次成功）及缓存异常 fail-closed。
func TestH19CaptchaVerifyAtomicSingleUseAndFailClosed(t *testing.T) {
	ctx := context.Background()
	store := &memCaptchaStore{m: map[string]string{captchaKeyPrefix + "cap-1": "AB23"}}
	svc := &CaptchaService{store: store}

	// 20 并发请求同时使用同一有效验证码：必须恰有 1 次成功，其余全部返回 ErrCaptchaNotFound
	const workers = 20
	var okCount atomic.Int32
	var notFoundCount atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-start
			err := svc.Verify(ctx, "cap-1", "ab23", false)
			switch {
			case err == nil:
				okCount.Add(1)
			case errors.Is(err, ErrCaptchaNotFound):
				notFoundCount.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if okCount.Load() != 1 || notFoundCount.Load() != workers-1 {
		t.Fatalf("concurrent captcha verify: ok=%d notFound=%d, want 1 and %d",
			okCount.Load(), notFoundCount.Load(), workers-1)
	}

	// 错误验证码也应一次性消费（不能重复爆破同一 captcha_id）
	_ = store.Set(ctx, captchaKeyPrefix+"cap-2", "XY78", time.Minute)
	if err := svc.Verify(ctx, "cap-2", "ZZZZ", false); !errors.Is(err, ErrCaptchaMismatch) {
		t.Fatalf("wrong code err = %v, want ErrCaptchaMismatch", err)
	}
	if err := svc.Verify(ctx, "cap-2", "XY78", false); !errors.Is(err, ErrCaptchaNotFound) {
		t.Fatalf("retry after wrong code err = %v, want ErrCaptchaNotFound", err)
	}

	// 缓存 GetDel 返回后端错误时必须 fail-closed 拒绝
	store.getDelErr = errors.New("valkey connection reset")
	_ = store.Set(ctx, captchaKeyPrefix+"cap-3", "MN45", time.Minute)
	if err := svc.Verify(ctx, "cap-3", "MN45", false); err == nil {
		t.Fatal("expected fail-closed error when GetDel fails, got nil")
	}

	// nil store 必须 fail-closed
	if err := (&CaptchaService{}).Verify(ctx, "cap-1", "AB23", false); !errors.Is(err, ErrCaptchaNotFound) {
		t.Fatalf("nil store err = %v, want ErrCaptchaNotFound", err)
	}
}
