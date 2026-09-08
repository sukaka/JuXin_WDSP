package pipeline

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// captureWindowStore 捕获 AddAndCount 调用的 WindowStore 替身。
type captureWindowStore struct{ calls []string }

func (c *captureWindowStore) AddAndCount(key string) (int, []int) {
	c.calls = append(c.calls, key)
	return 1, nil
}

func behaviorRequest(t *testing.T) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "http://h/v1/orders/9", strings.NewReader(`{"id":1}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer t")
	return r
}

// Process 将 Stores 绑定到本次 RequestContext；后续无覆盖请求不得复用它。
func TestProcessUsesRequestScopedStores(t *testing.T) {
	cap := &captureWindowStore{}
	res, err := Process(behaviorRequest(t), Config{
		Enabled: true,
		Mode:    "OBSERVE",
		Stores:  &detectors.StoreOverrides{BehaviorWindow: cap},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped || len(cap.calls) == 0 {
		t.Fatalf("request-scoped behavior store was not used: skipped=%v calls=%v", res.Skipped, cap.calls)
	}

	before := len(cap.calls)
	if _, err := Process(behaviorRequest(t), Config{Enabled: true, Mode: "OBSERVE"}, nil); err != nil {
		t.Fatal(err)
	}
	if len(cap.calls) != before {
		t.Fatal("a request without Stores reused another request's override")
	}
}

// 关闭管线时不创建上下文，也不触碰存储。
func TestProcessDisabledDoesNotUseStores(t *testing.T) {
	cap := &captureWindowStore{}
	res, err := Process(behaviorRequest(t), Config{
		Enabled: false,
		Stores:  &detectors.StoreOverrides{BehaviorWindow: cap},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped {
		t.Fatal("expected skip when disabled")
	}
	if len(cap.calls) != 0 {
		t.Fatalf("disabled pipeline must not touch stores: %v", cap.calls)
	}
}
