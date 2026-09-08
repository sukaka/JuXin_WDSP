package jiuzhang_guard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// stubValkey 最小 counters.ValkeyClient 替身（装配测试只关心注入与否，不执行命令）。
type stubValkey struct{}

func (stubValkey) Eval(_ context.Context, _ string, _ []string, _ []string) ([]interface{}, error) {
	return nil, nil
}
func (stubValkey) HSet(_ context.Context, _, _, _ string) error                   { return nil }
func (stubValkey) HGetAll(_ context.Context, _ string) (map[string]string, error) { return nil, nil }
func (stubValkey) HDel(_ context.Context, _ string, _ ...string) error            { return nil }
func (stubValkey) Ping(_ context.Context) error                                   { return nil }
func (stubValkey) Close() error                                                   { return nil }

// behavior_store 缺省/memory → 不注入（nil，进程内默认，零行为变化）。
func TestBuildBehaviorStores_DefaultAndMemoryNil(t *testing.T) {
	g := &Guard{logger: zap.NewNop()}
	if o := buildBehaviorStores(g, &sharedEngine{}); o != nil {
		t.Fatalf("empty behavior_store must not inject: %+v", o)
	}
	g.BehaviorStore = "memory"
	if o := buildBehaviorStores(g, &sharedEngine{valkey: stubValkey{}}); o != nil {
		t.Fatalf("memory behavior_store must not inject even with valkey client: %+v", o)
	}
}

// behavior_store=valkey 但共享引擎无 Valkey 连接：装配期 Fail-open——告警 + 回退 nil（不阻断启动）。
func TestBuildBehaviorStores_ValkeyWithoutClientWarnsAndFallsBack(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	g := &Guard{BehaviorStore: "valkey", logger: zap.New(core)}
	if o := buildBehaviorStores(g, &sharedEngine{}); o != nil {
		t.Fatalf("no valkey client must fall back to nil: %+v", o)
	}
	if logs.Len() != 1 || !strings.Contains(logs.All()[0].Message, "behavior_store=valkey") {
		t.Fatalf("expected one warn about missing valkey connection, got %+v", logs.All())
	}
	// 引擎为 nil 的极端情况同样不 panic、回退 nil
	if o := buildBehaviorStores(g, nil); o != nil {
		t.Fatalf("nil engine must fall back to nil: %+v", o)
	}
}

// behavior_store=valkey 且引擎已建连：注入完整五路存储覆盖。
func TestBuildBehaviorStores_ValkeyInjectsAllOverrides(t *testing.T) {
	g := &Guard{BehaviorStore: "valkey", logger: zap.NewNop()}
	o := buildBehaviorStores(g, &sharedEngine{valkey: stubValkey{}})
	if o == nil {
		t.Fatal("valkey store must be injected")
	}
	if o.BehaviorWindow == nil || o.APIWriteWindow == nil || o.ObjectCursor == nil ||
		o.IPSpread == nil || o.Concurrency == nil {
		t.Fatalf("overrides incomplete: %+v", o)
	}
}

// Validate 校验 behavior_store 取值与 TTL 非负。
func TestValidate_BehaviorStore(t *testing.T) {
	base := func() *Guard { return &Guard{EventsLog: "x"} }
	for _, v := range []string{"", "memory", "valkey"} {
		g := base()
		g.BehaviorStore = v
		if err := g.Validate(); err != nil {
			t.Fatalf("behavior_store=%q must be valid: %v", v, err)
		}
	}
	g := base()
	g.BehaviorStore = "redis"
	if err := g.Validate(); err == nil {
		t.Fatal("behavior_store=redis must be rejected")
	}
	g = base()
	g.BehaviorStoreTTLSeconds = -1
	if err := g.Validate(); err == nil {
		t.Fatal("negative behavior_store_ttl_seconds must be rejected")
	}
	g = base()
	g.BehaviorStoreTTLSeconds = 900
	if err := g.Validate(); err != nil {
		t.Fatalf("positive ttl must be valid: %v", err)
	}
}

// spyConcurrencyStore 记录 Acquire 调用的并发存储探针。
type spyConcurrencyStore struct{ acquires atomic.Int32 }

func (s *spyConcurrencyStore) Acquire(string) int { s.acquires.Add(1); return 1 }
func (s *spyConcurrencyStore) Release(string)     {}
func (s *spyConcurrencyStore) Current(string) int { return 0 }

// MED-5 回归：同进程内两个 Guard 各自使用实例绑定的存储，互不串用。
func TestBehaviorStoresAreIsolatedPerGuard(t *testing.T) {
	spy := &spyConcurrencyStore{}
	injected := provisionIBHTestGuard(t, Guard{
		AppID: "app1", APIDynamicProtection: true, APIProtectionMode: "OBSERVE",
	})
	injected.behaviorStores = &detectors.StoreOverrides{Concurrency: spy}
	memory := provisionIBHTestGuard(t, Guard{
		AppID: "app1", APIDynamicProtection: true, APIProtectionMode: "OBSERVE",
	})

	serve := func(g *Guard, remoteAddr string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "http://waf-test.local/v1/orders", nil)
		r.RemoteAddr = remoteAddr
		r.Header.Set("Authorization", "Bearer test-token")
		if err := g.serveNext(httptest.NewRecorder(), r, nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			return nil
		})); err != nil {
			t.Fatalf("serveNext: %v", err)
		}
	}

	serve(injected, "203.0.113.10:1")
	serve(memory, "203.0.113.11:1")
	if got := spy.acquires.Load(); got != 1 {
		t.Fatalf("only the injected Guard may use its concurrency store: acquires=%d", got)
	}
}
