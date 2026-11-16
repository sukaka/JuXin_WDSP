package jiuzhang_guard

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/ratelimit"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/temporaryblock"
)

// ---------- 共享引擎（进程级：Valkey 连接/临时封禁缓存/内存计数器） ----------

type sharedEngine struct {
	mu          sync.Mutex
	initialized bool
	sig         string // 配置指纹（backend/addr/密码/DB/maxKeys）
	valkey      counters.ValkeyClient
	limiter     ratelimit.Limiter
	memLimiter  *ratelimit.MemoryLimiter
	blockStore  *temporaryblock.Store
	blockCache  *temporaryblock.Cache
	failOpen    bool
	cancelPoll  context.CancelFunc
	// 引擎错误告警节流（每分钟每类最多一条事件）
	lastErrEmit map[string]time.Time
}

var (
	engineMu   sync.Mutex
	engineInst *sharedEngine
)

// engineFingerprint 用于判断共享引擎是否需重建（凭据/后端变化）。
func engineFingerprint(g *Guard) string {
	backend := g.CounterBackend
	if backend == "" {
		backend = "valkey"
	}
	addr, user, pass, db := "", "", "", 0
	if g.Valkey != nil {
		addr = g.Valkey.Address
		user = g.Valkey.Username
		pass = g.Valkey.Password
		db = g.Valkey.DB
	}
	return fmt.Sprintf("%s|%s|%s|%s|%d|%d", backend, addr, user, pass, db, g.MaxCounterKeys)
}

// getEngine 初始化或复用共享引擎；失败不缓存半初始化实例，配置指纹变化时重建。
// 重建顺序（HIGH-5）：先完整构建并 init 新引擎（不触碰旧实例）→ 验证必需组件就绪 →
// 原子替换 engineInst → 替换成功后再关闭旧实例。init 失败时旧实例保持存活——Caddy 拒绝
// 新配置但在线旧配置的引擎（封禁轮询、CC/配额限速）不受失败重载影响。
func getEngine(g *Guard) (*sharedEngine, error) {
	engineMu.Lock()
	defer engineMu.Unlock()
	sig := engineFingerprint(g)
	if engineInst != nil && engineInst.initialized && engineInst.sig == sig &&
		engineInst.limiter != nil && engineInst.blockCache != nil {
		return engineInst, nil
	}
	e := &sharedEngine{lastErrEmit: map[string]time.Time{}, sig: sig}
	if err := e.init(g); err != nil {
		return nil, err
	}
	if e.limiter == nil || e.blockCache == nil {
		// init 未装配完整：回收半成品（不污染共享指针），旧实例继续服务
		e.shutdown()
		return nil, fmt.Errorf("engine init incomplete")
	}
	old := engineInst
	engineInst = e
	// 替换成功后停止旧轮询并关闭旧 Valkey 连接：不关则每次改 Valkey 配置的 reload
	// 都会泄漏一条（Close 失败仅告警；在途请求由引擎 FailOpen 策略兜底）
	if old != nil {
		old.shutdown()
	}
	return engineInst, nil
}

// shutdown 停止封禁轮询并关闭 Valkey 连接（引擎被替换或半成品回收时调用；幂等）。
func (e *sharedEngine) shutdown() {
	if e.cancelPoll != nil {
		e.cancelPoll()
		e.cancelPoll = nil
	}
	if e.valkey != nil {
		if err := e.valkey.Close(); err != nil {
			slog.Warn("jiuzhang_guard old valkey connection close on engine rebuild failed", "error", err)
		}
		e.valkey = nil
	}
}

// resetSharedEngineForTest 测试辅助：清空进程级引擎。
func resetSharedEngineForTest() {
	engineMu.Lock()
	defer engineMu.Unlock()
	if engineInst != nil {
		engineInst.shutdown()
	}
	engineInst = nil
}

func (e *sharedEngine) init(g *Guard) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failOpen = g.FailOpen == nil || *g.FailOpen
	e.memLimiter = ratelimit.NewMemoryLimiter(g.MaxCounterKeys)
	backend := g.CounterBackend
	if backend == "" {
		backend = "valkey"
	}
	if backend == "valkey" && g.Valkey != nil && g.Valkey.Address != "" {
		cli, err := counters.NewValkeyClient(counters.ValkeyConfig{
			Address:  g.Valkey.Address,
			Username: g.Valkey.Username,
			Password: g.Valkey.Password,
			DB:       g.Valkey.DB,
		})
		if err != nil {
			return fmt.Errorf("valkey init: %w", err)
		}
		e.valkey = cli
		e.limiter = ratelimit.NewValkeyLimiter(cli, "")
		e.blockStore = temporaryblock.NewStore(cli, "")
		poll, _ := time.ParseDuration(g.TempBlockPollInterval)
		e.blockCache = temporaryblock.NewCache(e.blockStore, poll)
		ctx, cancel := context.WithCancel(context.Background())
		e.cancelPoll = cancel
		if err := e.initialBlockRefresh(g, ctx); err != nil {
			// fail-closed 首刷失败拒绝加载：回收半成品（关 Valkey 连接/取消 ctx），
			// 旧引擎保持存活（HIGH-5），Caddy 拒绝新配置
			e.shutdown()
			return err
		}
		e.blockCache.Start(ctx)
	} else {
		// 纯内存模式：临时封禁仅进程内有效（单节点模式）
		e.blockCache = temporaryblock.NewCache(nil, 0)
		e.limiter = e.memLimiter
	}
	e.initialized = true
	return nil
}

// tempBlockRefreshErrKey 启动首刷失败告警的节流键（无策略维度，引擎级固定键）。
const tempBlockRefreshErrKey = "__tempblock_initial_refresh__"

// initialBlockRefresh 启动首刷（M-13）：失败除 Error 日志外产节流事件（与请求路径
// emitEngineErrorThrottled 同一节流口径，共享 lastErrEmit）；fail-closed 下首刷失败
// 返回错误拒绝加载，fail-open（默认）行为不变——空缓存启动、下一轮轮询重试。
// 调用方须已持有 e.mu。
func (e *sharedEngine) initialBlockRefresh(g *Guard, ctx context.Context) error {
	if err := e.blockCache.Refresh(ctx); err != nil {
		slog.Error("jiuzhang_guard tempblock initial refresh failed", "error", err)
		if engineErrThrottleLocked(e, tempBlockRefreshErrKey) {
			g.emitStartupEngineError(err)
		}
		if !e.failOpen {
			return fmt.Errorf("tempblock initial refresh: %w", err)
		}
	}
	return nil
}
