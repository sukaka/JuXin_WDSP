// ch_manager.go ClickHouse 数据面连接管理器：DSN 运行期可变（系统设置界面热生效），
// Resolve 按当前生效 DSN 惰性建连/按变化重建，查询方（apm.Store 逐次解析、组件
// 探针、采集滞后评估源、数据流读写器）共享同一缓存连接。
//
// 降级与自愈纪律（遥测故障不影响管理面，但不得永久锁死）：
//   - DSN 为空 → (nil, nil)，纯无 Agent 模式；
//   - 建连失败 → Warn 日志 + (nil, nil) 降级（不 panic、不 500），并记录失败时间；
//     冷却期（默认 15s）内快速返回降级避免阻塞管理面，冷却期过后下次 Resolve 自动重试建连；
//   - Reconnect / RetryDisconnected 供设置接口在显式保存时绕过冷却立即重连；
//   - DSN 变化或显式重建前先关闭旧连接（防连接泄漏）。
package apm

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"
)

// defaultCHRetryInterval ClickHouse 建连失败后的最小重试冷却间隔：
// 既避免 ClickHouse 不可达时每个请求阻塞 5s Ping 拖慢管理面，也保证升级接通网络
// 或 ClickHouse 恢复后短时间内自动自愈，不再永久缓存 nil。
const defaultCHRetryInterval = 15 * time.Second

// CHManager ClickHouse 连接管理器（goroutine 安全；dial/now/retryInterval 可注入便于单测）。
type CHManager struct {
	cfg           *RuntimeConfig
	dial          func(dsn string) (CHQuerier, error)
	now           func() time.Time
	retryInterval time.Duration

	mu         sync.Mutex
	resolved   bool      // 是否已完成首次解析（首次调用触发建连）
	dsn        string    // 当前缓存状态对应的生效 DSN
	querier    CHQuerier // nil = 数据面未接入（DSN 空/建连失败降级）
	health     *CHHealth // 与 querier 同生共死
	lastFailAt time.Time // 最近一次建连失败时刻（仅非空 DSN 失败时非零，用于冷却退避）
}

// NewCHManager 创建连接管理器（生产 dial 为 OpenClickHouse）。
func NewCHManager(cfg *RuntimeConfig) *CHManager {
	return &CHManager{
		cfg:           cfg,
		dial:          OpenClickHouse,
		now:           time.Now,
		retryInterval: defaultCHRetryInterval,
	}
}

func (m *CHManager) currentTime() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// Resolve 解析当前 ClickHouse 查询器与健康读数：
//   - 已建连且 DSN 一致 → 直接复用缓存连接；
//   - 空 DSN → 返回 (nil, nil)；
//   - 非空 DSN 上次建连失败 → 冷却期内直接降级 (nil, nil)，超过冷却期自动重试建连；
//   - DSN 变化（含首次解析）→ 关闭旧连接并按新 DSN 建连。
func (m *CHManager) Resolve(ctx context.Context) (CHQuerier, *CHHealth) {
	return m.resolve(ctx, false, false)
}

// Reconnect 绕过失败冷却并按当前生效 DSN 强制重建连接（PUT /api/v1/apm/settings
// 显式提交 clickhouse_dsn 时调用，确保重新保存相同 DSN 也能立即触发建连/刷新）。
func (m *CHManager) Reconnect(ctx context.Context) (CHQuerier, *CHHealth) {
	return m.resolve(ctx, true, true)
}

// RetryDisconnected 绕过失败冷却在当前未连接时立即重试建连；已有正常连接且 DSN
// 未变化时不打断现有连接（PUT /api/v1/apm/settings 仅切换总开关时调用）。
func (m *CHManager) RetryDisconnected(ctx context.Context) (CHQuerier, *CHHealth) {
	return m.resolve(ctx, true, false)
}

func (m *CHManager) resolve(ctx context.Context, bypassCooldown, forceRebuild bool) (CHQuerier, *CHHealth) {
	dsn := m.cfg.ClickHouseDSN(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.resolved && dsn == m.dsn {
		if dsn == "" {
			return nil, nil
		}
		if m.querier != nil && !forceRebuild {
			return m.querier, m.health
		}
		if m.querier == nil && !bypassCooldown && m.retryInterval > 0 && !m.lastFailAt.IsZero() &&
			m.currentTime().Sub(m.lastFailAt) < m.retryInterval {
			return nil, nil
		}
	}
	// DSN 变化、强制重建或冷却后重连：先回收旧连接再按目标 DSN 重建
	if closer, ok := m.querier.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			slog.Warn("APM ClickHouse 旧连接关闭失败", "error", err)
		}
	}
	m.resolved = true
	m.dsn = dsn
	m.querier, m.health = nil, nil
	m.lastFailAt = time.Time{}
	if dsn == "" {
		return nil, nil
	}
	q, err := m.dial(dsn)
	if err != nil {
		m.lastFailAt = m.currentTime()
		slog.Warn("APM ClickHouse 数据面连接失败，OTel 检索降级为 agentless 空数据（冷却后自动重试）",
			"error", err, "retry_after", m.retryInterval.String())
		return nil, nil
	}
	m.querier = q
	m.health = NewCHHealth(q)
	slog.Info("APM ClickHouse 数据面已接入")
	return m.querier, m.health
}

// ResolveQuerier 适配 apm.NewStore 的运行期查询器解析函数。
func (m *CHManager) ResolveQuerier(ctx context.Context) CHQuerier {
	q, _ := m.Resolve(ctx)
	return q
}

// Connected 当前数据面是否可用（GET /api/v1/apm/settings 的 ch_connected 字段用）。
func (m *CHManager) Connected(ctx context.Context) bool {
	q, _ := m.Resolve(ctx)
	return q != nil
}

// CHProberAdapter runtimehealth.ClickHouseProber 的运行期适配（ duck-type 不反向依赖）：
// 探测时逐次解析当前连接；无可用连接时 Available=false——组件不采集不判级，
// 与原"未注入探针"形态等价（DSN 被清空/连接失败后组件自动退出判级，默认部署
// 零行为变化）。
type CHProberAdapter struct{ m *CHManager }

// NewCHProberAdapter 创建组件探针适配器。
func NewCHProberAdapter(m *CHManager) *CHProberAdapter { return &CHProberAdapter{m: m} }

// Available 本轮是否有可用数据面连接（runtimehealth 采集器据此决定是否纳入判级；
// 首次调用触发惰性建连）。
func (a *CHProberAdapter) Available() bool {
	_, h := a.m.Resolve(context.Background())
	return h != nil
}

// Ping 数据面连通性轻探测（无连接时返回错误——正常路径被 Available 门控不会走到）。
func (a *CHProberAdapter) Ping(ctx context.Context) error {
	_, h := a.m.Resolve(ctx)
	if h == nil {
		return errors.New("ClickHouse 数据面未接入")
	}
	return h.Ping(ctx)
}

// TracesTableExists 核心表存在性检查（无连接口径同 Ping）。
func (a *CHProberAdapter) TracesTableExists(ctx context.Context) (bool, error) {
	_, h := a.m.Resolve(ctx)
	if h == nil {
		return false, errors.New("ClickHouse 数据面未接入")
	}
	return h.TracesTableExists(ctx)
}

// IngestLagSource systemalerts.IngestLagStatsStore 的运行期适配：无可用连接时
// ok=false（EvaluateIngestLag 自然空转/恢复既有告警，与原"未注入读数源"等价）。
type IngestLagSource struct{ m *CHManager }

// NewIngestLagSource 创建采集滞后读数适配器。
func NewIngestLagSource(m *CHManager) *IngestLagSource { return &IngestLagSource{m: m} }

// LatestIngestAt 数据面最新遥测时间（无连接时 ok=false，非故障）。
func (s *IngestLagSource) LatestIngestAt(ctx context.Context) (time.Time, bool, error) {
	_, h := s.m.Resolve(ctx)
	if h == nil {
		return time.Time{}, false, nil
	}
	return h.LatestIngestAt(ctx)
}
