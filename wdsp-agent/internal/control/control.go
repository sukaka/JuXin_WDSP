// Package control 控制通道循环：心跳（含 metrics）、配置拉取与 ACK、启用/禁用。
//
// 对应契约 §3.2/§3.3 与 §6：注册→心跳循环（默认 15s，按服务端返回值调整；
// config_version 大于本地已应用版本时拉取配置并 ACK APPLIED/FAILED；
// desired_state=DISABLED 停抓保心跳）；断线指数退避重连（1s→60s）。
package control

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

// Deps 控制循环依赖（由 agent 编排层注入）。
type Deps struct {
	Client *transport.Client
	Log    *slog.Logger

	AgentID          string
	InitialInterval  int                      // 秒，<=0 用 15
	StatusFn         func() string            // ONLINE | DEGRADED | ERROR
	MetricsFn        func() transport.Metrics // metrics 快照
	AppliedVersionFn func() int64             // 本地已应用配置版本
	// ApplyConfigFn 应用并持久化配置（overrides 为 Phase 4 定向采集规则，
	// 缺省/解析失败按空数组）。
	ApplyConfigFn  func(policy *config.Policy, overrides []config.Override, version int64) error
	SetEnabledFn   func(enabled bool)        // desired_state 处置（DISABLED 停抓保心跳）
	OnConnectionFn func(connected bool)      // 断线/恢复（恢复后触发补传）
	CheckRotateFn  func(ctx context.Context) // 证书轮换检查（契约 §9；nil=无证书 Bearer 模式）
	// OnCapabilitiesFn 心跳回执的能力生效集回调（v2 契约 §3；nil 回执=旧服务端，
	// 按仅 v1 处理）。每次心跳成功后调用。
	OnCapabilitiesFn func(effective *transport.Capabilities)
}

// Loop 控制通道循环。
type Loop struct {
	d        Deps
	interval atomic.Int64 // 秒
}

// New 创建控制循环。
func New(d Deps) *Loop {
	l := &Loop{d: d}
	init := d.InitialInterval
	if init <= 0 {
		init = 15
	}
	l.interval.Store(int64(init))
	return l
}

// Run 阻塞运行直到 ctx 取消。启动即发第一次心跳。
func (l *Loop) Run(ctx context.Context) {
	log := l.d.Log
	backoff := transport.NewBackoff(0, 0)
	connected := false
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		hbCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		resp, err := l.d.Client.Heartbeat(hbCtx, l.d.AgentID, transport.HeartbeatRequest{
			Timestamp:    time.Now().Unix(),
			Status:       l.d.StatusFn(),
			Metrics:      l.d.MetricsFn(),
			Capabilities: transport.DeclaredCapabilities(), // v2 契约 §3 能力声明
		})
		cancel()
		if err != nil {
			if transport.IsUnauthorized(err) {
				log.Error("心跳 401：credential 失效（需重新 enroll）", "err", err)
			} else {
				log.Warn("心跳失败，退避重连", "err", err)
			}
			if connected {
				connected = false
				if l.d.OnConnectionFn != nil {
					l.d.OnConnectionFn(false)
				}
			}
			timer.Reset(backoff.Next())
			continue
		}
		backoff.Reset()
		if !connected {
			connected = true
			log.Info("控制通道已连接", "agent_id", l.d.AgentID)
			if l.d.OnConnectionFn != nil {
				l.d.OnConnectionFn(true)
			}
		}
		// v2 契约 §3：应用服务端回执的能力生效集（nil=旧服务端 → 仅 v1）
		if l.d.OnCapabilitiesFn != nil {
			l.d.OnCapabilitiesFn(resp.Capabilities)
		}
		// 心跳间隔以服务端返回值为准（契约 §6）
		if resp.HeartbeatIntervalSeconds > 0 &&
			int64(resp.HeartbeatIntervalSeconds) != l.interval.Load() {
			l.interval.Store(int64(resp.HeartbeatIntervalSeconds))
			log.Info("心跳间隔调整", "interval_s", resp.HeartbeatIntervalSeconds)
		}
		// desired_state 处置
		if l.d.SetEnabledFn != nil {
			l.d.SetEnabledFn(resp.DesiredState != "DISABLED")
		}
		// 配置版本推进 → 拉取并应用
		if resp.ConfigVersion > l.d.AppliedVersionFn() {
			l.pullAndApply(ctx, resp.ConfigVersion)
		}
		// 证书轮换检查（契约 §9：存活期过半自动轮换，内部自判时机与退避）
		if l.d.CheckRotateFn != nil {
			l.d.CheckRotateFn(ctx)
		}
		timer.Reset(time.Duration(l.interval.Load()) * time.Second)
	}
}

// pullAndApply 拉取配置 → 应用 → ACK（契约 §3.3）。
func (l *Loop) pullAndApply(ctx context.Context, version int64) {
	log := l.d.Log
	cfgCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	resp, err := l.d.Client.GetConfig(cfgCtx, l.d.AgentID)
	cancel()
	if err != nil {
		log.Warn("配置拉取失败，下个心跳周期重试", "version", version, "err", err)
		return
	}
	var policy *config.Policy
	if resp.Policy != nil && len(*resp.Policy) > 0 && string(*resp.Policy) != "null" {
		var p config.Policy
		if err := json.Unmarshal(*resp.Policy, &p); err != nil {
			l.ack(ctx, resp.Version, "FAILED", "策略 JSON 解析失败: "+err.Error())
			return
		}
		policy = &p
	}
	// Phase 4 契约 §2.4：overrides 顶层字段（旧服务端无此字段按空数组）；
	// 解析失败不阻断配置应用（Warn + 空数组，契约红线：不阻断采集）。
	var overrides []config.Override
	if len(resp.Overrides) > 0 && string(resp.Overrides) != "null" {
		if err := json.Unmarshal(resp.Overrides, &overrides); err != nil {
			log.Warn("overrides 解析失败，按空数组处理", "err", err)
			overrides = nil
		}
	}
	applyErr := l.d.ApplyConfigFn(policy, overrides, resp.Version)
	if applyErr != nil {
		log.Error("配置应用失败", "version", resp.Version, "err", applyErr)
		l.ack(ctx, resp.Version, "FAILED", applyErr.Error())
		return
	}
	if policy == nil {
		log.Info("配置已应用（无绑定策略，使用内置默认采集集）", "version", resp.Version)
	} else {
		log.Info("配置已应用", "version", resp.Version, "policy", policy.Name)
	}
	l.ack(ctx, resp.Version, "APPLIED", "")
}

// ack 配置 ACK（失败仅记日志，下个周期由版本差再次触发）。
func (l *Loop) ack(ctx context.Context, version int64, status, errMsg string) {
	ackCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err := l.d.Client.AckConfig(ackCtx, l.d.AgentID, transport.AckRequest{
		Version: version, Status: status, Error: errMsg,
	})
	cancel()
	if err != nil {
		l.d.Log.Warn("配置 ACK 失败", "version", version, "status", status, "err", err)
	}
}
