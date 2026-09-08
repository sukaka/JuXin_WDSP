// Envoy tap 来源装配与发送路径（P1-03 §3.3，G3）。
//
// tap 记录为 v2 来源（source_type=ENVOY_TAP）：仅经 v2 线格式上行，服务端
// 未协商 v2 时丢弃计数（dropped_by_reason=tap_v2_not_negotiated，非静默、
// 不降级 v1 误标来源）。队列/缓存/发送复用 G2 的 v2 共用通道（'M' 标签、
// sendV2Batch/replayV2Batch）。适配器故障 Fail-Open：只出向读取本机回环
// Envoy Admin，不监听端口、不影响业务转发。
package agent

import (
	"context"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/tapsrc"
)

// tapSourceConfig 本地配置 → 适配器配置（校验在 tapsrc.New 内完成）。
func tapSourceConfig(tc config.TapConfig) tapsrc.Config {
	return tapsrc.Config{
		AdminAddr:           tc.AdminAddr,
		SourceInstance:      tc.SourceInstance,
		ConfigID:            tc.ConfigID,
		ObservedHTTPVersion: tc.ObservedHTTPVersion,
		TLSTerminated:       tc.TLSTerminated,
		BodyEnabled:         tc.BodyEnabled,
		MaxBodyBytes:        tc.MaxBodyBytes,
		MaxMessageBytes:     tc.MaxMessageBytes,
		ReconnectMin:        time.Duration(tc.ReconnectMinMs) * time.Millisecond,
		ReconnectMax:        time.Duration(tc.ReconnectMaxMs) * time.Millisecond,
	}
}

// onTapRecord tap v2 记录出口（tapsrc 回调）：与镜像记录共用 v2 内存队列/
// 磁盘缓存通道。记录已在 tapsrc 内经 httpsensor 同一脱敏出口完成脱敏。
func (a *Agent) onTapRecord(rec events.HTTPRecordV2) {
	a.onMirrorRecord(rec)
}

// startTap 启动 tap 适配器（默认关闭；启动失败 Fail-Open，仅记录日志）。
func (a *Agent) startTap() {
	if a.tap == nil {
		return
	}
	go func() {
		defer a.recover("tapsrc")
		a.tap.Run(context.Background())
	}()
	a.log.Info("tapsrc Envoy tap 适配器已启用",
		"source_instance", a.cfg.Tap.SourceInstance, "config_id", a.cfg.Tap.ConfigID,
		"note", "tap 记录仅经 v2 线格式上行，服务端未协商 v2 时丢弃计数")
}

// stopTap 停止 tap 适配器（优雅停机有界）。
func (a *Agent) stopTap() {
	if a.tap == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	a.tap.Shutdown(ctx)
	cancel()
}

// newTapSource 按本地配置创建 tap 适配器（未启用/配置非法返回 nil + 日志）。
func (a *Agent) newTapSource() *tapsrc.Source {
	if !a.cfg.Tap.Enabled {
		return nil
	}
	s, err := tapsrc.New(a.cfg.AgentID, tapSourceConfig(a.cfg.Tap), a.onTapRecord, a.log)
	if err != nil {
		a.log.Error("tapsrc 配置非法，tap 适配器未启用（Fail-Open）", "err", err)
		return nil
	}
	policy := a.cfg.EffectivePolicy()
	s.UpdatePolicy(policy.EffectiveCaptureLevel(),
		policy.Limits.EffectiveMaxBodySize(), policy.Masking.Effective())
	return s
}
