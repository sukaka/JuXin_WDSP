// Nginx mirror 来源装配与发送路径（P1-03 §3.2，G2）。
//
// 镜像记录为 v2 单向源（source_type=NGINX_MIRROR）：仅经 v2 线格式上行，
// 服务端未协商 v2 时不降级为 v1（v1 无来源字段，降级会把镜像记录误标为
// PASSIVE_HTTP1）——丢弃并计数（dropped_by_reason=mirror_v2_not_negotiated，
// 非静默）。磁盘缓存使用独立类型标签 'M' 保留完整 v2 字段（不用 'H' 通道的
// v1 反序列化，避免静默丢失 v2 增量）。
package agent

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/mirrorsrc"
	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

// DropReasonMirrorV2NotNegotiated 服务端生效集不含 v2：镜像记录无法如实标注来源，
// 丢弃计数（可查询），不降级误标（dropped_by_reason 词表增量，G2）。
const DropReasonMirrorV2NotNegotiated = "mirror_v2_not_negotiated"

// mirrorReceiverConfig 本地配置 → 接收器配置（校验在 mirrorsrc.New 内完成）。
func mirrorReceiverConfig(mc config.MirrorConfig) mirrorsrc.Config {
	return mirrorsrc.Config{
		SocketPath:     mc.SocketPath,
		ListenAddr:     mc.ListenAddr,
		SocketMode:     os.FileMode(mc.SocketMode),
		SocketGroup:    mc.SocketGroup,
		SourceInstance: mc.SourceInstance,
		InstanceToken:  mc.InstanceToken,
		TLSTerminated:  mc.TLSTerminated,
		BodyEnabled:    mc.BodyEnabled,
		MaxBodyBytes:   mc.MaxBodyBytes,
		MaxConns:       mc.MaxConns,
	}
}

// onMirrorRecord 镜像 v2 记录出口（mirrorsrc 回调）：入内存队列（与 HTTP 记录
// 共享 64MB 字节硬上限）；满则写磁盘缓存（'M' 标签保留完整 v2 字段）。
// 记录已在 mirrorsrc 内经 httpsensor 同一脱敏出口完成脱敏。
func (a *Agent) onMirrorRecord(rec events.HTTPRecordV2) {
	est := estV2RecordBytes(rec)
	if !reserveQBytes(&a.httpQBytes, est, queueMaxBytes) {
		a.bufferMirror([]events.HTTPRecordV2{rec})
		return
	}
	select {
	case a.httpQ <- httpQItem{est: est, v2rec: &rec}:
	default:
		a.httpQBytes.Add(-est) // 入队失败回滚预留额度
		a.bufferMirror([]events.HTTPRecordV2{rec})
	}
}

// estV2RecordBytes v2 记录序列化字节估算（镜像源低频，直接序列化计量）。
func estV2RecordBytes(rec events.HTTPRecordV2) int64 {
	data, err := json.Marshal(rec)
	if err != nil {
		return 1024
	}
	return int64(len(data) + 64)
}

// bufferMirror 镜像 v2 记录写磁盘缓存（'M' 标签；缓存不可用则丢弃计数）。
func (a *Agent) bufferMirror(recs []events.HTTPRecordV2) {
	for _, rec := range recs {
		data, err := json.Marshal(rec)
		if err != nil {
			a.metrics.Dropped.Add(1)
			a.metrics.DropReason(events.DropUnserializable, 1)
			continue
		}
		if err := a.buf.Write(append([]byte{bufTagMirror}, data...)); err != nil {
			a.metrics.BufferFailed.Add(1)
			a.metrics.Dropped.Add(1)
			a.metrics.DropReason(DropReasonSpoolWriteFailed, 1)
			continue
		}
		a.metrics.HTTPBuffered.Add(1)
	}
}

// sendMirrorBatch 镜像 v2 批外发（实时路径；错误分类同 sendHTTPBatch，
// 但绝不降级 v1 线格式）：
//   - 未协商 v2 → 丢弃计数（mirror_v2_not_negotiated，WARN 一次）；
//   - 429 窗口内 / 限速桶满 / 5xx / 网络错误 → 转磁盘缓存；
//   - 永久非法：有 invalid_records 按索引隔离丢弃（其余重发一次）；
//     无索引定位 → 整批丢弃计数（适配器侧已全量自检，包络级 400 属异常）；
//   - 404（旧服务端无端点）→ 与主通道同处置：标记 httpGone 并丢弃计数。
func (a *Agent) sendMirrorBatch(recs []events.HTTPRecordV2) {
	if len(recs) == 0 {
		return
	}
	if a.httpGone.Load() {
		a.metrics.Dropped.Add(uint64(len(recs)))
		a.metrics.DropReason(DropReasonHTTPEndpointGone, uint64(len(recs)))
		return
	}
	if !a.httpV2.Load() {
		a.metrics.Dropped.Add(uint64(len(recs)))
		a.metrics.DropReason(DropReasonMirrorV2NotNegotiated, uint64(len(recs)))
		a.log.Warn("服务端未协商 HTTP 事件 schema v2，镜像记录丢弃计数（不降级 v1 误标来源）",
			"records", len(recs))
		return
	}
	if a.httpRetryWait() > 0 {
		a.bufferMirror(recs) // 429 退避窗口内：转缓存等待
		return
	}
	data, err := json.Marshal(events.HTTPRequestV2{SchemaVersion: events.HTTPRecordSchemaVersion, Records: recs})
	if err != nil {
		a.metrics.Dropped.Add(uint64(len(recs)))
		a.metrics.DropReason(events.DropUnserializable, uint64(len(recs)))
		return
	}
	if len(data) > events.MaxHTTPBatchBytes && len(recs) > 1 {
		// 防御性拆分（镜像记录本身有界，正常不可达）
		mid := len(recs) / 2
		a.sendMirrorBatch(recs[:mid])
		a.sendMirrorBatch(recs[mid:])
		return
	}
	if !a.bucket.Allow(len(data)) {
		a.bufferMirror(recs) // 桶满：转磁盘缓存
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	accepted, duplicate, invalid, err := a.client.PostHTTPV2(ctx, a.cfg.AgentID, recs)
	cancel()
	if err != nil {
		a.handleMirrorSendError(recs, invalid, err)
		return
	}
	a.metrics.Forwarded.Add(uint64(len(recs)))
	a.metrics.Accepted.Add(uint64(accepted))
	if duplicate > 0 {
		a.metrics.Duplicate.Add(uint64(duplicate))
	}
	a.metrics.ForwardBytes.Add(uint64(len(data)))
}

// handleMirrorSendError 镜像批发送失败分类处置（无 v1 降级路径）。
func (a *Agent) handleMirrorSendError(recs []events.HTTPRecordV2, invalid []events.InvalidRecord, err error) {
	switch {
	case transport.IsNotFound(err):
		a.httpGone.Store(true)
		a.log.Warn("服务端无 /http 端点（旧版本），镜像记录丢弃计数", "records", len(recs))
		a.metrics.Dropped.Add(uint64(len(recs)))
		a.metrics.DropReason(DropReasonHTTPEndpointGone, uint64(len(recs)))
	case transport.IsPermanent(err) && len(invalid) > 0:
		a.isolateMirrorByIndex(recs, invalid)
	case transport.IsPermanent(err):
		a.log.Warn("镜像批次被服务端永久拒绝且无非法记录定位，整批丢弃计数", "records", len(recs), "err", err)
		a.metrics.Dropped.Add(uint64(len(recs)))
		a.metrics.DropReason(DropReasonPermanentInvalid, uint64(len(recs)))
	case transport.IsTooManyRequests(err):
		d := transport.RetryAfterOf(err)
		a.setHTTPRetryAfter(d)
		a.log.Warn("镜像上报被限速（429），尊重 Retry-After 退避", "records", len(recs), "retry_after", d)
		a.bufferMirror(recs)
	default:
		a.log.Warn("镜像上报失败，转磁盘缓存", "records", len(recs), "err", err)
		a.bufferMirror(recs)
	}
}

// isolateMirrorByIndex 按 v2 invalid_records 索引隔离非法镜像记录（丢弃计数），
// 剩余记录重发一次；索引不可定位按批次级拒绝整批丢弃（不无限重试）。
func (a *Agent) isolateMirrorByIndex(recs []events.HTTPRecordV2, invalid []events.InvalidRecord) {
	bad := make(map[int]string, len(invalid))
	for _, iv := range invalid {
		if iv.Index < 0 || iv.Index >= len(recs) {
			a.log.Warn("镜像批 v2 非法记录索引不可定位，整批丢弃计数", "index", iv.Index, "reason", iv.Reason)
			a.metrics.Dropped.Add(uint64(len(recs)))
			a.metrics.DropReason(DropReasonPermanentInvalid, uint64(len(recs)))
			return
		}
		bad[iv.Index] = iv.Reason
	}
	keep := make([]events.HTTPRecordV2, 0, len(recs)-len(bad))
	for i, rec := range recs {
		if reason, drop := bad[i]; drop {
			a.log.Warn("镜像记录被服务端判定永久非法，按索引隔离丢弃",
				"event_id", rec.EventID, "reason", reason)
			a.metrics.Dropped.Add(1)
			a.metrics.DropReason(DropReasonPermanentInvalid, 1)
			continue
		}
		keep = append(keep, rec)
	}
	if len(keep) > 0 {
		a.sendMirrorBatch(keep)
	}
}

// replayMirrorBatch 补传一批镜像 v2 记录（'M' 标签缓存）。返回 nil 本批了结；
// 返回错误保留该段下轮重试。未协商 v2 → 丢弃计数（服务端升级前补传无意义，
// 且不得阻塞同段其他记录补传）；429 → errReplayBackoff；5xx/网络 → 保留重试。
func (a *Agent) replayMirrorBatch(recs []events.HTTPRecordV2) error {
	if len(recs) == 0 {
		return nil
	}
	if a.httpGone.Load() {
		a.metrics.Dropped.Add(uint64(len(recs)))
		a.metrics.DropReason(DropReasonHTTPEndpointGone, uint64(len(recs)))
		return nil
	}
	if !a.httpV2.Load() {
		a.metrics.Dropped.Add(uint64(len(recs)))
		a.metrics.DropReason(DropReasonMirrorV2NotNegotiated, uint64(len(recs)))
		a.log.Warn("补传镜像记录时服务端未协商 v2，丢弃计数（不降级 v1 误标来源）", "records", len(recs))
		return nil
	}
	if a.httpRetryWait() > 0 {
		return errReplayBackoff
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	accepted, duplicate, invalid, err := a.client.PostHTTPV2(ctx, a.cfg.AgentID, recs)
	cancel()
	if err != nil {
		switch {
		case transport.IsNotFound(err):
			a.httpGone.Store(true)
			a.metrics.Dropped.Add(uint64(len(recs)))
			a.metrics.DropReason(DropReasonHTTPEndpointGone, uint64(len(recs)))
			return nil
		case transport.IsPermanent(err) && len(invalid) > 0:
			a.isolateMirrorByIndex(recs, invalid)
			return nil
		case transport.IsPermanent(err):
			a.metrics.Dropped.Add(uint64(len(recs)))
			a.metrics.DropReason(DropReasonPermanentInvalid, uint64(len(recs)))
			return nil
		case transport.IsTooManyRequests(err):
			a.setHTTPRetryAfter(transport.RetryAfterOf(err))
			return errReplayBackoff
		default:
			return err
		}
	}
	a.metrics.Forwarded.Add(uint64(len(recs)))
	a.metrics.Accepted.Add(uint64(accepted))
	if duplicate > 0 {
		a.metrics.Duplicate.Add(uint64(duplicate))
	}
	return nil
}

// startMirror 启动镜像接收器（默认关闭；启动失败 Fail-Open，仅记录日志）。
func (a *Agent) startMirror() {
	if a.mirror == nil {
		return
	}
	if err := a.mirror.Start(); err != nil {
		a.log.Error("mirrorsrc 镜像接收器启动失败（Fail-Open，其余采集不受影响）", "err", err)
		return
	}
	a.log.Info("mirrorsrc 镜像接收器已启用",
		"source_instance", a.cfg.Mirror.SourceInstance,
		"note", "镜像记录仅经 v2 线格式上行，服务端未协商 v2 时丢弃计数")
}

// stopMirror 停止镜像接收器（优雅停机有界）。
func (a *Agent) stopMirror() {
	if a.mirror == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	a.mirror.Shutdown(ctx)
	cancel()
}

// newMirrorReceiver 按本地配置创建接收器（未启用/配置非法返回 nil + 日志）。
func (a *Agent) newMirrorReceiver() *mirrorsrc.Receiver {
	if !a.cfg.Mirror.Enabled {
		return nil
	}
	r, err := mirrorsrc.New(a.cfg.AgentID, mirrorReceiverConfig(a.cfg.Mirror), a.onMirrorRecord, a.log)
	if err != nil {
		a.log.Error("mirrorsrc 配置非法，镜像接收器未启用（Fail-Open）", "err", err)
		return nil
	}
	policy := a.cfg.EffectivePolicy()
	r.UpdatePolicy(policy.EffectiveCaptureLevel(),
		policy.Limits.EffectiveMaxBodySize(), policy.Masking.Effective())
	return r
}
