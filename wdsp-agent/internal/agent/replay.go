package agent

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/apievent"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

// 补传限速等待参数（契约 §6 限速约束；测试可缩短）。
var (
	replayWaitAttempts = 50
	replayWaitInterval = 100 * time.Millisecond
)

// errReplayThrottled 补传批次在限速等待窗口内未获令牌：整批保留在缓存，下轮重试。
var errReplayThrottled = errors.New("限速桶持续饱和，暂停本轮补传")

// errReplayBackoff 429 Retry-After 退避窗口内：整批保留在缓存，窗口过后重试。
var errReplayBackoff = errors.New("429 Retry-After 退避中，暂停本轮补传")

// replayBuffer 补传磁盘缓存（at-least-once；独立公平预算限速下逐批外发）。
// 缓存记录带类型标签（Phase 3 起）：F=flow 事件，H=HTTP 记录；无标签的旧版
// 缓存按 flow 事件解析。HTTP 记录按契约 §3 上限（≤100 条/≤8MB）重新分批；
// 补传中遇 /http 404 → 降级 L0 并丢弃该批 HTTP 记录（不进入补传死循环）；
// 遇 400/413/422 永久非法 → 二分隔离丢弃非法记录（其余照常补传）；
// 遇 429 → 尊重 Retry-After 暂停本轮。
func (a *Agent) replayBuffer() {
	_, err := a.buf.Replay(events.MaxEventsPerBatch, func(recs [][]byte) error {
		evs := make([]events.FlowEvent, 0, len(recs))
		var https []events.HTTPRecord
		var mirrors []events.HTTPRecordV2
		var observations []apievent.Record
		for _, r := range recs {
			switch {
			case len(r) > 1 && r[0] == bufTagAPIObservation:
				var rec apievent.Record
				if err := json.Unmarshal(r[1:], &rec); err == nil {
					observations = append(observations, rec)
				}
			case len(r) > 1 && r[0] == bufTagMirror:
				var rec events.HTTPRecordV2
				if err := json.Unmarshal(r[1:], &rec); err == nil {
					mirrors = append(mirrors, rec)
				}
			case len(r) > 1 && r[0] == bufTagHTTP:
				var rec events.HTTPRecord
				if err := json.Unmarshal(r[1:], &rec); err == nil {
					https = append(https, rec)
				}
			case len(r) > 1 && r[0] == bufTagFlow:
				var ev events.FlowEvent
				if err := json.Unmarshal(r[1:], &ev); err == nil {
					evs = append(evs, ev)
				}
			default: // 旧版无标签缓存（Phase 1/2）
				var ev events.FlowEvent
				if err := json.Unmarshal(r, &ev); err == nil {
					evs = append(evs, ev)
				}
			}
		}
		if len(evs) == 0 && len(https) == 0 && len(mirrors) == 0 && len(observations) == 0 {
			return nil
		}
		if len(evs) > 0 {
			if err := a.replayFlowRecords(evs); err != nil {
				return err
			}
		}
		// HTTP 记录按契约上限重新分批
		batcher := events.NewHTTPBatcher(func(reason string) {
			a.metrics.DropReason(reason, 1)
			a.metrics.Dropped.Add(1)
		})
		for _, rec := range https {
			if !batcher.Add(rec) {
				if err := a.replayHTTPRecords(batcher.Flush()); err != nil {
					return err
				}
				batcher.Add(rec) //nolint:errcheck // 新批次首条必成功（超限已在 Add 内缩减/丢弃）
			}
		}
		if err := a.replayHTTPRecords(batcher.Flush()); err != nil {
			return err
		}
		// 镜像 v2 记录按 ≤100 条重新分批补传（不降级 v1，避免来源误标）
		for len(mirrors) > 0 {
			n := len(mirrors)
			if n > events.MaxHTTPRecordsPerBatch {
				n = events.MaxHTTPRecordsPerBatch
			}
			if err := a.replayV2Records(mirrors[:n]); err != nil {
				return err
			}
			mirrors = mirrors[n:]
		}
		if err := a.replayAPIObservations(observations); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		a.log.Warn("缓存补传中断", "err", err)
	}
}

// replayAllow 按一次实际网络请求体获取补传预算。超过 burst 的单元直接暂停，
// 避免在固定等待窗口内反复请求一个永远不可能被令牌桶接纳的大小。
func (a *Agent) replayAllow(size int) bool {
	bucket := a.replayBucket
	if bucket == nil {
		bucket = a.bucket
	}
	if burst := bucket.Burst(); burst > 0 && size > burst {
		return false
	}
	for i := 0; i < replayWaitAttempts; i++ {
		if bucket.Allow(size) {
			return true
		}
		time.Sleep(replayWaitInterval)
	}
	return false
}

func (a *Agent) replayFlowRecords(evs []events.FlowEvent) error {
	var batch []events.FlowEvent
	for _, ev := range evs {
		candidate := append(batch, ev)
		data, err := json.Marshal(events.FlowsRequest{Events: candidate})
		if err != nil {
			return err
		}
		if len(batch) > 0 {
			if burst := a.replayBurst(); burst > 0 && len(data) > burst {
				if err := a.replayFlowUnit(batch); err != nil {
					return err
				}
				batch = batch[:0]
				candidate = append(batch, ev)
				data, err = json.Marshal(events.FlowsRequest{Events: candidate})
				if err != nil {
					return err
				}
			}
		}
		if burst := a.replayBurst(); burst > 0 && len(data) > burst {
			return errReplayThrottled
		}
		batch = append(batch, ev)
	}
	return a.replayFlowUnit(batch)
}

func (a *Agent) replayFlowUnit(evs []events.FlowEvent) error {
	if len(evs) == 0 {
		return nil
	}
	data, err := json.Marshal(events.FlowsRequest{Events: evs})
	if err != nil {
		return err
	}
	if !a.replayAllow(len(data)) {
		return errReplayThrottled
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	accepted, err := a.client.PostFlows(ctx, a.cfg.AgentID, evs)
	cancel()
	if err != nil {
		if transport.IsPermanent(err) {
			if len(evs) == 1 {
				if a.log != nil {
					a.log.Warn("补传 flow 记录被服务端判定永久非法，隔离丢弃",
						"flow_id", evs[0].FlowID, "err", err)
				}
				a.metrics.Dropped.Add(1)
				a.metrics.DropReason(DropReasonPermanentInvalid, 1)
				return nil
			}
			mid := len(evs) / 2
			if err := a.replayFlowUnit(evs[:mid]); err != nil {
				return err
			}
			return a.replayFlowUnit(evs[mid:])
		}
		return err
	}
	a.metrics.Forwarded.Add(uint64(len(evs)))
	a.metrics.Accepted.Add(uint64(accepted))
	a.metrics.ForwardBytes.Add(uint64(len(data)))
	return nil
}

func (a *Agent) replayBurst() int {
	bucket := a.replayBucket
	if bucket == nil {
		bucket = a.bucket
	}
	return bucket.Burst()
}

func (a *Agent) replayHTTPRecords(recs []events.HTTPRecord) error {
	for len(recs) > 0 {
		n := len(recs)
		for n > 1 {
			size, err := a.replayHTTPPayloadSize(recs[:n])
			if err != nil {
				return err
			}
			if burst := a.replayBurst(); burst <= 0 || size <= burst {
				break
			}
			n /= 2
		}
		if err := a.replayHTTPBatch(recs[:n]); err != nil {
			return err
		}
		recs = recs[n:]
	}
	return nil
}

func (a *Agent) replayHTTPPayloadSize(recs []events.HTTPRecord) (int, error) {
	if a.httpV2.Load() {
		return marshalSize(events.NewHTTPBatchV2(a.cfg.AgentID, recs, a.sourceRef()))
	}
	return marshalSize(events.HTTPRequest{Records: recs})
}

func (a *Agent) replayV2Records(recs []events.HTTPRecordV2) error {
	for len(recs) > 0 {
		n := len(recs)
		for n > 1 {
			size, err := marshalSize(events.HTTPRequestV2{SchemaVersion: events.HTTPRecordSchemaVersion, Records: recs[:n]})
			if err != nil {
				return err
			}
			if burst := a.replayBurst(); burst <= 0 || size <= burst {
				break
			}
			n /= 2
		}
		if err := a.replayMirrorBatch(recs[:n]); err != nil {
			return err
		}
		recs = recs[n:]
	}
	return nil
}

func marshalSize(v any) (int, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

// replayHTTPBatch 补传一批 HTTP 记录。返回 nil 表示本批已了结（全部接受，
// 或永久非法记录已隔离丢弃）可删段；返回错误保留该段下轮重试。
// 404 → 降级并丢弃（返回 nil）；429 → 设置 Retry-After 退避并暂停本轮；
// 400/413/422 → v2 按 invalid_records 索引隔离丢弃（其余照常补传），v1 二分隔离；
// v2 无索引定位的 400 → 降级 v1 重发本批（event_id 由记录内容派生，重放不变）。
func (a *Agent) replayHTTPBatch(recs []events.HTTPRecord) error {
	if len(recs) == 0 {
		return nil
	}
	if a.httpGone.Load() {
		a.metrics.Dropped.Add(uint64(len(recs)))
		a.metrics.DropReason(DropReasonHTTPEndpointGone, uint64(len(recs)))
		return nil
	}
	if a.httpRetryWait() > 0 {
		return errReplayBackoff // 429 退避窗口内暂停补传（本批保留）
	}
	data, err := a.replayHTTPPayload(recs)
	if err != nil {
		return err
	}
	if !a.replayAllow(len(data)) {
		return errReplayThrottled
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	accepted, duplicate, invalid, err := a.postHTTP(ctx, recs, a.httpV2.Load())
	cancel()
	if err != nil {
		switch {
		case transport.IsNotFound(err):
			a.httpGone.Store(true)
			a.log.Warn("补传遇 /http 404：服务端为旧版本，HTTP 采集降级为 L0 行为", "records", len(recs))
			a.metrics.Dropped.Add(uint64(len(recs)))
			a.metrics.DropReason(DropReasonHTTPEndpointGone, uint64(len(recs)))
			a.applyPolicy(a.currentPolicy())
			return nil
		case transport.IsPermanent(err) && len(invalid) > 0:
			return a.replayIsolateByIndex(recs, invalid)
		case transport.IsPermanent(err) && a.httpV2.Swap(false):
			// v2 补传 400 无索引定位（未协商/包络级拒绝）→ 降级 v1 重发本批一次
			a.log.Warn("v2 补传被服务端永久拒绝且无非法记录定位，降级 v1 重发", "records", len(recs), "err", err)
			return a.replayHTTPBatch(recs)
		case transport.IsPermanent(err):
			if len(recs) == 1 {
				a.log.Warn("补传记录被服务端判定永久非法，隔离丢弃",
					"flow_id", recs[0].FlowID, "err", err)
				a.metrics.Dropped.Add(1)
				a.metrics.DropReason(DropReasonPermanentInvalid, 1)
				return nil
			}
			mid := len(recs) / 2
			if err := a.replayHTTPBatch(recs[:mid]); err != nil {
				return err
			}
			return a.replayHTTPBatch(recs[mid:])
		case transport.IsTooManyRequests(err):
			d := transport.RetryAfterOf(err)
			a.setHTTPRetryAfter(d)
			a.log.Warn("补传被限速（429），尊重 Retry-After 暂停本轮", "records", len(recs), "retry_after", d)
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
	a.metrics.ForwardBytes.Add(uint64(len(data)))
	return nil
}

func (a *Agent) replayHTTPPayload(recs []events.HTTPRecord) ([]byte, error) {
	if a.httpV2.Load() {
		return json.Marshal(events.NewHTTPBatchV2(a.cfg.AgentID, recs, a.sourceRef()))
	}
	return json.Marshal(events.HTTPRequest{Records: recs})
}

// replayIsolateByIndex 补传批次按 v2 invalid_records 索引隔离（v2 契约 §4.4）：
// 非法记录丢弃计数后剩余继续补传；索引不可定位（批次级/越界）时回退二分隔离。
func (a *Agent) replayIsolateByIndex(recs []events.HTTPRecord, invalid []events.InvalidRecord) error {
	bad := make(map[int]string, len(invalid))
	for _, iv := range invalid {
		if iv.Index < 0 || iv.Index >= len(recs) {
			a.log.Warn("补传 v2 非法记录索引不可定位，回退二分隔离", "index", iv.Index, "reason", iv.Reason)
			if len(recs) == 1 {
				a.metrics.Dropped.Add(1)
				a.metrics.DropReason(DropReasonPermanentInvalid, 1)
				return nil
			}
			mid := len(recs) / 2
			if err := a.replayHTTPBatch(recs[:mid]); err != nil {
				return err
			}
			return a.replayHTTPBatch(recs[mid:])
		}
		bad[iv.Index] = iv.Reason
	}
	keep := make([]events.HTTPRecord, 0, len(recs)-len(bad))
	for i, rec := range recs {
		if reason, drop := bad[i]; drop {
			a.log.Warn("补传记录被服务端判定永久非法，按索引隔离丢弃",
				"flow_id", rec.FlowID, "reason", reason)
			a.metrics.Dropped.Add(1)
			a.metrics.DropReason(DropReasonPermanentInvalid, 1)
			continue
		}
		keep = append(keep, rec)
	}
	return a.replayHTTPBatch(keep)
}
