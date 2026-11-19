package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/apievent"
	"github.com/jiuzhang-waf/wdsp-agent/internal/apiobserve"
	"github.com/jiuzhang-waf/wdsp-agent/internal/inprocess"
	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

const (
	bufTagAPIObservation           byte = 'O'
	maxAPIObservationBatchRecords       = 100
	maxAPIObservationBatchBytes         = 4 << 20
	DropReasonAPIObsNotNegotiated       = "api_observation_v1_not_negotiated"
)

var errAPIObservationUnavailable = errors.New("API Observation capability is not negotiated")

type apiObservationServer interface {
	Run(context.Context) error
	Close() error
}

func (a *Agent) initAPIObservation() {
	a.apiQ = make(chan apievent.Record, httpQueueCap)
	if !a.cfg.APIObservation.Enabled {
		return
	}
	processor := newAPIObservationProcessor(
		a.cfg.AgentID,
		[]byte(os.Getenv(a.cfg.APIObservation.EffectiveHMACKeyEnv())),
		a.cfg.APIObservation.HMACKeyID,
		a.cfg.APIObservation.MaxBodyBytes,
		a.enqueueAPIObservation,
	)
	server, err := inprocess.Listen(a.cfg.APIObservation.EffectiveSocketPath(), a.cfg.APIObservation.EffectiveSocketMode(), processor, a.log)
	if err != nil {
		a.log.Error("API Observation 本地接收器启动失败，按禁用降级", "error", err)
		return
	}
	a.apiServer = server
}

func (a *Agent) startAPIObservation(ctx context.Context) {
	if a.apiServer == nil {
		return
	}
	a.wg.Add(2)
	go func() {
		defer a.wg.Done()
		defer a.recover("api-observation-server")
		a.runAPIObservationServer(ctx)
	}()
	go func() { defer a.wg.Done(); defer a.recover("api-observation-sender"); a.apiSenderLoop(ctx) }()
}

func (a *Agent) runAPIObservationServer(ctx context.Context) {
	if err := a.apiServer.Run(ctx); err != nil {
		a.log.Error("API Observation 本地接收器异常退出，按禁用降级", "error", err)
	}
}

func (a *Agent) stopAPIObservation() {
	if a.apiServer == nil {
		return
	}
	if err := a.apiServer.Close(); err != nil {
		a.log.Warn("API Observation 本地接收器关闭失败", "error", err)
	}
}

type apiObservationProcessor struct {
	processor *apiobserve.Processor
	emit      func(apievent.Record)
}

func newAPIObservationProcessor(agentID string, key []byte, keyID string, maxBodyBytes int, emit func(apievent.Record)) *apiObservationProcessor {
	return &apiObservationProcessor{
		processor: apiobserve.NewProcessor(agentID, key, keyID).WithMaxBodyBytes(maxBodyBytes),
		emit:      emit,
	}
}

func (p *apiObservationProcessor) ProcessBatch(batch apievent.CaptureBatch) ([]apievent.Record, error) {
	records, err := p.processor.ProcessBatch(batch)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		p.emit(record)
	}
	return records, nil
}

func (a *Agent) apiSenderLoop(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	batch := make([]apievent.Record, 0, 100)
	flush := func() {
		if len(batch) > 0 {
			a.sendAPIObservationBatch(batch)
			batch = batch[:0]
		}
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case record := <-a.apiQ:
			batch = append(batch, record)
			if len(batch) >= 100 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (a *Agent) sendAPIObservationBatch(records []apievent.Record) {
	if len(records) == 0 {
		return
	}
	if !a.apiV1.Load() {
		a.metrics.Dropped.Add(uint64(len(records)))
		a.metrics.DropReason(DropReasonAPIObsNotNegotiated, uint64(len(records)))
		return
	}
	for _, chunk := range a.splitAPIObservationBatches(records, maxAPIObservationBatchBytes) {
		data, err := json.Marshal(apievent.Batch{SchemaVersion: apievent.SchemaVersion, Records: chunk})
		if err != nil {
			a.metrics.Dropped.Add(uint64(len(chunk)))
			a.metrics.DropReason(DropReasonPermanentInvalid, uint64(len(chunk)))
			continue
		}
		if a.bucket != nil && !a.bucket.Allow(len(data)) {
			a.bufferAPIObservations(chunk)
			continue
		}
		if err := a.postAPIObservationBatch(chunk, len(data)); err != nil {
			if transport.IsPermanent(err) {
				a.isolateAPIObservationBatch(chunk, err)
				continue
			}
			a.bufferAPIObservations(chunk)
		}
	}
}

func (a *Agent) isolateAPIObservationBatch(records []apievent.Record, cause error) {
	if len(records) == 1 {
		if a.log != nil {
			a.log.Warn("API Observation 被服务端永久拒绝，丢弃并计数", "event_id", records[0].EventID, "error", cause)
		}
		a.metrics.Dropped.Add(1)
		a.metrics.DropReason(DropReasonPermanentInvalid, 1)
		return
	}
	mid := len(records) / 2
	a.sendAPIObservationBatch(records[:mid])
	a.sendAPIObservationBatch(records[mid:])
}

func (a *Agent) splitAPIObservationBatches(records []apievent.Record, maxBytes int) [][]apievent.Record {
	if maxBytes <= 0 || maxBytes > maxAPIObservationBatchBytes {
		maxBytes = maxAPIObservationBatchBytes
	}
	var chunks [][]apievent.Record
	var cur []apievent.Record
	for _, rec := range records {
		singleSize, err := marshalSize(apievent.Batch{SchemaVersion: apievent.SchemaVersion, Records: []apievent.Record{rec}})
		if err != nil || singleSize > maxAPIObservationBatchBytes {
			if a.log != nil {
				a.log.Warn("单条 API Observation 超过批次字节硬上限，丢弃并计数", "event_id", rec.EventID, "bytes", singleSize)
			}
			a.metrics.Dropped.Add(1)
			a.metrics.DropReason(DropReasonPermanentInvalid, 1)
			continue
		}
		candidate := append(cur, rec)
		candSize, err := marshalSize(apievent.Batch{SchemaVersion: apievent.SchemaVersion, Records: candidate})
		if err == nil && len(candidate) <= maxAPIObservationBatchRecords && candSize <= maxBytes {
			cur = candidate
			continue
		}
		if len(cur) > 0 {
			chunks = append(chunks, cur)
		}
		cur = []apievent.Record{rec}
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	return chunks
}

func (a *Agent) postAPIObservationBatch(records []apievent.Record, wireBytes int) error {
	if len(records) == 0 {
		return nil
	}
	if !a.apiV1.Load() {
		return errAPIObservationUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	accepted, duplicate, err := a.client.PostAPIObservations(ctx, a.cfg.AgentID, records)
	cancel()
	if err != nil {
		return err
	}
	a.metrics.Forwarded.Add(uint64(len(records)))
	a.metrics.Accepted.Add(uint64(accepted))
	if duplicate > 0 {
		a.metrics.Duplicate.Add(uint64(duplicate))
	}
	if wireBytes > 0 {
		a.metrics.ForwardBytes.Add(uint64(wireBytes))
	}
	return nil
}

func (a *Agent) bufferAPIObservations(records []apievent.Record) {
	if !a.apiV1.Load() {
		a.metrics.Dropped.Add(uint64(len(records)))
		a.metrics.DropReason(DropReasonAPIObsNotNegotiated, uint64(len(records)))
		return
	}
	if a.buf == nil {
		a.metrics.Dropped.Add(uint64(len(records)))
		a.metrics.DropReason(DropReasonSpoolWriteFailed, uint64(len(records)))
		return
	}
	for _, record := range records {
		data, err := json.Marshal(record)
		if err != nil {
			a.metrics.Dropped.Add(1)
			continue
		}
		if err := a.buf.Write(append([]byte{bufTagAPIObservation}, data...)); err != nil {
			a.metrics.BufferFailed.Add(1)
			a.metrics.Dropped.Add(1)
			a.metrics.DropReason(DropReasonSpoolWriteFailed, 1)
		}
	}
}

func (a *Agent) enqueueAPIObservation(record apievent.Record) {
	if !a.apiV1.Load() {
		a.metrics.Dropped.Add(1)
		a.metrics.DropReason(DropReasonAPIObsNotNegotiated, 1)
		return
	}
	select {
	case a.apiQ <- record:
	default:
		a.bufferAPIObservations([]apievent.Record{record})
	}
}

func (a *Agent) replayAPIObservations(records []apievent.Record) error {
	if len(records) == 0 {
		return nil
	}
	if !a.apiV1.Load() {
		return errAPIObservationUnavailable
	}
	maxBytes := maxAPIObservationBatchBytes
	if a.replayBucket != nil || a.bucket != nil {
		if burst := a.replayBurst(); burst > 0 && burst < maxBytes {
			maxBytes = burst
		}
	}
	for _, chunk := range a.splitAPIObservationBatches(records, maxBytes) {
		if err := a.replayAPIObservationUnit(chunk); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) replayAPIObservationUnit(records []apievent.Record) error {
	if len(records) == 0 {
		return nil
	}
	data, err := json.Marshal(apievent.Batch{SchemaVersion: apievent.SchemaVersion, Records: records})
	if err != nil {
		a.metrics.Dropped.Add(uint64(len(records)))
		a.metrics.DropReason(DropReasonPermanentInvalid, uint64(len(records)))
		return nil
	}
	if (a.replayBucket != nil || a.bucket != nil) && !a.replayAllow(len(data)) {
		return errReplayThrottled
	}
	if err := a.postAPIObservationBatch(records, len(data)); err != nil {
		if transport.IsPermanent(err) {
			if len(records) == 1 {
				a.metrics.Dropped.Add(1)
				a.metrics.DropReason(DropReasonPermanentInvalid, 1)
				return nil
			}
			mid := len(records) / 2
			if err := a.replayAPIObservationUnit(records[:mid]); err != nil {
				return err
			}
			return a.replayAPIObservationUnit(records[mid:])
		}
		return err
	}
	return nil
}
