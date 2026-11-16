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

const bufTagAPIObservation byte = 'O'

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
	processor := newAPIObservationProcessor(a.cfg.AgentID, []byte(os.Getenv(a.cfg.APIObservation.EffectiveHMACKeyEnv())), a.cfg.APIObservation.HMACKeyID, a.enqueueAPIObservation)
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

func newAPIObservationProcessor(agentID string, key []byte, keyID string, emit func(apievent.Record)) *apiObservationProcessor {
	return &apiObservationProcessor{processor: apiobserve.NewProcessor(agentID, key, keyID), emit: emit}
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
	if err := a.postAPIObservationBatch(records); err != nil {
		if transport.IsPermanent(err) {
			a.log.Warn("API Observation 被服务端永久拒绝，丢弃并计数", "records", len(records), "error", err)
			a.metrics.Dropped.Add(uint64(len(records)))
			a.metrics.DropReason(DropReasonPermanentInvalid, uint64(len(records)))
			return
		}
		a.bufferAPIObservations(records)
	}
}

func (a *Agent) postAPIObservationBatch(records []apievent.Record) error {
	if len(records) == 0 {
		return nil
	}
	if !a.apiV1.Load() {
		return errAPIObservationUnavailable
	}
	accepted, duplicate, err := a.client.PostAPIObservations(context.Background(), a.cfg.AgentID, records)
	if err != nil {
		return err
	}
	a.metrics.Forwarded.Add(uint64(len(records)))
	a.metrics.Accepted.Add(uint64(accepted))
	if duplicate > 0 {
		a.metrics.Duplicate.Add(uint64(duplicate))
	}
	return nil
}

func (a *Agent) bufferAPIObservations(records []apievent.Record) {
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
	select {
	case a.apiQ <- record:
	default:
		a.bufferAPIObservations([]apievent.Record{record})
	}
}

func (a *Agent) replayAPIObservations(records []apievent.Record) error {
	for len(records) > 0 {
		n := len(records)
		if n > 100 {
			n = 100
		}
		if err := a.postAPIObservationBatch(records[:n]); err != nil {
			if transport.IsPermanent(err) {
				a.metrics.Dropped.Add(uint64(n))
				a.metrics.DropReason(DropReasonPermanentInvalid, uint64(n))
				records = records[n:]
				continue
			}
			return err
		}
		records = records[n:]
	}
	return nil
}
