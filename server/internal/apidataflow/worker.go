package apidataflow

import (
	"context"
	"log/slog"
	"time"

	"github.com/jiuzhang-waf/server/internal/ingest"
)

type DataflowWorker struct {
	consumer ingest.Consumer
	topic    string
	store    ContributionStore
	decoder  *Projector
}

func NewDataflowWorker(consumer ingest.Consumer, producer ingest.Producer, topic, dlqTopic string, store ContributionStore) *DataflowWorker {
	return &DataflowWorker{consumer: consumer, topic: topic, store: store, decoder: NewProjector(nil, producer, topic, dlqTopic, nil, nil)}
}

func (w *DataflowWorker) Run(ctx context.Context) {
	for ctx.Err() == nil {
		err := w.consumer.Run(ctx, "wdsp-dataflow-builder-v1", []string{w.topic}, w.BuildBatch)
		if ctx.Err() != nil {
			return
		}
		slog.Error("dataflow consumer stopped; retrying with bounded backoff", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (w *DataflowWorker) BuildBatch(ctx context.Context, records []ingest.Record) error {
	envelopes, err := w.decoder.decodeBatch(ctx, records)
	if err != nil {
		return err
	}
	if w.store == nil {
		return ErrObservationDataPlane
	}
	if store, ok := w.store.(ObservationContributionStore); ok {
		return store.SaveObservationContributions(ctx, envelopes)
	}
	return w.store.SaveContributions(ctx, BuildContributions(envelopes))
}
