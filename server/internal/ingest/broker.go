package ingest

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

type Record struct {
	Key     string
	Value   []byte
	Headers map[string]string
}

type BatchHandler func(context.Context, []Record) error

type Producer interface {
	PublishBatch(context.Context, string, []Record) error
	Health(context.Context) error
	Close() error
}

type Consumer interface {
	Run(context.Context, string, []string, BatchHandler) error
	Health(context.Context) error
	Close() error
}

type Broker struct {
	config Config
	mu     sync.Mutex
	client *kgo.Client
	closed bool
}

func NewBroker(config Config) *Broker {
	return &Broker{config: config.withDefaults()}
}

func (b *Broker) producerClient() (*kgo.Client, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, errors.New("kafka broker is closed")
	}
	if b.client != nil {
		return b.client, nil
	}
	opts, err := b.config.clientOptions()
	if err != nil {
		return nil, err
	}
	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, err
	}
	b.client = client
	return client, nil
}

func (b *Broker) Health(ctx context.Context) error {
	client, err := b.producerClient()
	if err != nil {
		return err
	}
	pingCtx, cancel := context.WithTimeout(ctx, b.config.ProduceTimeout)
	defer cancel()
	return client.Ping(pingCtx)
}

func (b *Broker) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	if b.client != nil {
		b.client.Close()
		b.client = nil
	}
	return nil
}

func recordByteSize(rec *Record) int {
	size := len(rec.Key) + len(rec.Value)
	for key, value := range rec.Headers {
		size += len(key) + len(value)
	}
	return size
}

func splitKafkaChunks(topic string, records []Record, maxBatchBytes int) ([][]*kgo.Record, error) {
	if maxBatchBytes <= 0 {
		maxBatchBytes = DefaultMaxBatchBytes
	}
	var chunks [][]*kgo.Record
	var cur []*kgo.Record
	curBytes := 0
	for i := range records {
		rec := &records[i]
		if rec.Key == "" || len(rec.Key) > 128 {
			return nil, fmt.Errorf("record %d key must be 1..128 characters", i)
		}
		if len(rec.Value) == 0 {
			return nil, fmt.Errorf("record %d value is empty", i)
		}
		recSize := recordByteSize(rec)
		if recSize > maxBatchBytes {
			return nil, fmt.Errorf("record %d exceeds max batch size of %d bytes (%d bytes)", i, maxBatchBytes, recSize)
		}
		if len(cur) > 0 && curBytes+recSize > maxBatchBytes {
			chunks = append(chunks, cur)
			cur = nil
			curBytes = 0
		}
		cur = append(cur, &kgo.Record{
			Topic:   topic,
			Key:     []byte(rec.Key),
			Value:   append([]byte(nil), rec.Value...),
			Headers: kafkaHeaders(rec.Headers),
		})
		curBytes += recSize
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	return chunks, nil
}

func (b *Broker) PublishBatch(ctx context.Context, topic string, records []Record) error {
	if len(records) == 0 {
		return nil
	}
	if topic == "" || len(topic) > 249 {
		return errors.New("invalid kafka topic")
	}
	if len(records) > b.config.MaxBatchRecords {
		return fmt.Errorf("kafka batch has %d records, limit is %d", len(records), b.config.MaxBatchRecords)
	}
	maxBytes := b.config.MaxBatchBytes
	if maxBytes <= 0 || maxBytes > DefaultMaxBatchBytes {
		maxBytes = DefaultMaxBatchBytes
	}
	chunks, err := splitKafkaChunks(topic, records, maxBytes)
	if err != nil {
		return err
	}
	client, err := b.producerClient()
	if err != nil {
		return err
	}
	offset := 0
	for _, chunk := range chunks {
		produceCtx, cancel := context.WithTimeout(ctx, b.config.ProduceTimeout+10*time.Second)
		results := client.ProduceSync(produceCtx, chunk...)
		cancel()
		for i, result := range results {
			if result.Err != nil {
				return fmt.Errorf("produce record %d: %w", offset+i, result.Err)
			}
		}
		offset += len(chunk)
	}
	return nil
}

func (b *Broker) Run(ctx context.Context, group string, topics []string, handler BatchHandler) error {
	if group == "" || len(topics) == 0 || handler == nil {
		return errors.New("consumer group, topics and handler are required")
	}
	opts, err := b.config.clientOptions()
	if err != nil {
		return err
	}
	opts = append(opts,
		kgo.ConsumerGroup(group),
		kgo.ConsumeTopics(topics...),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.DisableAutoCommit(),
		kgo.BlockRebalanceOnPoll(),
	)
	client, err := kgo.NewClient(opts...)
	if err != nil {
		return err
	}
	defer client.CloseAllowingRebalance()
	for {
		stop, err := b.pollAndProcessOnce(ctx, client, handler)
		if err != nil {
			return err
		}
		if stop {
			return nil
		}
	}
}

func (b *Broker) pollAndProcessOnce(ctx context.Context, client *kgo.Client, handler BatchHandler) (bool, error) {
	fetches := client.PollRecords(ctx, b.config.MaxBatchRecords)
	defer client.AllowRebalance()
	if ctx.Err() != nil {
		return true, nil
	}
	if errs := fetches.Errors(); len(errs) > 0 {
		return false, fmt.Errorf("consume kafka: %v", errs)
	}
	records := fetches.Records()
	if len(records) == 0 {
		return false, nil
	}
	batch := make([]Record, 0, len(records))
	for _, rec := range records {
		batch = append(batch, Record{Key: string(rec.Key), Value: append([]byte(nil), rec.Value...), Headers: headerMap(rec.Headers)})
	}
	if err := handler(ctx, batch); err != nil {
		return false, err
	}
	commitCtx, commitCancel := context.WithTimeout(context.WithoutCancel(ctx), b.config.ProduceTimeout)
	err := client.CommitRecords(commitCtx, records...)
	commitCancel()
	if err != nil {
		return false, fmt.Errorf("commit kafka offsets: %w", err)
	}
	return false, nil
}

func kafkaHeaders(headers map[string]string) []kgo.RecordHeader {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]kgo.RecordHeader, 0, len(keys))
	for _, key := range keys {
		out = append(out, kgo.RecordHeader{Key: key, Value: []byte(headers[key])})
	}
	return out
}

func headerMap(headers []kgo.RecordHeader) map[string]string {
	out := make(map[string]string, len(headers))
	for _, header := range headers {
		out[header.Key] = string(header.Value)
	}
	return out
}
