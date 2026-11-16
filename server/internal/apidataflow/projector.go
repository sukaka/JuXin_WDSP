package apidataflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/agents"
	"github.com/jiuzhang-waf/server/internal/ingest"
)

type Projector struct {
	consumer     ingest.Consumer
	producer     ingest.Producer
	topic        string
	dlqTopic     string
	observations ObservationStore
	assets       AssetProjector
	now          func() time.Time
}

func NewProjector(consumer ingest.Consumer, producer ingest.Producer, topic, dlqTopic string, observations ObservationStore, assets AssetProjector) *Projector {
	return &Projector{consumer: consumer, producer: producer, topic: topic, dlqTopic: dlqTopic, observations: observations, assets: assets, now: time.Now}
}

func (p *Projector) Run(ctx context.Context) {
	for ctx.Err() == nil {
		err := p.consumer.Run(ctx, "wdsp-api-projection-v1", []string{p.topic}, p.ProjectBatch)
		if ctx.Err() != nil {
			return
		}
		slog.Error("API observation projection stopped; retrying with bounded backoff", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (p *Projector) ProjectBatch(ctx context.Context, records []ingest.Record) error {
	envelopes, err := p.decodeBatch(ctx, records)
	if err != nil {
		return err
	}
	if len(envelopes) == 0 {
		return nil
	}
	if p.observations == nil || p.assets == nil {
		return errors.New("API observation projection is not configured")
	}
	if err := p.observations.SaveBatch(ctx, envelopes); err != nil {
		return err
	}
	for _, envelope := range envelopes {
		if err := p.assets.Project(ctx, envelope); err != nil {
			return fmt.Errorf("project API asset for %s: %w", envelope.EventID, err)
		}
	}
	return nil
}

func (p *Projector) decodeBatch(ctx context.Context, records []ingest.Record) ([]agents.APIObservationEnvelope, error) {
	envelopes := make([]agents.APIObservationEnvelope, 0, len(records))
	for _, raw := range records {
		envelope, err := p.decode(raw)
		if err != nil {
			if err := p.deadLetter(ctx, raw, err); err != nil {
				return nil, err
			}
			continue
		}
		envelopes = append(envelopes, envelope)
	}
	return envelopes, nil
}

func (p *Projector) decode(raw ingest.Record) (agents.APIObservationEnvelope, error) {
	var envelope agents.APIObservationEnvelope
	decoder := json.NewDecoder(strings.NewReader(string(raw.Value)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return envelope, fmt.Errorf("decode observation: %w", err)
	}
	if decoder.More() {
		return envelope, errors.New("decode observation: trailing content")
	}
	if envelope.SchemaVersion != agents.APIObservationSchemaV1 {
		return envelope, errors.New("unsupported observation schema")
	}
	if envelope.AgentID == uuid.Nil || raw.Key != envelope.AgentID.String() {
		return envelope, errors.New("observation agent identity does not match message key")
	}
	if envelope.ReceivedAt.IsZero() {
		return envelope, errors.New("observation received_at is required")
	}
	if eventID := raw.Headers["event_id"]; eventID != "" && eventID != envelope.EventID {
		return envelope, errors.New("observation event_id does not match Kafka header")
	}
	batch := agents.APIObservationBatch{SchemaVersion: agents.APIObservationSchemaV1, Records: []agents.APIObservationRecord{envelope.APIObservationRecord}}
	if invalid := batch.Validate(p.now().UTC()); len(invalid) > 0 {
		return envelope, errors.New(invalid[0].Reason)
	}
	return envelope, nil
}

func (p *Projector) deadLetter(ctx context.Context, raw ingest.Record, cause error) error {
	if p.producer == nil || p.dlqTopic == "" {
		return errors.New("DLQ producer is not configured")
	}
	eventID := raw.Headers["event_id"]
	if eventID == "" {
		eventID = "unknown-" + uuid.NewString()
	}
	agentID := raw.Headers["agent_id"]
	if agentID == "" {
		agentID = raw.Key
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"schema_version": 1, "agent_id": agentID, "event_id": eventID,
		"payload": string(raw.Value), "error_category": "INVALID_OBSERVATION",
		"error_message": truncate(cause.Error(), 512), "retry_count": 0,
		"created_at": p.now().UTC(),
	})
	return p.producer.PublishBatch(ctx, p.dlqTopic, []ingest.Record{{
		Key: agentID + ":" + eventID, Value: payload,
		Headers: map[string]string{"schema_version": "1", "event_id": eventID, "agent_id": agentID},
	}})
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
