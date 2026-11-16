package apidataflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/agents"
	"github.com/jiuzhang-waf/server/internal/apm"
)

var ErrObservationDataPlane = errors.New("API observation ClickHouse data plane is unavailable")

type ObservationStore interface {
	SaveBatch(context.Context, []agents.APIObservationEnvelope) error
}

type CHObservationStore struct {
	resolve func(context.Context) apm.CHQuerier
}

func NewCHObservationStore(resolve func(context.Context) apm.CHQuerier) *CHObservationStore {
	return &CHObservationStore{resolve: resolve}
}

type chExecutor interface {
	Exec(context.Context, string, ...any) error
}

func (s *CHObservationStore) executor(ctx context.Context) (chExecutor, error) {
	if s.resolve == nil {
		return nil, ErrObservationDataPlane
	}
	querier := s.resolve(ctx)
	if querier == nil {
		return nil, ErrObservationDataPlane
	}
	executor, ok := querier.(chExecutor)
	if !ok {
		return nil, fmt.Errorf("%w: writer is not implemented", ErrObservationDataPlane)
	}
	return executor, nil
}

func (s *CHObservationStore) SaveBatch(ctx context.Context, records []agents.APIObservationEnvelope) error {
	if len(records) == 0 {
		return nil
	}
	executor, err := s.executor(ctx)
	if err != nil {
		return err
	}
	observationArgs := make([]any, 0, len(records)*39)
	fieldArgs := make([]any, 0)
	fieldRows := 0
	for i := range records {
		r := &records[i]
		quality, err := json.Marshal(r.Quality)
		if err != nil {
			return err
		}
		observationArgs = append(observationArgs,
			r.AgentID, r.EventID, nullableUUID(r.ApplicationID), nullableUUID(r.ApplicationBindingID), r.BindingVersion,
			r.OccurredAt.UTC(), r.ReceivedAt.UTC(), r.Source.Type, r.Source.Language, r.Source.Framework,
			r.Source.AgentVersion, r.Source.SourceEpoch, r.Service.Name, r.Service.InstanceID,
			r.Service.Version, r.Service.Environment, r.Service.Namespace, r.Service.Cluster,
			r.Trace.TraceID, r.Trace.SpanID, r.Trace.ParentSpanID, r.HTTP.Direction, r.HTTP.Method,
			r.HTTP.Scheme, r.HTTP.Host, r.HTTP.Route, r.HTTP.PathTemplate, r.HTTP.Status,
			r.HTTP.LatencyMS, r.HTTP.RequestContentType, r.HTTP.ResponseContentType, r.HTTP.PeerService,
			r.HTTP.PeerAddress, r.HTTP.ClientAddress, r.HTTP.ClientAddressSource, r.HTTP.ServerAddress,
			r.HTTP.MessagingSystem, r.HTTP.MessagingDestination, string(quality),
		)
		for _, field := range r.Fields {
			fieldRows++
			fieldArgs = append(fieldArgs,
				r.AgentID, r.EventID, r.OccurredAt.UTC(), field.Side, field.Location, field.Path,
				field.DataType, field.Level, field.ValueHMAC, field.HMACKeyID, field.ValuePresent, field.Truncated,
			)
		}
	}
	observationSQL := insertValuesSQL("wdsp.api_observations", []string{
		"agent_id", "event_id", "application_id", "application_binding_id", "binding_version",
		"occurred_at", "received_at", "source_type", "language", "framework", "agent_version", "source_epoch",
		"service_name", "service_instance_id", "service_version", "environment", "namespace", "cluster",
		"trace_id", "span_id", "parent_span_id", "direction", "method", "scheme", "host", "route", "path_template",
		"status", "latency_ms", "request_content_type", "response_content_type", "peer_service", "peer_address",
		"client_address", "client_address_source", "server_address", "messaging_system", "messaging_destination", "quality_json",
	}, len(records))
	if err := executor.Exec(ctx, observationSQL, observationArgs...); err != nil {
		return fmt.Errorf("insert API observations: %w", err)
	}
	if fieldRows > 0 {
		fieldSQL := insertValuesSQL("wdsp.api_field_observations", []string{
			"agent_id", "event_id", "occurred_at", "side", "location", "field_path", "data_type",
			"level", "value_hmac", "hmac_key_id", "value_present", "truncated",
		}, fieldRows)
		if err := executor.Exec(ctx, fieldSQL, fieldArgs...); err != nil {
			return fmt.Errorf("insert API field observations: %w", err)
		}
	}
	return nil
}

func insertValuesSQL(table string, columns []string, rows int) string {
	var b strings.Builder
	b.WriteString("INSERT INTO ")
	b.WriteString(table)
	b.WriteString(" (")
	b.WriteString(strings.Join(columns, ","))
	b.WriteString(") VALUES ")
	row := "(" + strings.TrimSuffix(strings.Repeat("?,", len(columns)), ",") + ")"
	for i := 0; i < rows; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(row)
	}
	return b.String()
}

func nullableUUID(value *uuid.UUID) any {
	if value == nil {
		return nil
	}
	return *value
}
