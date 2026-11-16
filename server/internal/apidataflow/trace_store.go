package apidataflow

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/agents"
)

type ObservationContributionStore interface {
	SaveObservationContributions(context.Context, []agents.APIObservationEnvelope) error
}

func (s *CHContributionStore) SaveObservationContributions(ctx context.Context, records []agents.APIObservationEnvelope) error {
	if len(records) == 0 {
		return nil
	}
	if err := NewCHObservationStore(s.resolve).SaveBatch(ctx, records); err != nil {
		return fmt.Errorf("persist observations for dataflow correlation: %w", err)
	}
	traceSet := map[string]bool{}
	for _, record := range records {
		if record.Trace.TraceID != "" {
			traceSet[record.Trace.TraceID] = true
		}
	}
	if len(traceSet) == 0 {
		return s.SaveContributions(ctx, BuildContributions(records))
	}
	traceIDs := make([]string, 0, len(traceSet))
	for traceID := range traceSet {
		traceIDs = append(traceIDs, traceID)
	}
	sort.Strings(traceIDs)
	persisted, err := s.loadTraceObservations(ctx, traceIDs)
	if err != nil {
		return err
	}
	byKey := make(map[observationKey]agents.APIObservationEnvelope, len(persisted)+len(records))
	for _, record := range persisted {
		byKey[keyForObservation(record)] = record
	}
	for _, record := range records {
		byKey[keyForObservation(record)] = record
	}
	merged := make([]agents.APIObservationEnvelope, 0, len(byKey))
	for _, record := range byKey {
		merged = append(merged, record)
	}
	return s.SaveContributions(ctx, persistentContributions(merged))
}

func (s *CHContributionStore) loadTraceObservations(ctx context.Context, traceIDs []string) ([]agents.APIObservationEnvelope, error) {
	querier, err := (&CHReader{resolve: s.resolve}).querier(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := querier.Query(ctx, `
SELECT agent_id,event_id,
 argMax(occurred_at,received_at) AS occurred_at,
 argMax(ifNull(application_id,toUUID('00000000-0000-0000-0000-000000000000')),received_at) AS application_id,
 argMax(service_name,received_at) AS service_name,
 argMax(trace_id,received_at) AS latest_trace_id,
 argMax(span_id,received_at) AS span_id,
 argMax(parent_span_id,received_at) AS parent_span_id,
 argMax(direction,received_at) AS direction,
 argMax(method,received_at) AS method,
 argMax(host,received_at) AS host,
 argMax(path_template,received_at) AS path_template,
 argMax(status,received_at) AS status,
 argMax(latency_ms,received_at) AS latency_ms,
 argMax(peer_service,received_at) AS peer_service,
 argMax(peer_address,received_at) AS peer_address,
 argMax(client_address,received_at) AS client_address,
 argMax(client_address_source,received_at) AS client_address_source,
 argMax(server_address,received_at) AS server_address,
 argMax(messaging_system,received_at) AS messaging_system,
 argMax(messaging_destination,received_at) AS messaging_destination
FROM wdsp.api_observations
WHERE trace_id IN (?)
GROUP BY agent_id,event_id
ORDER BY occurred_at,event_id`, traceIDs)
	if err != nil {
		return nil, fmt.Errorf("load persisted trace observations: %w", err)
	}
	defer rows.Close()
	records := []agents.APIObservationEnvelope{}
	indexes := map[observationKey]int{}
	for rows.Next() {
		record := agents.APIObservationEnvelope{SchemaVersion: agents.APIObservationSchemaV1}
		var applicationID uuid.UUID
		var status uint16
		var latencyMS uint32
		if err := rows.Scan(
			&record.AgentID, &record.EventID, &record.OccurredAt, &applicationID,
			&record.Service.Name, &record.Trace.TraceID, &record.Trace.SpanID, &record.Trace.ParentSpanID,
			&record.HTTP.Direction, &record.HTTP.Method, &record.HTTP.Host, &record.HTTP.PathTemplate,
			&status, &latencyMS, &record.HTTP.PeerService, &record.HTTP.PeerAddress,
			&record.HTTP.ClientAddress, &record.HTTP.ClientAddressSource, &record.HTTP.ServerAddress,
			&record.HTTP.MessagingSystem, &record.HTTP.MessagingDestination,
		); err != nil {
			return nil, err
		}
		record.HTTP.Status = int(status)
		record.HTTP.LatencyMS = int64(latencyMS)
		if applicationID != uuid.Nil {
			record.ApplicationID = &applicationID
		}
		indexes[keyForObservation(record)] = len(records)
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return records, nil
	}
	fieldRows, err := querier.Query(ctx, `
SELECT agent_id,event_id,side,location,field_path,data_type,
 argMax(level,ingested_at) AS level,value_hmac,hmac_key_id,
 argMax(value_present,ingested_at) AS value_present,
 argMax(truncated,ingested_at) AS truncated
FROM wdsp.api_field_observations
WHERE (agent_id,event_id) IN (
 SELECT agent_id,event_id FROM wdsp.api_observations
 WHERE trace_id IN (?)
 GROUP BY agent_id,event_id
)
GROUP BY agent_id,event_id,side,location,field_path,data_type,value_hmac,hmac_key_id
ORDER BY agent_id,event_id,side,field_path,data_type,value_hmac`, traceIDs)
	if err != nil {
		return nil, fmt.Errorf("load persisted trace fields: %w", err)
	}
	defer fieldRows.Close()
	for fieldRows.Next() {
		var key observationKey
		var field agents.APIObservationField
		if err := fieldRows.Scan(&key.agentID, &key.eventID, &field.Side, &field.Location, &field.Path,
			&field.DataType, &field.Level, &field.ValueHMAC, &field.HMACKeyID, &field.ValuePresent, &field.Truncated); err != nil {
			return nil, err
		}
		if index, ok := indexes[key]; ok {
			records[index].Fields = append(records[index].Fields, field)
		}
	}
	if err := fieldRows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}
