package apidataflow

import (
	"context"
	"fmt"
	"sort"
	"time"

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
	windowStart, windowEnd, hasWindow := computeTraceLookupWindow(records, s.effectiveTraceWindow())
	persisted, err := s.loadTraceObservations(ctx, traceIDs, windowStart, windowEnd, hasWindow)
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

func computeTraceLookupWindow(records []agents.APIObservationEnvelope, window time.Duration) (time.Time, time.Time, bool) {
	if window <= 0 {
		window = defaultTraceLookupWindow
	}
	var minOccurred, maxOccurred time.Time
	update := func(ts time.Time) {
		if ts.IsZero() {
			return
		}
		utc := ts.UTC()
		if minOccurred.IsZero() || utc.Before(minOccurred) {
			minOccurred = utc
		}
		if maxOccurred.IsZero() || utc.After(maxOccurred) {
			maxOccurred = utc
		}
	}
	for _, record := range records {
		if record.Trace.TraceID != "" {
			update(record.OccurredAt)
		}
	}
	if minOccurred.IsZero() {
		for _, record := range records {
			update(record.OccurredAt)
		}
	}
	if minOccurred.IsZero() {
		return time.Time{}, time.Time{}, false
	}
	return minOccurred.Add(-window), maxOccurred.Add(window), true
}

func (s *CHContributionStore) loadTraceObservations(ctx context.Context, traceIDs []string, windowStart, windowEnd time.Time, hasWindow bool) ([]agents.APIObservationEnvelope, error) {
	querier, err := (&CHReader{resolve: s.resolve}).querier(ctx)
	if err != nil {
		return nil, err
	}
	queryCtx := withCHQuerySettings(ctx)
	obsWhere := "trace_id IN (?)"
	obsArgs := []any{traceIDs}
	if hasWindow {
		obsWhere = "occurred_at >= ? AND occurred_at <= ? AND trace_id IN (?)"
		obsArgs = []any{windowStart.UTC(), windowEnd.UTC(), traceIDs}
	}
	rows, err := querier.Query(queryCtx, `
SELECT agent_id,event_id,
 argMax(occurred_at,received_at) AS latest_occurred_at,
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
WHERE `+obsWhere+`
GROUP BY agent_id,event_id
ORDER BY latest_occurred_at,event_id`, obsArgs...)
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

	agentSet := make(map[uuid.UUID]struct{}, len(records))
	eventSet := make(map[string]struct{}, len(records))
	var minFieldOccurred, maxFieldOccurred time.Time
	allFieldsDated := true
	for _, record := range records {
		agentSet[record.AgentID] = struct{}{}
		eventSet[record.EventID] = struct{}{}
		if record.OccurredAt.IsZero() {
			allFieldsDated = false
			continue
		}
		utc := record.OccurredAt.UTC()
		if minFieldOccurred.IsZero() || utc.Before(minFieldOccurred) {
			minFieldOccurred = utc
		}
		if maxFieldOccurred.IsZero() || utc.After(maxFieldOccurred) {
			maxFieldOccurred = utc
		}
	}
	agentIDs := make([]uuid.UUID, 0, len(agentSet))
	for agentID := range agentSet {
		agentIDs = append(agentIDs, agentID)
	}
	sort.Slice(agentIDs, func(i, j int) bool {
		return agentIDs[i].String() < agentIDs[j].String()
	})
	eventIDs := make([]string, 0, len(eventSet))
	for eventID := range eventSet {
		eventIDs = append(eventIDs, eventID)
	}
	sort.Strings(eventIDs)

	fieldWhere := "agent_id IN (?) AND event_id IN (?)"
	fieldArgs := []any{agentIDs, eventIDs}
	if allFieldsDated && !minFieldOccurred.IsZero() {
		fieldWhere = "occurred_at >= ? AND occurred_at <= ? AND agent_id IN (?) AND event_id IN (?)"
		fieldArgs = []any{minFieldOccurred.Add(-time.Second), maxFieldOccurred.Add(time.Second), agentIDs, eventIDs}
	}

	fieldRows, err := querier.Query(queryCtx, `
SELECT agent_id,event_id,side,location,field_path,data_type,
 argMax(level,ingested_at) AS level,value_hmac,hmac_key_id,
 argMax(value_present,ingested_at) AS value_present,
 argMax(truncated,ingested_at) AS truncated
FROM wdsp.api_field_observations
WHERE `+fieldWhere+`
GROUP BY agent_id,event_id,side,location,field_path,data_type,value_hmac,hmac_key_id
ORDER BY agent_id,event_id,side,field_path,data_type,value_hmac`, fieldArgs...)
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
