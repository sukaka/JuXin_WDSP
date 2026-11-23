package apidataflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/apm"
)

type Reader interface {
	Graph(context.Context, GraphFilter) (*Graph, error)
	Evidence(context.Context, string, GraphFilter, int) ([]EvidenceRecord, error)
	Quality(context.Context, GraphFilter) (DataQuality, error)
}

type CHReader struct {
	resolve       func(context.Context) apm.CHQuerier
	runtimeFields RuntimeFieldReader
}

func NewCHReader(resolve func(context.Context) apm.CHQuerier) *CHReader {
	return &CHReader{resolve: resolve}
}

func (s *CHReader) WithRuntimeFields(reader RuntimeFieldReader) *CHReader {
	copy := *s
	copy.runtimeFields = reader
	return &copy
}

func (s *CHReader) querier(ctx context.Context) (apm.CHQuerier, error) {
	if s.resolve == nil {
		return nil, ErrObservationDataPlane
	}
	querier := s.resolve(ctx)
	if querier == nil {
		return nil, ErrObservationDataPlane
	}
	return querier, nil
}

func (s *CHReader) Graph(ctx context.Context, filter GraphFilter) (*Graph, error) {
	if err := validateGraphFilter(&filter); err != nil {
		return nil, err
	}
	querier, err := s.querier(ctx)
	if err != nil {
		return nil, err
	}
	runtimeEnabled := s.runtimeFields != nil
	filterRuntimeDataType := runtimeEnabled && filter.DataType != ""
	where, args := graphWhereForRuntime(filter, false, runtimeEnabled)
	runtimeSelect := ""
	if runtimeEnabled {
		runtimeSelect = fmt.Sprintf(`,
 groupUniqArrayIf(%d)(toJSONString(tuple(latest_trace_id,latest_method,latest_path_template,ifNull(toString(app_id),''))),latest_trace_id != '') AS runtime_refs,
 uniqExactIf(tuple(latest_trace_id,latest_method,latest_path_template,ifNull(toString(app_id),'')),latest_trace_id != '') AS runtime_ref_count`, runtimeGraphReferencesPerEdge)
	}
	query := `
SELECT any(edge_id) AS id,
 latest_source_node AS source_node,
 latest_source_type AS source_type,
 latest_target_node AS target_node,
 latest_target_type AS target_type,
 latest_protocol AS protocol,
 sum(latest_count_weight) AS calls,
 sum(latest_error) AS errors,
 sum(latest_latency_ms * latest_count_weight) / greatest(sum(latest_count_weight),1) AS avg_ms,
 max(latest_latency_ms) AS max_ms,
 min(event_time) AS first_seen,
 max(event_time) AS last_seen,
 argMax(latest_evidence_type,event_time) AS evidence_type,
 max(latest_confidence) AS confidence,
 groupUniqArrayIf(100)(concat(latest_method, ' ', latest_path_template),latest_method != '' OR latest_path_template != '') AS apis,
 groupUniqArray(20)(latest_data_types_json) AS data_type_sets,
 groupUniqArray(20)(latest_field_evidence_json) AS field_sets,
 groupUniqArrayIf(3)(latest_trace_id,latest_trace_id != '') AS sample_traces,
 argMax(latest_source_zone,event_time) AS source_zone,
 argMax(latest_target_zone,event_time) AS target_zone,
 argMax(latest_boundary_type,event_time) AS boundary_type,
 argMax(latest_boundary_evidence,event_time) AS boundary_evidence` + runtimeSelect + `
FROM (
 SELECT agent_id,event_id,edge_id,
  argMax(occurred_at,received_at) AS event_time,
  argMax(application_id,received_at) AS app_id,
  argMax(source_node,received_at) AS latest_source_node,
  argMax(source_type,received_at) AS latest_source_type,
  argMax(target_node,received_at) AS latest_target_node,
  argMax(target_type,received_at) AS latest_target_type,
  argMax(protocol,received_at) AS latest_protocol,
  argMax(method,received_at) AS latest_method,
  argMax(path_template,received_at) AS latest_path_template,
  argMax(status,received_at) AS latest_status,
  argMax(latency_ms,received_at) AS latest_latency_ms,
  argMax(error,received_at) AS latest_error,
  argMax(count_weight,received_at) AS latest_count_weight,
  argMax(data_types_json,received_at) AS latest_data_types_json,
  argMax(field_evidence_json,received_at) AS latest_field_evidence_json,
  argMax(evidence_type,received_at) AS latest_evidence_type,
  argMax(confidence,received_at) AS latest_confidence,
  argMax(trace_id,received_at) AS latest_trace_id,
  argMax(span_id,received_at) AS latest_span_id,
  argMax(source_zone,received_at) AS latest_source_zone,
  argMax(target_zone,received_at) AS latest_target_zone,
  argMax(boundary_type,received_at) AS latest_boundary_type,
  argMax(boundary_evidence,received_at) AS latest_boundary_evidence
 FROM wdsp.data_flow_contributions
 WHERE ` + where + `
 GROUP BY agent_id,event_id,edge_id
)
WHERE latest_evidence_type NOT IN ('PAIRED_CLIENT','PAIRED_SERVER')
GROUP BY edge_id,latest_source_node,latest_source_type,latest_target_node,latest_target_type,latest_protocol
ORDER BY calls DESC,latest_source_node ASC,latest_target_node ASC
LIMIT ?`
	candidateLimit := filter.MaxEdges + 1
	if filterRuntimeDataType {
		candidateLimit = runtimeGraphCandidateLimit + 1
	}
	args = append(args, candidateLimit)
	rows, err := querier.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query dataflow graph: %w", err)
	}
	defer rows.Close()
	type graphCandidate struct {
		edge       Edge
		sourceType string
		targetType string
		references []RuntimeFieldReference
	}
	candidates := []graphCandidate{}
	candidateTruncated := false
	runtimeReferenceTruncated := false
	for rows.Next() {
		edge := Edge{}
		var sourceType, targetType string
		var avgMS float64
		var maxMS uint32
		var confidence float32
		var dataTypeSets, fieldSets, traces []string
		destinations := []any{&edge.ID, &edge.SourceName, &sourceType, &edge.TargetName, &targetType, &edge.Protocol,
			&edge.Calls, &edge.Errors, &avgMS, &maxMS, &edge.FirstSeenAt, &edge.LastSeenAt,
			&edge.EvidenceType, &confidence, &edge.APIs, &dataTypeSets, &fieldSets, &traces,
			&edge.SourceZone, &edge.TargetZone, &edge.BoundaryType, &edge.BoundaryEvidence}
		var runtimeReferenceJSON []string
		var runtimeReferenceCount uint64
		if runtimeEnabled {
			destinations = append(destinations, &runtimeReferenceJSON, &runtimeReferenceCount)
		}
		if err := rows.Scan(destinations...); err != nil {
			return nil, err
		}
		if filterRuntimeDataType && len(candidates) >= runtimeGraphCandidateLimit {
			candidateTruncated = true
			break
		}
		if !filterRuntimeDataType && len(candidates) >= filter.MaxEdges {
			candidateTruncated = true
			break
		}
		edge.Confidence = float64(confidence)
		edge.AvgLatencyMS = avgMS
		edge.MaxLatencyMS = int64(maxMS)
		edge.SourceID = nodeID(sourceType, edge.SourceName)
		edge.TargetID = nodeID(targetType, edge.TargetName)
		edge.DataTypes = mergeJSONStrings(dataTypeSets)
		edge.Fields = mergeFieldEvidence(fieldSets)
		edge.SampleTraceIDs = traces
		candidate := graphCandidate{edge: edge, sourceType: sourceType, targetType: targetType}
		if runtimeEnabled {
			uniqueReferenceJSON := []string{}
			for _, encoded := range runtimeReferenceJSON {
				uniqueReferenceJSON = appendUniqueString(uniqueReferenceJSON, encoded)
			}
			if runtimeReferenceCount != uint64(len(uniqueReferenceJSON)) {
				if filterRuntimeDataType {
					return nil, ErrRuntimeFieldReferenceLimit
				}
				runtimeReferenceTruncated = true
			}
			references, err := parseRuntimeFieldReferences(uniqueReferenceJSON)
			if err != nil {
				return nil, err
			}
			candidate.references = references
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if filterRuntimeDataType && candidateTruncated {
		return nil, ErrRuntimeFieldGraphLimit
	}
	allReferences := []RuntimeFieldReference{}
	for _, candidate := range candidates {
		allReferences = append(allReferences, candidate.references...)
	}
	runtimeFields := map[string][]FieldEvidence{}
	runtimeWarning := ""
	if runtimeReferenceTruncated {
		runtimeWarning = runtimeFieldQualityMessage
		slog.Warn("dataflow runtime field enrichment degraded", "error", ErrRuntimeFieldReferenceLimit)
	} else {
		loaded, loadErr := s.loadRuntimeFields(ctx, filter, allReferences)
		if loadErr != nil {
			if filterRuntimeDataType {
				return nil, loadErr
			}
			runtimeWarning = runtimeFieldQualityMessage
			slog.Warn("dataflow runtime field enrichment degraded", "error", loadErr)
		} else {
			runtimeFields = loaded
		}
	}
	graph := &Graph{Nodes: []Node{}, Edges: []Edge{}, Truncated: candidateTruncated || runtimeWarning != "", RuntimeFieldsWarning: runtimeWarning}
	nodeMap := map[string]*Node{}
	for _, candidate := range candidates {
		edge := candidate.edge
		mergeEdgeRuntimeFields(&edge, candidate.references, runtimeFields)
		if filterRuntimeDataType && !dataTypeMatches(edge.DataTypes, edge.Fields, filter.DataType) {
			continue
		}
		if len(graph.Edges) >= filter.MaxEdges {
			graph.Truncated = true
			break
		}
		graph.Edges = append(graph.Edges, edge)
		upsertGraphNode(nodeMap, edge.SourceID, edge.SourceName, candidate.sourceType, edge, true)
		upsertGraphNode(nodeMap, edge.TargetID, edge.TargetName, candidate.targetType, edge, false)
	}
	apiCounts, err := s.apiCounts(ctx, filter)
	if err != nil {
		return nil, err
	}
	for _, node := range nodeMap {
		node.APICount = apiCounts[node.Name]
		graph.Nodes = append(graph.Nodes, *node)
	}
	graph.View = filter.View
	if len(graph.Nodes) > 0 {
		if err := s.addNodeMetadata(ctx, filter, graph); err != nil {
			return nil, err
		}
		if filter.View == "network" {
			applyNetworkView(graph)
		}
	}
	return graph, nil
}

func (s *CHReader) apiCounts(ctx context.Context, filter GraphFilter) (map[string]uint64, error) {
	querier, err := s.querier(ctx)
	if err != nil {
		return nil, err
	}
	where, args := graphWhere(filter, true)
	if filter.View == "service" {
		where += " AND direction IN ('CLIENT','SERVER')"
	}
	rows, err := querier.Query(ctx, `
SELECT service_name,countDistinct((method,path_template)) FROM (
 SELECT agent_id,event_id,
  argMax(service_name,received_at) AS service_name,
  argMax(method,received_at) AS method,
  argMax(path_template,received_at) AS path_template
 FROM wdsp.api_observations
 WHERE `+where+`
 GROUP BY agent_id,event_id
)
GROUP BY service_name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]uint64{}
	for rows.Next() {
		var service string
		var count uint64
		if err := rows.Scan(&service, &count); err != nil {
			return nil, err
		}
		out[service] = count
	}
	return out, rows.Err()
}

func (s *CHReader) Evidence(ctx context.Context, edgeID string, filter GraphFilter, limit int) ([]EvidenceRecord, error) {
	if edgeID == "" || len(edgeID) > 128 {
		return nil, errors.New("invalid edge id")
	}
	if err := validateGraphFilter(&filter); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	querier, err := s.querier(ctx)
	if err != nil {
		return nil, err
	}
	runtimeEnabled := s.runtimeFields != nil
	filterRuntimeDataType := runtimeEnabled && filter.DataType != ""
	where, args := graphWhereForRuntime(filter, false, runtimeEnabled)
	runtimeOuter := ""
	runtimeInner := ""
	if runtimeEnabled {
		runtimeOuter = `,
 latest_data_types_json AS runtime_data_types,
 toJSONString(tuple(latest_trace_id,latest_method,latest_path_template,ifNull(toString(app_id),''))) AS runtime_ref`
		runtimeInner = `,
  argMax(application_id,received_at) AS app_id,
  argMax(method,received_at) AS latest_method,
  argMax(path_template,received_at) AS latest_path_template,
  argMax(data_types_json,received_at) AS latest_data_types_json`
	}
	candidateLimit := limit
	if filterRuntimeDataType {
		candidateLimit = runtimeEvidenceCandidateLimit + 1
	}
	rows, err := querier.Query(ctx, `
SELECT agent_id,event_id,edge_id,
 event_time,
 if(latest_evidence_type = 'OBSERVED_SERVER',latest_target_node,latest_source_node) AS service_name,
 latest_trace_id AS trace_id,
 latest_span_id AS span_id,
 latest_field_evidence_json AS field_evidence_json,
 latest_evidence_type AS evidence_type,
 latest_confidence AS confidence,
 latest_peer_address AS peer_address,
 latest_client_address AS client_address,
 latest_client_address_source AS client_address_source,
 latest_server_address AS server_address,
 latest_source_zone AS source_zone,
 latest_target_zone AS target_zone,
 latest_boundary_type AS boundary_type,
 latest_boundary_evidence AS boundary_evidence`+runtimeOuter+`
FROM (
 SELECT agent_id,event_id,edge_id,
  argMax(occurred_at,received_at) AS event_time,
  argMax(source_node,received_at) AS latest_source_node,
  argMax(target_node,received_at) AS latest_target_node,
  argMax(trace_id,received_at) AS latest_trace_id,
  argMax(span_id,received_at) AS latest_span_id,
  argMax(field_evidence_json,received_at) AS latest_field_evidence_json,
  argMax(evidence_type,received_at) AS latest_evidence_type,
  argMax(confidence,received_at) AS latest_confidence,
  argMax(peer_address,received_at) AS latest_peer_address,
  argMax(client_address,received_at) AS latest_client_address,
  argMax(client_address_source,received_at) AS latest_client_address_source,
  argMax(server_address,received_at) AS latest_server_address,
  argMax(source_zone,received_at) AS latest_source_zone,
  argMax(target_zone,received_at) AS latest_target_zone,
  argMax(boundary_type,received_at) AS latest_boundary_type,
  argMax(boundary_evidence,received_at) AS latest_boundary_evidence`+runtimeInner+`
 FROM wdsp.data_flow_contributions
 WHERE `+where+` AND edge_id = ?
 GROUP BY agent_id,event_id,edge_id
)
WHERE latest_evidence_type NOT IN ('PAIRED_CLIENT','PAIRED_SERVER')
ORDER BY event_time DESC
LIMIT ?`, append(args, edgeID, candidateLimit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type evidenceCandidate struct {
		record    EvidenceRecord
		reference RuntimeFieldReference
		dataTypes []string
	}
	candidates := []evidenceCandidate{}
	candidateTruncated := false
	for rows.Next() {
		var record EvidenceRecord
		var fields string
		var confidence float32
		destinations := []any{&record.AgentID, &record.EventID, &record.EdgeID, &record.OccurredAt,
			&record.ServiceName, &record.TraceID, &record.SpanID, &fields, &record.EvidenceType, &confidence,
			&record.PeerAddress, &record.ClientAddress, &record.ClientAddressSource, &record.ServerAddress,
			&record.SourceZone, &record.TargetZone, &record.BoundaryType, &record.BoundaryEvidence}
		var dataTypesJSON, referenceJSON string
		if runtimeEnabled {
			destinations = append(destinations, &dataTypesJSON, &referenceJSON)
		}
		if err := rows.Scan(destinations...); err != nil {
			return nil, err
		}
		if filterRuntimeDataType && len(candidates) >= runtimeEvidenceCandidateLimit {
			candidateTruncated = true
			break
		}
		record.Confidence = float64(confidence)
		if err := json.Unmarshal([]byte(fields), &record.Fields); err != nil {
			return nil, err
		}
		candidate := evidenceCandidate{record: record}
		if runtimeEnabled {
			candidate.dataTypes = mergeJSONStrings([]string{dataTypesJSON})
			references, err := parseRuntimeFieldReferences([]string{referenceJSON})
			if err != nil {
				return nil, err
			}
			if len(references) == 1 {
				candidate.reference = references[0]
			}
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	references := make([]RuntimeFieldReference, 0, len(candidates))
	for _, candidate := range candidates {
		references = append(references, candidate.reference)
	}
	runtimeFields, err := s.loadRuntimeFields(ctx, filter, references)
	if err != nil {
		return nil, err
	}
	out := []EvidenceRecord{}
	for _, candidate := range candidates {
		record := candidate.record
		matched := runtimeFieldsForReference(runtimeFields, candidate.reference)
		record.Fields = mergeFieldEvidenceLists(record.Fields, matched)
		dataTypes := candidate.dataTypes
		for _, field := range matched {
			dataTypes = appendUniqueString(dataTypes, field.DataType)
		}
		if filterRuntimeDataType && !dataTypeMatches(dataTypes, record.Fields, filter.DataType) {
			continue
		}
		out = append(out, record)
		if len(out) == limit {
			break
		}
	}
	if candidateTruncated && len(out) < limit {
		return nil, ErrRuntimeFieldEvidenceLimit
	}
	return out, nil
}

func (s *CHReader) Quality(ctx context.Context, filter GraphFilter) (DataQuality, error) {
	if err := validateGraphFilter(&filter); err != nil {
		return DataQuality{}, err
	}
	querier, err := s.querier(ctx)
	if err != nil {
		return DataQuality{}, err
	}
	where, args := graphWhere(filter, true)
	rows, err := querier.Query(ctx, `
SELECT countDistinct((agent_id,event_id)),
 countDistinctIf((agent_id,event_id),trace_id != ''),
 countDistinctIf((agent_id,event_id),quality_json LIKE '%"truncated":true%')
FROM wdsp.api_observations
WHERE `+where, args...)
	if err != nil {
		return DataQuality{}, err
	}
	defer rows.Close()
	quality := DataQuality{DataSource: "clickhouse"}
	if rows.Next() {
		if err := rows.Scan(&quality.Observations, &quality.TraceLinked, &quality.Truncated); err != nil {
			return DataQuality{}, err
		}
	}
	if err := rows.Err(); err != nil {
		return DataQuality{}, err
	}
	if quality.Observations > 0 {
		quality.TraceCoverage = float64(quality.TraceLinked) / float64(quality.Observations)
	}
	quality.Partial = quality.TraceLinked < quality.Observations
	quality.Message = "当前时间窗无观测数据"
	if quality.Observations > 0 && quality.Partial {
		quality.Message = "部分观测没有 Trace 关联，当前为部分链路"
	} else if quality.Observations > 0 {
		quality.Message = "观测数据完整度以当前采集覆盖率为准"
	}
	return quality, nil
}

func validateGraphFilter(filter *GraphFilter) error {
	if filter.Start.IsZero() || filter.End.IsZero() || !filter.End.After(filter.Start) {
		return errors.New("invalid dataflow time range")
	}
	if filter.End.Sub(filter.Start) > 31*24*time.Hour {
		return errors.New("dataflow time range cannot exceed 31 days")
	}
	if filter.MaxEdges <= 0 || filter.MaxEdges > 200 {
		filter.MaxEdges = 50
	}
	if filter.View == "" {
		filter.View = "service"
	}
	if filter.View != "service" && filter.View != "network" && filter.View != "boundary" {
		return errors.New("view 仅支持 service/network/boundary")
	}
	return nil
}

func graphWhere(filter GraphFilter, observations bool) (string, []any) {
	return graphWhereForRuntime(filter, observations, false)
}

func graphWhereForRuntime(filter GraphFilter, observations, runtimeEnabled bool) (string, []any) {
	table := "wdsp.data_flow_contributions"
	if observations {
		table = "wdsp.api_observations"
	}
	where := table + ".occurred_at >= ? AND " + table + ".occurred_at < ?"
	args := []any{filter.Start.UTC(), filter.End.UTC()}
	if filter.ApplicationID != nil {
		where += " AND " + table + ".application_id = ?"
		args = append(args, *filter.ApplicationID)
	}
	if !observations && filter.View == "service" {
		where += " AND " + table + ".protocol = 'HTTP' AND " + table + ".source_type = 'SERVICE' AND " + table + ".target_type = 'SERVICE' AND " + table + ".evidence_type = 'OBSERVED_TRACE'"
	}
	if !observations && filter.View == "boundary" {
		where += " AND " + table + ".protocol = 'HTTP' AND " + table + ".source_type IN ('CLIENT','EXTERNAL') AND " + table + ".target_type = 'SERVICE' AND " + table + ".boundary_type IN ('PUBLIC_TO_INTERNAL','UNKNOWN')"
	}
	if filter.Method != "" && !observations {
		where += " AND " + table + ".method = ?"
		args = append(args, filter.Method)
	}
	if filter.DataType != "" && !observations && !runtimeEnabled {
		where += " AND " + table + ".data_types_json LIKE ?"
		args = append(args, "%\""+strings.ToUpper(strings.TrimSpace(filter.DataType))+"\"%")
	}
	return where, args
}

func upsertGraphNode(nodes map[string]*Node, id, name, nodeType string, edge Edge, outgoing bool) {
	node := nodes[id]
	if node == nil {
		node = &Node{ID: id, Name: name, Type: nodeType, Health: "HEALTHY"}
		nodes[id] = node
	}
	node.Calls += edge.Calls
	node.errors += edge.Errors
	if outgoing {
		node.OutgoingCount++
	} else {
		node.IncomingCount++
	}
	zone := edge.TargetZone
	if outgoing {
		zone = edge.SourceZone
	}
	if node.NetworkZone == "" {
		node.NetworkZone = zone
	} else if zone != "" && zone != node.NetworkZone {
		node.NetworkZone = "UNKNOWN"
	}
	if edge.MaxLatencyMS > node.MaxLatencyMS {
		node.MaxLatencyMS = edge.MaxLatencyMS
	}
	if edge.Calls > 0 {
		node.AvgLatencyMS = (node.AvgLatencyMS*float64(node.Calls-edge.Calls) + edge.AvgLatencyMS*float64(edge.Calls)) / float64(node.Calls)
	}
	if node.Calls > 0 {
		rate := float64(node.errors) / float64(node.Calls)
		if rate > 0.10 {
			node.Health = "ERROR"
		} else if rate > 0.05 {
			node.Health = "DEGRADED"
		} else {
			node.Health = "HEALTHY"
		}
		node.ErrorRate = rate
	}
}

func nodeID(nodeType, name string) string {
	return strings.ToLower(nodeType) + ":" + name
}

func edgeID(source, target, protocol string) string {
	return source + "->" + target + "|" + protocol
}

func mergeJSONStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		var items []string
		if json.Unmarshal([]byte(value), &items) != nil {
			continue
		}
		for _, item := range items {
			if !seen[item] {
				seen[item] = true
				out = append(out, item)
			}
		}
	}
	return out
}

func mergeFieldEvidence(values []string) []FieldEvidence {
	out := []FieldEvidence{}
	for _, value := range values {
		var items []FieldEvidence
		if json.Unmarshal([]byte(value), &items) != nil {
			continue
		}
		out = mergeFieldEvidenceLists(out, items)
	}
	return out
}
