package accesslogs

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	flowMaxRows     = 20000
	flowMaxDrillIDs = 100
)

type FlowNode struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Kind            string            `json:"kind"`
	RequestCount    int               `json:"request_count"`
	FieldHits       int64             `json:"field_hits"`
	Verified        bool              `json:"verified"`
	Other           bool              `json:"other"`
	AggregatedNodes int               `json:"aggregated_nodes,omitempty"`
	Filters         map[string]string `json:"filters"`
	RequestIDs      []string          `json:"request_ids,omitempty"`
	DrillExact      bool              `json:"drill_exact"`
	requestSet      map[string]struct{}
}

type FlowEdge struct {
	ID           string            `json:"id"`
	SourceID     string            `json:"source_id"`
	TargetID     string            `json:"target_id"`
	RequestCount int               `json:"request_count"`
	FieldHits    int64             `json:"field_hits"`
	Filters      map[string]string `json:"filters"`
	RequestIDs   []string          `json:"request_ids,omitempty"`
	DrillExact   bool              `json:"drill_exact"`
	requestSet   map[string]struct{}
}

type FlowResult struct {
	Nodes                 []FlowNode `json:"nodes"`
	Edges                 []FlowEdge `json:"edges"`
	RequestCount          int        `json:"request_count"`
	SensitiveRequestCount int        `json:"sensitive_request_count"`
	StartTime             time.Time  `json:"start_time"`
	EndTime               time.Time  `json:"end_time"`
	Truncated             bool       `json:"truncated"`
	DataSource            string     `json:"data_source"`
}

type flowRow struct {
	requestID, sourceIP, applicationID, applicationName string
	endpoint, identity, jwtStatus                       string
	eventID, fieldPath, dataType, direction, ruleID     string
}

type flowAggregate struct {
	requests map[string]struct{}
	hits     int64
	filters  map[string]string
}

func newFlowAggregate(filters map[string]string) *flowAggregate {
	return &flowAggregate{requests: make(map[string]struct{}), filters: copyStringMap(filters)}
}

func (a *flowAggregate) add(requestID string, hits int64) {
	a.requests[requestID] = struct{}{}
	a.hits += hits
}

type flowBuilder struct {
	nodes       map[string]*flowAggregate
	edges       map[string]*flowAggregate
	nodeMeta    map[string]FlowNode
	edgeMeta    map[string]FlowEdge
	allRequests map[string]struct{}
	sensitive   map[string]struct{}
}

func (s *Store) Flow(ctx context.Context, filter ListFilter, nodeLimit int) (FlowResult, error) {
	if filter.StartTime == nil || filter.EndTime == nil || !filter.EndTime.After(*filter.StartTime) {
		return FlowResult{}, fmt.Errorf("flow time range is required")
	}
	if nodeLimit <= 0 || nodeLimit > 20 {
		nodeLimit = 8
	}
	where, args := buildListWhere(filter)
	args = append(args, flowMaxRows+1)
	rows, err := s.db.Query(ctx, `
WITH filtered_logs AS (SELECT * FROM access_logs WHERE `+where+`)
SELECT filtered_logs.request_id, host(filtered_logs.client_ip),
 COALESCE(filtered_logs.application_id::text,''), COALESCE(applications.name,NULLIF(filtered_logs.domain,''),'未归属应用'),
 COALESCE(NULLIF(filtered_logs.endpoint_key,''),filtered_logs.request_method || ' ' || COALESCE(NULLIF(filtered_logs.path_template,''),NULLIF(filtered_logs.request_path,''),NULLIF(split_part(filtered_logs.request_uri,'?',1),''),'/')),
 COALESCE(runtime.identity_fingerprint,''), COALESCE(runtime.jwt_verification->>'status',''),
 COALESCE(runtime.id::text,''),
 CASE WHEN detail.payload IS NULL THEN '' WHEN COALESCE(detail.payload->'evidence'->>'location','')=''
      THEN detail.payload->'evidence'->>'field'
      ELSE detail.payload->'evidence'->>'location' || '.' || (detail.payload->'evidence'->>'field') END,
 COALESCE(detail.payload->'evidence'->>'data_type',''),
 CASE WHEN detail.payload IS NULL THEN '' WHEN UPPER(COALESCE(detail.payload->'evidence'->>'direction','REQUEST')) IN ('REQUEST','RESPONSE')
      THEN UPPER(COALESCE(detail.payload->'evidence'->>'direction','REQUEST')) ELSE '' END,
 COALESCE(detail.payload->>'rule_id','')
FROM filtered_logs
LEFT JOIN applications ON applications.id=filtered_logs.application_id
LEFT JOIN api_runtime_events runtime ON runtime.request_id=filtered_logs.request_id
LEFT JOIN LATERAL jsonb_array_elements(COALESCE(runtime.details_json,'[]'::jsonb)) WITH ORDINALITY detail(payload,ordinal)
 ON detail.payload->>'detector'='sensitive_data' AND COALESCE(detail.payload->'evidence'->>'field','')<>''
ORDER BY filtered_logs.occurred_at DESC,filtered_logs.request_id,runtime.id,detail.ordinal
LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return FlowResult{}, err
	}
	defer rows.Close()
	builder := &flowBuilder{nodes: make(map[string]*flowAggregate), edges: make(map[string]*flowAggregate),
		nodeMeta: make(map[string]FlowNode), edgeMeta: make(map[string]FlowEdge),
		allRequests: make(map[string]struct{}), sensitive: make(map[string]struct{})}
	rowCount := 0
	for rows.Next() {
		var row flowRow
		if err := rows.Scan(&row.requestID, &row.sourceIP, &row.applicationID, &row.applicationName, &row.endpoint,
			&row.identity, &row.jwtStatus, &row.eventID, &row.fieldPath, &row.dataType, &row.direction, &row.ruleID); err != nil {
			return FlowResult{}, err
		}
		rowCount++
		builder.addRow(row, filter)
	}
	if err := rows.Err(); err != nil {
		return FlowResult{}, err
	}
	result := builder.result(*filter.StartTime, *filter.EndTime, nodeLimit)
	result.Truncated = rowCount > flowMaxRows
	return result, nil
}

func (b *flowBuilder) addRow(row flowRow, filter ListFilter) {
	if row.requestID == "" {
		return
	}
	b.allRequests[row.requestID] = struct{}{}
	if row.sourceIP == "" {
		row.sourceIP = "未识别来源"
	}
	if len(row.identity) > 128 {
		row.identity = ""
	}
	fieldRunes := []rune(row.fieldPath)
	if len(fieldRunes) > 512 {
		row.fieldPath = string(fieldRunes[:512])
	}
	if row.fieldPath != "" && row.direction != "" {
		b.sensitive[row.requestID] = struct{}{}
	}
	base := flowFilters(filter)
	sourceFilters := copyStringMap(base)
	if row.sourceIP != "未识别来源" {
		sourceFilters["client_ip"] = row.sourceIP
	}
	sourceID := b.node("SOURCE", row.sourceIP, row.sourceIP, false, sourceFilters)
	b.nodes[sourceID].add(row.requestID, 0)
	originID := sourceID
	if row.identity != "" {
		name := row.identity
		if len(name) > 12 {
			name = name[:12]
		}
		originID = b.node("ACCOUNT", row.identity, "身份 "+name, row.jwtStatus == "VERIFIED", mergeFilters(base, map[string]string{"identity_fingerprint": row.identity}))
		b.nodes[originID].add(row.requestID, 0)
		b.link(sourceID, originID, row, filter, false)
	}
	applicationFilter := copyStringMap(base)
	if row.applicationID != "" {
		applicationFilter["application_id"] = row.applicationID
	}
	applicationID := b.node("APPLICATION", row.applicationID+"\x00"+row.applicationName, row.applicationName, false, applicationFilter)
	apiID := b.node("API", row.endpoint, row.endpoint, false, mergeFilters(base, map[string]string{"endpoint_key": row.endpoint}))
	b.nodes[applicationID].add(row.requestID, 0)
	b.nodes[apiID].add(row.requestID, 0)
	b.link(applicationID, apiID, row, filter, false)
	if row.fieldPath == "" || row.direction == "" {
		b.link(originID, applicationID, row, filter, false)
		return
	}
	fieldID := b.node(row.direction+"_FIELD", row.direction+"\x00"+row.fieldPath+"\x00"+row.dataType,
		row.fieldPath+" · "+flowDataType(row.dataType), false, flowFieldFilters(base, row))
	fieldHits := int64(0)
	if row.eventID != "" {
		fieldHits = 1
	}
	b.nodes[fieldID].add(row.requestID, fieldHits)
	if row.direction == "REQUEST" {
		b.link(originID, fieldID, row, filter, true)
		b.link(fieldID, applicationID, row, filter, true)
	} else {
		b.link(apiID, fieldID, row, filter, true)
	}
}

func (b *flowBuilder) node(kind, key, name string, verified bool, filters map[string]string) string {
	id := kind + ":" + key
	if _, exists := b.nodes[id]; !exists {
		b.nodes[id] = newFlowAggregate(filters)
		b.nodeMeta[id] = FlowNode{ID: id, Name: name, Kind: kind, Verified: verified}
	}
	return id
}

func (b *flowBuilder) link(sourceID, targetID string, row flowRow, filter ListFilter, fieldHit bool) {
	id := sourceID + "->" + targetID
	if _, exists := b.edges[id]; !exists {
		filters := flowFilters(filter)
		if src := b.nodes[sourceID]; src != nil {
			filters = mergeFilters(filters, src.filters)
		}
		if dst := b.nodes[targetID]; dst != nil {
			filters = mergeFilters(filters, dst.filters)
		}
		if row.applicationID != "" {
			filters["application_id"] = row.applicationID
		}
		filters["endpoint_key"] = row.endpoint
		b.edges[id] = newFlowAggregate(filters)
		b.edgeMeta[id] = FlowEdge{ID: id, SourceID: sourceID, TargetID: targetID}
	}
	hits := int64(0)
	if fieldHit && row.eventID != "" {
		hits = 1
	}
	b.edges[id].add(row.requestID, hits)
}

func (b *flowBuilder) result(start, end time.Time, nodeLimit int) FlowResult {
	result := FlowResult{StartTime: start, EndTime: end, RequestCount: len(b.allRequests), SensitiveRequestCount: len(b.sensitive),
		DataSource: "access_logs+api_runtime_events", Nodes: make([]FlowNode, 0, len(b.nodes)), Edges: make([]FlowEdge, 0, len(b.edges))}
	for id, aggregate := range b.nodes {
		node := b.nodeMeta[id]
		node.RequestCount = len(aggregate.requests)
		node.FieldHits = aggregate.hits
		node.Filters = aggregate.filters
		node.RequestIDs, node.DrillExact = flowRequestIDs(aggregate.requests)
		node.requestSet = aggregate.requests
		result.Nodes = append(result.Nodes, node)
	}
	for id, aggregate := range b.edges {
		edge := b.edgeMeta[id]
		edge.RequestCount = len(aggregate.requests)
		edge.FieldHits = aggregate.hits
		edge.Filters = aggregate.filters
		edge.RequestIDs, edge.DrillExact = flowRequestIDs(aggregate.requests)
		edge.requestSet = aggregate.requests
		result.Edges = append(result.Edges, edge)
	}
	return limitFlowNodes(result, nodeLimit)
}

func flowRequestIDs(requests map[string]struct{}) ([]string, bool) {
	ids := make([]string, 0, len(requests))
	for id := range requests {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > flowMaxDrillIDs {
		return nil, false
	}
	return ids, true
}

func limitFlowNodes(result FlowResult, limit int) FlowResult {
	groups := make(map[string][]FlowNode)
	for _, node := range result.Nodes {
		groups[node.Kind] = append(groups[node.Kind], node)
	}
	mapping := make(map[string]string)
	kept := make([]FlowNode, 0, len(result.Nodes))
	for kind, nodes := range groups {
		sort.Slice(nodes, func(i, j int) bool {
			if nodes[i].RequestCount != nodes[j].RequestCount {
				return nodes[i].RequestCount > nodes[j].RequestCount
			}
			return nodes[i].Name < nodes[j].Name
		})
		if len(nodes) <= limit {
			kept = append(kept, nodes...)
			continue
		}
		result.Truncated = true
		kept = append(kept, nodes[:limit]...)
		other := FlowNode{ID: "OTHER:" + kind, Name: "其他", Kind: kind, Other: true, AggregatedNodes: len(nodes) - limit,
			Filters: make(map[string]string)}
		requests := make(map[string]struct{})
		for _, node := range nodes[limit:] {
			mapping[node.ID] = other.ID
			other.FieldHits += node.FieldHits
			for requestID := range node.requestSet {
				requests[requestID] = struct{}{}
			}
		}
		other.RequestCount = len(requests)
		other.RequestIDs, other.DrillExact = flowRequestIDs(requests)
		other.requestSet = requests
		kept = append(kept, other)
	}
	edges := make(map[string]FlowEdge)
	requestSets := make(map[string]map[string]struct{})
	for _, edge := range result.Edges {
		source := edge.SourceID
		target := edge.TargetID
		if replacement := mapping[source]; replacement != "" {
			source = replacement
		}
		if replacement := mapping[target]; replacement != "" {
			target = replacement
		}
		id := source + "->" + target
		current, exists := edges[id]
		if !exists {
			current = FlowEdge{ID: id, SourceID: source, TargetID: target, Filters: copyStringMap(edge.Filters)}
			requestSets[id] = make(map[string]struct{})
		}
		current.FieldHits += edge.FieldHits
		for requestID := range edge.requestSet {
			requestSets[id][requestID] = struct{}{}
		}
		current.Filters = commonFilters(current.Filters, edge.Filters)
		edges[id] = current
	}
	result.Nodes = kept
	result.Edges = make([]FlowEdge, 0, len(edges))
	for id, edge := range edges {
		edge.RequestCount = len(requestSets[id])
		edge.RequestIDs, edge.DrillExact = flowRequestIDs(requestSets[id])
		result.Edges = append(result.Edges, edge)
	}
	sort.Slice(result.Nodes, func(i, j int) bool {
		if result.Nodes[i].Kind != result.Nodes[j].Kind {
			return result.Nodes[i].Kind < result.Nodes[j].Kind
		}
		return result.Nodes[i].Name < result.Nodes[j].Name
	})
	sort.Slice(result.Edges, func(i, j int) bool { return result.Edges[i].ID < result.Edges[j].ID })
	return result
}

func flowFilters(filter ListFilter) map[string]string {
	result := make(map[string]string)
	if filter.StartTime != nil {
		result["start_time"] = filter.StartTime.UTC().Format(time.RFC3339Nano)
	}
	if filter.EndTime != nil {
		result["end_time"] = filter.EndTime.UTC().Format(time.RFC3339Nano)
	}
	for key, value := range map[string]string{"domain": filter.Domain, "client_ip": filter.ClientIP, "method": filter.Method,
		"uri": filter.URI, "waf_action": filter.WAFAction, "request_id": filter.RequestID, "trace_id": filter.TraceID,
		"identity_fingerprint": filter.IdentityFingerprint, "rule_id": filter.RuleID, "endpoint_key": filter.EndpointKey,
		"field_path": filter.FieldPath, "data_type": filter.DataType, "direction": filter.Direction} {
		if value != "" {
			result[key] = value
		}
	}
	if filter.ApplicationID != nil {
		result["application_id"] = filter.ApplicationID.String()
	}
	if filter.Status != nil {
		result["status"] = fmt.Sprint(*filter.Status)
	}
	if len(filter.RequestIDs) > 0 {
		result["request_ids"] = strings.Join(filter.RequestIDs, ",")
	}
	return result
}

func flowFieldFilters(base map[string]string, row flowRow) map[string]string {
	result := mergeFilters(base, map[string]string{"field_path": row.fieldPath, "direction": row.direction})
	if row.dataType != "" {
		result["data_type"] = row.dataType
	}
	if row.ruleID != "" && base["rule_id"] == "" {
		result["rule_id"] = row.ruleID
	}
	return result
}

func flowDataType(value string) string {
	if value == "" {
		return "未知类型"
	}
	return value
}

func copyStringMap(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func mergeFilters(left, right map[string]string) map[string]string {
	result := copyStringMap(left)
	for key, value := range right {
		if current := result[key]; current == "" || current == value {
			result[key] = value
		} else {
			delete(result, key)
		}
	}
	return result
}

func commonFilters(left, right map[string]string) map[string]string {
	result := make(map[string]string)
	for key, value := range left {
		if right[key] == value {
			result[key] = value
		}
	}
	return result
}
