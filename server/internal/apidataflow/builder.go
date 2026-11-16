package apidataflow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/agents"
	"github.com/jiuzhang-waf/server/internal/apigeo"
)

type FieldEvidence struct {
	Side      string `json:"side"`
	Path      string `json:"path"`
	DataType  string `json:"data_type"`
	ValueHMAC string `json:"value_hmac,omitempty"`
	HMACKeyID string `json:"hmac_key_id,omitempty"`
	Match     string `json:"match"`
}

type Contribution struct {
	AgentID             uuid.UUID
	EventID             string
	EdgeID              string
	OccurredAt          time.Time
	ApplicationID       *uuid.UUID
	SourceNode          string
	SourceType          string
	TargetNode          string
	TargetType          string
	Protocol            string
	Method              string
	PathTemplate        string
	Status              int
	LatencyMS           int64
	Error               bool
	CountWeight         uint64
	DataTypes           []string
	Fields              []FieldEvidence
	EvidenceType        string
	Confidence          float64
	TraceID             string
	SpanID              string
	PeerAddress         string
	ClientAddress       string
	ClientAddressSource string
	ServerAddress       string
	SourceZone          string
	TargetZone          string
	BoundaryType        string
	BoundaryEvidence    string
}

type observationKey struct {
	agentID uuid.UUID
	eventID string
}

type observationPair struct {
	client agents.APIObservationEnvelope
	server agents.APIObservationEnvelope
}

// BuildContributions correlates one immutable observation snapshot. The Kafka worker
// supplies a persisted Trace snapshot so pairing does not depend on batch boundaries.
func BuildContributions(records []agents.APIObservationEnvelope) []Contribution {
	out, _ := buildContributions(records)
	return out
}

func buildContributions(records []agents.APIObservationEnvelope) ([]Contribution, map[observationKey]observationPair) {
	sorted := append([]agents.APIObservationEnvelope(nil), records...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].OccurredAt.Equal(sorted[j].OccurredAt) {
			return sorted[i].EventID < sorted[j].EventID
		}
		return sorted[i].OccurredAt.Before(sorted[j].OccurredAt)
	})
	pairs := pairObservations(sorted)
	pairedServers := map[observationKey]bool{}
	for _, pair := range pairs {
		pairedServers[keyForObservation(pair.server)] = true
	}
	out := make([]Contribution, 0, len(sorted))
	for _, record := range sorted {
		switch record.HTTP.Direction {
		case "CLIENT":
			target := firstNonEmpty(record.HTTP.PeerService, record.HTTP.Host, "unknown")
			targetType := "EXTERNAL"
			paired, ok := pairs[keyForObservation(record)]
			fields := append(observedFields(record, "REQUEST"), observedFields(record, "RESPONSE")...)
			evidence := "OBSERVED"
			confidence := 0.85
			if ok {
				targetType = "SERVICE"
				evidence = "OBSERVED_TRACE"
				confidence = 0.98
				requestFields := correlateFields(observedFields(record, "REQUEST"), observedFields(paired.server, "REQUEST"))
				fields = append(requestFields, observedFields(record, "RESPONSE")...)
				fields = append(fields, observedFields(paired.server, "RESPONSE")...)
			}
			out = append(out, newContribution(record, record.Service.Name, "SERVICE", target, targetType, "HTTP", fields, evidence, confidence, 1))
		case "SERVER":
			if pairedServers[keyForObservation(record)] {
				continue
			}
			out = append(out, standaloneServerContribution(record, "OBSERVED_SERVER", observedFields(record, "REQUEST"), 1))
		case "PRODUCER":
			system := strings.ToUpper(firstNonEmpty(record.HTTP.MessagingSystem, "kafka"))
			target := strings.ToLower(firstNonEmpty(record.HTTP.MessagingSystem, "kafka")) + "/" + record.HTTP.MessagingDestination
			out = append(out, newContribution(record, record.Service.Name, "SERVICE", target, system, system, messageFields(record), "OBSERVED_MQ", 0.95, 1))
		case "CONSUMER":
			system := strings.ToUpper(firstNonEmpty(record.HTTP.MessagingSystem, "kafka"))
			source := strings.ToLower(firstNonEmpty(record.HTTP.MessagingSystem, "kafka")) + "/" + record.HTTP.MessagingDestination
			out = append(out, newContribution(record, source, system, record.Service.Name, "SERVICE", system, messageFields(record), "OBSERVED_MQ", 0.95, 1))
		}
	}
	out = append(out, correlatedResponseContributions(sorted)...)
	return out, pairs
}

func pairObservations(records []agents.APIObservationEnvelope) map[observationKey]observationPair {
	servers := map[string][]agents.APIObservationEnvelope{}
	for _, record := range records {
		if record.Trace.TraceID != "" && record.HTTP.Direction == "SERVER" {
			servers[record.Trace.TraceID] = append(servers[record.Trace.TraceID], record)
		}
	}
	pairs := map[observationKey]observationPair{}
	usedServers := map[observationKey]bool{}
	for _, client := range records {
		if client.Trace.TraceID == "" || client.HTTP.Direction != "CLIENT" || client.Trace.SpanID == "" {
			continue
		}
		target := firstNonEmpty(client.HTTP.PeerService, client.HTTP.Host, "unknown")
		for i := range servers[client.Trace.TraceID] {
			server := servers[client.Trace.TraceID][i]
			key := keyForObservation(server)
			if usedServers[key] || server.Service.Name != target || server.Trace.ParentSpanID != client.Trace.SpanID {
				continue
			}
			pairs[keyForObservation(client)] = observationPair{client: client, server: server}
			usedServers[key] = true
			break
		}
	}
	for _, client := range records {
		clientKey := keyForObservation(client)
		if client.Trace.TraceID == "" || client.HTTP.Direction != "CLIENT" {
			continue
		}
		if _, ok := pairs[clientKey]; ok {
			continue
		}
		target := firstNonEmpty(client.HTTP.PeerService, client.HTTP.Host, "unknown")
		var first, firstAfter *agents.APIObservationEnvelope
		for i := range servers[client.Trace.TraceID] {
			candidate := &servers[client.Trace.TraceID][i]
			if usedServers[keyForObservation(*candidate)] || candidate.Service.Name != target {
				continue
			}
			if first == nil {
				first = candidate
			}
			if firstAfter == nil && !candidate.OccurredAt.Before(client.OccurredAt) {
				firstAfter = candidate
				break
			}
		}
		candidate := first
		if firstAfter != nil {
			candidate = firstAfter
		}
		if candidate != nil {
			pairs[clientKey] = observationPair{client: client, server: *candidate}
			usedServers[keyForObservation(*candidate)] = true
		}
	}
	return pairs
}

func keyForObservation(record agents.APIObservationEnvelope) observationKey {
	return observationKey{agentID: record.AgentID, eventID: record.EventID}
}

func standaloneServerContribution(record agents.APIObservationEnvelope, evidence string, fields []FieldEvidence, weight uint64) Contribution {
	source := firstNonEmpty(record.HTTP.PeerService, record.HTTP.PeerAddress, "external")
	sourceType := "EXTERNAL"
	if record.HTTP.PeerService != "" {
		sourceType = "SERVICE"
	} else if record.HTTP.PeerAddress != "" {
		sourceType = "CLIENT"
	}
	confidence := 0.80
	if evidence != "OBSERVED_SERVER" {
		confidence = 0
	}
	return newContribution(record, source, sourceType, record.Service.Name, "SERVICE", "HTTP", fields, evidence, confidence, weight)
}

func persistentContributions(records []agents.APIObservationEnvelope) []Contribution {
	out, pairs := buildContributions(records)
	for _, pair := range pairs {
		client := pair.client
		target := firstNonEmpty(client.HTTP.PeerService, client.HTTP.Host, "unknown")
		clientFields := append(observedFields(client, "REQUEST"), observedFields(client, "RESPONSE")...)
		out = append(out, newContribution(client, client.Service.Name, "SERVICE", target, "EXTERNAL", "HTTP", clientFields, "PAIRED_CLIENT", 0, 0))
		out = append(out, standaloneServerContribution(pair.server, "PAIRED_SERVER", observedFields(pair.server, "REQUEST"), 0))
	}
	return out
}

func newContribution(record agents.APIObservationEnvelope, source, sourceType, target, targetType, protocol string, fields []FieldEvidence, evidence string, confidence float64, weight uint64) Contribution {
	application := ""
	if record.ApplicationID != nil {
		application = record.ApplicationID.String()
	}
	edge := sha256.Sum256([]byte(application + "\x00" + source + "\x00" + sourceType + "\x00" + target + "\x00" + targetType + "\x00" + protocol))
	boundary := classifyNetworkBoundary(record.HTTP)
	return Contribution{
		AgentID: record.AgentID, EventID: record.EventID, EdgeID: hex.EncodeToString(edge[:]),
		OccurredAt: record.OccurredAt.UTC(), ApplicationID: record.ApplicationID,
		SourceNode: source, SourceType: sourceType, TargetNode: target, TargetType: targetType,
		Protocol: protocol, Method: record.HTTP.Method, PathTemplate: record.HTTP.PathTemplate,
		Status: record.HTTP.Status, LatencyMS: record.HTTP.LatencyMS,
		Error: record.HTTP.Status >= 500, CountWeight: weight,
		DataTypes: uniqueDataTypes(fields), Fields: fields, EvidenceType: evidence, Confidence: confidence,
		TraceID: record.Trace.TraceID, SpanID: record.Trace.SpanID,
		PeerAddress: record.HTTP.PeerAddress, ClientAddress: boundary.clientAddress,
		ClientAddressSource: boundary.clientAddressSource, ServerAddress: record.HTTP.ServerAddress,
		SourceZone: boundary.sourceZone, TargetZone: boundary.targetZone,
		BoundaryType: boundary.boundaryType, BoundaryEvidence: boundary.boundaryEvidence,
	}
}

type networkBoundary struct {
	clientAddress       string
	clientAddressSource string
	sourceZone          string
	targetZone          string
	boundaryType        string
	boundaryEvidence    string
}

func classifyNetworkBoundary(http agents.APIObservationHTTP) networkBoundary {
	clientAddress := http.ClientAddress
	clientAddressSource := http.ClientAddressSource
	if clientAddress == "" && http.PeerAddress != "" && (clientAddressSource == "" || clientAddressSource == "DIRECT_PEER") {
		clientAddress = http.PeerAddress
		clientAddressSource = "DIRECT_PEER"
	}
	if clientAddress != "" && clientAddressSource == "" {
		clientAddressSource = "UNKNOWN"
	}
	result := networkBoundary{
		clientAddress: clientAddress, clientAddressSource: clientAddressSource,
		targetZone: networkZone(http.ServerAddress), boundaryType: "UNKNOWN",
	}
	trustedSource := trustedClientAddressSource(clientAddressSource)
	if trustedSource {
		result.sourceZone = networkZone(clientAddress)
	} else {
		result.sourceZone = "UNKNOWN"
	}
	switch {
	case clientAddress == "":
		result.boundaryEvidence = "MISSING_CLIENT_ADDRESS"
	case !trustedSource:
		result.boundaryEvidence = "UNTRUSTED_CLIENT_SOURCE"
	case http.ServerAddress == "":
		result.boundaryEvidence = "MISSING_SERVER_ADDRESS"
	default:
		result.boundaryEvidence = clientAddressSource
	}
	if trustedSource && result.sourceZone == apigeo.IPScopePublic && result.targetZone == apigeo.IPScopeInternal {
		result.boundaryType = "PUBLIC_TO_INTERNAL"
	}
	return result
}

func trustedClientAddressSource(source string) bool {
	switch source {
	case "DIRECT_PEER", "TRUSTED_PROXY", "GATEWAY":
		return true
	default:
		return false
	}
}

func networkZone(address string) string {
	scope := apigeo.ClassifyIPScope(address)
	if scope == apigeo.IPScopePublic || scope == apigeo.IPScopeInternal {
		return scope
	}
	return "UNKNOWN"
}

func observedFields(record agents.APIObservationEnvelope, side string) []FieldEvidence {
	out := []FieldEvidence{}
	for _, field := range record.Fields {
		if field.Side != side {
			continue
		}
		out = append(out, FieldEvidence{Side: side, Path: field.Path, DataType: field.DataType, ValueHMAC: field.ValueHMAC, HMACKeyID: field.HMACKeyID, Match: "OBSERVED"})
	}
	return out
}

func messageFields(record agents.APIObservationEnvelope) []FieldEvidence {
	fields := observedFields(record, "MESSAGE")
	if len(fields) == 0 {
		fields = observedFields(record, "REQUEST")
	}
	return fields
}

func correlateFields(observed, downstream []FieldEvidence) []FieldEvidence {
	byHMAC := map[string]bool{}
	for _, field := range downstream {
		if field.ValueHMAC != "" {
			byHMAC[field.HMACKeyID+":"+field.ValueHMAC] = true
		}
	}
	for i := range observed {
		if observed[i].ValueHMAC != "" && byHMAC[observed[i].HMACKeyID+":"+observed[i].ValueHMAC] {
			observed[i].Match = "CORRELATED_FIELD"
		}
	}
	return observed
}

func correlatedResponseContributions(records []agents.APIObservationEnvelope) []Contribution {
	out := []Contribution{}
	for _, source := range records {
		if source.HTTP.Direction != "SERVER" || source.Trace.TraceID == "" {
			continue
		}
		sourceFields := observedFields(source, "RESPONSE")
		if len(sourceFields) == 0 {
			continue
		}
		for _, target := range records {
			if target.HTTP.Direction != "CLIENT" || target.Trace.TraceID != source.Trace.TraceID || target.Service.Name == source.Service.Name || target.OccurredAt.Before(source.OccurredAt) {
				continue
			}
			targetFields := observedFields(target, "REQUEST")
			matched := []FieldEvidence{}
			for _, sourceField := range sourceFields {
				if sourceField.ValueHMAC == "" {
					continue
				}
				for _, targetField := range targetFields {
					if sourceField.ValueHMAC == targetField.ValueHMAC && sourceField.HMACKeyID == targetField.HMACKeyID && sourceField.DataType == targetField.DataType {
						matched = append(matched, FieldEvidence{Side: "RESPONSE_TO_REQUEST", Path: sourceField.Path + " -> " + targetField.Path, DataType: sourceField.DataType, ValueHMAC: sourceField.ValueHMAC, HMACKeyID: sourceField.HMACKeyID, Match: "CORRELATED_FIELD"})
					}
				}
			}
			if len(matched) > 0 {
				out = append(out, newContribution(source, source.Service.Name, "SERVICE", target.Service.Name, "SERVICE", "HTTP", matched, "CORRELATED_FIELD", 0.95, 0))
			}
		}
	}
	return out
}

func uniqueDataTypes(fields []FieldEvidence) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, field := range fields {
		if field.DataType != "" && !seen[field.DataType] {
			seen[field.DataType] = true
			out = append(out, field.DataType)
		}
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func fieldEvidenceJSON(fields []FieldEvidence) string {
	data, _ := json.Marshal(fields)
	return string(data)
}
