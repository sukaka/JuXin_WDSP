package apidataflow

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	runtimeFieldBatchSize         = 200
	runtimeFieldBatchRowLimit     = 1000
	maxRuntimeFieldReferences     = 4096
	runtimeGraphCandidateLimit    = 500
	runtimeGraphReferencesPerEdge = 2000
	runtimeEvidenceCandidateLimit = 2000
	maxRuntimeFieldPathBytes      = 512
)

const runtimeFieldQualityMessage = "网关敏感字段未完整关联，请缩小时间窗/稍后重试"

var (
	ErrRuntimeFieldReferenceLimit = errors.New("runtime field reference limit exceeded; narrow the dataflow query")
	ErrRuntimeFieldRowLimit       = errors.New("runtime field event limit exceeded; narrow the dataflow query")
	ErrRuntimeFieldGraphLimit     = errors.New("runtime field graph scan limit exceeded; narrow the dataflow query")
	ErrRuntimeFieldEvidenceLimit  = errors.New("runtime field evidence scan limit exceeded; narrow the dataflow query")
)

type RuntimeFieldReference struct {
	TraceID       string
	Method        string
	PathTemplate  string
	ApplicationID *uuid.UUID
}

type RuntimeFieldQuery struct {
	Start      time.Time
	End        time.Time
	References []RuntimeFieldReference
}

type RuntimeFieldRecord struct {
	Reference RuntimeFieldReference
	Fields    []FieldEvidence
}

type RuntimeFieldReader interface {
	ReadRuntimeFields(context.Context, RuntimeFieldQuery) ([]RuntimeFieldRecord, error)
}

type runtimeFieldRows interface {
	Next() bool
	Scan(...any) error
	Close() error
	Err() error
}

type runtimeFieldQueryFunc func(context.Context, string, ...any) (runtimeFieldRows, error)

type PGRuntimeFieldReader struct {
	query runtimeFieldQueryFunc
}

func NewPGRuntimeFieldReader(db *sql.DB) *PGRuntimeFieldReader {
	reader := &PGRuntimeFieldReader{}
	if db != nil {
		reader.query = func(ctx context.Context, query string, args ...any) (runtimeFieldRows, error) {
			return db.QueryContext(ctx, query, args...)
		}
	}
	return reader
}

func (r *PGRuntimeFieldReader) ReadRuntimeFields(ctx context.Context, query RuntimeFieldQuery) ([]RuntimeFieldRecord, error) {
	if r == nil || r.query == nil {
		return nil, errors.New("runtime field PostgreSQL reader is not configured")
	}
	if query.Start.IsZero() || query.End.IsZero() || !query.End.After(query.Start) {
		return nil, errors.New("invalid runtime field time range")
	}
	references := normalizeRuntimeFieldReferences(query.References)
	if len(references) == 0 {
		return []RuntimeFieldRecord{}, nil
	}
	if len(references) > maxRuntimeFieldReferences {
		return nil, ErrRuntimeFieldReferenceLimit
	}
	requested := make(map[string]RuntimeFieldReference, len(references))
	for _, reference := range references {
		requested[runtimeFieldKey(reference)] = reference
	}
	fieldsByKey := map[string][]FieldEvidence{}
	totalRows := 0
	for start := 0; start < len(references); start += runtimeFieldBatchSize {
		end := start + runtimeFieldBatchSize
		if end > len(references) {
			end = len(references)
		}
		traceIDs := uniqueRuntimeTraceIDs(references[start:end])
		placeholders := make([]string, len(traceIDs))
		args := []any{query.Start.UTC(), query.End.UTC()}
		for i, traceID := range traceIDs {
			placeholders[i] = fmt.Sprintf("$%d", i+3)
			args = append(args, traceID)
		}
		limit := runtimeFieldBatchRowLimit + 1
		if remaining := maxRuntimeFieldReferences - totalRows; remaining < limit {
			limit = remaining + 1
		}
		args = append(args, limit)
		statement := fmt.Sprintf(`
SELECT trace_id, endpoint_key, method, application_id, details_json
FROM api_runtime_events
WHERE occurred_at >= $1 AND occurred_at < $2
  AND trace_id IN (%s)
  AND details_json @> '[{"detector":"sensitive_data"}]'::jsonb
ORDER BY occurred_at ASC, id ASC
LIMIT $%d`, strings.Join(placeholders, ","), len(args))
		rows, err := r.query(ctx, statement, args...)
		if err != nil {
			return nil, fmt.Errorf("query runtime fields: %w", err)
		}
		batchRows := 0
		for rows.Next() {
			batchRows++
			totalRows++
			if batchRows > runtimeFieldBatchRowLimit || totalRows > maxRuntimeFieldReferences {
				_ = rows.Close()
				return nil, ErrRuntimeFieldRowLimit
			}
			var traceID, method, applicationID sql.NullString
			var endpointKey string
			var details []byte
			if err := rows.Scan(&traceID, &endpointKey, &method, &applicationID, &details); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("scan runtime field event: %w", err)
			}
			reference, ok := runtimeFieldEventReference(traceID, endpointKey, method, applicationID)
			if !ok {
				continue
			}
			key := runtimeFieldKey(reference)
			if _, ok := requested[key]; !ok {
				continue
			}
			fields, err := extractRuntimeFieldEvidence(details)
			if err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("parse runtime field event: %w", err)
			}
			fieldsByKey[key] = mergeRuntimeFieldLists(fieldsByKey[key], fields)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("read runtime field events: %w", err)
		}
		if err := rows.Close(); err != nil {
			return nil, fmt.Errorf("close runtime field events: %w", err)
		}
	}
	out := make([]RuntimeFieldRecord, 0, len(fieldsByKey))
	for _, reference := range references {
		key := runtimeFieldKey(reference)
		if fields := fieldsByKey[key]; len(fields) > 0 {
			out = append(out, RuntimeFieldRecord{Reference: reference, Fields: fields})
		}
	}
	return out, nil
}

func runtimeFieldEventReference(traceID sql.NullString, endpointKey string, method, applicationID sql.NullString) (RuntimeFieldReference, bool) {
	if !traceID.Valid || strings.TrimSpace(traceID.String) == "" {
		return RuntimeFieldReference{}, false
	}
	endpointMethod, endpointPath, ok := strings.Cut(strings.TrimSpace(endpointKey), " ")
	if !ok {
		return RuntimeFieldReference{}, false
	}
	reference := normalizeRuntimeFieldReference(RuntimeFieldReference{
		TraceID: traceID.String, Method: endpointMethod, PathTemplate: endpointPath,
	})
	if reference.Method == "" || reference.PathTemplate == "" {
		return RuntimeFieldReference{}, false
	}
	if method.Valid && strings.TrimSpace(method.String) != "" && strings.ToUpper(strings.TrimSpace(method.String)) != reference.Method {
		return RuntimeFieldReference{}, false
	}
	if applicationID.Valid && strings.TrimSpace(applicationID.String) != "" {
		parsed, err := uuid.Parse(strings.TrimSpace(applicationID.String))
		if err != nil {
			return RuntimeFieldReference{}, false
		}
		reference.ApplicationID = &parsed
	}
	return reference, true
}

func extractRuntimeFieldEvidence(detailsJSON []byte) ([]FieldEvidence, error) {
	var details []struct {
		Detector string            `json:"detector"`
		Evidence map[string]string `json:"evidence"`
	}
	if err := json.Unmarshal(detailsJSON, &details); err != nil {
		return nil, fmt.Errorf("parse details_json: %w", err)
	}
	fields := []FieldEvidence{}
	for _, detail := range details {
		if detail.Detector != "sensitive_data" || detail.Evidence == nil {
			continue
		}
		field := strings.TrimSpace(detail.Evidence["field"])
		location := strings.TrimSpace(detail.Evidence["location"])
		dataType := strings.ToUpper(strings.TrimSpace(detail.Evidence["data_type"]))
		side := strings.ToUpper(strings.TrimSpace(detail.Evidence["direction"]))
		if side == "" {
			side = "REQUEST"
		}
		if field == "" || location == "" || dataType == "" || (side != "REQUEST" && side != "RESPONSE") {
			continue
		}
		fields = mergeRuntimeFieldLists(fields, []FieldEvidence{{
			Side: side, Path: location + "." + field, DataType: dataType, Match: "OBSERVED",
		}})
	}
	return fields, nil
}

func parseRuntimeFieldReferences(encoded []string) ([]RuntimeFieldReference, error) {
	out := make([]RuntimeFieldReference, 0, len(encoded))
	for _, value := range encoded {
		var parts []string
		if err := json.Unmarshal([]byte(value), &parts); err != nil {
			return nil, fmt.Errorf("parse ClickHouse runtime field reference: %w", err)
		}
		if len(parts) != 4 {
			return nil, errors.New("invalid ClickHouse runtime field reference")
		}
		reference := RuntimeFieldReference{TraceID: parts[0], Method: parts[1], PathTemplate: parts[2]}
		if parts[3] != "" {
			applicationID, err := uuid.Parse(parts[3])
			if err != nil {
				return nil, fmt.Errorf("parse runtime field application: %w", err)
			}
			reference.ApplicationID = &applicationID
		}
		out = append(out, normalizeRuntimeFieldReference(reference))
	}
	return out, nil
}

func normalizeRuntimeFieldReferences(references []RuntimeFieldReference) []RuntimeFieldReference {
	seen := map[string]bool{}
	out := make([]RuntimeFieldReference, 0, len(references))
	for _, reference := range references {
		reference = normalizeRuntimeFieldReference(reference)
		if reference.TraceID == "" || reference.Method == "" || reference.PathTemplate == "" {
			continue
		}
		key := runtimeFieldKey(reference)
		if !seen[key] {
			seen[key] = true
			out = append(out, reference)
		}
	}
	return out
}

func normalizeRuntimeFieldReference(reference RuntimeFieldReference) RuntimeFieldReference {
	reference.TraceID = strings.TrimSpace(reference.TraceID)
	reference.Method = strings.ToUpper(strings.TrimSpace(reference.Method))
	reference.PathTemplate = normalizeRuntimeFieldPath(reference.PathTemplate)
	if reference.ApplicationID != nil {
		applicationID := *reference.ApplicationID
		reference.ApplicationID = &applicationID
	}
	return reference
}

func normalizeRuntimeFieldPath(path string) string {
	path = strings.TrimSpace(path)
	if index := strings.IndexAny(path, "?#"); index >= 0 {
		path = path[:index]
	}
	return strings.TrimSpace(path)
}

func runtimeFieldKey(reference RuntimeFieldReference) string {
	reference = normalizeRuntimeFieldReference(reference)
	applicationID := ""
	if reference.ApplicationID != nil {
		applicationID = reference.ApplicationID.String()
	}
	return reference.TraceID + "\x00" + reference.Method + "\x00" + reference.PathTemplate + "\x00" + applicationID
}

func uniqueRuntimeTraceIDs(references []RuntimeFieldReference) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(references))
	for _, reference := range references {
		if !seen[reference.TraceID] {
			seen[reference.TraceID] = true
			out = append(out, reference.TraceID)
		}
	}
	return out
}

func mergeRuntimeFieldLists(base, extra []FieldEvidence) []FieldEvidence {
	seen := map[string]bool{}
	for _, field := range base {
		seen[runtimeFieldEvidenceKey(field)] = true
	}
	out := append([]FieldEvidence(nil), base...)
	for _, field := range extra {
		field = FieldEvidence{
			Side: strings.ToUpper(strings.TrimSpace(field.Side)), Path: strings.TrimSpace(field.Path),
			DataType: strings.ToUpper(strings.TrimSpace(field.DataType)), Match: "OBSERVED",
		}
		if (field.Side != "REQUEST" && field.Side != "RESPONSE") || field.Path == "" || len(field.Path) > maxRuntimeFieldPathBytes || field.DataType == "" {
			continue
		}
		key := runtimeFieldEvidenceKey(field)
		if !seen[key] {
			seen[key] = true
			out = append(out, field)
		}
	}
	return out
}

func runtimeFieldEvidenceKey(field FieldEvidence) string {
	return field.Side + "\x00" + field.Path + "\x00" + field.DataType + "\x00" + field.Match
}

func (s *CHReader) loadRuntimeFields(ctx context.Context, filter GraphFilter, references []RuntimeFieldReference) (map[string][]FieldEvidence, error) {
	out := map[string][]FieldEvidence{}
	if s.runtimeFields == nil {
		return out, nil
	}
	references = normalizeRuntimeFieldReferences(references)
	if len(references) == 0 {
		return out, nil
	}
	if len(references) > maxRuntimeFieldReferences {
		return nil, ErrRuntimeFieldReferenceLimit
	}
	records, err := s.runtimeFields.ReadRuntimeFields(ctx, RuntimeFieldQuery{
		Start: filter.Start, End: filter.End, References: references,
	})
	if err != nil {
		return nil, err
	}
	requested := map[string]bool{}
	for _, reference := range references {
		requested[runtimeFieldKey(reference)] = true
	}
	for _, record := range records {
		key := runtimeFieldKey(record.Reference)
		if !requested[key] {
			continue
		}
		out[key] = mergeRuntimeFieldLists(out[key], record.Fields)
	}
	return out, nil
}

func runtimeFieldsForReference(fields map[string][]FieldEvidence, reference RuntimeFieldReference) []FieldEvidence {
	return fields[runtimeFieldKey(reference)]
}

func mergeEdgeRuntimeFields(edge *Edge, references []RuntimeFieldReference, fields map[string][]FieldEvidence) {
	for _, reference := range references {
		matched := runtimeFieldsForReference(fields, reference)
		if len(matched) == 0 {
			continue
		}
		edge.Fields = mergeFieldEvidenceLists(edge.Fields, matched)
		for _, field := range matched {
			edge.DataTypes = appendUniqueString(edge.DataTypes, field.DataType)
		}
	}
}

func mergeFieldEvidenceLists(base, extra []FieldEvidence) []FieldEvidence {
	seen := map[string]bool{}
	for _, field := range base {
		seen[fieldEvidenceKey(field)] = true
	}
	out := append([]FieldEvidence(nil), base...)
	for _, field := range extra {
		key := fieldEvidenceKey(field)
		if !seen[key] {
			seen[key] = true
			out = append(out, field)
		}
	}
	return out
}

func fieldEvidenceKey(field FieldEvidence) string {
	return field.Side + "\x00" + field.Path + "\x00" + field.DataType + "\x00" + field.ValueHMAC + "\x00" + field.Match
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func dataTypeMatches(dataTypes []string, fields []FieldEvidence, wanted string) bool {
	wanted = strings.ToUpper(strings.TrimSpace(wanted))
	if wanted == "" {
		return true
	}
	for _, dataType := range dataTypes {
		if strings.ToUpper(strings.TrimSpace(dataType)) == wanted {
			return true
		}
	}
	for _, field := range fields {
		if strings.ToUpper(strings.TrimSpace(field.DataType)) == wanted {
			return true
		}
	}
	return false
}
