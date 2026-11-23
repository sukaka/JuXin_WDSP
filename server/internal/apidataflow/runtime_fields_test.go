package apidataflow

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type runtimeFieldFakeRows struct {
	rows  [][]any
	index int
}

func (r *runtimeFieldFakeRows) Next() bool   { return r.index < len(r.rows) }
func (r *runtimeFieldFakeRows) Close() error { return nil }
func (r *runtimeFieldFakeRows) Err() error   { return nil }

func (r *runtimeFieldFakeRows) Scan(dest ...any) error {
	if r.index >= len(r.rows) {
		return fmt.Errorf("scan past end")
	}
	row := r.rows[r.index]
	r.index++
	if len(dest) != len(row) {
		return fmt.Errorf("scan arity = %d, want %d", len(dest), len(row))
	}
	for i, value := range row {
		switch target := dest[i].(type) {
		case *string:
			*target = value.(string)
		case *[]byte:
			*target = append((*target)[:0], value.([]byte)...)
		case *sql.NullString:
			if value == nil {
				*target = sql.NullString{}
			} else {
				*target = sql.NullString{String: value.(string), Valid: true}
			}
		default:
			return fmt.Errorf("unsupported scan destination %T", dest[i])
		}
	}
	return nil
}

type runtimeFieldFakePG struct {
	rows    [][]any
	queries []string
	args    [][]any
	err     error
}

func (f *runtimeFieldFakePG) query(_ context.Context, query string, args ...any) (runtimeFieldRows, error) {
	f.queries = append(f.queries, query)
	f.args = append(f.args, append([]any(nil), args...))
	if f.err != nil {
		return nil, f.err
	}
	return &runtimeFieldFakeRows{rows: f.rows}, nil
}

func runtimeDetails(detector, field, location, direction, dataType string) []byte {
	data, _ := json.Marshal([]map[string]any{{
		"detector": detector,
		"evidence": map[string]string{
			"field": field, "location": location, "direction": direction, "data_type": dataType,
		},
	}})
	return data
}

func TestExtractRuntimeFieldEvidence(t *testing.T) {
	fields, err := extractRuntimeFieldEvidence([]byte(`[
		{"detector":"sensitive_data","evidence":{"field":"pwd","location":"form","direction":"REQUEST","data_type":"credential","value":"must-not-leak"}},
		{"detector":"sensitive_data","evidence":{"field":"card","location":"json","direction":"response","data_type":" bank_card "}},
		{"detector":"sensitive_data","evidence":{"field":"pwd","location":"form","direction":"REQUEST","data_type":"credential"}},
		{"detector":"sensitive_data","evidence":{"field":"missing_type","location":"form","direction":"REQUEST"}},
		{"detector":"sensitive_data","evidence":{"field":"missing_location","direction":"REQUEST","data_type":"phone"}},
		{"detector":"sensitive_data","evidence":{"field":"bad_direction","location":"form","direction":"SIDE","data_type":"phone"}},
		{"detector":"waf","evidence":{"field":"attack","location":"form","direction":"REQUEST","data_type":"credential"}}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 {
		t.Fatalf("unexpected fields: %+v", fields)
	}
	if fields[0].Side != "REQUEST" || fields[0].Path != "form.pwd" || fields[0].DataType != "CREDENTIAL" || fields[0].Match != "OBSERVED" ||
		fields[1].Side != "RESPONSE" || fields[1].Path != "json.card" || fields[1].DataType != "BANK_CARD" {
		t.Fatalf("runtime evidence was not normalized safely: %+v", fields)
	}
	for _, field := range fields {
		if field.ValueHMAC != "" || field.HMACKeyID != "" {
			t.Fatalf("runtime enrichment fabricated a value fingerprint: %+v", field)
		}
	}
	encoded, _ := json.Marshal(fields)
	if strings.Contains(string(encoded), "must-not-leak") {
		t.Fatalf("raw sensitive value leaked into fields: %s", encoded)
	}
	if _, err := extractRuntimeFieldEvidence([]byte(`{not-json`)); err == nil {
		t.Fatal("malformed details_json must return an error")
	}
}

func TestPGRuntimeFieldReaderStrictReferenceMatching(t *testing.T) {
	applicationID := uuid.New()
	otherApplicationID := uuid.New()
	traceID := strings.Repeat("a", 32)
	pg := &runtimeFieldFakePG{rows: [][]any{
		{traceID, "post /login", "POST", applicationID.String(), runtimeDetails("sensitive_data", "pwd", "form", "REQUEST", "credential")},
		{traceID, "POST /verify", "POST", applicationID.String(), runtimeDetails("sensitive_data", "token", "query", "RESPONSE", "credential")},
		{traceID, "POST /other-hop", "POST", applicationID.String(), runtimeDetails("sensitive_data", "other", "form", "REQUEST", "credential")},
		{traceID, "POST /login", "POST", otherApplicationID.String(), runtimeDetails("sensitive_data", "wrong_app", "form", "REQUEST", "credential")},
		{traceID, "POST /login", "DELETE", applicationID.String(), runtimeDetails("sensitive_data", "conflicting_method", "form", "REQUEST", "credential")},
	}}
	reader := &PGRuntimeFieldReader{query: pg.query}
	records, err := reader.ReadRuntimeFields(context.Background(), RuntimeFieldQuery{
		Start: time.Now().Add(-time.Hour), End: time.Now(),
		References: []RuntimeFieldReference{
			{TraceID: traceID, Method: "POST", PathTemplate: "/login", ApplicationID: &applicationID},
			{TraceID: traceID, Method: "POST", PathTemplate: "/verify", ApplicationID: &applicationID},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("unassociated or ambiguous events were returned: %+v", records)
	}
	byPath := map[string]RuntimeFieldRecord{}
	for _, record := range records {
		byPath[record.Reference.PathTemplate] = record
	}
	if len(byPath["/login"].Fields) != 1 || byPath["/login"].Fields[0].Path != "form.pwd" ||
		len(byPath["/verify"].Fields) != 1 || byPath["/verify"].Fields[0].Path != "query.token" {
		t.Fatalf("trace-only matching contaminated another endpoint: %+v", records)
	}
	if len(pg.queries) != 1 || !strings.Contains(pg.queries[0], "FROM api_runtime_events") ||
		!strings.Contains(pg.queries[0], "details_json") || strings.Contains(pg.queries[0], "api_sensitive_fields") {
		t.Fatalf("unexpected runtime field query: %+v", pg.queries)
	}
}

func TestPGRuntimeFieldReaderBoundsQueries(t *testing.T) {
	now := time.Now()
	references := make([]RuntimeFieldReference, runtimeFieldBatchSize+1)
	for i := range references {
		references[i] = RuntimeFieldReference{TraceID: fmt.Sprintf("%032x", i+1), Method: "POST", PathTemplate: "/login"}
	}
	pg := &runtimeFieldFakePG{}
	reader := &PGRuntimeFieldReader{query: pg.query}
	if _, err := reader.ReadRuntimeFields(context.Background(), RuntimeFieldQuery{Start: now.Add(-time.Hour), End: now, References: references}); err != nil {
		t.Fatal(err)
	}
	if len(pg.queries) != 2 {
		t.Fatalf("trace references were not batched: %d queries", len(pg.queries))
	}
	for i, query := range pg.queries {
		if !strings.Contains(query, "LIMIT") || len(pg.args[i]) == 0 {
			t.Fatalf("unbounded PostgreSQL query: %s", query)
		}
	}

	tooMany := make([]RuntimeFieldReference, maxRuntimeFieldReferences+1)
	for i := range tooMany {
		tooMany[i] = RuntimeFieldReference{TraceID: fmt.Sprintf("%032x", i+1), Method: "POST", PathTemplate: "/login"}
	}
	before := len(pg.queries)
	if _, err := reader.ReadRuntimeFields(context.Background(), RuntimeFieldQuery{Start: now.Add(-time.Hour), End: now, References: tooMany}); err == nil {
		t.Fatal("excess cross-database references must fail explicitly")
	}
	if len(pg.queries) != before {
		t.Fatal("over-limit request reached PostgreSQL")
	}
}

func TestPGRuntimeFieldReaderPropagatesQueryErrors(t *testing.T) {
	injected := errors.New("injected")
	pg := &runtimeFieldFakePG{err: injected}
	reader := &PGRuntimeFieldReader{query: pg.query}
	_, err := reader.ReadRuntimeFields(context.Background(), RuntimeFieldQuery{
		Start: time.Now().Add(-time.Hour), End: time.Now(),
		References: []RuntimeFieldReference{{TraceID: strings.Repeat("a", 32), Method: "POST", PathTemplate: "/login"}},
	})
	if !errors.Is(err, injected) {
		t.Fatalf("query error was hidden: %v", err)
	}
}

func TestNewPGRuntimeFieldReaderAcceptsSQLDB(t *testing.T) {
	if reader := NewPGRuntimeFieldReader((*sql.DB)(nil)); reader == nil {
		t.Fatal("constructor returned nil")
	}
}

func TestExtractRuntimeFieldEvidenceDefaultsLegacyRequestDirection(t *testing.T) {
	fields, err := extractRuntimeFieldEvidence([]byte(`[
		{"detector":"sensitive_data","rule_id":"sensitive.field","evidence":{"field":"pwd","location":"form","data_type":"credential"}}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 1 || fields[0].Side != "REQUEST" || fields[0].Path != "form.pwd" || fields[0].DataType != "CREDENTIAL" {
		t.Fatalf("legacy request-side evidence was lost: %+v", fields)
	}
}

func TestPGRuntimeFieldReaderRejectsExcessRows(t *testing.T) {
	rows := make([][]any, runtimeFieldBatchRowLimit+1)
	for i := range rows {
		rows[i] = []any{strings.Repeat("a", 32), "POST /login", "POST", nil, runtimeDetails("sensitive_data", "pwd", "form", "REQUEST", "credential")}
	}
	pg := &runtimeFieldFakePG{rows: rows}
	reader := &PGRuntimeFieldReader{query: pg.query}
	_, err := reader.ReadRuntimeFields(context.Background(), RuntimeFieldQuery{
		Start: time.Now().Add(-time.Hour), End: time.Now(),
		References: []RuntimeFieldReference{{TraceID: strings.Repeat("a", 32), Method: "POST", PathTemplate: "/login"}},
	})
	if !errors.Is(err, ErrRuntimeFieldRowLimit) {
		t.Fatalf("row overflow was not reported explicitly: %v", err)
	}
}

func TestRuntimeFieldPathUsesObservationByteLimit(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		want  int
	}{
		{name: "exactly 512 bytes", field: strings.Repeat("a", 507), want: 1},
		{name: "513 bytes", field: strings.Repeat("a", 508), want: 0},
		{name: "multibyte exactly 512 bytes", field: strings.Repeat("界", 169), want: 1},
		{name: "multibyte over 512 bytes", field: strings.Repeat("界", 170), want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			fields, err := extractRuntimeFieldEvidence([]byte(`[{"detector":"sensitive_data","evidence":{"field":` +
				strconv.Quote(test.field) + `,"location":"form","direction":"REQUEST","data_type":"credential"}}]`))
			if err != nil {
				t.Fatal(err)
			}
			if len(fields) != test.want {
				t.Fatalf("path byte limit not enforced: fields=%+v", fields)
			}
			if len(fields) == 1 && len(fields[0].Path) != 512 {
				t.Fatalf("path length = %d bytes, want 512", len(fields[0].Path))
			}
		})
	}
}

func TestMergeFieldEvidenceListsReturnsEmptySliceNotNil(t *testing.T) {
	merged := mergeFieldEvidenceLists(nil, nil)
	if merged == nil || len(merged) != 0 {
		t.Fatalf("expected non-nil empty slice, got %#v", merged)
	}
	encoded, err := json.Marshal(EvidenceRecord{
		AgentID: uuid.New(), EventID: "ev-empty", EdgeID: "edge-1", Fields: merged,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"fields":[]`) {
		t.Fatalf("empty fields marshaled as null instead of []: %s", encoded)
	}
}
