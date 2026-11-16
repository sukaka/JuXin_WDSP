package apievents

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func findObs(t *testing.T, obs []ParamObservation, loc, name, path string) *ParamObservation {
	t.Helper()
	for i := range obs {
		if obs[i].Location == loc && obs[i].Name == name && obs[i].Path == path {
			return &obs[i]
		}
	}
	t.Fatalf("observation %s:%s:%s not found in %+v", loc, name, path, obs)
	return nil
}

func TestExtendParamObservationsBasic(t *testing.T) {
	p := &parser.Parsed{
		Query:          map[string]string{"q": "hello-world", "empty": ""},
		JSONValues:     map[string]string{"user.name": "alice", "user.age": "30"},
		JSONFields:     map[string]string{"user.name": "string", "user.age": "number", "user.note": "null", "tags": "array"},
		RawPath:        "/users/123",
		NormalizedPath: "/users/{id}",
	}
	base := detectors.CollectParamObservationsSecure(p, "salt", nil, nil)
	out := ExtendParamObservations(base, p, "salt")
	if len(out) != len(base)+1 { // 既有观测 + 1 条 null 观测
		t.Fatalf("len = %d, want %d", len(out), len(base)+1)
	}

	q := findObs(t, out, "QUERY", "q", "")
	if q.CharHist["108"] != 3 || q.CharHist["111"] != 2 || q.CharHist["104"] != 1 { // 'l'×3 'o'×2 'h'×1
		t.Fatalf("q char hist wrong: %v", q.CharHist)
	}
	if got := len(q.CharHist); got != 8 { // h e l o - w r d 共 8 个非零桶
		t.Fatalf("q hist buckets = %d, want 8", got)
	}
	if want := detectors.Fingerprint("salt", "hello-wo")[:16]; q.PrefixHash != want {
		t.Fatalf("q prefix = %q, want %q", q.PrefixHash, want)
	}
	if want := detectors.Fingerprint("salt", "lo-world")[:16]; q.SuffixHash != want {
		t.Fatalf("q suffix = %q, want %q", q.SuffixHash, want)
	}

	empty := findObs(t, out, "QUERY", "empty", "")
	if empty.CharHist != nil || empty.PrefixHash != "" || empty.SuffixHash != "" {
		t.Fatalf("empty value must not produce value-derived fields: %+v", empty)
	}

	age := findObs(t, out, "BODY", "age", "user.age")
	if age.NumValue == nil || *age.NumValue != 30 {
		t.Fatalf("age num_value lost: %+v", age)
	}
	// 短值前后缀 = 整体，与 value_hash 同输入
	if age.PrefixHash != age.ValueHash || age.SuffixHash != age.ValueHash {
		t.Fatalf("short value affix should equal value hash: %+v", age)
	}

	note := findObs(t, out, "BODY", "note", "user.note")
	if !note.Null || note.BaseType != "null" || note.ValueHash != "" || note.CharHist != nil {
		t.Fatalf("null observation wrong: %+v", note)
	}

	id := findObs(t, out, "PATH", "{id}", "1")
	if id.PrefixHash != detectors.Fingerprint("salt", "123")[:16] {
		t.Fatalf("path segment prefix wrong: %+v", id)
	}
}

func TestExtendParamObservationsSensitiveSuppressed(t *testing.T) {
	p := &parser.Parsed{Query: map[string]string{"password": "123456", "q": "ok"}}
	patterns, err := detectors.CompileSensitivePatterns(nil) // 默认表含 password
	if err != nil {
		t.Fatal(err)
	}
	base := detectors.CollectParamObservationsSecure(p, "salt", patterns, nil)
	out := ExtendParamObservations(base, p, "salt")
	pw := findObs(t, out, "QUERY", "password", "")
	if pw.ValueHash != "" {
		t.Fatalf("sensitive value hash must stay suppressed: %+v", pw)
	}
	if pw.CharHist != nil || pw.PrefixHash != "" || pw.SuffixHash != "" || pw.NumValue != nil {
		t.Fatalf("sensitive param must not leak value-derived fields: %+v", pw)
	}
	if pw.Length != 6 {
		t.Fatalf("sensitive param keeps length shape stat: %+v", pw)
	}
	// 非敏感参数正常产出
	q := findObs(t, out, "QUERY", "q", "")
	if q.PrefixHash == "" {
		t.Fatalf("non-sensitive param must produce affix hash: %+v", q)
	}
}

func TestExtendParamObservationsNullCap(t *testing.T) {
	fields := map[string]string{}
	for i := 0; i < 100; i++ {
		fields[fmt.Sprintf("f%03d", i)] = "null"
	}
	p := &parser.Parsed{JSONFields: fields}
	out := ExtendParamObservations(nil, p, "salt")
	if len(out) != maxNullObservations {
		t.Fatalf("null observations = %d, want cap %d", len(out), maxNullObservations)
	}
	for _, o := range out {
		if !o.Null || o.BaseType != "null" {
			t.Fatalf("unexpected element: %+v", o)
		}
	}
}

func TestExtendParamObservationsHistogramSampleCap(t *testing.T) {
	long := strings.Repeat("ab", 200) // 400 字节
	p := &parser.Parsed{Query: map[string]string{"q": long}}
	base := detectors.CollectParamObservationsSecure(p, "salt", nil, nil)
	out := ExtendParamObservations(base, p, "salt")
	q := findObs(t, out, "QUERY", "q", "")
	var total int64
	for b, c := range q.CharHist {
		if b != "97" && b != "98" { // 'a' / 'b'
			t.Fatalf("unexpected bucket %s", b)
		}
		total += c
	}
	if total != histSampleByteCap {
		t.Fatalf("hist sampled bytes = %d, want cap %d", total, histSampleByteCap)
	}
}

func TestParamObservationWireCompat(t *testing.T) {
	p := &parser.Parsed{Query: map[string]string{"q": "alice"}}
	base := detectors.CollectParamObservationsSecure(p, "salt", nil, nil)
	out := ExtendParamObservations(base, p, "salt")
	data, err := json.Marshal(out[0])
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, `"char_hist"`) || !strings.Contains(s, `"prefix_hash"`) {
		t.Fatalf("extended keys missing: %s", s)
	}
	if strings.Contains(s, "alice") {
		t.Fatalf("plaintext leaked into wire JSON: %s", s)
	}
	// 旧版采集端镜像（detectors.ParamObservation 口径）可解码新版 JSON
	var legacy detectors.ParamObservation
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatalf("legacy mirror decode: %v", err)
	}
	if legacy.ValueHash == "" || legacy.Length != 5 {
		t.Fatalf("legacy mirror fields lost: %+v", legacy)
	}
	// 新版镜像容忍旧版 JSON（扩展字段缺省零值）
	old := []byte(`{"location":"QUERY","name":"q","base_type":"string","length":3,"value_hash":"ab"}`)
	var decoded ParamObservation
	if err := json.Unmarshal(old, &decoded); err != nil {
		t.Fatalf("new mirror decode old JSON: %v", err)
	}
	if decoded.Null || decoded.CharHist != nil || decoded.PrefixHash != "" {
		t.Fatalf("old JSON must decode with zero extended fields: %+v", decoded)
	}
}

func TestExtendParamObservationsNilParsed(t *testing.T) {
	base := detectors.CollectParamObservationsSecure(&parser.Parsed{
		Query: map[string]string{"q": "v"},
	}, "salt", nil, nil)
	out := ExtendParamObservations(base, nil, "salt")
	if len(out) != len(base) {
		t.Fatalf("nil parsed must keep base only: %d vs %d", len(out), len(base))
	}
	if out[0].CharHist != nil {
		t.Fatalf("nil parsed must not produce extended fields: %+v", out[0])
	}
}

func TestDetectStringFormat(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "uuid", value: "550e8400-e29b-41d4-a716-446655440000", want: "UUID"},
		{name: "uuid uppercase", value: "550E8400-E29B-41D4-A716-446655440000", want: "UUID"},
		{name: "uuid missing hyphens", value: "550e8400e29b41d4a716446655440000", want: ""},
		{name: "uuid non hex", value: "550e8400-e29b-41d4-a716-44665544000g", want: ""},
		{name: "uuid braces", value: "{550e8400-e29b-41d4-a716-446655440000}", want: ""},
		{name: "uuid wrong group", value: "550e8400-e29b-41d4-a716-44665544000", want: ""},
		{name: "email", value: "alice@example.com", want: "EMAIL"},
		{name: "email dot atom", value: "user.name+tag@example-domain.com", want: "EMAIL"},
		{name: "email display name", value: "Alice <alice@example.com>", want: ""},
		{name: "email two at signs", value: "alice@@example.com", want: ""},
		{name: "email consecutive local dots", value: "alice..smith@example.com", want: ""},
		{name: "email leading local dot", value: ".alice@example.com", want: ""},
		{name: "email domain hyphen", value: "alice@-example.com", want: ""},
		{name: "email domain trailing dot", value: "alice@example.com.", want: ""},
		{name: "email whitespace", value: "alice @example.com", want: ""},
		{name: "email missing domain", value: "alice@", want: ""},
		{name: "ipv4", value: "192.0.2.1", want: "IPV4"},
		{name: "ipv4 leading zero", value: "192.168.001.1", want: ""},
		{name: "ipv4 overflow", value: "256.0.0.1", want: ""},
		{name: "ipv4 shorthand", value: "127.1", want: ""},
		{name: "ipv4 cidr", value: "192.0.2.1/32", want: ""},
		{name: "ipv6", value: "2001:db8::1", want: "IPV6"},
		{name: "ipv6 mapped", value: "::ffff:192.0.2.128", want: "IPV6"},
		{name: "ipv6 zone", value: "fe80::1%lo0", want: ""},
		{name: "ipv6 brackets", value: "[2001:db8::1]", want: ""},
		{name: "ipv6 cidr", value: "2001:db8::1/128", want: ""},
		{name: "date leap day", value: "2024-02-29", want: "DATE"},
		{name: "date non leap day", value: "2023-02-29", want: ""},
		{name: "date non padded", value: "2024-2-09", want: ""},
		{name: "date invalid month", value: "2024-13-01", want: ""},
		{name: "datetime zulu", value: "2024-02-29T12:34:56Z", want: "DATETIME"},
		{name: "datetime fractional offset", value: "2024-02-29T12:34:56.123456789+08:00", want: "DATETIME"},
		{name: "datetime invalid date", value: "2023-02-29T12:34:56Z", want: ""},
		{name: "datetime lowercase", value: "2024-02-29t12:34:56z", want: ""},
		{name: "datetime space separator", value: "2024-02-29 12:34:56Z", want: ""},
		{name: "datetime missing zone", value: "2024-02-29T12:34:56", want: ""},
		{name: "datetime comma fraction", value: "2024-02-29T12:34:56,123Z", want: ""},
		{name: "datetime invalid offset hour", value: "2024-02-29T12:34:56+24:00", want: ""},
		{name: "datetime invalid offset minute", value: "2024-02-29T12:34:56+08:60", want: ""},
		{name: "unknown", value: "hello-world", want: ""},
		{name: "empty", value: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectStringFormat(tt.value); got != tt.want {
				t.Fatalf("detectStringFormat(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestExtendParamObservationsFormatSamples(t *testing.T) {
	uuidValue := "550e8400-e29b-41d4-a716-446655440000"
	p := &parser.Parsed{
		Query: map[string]string{
			"uuid_value":     uuidValue,
			"email_value":    "alice@example.com",
			"ipv4_value":     "192.0.2.1",
			"ipv6_value":     "2001:db8::1",
			"date_value":     "2024-02-29",
			"datetime_value": "2024-02-29T12:34:56Z",
			"unknown":        "hello-world",
			"empty":          "",
			"number":         "42",
			"boolean":        "true",
			"email":          "2024-01-01",
			"uuid":           "not-a-uuid",
		},
		RawPath:        "/items/" + uuidValue,
		NormalizedPath: "/items/{uuid}",
	}
	base := detectors.CollectParamObservationsSecure(p, "salt", nil, nil)
	out := ExtendParamObservations(base, p, "salt")
	wantCandidates := map[string]string{
		"uuid_value":     "UUID",
		"email_value":    "EMAIL",
		"ipv4_value":     "IPV4",
		"ipv6_value":     "IPV6",
		"date_value":     "DATE",
		"datetime_value": "DATETIME",
		"unknown":        "",
		"email":          "DATE",
		"uuid":           "",
	}
	for name, want := range wantCandidates {
		o := findObs(t, out, "QUERY", name, "")
		if !o.FormatSample || o.FormatCandidate != want {
			t.Errorf("%s format = (%t, %q), want (true, %q)", name, o.FormatSample, o.FormatCandidate, want)
		}
	}
	for _, name := range []string{"empty", "number", "boolean"} {
		o := findObs(t, out, "QUERY", name, "")
		if o.FormatSample || o.FormatCandidate != "" {
			t.Errorf("%s must not be a format sample: %+v", name, o)
		}
		data, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), `"format_sample"`) || strings.Contains(string(data), `"format_candidate"`) {
			t.Errorf("%s must omit format keys: %s", name, data)
		}
	}
	path := findObs(t, out, "PATH", "{uuid}", "1")
	if !path.FormatSample || path.FormatCandidate != "UUID" {
		t.Fatalf("path format = (%t, %q), want (true, UUID)", path.FormatSample, path.FormatCandidate)
	}

	unknown := findObs(t, out, "QUERY", "unknown", "")
	data, err := json.Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"format_sample":true`) || strings.Contains(string(data), `"format_candidate"`) {
		t.Fatalf("unknown string must be sampled without a candidate: %s", data)
	}
	if strings.Contains(string(data), "hello-world") {
		t.Fatalf("plaintext leaked into wire JSON: %s", data)
	}
}

func TestExtendParamObservationsFormatSensitiveSuppressed(t *testing.T) {
	p := &parser.Parsed{Query: map[string]string{"password": "alice@example.com"}}
	patterns, err := detectors.CompileSensitivePatterns(nil)
	if err != nil {
		t.Fatal(err)
	}
	base := detectors.CollectParamObservationsSecure(p, "salt", patterns, nil)
	out := ExtendParamObservations(base, p, "salt")
	password := findObs(t, out, "QUERY", "password", "")
	if password.BaseType != "string" || password.ValueHash != "" {
		t.Fatalf("test requires a suppressed string observation: %+v", password)
	}
	if password.FormatSample || password.FormatCandidate != "" {
		t.Fatalf("sensitive value must not produce format fields: %+v", password)
	}
	data, err := json.Marshal(password)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"format_sample"`) || strings.Contains(string(data), `"format_candidate"`) {
		t.Fatalf("sensitive value must omit format keys: %s", data)
	}
}

func TestParamObservationFormatLegacyCompat(t *testing.T) {
	old := []byte(`{"location":"QUERY","name":"q","base_type":"string","length":36,"value_hash":"ab"}`)
	var decoded ParamObservation
	if err := json.Unmarshal(old, &decoded); err != nil {
		t.Fatalf("new mirror decode old JSON: %v", err)
	}
	if decoded.FormatSample || decoded.FormatCandidate != "" {
		t.Fatalf("old observation must not acquire format knowledge: %+v", decoded)
	}
	data, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"format_sample"`) || strings.Contains(string(data), `"format_candidate"`) {
		t.Fatalf("zero format fields must be omitted: %s", data)
	}
}
