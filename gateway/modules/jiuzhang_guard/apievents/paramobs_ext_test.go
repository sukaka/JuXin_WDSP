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
