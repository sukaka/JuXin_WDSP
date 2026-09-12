// fileobs_test.go 文件观测采集单测：敏感词表分类 / IP 掩码 / 采集器接线
// （nil 容忍、缺失键容忍、观测透传）。UPSERT 幂等见 server/tests 集成测试（真实库）。
package apiruntime

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 敏感文件扩展名词表 v1：高置信类别命中，词表外/大小写/空白归一。
func TestClassifyFileSensitivity(t *testing.T) {
	cases := []struct {
		ext  string
		want []string
	}{
		{"pem", []string{"credential_file"}},
		{"KEY", []string{"credential_file"}},
		{" sql ", []string{"database_backup"}},
		{"bak", []string{"database_backup"}},
		{"xlsx", []string{"data_export"}},
		{"pdf", []string{}},
		{"", []string{}},
		{"txt", []string{}},
	}
	for _, c := range cases {
		got := classifyFileSensitivity(c.ext)
		if len(got) != len(c.want) || (len(got) == 1 && got[0] != c.want[0]) {
			t.Fatalf("classifyFileSensitivity(%q) = %v, want %v", c.ext, got, c.want)
		}
	}
}

// 客户端 IP 掩码：IPv4 /24、IPv6 /64、非法/空输入归一空串。
func TestMaskClientIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"203.0.113.87", "203.0.113.0"},
		{" 10.1.2.3 ", "10.1.2.0"},
		{"2001:db8:abcd:1234::1", "2001:db8:abcd:1234::"},
		{"", ""},
		{"not-an-ip", ""},
	}
	for _, c := range cases {
		if got := maskClientIP(c.in); got != c.want {
			t.Fatalf("maskClientIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// fakeFileObsRecorder 捕获采集透传（断言观测原样到达 recorder）。
type fakeFileObsRecorder struct{ recs []*Record }

func (f *fakeFileObsRecorder) RecordFileObservations(_ context.Context, rec *Record) error {
	f.recs = append(f.recs, rec)
	return nil
}

// 采集接线：含 file_observations 的事件触发 recorder；无观测事件跳过；nil recorder 零开销。
func TestCollectOnce_FileObservationsWired(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	rec := Record{
		RequestID: "r-file-1", EndpointKey: "POST /api/v1/files/upload", Method: "POST",
		PathTemplate: "/api/v1/files/upload", IsAPI: true, APIConfidence: 0.5,
		FinalAction: "ALLOW", RiskLevel: "NONE", OccurredAt: time.Now().UTC(),
		IdentityFingerprint: "auth:abc",
		ClientIP:            "203.0.113.87",
		FileObservations: []FileObservation{
			{Direction: "UPLOAD", FileName: "report.pdf", Extension: "pdf", MIME: "application/pdf", Size: 100},
		},
	}
	plain := Record{
		RequestID: "r-file-2", EndpointKey: "GET /v1/orders/{id}", Method: "GET",
		PathTemplate: "/v1/orders/{id}", IsAPI: true, APIConfidence: 0.5,
		FinalAction: "ALLOW", RiskLevel: "NONE", OccurredAt: time.Now().UTC(),
	}
	writeLines(t, logPath, []string{mustJSON(t, rec), mustJSON(t, plain)})

	recorder := &fakeFileObsRecorder{}
	c := NewCollector(&fakeSaver{}, "test-fileobs", logPath, "", "node")
	c.SetFileObsRecorder(recorder)
	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 2 {
		t.Fatalf("processed = %d, want 2", n)
	}
	if len(recorder.recs) != 1 {
		t.Fatalf("recorder calls = %d, want 1 (only event with observations)", len(recorder.recs))
	}
	got := recorder.recs[0].FileObservations
	if len(got) != 1 || got[0].Direction != "UPLOAD" || got[0].FileName != "report.pdf" || got[0].Size != 100 {
		t.Fatalf("forwarded observations = %+v", got)
	}

	// nil recorder：同样两条记录不报错（跳过文件观测落库）
	rec2 := rec
	rec2.RequestID = "r-file-3"
	writeLines(t, logPath, []string{mustJSON(t, rec2)})
	c2 := NewCollector(&fakeSaver{}, "test-fileobs-nil", logPath, "", "node")
	if _, err := c2.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce without recorder: %v", err)
	}
}

// 缺失容忍：旧版网关事件（无 file_observations 键）解析与采集全程零变化。
func TestParseRecordLine_LegacyWithoutFileObs(t *testing.T) {
	rec, err := parseRecordLine([]byte(`{"request_id":"r-legacy","endpoint_key":"GET /v1/a","is_api":true}`))
	if err != nil {
		t.Fatalf("parse legacy record: %v", err)
	}
	if rec.FileObservations != nil {
		t.Fatalf("legacy record must have nil file observations, got %+v", rec.FileObservations)
	}
}

// 写入辅助防回归：file_observations 键 JSON 形状与网关契约一致（蛇形键名）。
func TestFileObservationJSONContract(t *testing.T) {
	rec := Record{
		RequestID: "r-json", EndpointKey: "POST /a",
		FileObservations: []FileObservation{
			{Direction: "DOWNLOAD", FileName: "a.pdf", Extension: "pdf", MIME: "application/pdf", Size: 7},
		},
	}
	raw := mustJSON(t, rec)
	for _, key := range []string{`"file_observations"`, `"direction"`, `"filename"`, `"extension"`, `"mime"`, `"size"`} {
		if !strings.Contains(raw, key) {
			t.Fatalf("json contract missing %s in %s", key, raw)
		}
	}
}
