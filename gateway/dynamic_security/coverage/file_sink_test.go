// file_sink_test.go FileSink 契约测试：JSONL 形态回读校验、目录自动创建、
// 多批次追加不丢行、写失败只计数不 panic（Emitter 热路径语义）。
package coverage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readJSONLObs 逐行读回并反序列化（模拟 server 采集侧的最小形态）。
func readJSONLObs(t *testing.T, path string) []Observation {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open sink output: %v", err)
	}
	defer f.Close()
	var out []Observation
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Bytes()
		if len(line) == 0 {
			t.Fatalf("第 %d 行为空（JSONL 不允许空行）", lineNo)
		}
		var o Observation
		if err := json.Unmarshal(line, &o); err != nil {
			t.Fatalf("第 %d 行反序列化失败: %v", lineNo, err)
		}
		out = append(out, o)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan sink output: %v", err)
	}
	return out
}

func TestFileSinkWriteReadbackValidate(t *testing.T) {
	dir := t.TempDir()
	s := NewFileSink(dir)
	defer s.Close()

	obs := []Observation{
		baseObs(),
		func() Observation {
			o := baseObs()
			o.RequestID = "rid-partial"
			o.Status = StatusPartial
			o.ReasonCode = ReasonInputTruncated
			o.Truncated = true
			o.BytesExamined = 512
			return o
		}(),
		func() Observation {
			o := baseObs()
			o.RequestID = "rid-na"
			o.Status = StatusNotApplicable
			o.ReasonCode = ReasonNAFrozenRule
			o.NARuleID = "na-classification/graphql-subscription"
			return o
		}(),
	}
	s.Store(obs)
	if err := s.Close(); err != nil {
		t.Fatalf("close sink: %v", err)
	}

	if s.Path() != filepath.Join(dir, FileSinkName) {
		t.Fatalf("输出路径 = %q, want <dir>/%s", s.Path(), FileSinkName)
	}
	got := readJSONLObs(t, s.Path())
	if len(got) != len(obs) {
		t.Fatalf("回读 %d 行, want %d", len(got), len(obs))
	}
	for i, o := range got {
		if msg := o.Validate(); msg != "" {
			t.Fatalf("第 %d 条回读记录契约校验失败: %s", i, msg)
		}
		if o.RequestID != obs[i].RequestID || o.Status != obs[i].Status || o.Detector != obs[i].Detector {
			t.Fatalf("第 %d 条内容不符: got %+v", i, o)
		}
	}
	if s.Dropped() != 0 {
		t.Fatalf("正常写入不应有丢弃: dropped=%d", s.Dropped())
	}
}

func TestFileSinkCreatesMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "logs")
	s := NewFileSink(dir)
	defer s.Close()
	s.Store([]Observation{baseObs()})
	if got := readJSONLObs(t, s.Path()); len(got) != 1 {
		t.Fatalf("目录自动创建后回读 %d 行, want 1", len(got))
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("目录应被创建: %v", err)
	}
}

func TestFileSinkMultiBatchAppendNoLoss(t *testing.T) {
	dir := t.TempDir()
	s := NewFileSink(dir)
	defer s.Close()
	const batches = 5
	const perBatch = 3
	for b := 0; b < batches; b++ {
		buf := make([]Observation, 0, perBatch)
		for i := 0; i < perBatch; i++ {
			o := baseObs()
			o.RequestID = fmt.Sprintf("rid-b%d-%d", b, i)
			buf = append(buf, o)
		}
		s.Store(buf)
	}
	// 关闭后重开（模拟进程重启/装配重挂）继续追加，不覆盖既有行
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := NewFileSink(dir)
	defer s2.Close()
	s2.Store([]Observation{baseObs()})

	got := readJSONLObs(t, s.Path())
	if len(got) != batches*perBatch+1 {
		t.Fatalf("多批次追加后 %d 行, want %d（丢行/覆盖）", len(got), batches*perBatch+1)
	}
	seen := map[string]bool{}
	for _, o := range got {
		if seen[o.RequestID] {
			t.Fatalf("request_id %s 重复（写重）", o.RequestID)
		}
		seen[o.RequestID] = true
	}
}

func TestFileSinkLineIsSingleJSON(t *testing.T) {
	dir := t.TempDir()
	s := NewFileSink(dir)
	defer s.Close()
	o := baseObs()
	o.EndpointKey = "POST /v1/a\nb" // 脏字符经 JSON 转义后仍须单行
	s.Store([]Observation{o})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(strings.TrimRight(string(raw), "\n"), "\n") != 0 {
		t.Fatalf("单条记录必须只占一行: %q", raw)
	}
}

func TestFileSinkWriteFailureCountsNotPanics(t *testing.T) {
	dir := t.TempDir()
	s := NewFileSink(dir)
	// 在输出路径上预先放一个目录，使 OpenFile 必然失败
	if err := os.MkdirAll(s.Path(), 0o755); err != nil {
		t.Fatal(err)
	}
	s.Store([]Observation{baseObs(), baseObs()})
	if s.Dropped() != 2 {
		t.Fatalf("写失败应按批计数: dropped=%d, want 2", s.Dropped())
	}
}

func TestFileSinkEmitterIntegration(t *testing.T) {
	dir := t.TempDir()
	s := NewFileSink(dir)
	e := NewEmitter(64, 4, s)
	e.Start()
	const n = 10
	for i := 0; i < n; i++ {
		o := baseObs()
		o.RequestID = fmt.Sprintf("rid-e-%d", i)
		e.Emit(o)
	}
	e.Stop() // Stop 排空队列后再读文件
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	got := readJSONLObs(t, s.Path())
	if len(got) != n {
		t.Fatalf("Emitter→FileSink 端到端 %d 行, want %d", len(got), n)
	}
	for _, o := range got {
		if msg := o.Validate(); msg != "" {
			t.Fatalf("回读记录契约校验失败: %s", msg)
		}
	}
}

func TestNewFileSinkEmptyDirDefault(t *testing.T) {
	s := NewFileSink("")
	want := string(filepath.Separator) + filepath.Join("var", "log", "caddy", FileSinkName)
	if s.Path() != want {
		t.Fatalf("空目录默认路径 = %q, want %q", s.Path(), want)
	}
}
