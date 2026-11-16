// logs_test.go 日志流解析（多路复用头/TTY 原始流）、上限截断与时间戳处理测试。
package containeropsd

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestParseMultiplexedStream(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(muxFrame(1, "2026-10-19T01:02:03.111111111Z stdout 第一行\n"))
	buf.Write(muxFrame(2, "2026-10-19T01:02:04.222222222Z stderr 第二行\n"))
	buf.Write(muxFrame(1, "2026-10-19T01:02:05.333333333Z password=abc123 需脱敏\n"))

	lines, truncated, nextSince, err := ParseLogStream(&buf, false, MaxLogBytes)
	if err != nil {
		t.Fatalf("ParseLogStream: %v", err)
	}
	if truncated {
		t.Fatal("不应截断")
	}
	if len(lines) != 3 {
		t.Fatalf("行数 = %d, want 3", len(lines))
	}
	if lines[0].Stream != "stdout" || lines[1].Stream != "stderr" {
		t.Fatalf("流标签错误: %+v", lines)
	}
	if lines[0].Timestamp != "2026-10-19T01:02:03.111111111Z" {
		t.Fatalf("时间戳错误: %q", lines[0].Timestamp)
	}
	if strings.Contains(lines[2].Message, "abc123") {
		t.Fatalf("脱敏失败: %q", lines[2].Message)
	}
	// next_since = 最后一行时间戳的 Unix 秒
	ts, terr := time.Parse(time.RFC3339Nano, "2026-10-19T01:02:05.333333333Z")
	if terr != nil {
		t.Fatalf("解析期望时间戳: %v", terr)
	}
	if nextSince != ts.Unix() {
		t.Fatalf("next_since = %d, want %d", nextSince, ts.Unix())
	}
}

func TestParseMultiplexedTruncation(t *testing.T) {
	var buf bytes.Buffer
	big := strings.Repeat("x", 200*1024)
	buf.Write(muxFrame(1, "2026-10-19T01:02:03Z "+big+"\n"))
	buf.Write(muxFrame(1, "2026-10-19T01:02:04Z "+big+"\n"))
	buf.Write(muxFrame(1, "2026-10-19T01:02:05Z 不应出现\n"))

	lines, truncated, _, err := ParseLogStream(&buf, false, MaxLogBytes)
	if err != nil {
		t.Fatalf("ParseLogStream: %v", err)
	}
	if !truncated {
		t.Fatal("超过 256KiB 上限应标记 truncated")
	}
	if len(lines) != 1 {
		t.Fatalf("应只保留 1 行，实际 %d", len(lines))
	}
}

func TestParseRawStreamTTY(t *testing.T) {
	raw := "2026-10-19T01:02:03.5Z tty 输出一\n2026-10-19T01:02:04.5Z Authorization: Bearer topsecret\n"
	lines, truncated, nextSince, err := ParseLogStream(strings.NewReader(raw), true, MaxLogBytes)
	if err != nil {
		t.Fatalf("ParseLogStream: %v", err)
	}
	if truncated || len(lines) != 2 {
		t.Fatalf("lines=%d truncated=%v", len(lines), truncated)
	}
	if lines[0].Stream != "stdout" || lines[1].Stream != "stdout" {
		t.Fatalf("TTY 流应全部标记 stdout: %+v", lines)
	}
	if strings.Contains(lines[1].Message, "topsecret") {
		t.Fatalf("TTY 流脱敏失败: %q", lines[1].Message)
	}
	if nextSince == 0 {
		t.Fatal("next_since 应取自最后一行时间戳")
	}
}

func TestParseStreamHandlesMissingTimestamp(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(muxFrame(1, "无时间戳的行\n"))
	lines, _, _, err := ParseLogStream(&buf, false, MaxLogBytes)
	if err != nil {
		t.Fatalf("ParseLogStream: %v", err)
	}
	if len(lines) != 1 || lines[0].Timestamp != "" || lines[0].Message != "无时间戳的行" {
		t.Fatalf("无时间戳行处理错误: %+v", lines)
	}
}

func TestParseStreamRejectsHugeFrame(t *testing.T) {
	var buf bytes.Buffer
	hdr := make([]byte, 8)
	hdr[0] = 1
	// 长度头声称 32MB（超过防御上限）
	hdr[4] = 2
	buf.Write(hdr)
	if _, _, _, err := ParseLogStream(&buf, false, MaxLogBytes); err == nil {
		t.Fatal("异常帧长度应报错")
	}
}

func TestClampTail(t *testing.T) {
	cases := map[int]int{0: DefaultTail, -5: DefaultTail, 1: 1, 500: 500, MaxTail: MaxTail, MaxTail + 1: MaxTail, 999999: MaxTail}
	for in, want := range cases {
		if got := clampTail(in); got != want {
			t.Fatalf("clampTail(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestStripControlsInStream(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(muxFrame(1, "2026-10-19T01:02:03Z 正常\r\n\x1b[31m红色\n"))
	lines, _, _, err := ParseLogStream(&buf, false, MaxLogBytes)
	if err != nil {
		t.Fatalf("ParseLogStream: %v", err)
	}
	for _, l := range lines {
		if strings.ContainsAny(l.Message, "\r\x1b") {
			t.Fatalf("控制字符未剥离: %q", l.Message)
		}
	}
	// 载荷内嵌 \n 拆成两行（"…正常\r" 与 "\x1b[31m红色"）
	if len(lines) != 2 {
		t.Fatalf("行数 = %d, want 2", len(lines))
	}
}
