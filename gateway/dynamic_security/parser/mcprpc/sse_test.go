// sse_test.go SSE 事件边界读取器黄金矩阵：多行 data 拼接/注释行 keepalive
// 透传语义/字段与行尾三形态/单事件超限 ErrBudget 粘滞/EOF 正常结束/BOM。
package mcprpc

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// readAllEvents 读完全部事件（io.EOF 终止）。
func readAllEvents(r *SSEReader) ([]*SSEEvent, error) {
	var out []*SSEEvent
	for {
		ev, err := r.Next()
		if err != nil {
			return out, err
		}
		out = append(out, ev)
	}
}

func TestSSEBasicEvents(t *testing.T) {
	r := NewSSEReader(strings.NewReader("data: hello\n\ndata: world\n\n"), 0)
	evs, err := readAllEvents(r)
	if err != io.EOF {
		t.Fatalf("终止 = %v", err)
	}
	if len(evs) != 2 || string(evs[0].Data) != "hello" || string(evs[1].Data) != "world" {
		t.Fatalf("事件 = %v", evs)
	}
	// EOF 后恒 EOF（不粘滞语义——正常结束）
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("结束后应恒 EOF: %v", err)
	}
}

func TestSSEMultiLineDataJoin(t *testing.T) {
	// 多行 data 按协议 \n 拼接
	r := NewSSEReader(strings.NewReader("data: line1\ndata: line2\ndata:line3\n\n"), 0)
	ev, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if string(ev.Data) != "line1\nline2\nline3" {
		t.Fatalf("拼接 = %q", ev.Data)
	}
	// 冒号后至多一个前导空格剥离：「data: x」与「data:x」等价
	r2 := NewSSEReader(strings.NewReader("data: a\ndata:b\n\n"), 0)
	ev2, _ := r2.Next()
	if string(ev2.Data) != "a\nb" {
		t.Fatalf("空格剥离 = %q", ev2.Data)
	}
	// 空 data 行
	r3 := NewSSEReader(strings.NewReader("data:\n\n"), 0)
	ev3, _ := r3.Next()
	if ev3 == nil || string(ev3.Data) != "" {
		t.Fatalf("空 data = %+v", ev3)
	}
}

func TestSSEEventAndIDFields(t *testing.T) {
	r := NewSSEReader(strings.NewReader("event: message\nid: evt-1\ndata: x\n\nevent: other\nid: evt-2\ndata: y\n\n"), 0)
	evs, _ := readAllEvents(r)
	if len(evs) != 2 {
		t.Fatalf("事件数 = %d", len(evs))
	}
	if evs[0].Event != "message" || evs[0].ID != "evt-1" || evs[1].Event != "other" || evs[1].ID != "evt-2" {
		t.Fatalf("字段 = %+v", evs)
	}
	// 同名字段后值覆盖前值；retry 忽略
	r2 := NewSSEReader(strings.NewReader("retry: 3000\nid: a\nid: b\ndata: x\n\n"), 0)
	ev2, _ := r2.Next()
	if ev2.ID != "b" {
		t.Fatalf("id 覆盖 = %q", ev2.ID)
	}
	// 仅 event/id 无 data：按协议不分派（跳过至下一含 data 事件）
	r3 := NewSSEReader(strings.NewReader("event: ping\n\ndata: real\n\n"), 0)
	ev3, err := r3.Next()
	if err != nil || string(ev3.Data) != "real" {
		t.Fatalf("无 data 不分派: %v %+v", err, ev3)
	}
}

func TestSSECommentKeepalivePassthrough(t *testing.T) {
	// 注释-only 块以零值事件透出（keepalive 透传语义承载）
	r := NewSSEReader(strings.NewReader(": keepalive\n\n: ka2\n\ndata: real\n\n"), 0)
	evs, err := readAllEvents(r)
	if err != io.EOF {
		t.Fatalf("终止 = %v", err)
	}
	if len(evs) != 3 {
		t.Fatalf("事件数 = %d（两 keepalive + 一 data）", len(evs))
	}
	if evs[0].Data != nil || evs[0].Event != "" || evs[0].ID != "" {
		t.Fatalf("keepalive 应零值事件: %+v", evs[0])
	}
	if string(evs[2].Data) != "real" {
		t.Fatalf("data 事件 = %+v", evs[2])
	}
	// 注释行夹在数据块内：忽略不污染
	r2 := NewSSEReader(strings.NewReader("data: a\n: mid-comment\ndata: b\n\n"), 0)
	ev2, _ := r2.Next()
	if string(ev2.Data) != "a\nb" {
		t.Fatalf("块内注释应忽略: %q", ev2.Data)
	}
}

func TestSSELineEndings(t *testing.T) {
	// \n / \r\n / 孤立 \r 三形态
	for name, raw := range map[string]string{
		"LF":   "data: a\n\ndata: b\n\n",
		"CRLF": "data: a\r\n\r\ndata: b\r\n\r\n",
		"CR":   "data: a\r\rdata: b\r\r",
		"混合":   "data: a\r\n\rdata: b\n\r\n",
	} {
		r := NewSSEReader(strings.NewReader(raw), 0)
		evs, err := readAllEvents(r)
		if err != io.EOF || len(evs) != 2 || string(evs[0].Data) != "a" || string(evs[1].Data) != "b" {
			t.Errorf("%s: 事件 = %v err=%v", name, evs, err)
		}
	}
}

func TestSSEBOMAndEdgeCases(t *testing.T) {
	// 流首 BOM 剥离
	r := NewSSEReader(strings.NewReader("\xef\xbb\xbfdata: x\n\n"), 0)
	ev, err := r.Next()
	if err != nil || string(ev.Data) != "x" {
		t.Fatalf("BOM: %v %+v", err, ev)
	}
	// 空流立即 EOF
	r2 := NewSSEReader(strings.NewReader(""), 0)
	if _, err := r2.Next(); err != io.EOF {
		t.Fatalf("空流应 EOF: %v", err)
	}
	// 流尾不完整块（无空行收尾）丢弃——EOF 正常结束不产半截事件
	r3 := NewSSEReader(strings.NewReader("data: complete\n\ndata: partial\nno-blank"), 0)
	evs, err := readAllEvents(r3)
	if err != io.EOF || len(evs) != 1 || string(evs[0].Data) != "complete" {
		t.Fatalf("半截块应丢弃: %v %+v", err, evs)
	}
	// 半行 EOF（无终止符）同样丢弃
	r4 := NewSSEReader(strings.NewReader("data: x\n\nda"), 0)
	evs4, err4 := readAllEvents(r4)
	if err4 != io.EOF || len(evs4) != 1 {
		t.Fatalf("半行 EOF 应丢弃: %v %d", err4, len(evs4))
	}
	// 连续空行不产事件
	r5 := NewSSEReader(strings.NewReader("\n\n\ndata: x\n\n\n\n"), 0)
	evs5, _ := readAllEvents(r5)
	if len(evs5) != 1 {
		t.Fatalf("连续空行: %d", len(evs5))
	}
	// 无冒号行整行按字段名空值（非 data/event/id——本块无 data 不分派，后续 data 正常）
	r6 := NewSSEReader(strings.NewReader("garbageline\ndata: x\n\n"), 0)
	ev6, err6 := r6.Next()
	if err6 != nil || string(ev6.Data) != "x" {
		t.Fatalf("无冒号行: %v %+v", err6, ev6)
	}
}

func TestSSEEventBudget(t *testing.T) {
	// 单事件超限 → ErrBudget（粘滞——后续 Next 恒同一错误）
	big := "data: " + strings.Repeat("x", 2048) + "\n\n"
	r := NewSSEReader(strings.NewReader(big+"data: next\n\n"), 1024)
	_, err := r.Next()
	var be *BudgetError
	if !errors.As(err, &be) || be.Rule != "event_bytes_exceeded" || be.Limit != 1024 {
		t.Fatalf("应 ErrBudget event_bytes_exceeded: %v", err)
	}
	if !errors.Is(err, ErrBudget) {
		t.Fatalf("哨兵链: %v", err)
	}
	// 粘滞
	if _, err2 := r.Next(); !errors.Is(err2, ErrBudget) {
		t.Fatalf("粘滞错误: %v", err2)
	}
	// 恰等边界：内容恰 ≤ 上限通过
	body := "data: " + strings.Repeat("x", 1010) + "\n\n" // 6+1010+2 行字节 ≈ 1018
	r2 := NewSSEReader(strings.NewReader(body), 2048)
	if _, err := r2.Next(); err != nil {
		t.Fatalf("恰内应通过: %v", err)
	}
	// 预算缺省 1MiB
	if sr := NewSSEReader(strings.NewReader(""), 0); sr.maxEventBytes != 1<<20 {
		t.Fatalf("缺省预算 = %d", sr.maxEventBytes)
	}
}
