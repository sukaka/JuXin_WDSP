// reader_test.go 流式帧读取器黄金样本：任意分片重组、四重预算逐层边界
// （恰等/超 1）、格式错误与预算错误语义分离、截断矩阵、同连接不串位、
// 全局预算并发与释放。
package grpcframe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

// stepReader 步进读取器（每次 Read 至多返回 step 字节——任意分片模拟）。
type stepReader struct {
	r    io.Reader
	step int
}

func newStepReader(r io.Reader, step int) *stepReader {
	if step <= 0 {
		step = 1
	}
	return &stepReader{r: r, step: step}
}

func (s *stepReader) Read(p []byte) (int, error) {
	if len(p) > s.step {
		p = p[:s.step]
	}
	return s.r.Read(p)
}

// frameBytes 构造一条帧（压缩标志 + 大端长度 + 体）。
func frameBytes(compressed bool, body []byte) []byte {
	out := make([]byte, 5, 5+len(body))
	if compressed {
		out[0] = 1
	}
	binary.BigEndian.PutUint32(out[1:5], uint32(len(body)))
	return append(out, body...)
}

// forgedFrame 构造声明长度伪造的帧（声明与体不一致）。
func forgedFrame(flag byte, declared uint32, body []byte) []byte {
	out := make([]byte, 5, 5+len(body))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:5], declared)
	return append(out, body...)
}

// multiFrames 拼接多条帧。
func multiFrames(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// readAll 读完全部帧（返回帧与终止错误）。
func readAll(rd *Reader) ([]*Frame, error) {
	var out []*Frame
	for {
		fr, err := rd.Next()
		if err != nil {
			return out, err
		}
		out = append(out, fr)
	}
}

// TestReassembleAcrossFragments 任意分片重组（R01）：1/2/3/7 字节步进切分，
// 多帧（含空消息、含压缩标志位）正确重组不错位。
func TestReassembleAcrossFragments(t *testing.T) {
	m1 := []byte("hello grpc")
	m2 := []byte{} // 空消息（长度 0）合法
	m3 := bytes.Repeat([]byte{0xAB}, 1024)
	stream := multiFrames(frameBytes(false, m1), frameBytes(true, m2), frameBytes(false, m3))
	for _, step := range []int{1, 2, 3, 7, len(stream)} {
		g := NewGlobalBudget(0)
		rd := NewReader(newStepReader(bytes.NewReader(stream), step), Config{Global: g})
		frames, err := readAll(rd)
		if err != io.EOF {
			t.Fatalf("step=%d 终止错误 = %v", step, err)
		}
		if len(frames) != 3 {
			t.Fatalf("step=%d 帧数 = %d", step, len(frames))
		}
		if !bytes.Equal(frames[0].Body, m1) || frames[0].Compressed || frames[0].Index != 1 {
			t.Fatalf("step=%d 帧1 = %+v", step, frames[0])
		}
		if len(frames[1].Body) != 0 || !frames[1].Compressed || frames[1].Index != 2 {
			t.Fatalf("step=%d 帧2（空消息） = %+v", step, frames[1])
		}
		if !bytes.Equal(frames[2].Body, m3) || frames[2].Index != 3 {
			t.Fatalf("step=%d 帧3 重组错位", step)
		}
		if rd.Messages() != 3 || rd.TotalDeclared() != int64(len(m1)+len(m3)) {
			t.Fatalf("step=%d 读数 = %d/%d", step, rd.Messages(), rd.TotalDeclared())
		}
		if err := rd.Close(); err != nil || g.Used() != 0 {
			t.Fatalf("step=%d Close 后全局持有 = %d", step, g.Used())
		}
		// 干净结束后 Next 恒 io.EOF
		if _, err := rd.Next(); err != io.EOF {
			t.Fatalf("step=%d 结束后 Next = %v", step, err)
		}
	}
}

// TestBudgetBoundaries 四重预算逐层边界（恰等放行 / 超 1 拒绝）。
func TestBudgetBoundaries(t *testing.T) {
	t.Run("单消息", func(t *testing.T) {
		cfg := Config{MaxMessageBytes: 16, Global: NewGlobalBudget(0)}
		// 恰等 16 放行；17 拒绝（不分配）
		rd := NewReader(bytes.NewReader(frameBytes(false, bytes.Repeat([]byte{1}, 16))), cfg)
		if _, err := rd.Next(); err != nil {
			t.Fatalf("恰等应放行: %v", err)
		}
		rd2 := NewReader(bytes.NewReader(forgedFrame(0, 17, bytes.Repeat([]byte{1}, 17))), cfg)
		_, err := rd2.Next()
		var be *BudgetError
		if !errors.As(err, &be) || be.Kind != "message_bytes" || be.Limit != 16 || be.Actual != 17 {
			t.Fatalf("超 1 应 message_bytes 拒: %v", err)
		}
	})
	t.Run("消息数", func(t *testing.T) {
		cfg := Config{MaxMessages: 2, Global: NewGlobalBudget(0)}
		stream := multiFrames(frameBytes(false, nil), frameBytes(false, nil), frameBytes(false, nil))
		rd := NewReader(bytes.NewReader(stream), cfg)
		_, err := readAll(rd)
		var be *BudgetError
		if !errors.As(err, &be) || be.Kind != "message_count" || be.Limit != 2 || be.Actual != 3 {
			t.Fatalf("第 3 条应 message_count 拒: %v", err)
		}
		// 恰等 2 条放行
		rd2 := NewReader(bytes.NewReader(multiFrames(frameBytes(false, nil), frameBytes(false, nil))), cfg)
		if _, err := readAll(rd2); err != io.EOF {
			t.Fatalf("恰等 2 条应放行: %v", err)
		}
	})
	t.Run("声明合计", func(t *testing.T) {
		cfg := Config{MaxRequestBytes: 32, Global: NewGlobalBudget(0)}
		// 16+16 恰等；再 +1 拒
		stream := multiFrames(frameBytes(false, bytes.Repeat([]byte{1}, 16)),
			frameBytes(false, bytes.Repeat([]byte{2}, 16)), frameBytes(false, []byte{3}))
		rd := NewReader(bytes.NewReader(stream), cfg)
		_, err := readAll(rd)
		var be *BudgetError
		if !errors.As(err, &be) || be.Kind != "request_bytes" || be.Limit != 32 || be.Actual != 33 {
			t.Fatalf("合计超 1 应 request_bytes 拒: %v", err)
		}
	})
	t.Run("全局并发", func(t *testing.T) {
		g := NewGlobalBudget(32)
		cfg := Config{Global: g}
		// 读取器 1 持有 32（未 Close）；读取器 2 新解析拒（不排队）
		rd1 := NewReader(bytes.NewReader(frameBytes(false, bytes.Repeat([]byte{1}, 32))), cfg)
		if _, err := rd1.Next(); err != nil {
			t.Fatalf("rd1: %v", err)
		}
		rd2 := NewReader(bytes.NewReader(frameBytes(false, []byte{1})), cfg)
		_, err := rd2.Next()
		var be *BudgetError
		if !errors.As(err, &be) || be.Kind != "global_budget" {
			t.Fatalf("全局占满应 global_budget 拒: %v", err)
		}
		// rd1 Close 释放后 rd2 可行
		_ = rd1.Close()
		rd3 := NewReader(bytes.NewReader(frameBytes(false, []byte{1})), cfg)
		if _, err := rd3.Next(); err != nil {
			t.Fatalf("释放后应可行: %v", err)
		}
	})
}

// TestMalformedClassification 格式错误与预算错误语义分离 + 保留位非零。
func TestMalformedClassification(t *testing.T) {
	// 保留位非零（0x02/0xFE/0xFF）→ ProtocolError reserved_flag_bits（格式类）
	for _, flag := range []byte{0x02, 0xFE, 0xFF, 0x80} {
		rd := NewReader(bytes.NewReader(forgedFrame(flag, 0, nil)), Config{Global: NewGlobalBudget(0)})
		_, err := rd.Next()
		var pe *ProtocolError
		if !errors.As(err, &pe) || pe.Kind != "reserved_flag_bits" {
			t.Fatalf("flag=0x%02x 应 reserved_flag_bits: %v", flag, err)
		}
		if IsBudgetError(err) {
			t.Fatalf("flag=0x%02x 不得归入预算类", flag)
		}
	}
	// 声明长度伪造（声明 > 实际剩余）→ ProtocolError truncated_body（格式类，非预算）
	rd := NewReader(bytes.NewReader(forgedFrame(0, 100, []byte{1, 2, 3})), Config{Global: NewGlobalBudget(0)})
	_, err := rd.Next()
	var pe2 *ProtocolError
	if !errors.As(err, &pe2) || pe2.Kind != "truncated_body" {
		t.Fatalf("长度伪造应 truncated_body: %v", err)
	}
	// 单消息超上限 → BudgetError（预算类，非格式）
	rd2 := NewReader(bytes.NewReader(forgedFrame(0, 1<<20, nil)), Config{MaxMessageBytes: 16, Global: NewGlobalBudget(0)})
	_, err = rd2.Next()
	if !IsBudgetError(err) || IsProtocolError(err) {
		t.Fatalf("超上限应预算类: %v", err)
	}
}

// TestTruncationMatrix 截断矩阵：两帧流逐位置截断，错误分类稳定、无 panic、
// 无预算驻留。
func TestTruncationMatrix(t *testing.T) {
	stream := multiFrames(frameBytes(false, []byte("abc")), frameBytes(true, []byte("defgh")))
	for cut := 0; cut < len(stream); cut++ {
		g := NewGlobalBudget(0)
		rd := NewReader(bytes.NewReader(stream[:cut]), Config{Global: g})
		frames, err := readAll(rd)
		_ = rd.Close()
		// 落在帧边界（0=空、8=恰一完整帧）为干净结束——截断在帧头/帧体中段才判畸形
		if cut == 0 || cut == 8 {
			wantFrames := 0
			if cut == 8 {
				wantFrames = 1
			}
			if err != io.EOF || len(frames) != wantFrames {
				t.Fatalf("cut=%d 帧边界应干净结束(%d 帧): %v %d", cut, wantFrames, err, len(frames))
			}
			continue
		}
		if err == io.EOF {
			t.Fatalf("cut=%d 截断不可能干净结束", cut)
		}
		if !IsProtocolError(err) {
			t.Fatalf("cut=%d 应协议格式错误: %v", cut, err)
		}
		if g.Used() != 0 {
			t.Fatalf("cut=%d 预算驻留 %d", cut, g.Used())
		}
	}
	// 完整流对照：干净结束
	rd := NewReader(bytes.NewReader(stream), Config{Global: NewGlobalBudget(0)})
	if _, err := readAll(rd); err != io.EOF {
		t.Fatalf("完整流应干净结束: %v", err)
	}
}

// TestStickyErrorAndNoCrossTalk 错误粘滞（不再走帧）与同连接不串位：
// 前请求畸形 → Drain 丢弃后续体 → 后请求独立读取器正常解析。
func TestStickyErrorAndNoCrossTalk(t *testing.T) {
	bad := forgedFrame(0xFF, 0, []byte("garbage-tail"))
	good := multiFrames(frameBytes(false, []byte("next-request-ok")))
	g := NewGlobalBudget(0)
	rd1 := NewReader(bytes.NewReader(multiFrames(bad, good)), Config{Global: g})
	if _, err := rd1.Next(); !IsProtocolError(err) {
		t.Fatalf("首请求应畸形: %v", err)
	}
	// 粘滞：后续 Next 恒同一错误（不再走帧不错位）
	if _, err := rd1.Next(); !IsProtocolError(err) {
		t.Fatalf("粘滞错误: %v", err)
	}
	// 畸形处置：Drain 丢弃该请求后续体
	if _, err := rd1.Drain(); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	// 后请求（独立体独立读取器）正常——读取器无跨请求状态天然不串位
	rd2 := NewReader(bytes.NewReader(good), Config{Global: g})
	frames, err := readAll(rd2)
	if err != io.EOF || len(frames) != 1 || string(frames[0].Body) != "next-request-ok" {
		t.Fatalf("后请求应正常: %v %+v", err, frames)
	}
}

// TestGlobalBudgetConcurrent 并发解析下全局预算精确记账（不超发、终态归零）。
func TestGlobalBudgetConcurrent(t *testing.T) {
	g := NewGlobalBudget(64 << 10)
	body := bytes.Repeat([]byte{7}, 256)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rd := NewReader(bytes.NewReader(multiFrames(frameBytes(false, body), frameBytes(false, body))), Config{Global: g})
			_, _ = readAll(rd)
			_ = rd.Close()
		}()
	}
	wg.Wait()
	if g.Used() != 0 {
		t.Fatalf("并发终态持有 = %d", g.Used())
	}
	// 过满注入：持有方不释放时新解析必拒（不排队膨胀）
	holder := NewReader(bytes.NewReader(frameBytes(false, bytes.Repeat([]byte{1}, 64<<10))), Config{Global: g})
	if _, err := holder.Next(); err != nil {
		t.Fatalf("holder: %v", err)
	}
	rejected := NewReader(bytes.NewReader(frameBytes(false, []byte{1})), Config{Global: g})
	if _, err := rejected.Next(); !IsBudgetError(err) {
		t.Fatalf("占满应拒: %v", err)
	}
	_ = holder.Close()
}

// TestZeroLengthMessageAndEmptyStream 空消息合法、空流立即 EOF。
func TestZeroLengthMessageAndEmptyStream(t *testing.T) {
	rd := NewReader(strings.NewReader(""), Config{Global: NewGlobalBudget(0)})
	if _, err := rd.Next(); err != io.EOF {
		t.Fatalf("空流应 io.EOF: %v", err)
	}
	rd2 := NewReader(bytes.NewReader(frameBytes(false, nil)), Config{Global: NewGlobalBudget(0)})
	fr, err := rd2.Next()
	if err != nil || fr.Index != 1 || len(fr.Body) != 0 {
		t.Fatalf("空消息应合法: err=%v frame=%+v", err, fr)
	}
	if _, err := rd2.Next(); err != io.EOF {
		t.Fatalf("空消息后应干净结束: %v", err)
	}
}
