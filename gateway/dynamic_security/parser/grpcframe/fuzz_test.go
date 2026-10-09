// fuzz_test.go 帧读取器 Go native fuzz（R01 断言形态：任意字节序列无 panic、
// 无越界读、无预算逃逸、无全局预算驻留——语料覆盖合法多帧/分片/截断/
// 长度伪造/压缩炸弹/嵌套 gzip/零长/64 消息边界；黄金表驱动测试互补于
// reader_test.go / decompress_test.go）。
package grpcframe

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// fuzzFrame 语料构造（与 reader_test.go 同形，独立一份防 fuzz 种子互相污染）。
func fuzzFrame(compressed bool, body []byte) []byte {
	out := make([]byte, 5, 5+len(body))
	if compressed {
		out[0] = 1
	}
	binary.BigEndian.PutUint32(out[1:5], uint32(len(body)))
	return append(out, body...)
}

func fuzzGzip(payload []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(payload)
	_ = zw.Close()
	return buf.Bytes()
}

// FuzzGrpcFrameReader 帧读取器模糊目标。
// data=帧流原文；step=分片步进（1~23 字节，模拟任意切分）；mode bit0=对压缩帧
// 调 Gunzip（含嵌套/炸弹），bit1=用小预算配置（更易触顶）。
func FuzzGrpcFrameReader(f *testing.F) {
	bomb := fuzzGzip(make([]byte, 1<<20))     // 压缩炸弹（全零 1MiB）
	nested := fuzzGzip(fuzzGzip([]byte("x"))) // 嵌套 gzip
	var sixtyFour []byte                      // 64 消息边界
	for i := 0; i < 64; i++ {
		sixtyFour = append(sixtyFour, fuzzFrame(false, []byte{byte(i)})...)
	}
	seeds := [][]byte{
		fuzzFrame(false, []byte("hello")),                                                // 单帧
		append(fuzzFrame(false, []byte("a")), fuzzFrame(true, fuzzGzip([]byte("b")))...), // 合法多帧
		fuzzFrame(false, nil),                                                            // 零长消息
		{0xFF, 0, 0, 0, 0},                                                               // 保留位非零
		{0, 0xFF, 0xFF, 0xFF, 0xFF},                                                      // 长度伪造最大
		{0, 0, 0, 0, 10, 1, 2, 3},                                                        // 声明 > 剩余（截断体）
		{0, 0, 0},                                                                        // 截断头
		append(fuzzFrame(true, nil), []byte("tail")...),                                  // 压缩空帧
		append(fuzzFrame(true, bomb[:40]), fuzzFrame(false, []byte("x"))...), // 炸弹截断
		fuzzFrame(true, bomb),   // 完整炸弹帧
		fuzzFrame(true, nested), // 嵌套帧
		sixtyFour,               // 恰 64 消息
		append(sixtyFour, fuzzFrame(false, []byte{65})...), // 65 消息
		{},
	}
	for _, s := range seeds {
		f.Add(s, uint8(1), uint8(1))
		f.Add(s, uint8(7), uint8(3))
	}
	f.Add([]byte("random"), uint8(0), uint8(2))

	f.Fuzz(func(t *testing.T, data []byte, step, mode uint8) {
		g := NewGlobalBudget(0)
		cfg := Config{Global: g}
		if mode&2 != 0 {
			// 小预算配置：更易触顶（预算拒绝路径覆盖率）
			cfg.MaxMessageBytes = 64
			cfg.MaxMessages = 4
			cfg.MaxRequestBytes = 256
		}
		rd := NewReader(newStepReader(bytes.NewReader(data), 1+int(step%23)), cfg)
		for i := 0; i < 80; i++ { // 读帧循环硬上限（fuzz 不得挂死）
			fr, err := rd.Next()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				// bytes.Reader 不产生源错误：终止错误必须已分类
				// （协议格式/预算/编码三类之一）——未知类即契约破坏
				if !IsProtocolError(err) && !IsBudgetError(err) && !IsEncodingError(err) {
					t.Fatalf("未分类错误 %T: %v", err, err)
				}
				break
			}
			if fr.Index > 64 && mode&2 == 0 {
				t.Fatalf("消息数预算逃逸: %d", fr.Index)
			}
			if int64(len(fr.Body)) > DefaultMaxMessageBytes && mode&2 == 0 {
				t.Fatalf("单消息预算逃逸: %d", len(fr.Body))
			}
			if mode&1 != 0 && fr.Compressed {
				// 有界解压不得 panic/不得超内存逃逸（预算内错误合法）
				_, _ = Gunzip(fr.Body)
			}
		}
		_ = rd.Close()
		if g.Used() != 0 {
			t.Fatalf("全局预算驻留 %d（泄漏）", g.Used())
		}
	})
}
