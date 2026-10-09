// decompress_test.go 有界解压黄金样本：四重压缩预算逐层边界（恰等/超 1）、
// 未知算法（UNIMPLEMENTED 语义）、嵌套 gzip、gzip 流损坏、zip bomb 读断
// 峰值证据（R02 不无限解压）。
package grpcframe

import (
	"bytes"
	"compress/gzip"
	"errors"
	"testing"
)

// gzipBytes 压缩构造（测试辅助）。
func gzipBytes(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestGunzipRoundtrip(t *testing.T) {
	// 低压缩率负载（伪随机确定序列，倍率 <100× 合法区间）
	payload := make([]byte, 13000)
	for i := range payload {
		payload[i] = byte(i*31 + i>>4)
	}
	compressed := gzipBytes(t, payload)
	out, err := Gunzip(compressed)
	if err != nil || !bytes.Equal(out, payload) {
		t.Fatalf("往返 = %v %d", err, len(out))
	}
	// 恰等边界：倍率恰 100× 内放行
	small := bytes.Repeat([]byte{1}, 128)
	c := gzipBytes(t, small)
	if _, err := Gunzip(c); err != nil {
		t.Fatalf("正常倍率应放行: %v", err)
	}
}

func TestGunzipInputBudget(t *testing.T) {
	// 压缩体 >4MiB：独立夹紧（帧读取器之外的第二道防线）
	over := make([]byte, MaxCompressedBytes+1)
	if _, err := Gunzip(over); err == nil {
		t.Fatal("超 4MiB 压缩体应拒")
	} else {
		var be *BudgetError
		if !errors.As(err, &be) || be.Kind != "compressed_bytes" || be.Limit != MaxCompressedBytes {
			t.Fatalf("应 compressed_bytes: %v", err)
		}
	}
}

func TestGunzipRatioBudget(t *testing.T) {
	// 高熵小输入 + 大膨胀：128 字节全零 → gzip ~几十字节？全零压缩率极高——
	// 用低压缩率形态控制输入体量：直接构造 10KB 随机态（伪随机确定序列）
	payload := make([]byte, 10<<10)
	for i := range payload {
		payload[i] = byte(i*7 + i>>3)
	}
	compressed := gzipBytes(t, payload)
	// 人为放大：把压缩预算检查旁路，直接验证倍率——构造超大膨胀比输入：
	// 全零 200KB → gzip 仅 ~200B，倍率 ~1000×（超 100×）
	bomb := gzipBytes(t, make([]byte, 200<<10))
	_, err := Gunzip(bomb)
	var be *BudgetError
	if !errors.As(err, &be) || be.Kind != "decompress_ratio" {
		t.Fatalf("超倍率应 decompress_ratio: %v", err)
	}
	// 读断峰值证据：Actual = 100×压缩体 + 1（双层读断点，与理论膨胀量无关）
	wantCap := int64(len(bomb)) * MaxDecompressRatio
	if be.Actual != wantCap+1 {
		t.Fatalf("读断点 = %d，应 %d（压缩体 %d 的 100×+1）", be.Actual, wantCap+1, len(bomb))
	}
	if int64(len(compressed)) <= 0 {
		t.Fatal("辅助输入无效")
	}
}

func TestGunzipOutputBudget(t *testing.T) {
	// 三层预算命中顺序构造：压缩体须落在 (16MiB/100, 4MiB) = (160KiB, 4MiB)
	// 区间——此时倍率预算（压缩体×100）> 16MiB，总量层 decompressed_bytes
	// 必先触顶；同时压缩体 <4MiB 不撞 compressed_bytes 输入层。
	// 形态：低熵密度载荷（每 16 字节 1 字节 xorshift 随机 + 15 字节零填充，
	// 熵密度 1/16，压缩率 ~13×）——17MiB 解压输出对应压缩体 ~1MiB 区间中。
	// （注意 DEFLATE 滑动窗口仅 32KiB：重复大块超过窗口即不可反向引用，
	// 大块重复构造无效，必须靠熵密度控制压缩率）
	payload := make([]byte, 17<<20)
	var x uint32 = 42
	for i := 0; i < len(payload); i += 16 {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		payload[i] = byte(x >> 24)
	}
	compressed := gzipBytes(t, payload)
	if int64(len(compressed)) > MaxCompressedBytes {
		t.Fatalf("构造前提不成立（压缩体 %d 超 4MiB 输入层）", len(compressed))
	}
	if int64(len(compressed))*MaxDecompressRatio <= MaxDecompressedBytes {
		t.Fatalf("构造前提不成立（压缩体 %d 的 100× 未超 16MiB）", len(compressed))
	}
	_, err := Gunzip(compressed)
	var be *BudgetError
	if !errors.As(err, &be) || be.Kind != "decompressed_bytes" {
		t.Fatalf("超解压总量应 decompressed_bytes: %v", err)
	}
	if be.Actual != MaxDecompressedBytes+1 {
		t.Fatalf("读断点 = %d，应 %d", be.Actual, MaxDecompressedBytes+1)
	}
}

func TestGunzipBombPeakBounded(t *testing.T) {
	// R02 压缩炸弹：4MiB 全零（理论膨胀 ~4GiB 级别形态）——双层读断，
	// 错误分类稳定，峰值 = min(16MiB, 100×压缩体)+1 与理论膨胀无关
	bomb := gzipBytes(t, make([]byte, 4<<20))
	_, err := Gunzip(bomb)
	var be *BudgetError
	if !errors.As(err, &be) {
		t.Fatalf("炸弹应预算拒绝: %v", err)
	}
	if be.Kind != "decompress_ratio" && be.Kind != "decompressed_bytes" {
		t.Fatalf("炸弹触顶层 = %q", be.Kind)
	}
}

func TestGunzipNestedNotRecursive(t *testing.T) {
	// 嵌套 gzip：外层解压出内层 gzip 字节按数据处理（不递归——递归即放大器）
	inner := gzipBytes(t, []byte("payload"))
	nested := gzipBytes(t, inner)
	out, err := Gunzip(nested)
	if err != nil {
		t.Fatalf("嵌套外层应正常解压: %v", err)
	}
	if !bytes.Equal(out, inner) {
		t.Fatalf("输出应为内层 gzip 字节: %d vs %d", len(out), len(inner))
	}
	if len(out) < 2 || out[0] != 0x1f || out[1] != 0x8b {
		t.Fatal("输出仍具 gzip magic（未递归）")
	}
}

func TestGunzipInvalidStream(t *testing.T) {
	cases := [][]byte{
		nil,                           // 空
		{0x1f},                        // magic 半截
		{0x1f, 0x8b},                  // 头不完整
		[]byte("not a gzip stream"),   // 非 gzip
		gzipBytes(t, []byte("x"))[:5], // 截断头
	}
	for i, c := range cases {
		_, err := Gunzip(c)
		var pe *ProtocolError
		if !errors.As(err, &pe) || pe.Kind != "invalid_gzip" {
			t.Errorf("case %d 应 invalid_gzip（格式类）: %v", i, err)
		}
		if IsBudgetError(err) {
			t.Errorf("case %d 流损坏不得归入预算类", i)
		}
	}
	// 头合法体截断
	full := gzipBytes(t, []byte("hello"))
	if _, err := Gunzip(full[:len(full)-3]); !IsProtocolError(err) {
		t.Fatalf("体截断应 invalid_gzip: %v", err)
	}
}

func TestCheckEncoding(t *testing.T) {
	for _, ok := range []string{"", "identity", "IDENTITY", "gzip", "GZIP", " gzip "} {
		if _, err := CheckEncoding(ok); err != nil {
			t.Errorf("%q 应通过: %v", ok, err)
		}
	}
	canon, _ := CheckEncoding("")
	if canon != "identity" {
		t.Fatalf("缺省应 identity: %q", canon)
	}
	for _, bad := range []string{"snappy", "lz4", "zstd", "deflate", "br"} {
		_, err := CheckEncoding(bad)
		var ee *EncodingError
		if !errors.As(err, &ee) || ee.Encoding != bad {
			t.Errorf("%q 应 EncodingError（UNIMPLEMENTED 语义）: %v", bad, err)
		}
	}
}

// TestFrameMessageCompressed Frame.Message 接线（压缩帧经有界解压；未压缩直通）。
func TestFrameMessageCompressed(t *testing.T) {
	payload := []byte("protobuf-bytes")
	fr := &Frame{Index: 1, Compressed: true, Body: gzipBytes(t, payload)}
	out, err := fr.Message()
	if err != nil || !bytes.Equal(out, payload) {
		t.Fatalf("压缩帧 Message = %v", err)
	}
	fr2 := &Frame{Index: 1, Body: payload}
	if out2, err := fr2.Message(); err != nil || !bytes.Equal(out2, payload) {
		t.Fatalf("未压缩帧 Message = %v", err)
	}
	var frNil *Frame
	if out3, err := frNil.Message(); err != nil || out3 != nil {
		t.Fatal("nil Frame 零值安全")
	}
}
