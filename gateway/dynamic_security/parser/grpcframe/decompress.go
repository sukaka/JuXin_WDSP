// decompress.go gRPC 压缩有界解压（NG-GRPC §1.5/D5 冻结）。
//
//   - 批准算法：gzip 唯一（identity 未压缩为基线）；其余 grpc-encoding 值 →
//     EncodingError（UNIMPLEMENTED(12) 语义——协议标准应答而非安全误断，
//     执行层批次 B 消费）；
//   - 四重预算：压缩体 ≤4MiB（与单消息上限同源，独立夹紧防御）/ 解压 ≤16MiB /
//     倍率 ≤100×（+CPU 工作预算由请求处理时延预算承担，§1.7，本层不重复计时）；
//   - 不无限解压（R02）：流式 gzip.Reader 配双层 io.LimitReader（解压 16MiB
//     外层 + 倍率内层）读断——峰值内存 ≤ min(16MiB, 100×压缩体)+1，与炸弹
//     理论膨胀量无关；
//   - 嵌套 gzip 不递归解压（递归即放大器）：内层字节按数据如实返回。
package grpcframe

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
)

// CheckEncoding grpc-encoding 头值校验（§1.5）：identity（缺省等同）/gzip 通过
// （返回规范名）；其余值返回 *EncodingError（UNIMPLEMENTED(12) 语义）。
func CheckEncoding(enc string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "", "identity":
		return "identity", nil
	case "gzip":
		return "gzip", nil
	default:
		return "", &EncodingError{Encoding: enc}
	}
}

// Gunzip 有界解压（四重预算逐层）：compressed 为单消息线格式字节
// （长度通常已被帧读取器单消息预算约束，本函数仍独立夹紧防御）。
// 返回解压字节；预算触顶返回 *BudgetError（compressed_bytes /
// decompressed_bytes / decompress_ratio），gzip 流损坏返回 *ProtocolError
// （invalid_gzip——格式错误类，与预算语义分离）。
func Gunzip(compressed []byte) ([]byte, error) {
	if int64(len(compressed)) > MaxCompressedBytes {
		return nil, &BudgetError{Kind: "compressed_bytes", Limit: MaxCompressedBytes, Actual: int64(len(compressed))}
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, &ProtocolError{Kind: "invalid_gzip", Detail: err.Error()}
	}
	defer func() { _ = zr.Close() }()

	ratioCap := int64(len(compressed)) * MaxDecompressRatio
	// 双层 LimitReader 读断（外层解压 16MiB、内层倍率）——任一先到即停，
	// 实际读取 ≤ min(16MiB, 100×压缩体)+1，不无限解压
	limited := io.LimitReader(io.LimitReader(zr, MaxDecompressedBytes+1), ratioCap+1)
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, &ProtocolError{Kind: "invalid_gzip", Detail: err.Error()}
	}
	if int64(len(out)) > ratioCap {
		return nil, &BudgetError{Kind: "decompress_ratio", Limit: ratioCap, Actual: int64(len(out))}
	}
	if int64(len(out)) > MaxDecompressedBytes {
		return nil, &BudgetError{Kind: "decompressed_bytes", Limit: MaxDecompressedBytes, Actual: int64(len(out))}
	}
	return out, nil
}
