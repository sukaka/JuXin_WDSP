// sf.go 最小 RFC 8941 结构化字段序列化（NG-ID G1 批次 C 参照客户端专用）：
// 仅覆盖签名构造所需子集——String（DQUOTE 与反斜杠转义）/Integer/Byte Sequence
// （标准 base64 带填充）/Inner List/Dictionary 参数段。许可证核实：候选库
// github.com/dunglas/httpsfv 为 BSD-3-Clause（宽松，可用——核实记录于
// docs/nextgen/s7/S7-EXIT-SUMMARY.md）；客户端只需序列化窄子集，自实现保持
// 本模块零第三方依赖（批次 A 网关侧 SF 解析同样自实现，两端同 RFC 文本）。
package main

import (
	"encoding/base64"
	"strconv"
	"strings"
)

// sfQuote 字符串序列化（RFC 8941 §3.3.3：值须在 %x20-7E；DQUOTE/反斜杠转义）。
func sfQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			panic("sf: 非可打印 ASCII 字符拒序列化")
		}
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteByte('"')
	return b.String()
}

// sfInt 整数序列化（RFC 8941 §3.3.1）。
func sfInt(v int64) string { return strconv.FormatInt(v, 10) }

// sfBytes Byte Sequence 序列化（RFC 8941 §3.3.5：标准 base64 带填充，冒号包裹）。
func sfBytes(b []byte) string { return ":" + base64.StdEncoding.EncodeToString(b) + ":" }

// sfInnerList 成分内列表（("@method" "@path") 形态——项均为字符串，G1 不用项参数）。
func sfInnerList(items []string) string {
	var b strings.Builder
	b.WriteByte('(')
	for i, it := range items {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(sfQuote(it))
	}
	b.WriteByte(')')
	return b.String()
}

// sfSigParams 签名参数段（;created=N;expires=M;nonce="x";keyid="k";alg="a" ——
// 参数序固定即签名基线 "@signature-params" 行尾序（网关经原文重读忠实重现，
// 客户端同串两用：头发送与基线构造））。
func sfSigParams(created, expires int64, nonce, keyID, alg string) string {
	return ";created=" + sfInt(created) +
		";expires=" + sfInt(expires) +
		";nonce=" + sfQuote(nonce) +
		";keyid=" + sfQuote(keyID) +
		";alg=" + sfQuote(alg)
}
