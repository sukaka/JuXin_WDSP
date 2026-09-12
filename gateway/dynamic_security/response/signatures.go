package response

import "bytes"

// maxErrorSignatureScanBytes 错误签名体扫描上限（防超大响应体扫描开销）。
const maxErrorSignatureScanBytes = 64 << 10

// errorSignatureNeedles 错误签名特征子串表（固定顺序，命中即收录一次）。
// 仅匹配堆栈/错误特征，不提取原文（证据只含签名标签）。
var errorSignatureNeedles = []struct {
	signature string
	needles   []string
}{
	{"stack.python_traceback", []string{"Traceback (most recent call last)"}},
	{"stack.go_panic", []string{"panic: "}},
	{"stack.java_trace", []string{".java:", "Exception in thread"}},
	{"db.sqlstate", []string{"SQLSTATE"}},
	{"db.oracle", []string{"ORA-"}},
}

// ExtractErrorSignatures 提取响应错误签名：5xx 状态码 + 体内堆栈/数据库错误特征。
// body 为捕获体（可截断/可为空）；扫描上限 64 KiB。
func ExtractErrorSignatures(status int, body []byte) []string {
	var sigs []string
	if status >= 500 && status < 600 {
		sigs = append(sigs, "http_5xx")
	}
	if len(body) == 0 {
		return sigs
	}
	scan := body
	if len(scan) > maxErrorSignatureScanBytes {
		scan = scan[:maxErrorSignatureScanBytes]
	}
	for _, c := range errorSignatureNeedles {
		for _, n := range c.needles {
			if bytes.Contains(scan, []byte(n)) {
				sigs = append(sigs, c.signature)
				break
			}
		}
	}
	return sigs
}
