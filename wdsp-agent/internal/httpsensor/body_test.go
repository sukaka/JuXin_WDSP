package httpsensor

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"testing"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
)

func TestProcessBodyDecompressionTruncation(t *testing.T) {
	const maxBodySize = 8
	plain := []byte(`{"payload":"long"}`)

	tests := []struct {
		name     string
		encoding string
		compress func([]byte) []byte
	}{
		{name: "gzip", encoding: "gzip", compress: gzipBytes},
		{name: "deflate", encoding: "deflate", compress: zlibBytes},
	}
	for _, tc := range tests {
		t.Run(tc.name+" over limit", func(t *testing.T) {
			res := processBody(tc.compress(plain), int64(len(plain)), false, map[string]string{
				"content-type":     "application/json",
				"content-encoding": tc.encoding,
			}, &Policy{Level: config.LevelL2, MaxBodySize: maxBodySize}, nil)

			if !res.truncated {
				t.Fatalf("解压输出超限后应标记 truncated: %+v", res)
			}
			if len(res.body) != maxBodySize {
				t.Fatalf("解压输出驻留内存超限: got %d, want %d", len(res.body), maxBodySize)
			}
		})

		t.Run(tc.name+" within limit", func(t *testing.T) {
			res := processBody(tc.compress(plain), int64(len(plain)), false, map[string]string{
				"content-type":     "application/json",
				"content-encoding": tc.encoding,
			}, &Policy{Level: config.LevelL2, MaxBodySize: len(plain)}, nil)

			if res.truncated {
				t.Fatalf("解压输出未超限不应标记 truncated: %+v", res)
			}
			if res.body != string(plain) {
				t.Fatalf("解压内容错误: got %q, want %q", res.body, plain)
			}
		})
	}
}

func TestProcessBodyPreservesCaptureTruncationAfterDecompression(t *testing.T) {
	plain := []byte(`{"ok":true}`)
	res := processBody(gzipBytes(plain), int64(len(plain)), true, map[string]string{
		"content-type":     "application/json",
		"content-encoding": "gzip",
	}, &Policy{Level: config.LevelL2, MaxBodySize: len(plain)}, nil)

	if !res.truncated {
		t.Fatalf("原始抓包已截断时不应被解压路径清除: %+v", res)
	}
	if res.body != string(plain) {
		t.Fatalf("解压内容错误: got %q, want %q", res.body, plain)
	}
}

func gzipBytes(in []byte) []byte {
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	_, _ = w.Write(in)
	_ = w.Close()
	return out.Bytes()
}

func zlibBytes(in []byte) []byte {
	var out bytes.Buffer
	w := zlib.NewWriter(&out)
	_, _ = w.Write(in)
	_ = w.Close()
	return out.Bytes()
}
