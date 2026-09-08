// 代码审查回归测试（批次5-A）：LOW-A6 嗅探决策后立即释放缓冲。
package httpparse

import "testing"

// 决策后（PLAINTEXT / ENCRYPTED / UNKNOWN 任一）缓冲立即置 nil，
// 不随流常驻（最高 16KB/流）到流表驱逐。
func TestBufferReleasedOnDecision(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"plaintext", "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{"encrypted", string([]byte{0x16, 0x03, 0x01, 0x00, 0x2e})},
		{"unknown", "SSH-2.0-x\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSniffer(0)
			if !s.Feed([]byte(tc.data)) {
				t.Fatal("单包应足以决策")
			}
			if s.buf != nil {
				t.Fatal("决策后嗅探缓冲应释放")
			}
			// 决策后继续 Feed 不重建缓冲
			s.Feed([]byte("more bytes"))
			if s.buf != nil {
				t.Fatal("决策后 Feed 不应重建缓冲")
			}
		})
	}
}
