// 代码审查回归测试（批次5-A）：
// LOW-A3 磁盘缓存单记录上限覆盖合法最大 HTTP 记录（Body 硬上限 10MB×2+开销），
// 断网期大 Body 记录不再被静默丢弃。
package buffer

import (
	"bytes"
	"testing"
	"time"
)

func TestWriteLargeHTTPRecordRoundTrip(t *testing.T) {
	b := openTB(t, 0, 0, time.Hour)
	// 12MB：超旧 1MB 上限的合法大记录（请求+响应 Body 可各达 10MB 硬上限）
	big := bytes.Repeat([]byte{'x'}, 12<<20)
	if err := b.Write(big); err != nil {
		t.Fatalf("大记录应可写入: %v", err)
	}
	got := 0
	_, err := b.Replay(10, func(recs [][]byte) error {
		for _, r := range recs {
			if !bytes.Equal(r, big) {
				t.Fatalf("补传记录内容不符: len=%d", len(r))
			}
			got++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("大记录应完整补传: %d", got)
	}
}

func TestWriteOverMaxRecordStillRejected(t *testing.T) {
	b := openTB(t, 0, 0, time.Hour)
	if err := b.Write(make([]byte, maxRecordBytes+1)); err == nil {
		t.Fatal("超单记录上限仍应拒绝（防御畸形）")
	}
	if err := b.Write(make([]byte, maxRecordBytes)); err != nil {
		t.Fatalf("恰达上限应可写入: %v", err)
	}
}
