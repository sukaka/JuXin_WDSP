package main

import (
	"strings"
	"testing"
)

// summarizeLine 不落原始行：敏感头/口令明文不得出现在错误记录中，
// 但保留 tx_id（尽力提取）、行长度与内容哈希供对照排查。
func TestSummarizeLine(t *testing.T) {
	line := []byte(`{"transaction":{"id":"tx-secret","timestamp":"2026/07/20 13:40:14",` +
		`"request":{"headers":{"authorization":["Bearer plain-secret"],"cookie":["session=plain-secret"]}}},"messages":[]}`)
	rec := summarizeLine(line, "boom")

	if rec.Reason != "boom" {
		t.Errorf("reason = %q", rec.Reason)
	}
	if rec.TxID != "tx-secret" {
		t.Errorf("tx_id = %q, want tx-secret（尽力提取）", rec.TxID)
	}
	if rec.LineBytes != len(line) {
		t.Errorf("line_bytes = %d, want %d", rec.LineBytes, len(line))
	}
	if len(rec.LineSHA256) != 64 {
		t.Errorf("line_sha256 长度 = %d, want 64", len(rec.LineSHA256))
	}
	// 记录任何字段均不得含原始敏感内容
	for _, forbidden := range []string{"plain-secret", "Bearer"} {
		if strings.Contains(rec.TxID, forbidden) || strings.Contains(rec.Reason, forbidden) {
			t.Errorf("错误记录泄漏原始内容: %+v", rec)
		}
	}

	// 非 JSON 行：无 tx_id，仍有长度与哈希
	rec2 := summarizeLine([]byte("{not json"), "invalid")
	if rec2.TxID != "" || rec2.LineBytes != 9 || rec2.LineSHA256 == "" {
		t.Errorf("非 JSON 行摘要异常: %+v", rec2)
	}
}
