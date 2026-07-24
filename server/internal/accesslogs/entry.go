// Package accesslogs 全量访问日志（二期）：网关 JSON Lines 采集入库、分页查询与留存清理。
//
// 数据流：网关 jiuzhang_guard 在放行路径写 access-full.jsonl（已脱敏）→ 本包采集器
// tail 文件（DB 断点 event_collector_checkpoints，collector_id=accesslog-01）逐行解析入库
// access_logs 表；留存清理由 retention 循环按 logging.retention_days 定期批量删除。
package accesslogs

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// LogEntry 是网关 access-full.jsonl 单行（字段与 guard accessLogRecord / access_logs 表对应）。
type LogEntry struct {
	OccurredAt            time.Time           `json:"occurred_at"`
	RequestID             string              `json:"request_id"`
	ApplicationID         string              `json:"application_id"`
	Domain                string              `json:"domain"`
	GatewayNodeID         string              `json:"gateway_node_id"`
	ClientIP              string              `json:"client_ip"`
	ClientPort            int                 `json:"client_port"`
	RequestMethod         string              `json:"request_method"`
	RequestURI            string              `json:"request_uri"`
	RequestPath           string              `json:"request_path"`
	QuerySummary          string              `json:"query_summary"`
	HTTPVersion           string              `json:"http_version"`
	ContentType           string              `json:"content_type"`
	UserAgentSummary      string              `json:"user_agent_summary"`
	RefererSummary        string              `json:"referer_summary"`
	ResponseStatus        int                 `json:"response_status"`
	BytesIn               int64               `json:"bytes_in"`
	BytesOut              int64               `json:"bytes_out"`
	DurationMS            int                 `json:"duration_ms"`
	WAFAction             string              `json:"waf_action"`
	RequestHeaders        map[string][]string `json:"request_headers"`
	RequestBody           string              `json:"request_body"`
	RequestBodyTruncated  bool                `json:"request_body_truncated"`
	ResponseHeaders       map[string][]string `json:"response_headers"`
	ResponseBody          string              `json:"response_body"`
	ResponseBodyTruncated bool                `json:"response_body_truncated"`
}

// 入库前字段长度兜底（网关侧已截断，采集侧再防一道，防脏数据撑爆表）。
const (
	maxLineLen       = 1 << 20 // 1MB，超限行直接进失败队列
	maxRequestIDLen  = 64
	maxDomainLen     = 255
	maxNodeLen       = 64
	maxMethodLen     = 16
	maxVersionLen    = 16
	maxCTLen         = 255
	maxSummaryLen    = 512
	maxWAFActionLen  = 32
	maxBodyColumnLen = 1 << 20 // text 列兜底 1MB
)

// ParseLine 解析单行 JSON Lines 访问日志（校验 + 长度兜底 + NUL 剥离）。
func ParseLine(line []byte) (*LogEntry, error) {
	s := strings.TrimSpace(string(line))
	if s == "" {
		return nil, fmt.Errorf("empty line")
	}
	if len(s) > maxLineLen {
		return nil, fmt.Errorf("line too long: %d bytes", len(s))
	}
	var e LogEntry
	if err := json.Unmarshal([]byte(s), &e); err != nil {
		return nil, fmt.Errorf("invalid access log json: %w", err)
	}
	if e.OccurredAt.IsZero() {
		return nil, fmt.Errorf("missing occurred_at")
	}
	e.RequestID = truncateStr(e.RequestID, maxRequestIDLen)
	e.Domain = truncateStr(e.Domain, maxDomainLen)
	e.GatewayNodeID = truncateStr(e.GatewayNodeID, maxNodeLen)
	e.RequestMethod = truncateStr(e.RequestMethod, maxMethodLen)
	e.HTTPVersion = truncateStr(e.HTTPVersion, maxVersionLen)
	e.ContentType = truncateStr(e.ContentType, maxCTLen)
	e.UserAgentSummary = truncateStr(e.UserAgentSummary, maxSummaryLen)
	e.RefererSummary = truncateStr(e.RefererSummary, maxSummaryLen)
	e.WAFAction = truncateStr(e.WAFAction, maxWAFActionLen)
	// PostgreSQL text 列拒绝 NUL；网关侧已剥离，采集侧再兜底
	e.RequestBody = truncateStr(stripNUL(e.RequestBody), maxBodyColumnLen)
	e.ResponseBody = truncateStr(stripNUL(e.ResponseBody), maxBodyColumnLen)
	e.RequestURI = stripNUL(e.RequestURI)
	e.RequestPath = stripNUL(e.RequestPath)
	e.QuerySummary = stripNUL(e.QuerySummary)
	return &e, nil
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func stripNUL(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}
