// Package apievents API 动态防护运行时事件输出（JSON Lines，由管理平台采集入库）。
// 与 events 包（访问控制/CC 事件）并列，承载统一引擎产出的主事件与端点发现信息。
package apievents

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// Record 统一运行时主事件 + 端点发现信息（采集端据此写 api_runtime_events 并 upsert 端点资产）。
type Record struct {
	ID            string                `json:"id,omitempty"`
	RequestID     string                `json:"request_id"`
	OccurredAt    time.Time             `json:"occurred_at"`
	ApplicationID string                `json:"application_id,omitempty"`
	AppCode       string                `json:"app_code,omitempty"`
	Domain        string                `json:"domain,omitempty"`
	EndpointKey   string                `json:"endpoint_key"`
	Method        string                `json:"method,omitempty"`
	PathTemplate  string                `json:"path_template,omitempty"`
	IsAPI         bool                  `json:"is_api"`
	APIConfidence float64               `json:"api_confidence,omitempty"`
	RiskScore     int                   `json:"risk_score"`
	RiskLevel     string                `json:"risk_level"`
	FinalAction   string                `json:"final_action"`
	Details       []dsctx.DetectorMatch `json:"details"`
	GatewayNode   string                `json:"gateway_node_id"`
}

// 字段长度上限（防超大输入撑爆日志）。
const (
	maxEndpointKeyLen = 560
	maxPathLen        = 512
	maxDomainLen      = 255
)

// Logger JSON Lines 事件记录器（并发安全）。
type Logger struct {
	mu   sync.Mutex
	f    *os.File
	node string
}

// NewLogger 打开事件日志文件（追加写入）。
func NewLogger(path, gatewayNode string) (*Logger, error) {
	if path == "" {
		return nil, fmt.Errorf("api events log path required")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open api events log: %w", err)
	}
	return &Logger{f: f, node: gatewayNode}, nil
}

// sanitize 截断超长字段、剥离控制字符（防日志注入；JSON 转义为第二道防线）。
func sanitize(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}

// Emit 输出一条记录（出错返回，不静默丢弃）。
func (l *Logger) Emit(e Record) error {
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	e.GatewayNode = l.node
	e.EndpointKey = sanitize(e.EndpointKey, maxEndpointKeyLen)
	e.PathTemplate = sanitize(e.PathTemplate, maxPathLen)
	e.Domain = sanitize(e.Domain, maxDomainLen)
	if e.Details == nil {
		e.Details = []dsctx.DetectorMatch{}
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal api event: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write api event: %w", err)
	}
	return nil
}

// Close 关闭文件。
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
