// Package events 访问控制/CC 事件输出（JSON Lines，由管理平台采集入库）。
package events

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Type 事件类型。
type Type string

const (
	IPAllowMatch           Type = "IP_ALLOW_MATCH"
	IPDenyMatch            Type = "IP_DENY_MATCH"
	CCThresholdExceeded    Type = "CC_THRESHOLD_EXCEEDED"
	CCRequestRejected      Type = "CC_REQUEST_REJECTED"
	CCTempBlockCreated     Type = "CC_TEMP_BLOCK_CREATED"
	CCTempBlockExpired     Type = "CC_TEMP_BLOCK_EXPIRED"
	CCTempBlockReleased    Type = "CC_TEMP_BLOCK_RELEASED"
	TrustedProxyInvalid    Type = "TRUSTED_PROXY_INVALID"
	ForwardedHeaderInvalid Type = "FORWARDED_HEADER_INVALID"
	ForwardedChainTooLong  Type = "FORWARDED_CHAIN_TOO_LONG"
	RateLimitEngineError   Type = "RATE_LIMIT_ENGINE_ERROR"
)

// Event 访问控制/CC 事件（字段与数据库 access_control_events 对应）。
type Event struct {
	RequestID      string     `json:"request_id"`
	OccurredAt     time.Time  `json:"occurred_at"`
	ApplicationID  string     `json:"application_id,omitempty"`
	AppCode        string     `json:"application_code,omitempty"`
	ClientIP       string     `json:"client_ip"`
	ConnectionIP   string     `json:"connection_ip"`
	Domain         string     `json:"domain,omitempty"`
	Method         string     `json:"request_method,omitempty"`
	Path           string     `json:"request_path,omitempty"`
	EventType      Type       `json:"event_type"`
	Action         string     `json:"action,omitempty"`
	PolicyID       string     `json:"policy_id,omitempty"`
	AccessRuleID   string     `json:"access_rule_id,omitempty"`
	CurrentCount   int64      `json:"current_count,omitempty"`
	LimitValue     int64      `json:"limit_value,omitempty"`
	WindowSeconds  int        `json:"window_seconds,omitempty"`
	BlockExpiresAt *time.Time `json:"block_expires_at,omitempty"`
	ResponseStatus int        `json:"response_status,omitempty"`
	GatewayNode    string     `json:"gateway_node_id"`
	Message        string     `json:"message,omitempty"`
}

// 字段长度上限（防超大输入撑爆日志）。
const (
	maxPathLen   = 512
	maxDomainLen = 255
	maxMsgLen    = 512
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
		return nil, fmt.Errorf("events log path required")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open events log: %w", err)
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

// Emit 输出一条事件（出错返回，不静默丢弃）。
func (l *Logger) Emit(e Event) error {
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	e.GatewayNode = l.node
	e.Path = sanitize(e.Path, maxPathLen)
	e.Domain = sanitize(e.Domain, maxDomainLen)
	e.Message = sanitize(e.Message, maxMsgLen)
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	return nil
}

// Close 关闭文件。
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
