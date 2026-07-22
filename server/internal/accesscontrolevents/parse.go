// Package accesscontrolevents 提供访问控制事件（IP黑白名单/CC防护）的解析、存储、查询与采集。
package accesscontrolevents

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 事件类型（网关 jiuzhang_guard 产生 + 管理面到期/解封补齐）
const (
	EventTypeCCTempBlockCreated  = "CC_TEMP_BLOCK_CREATED"
	EventTypeCCTempBlockExpired  = "CC_TEMP_BLOCK_EXPIRED"
	EventTypeCCTempBlockReleased = "CC_TEMP_BLOCK_RELEASED"
	EventTypeCCThresholdExceeded = "CC_THRESHOLD_EXCEEDED"
	EventTypeCCRequestRejected   = "CC_REQUEST_REJECTED"
)

// 动作
const (
	ActionLog       = "LOG"
	ActionObserve   = "OBSERVE"
	ActionReject    = "REJECT"
	ActionTempBlock = "TEMP_BLOCK"
)

// Event 是一条访问控制事件。
type Event struct {
	ID              uuid.UUID  `json:"id"`
	RequestID       string     `json:"request_id"`
	OccurredAt      time.Time  `json:"occurred_at"`
	ApplicationID   *uuid.UUID `json:"application_id"`
	ApplicationCode string     `json:"application_code"`
	ClientIP        string     `json:"client_ip"`
	ConnectionIP    string     `json:"connection_ip"`
	Domain          string     `json:"domain"`
	RequestMethod   string     `json:"request_method"`
	RequestPath     string     `json:"request_path"`
	EventType       string     `json:"event_type"`
	Action          string     `json:"action"`
	PolicyID        string     `json:"policy_id"`
	AccessRuleID    string     `json:"access_rule_id"`
	CurrentCount    *int64     `json:"current_count"`
	LimitValue      *int64     `json:"limit_value"`
	WindowSeconds   *int       `json:"window_seconds"`
	BlockExpiresAt  *time.Time `json:"block_expires_at"`
	ResponseStatus  *int       `json:"response_status"`
	GatewayNodeID   string     `json:"gateway_node_id"`
	Message         string     `json:"message"`
	CreatedAt       time.Time  `json:"created_at"`
}

// rawEvent 是网关 guard 事件 JSONL 行结构。
type rawEvent struct {
	RequestID       string     `json:"request_id"`
	OccurredAt      string     `json:"occurred_at"`
	ApplicationID   string     `json:"application_id"`
	ApplicationCode string     `json:"application_code"`
	ClientIP        string     `json:"client_ip"`
	ConnectionIP    string     `json:"connection_ip"`
	Domain          string     `json:"domain"`
	RequestMethod   string     `json:"request_method"`
	RequestPath     string     `json:"request_path"`
	EventType       string     `json:"event_type"`
	Action          string     `json:"action"`
	PolicyID        string     `json:"policy_id"`
	AccessRuleID    string     `json:"access_rule_id"`
	CurrentCount    *int64     `json:"current_count"`
	LimitValue      *int64     `json:"limit_value"`
	WindowSeconds   *int       `json:"window_seconds"`
	BlockExpiresAt  *time.Time `json:"block_expires_at"`
	ResponseStatus  *int       `json:"response_status"`
	GatewayNodeID   string     `json:"gateway_node_id"`
	Message         string     `json:"message"`
}

// ParseEventLine 解析单行 guard 事件 JSONL。defaultNode 为事件缺省网关节点。
// 解析失败的行由采集器写入错误文件，不得静默丢弃。
func ParseEventLine(line []byte, defaultNode string) (*Event, error) {
	line = []byte(strings.TrimSpace(string(line)))
	if len(line) == 0 {
		return nil, fmt.Errorf("empty line")
	}
	var raw rawEvent
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, fmt.Errorf("invalid event json: %w", err)
	}
	if raw.EventType == "" {
		return nil, fmt.Errorf("missing event_type")
	}
	if raw.OccurredAt == "" {
		return nil, fmt.Errorf("missing occurred_at")
	}
	occurredAt, err := time.Parse(time.RFC3339Nano, raw.OccurredAt)
	if err != nil {
		return nil, fmt.Errorf("invalid occurred_at: %w", err)
	}
	if raw.ClientIP == "" {
		return nil, fmt.Errorf("missing client_ip")
	}
	clientIP, err := netip.ParseAddr(raw.ClientIP)
	if err != nil {
		return nil, fmt.Errorf("invalid client_ip %q: %w", raw.ClientIP, err)
	}
	var connIP string
	if raw.ConnectionIP != "" {
		addr, err := netip.ParseAddr(raw.ConnectionIP)
		if err != nil {
			return nil, fmt.Errorf("invalid connection_ip %q: %w", raw.ConnectionIP, err)
		}
		connIP = addr.String()
	}
	var appID *uuid.UUID
	if raw.ApplicationID != "" {
		id, err := uuid.Parse(raw.ApplicationID)
		if err != nil {
			return nil, fmt.Errorf("invalid application_id %q: %w", raw.ApplicationID, err)
		}
		appID = &id
	}

	evt := &Event{
		RequestID:       truncate(raw.RequestID, 64),
		OccurredAt:      occurredAt.UTC(),
		ApplicationID:   appID,
		ApplicationCode: truncate(raw.ApplicationCode, 64),
		ClientIP:        clientIP.String(),
		ConnectionIP:    connIP,
		Domain:          truncate(raw.Domain, 255),
		RequestMethod:   truncate(raw.RequestMethod, 10),
		RequestPath:     truncate(raw.RequestPath, 512),
		EventType:       truncate(raw.EventType, 40),
		Action:          truncate(raw.Action, 20),
		PolicyID:        truncate(raw.PolicyID, 64),
		AccessRuleID:    truncate(raw.AccessRuleID, 64),
		CurrentCount:    raw.CurrentCount,
		LimitValue:      raw.LimitValue,
		WindowSeconds:   raw.WindowSeconds,
		BlockExpiresAt:  raw.BlockExpiresAt,
		ResponseStatus:  raw.ResponseStatus,
		GatewayNodeID:   truncate(raw.GatewayNodeID, 100),
		Message:         truncate(raw.Message, 512),
	}
	if evt.GatewayNodeID == "" {
		evt.GatewayNodeID = defaultNode
	}
	return evt, nil
}

// isRejected 判断事件是否为拒绝类（运行汇总 rejected 计数）。
func isRejected(evt *Event) bool {
	if evt.Action == ActionReject || evt.Action == ActionTempBlock {
		return true
	}
	return evt.EventType == EventTypeCCRequestRejected || evt.EventType == EventTypeCCTempBlockCreated
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
