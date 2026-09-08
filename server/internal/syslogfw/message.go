// Package syslogfw 提供 syslog（RFC5424）外发能力：UDP/TCP 传输、有界内存缓冲、
// 磁盘 spool 重放与配置热读取。安全事件/访问控制事件/访问日志采集器与操作审计/
// 登录日志/系统告警服务在入库成功后通过 Enqueue 非阻塞投递，
// 由后台协程按 system_settings（logging 组）最新配置外发。
package syslogfw

import (
	"fmt"
	"strings"
	"time"
)

// Kind 是外发消息类型。
type Kind int

const (
	KindSecurityEvent Kind = iota
	KindAccessControlEvent
	KindAccessLog
	KindOperationAudit
	KindLoginLog
	KindSystemAlert
	KindTest
)

// appName 是 RFC5424 APP-NAME 字段。
const appName = "jiuzhang-waf"

// msgID 返回 RFC5424 MSGID 字段。
func (k Kind) msgID() string {
	switch k {
	case KindSecurityEvent:
		return "security-event"
	case KindAccessControlEvent:
		return "access-control-event"
	case KindAccessLog:
		return "access-log"
	case KindOperationAudit:
		return "operation-audit"
	case KindLoginLog:
		return "login-log"
	case KindSystemAlert:
		return "system-alert"
	case KindTest:
		return "test"
	}
	return "event"
}

// RFC5424 severity 数值。
const (
	severityCritical = 2
	severityError    = 3
	severityWarning  = 4
	severityNotice   = 5
	severityInfo     = 6
)

// severityFor 计算消息的 severity：
// - 安全事件按事件等级映射（HIGH→3/MEDIUM→4/LOW→5/其他→6）
// - 系统告警按告警等级映射（CRITICAL→2/HIGH→3/MEDIUM→4/LOW→5/其他→6）
// - 登录日志与操作审计 hint 为 "warning"（登录失败、删除/禁用类操作）时 →4
// - 其余类型固定 6（info）
func severityFor(kind Kind, severityHint string) int {
	switch kind {
	case KindSecurityEvent:
		switch strings.ToUpper(severityHint) {
		case "HIGH":
			return severityError
		case "MEDIUM":
			return severityWarning
		case "LOW":
			return severityNotice
		}
	case KindSystemAlert:
		switch strings.ToUpper(severityHint) {
		case "CRITICAL":
			return severityCritical
		case "HIGH":
			return severityError
		case "MEDIUM":
			return severityWarning
		case "LOW":
			return severityNotice
		}
	case KindLoginLog, KindOperationAudit:
		if strings.EqualFold(severityHint, "warning") {
			return severityWarning
		}
	}
	return severityInfo
}

// sanitizeField 清洗 RFC5424 头部字段（空格与不可见字符会破坏帧解析，空值用 NILVALUE）。
func sanitizeField(s string) string {
	s = strings.Map(func(r rune) rune {
		if r <= ' ' || r == 0x7f {
			return '-'
		}
		return r
	}, s)
	if s == "" {
		return "-"
	}
	if len(s) > 255 {
		s = s[:255]
	}
	return s
}

// BuildMessage 构造 RFC5424 消息：
// <pri>1 timestamp hostname app-name procid msgid structured-data msg
// msg 为紧凑 JSON（由调用方 marshal）。返回不含换行符的单行消息。
func BuildMessage(facility, severity int, hostname, procID string, kind Kind, msg []byte) []byte {
	if facility < 0 || facility > 23 {
		facility = 1
	}
	pri := facility*8 + severity
	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
	// 换行会破坏 UDP 单报文与 TCP non-transparent 分帧，一律替换为空格
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, string(msg))
	return []byte(fmt.Sprintf("<%d>1 %s %s %s %s %s - %s",
		pri, ts, sanitizeField(hostname), appName, sanitizeField(procID), kind.msgID(), clean))
}
