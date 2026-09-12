package syslogfw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"
)

const (
	// queueCapacity 是内存缓冲容量，满了丢弃最旧并告警计数。
	queueCapacity = 10000
	// spoolMaxBytes 是磁盘 spool 上限（50MB），超过时重写文件只留后半部分。
	spoolMaxBytes = 50 << 20
	// spoolFileName 是 spool 文件名（位于数据目录下）。
	spoolFileName = "syslog-spool.jsonl"
	// dialTimeout 是连接与写超时。
	dialTimeout = 5 * time.Second
)

// SettingsReader 是 forwarder 依赖的设置读取接口（*settings.Service 实现，测试可注入内存实现）。
type SettingsReader interface {
	GetBool(ctx context.Context, group, key string, def bool) bool
	GetInt(ctx context.Context, group, key string, def int) int
	GetString(ctx context.Context, group, key, def string) string
}

// config 是 syslog 外发配置快照（每次发送批量前从 settings 热读取）。
type config struct {
	enabled         bool
	protocol        string
	address         string
	facility        int
	forwardSecEvt   bool
	forwardACEvt    bool
	forwardAccess   bool
	forwardOpAudit  bool
	forwardLoginLog bool
	forwardSysAlert bool
}

// item 是队列中的一条待外发消息。
type item struct {
	kind         Kind
	severityHint string
	payload      interface{} // 发送时 marshal 为紧凑 JSON
}

// Forwarder 是 syslog 外发器：非阻塞 Enqueue 投递，后台协程批量发送 + spool 重放。
type Forwarder struct {
	settings  SettingsReader
	hostname  string
	procID    string
	spoolPath string
	queue     chan item
	dropped   int64 // channel 满丢弃最旧计数
}

// NewForwarder 创建外发器。dataDir 为可写数据目录（spool 文件落在此处）。
func NewForwarder(settings SettingsReader, dataDir string) *Forwarder {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "-"
	}
	return &Forwarder{
		settings:  settings,
		hostname:  hostname,
		procID:    strconv.Itoa(os.Getpid()),
		spoolPath: filepath.Join(dataDir, spoolFileName),
		queue:     make(chan item, queueCapacity),
	}
}

// loadConfig 读取最新 syslog 配置（热更新：运行中改开关/地址即生效）。
func (f *Forwarder) loadConfig(ctx context.Context) config {
	return config{
		enabled:         f.settings.GetBool(ctx, "logging", "syslog_enabled", false),
		protocol:        f.settings.GetString(ctx, "logging", "syslog_protocol", "udp"),
		address:         f.settings.GetString(ctx, "logging", "syslog_address", ""),
		facility:        f.settings.GetInt(ctx, "logging", "syslog_facility", 1),
		forwardSecEvt:   f.settings.GetBool(ctx, "logging", "syslog_forward_security_events", true),
		forwardACEvt:    f.settings.GetBool(ctx, "logging", "syslog_forward_access_control_events", true),
		forwardAccess:   f.settings.GetBool(ctx, "logging", "syslog_forward_access_logs", false),
		forwardOpAudit:  f.settings.GetBool(ctx, "logging", "syslog_forward_operation_audits", true),
		forwardLoginLog: f.settings.GetBool(ctx, "logging", "syslog_forward_login_logs", true),
		forwardSysAlert: f.settings.GetBool(ctx, "logging", "syslog_forward_system_alerts", true),
	}
}

// kindEnabled 判断该消息类型是否按当前配置外发。
func (c config) kindEnabled(k Kind) bool {
	switch k {
	case KindSecurityEvent:
		return c.forwardSecEvt
	case KindAccessControlEvent:
		return c.forwardACEvt
	case KindAccessLog:
		return c.forwardAccess
	case KindOperationAudit:
		return c.forwardOpAudit
	case KindLoginLog:
		return c.forwardLoginLog
	case KindSystemAlert:
		return c.forwardSysAlert
	case KindTest:
		return true
	}
	return false
}

// Enqueue 非阻塞投递一条消息（payload 发送时 marshal 为紧凑 JSON）。
// 队列满时丢弃最旧消息并告警计数，绝不阻塞采集主流程。
func (f *Forwarder) Enqueue(kind Kind, severityHint string, payload interface{}) {
	if f == nil {
		return
	}
	it := item{kind: kind, severityHint: severityHint, payload: payload}
	select {
	case f.queue <- it:
		return
	default:
	}
	// 满了：丢弃最旧，再入队
	select {
	case <-f.queue:
		n := atomic.AddInt64(&f.dropped, 1)
		slog.Warn("syslog queue full, dropped oldest message", "dropped_total", n)
	default:
	}
	select {
	case f.queue <- it:
	default:
	}
}

// DroppedCount 返回因队列满丢弃的消息总数（指标/测试用）。
func (f *Forwarder) DroppedCount() int64 {
	return atomic.LoadInt64(&f.dropped)
}

// Run 启动发送循环与 spool 重放循环（单协程，ctx 取消即退出）。
func (f *Forwarder) Run(ctx context.Context) {
	snd := &sender{}
	spoolTicker := time.NewTicker(10 * time.Second)
	defer spoolTicker.Stop()
	slog.Info("syslog forwarder started", "spool", f.spoolPath)
	for {
		select {
		case <-ctx.Done():
			snd.close()
			slog.Info("syslog forwarder stopped")
			return
		case it := <-f.queue:
			batch := make([]item, 0, 128)
			batch = append(batch, it)
			// 不阻塞地聚拢当前积压，凑成一批
		drain:
			for len(batch) < cap(batch) {
				select {
				case it2 := <-f.queue:
					batch = append(batch, it2)
				default:
					break drain
				}
			}
			f.sendBatch(ctx, snd, batch)
		case <-spoolTicker.C:
			f.replaySpool(ctx, snd)
		}
	}
}

// buildMessage 把队列条目构造成 RFC5424 消息。
func (f *Forwarder) buildMessage(cfg config, it item) ([]byte, error) {
	payload, err := json.Marshal(it.payload)
	if err != nil {
		return nil, fmt.Errorf("marshal syslog payload: %w", err)
	}
	return BuildMessage(cfg.facility, severityFor(it.kind, it.severityHint),
		f.hostname, f.procID, it.kind, payload), nil
}

// sendBatch 发送一批消息：先热读配置，未启用/地址为空直接丢弃本批；
// 发送失败的消息追加到磁盘 spool，由后台协程重放。
func (f *Forwarder) sendBatch(ctx context.Context, snd *sender, batch []item) {
	cfg := f.loadConfig(ctx)
	if !cfg.enabled || cfg.address == "" {
		return
	}
	for _, it := range batch {
		if !cfg.kindEnabled(it.kind) {
			continue
		}
		msg, err := f.buildMessage(cfg, it)
		if err != nil {
			slog.Error("build syslog message failed", "error", err)
			continue
		}
		if err := snd.send(cfg.protocol, cfg.address, msg); err != nil {
			slog.Warn("syslog send failed, spooled for retry", "error", err, "address", cfg.address)
			f.spoolAppend(msg)
		}
	}
}

// SendTestMessage 用当前配置立即发送一条测试消息（syslog-test 接口用，不经过队列）。
// 未启用/地址为空/网络错误均如实返回错误原因。
func (f *Forwarder) SendTestMessage(ctx context.Context) error {
	cfg := f.loadConfig(ctx)
	if !cfg.enabled {
		return errors.New("syslog 外发未启用")
	}
	if cfg.address == "" {
		return errors.New("syslog 服务器地址为空")
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"test":   true,
		"source": appName,
		"ts":     time.Now().UTC().Format(time.RFC3339Nano),
	})
	msg := BuildMessage(cfg.facility, severityInfo, f.hostname, f.procID, KindTest, payload)
	return sendOnce(cfg.protocol, cfg.address, msg)
}

// sendOnce 建立一次性连接发送单条消息（测试消息用）。
func sendOnce(protocol, address string, msg []byte) error {
	switch protocol {
	case "udp":
		conn, err := net.DialTimeout("udp", address, dialTimeout)
		if err != nil {
			return fmt.Errorf("连接 syslog 服务器失败: %w", err)
		}
		defer conn.Close()
		_ = conn.SetWriteDeadline(time.Now().Add(dialTimeout))
		if _, err := conn.Write(msg); err != nil {
			return fmt.Errorf("发送 syslog 消息失败: %w", err)
		}
		return nil
	case "tcp":
		conn, err := net.DialTimeout("tcp", address, dialTimeout)
		if err != nil {
			return fmt.Errorf("连接 syslog 服务器失败: %w", err)
		}
		defer conn.Close()
		_ = conn.SetWriteDeadline(time.Now().Add(dialTimeout))
		if _, err := conn.Write(append(msg, '\n')); err != nil {
			return fmt.Errorf("发送 syslog 消息失败: %w", err)
		}
		return nil
	}
	return fmt.Errorf("不支持的 syslog 协议: %s", protocol)
}

// sender 维持一条到 syslog 服务器的连接（TCP 断线自动重连，退避 1s→30s；
// UDP 写失败同样按退避重建）。仅由 Run 协程使用，无并发。
type sender struct {
	protocol    string
	address     string
	conn        net.Conn
	backoff     time.Duration
	nextAttempt time.Time
}

var errBackoff = errors.New("syslog reconnect backoff")

// send 发送一条消息；配置变化时先关闭旧连接。
func (s *sender) send(protocol, address string, msg []byte) error {
	if protocol != "udp" && protocol != "tcp" {
		return fmt.Errorf("不支持的 syslog 协议: %s", protocol)
	}
	if s.conn != nil && (s.protocol != protocol || s.address != address) {
		s.close()
	}
	s.protocol, s.address = protocol, address

	if s.conn == nil {
		if time.Now().Before(s.nextAttempt) {
			return errBackoff
		}
		conn, err := net.DialTimeout(protocol, address, dialTimeout)
		if err != nil {
			s.increaseBackoff()
			return err
		}
		s.conn = conn
		s.backoff = 0
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(dialTimeout))
	frame := msg
	if protocol == "tcp" {
		// RFC6587 non-transparent framing：换行分隔
		frame = append(msg, '\n')
	}
	if _, err := s.conn.Write(frame); err != nil {
		s.close()
		s.increaseBackoff()
		return err
	}
	return nil
}

func (s *sender) increaseBackoff() {
	if s.backoff <= 0 {
		s.backoff = time.Second
	} else {
		s.backoff *= 2
		if s.backoff > 30*time.Second {
			s.backoff = 30 * time.Second
		}
	}
	s.nextAttempt = time.Now().Add(s.backoff)
}

func (s *sender) close() {
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
}

// spoolRecord 是 spool 文件中的一行（完整 RFC5424 报文原样保存，重放不再重建）。
type spoolRecord struct {
	Message string `json:"message"`
}

// spoolAppend 把发送失败的消息追加到 spool 文件；文件超过 50MB 时先截断只留后半部分。
func (f *Forwarder) spoolAppend(msg []byte) {
	if info, err := os.Stat(f.spoolPath); err == nil && info.Size() >= spoolMaxBytes {
		f.truncateSpool()
	}
	rec, err := json.Marshal(spoolRecord{Message: string(msg)})
	if err != nil {
		slog.Error("marshal spool record failed", "error", err)
		return
	}
	file, err := os.OpenFile(f.spoolPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		slog.Error("open syslog spool failed", "path", f.spoolPath, "error", err)
		return
	}
	defer file.Close()
	if _, err := file.Write(append(rec, '\n')); err != nil {
		slog.Error("write syslog spool failed", "path", f.spoolPath, "error", err)
	}
}

// truncateSpool 重写 spool 文件只保留后半部分（简单丢弃最旧）。
func (f *Forwarder) truncateSpool() {
	data, err := os.ReadFile(f.spoolPath)
	if err != nil {
		slog.Error("read syslog spool for truncate failed", "path", f.spoolPath, "error", err)
		return
	}
	half := data[len(data)/2:]
	// 对齐到下一行边界，避免半截 JSON
	for i, b := range half {
		if b == '\n' {
			half = half[i+1:]
			break
		}
	}
	tmp := f.spoolPath + ".tmp"
	if err := os.WriteFile(tmp, half, 0o600); err != nil {
		slog.Error("write truncated syslog spool failed", "error", err)
		return
	}
	if err := os.Rename(tmp, f.spoolPath); err != nil {
		slog.Error("replace syslog spool failed", "error", err)
		return
	}
	slog.Warn("syslog spool exceeded 50MB, dropped oldest half", "path", f.spoolPath)
}

// replaySpool 每 10s 尝试重发 spool 中的消息；全部成功后删除文件，
// 部分失败时重写文件只留未发出的（首个失败即停止，连接恢复后下轮再试）。
func (f *Forwarder) replaySpool(ctx context.Context, snd *sender) {
	info, err := os.Stat(f.spoolPath)
	if err != nil || info.Size() == 0 {
		return
	}
	cfg := f.loadConfig(ctx)
	if !cfg.enabled || cfg.address == "" {
		return
	}
	data, err := os.ReadFile(f.spoolPath)
	if err != nil {
		slog.Error("read syslog spool failed", "path", f.spoolPath, "error", err)
		return
	}
	var failed [][]byte
	lines := 0
	for _, line := range splitLines(data) {
		if len(failed) > 0 {
			failed = append(failed, line) // 已遇失败，剩余原样保留
			continue
		}
		var rec spoolRecord
		if err := json.Unmarshal(line, &rec); err != nil || rec.Message == "" {
			slog.Warn("drop corrupted syslog spool line")
			continue // 坏行丢弃（不静默：告警日志）
		}
		lines++
		if err := snd.send(cfg.protocol, cfg.address, []byte(rec.Message)); err != nil {
			failed = append(failed, line)
		}
	}
	if lines == 0 {
		return
	}
	if len(failed) == 0 {
		if err := os.Remove(f.spoolPath); err != nil {
			slog.Error("remove drained syslog spool failed", "path", f.spoolPath, "error", err)
		}
		slog.Info("syslog spool fully replayed", "path", f.spoolPath)
		return
	}
	// 重写文件只留未发出的
	var out []byte
	for _, l := range failed {
		out = append(out, l...)
		out = append(out, '\n')
	}
	tmp := f.spoolPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		slog.Error("rewrite syslog spool failed", "error", err)
		return
	}
	if err := os.Rename(tmp, f.spoolPath); err != nil {
		slog.Error("replace syslog spool failed", "error", err)
	}
}

// splitLines 按行拆分（容忍末尾无换行与空行）。
func splitLines(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				out = append(out, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		out = append(out, data[start:])
	}
	return out
}
