// dispatcher.go 通知调度器：非阻塞 Enqueue（有界 channel，满则丢弃最旧）+ 单协程 drain
// + 磁盘 spool（notify-spool.jsonl，上限 50MB，10s 重放）+ 配置热读（每批重读渠道与
// notify 组抑制参数，CRUD 最迟下一批生效）。发送失败不静默：记日志并落 spool 重放。
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

const (
	// queueCapacity 是内存缓冲容量，满了丢弃最旧并计数。
	queueCapacity = 10000
	// spoolMaxBytes 是磁盘 spool 上限（50MB），超过时重写文件只留后半部分。
	spoolMaxBytes = 50 << 20
	// spoolFileName 是 spool 文件名（位于数据目录下）。
	spoolFileName = "notify-spool.jsonl"
)

// SettingsReader 是抑制参数读取接口（*settings.Service 实现，测试注入内存实现）。
type SettingsReader interface {
	GetBool(ctx context.Context, group, key string, def bool) bool
	GetInt(ctx context.Context, group, key string, def int) int
}

// SyslogSender 是 syslog 渠道的发送出口（由 app 装配层适配 syslogfw.Forwarder）。
// syslog 渠道沿用 logging 组 syslog 配置（开关/地址/协议/system_alerts 类别开关全部生效）。
type SyslogSender interface {
	EnqueueSyslogAlert(severityHint string, payload interface{})
	SendTestMessage(ctx context.Context) error
}

// Dispatcher 是通知调度器。
type Dispatcher struct {
	store      ChannelStore
	settings   SettingsReader
	syslog     SyslogSender // nil 时跳过 syslog 渠道（记日志，不视为发送失败）
	suppressor *Suppressor
	spoolPath  string
	queue      chan Event
	dropped    int64 // channel 满丢弃最旧计数

	wecom  WecomSender
	feishu FeishuSender
	smtp   *SMTPSender
	sms    SMSSender

	now           func() time.Time // 可注入（测试）
	flushInterval time.Duration    // 聚合到期检查周期（默认 1s）
	spoolInterval time.Duration    // spool 重放周期（默认 10s）
}

// NewDispatcher 创建调度器。dataDir 为可写数据目录（spool 落在此处）。
func NewDispatcher(store ChannelStore, settings SettingsReader, dataDir string) *Dispatcher {
	return &Dispatcher{
		store:         store,
		settings:      settings,
		suppressor:    NewSuppressor(nil),
		spoolPath:     filepath.Join(dataDir, spoolFileName),
		queue:         make(chan Event, queueCapacity),
		smtp:          NewSMTPSender(),
		now:           time.Now,
		flushInterval: time.Second,
		spoolInterval: 10 * time.Second,
	}
}

// SetSyslogSender 注入 syslog 渠道出口（可为 nil）。
func (d *Dispatcher) SetSyslogSender(s SyslogSender) { d.syslog = s }

// Enqueue 非阻塞投递一条告警事件；队列满时丢弃最旧并告警计数，绝不阻塞告警主流程。
func (d *Dispatcher) Enqueue(ev Event) {
	if d == nil {
		return
	}
	select {
	case d.queue <- ev:
		return
	default:
	}
	select {
	case <-d.queue:
		n := atomic.AddInt64(&d.dropped, 1)
		slog.Warn("notify queue full, dropped oldest event", "dropped_total", n)
	default:
	}
	select {
	case d.queue <- ev:
	default:
	}
}

// DroppedCount 返回因队列满丢弃的事件总数（指标/测试用）。
func (d *Dispatcher) DroppedCount() int64 {
	return atomic.LoadInt64(&d.dropped)
}

// loadParams 热读抑制参数（settings 读取失败回退默认值，与 syslogfw 配置热读口径一致）。
func (d *Dispatcher) loadParams(ctx context.Context) Params {
	return Params{
		RatePerMinute:  d.settings.GetInt(ctx, "notify", "notify_rate_limit_per_minute", 10),
		MuteMinutes:    d.settings.GetInt(ctx, "notify", "notify_mute_minutes", 30),
		WindowSeconds:  d.settings.GetInt(ctx, "notify", "notify_group_window_seconds", 60),
		ResolvedNotify: d.settings.GetBool(ctx, "notify", "notify_resolved", false),
	}
}

// Run 启动发送循环（单协程，ctx 取消即退出）：队列 drain + 聚合到期 flush + spool 重放。
func (d *Dispatcher) Run(ctx context.Context) {
	flushTicker := time.NewTicker(d.flushInterval)
	defer flushTicker.Stop()
	spoolTicker := time.NewTicker(d.spoolInterval)
	defer spoolTicker.Stop()
	slog.Info("notify dispatcher started", "spool", d.spoolPath)
	for {
		select {
		case <-ctx.Done():
			slog.Info("notify dispatcher stopped")
			return
		case ev := <-d.queue:
			batch := make([]Event, 0, 128)
			batch = append(batch, ev)
		drain:
			for len(batch) < cap(batch) {
				select {
				case ev2 := <-d.queue:
					batch = append(batch, ev2)
				default:
					break drain
				}
			}
			d.processBatch(ctx, batch)
		case <-flushTicker.C:
			d.flushAggregations(ctx)
		case <-spoolTicker.C:
			d.replaySpool(ctx)
		}
	}
}

// processBatch 处理一批事件：热读渠道与抑制参数 → 订阅过滤 → 抑制判定 → 发送/聚合。
func (d *Dispatcher) processBatch(ctx context.Context, batch []Event) {
	channels, err := d.store.ListDecrypted(ctx)
	if err != nil {
		// 渠道读取失败：整批落 spool（channel_id 空 = 重放时重新路由），不丢弃不阻塞
		slog.Error("notify load channels failed, spooled batch", "error", err, "events", len(batch))
		for _, ev := range batch {
			d.spoolAppend(spoolRecord{Event: ev})
		}
		return
	}
	params := d.loadParams(ctx)
	for _, ev := range batch {
		if ev.Status == StatusResolved && !params.ResolvedNotify {
			continue // 恢复通知默认关闭
		}
		for i := range channels {
			ch := &channels[i]
			if !ch.subscribes(ev) {
				continue
			}
			switch d.suppressor.Process(ch.ID, ev, params) {
			case DecisionSend:
				if err := d.sendNow(ctx, ch, ev); err != nil {
					slog.Warn("notify send failed, spooled for retry",
						"channel", ch.Name, "type", ch.Type, "error", err)
					d.spoolAppend(spoolRecord{ChannelID: ch.ID.String(), Event: ev})
				}
			case DecisionMuted, DecisionAggregated:
				// 静默丢弃 / 已入聚合（摘要由 flushAggregations 发送）
			}
		}
	}
}

// flushAggregations 把窗口到期的聚合摘要发送到对应渠道（摘要本身不再限流——
// 它就是限流的产物，每窗口每渠道至多一条）。
func (d *Dispatcher) flushAggregations(ctx context.Context) {
	if !d.suppressor.HasPending() {
		return
	}
	params := d.loadParams(ctx)
	due := d.suppressor.FlushDue(params.WindowSeconds)
	if len(due) == 0 {
		return
	}
	channels, err := d.store.ListDecrypted(ctx)
	if err != nil {
		slog.Error("notify load channels for summary flush failed", "error", err)
		return
	}
	byID := make(map[uuid.UUID]*Channel, len(channels))
	for i := range channels {
		byID[channels[i].ID] = &channels[i]
	}
	for _, id := range due {
		summary, ok := d.suppressor.TakeSummary(id)
		if !ok {
			continue
		}
		ch, ok := byID[id]
		if !ok {
			slog.Warn("notify summary dropped: channel removed", "channel_id", id)
			continue
		}
		if err := d.sendNow(ctx, ch, summary); err != nil {
			slog.Warn("notify summary send failed, spooled for retry",
				"channel", ch.Name, "type", ch.Type, "error", err)
			d.spoolAppend(spoolRecord{ChannelID: ch.ID.String(), Event: summary})
		}
	}
}

// sendNow 立即按渠道类型发送一条消息（渲染 + 分发）。
func (d *Dispatcher) sendNow(ctx context.Context, ch *Channel, ev Event) error {
	if ch.Type == TypeSyslog {
		if d.syslog == nil {
			return errors.New("syslog 出口未注入")
		}
		msg := renderMessage(ev)
		d.syslog.EnqueueSyslogAlert(ev.Severity, map[string]interface{}{
			"notification": true,
			"alert_type":   ev.AlertType,
			"severity":     ev.Severity,
			"component":    ev.Component,
			"title":        ev.Title,
			"message":      ev.Message,
			"status":       ev.Status,
			"occurred_at":  ev.OccurredAt.UTC().Format(time.RFC3339Nano),
			"text":         msg.Text,
		})
		return nil // syslog 出口自带队列/spool，投递即成功
	}
	msg := renderMessage(ev)
	switch ch.Type {
	case TypeWecom:
		cfg, err := ParseWecomConfig(ch.Config)
		if err != nil {
			return err
		}
		return d.wecom.Send(ctx, cfg, msg)
	case TypeFeishu:
		cfg, err := ParseFeishuConfig(ch.Config)
		if err != nil {
			return err
		}
		return d.feishu.Send(ctx, cfg, msg)
	case TypeSMTP:
		cfg, err := ParseSMTPConfig(ch.Config)
		if err != nil {
			return err
		}
		return d.smtp.Send(ctx, cfg, msg)
	case TypeSMS:
		cfg, err := ParseSMSConfig(ch.Config)
		if err != nil {
			return err
		}
		return d.sms.Send(ctx, cfg, ev)
	}
	return fmt.Errorf("未知的渠道类型: %s", ch.Type)
}

// SendTest 用当前渠道配置立即发送一条测试消息（test 接口用，不经过队列与抑制），
// 如实返回失败原因。
func (d *Dispatcher) SendTest(ctx context.Context, ch *Channel) error {
	if ch.Type == TypeSyslog {
		if d.syslog == nil {
			return errors.New("syslog 出口未注入")
		}
		return d.syslog.SendTestMessage(ctx)
	}
	return d.sendNow(ctx, ch, Event{
		AlertType:  "GATEWAY_DOWN",
		Severity:   SeverityLow,
		Component:  "NOTIFY_TEST",
		Title:      "告警通知渠道测试",
		Message:    "这是一条测试消息，用于验证通知渠道配置是否正确。",
		Status:     StatusOpen,
		OccurredAt: d.now(),
	})
}

// ---------- 磁盘 spool ----------

// spoolRecord 是 spool 文件中的一行（channel_id 空 = 发送前未路由，重放时重新匹配渠道）。
type spoolRecord struct {
	ChannelID string `json:"channel_id,omitempty"`
	Event     Event  `json:"event"`
}

// spoolAppend 把待重试事件追加到 spool 文件；文件超过 50MB 时先截断只留后半部分。
func (d *Dispatcher) spoolAppend(rec spoolRecord) {
	if info, err := os.Stat(d.spoolPath); err == nil && info.Size() >= spoolMaxBytes {
		d.truncateSpool()
	}
	line, err := json.Marshal(rec)
	if err != nil {
		slog.Error("marshal notify spool record failed", "error", err)
		return
	}
	file, err := os.OpenFile(d.spoolPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		slog.Error("open notify spool failed", "path", d.spoolPath, "error", err)
		return
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		slog.Error("write notify spool failed", "path", d.spoolPath, "error", err)
	}
}

// truncateSpool 重写 spool 文件只保留后半部分（简单丢弃最旧）。
func (d *Dispatcher) truncateSpool() {
	data, err := os.ReadFile(d.spoolPath)
	if err != nil {
		slog.Error("read notify spool for truncate failed", "path", d.spoolPath, "error", err)
		return
	}
	half := data[len(data)/2:]
	for i, b := range half {
		if b == '\n' {
			half = half[i+1:]
			break
		}
	}
	tmp := d.spoolPath + ".tmp"
	if err := os.WriteFile(tmp, half, 0o600); err != nil {
		slog.Error("write truncated notify spool failed", "error", err)
		return
	}
	if err := os.Rename(tmp, d.spoolPath); err != nil {
		slog.Error("replace notify spool failed", "error", err)
		return
	}
	slog.Warn("notify spool exceeded 50MB, dropped oldest half", "path", d.spoolPath)
}

// replaySpool 周期性重发 spool 中的事件；全部成功后删除文件，部分失败时重写文件
// 只留未发出的（首个失败即停止，下轮再试）。重放为补偿路径：直接发送，
// 不再经过抑制（事件入 spool 前已通过过滤与抑制判定）。
func (d *Dispatcher) replaySpool(ctx context.Context) {
	info, err := os.Stat(d.spoolPath)
	if err != nil || info.Size() == 0 {
		return
	}
	data, err := os.ReadFile(d.spoolPath)
	if err != nil {
		slog.Error("read notify spool failed", "path", d.spoolPath, "error", err)
		return
	}
	channels, err := d.store.ListDecrypted(ctx)
	if err != nil {
		slog.Error("notify load channels for spool replay failed", "error", err)
		return
	}
	byID := make(map[uuid.UUID]*Channel, len(channels))
	for i := range channels {
		byID[channels[i].ID] = &channels[i]
	}

	var failed [][]byte
	lines := 0
	for _, line := range splitLines(data) {
		if len(failed) > 0 {
			failed = append(failed, line)
			continue
		}
		var rec spoolRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			slog.Warn("drop corrupted notify spool line")
			continue
		}
		lines++
		if rec.ChannelID == "" {
			// 未路由记录（发送前渠道读取失败落盘）：按当前配置重新路由，直接发送
			for i := range channels {
				ch := &channels[i]
				if !ch.subscribes(rec.Event) {
					continue
				}
				if err := d.sendNow(ctx, ch, rec.Event); err != nil {
					slog.Warn("notify spool replay failed", "channel", ch.Name, "error", err)
					failed = append(failed, line)
					break
				}
			}
			continue
		}
		id, err := uuid.Parse(rec.ChannelID)
		if err != nil {
			slog.Warn("drop notify spool line with bad channel id", "channel_id", rec.ChannelID)
			continue
		}
		ch, ok := byID[id]
		if !ok {
			slog.Warn("notify spool line dropped: channel removed", "channel_id", rec.ChannelID)
			continue
		}
		if err := d.sendNow(ctx, ch, rec.Event); err != nil {
			slog.Warn("notify spool replay failed", "channel", ch.Name, "error", err)
			failed = append(failed, line)
		}
	}
	if lines == 0 {
		return
	}
	if len(failed) == 0 {
		if err := os.Remove(d.spoolPath); err != nil {
			slog.Error("remove drained notify spool failed", "path", d.spoolPath, "error", err)
		}
		slog.Info("notify spool fully replayed", "path", d.spoolPath)
		return
	}
	var out []byte
	for _, l := range failed {
		out = append(out, l...)
		out = append(out, '\n')
	}
	tmp := d.spoolPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		slog.Error("rewrite notify spool failed", "error", err)
		return
	}
	if err := os.Rename(tmp, d.spoolPath); err != nil {
		slog.Error("replace notify spool failed", "error", err)
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
