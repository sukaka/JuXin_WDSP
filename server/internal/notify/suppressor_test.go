package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fixedClock 是可手动推进的时钟。
type fixedClock struct{ now time.Time }

func (c *fixedClock) Now() time.Time          { return c.now }
func (c *fixedClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestSuppressor() (*Suppressor, *fixedClock) {
	clock := &fixedClock{now: time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)}
	return NewSuppressor(clock.Now), clock
}

func ev(alertType, component, severity string) Event {
	return Event{
		AlertType: alertType, Severity: severity, Component: component,
		Title: "t", Message: "m", Status: StatusOpen, OccurredAt: time.Now(),
	}
}

// TestSuppressorRateLimitAggregates 超出每渠道速率限制的事件不丢、进聚合摘要。
func TestSuppressorRateLimitAggregates(t *testing.T) {
	s, _ := newTestSuppressor()
	chID := uuid.New()
	p := Params{RatePerMinute: 2, MuteMinutes: 0, WindowSeconds: 60}

	// 前 2 条直发（令牌桶容量=2），第 3 条进聚合
	if d := s.Process(chID, ev("GATEWAY_DOWN", "G1", SeverityCritical), p); d != DecisionSend {
		t.Fatalf("第 1 条应直发, got %d", d)
	}
	if d := s.Process(chID, ev("DISK_SPACE_LOW", "D1", SeverityHigh), p); d != DecisionSend {
		t.Fatalf("第 2 条应直发, got %d", d)
	}
	if d := s.Process(chID, ev("VALKEY_UNAVAILABLE", "V1", SeverityHigh), p); d != DecisionAggregated {
		t.Fatalf("第 3 条应进聚合, got %d", d)
	}
	if d := s.Process(chID, ev("GATEWAY_DOWN", "G2", SeverityCritical), p); d != DecisionAggregated {
		t.Fatalf("第 4 条应进聚合, got %d", d)
	}
	// 不同渠道互不影响
	if d := s.Process(uuid.New(), ev("GATEWAY_DOWN", "G3", SeverityCritical), p); d != DecisionSend {
		t.Fatalf("新渠道第 1 条应直发, got %d", d)
	}

	summary, ok := s.TakeSummary(chID)
	if !ok {
		t.Fatal("应有聚合摘要")
	}
	if !summary.Summary {
		t.Error("摘要事件 Summary 应为 true")
	}
	// 聚合 2 条：Valkey不可用×1 + 网关离线×1（同数按中文名字典序）
	if !strings.Contains(summary.Message, "共 2 条告警") {
		t.Errorf("摘要总数错误: %s", summary.Message)
	}
	if !strings.Contains(summary.Message, "Valkey不可用×1") || !strings.Contains(summary.Message, "网关离线×1") {
		t.Errorf("摘要缺少分类计数: %s", summary.Message)
	}
	if summary.Severity != SeverityCritical {
		t.Errorf("摘要级别应取最高 CRITICAL, got %s", summary.Severity)
	}
	// 取走后清空
	if _, ok := s.TakeSummary(chID); ok {
		t.Error("摘要不应重复产出")
	}
}

// TestSuppressorRateZeroAggregatesAll 速率为 0 时全部进聚合（不直发）。
func TestSuppressorRateZeroAggregatesAll(t *testing.T) {
	s, _ := newTestSuppressor()
	chID := uuid.New()
	p := Params{RatePerMinute: 0, MuteMinutes: 0, WindowSeconds: 60}
	for i := 0; i < 3; i++ {
		if d := s.Process(chID, ev("GATEWAY_DOWN", "G", SeverityCritical), p); d != DecisionAggregated {
			t.Fatalf("rate=0 应全部聚合, got %d", d)
		}
	}
	summary, ok := s.TakeSummary(chID)
	if !ok || !strings.Contains(summary.Message, "共 3 条告警") || !strings.Contains(summary.Message, "网关离线×3") {
		t.Errorf("聚合摘要错误: %+v", summary)
	}
}

// TestSuppressorMuteFingerprint 同指纹（alert_type+component）静默期内不重复通知。
func TestSuppressorMuteFingerprint(t *testing.T) {
	s, clock := newTestSuppressor()
	chID := uuid.New()
	p := Params{RatePerMinute: 100, MuteMinutes: 30, WindowSeconds: 60}

	if d := s.Process(chID, ev("GATEWAY_DOWN", "GATEWAY", SeverityCritical), p); d != DecisionSend {
		t.Fatalf("首次应直发, got %d", d)
	}
	if d := s.Process(chID, ev("GATEWAY_DOWN", "GATEWAY", SeverityCritical), p); d != DecisionMuted {
		t.Fatalf("静默期内同指纹应静音, got %d", d)
	}
	// 不同组件 = 不同指纹
	if d := s.Process(chID, ev("GATEWAY_DOWN", "GATEWAY-2", SeverityCritical), p); d != DecisionSend {
		t.Fatalf("不同组件应直发, got %d", d)
	}
	// 不同类型 = 不同指纹
	if d := s.Process(chID, ev("DISK_SPACE_LOW", "GATEWAY", SeverityHigh), p); d != DecisionSend {
		t.Fatalf("不同类型应直发, got %d", d)
	}
	// 静默期过后恢复直发
	clock.Advance(31 * time.Minute)
	if d := s.Process(chID, ev("GATEWAY_DOWN", "GATEWAY", SeverityCritical), p); d != DecisionSend {
		t.Fatalf("静默期过后应直发, got %d", d)
	}
}

// TestSuppressorResolvedBypassesMute 恢复事件不参与同指纹静默（一次性收尾通知）。
func TestSuppressorResolvedBypassesMute(t *testing.T) {
	s, _ := newTestSuppressor()
	chID := uuid.New()
	p := Params{RatePerMinute: 100, MuteMinutes: 30, WindowSeconds: 60}

	firing := ev("GATEWAY_DOWN", "GATEWAY", SeverityCritical)
	if d := s.Process(chID, firing, p); d != DecisionSend {
		t.Fatalf("触发应直发, got %d", d)
	}
	resolved := firing
	resolved.Status = StatusResolved
	if d := s.Process(chID, resolved, p); d != DecisionSend {
		t.Fatalf("恢复事件不应被同指纹静音, got %d", d)
	}
	// 恢复事件自身不制造静默
	if d := s.Process(chID, resolved, p); d != DecisionSend {
		t.Fatalf("恢复事件不应制造静默, got %d", d)
	}
}

// TestSuppressorFlushDue 聚合窗口到期判定。
func TestSuppressorFlushDue(t *testing.T) {
	s, clock := newTestSuppressor()
	chID := uuid.New()
	p := Params{RatePerMinute: 0, MuteMinutes: 0, WindowSeconds: 60}
	s.Process(chID, ev("GATEWAY_DOWN", "G", SeverityCritical), p)

	if due := s.FlushDue(60); len(due) != 0 {
		t.Fatalf("窗口未到期不应 flush: %v", due)
	}
	clock.Advance(61 * time.Second)
	due := s.FlushDue(60)
	if len(due) != 1 || due[0] != chID {
		t.Fatalf("窗口到期应 flush 该渠道: %v", due)
	}
	if !s.HasPending() {
		t.Fatal("flush 判定期后聚合仍应待取出")
	}
	s.TakeSummary(chID)
	if s.HasPending() {
		t.Fatal("取出摘要后不应有待聚合")
	}
}

// TestSuppressorTokenRefill 令牌桶按速率补充（窗口推进后可再直发）。
func TestSuppressorTokenRefill(t *testing.T) {
	s, clock := newTestSuppressor()
	chID := uuid.New()
	p := Params{RatePerMinute: 2, MuteMinutes: 0, WindowSeconds: 60}
	s.Process(chID, ev("GATEWAY_DOWN", "G1", SeverityCritical), p)
	s.Process(chID, ev("GATEWAY_DOWN", "G2", SeverityCritical), p)
	if d := s.Process(chID, ev("GATEWAY_DOWN", "G3", SeverityCritical), p); d != DecisionAggregated {
		t.Fatalf("桶空应聚合, got %d", d)
	}
	// 30 秒补充 1 个令牌（2 个/分钟）
	clock.Advance(31 * time.Second)
	if d := s.Process(chID, ev("GATEWAY_DOWN", "G4", SeverityCritical), p); d != DecisionSend {
		t.Fatalf("补充令牌后应直发, got %d", d)
	}
	if d := s.Process(chID, ev("GATEWAY_DOWN", "G5", SeverityCritical), p); d != DecisionAggregated {
		t.Fatalf("令牌耗尽应再次聚合, got %d", d)
	}
}
