package notify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeChannelStore 是内存渠道仓储（实现 ChannelStore）。
type fakeChannelStore struct {
	channels []Channel
}

func (f *fakeChannelStore) ListDecrypted(_ context.Context) ([]Channel, error) {
	out := make([]Channel, len(f.channels))
	copy(out, f.channels)
	return out, nil
}

// fakeSettings 是内存抑制参数源（实现 SettingsReader）。
type fakeSettings struct {
	ints  map[string]int
	bools map[string]bool
}

func (f *fakeSettings) GetInt(_ context.Context, _, key string, def int) int {
	if v, ok := f.ints[key]; ok {
		return v
	}
	return def
}

func (f *fakeSettings) GetBool(_ context.Context, _, key string, def bool) bool {
	if v, ok := f.bools[key]; ok {
		return v
	}
	return def
}

// fakeSyslogSender 记录 syslog 渠道投递（实现 SyslogSender）。
type fakeSyslogSender struct {
	mu       sync.Mutex
	payloads []map[string]interface{}
	testErr  error
}

func (f *fakeSyslogSender) EnqueueSyslogAlert(_ string, payload interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := payload.(map[string]interface{}); ok {
		f.payloads = append(f.payloads, m)
	}
}

func (f *fakeSyslogSender) SendTestMessage(context.Context) error { return f.testErr }

func (f *fakeSyslogSender) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.payloads)
}

// newTestDispatcher 创建共享可控时钟的测试调度器。
func newTestDispatcher(store ChannelStore, st SettingsReader, dir string) (*Dispatcher, *fixedClock) {
	d := NewDispatcher(store, st, dir)
	clock := &fixedClock{now: time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)}
	d.now = clock.Now
	d.suppressor = NewSuppressor(clock.Now)
	return d, clock
}

func wecomChannel(id uuid.UUID, url string, minSev string, categories []string) Channel {
	return Channel{
		ID: id, Name: "测试企业微信", Type: TypeWecom, Enabled: true,
		MinSeverity: minSev, Categories: categories,
		Config: map[string]interface{}{"webhook_url": url, "mention_all": false},
	}
}

// dynamicServer 是响应码可在测试中途切换的接收端。
type dynamicServer struct {
	*httptest.Server
	rec    *webhookRecorder
	status *int
}

func newDynamicServer(t *testing.T, initial int) *dynamicServer {
	t.Helper()
	rec := &webhookRecorder{}
	status := &initial
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.handler(*status, `{"errcode":0,"errmsg":"ok"}`)(w, r)
	}))
	t.Cleanup(srv.Close)
	return &dynamicServer{Server: srv, rec: rec, status: status}
}

// TestEnqueueNonBlocking 队列满时 Enqueue 不阻塞且丢弃最旧计数。
func TestEnqueueNonBlocking(t *testing.T) {
	d, _ := newTestDispatcher(&fakeChannelStore{}, &fakeSettings{}, t.TempDir())
	// 不启动 Run：队列容量 10000，再投 100 条必然触发丢弃最旧路径
	start := time.Now()
	for i := 0; i < queueCapacity+100; i++ {
		d.Enqueue(ev("GATEWAY_DOWN", "G", SeverityCritical))
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Enqueue 应非阻塞，耗时 %v", elapsed)
	}
	if got := d.DroppedCount(); got <= 0 {
		t.Fatalf("队列满应丢弃最旧并计数, got %d", got)
	}
	if len(d.queue) != queueCapacity {
		t.Fatalf("队列应满, got %d", len(d.queue))
	}
}

// TestProcessBatchFiltering 订阅过滤：级别达标 + 类别匹配 + 渠道启用才发送。
func TestProcessBatchFiltering(t *testing.T) {
	useTestGuard(t, loopbackGuard())
	srv := newDynamicServer(t, http.StatusOK)
	ch := wecomChannel(uuid.New(), srv.URL, SeverityHigh, []string{"infrastructure"})
	store := &fakeChannelStore{channels: []Channel{ch}}
	d, _ := newTestDispatcher(store, &fakeSettings{}, t.TempDir())

	// MEDIUM < min_severity HIGH → 不发
	d.processBatch(context.Background(), []Event{ev("SOURCE_UNHEALTHY", "UPSTREAM", SeverityMedium)})
	if srv.rec.count() != 0 {
		t.Fatalf("级别不足不应发送, got %d", srv.rec.count())
	}
	// 类别不匹配（ops 不在订阅内）→ 不发
	d.processBatch(context.Background(), []Event{ev("BACKUP_FAILED", "BACKUP", SeverityHigh)})
	if srv.rec.count() != 0 {
		t.Fatalf("类别未订阅不应发送, got %d", srv.rec.count())
	}
	// CRITICAL + infrastructure → 发送
	d.processBatch(context.Background(), []Event{ev("GATEWAY_DOWN", "GATEWAY", SeverityCritical)})
	if srv.rec.count() != 1 {
		t.Fatalf("匹配订阅应发送 1 次, got %d", srv.rec.count())
	}
	body := srv.rec.last(t)
	if content, _ := body["markdown"].(map[string]interface{})["content"].(string); !strings.Contains(content, "网关离线") {
		t.Errorf("发送内容缺少类型中文名: %s", content)
	}
	// 渠道停用 → 不发
	store.channels[0].Enabled = false
	d.processBatch(context.Background(), []Event{ev("DATABASE_UNAVAILABLE", "POSTGRES", SeverityCritical)})
	if srv.rec.count() != 1 {
		t.Fatalf("停用渠道不应发送, got %d", srv.rec.count())
	}
}

// TestProcessBatchResolvedGating 恢复通知默认关闭，开启后才外发。
func TestProcessBatchResolvedGating(t *testing.T) {
	useTestGuard(t, loopbackGuard())
	srv := newDynamicServer(t, http.StatusOK)
	store := &fakeChannelStore{channels: []Channel{wecomChannel(uuid.New(), srv.URL, SeverityLow, nil)}}
	st := &fakeSettings{bools: map[string]bool{"notify_resolved": false}}
	d, _ := newTestDispatcher(store, st, t.TempDir())

	resolved := ev("GATEWAY_DOWN", "GATEWAY", SeverityCritical)
	resolved.Status = StatusResolved
	d.processBatch(context.Background(), []Event{resolved})
	if srv.rec.count() != 0 {
		t.Fatalf("notify_resolved=false 不应外发恢复通知, got %d", srv.rec.count())
	}
	st.bools["notify_resolved"] = true
	d.processBatch(context.Background(), []Event{resolved})
	if srv.rec.count() != 1 {
		t.Fatalf("notify_resolved=true 应外发恢复通知, got %d", srv.rec.count())
	}
	body := srv.rec.last(t)
	if content, _ := body["markdown"].(map[string]interface{})["content"].(string); !strings.Contains(content, "【九章WAF恢复】") {
		t.Errorf("恢复通知文案错误: %s", content)
	}
}

// TestAggregationFlushSendsSummary 被限流事件在聚合窗口到期后合并为一条摘要发送。
func TestAggregationFlushSendsSummary(t *testing.T) {
	useTestGuard(t, loopbackGuard())
	srv := newDynamicServer(t, http.StatusOK)
	store := &fakeChannelStore{channels: []Channel{wecomChannel(uuid.New(), srv.URL, SeverityLow, nil)}}
	st := &fakeSettings{ints: map[string]int{
		"notify_rate_limit_per_minute": 1,
		"notify_group_window_seconds":  60,
		"notify_mute_minutes":          0,
	}}
	d, clock := newTestDispatcher(store, st, t.TempDir())

	// 3 条不同指纹：1 条直发，2 条进聚合
	d.processBatch(context.Background(), []Event{
		ev("GATEWAY_DOWN", "G1", SeverityCritical),
		ev("GATEWAY_DOWN", "G2", SeverityCritical),
		ev("DISK_SPACE_LOW", "D1", SeverityHigh),
	})
	if srv.rec.count() != 1 {
		t.Fatalf("应直发 1 条, got %d", srv.rec.count())
	}
	// 窗口未到期不 flush
	d.flushAggregations(context.Background())
	if srv.rec.count() != 1 {
		t.Fatalf("窗口未到期不应发摘要, got %d", srv.rec.count())
	}
	// 推进 61 秒 → flush 摘要
	clock.Advance(61 * time.Second)
	d.flushAggregations(context.Background())
	if srv.rec.count() != 2 {
		t.Fatalf("窗口到期应发摘要, got %d", srv.rec.count())
	}
	body := srv.rec.last(t)
	content, _ := body["markdown"].(map[string]interface{})["content"].(string)
	if !strings.Contains(content, "【九章WAF告警摘要】") || !strings.Contains(content, "共 2 条告警") {
		t.Errorf("摘要文案错误: %s", content)
	}
}

// TestSpoolOnFailureAndReplay 发送失败落 spool，恢复后重放成功并清除 spool。
func TestSpoolOnFailureAndReplay(t *testing.T) {
	useTestGuard(t, loopbackGuard())
	srv := newDynamicServer(t, http.StatusInternalServerError)
	store := &fakeChannelStore{channels: []Channel{wecomChannel(uuid.New(), srv.URL, SeverityLow, nil)}}
	dir := t.TempDir()
	d, _ := newTestDispatcher(store, &fakeSettings{}, dir)

	d.processBatch(context.Background(), []Event{ev("GATEWAY_DOWN", "G1", SeverityCritical)})
	if srv.rec.count() != 1 {
		t.Fatalf("失败也应尝试过 1 次, got %d", srv.rec.count())
	}
	if _, err := os.Stat(d.spoolPath); err != nil {
		t.Fatalf("失败后应有 spool 文件: %v", err)
	}

	// 服务恢复 → 重放成功、spool 删除
	*srv.status = http.StatusOK
	d.replaySpool(context.Background())
	if srv.rec.count() != 2 {
		t.Fatalf("重放应再发 1 次, got %d", srv.rec.count())
	}
	if _, err := os.Stat(d.spoolPath); !os.IsNotExist(err) {
		t.Fatalf("重放成功后 spool 应删除, err=%v", err)
	}
}

// TestSyslogChannelDispatch syslog 渠道经 SyslogSender 出口投递（复用 logging 配置）。
func TestSyslogChannelDispatch(t *testing.T) {
	fake := &fakeSyslogSender{}
	ch := Channel{
		ID: uuid.New(), Name: "系统 syslog", Type: TypeSyslog, Enabled: true,
		MinSeverity: SeverityLow, Categories: []string{}, Config: map[string]interface{}{},
	}
	d, _ := newTestDispatcher(&fakeChannelStore{channels: []Channel{ch}}, &fakeSettings{}, t.TempDir())
	d.SetSyslogSender(fake)

	d.processBatch(context.Background(), []Event{ev("GATEWAY_DOWN", "GATEWAY", SeverityCritical)})
	if fake.count() != 1 {
		t.Fatalf("syslog 渠道应投递 1 次, got %d", fake.count())
	}
	p := fake.payloads[0]
	if p["alert_type"] != "GATEWAY_DOWN" || p["severity"] != "CRITICAL" || p["notification"] != true {
		t.Errorf("syslog payload 字段错误: %v", p)
	}
	if text, _ := p["text"].(string); !strings.Contains(text, "网关离线") {
		t.Errorf("syslog payload 缺少渲染文本: %v", p)
	}

	// SendTest 走 SyslogSender.SendTestMessage，错误如实透传
	fake.testErr = errTestSyslog
	if err := d.SendTest(context.Background(), &ch); !errors.Is(err, errTestSyslog) {
		t.Fatalf("SendTest 应透传 syslog 错误, got %v", err)
	}
}

var errTestSyslog = errors.New("syslog 外发未启用")
