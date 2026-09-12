package jiuzhang_guard

// 网关节点心跳（W17-HB）单测：发射内容/周期间隔/优雅退出/关闭零行为/配置校验。
// 不经过 caddy.Provision（进程级引擎纪律同 module_test.go），直接装配 runner 与 Guard 字段。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"go.uber.org/zap"
)

// hbLine 心跳记录 JSON 镜像（断言字段存在性与取值）。
type hbLine struct {
	RequestID           string     `json:"request_id"`
	EndpointKey         string     `json:"endpoint_key"`
	Heartbeat           bool       `json:"heartbeat"`
	GatewayNode         string     `json:"gateway_node_id"`
	PolicyVersion       string     `json:"policy_version"`
	FinalAction         string     `json:"final_action"`
	RiskLevel           string     `json:"risk_level"`
	UptimeSeconds       int64      `json:"uptime_seconds"`
	GuardStartTime      *time.Time `json:"guard_start_time"`
	FormalModelVersions int        `json:"formal_model_versions"`
	Details             []any      `json:"details"`
}

func newHBRunner(t *testing.T, interval time.Duration) (*heartbeatRunner, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "api-events.jsonl")
	l, err := apievents.NewLogger(path, "gw-hb-1")
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return newHeartbeatRunner(l, zap.NewNop(), interval, "v2026.3", 5), path
}

func readHBLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// 发射内容：心跳标记/端点键占位/节点/版本/模型摘要数/运行时长/装配时间/request_id 唯一。
func TestHeartbeatEmitContent(t *testing.T) {
	r, path := newHBRunner(t, time.Hour) // 手动 emit，不走周期
	if err := r.emit(); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if err := r.emit(); err != nil {
		t.Fatalf("emit 2: %v", err)
	}
	lines := readHBLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	seen := map[string]bool{}
	for i, ln := range lines {
		var rec hbLine
		if err := json.Unmarshal([]byte(ln), &rec); err != nil {
			t.Fatalf("line %d bad json: %v", i, err)
		}
		if !rec.Heartbeat || rec.EndpointKey != heartbeatEndpointKey {
			t.Fatalf("line %d not a heartbeat record: %s", i, ln)
		}
		if rec.GatewayNode != "gw-hb-1" || rec.PolicyVersion != "v2026.3" || rec.FormalModelVersions != 5 {
			t.Fatalf("line %d node/version fields wrong: %+v", i, rec)
		}
		if rec.FinalAction != "ALLOW" || rec.RiskLevel != "NONE" || len(rec.Details) != 0 {
			t.Fatalf("line %d must carry no business semantics: %+v", i, rec)
		}
		if rec.GuardStartTime == nil || rec.UptimeSeconds < 0 {
			t.Fatalf("line %d missing guard start/uptime: %+v", i, rec)
		}
		if rec.RequestID == "" || seen[rec.RequestID] {
			t.Fatalf("line %d request_id missing or duplicated: %q", i, rec.RequestID)
		}
		seen[rec.RequestID] = true
	}
	// 业务事件零变化佐证：心跳键只在心跳记录出现（Record 心跳字段均 omitempty，
	// 由 apievents 包既有用例覆盖业务记录不含这些键，此处确认解析键名一致）
	if !strings.Contains(lines[0], `"heartbeat":true`) {
		t.Fatalf("heartbeat flag missing: %s", lines[0])
	}
}

// 周期间隔：启动后立即首跳，随后按周期发射（短周期注入，生产配置范围由 Validate 把关）。
func TestHeartbeatInterval(t *testing.T) {
	r, path := newHBRunner(t, 30*time.Millisecond)
	r.start()
	time.Sleep(110 * time.Millisecond)
	r.stop()
	if n := len(readHBLines(t, path)); n < 3 {
		t.Fatalf("heartbeats = %d, want >= 3 (immediate first beat + ticks)", n)
	}
}

// 优雅退出：stop 后不再有新行；stop 幂等可重复调用（Cleanup/重载路径不泄漏 goroutine）。
func TestHeartbeatGracefulStop(t *testing.T) {
	r, path := newHBRunner(t, 20*time.Millisecond)
	r.start()
	time.Sleep(75 * time.Millisecond)
	r.stop()
	before := len(readHBLines(t, path))
	if before == 0 {
		t.Fatal("no heartbeat emitted before stop")
	}
	time.Sleep(80 * time.Millisecond)
	if after := len(readHBLines(t, path)); after != before {
		t.Fatalf("heartbeats after stop = %d, want %d (goroutine leaked)", after, before)
	}
	r.stop() // 幂等：重复停止不 panic 不阻塞
}

// 关闭零行为：api_node_heartbeat_seconds=0（缺省）不启动 runner。
func TestHeartbeatDisabledByDefault(t *testing.T) {
	g := &Guard{logger: zap.NewNop()}
	g.startAPINodeHeartbeat()
	if g.heartbeat != nil {
		t.Fatal("heartbeat runner must stay nil when api_node_heartbeat_seconds=0")
	}
	// 开启时装配（apiEvents 就绪后），Cleanup 停止并清空
	path := filepath.Join(t.TempDir(), "api-events.jsonl")
	l, err := apievents.NewLogger(path, "gw-hb-2")
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	g = &Guard{
		logger:                  zap.NewNop(),
		apiEvents:               l,
		APINodeHeartbeatSeconds: minHeartbeatSeconds,
		APIPolicyVersion:        "v2026.3",
	}
	g.startAPINodeHeartbeat()
	if g.heartbeat == nil {
		t.Fatal("heartbeat runner must start when configured")
	}
	if err := g.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	// LOW-G4：Cleanup 只停 goroutine、不置 nil 字段（请求路径无锁读字段，置 nil 构成竞态）；
	// 通过 done 通道确认 runner 已退出
	if g.heartbeat == nil {
		t.Fatal("Cleanup must keep heartbeat field assigned")
	}
	select {
	case <-g.heartbeat.done:
	default:
		t.Fatal("Cleanup must stop heartbeat runner")
	}
}

// 配置校验：0=关闭；开启须 30-300 秒且依赖 api_dynamic_protection。
func TestValidateHeartbeatSeconds(t *testing.T) {
	base := func() *Guard {
		return &Guard{EventsLog: "events.log", APIDynamicProtection: true}
	}
	cases := []struct {
		name    string
		mutate  func(g *Guard)
		wantErr bool
	}{
		{"缺省 0 关闭", func(g *Guard) {}, false},
		{"下限 30", func(g *Guard) { g.APINodeHeartbeatSeconds = 30 }, false},
		{"上限 300", func(g *Guard) { g.APINodeHeartbeatSeconds = 300 }, false},
		{"负值", func(g *Guard) { g.APINodeHeartbeatSeconds = -1 }, true},
		{"过密 29", func(g *Guard) { g.APINodeHeartbeatSeconds = 29 }, true},
		{"过疏 301", func(g *Guard) { g.APINodeHeartbeatSeconds = 301 }, true},
		{"未开 API 动态防护", func(g *Guard) {
			g.APIDynamicProtection = false
			g.APINodeHeartbeatSeconds = 60
		}, true},
	}
	for _, c := range cases {
		g := base()
		c.mutate(g)
		err := g.Validate()
		if c.wantErr && err == nil {
			t.Fatalf("%s: want error, got nil", c.name)
		}
		if !c.wantErr && err != nil {
			t.Fatalf("%s: want nil, got %v", c.name, err)
		}
	}
}
