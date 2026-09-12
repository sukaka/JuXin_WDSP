package jiuzhang_guard

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/netif"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// buildNetifFixture 最小 sysfs 风格目录树：单个物理口 jzt0（取不存在于真实宿主的名字，
// 避免 CI 上 ethtool 探测到宿主真实接口造成结果不确定）。
func buildNetifFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "devices", "0000:03:00.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	netDir := filepath.Join(root, "net")
	if0 := filepath.Join(netDir, "jzt0")
	if err := os.MkdirAll(if0, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "..", "devices", "0000:03:00.0"), filepath.Join(if0, "device")); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"address":   "00:11:22:33:44:55\n",
		"operstate": "up\n",
		"speed":     "1000\n",
	} {
		if err := os.WriteFile(filepath.Join(if0, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return netDir
}

func readNodeInterfaces(t *testing.T, path string) []netif.Record {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []netif.Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r netif.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("bad json line %q: %v", sc.Text(), err)
		}
		out = append(out, r)
	}
	return out
}

func TestEnsureNetifCollectorLifecycle(t *testing.T) {
	defer resetNetifCollectorForTest()
	oldSysfs := netifSysfsDir
	netifSysfsDir = buildNetifFixture(t)
	defer func() { netifSysfsDir = oldSysfs }()

	logDir := t.TempDir()
	g := &Guard{EventsLog: filepath.Join(logDir, "guard-events.log"), GatewayNode: "node-a", logger: zap.NewNop()}

	ensureNetifCollector(g)

	// 启动时同步首采：快照已生成且字段完整
	recs := readNodeInterfaces(t, filepath.Join(logDir, netifSnapshotName))
	if len(recs) != 1 {
		t.Fatalf("records: %+v", recs)
	}
	r := recs[0]
	if r.NodeName != "node-a" || r.IfName != "jzt0" || r.MAC != "00:11:22:33:44:55" ||
		r.PCIPath != "0000:03:00.0" || r.LinkSpeed != 1000 || r.OperState != "up" ||
		r.MediaType != netif.MediaUnknown || r.CollectedAt.IsZero() {
		t.Errorf("record: %+v", r)
	}

	// 同签名复用（不重启采集器）
	h1 := netifColl
	ensureNetifCollector(g)
	if netifColl != h1 {
		t.Error("same signature should reuse collector")
	}

	// 异签名替换：旧采集器取消，新目录生成快照
	logDir2 := t.TempDir()
	g2 := &Guard{EventsLog: filepath.Join(logDir2, "guard-events.log"), GatewayNode: "node-a", logger: zap.NewNop()}
	ensureNetifCollector(g2)
	if netifColl == h1 {
		t.Error("changed signature should replace collector")
	}
	if h1.ctx == nil || h1.ctx.Err() == nil {
		t.Error("old collector should be cancelled")
	}
	if recs := readNodeInterfaces(t, filepath.Join(logDir2, netifSnapshotName)); len(recs) != 1 {
		t.Errorf("new dir snapshot: %+v", recs)
	}
}

func TestEnsureNetifCollectorNodeNameFromEnv(t *testing.T) {
	defer resetNetifCollectorForTest()
	oldSysfs := netifSysfsDir
	netifSysfsDir = buildNetifFixture(t)
	defer func() { netifSysfsDir = oldSysfs }()

	t.Setenv("GATEWAY_NODE_NAME", "env-node")
	logDir := t.TempDir()
	g := &Guard{EventsLog: filepath.Join(logDir, "guard-events.log"), GatewayNode: "node-a", logger: zap.NewNop()}
	ensureNetifCollector(g)

	recs := readNodeInterfaces(t, filepath.Join(logDir, netifSnapshotName))
	if len(recs) != 1 || recs[0].NodeName != "env-node" {
		t.Errorf("node name should prefer GATEWAY_NODE_NAME: %+v", recs)
	}
}

func TestEnsureNetifCollectorSysfsMissing(t *testing.T) {
	defer resetNetifCollectorForTest()
	oldSysfs := netifSysfsDir
	netifSysfsDir = filepath.Join(t.TempDir(), "no-such-sysfs")
	defer func() { netifSysfsDir = oldSysfs }()

	core, logs := observer.New(zap.WarnLevel)
	logDir := t.TempDir()
	g := &Guard{EventsLog: filepath.Join(logDir, "guard-events.log"), GatewayNode: "n", logger: zap.New(core)}

	ensureNetifCollector(g)
	ensureNetifCollector(g) // 同签名不重复告警、不重试
	if logs.Len() != 1 {
		t.Errorf("warn count = %d, want exactly 1", logs.Len())
	}
	if netifColl == nil || !netifColl.unavailable {
		t.Error("collector should be marked unavailable")
	}
	if netifColl.cancel != nil {
		t.Error("no collect goroutine expected when sysfs missing")
	}
	if _, err := os.Stat(filepath.Join(logDir, netifSnapshotName)); !os.IsNotExist(err) {
		t.Errorf("no snapshot expected when sysfs missing: %v", err)
	}
}

func TestEnsureNetifCollectorConcurrentProvision(t *testing.T) {
	defer resetNetifCollectorForTest()
	oldSysfs := netifSysfsDir
	netifSysfsDir = buildNetifFixture(t)
	defer func() { netifSysfsDir = oldSysfs }()

	// 并发异签名 Provision 回归：handle 发布即携带 cancel，替换窗口内并发方读到的
	// cancel 必非 nil（旧实现先发布 cancel=nil 再补值，并发读到 nil 跳过取消会泄漏旧 runner）。
	// 测试目录在主 goroutine 预建（t.TempDir 不约定并发安全），goroutine 内只做 Provision。
	guards := make([]*Guard, 0, 16)
	for i := 0; i < 16; i++ {
		logDir := t.TempDir()
		guards = append(guards, &Guard{
			EventsLog:   filepath.Join(logDir, "guard-events.log"),
			GatewayNode: "node-a", logger: zap.NewNop(),
		})
	}
	var wg sync.WaitGroup
	for _, g := range guards {
		wg.Add(1)
		go func(g *Guard) {
			defer wg.Done()
			ensureNetifCollector(g)
		}(g)
	}
	wg.Wait()
	if netifColl == nil || netifColl.cancel == nil {
		t.Fatal("collector should be installed with non-nil cancel after concurrent provision")
	}
	if netifColl.ctx == nil || netifColl.ctx.Err() != nil {
		t.Error("final collector ctx should be live until replaced or reset")
	}
}
