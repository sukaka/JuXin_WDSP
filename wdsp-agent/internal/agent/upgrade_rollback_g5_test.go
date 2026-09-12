// G5 兼容升级 / 回退演练测试（任务书 docs/tasks/wdsp-p1/P1-03_AGENT_GATEWAY_PROTOCOLS.md
// §7 G5、§8 AGT-023/AGT-024/AGT-028；契约 docs/agents/WDSP_AGENT_HTTP_EVENT_V2_CONTRACT.md
// §1/§3/§4 与任务书 §9 回退顺序「先停止新来源并处理 v2 缓存，再降级不支持 v2 的程序」）。
//
// 覆盖场景：
//   - 升级正式路径：旧服务端（无 capabilities 回执）v1 线格式 → 服务端升级后
//     心跳回执 [1,2] → 切换 v2；升级前转缓存的 v1 格式记录补传时重构造 v2，
//     event_id 内容派生稳定（升级前后业务不中断、缓存不丢）（AGT-028 升级向）；
//   - 能力回退：生效集从 [1,2] 收回为 [1] → 实时通道降回 v1 线格式；
//     适配器（mirror/tap）v2 记录在收回期间丢弃计数（不降级误标、不静默）；
//     同段缓存的 H/M 混合记录补传：M 计数丢弃、H 照常送达、段正常清除（AGT-028 回退向）；
//   - 适配器关闭回退：镜像接收器启动后关闭，被动 HTTP 通道照常（原业务继续）；
//   - 旧程序误解析防护：v1 时代程序的缓存解析开关（F/H/缺省无标签三分支）对
//     'M' 标签 v2 记录必然解析失败跳过——不可能误解析为合法 flow/HTTP 记录；
//     新程序对同一段混合缓存可完整补传全部三类记录（AGT-028 缓存兼容）；
//   - 临时采集覆盖到期：applyServerConfig 持久化 overrides 快照（重启沿用），
//     求值时过期规则即时忽略（到期停止额外正文采集），Prune 惰性清理（AGT-024）。
package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/buffer"
	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

// g5WireBatch 服务端视角记录的每个 HTTP 批次线格式特征。
type g5WireBatch struct {
	schemaVersion int      // 0 = v1（无 schema_version 字段）
	eventIDs      []string // v2 批次逐条 event_id（v1 无此字段）
	headersArray  bool     // v2 headers 数组形态
}

// g5Server 可切换能力回执的旧/新服务端模拟（AGT-023/028 双端演练）。
type g5Server struct {
	mu       sync.Mutex
	upgraded bool         // 服务端是否已升级（心跳回执 [1,2]）
	failNext atomic.Int32 // HTTP 端点下一次请求返回 500（强制转缓存）
	batches  []g5WireBatch
}

func (s *g5Server) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agents/a1/heartbeat":
			s.mu.Lock()
			upgraded := s.upgraded
			s.mu.Unlock()
			resp := map[string]interface{}{
				"server_time": 1, "config_version": 0, "desired_state": "ENABLED",
				"heartbeat_interval_seconds": 15,
			}
			if upgraded {
				resp["capabilities"] = map[string]interface{}{"http_event_schema_versions": []int{1, 2}}
			}
			_ = json.NewEncoder(w).Encode(resp)
		case "/api/v1/agents/a1/http":
			var env map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
				t.Errorf("批次解析: %v", err)
			}
			b := g5WireBatch{}
			if v, ok := env["schema_version"].(float64); ok {
				b.schemaVersion = int(v)
			}
			recs, _ := env["records"].([]interface{})
			for _, raw := range recs {
				rec, _ := raw.(map[string]interface{})
				if id, ok := rec["event_id"].(string); ok {
					b.eventIDs = append(b.eventIDs, id)
				}
				req, _ := rec["request"].(map[string]interface{})
				if hdrs, _ := req["headers"].(map[string]interface{}); hdrs != nil {
					for _, v := range hdrs {
						if _, isArr := v.([]interface{}); isArr {
							b.headersArray = true
						}
					}
				}
			}
			s.mu.Lock()
			s.batches = append(s.batches, b)
			s.mu.Unlock()
			if s.failNext.Add(-1) >= 0 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			s.failNext.Store(0)
			w.WriteHeader(http.StatusAccepted)
			if b.schemaVersion == 2 {
				_ = json.NewEncoder(w).Encode(events.HTTPV2Response{AcceptedCount: len(recs)})
			} else {
				_ = json.NewEncoder(w).Encode(events.HTTPAcceptedResponse{Accepted: len(recs)})
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// g5Heartbeat 执行一次真实心跳往返并应用能力回执（返回生效集是否含 v2）。
func g5Heartbeat(t *testing.T, a *Agent) bool {
	t.Helper()
	hb, err := a.client.Heartbeat(context.Background(), "a1", transport.HeartbeatRequest{
		Timestamp: time.Now().Unix(), Status: "ONLINE", Capabilities: transport.DeclaredCapabilities(),
	})
	if err != nil {
		t.Fatal(err)
	}
	a.applyCapabilities(hb.Capabilities)
	return a.httpV2.Load()
}

// TestG5UpgradePathV1ToV2WithSpool 升级演练（AGT-023 新 Agent↔旧 Server + AGT-028 升级向）：
// 旧服务端 v1 收发 → 500 转缓存（v1 格式 'H' 标签）→ 服务端升级 → 心跳回执 [1,2]
// 开通 v2 → 实时记录切 v2 线格式 → 升级前缓存记录补传重构造 v2 且 event_id 稳定。
// 全程业务通道不中断（每阶段发送均被确认），升级前零 v2 请求、升级后零 v1 请求。
func TestG5UpgradePathV1ToV2WithSpool(t *testing.T) {
	gs := &g5Server{}
	srv := httptest.NewServer(gs.handler(t))
	defer srv.Close()

	a := newTestAgent(t, srv.URL)
	buf, err := buffer.Open(t.TempDir(), 0, 1<<20, time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	a.buf = buf
	a.cfg.Policy.Buffer.Enabled = true // applyPolicy 按策略热更缓存开关，须显式启用
	a.applyPolicy(a.cfg.EffectivePolicy())

	// ① 旧服务端：心跳无 capabilities 回执 → 仅 v1
	if g5Heartbeat(t, a) {
		t.Fatal("旧服务端无回执字段，不得启用 v2")
	}

	// ② v1 线格式实时发送（升级前）；带 Header 以区分 v1 单值 map / v2 数组形态
	recA := p1Record("/a")
	recA.Request.Headers = map[string]string{"x-g5": "1"}
	a.sendHTTPBatch([]events.HTTPRecord{recA})

	// ③ 500 → 转磁盘缓存（v1 格式 'H' 标签，升级前积压）
	recB := p1Record("/b")
	recB.FlowID = "a1-1.1.1.1-80-2.2.2.2-8080-2"
	recB.Request.Headers = map[string]string{"x-g5": "2"}
	gs.failNext.Store(1)
	a.sendHTTPBatch([]events.HTTPRecord{recB})
	if a.buf.Bytes() == 0 {
		t.Fatal("500 后记录应转磁盘缓存")
	}

	// ④ 服务端升级：心跳回执 [1,2] → 开通 v2
	gs.mu.Lock()
	gs.upgraded = true
	gs.mu.Unlock()
	if !g5Heartbeat(t, a) {
		t.Fatal("升级后生效集含 v2，应启用 v2 发送路径")
	}

	// ⑤ 升级后实时记录按 v2 线格式发送，event_id 内容派生稳定
	recC := p1Record("/c")
	recC.FlowID = "a1-1.1.1.1-80-2.2.2.2-8080-3"
	recC.Request.Headers = map[string]string{"x-g5": "3"}
	a.sendHTTPBatch([]events.HTTPRecord{recC})

	// ⑥ 升级前积压的 v1 缓存记录补传：重构造 v2、event_id 稳定、服务端确认
	a.replayBuffer()
	if a.buf.Bytes() != 0 {
		t.Fatalf("补传成功后缓存应清空: %d", a.buf.Bytes())
	}

	gs.mu.Lock()
	defer gs.mu.Unlock()
	if len(gs.batches) != 4 {
		t.Fatalf("应为 4 个批次（v1实时/v1转缓存/v2实时/v2补传）: %+v", gs.batches)
	}
	// 升级前：两批均为 v1 线格式（无 schema_version、无 event_id、headers 非数组）
	for i := 0; i < 2; i++ {
		b := gs.batches[i]
		if b.schemaVersion != 0 || len(b.eventIDs) != 0 || b.headersArray {
			t.Errorf("升级前批次 %d 应为纯 v1 线格式: %+v", i, b)
		}
	}
	// 升级后：实时 + 补传均为 v2 线格式
	for i := 2; i < 4; i++ {
		b := gs.batches[i]
		if b.schemaVersion != 2 || len(b.eventIDs) != 1 || !b.headersArray {
			t.Errorf("升级后批次 %d 应为 v2 线格式: %+v", i, b)
		}
	}
	if gs.batches[2].eventIDs[0] != events.StableEventID("a1", recC) {
		t.Errorf("实时 v2 event_id 不稳定: %q", gs.batches[2].eventIDs[0])
	}
	if gs.batches[3].eventIDs[0] != events.StableEventID("a1", recB) {
		t.Errorf("缓存补传重构造 v2 的 event_id 应由记录内容派生且稳定: %q, want %q",
			gs.batches[3].eventIDs[0], events.StableEventID("a1", recB))
	}
	if got := a.metrics.Accepted.Load(); got != 3 {
		t.Fatalf("accepted 应为 3（A 实时 + C 实时 + B 补传；B 首发 500 不计）: %d", got)
	}
}

// TestG5CapabilityRevokedDowngrade 能力回退演练（AGT-028 回退向 + AGT-023 不假报启用）：
// 生效集 [1,2] → 收回 [1]：实时 HTTP 通道降回 v1 线格式；mirror/tap v2 记录在
// 收回期间实时与补传两路均丢弃计数（不降级 v1 误标来源、不静默——计数可查询）；
// 同段混合缓存中 H 记录照常补传达服务端，段正常清除（M 丢弃不阻塞同段 H 记录）。
func TestG5CapabilityRevokedDowngrade(t *testing.T) {
	var mu sync.Mutex
	var httpCalls []g5WireBatch
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			t.Errorf("批次解析: %v", err)
		}
		b := g5WireBatch{}
		if v, ok := env["schema_version"].(float64); ok {
			b.schemaVersion = int(v)
		}
		recs, _ := env["records"].([]interface{})
		mu.Lock()
		httpCalls = append(httpCalls, b)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.HTTPAcceptedResponse{Accepted: len(recs)})
	}))
	defer srv.Close()

	a := newTestAgent(t, srv.URL)
	buf, err := buffer.Open(t.TempDir(), 0, 1<<20, time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	a.buf = buf

	// 已协商 v2 → 收回为 [1]
	a.applyCapabilities(&transport.Capabilities{HTTPEventSchemaVersions: []int{1, 2}})
	if !a.httpV2.Load() {
		t.Fatal("前提：v2 已生效")
	}
	a.applyCapabilities(&transport.Capabilities{HTTPEventSchemaVersions: []int{1}})
	if a.httpV2.Load() {
		t.Fatal("生效集收回 [1] 后必须降回 v1")
	}

	// 实时 HTTP 通道降回 v1 线格式（被动采集业务继续）
	a.sendHTTPBatch([]events.HTTPRecord{p1Record("/after-revoke")})

	// 适配器 v2 记录实时路径：未协商丢弃计数，不向服务端发请求
	a.sendMirrorBatch([]events.HTTPRecordV2{mirrorV2Record("/m-live")})
	if got := a.metrics.dropReasonsSnapshot()[DropReasonMirrorV2NotNegotiated]; got != 1 {
		t.Fatalf("实时镜像记录应计数 mirror_v2_not_negotiated: %v", a.metrics.dropReasonsSnapshot())
	}

	// 回退前积压的混合缓存（H v1 + M v2 同段）：补传时 M 计数丢弃、H 照常送达
	a.bufferHTTP([]events.HTTPRecord{p1Record("/spooled-h")})
	a.bufferMirror([]events.HTTPRecordV2{mirrorV2Record("/m-spooled")})
	a.replayBuffer()

	mu.Lock()
	defer mu.Unlock()
	if len(httpCalls) != 2 {
		t.Fatalf("服务端应只收到 2 个 v1 批次（实时 + 缓存 H 补传）: %+v", httpCalls)
	}
	for i, b := range httpCalls {
		if b.schemaVersion != 0 {
			t.Errorf("批次 %d 应为 v1 线格式: %+v", i, b)
		}
	}
	if got := a.metrics.dropReasonsSnapshot()[DropReasonMirrorV2NotNegotiated]; got != 2 {
		t.Fatalf("补传镜像记录也应计数丢弃（合计 2）: %v", a.metrics.dropReasonsSnapshot())
	}
	if a.buf.Bytes() != 0 {
		t.Fatalf("M 丢弃为显式计数了断，段应正常清除不残留积压: %d", a.buf.Bytes())
	}
}

// TestG5AdapterStopPassiveContinues 关闭适配器回退（AGT-028）：镜像接收器真实启动
// 后关闭，被动 HTTP/1 采集发送通道不受任何影响（原业务继续）。
func TestG5AdapterStopPassiveContinues(t *testing.T) {
	var accepted atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accepted.Add(1)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.HTTPAcceptedResponse{Accepted: 1})
	}))
	defer srv.Close()

	a := newTestAgent(t, srv.URL)
	a.cfg.Mirror = config.MirrorConfig{
		Enabled:        true,
		SocketPath:     filepath.Join(t.TempDir(), "m.sock"),
		SourceInstance: "nginx-a",
		InstanceToken:  "tok-g5",
	}
	a.mirror = a.newMirrorReceiver()
	if a.mirror == nil {
		t.Fatal("合法配置应创建镜像接收器")
	}
	a.startMirror()
	a.stopMirror() // 回退：关闭适配器

	// 被动通道照常（v1 未协商路径）
	a.sendHTTPBatch([]events.HTTPRecord{p1Record("/passive")})
	if accepted.Load() != 1 {
		t.Fatal("关闭适配器后被动 HTTP 通道必须照常工作")
	}
	// tap 未启用时停止为安全空操作（双适配器关闭回退不 panic）
	a.stopTap()
}

// TestG5LegacyProgramDoesNotMisparseV2Cache 旧程序缓存兼容（AGT-028）：
// v1 时代程序的补传解析开关为三分支（'F'→flow、'H'→HTTP v1、缺省→旧版无标签 flow）。
// 对 G2 起新增的 'M' 标签 v2 记录：首字节 'M' 使缺省分支 JSON 解析必然失败——
// 旧程序只能跳过该记录，物理上不可能把 v2 缓存误解析为合法 flow/HTTP 记录。
// 同时验证新程序对 F/H/M/无标签混合段可完整补传全部记录（旧记录可读、新缓存可续传）。
func TestG5LegacyProgramDoesNotMisparseV2Cache(t *testing.T) {
	a := newTestAgent(t, "http://127.0.0.1:1")
	buf, err := buffer.Open(t.TempDir(), 0, 1<<20, time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	a.buf = buf

	flowEv := events.FlowEvent{
		EventType: events.TypeFlowEnd, FlowID: "f1", Timestamp: 1788256800,
		SrcIP: "1.1.1.1", SrcPort: 80, DstIP: "2.2.2.2", DstPort: 8080,
		Protocol: "tcp", Direction: "ingress", TLSVisibility: events.VisibilityPlaintext,
	}
	httpRec := p1Record("/legacy-h")
	mirrorRec := mirrorV2Record("/legacy-m")

	// 新程序写入：F/H/M 三标签各一条
	a.bufferEvents([]events.FlowEvent{flowEv})
	a.bufferHTTP([]events.HTTPRecord{httpRec})
	a.bufferMirror([]events.HTTPRecordV2{mirrorRec})
	// 模拟 Phase 1/2 旧版缓存：无标签 flow JSON
	legacyRaw, err := json.Marshal(flowEv)
	if err != nil {
		t.Fatal(err)
	}
	if err := buf.Write(legacyRaw); err != nil {
		t.Fatal(err)
	}

	// 读出全部原始记录
	var raws [][]byte
	if _, err := buf.Replay(100, func(batch [][]byte) error {
		raws = append(raws, batch...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(raws) != 4 {
		t.Fatalf("应读出 4 条缓存记录: %d", len(raws))
	}

	// 旧程序（v1 时代）解析开关重放：M 记录必须解析失败被跳过
	legacyParse := func(r []byte) (kind string, ok bool) {
		switch {
		case len(r) > 1 && r[0] == bufTagFlow:
			var ev events.FlowEvent
			if json.Unmarshal(r[1:], &ev) == nil && ev.FlowID != "" {
				return "flow", true
			}
		case len(r) > 1 && r[0] == bufTagHTTP:
			var rec events.HTTPRecord
			if json.Unmarshal(r[1:], &rec) == nil && rec.FlowID != "" {
				return "http", true
			}
		default: // 旧版无标签缓存（含旧程序眼中的 'M' 记录）
			var ev events.FlowEvent
			if json.Unmarshal(r, &ev) == nil && ev.FlowID != "" {
				return "flow", true
			}
		}
		return "", false
	}
	legacyKinds := map[string]int{}
	misParsed := 0
	for i, r := range raws {
		kind, ok := legacyParse(r)
		if !ok {
			// 唯一应失败的是第 3 条（'M' 标签 v2 记录）
			if i != 2 || r[0] != bufTagMirror {
				t.Errorf("记录 %d 解析失败超出预期（仅 'M' 记录允许失败）", i)
			}
			continue
		}
		if r[0] == bufTagMirror {
			misParsed++
		}
		legacyKinds[kind]++
	}
	if misParsed != 0 {
		t.Fatal("'M' 标签 v2 记录被旧程序解析开关误解析为合法记录")
	}
	if legacyKinds["flow"] != 2 || legacyKinds["http"] != 1 {
		t.Fatalf("旧程序应正常解析 F×2(含无标签)/H×1: %v", legacyKinds)
	}

	// 新程序对同一混合段（重开缓存，v2 已协商）完整补传全部记录
	var mu sync.Mutex
	var flowsN, httpV2N, mirrorN int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/agents/a1/flows":
			var req events.FlowsRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("flows 解析: %v", err)
			}
			flowsN += len(req.Events)
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(events.FlowsResponse{Accepted: len(req.Events)})
		case "/api/v1/agents/a1/http":
			var req events.HTTPRequestV2
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("http 解析: %v", err)
			}
			for _, rec := range req.Records {
				if rec.SourceType == events.SourceNginxMirror {
					mirrorN++
				} else {
					httpV2N++
				}
			}
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(events.HTTPV2Response{AcceptedCount: len(req.Records)})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	a2 := newTestAgent(t, srv.URL)
	buf2, err := buffer.Open(filepath.Join(t.TempDir(), "b2"), 0, 1<<20, time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	a2.buf = buf2
	a2.bufferEvents([]events.FlowEvent{flowEv})
	a2.bufferHTTP([]events.HTTPRecord{httpRec})
	a2.bufferMirror([]events.HTTPRecordV2{mirrorRec})
	if err := buf2.Write(legacyRaw); err != nil {
		t.Fatal(err)
	}
	a2.applyCapabilities(&transport.Capabilities{HTTPEventSchemaVersions: []int{1, 2}})
	a2.replayBuffer()

	mu.Lock()
	defer mu.Unlock()
	if flowsN != 2 || httpV2N != 1 || mirrorN != 1 {
		t.Fatalf("新程序应完整补传 flows=2 http=1 mirror=1: flows=%d http=%d mirror=%d",
			flowsN, httpV2N, mirrorN)
	}
	if a2.buf.Bytes() != 0 {
		t.Fatalf("补传成功后缓存应清空: %d", a2.buf.Bytes())
	}
}

// TestG5OverrideExpiryStopsElevation 临时采集覆盖到期（AGT-024 补验证，Agent 侧接缝）：
// applyServerConfig 下发的定向覆盖规则随策略持久化快照（重启沿用）；求值时
// 过期规则即时忽略（到期停止提升采集等级 = 停止额外正文采集），Prune 惰性清理。
func TestG5OverrideExpiryStopsElevation(t *testing.T) {
	a := newTestAgent(t, "http://127.0.0.1:1")
	a.cfgPath = filepath.Join(t.TempDir(), "agent.json")

	now := time.Now().UTC()
	expires := now.Add(2 * time.Second) // RFC3339 秒精度，求值用 now 参数确定性驱动
	ov := config.Override{
		ID:           "ov-g5",
		Match:        config.OverrideMatch{DstIP: "10.9.9.9", DstPort: 443},
		CaptureLevel: config.LevelL3,
		ExpiresAt:    expires.Format(time.RFC3339),
	}
	policy := a.cfg.EffectivePolicy() // 基础 L2
	if err := a.applyServerConfig(policy, []config.Override{ov}, 7); err != nil {
		t.Fatal(err)
	}
	if a.appliedVersion() != 7 {
		t.Fatalf("已应用版本应为 7: %d", a.appliedVersion())
	}

	// 未到期：命中规则提升生效等级（L3 额外正文采集开启）
	if got := a.overrides.EvalFlow("10.9.9.9", 443, now); got != 3 {
		t.Fatalf("未到期命中应提升 L3: %d", got)
	}
	// 不命中的流不受覆盖影响
	if got := a.overrides.EvalFlow("10.9.9.8", 443, now); got != 0 {
		t.Fatalf("不命中应为 0: %d", got)
	}

	// 持久化快照：重启沿用（Load 回读 override 仍在）
	reloaded, err := config.Load(a.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Overrides) != 1 || reloaded.Overrides[0].ID != "ov-g5" {
		t.Fatalf("覆盖规则应随策略持久化: %+v", reloaded.Overrides)
	}
	if reloaded.AppliedConfigVersion != 7 {
		t.Fatalf("已应用版本应持久化: %d", reloaded.AppliedConfigVersion)
	}

	// 到期：求值即时忽略（额外正文采集停止；基础等级不变）
	after := expires.Add(time.Hour)
	if got := a.overrides.EvalFlow("10.9.9.9", 443, after); got != 0 {
		t.Fatalf("到期后规则必须即时忽略（停止提升）: %d", got)
	}
	// 惰性清理：Prune 移除过期规则
	a.overrides.Prune(after)
	if n := a.overrides.Len(); n != 0 {
		t.Fatalf("Prune 后应清空过期规则: %d", n)
	}
}
