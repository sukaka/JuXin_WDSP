// G4b（P1-03 §6）：k8smeta 状态契约（OK/STALE/UNAVAILABLE）、条目 TTL 与差分失效、
// owner 权威/推断区分、namespace 限定 endpoints、API 403/超时降级 的组件级测试。
// 真实集群验证（AGT-021/022）因本机无可用集群标 BLOCKED_ENV，见 WORKLOG。
package k8smeta

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newFakeKube 按 namespace 记录请求路径；pods/endpoints/replicasets 内容由回调决定。
func newFakeKube(t *testing.T, pods func() []any, endpoints map[string][]any, replicasets map[string][]any) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var forbidden atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write := func(items []any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{}, "items": items})
		}
		switch r.URL.Path {
		case "/api/v1/pods":
			write(pods())
		case "/api/v1/endpoints", "/apis/apps/v1/replicasets":
			// 不允许回退到全集群端点/RS 查询
			forbidden.Add(1)
			http.Error(w, "cluster-wide query not allowed", http.StatusForbidden)
		default:
			if ns, ok := strings.CutPrefix(r.URL.Path, "/api/v1/namespaces/"); ok && strings.HasSuffix(ns, "/endpoints") {
				write(endpoints[strings.TrimSuffix(ns, "/endpoints")])
				return
			}
			if ns, ok := strings.CutPrefix(r.URL.Path, "/apis/apps/v1/namespaces/"); ok && strings.HasSuffix(ns, "/replicasets") {
				write(replicasets[strings.TrimSuffix(ns, "/replicasets")])
				return
			}
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &forbidden
}

func pod(name, ns, ip string, owners ...any) any {
	m := map[string]any{"name": name, "namespace": ns}
	if len(owners) > 0 {
		m["ownerReferences"] = owners
	}
	return map[string]any{"metadata": m, "status": map[string]string{"podIP": ip}}
}

func hostNetworkPod(name, ns, ip string) any {
	return map[string]any{
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec":     map[string]any{"hostNetwork": true},
		"status":   map[string]string{"podIP": ip},
	}
}

func rs(name string, owners ...any) any {
	m := map[string]any{"name": name}
	if len(owners) > 0 {
		m["ownerReferences"] = owners
	}
	return map[string]any{"metadata": m}
}

func ep(ns, name string, ips ...string) any {
	addrs := make([]any, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, map[string]string{"ip": ip})
	}
	return map[string]any{"metadata": map[string]string{"name": name, "namespace": ns}, "subsets": []any{map[string]any{"addresses": addrs}}}
}

// 状态机：UNAVAILABLE（从未成功）→ OK（成功）→ STALE（失败保留旧快照）→ UNAVAILABLE（持续失败超阈值）→ OK（恢复）。
func TestHealthStateMachine(t *testing.T) {
	r := NewResolver()
	now := time.Now()
	r.now = func() time.Time { return now }

	if h := r.Health(); h.State != StateUnavailable {
		t.Fatalf("从未成功应为 UNAVAILABLE: %s", h.State)
	}

	r.Replace(map[string]Metadata{"10.0.0.1": {Cluster: "c", Namespace: "n", Pod: "p"}})
	if h := r.Health(); h.State != StateOK || h.Entries != 1 {
		t.Fatalf("成功后应为 OK/1 条目: %#v", h)
	}

	now = now.Add(time.Minute) // 距上次成功 1 分钟
	r.noteFailure(errors.New("kube API 403 Forbidden"), now)
	h := r.Health()
	if h.State != StateStale || h.StaleFor != time.Minute || h.SyncFailures != 1 || h.LastError == "" {
		t.Fatalf("失败后应为 STALE 并带距成功时长/错误: %#v", h)
	}
	if m := r.Resolve("", "10.0.0.1"); m == nil || m.Pod != "p" {
		t.Fatal("STALE 期间旧快照仍参与解析（采集继续）")
	}

	now = now.Add(r.UnavailableAfter) // 持续失败超过阈值
	if h := r.Health(); h.State != StateUnavailable {
		t.Fatalf("持续失败超阈值应为 UNAVAILABLE: %#v", h)
	}

	r.Replace(map[string]Metadata{"10.0.0.2": {Cluster: "c", Namespace: "n", Pod: "p2"}})
	h = r.Health()
	if h.State != StateOK || h.LastError != "" || h.SyncFailures != 1 {
		t.Fatalf("恢复后应为 OK 且保留累计失败计数: %#v", h)
	}
}

// 条目 TTL：长时间 API 故障期间，未被成功快照再确认的条目到期后不再解析，
// 防止 Pod 删除/IP 重用串联旧归属。
func TestEntryTTLExpiry(t *testing.T) {
	r := NewResolver()
	r.EntryTTL = time.Minute
	now := time.Now()
	r.now = func() time.Time { return now }
	r.Replace(map[string]Metadata{"10.0.0.1": {Cluster: "c", Namespace: "n", Pod: "p"}})

	if m := r.Resolve("", "10.0.0.1"); m == nil {
		t.Fatal("TTL 内应可解析")
	}
	now = now.Add(2 * time.Minute) // 刷新失败期间超过 TTL
	if m := r.Resolve("", "10.0.0.1"); m != nil {
		t.Fatalf("TTL 过期后不应再解析旧归属: %#v", m)
	}
	if h := r.Health(); h.Entries != 0 {
		t.Fatalf("过期条目不参与 Health.Entries 计数: %#v", h)
	}
}

// 快照差分失效：IP 重用解析到新 Pod，Pod 删除后立即不再解析。
func TestSnapshotDiffInvalidation(t *testing.T) {
	r := NewResolver()
	r.Replace(map[string]Metadata{"10.0.0.9": {Cluster: "c", Namespace: "a", Pod: "pod-a", Workload: "wa"}})
	if m := r.Resolve("", "10.0.0.9"); m.Pod != "pod-a" {
		t.Fatalf("got %#v", m)
	}
	// IP 重用：同一 IP 归属新 Pod/新工作负载，无旧归属残留
	r.Replace(map[string]Metadata{"10.0.0.9": {Cluster: "c", Namespace: "b", Pod: "pod-b", Workload: "wb"}})
	m := r.Resolve("", "10.0.0.9")
	if m.Pod != "pod-b" || m.Namespace != "b" || m.Workload != "wb" {
		t.Fatalf("IP 重用应解析到新归属: %#v", m)
	}
	// Pod 删除：下一次成功快照不再包含该 IP
	r.Replace(map[string]Metadata{})
	if m := r.Resolve("", "10.0.0.9"); m != nil {
		t.Fatalf("Pod 删除后不应再解析: %#v", m)
	}
}

// owner 权威/推断：Deployment 经 ReplicaSet 权威解析；RS 缺失/查询失败降级截尾推断；
// StatefulSet/DaemonSet/Job 直接 owner 权威；独立 Pod 工作负载即自身。
func TestSyncOwnerResolution(t *testing.T) {
	pods := func() []any {
		return []any{
			pod("web-7d9f84c8bf-x1", "prod", "10.1.0.1", map[string]string{"kind": "ReplicaSet", "name": "web-7d9f84c8bf"}),
			pod("orphan-6c96f59b7d-y2", "prod", "10.1.0.2", map[string]string{"kind": "ReplicaSet", "name": "orphan-6c96f59b7d"}), // RS 列表缺失 → 推断
			pod("redis-0", "prod", "10.1.0.3", map[string]string{"kind": "StatefulSet", "name": "redis"}),
			pod("bare", "prod", "10.1.0.4"),
		}
	}
	replicasets := map[string][]any{
		"prod": {rs("web-7d9f84c8bf", map[string]string{"kind": "Deployment", "name": "web"})},
	}
	srv, forbidden := newFakeKube(t, pods, map[string][]any{}, replicasets)
	c := &Client{baseURL: srv.URL, token: "t", nodeName: "n", cluster: "c", http: srv.Client()}

	items, err := c.sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if forbidden.Load() != 0 {
		t.Fatal("不得发起全集群 endpoints/replicasets 查询")
	}
	cases := []struct {
		ip       string
		workload string
		inferred bool
	}{
		{"10.1.0.1", "web", false},              // ReplicaSet → Deployment 权威解析
		{"10.1.0.2", "orphan", true},            // RS 缺失 → 截尾推断并显式标记
		{"10.1.0.3", "redis", false},            // StatefulSet 直接 owner 权威
		{"10.1.0.4", "bare", false},             // 独立 Pod：工作负载即自身
	}
	for _, tc := range cases {
		e, ok := items[tc.ip]
		if !ok {
			t.Fatalf("missing %s", tc.ip)
		}
		if e.meta.Workload != tc.workload || e.inferred != tc.inferred {
			t.Fatalf("%s workload=%q inferred=%v, want %q/%v", tc.ip, e.meta.Workload, e.inferred, tc.workload, tc.inferred)
		}
	}
}

// 独立 ReplicaSet（无 Deployment owner）：工作负载为 RS 名本身，权威非推断。
func TestSyncStandaloneReplicaSetIsAuthoritative(t *testing.T) {
	pods := func() []any {
		return []any{pod("solo-5b8f9c7d6-z3", "prod", "10.1.1.1", map[string]string{"kind": "ReplicaSet", "name": "solo-5b8f9c7d6"})}
	}
	replicasets := map[string][]any{"prod": {rs("solo-5b8f9c7d6")}} // 无 ownerReferences
	srv, _ := newFakeKube(t, pods, map[string][]any{}, replicasets)
	c := &Client{baseURL: srv.URL, token: "t", nodeName: "n", cluster: "c", http: srv.Client()}

	items, err := c.sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e := items["10.1.1.1"]
	if e.meta.Workload != "solo-5b8f9c7d6" || e.inferred {
		t.Fatalf("独立 RS 应权威归属自身: %#v", e)
	}
}

// ReplicaSet 查询 403（如沿用未授权 apps/replicasets 的旧 RBAC）：同步继续，
// Deployment 归属降级为截尾推断并经 Health.InferredOwners 可见。
func TestSyncReplicaSetForbiddenDegradesToInferred(t *testing.T) {
	pods := func() []any {
		return []any{pod("web-7d9f84c8bf-x1", "prod", "10.1.0.1", map[string]string{"kind": "ReplicaSet", "name": "web-7d9f84c8bf"})}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/pods":
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{}, "items": pods()})
		case "/api/v1/namespaces/prod/endpoints":
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{}, "items": []any{}})
		default:
			http.Error(w, "forbidden", http.StatusForbidden)
		}
	}))
	defer srv.Close()
	c := &Client{baseURL: srv.URL, token: "t", nodeName: "n", cluster: "c", http: srv.Client()}

	items, err := c.sync(context.Background())
	if err != nil {
		t.Fatalf("RS 403 不应拖垮整个同步: %v", err)
	}
	e := items["10.1.0.1"]
	if e.meta.Workload != "web" || !e.inferred {
		t.Fatalf("应降级为截尾推断: %#v", e)
	}

	r := NewResolver()
	r.replaceAll(items, time.Now())
	if h := r.Health(); h.InferredOwners != 1 {
		t.Fatalf("推断归属应计数可见: %#v", h)
	}
}

// hostNetwork Pod 的 podIP 是节点 IP：不得把节点级流量归属到该工作负载。
func TestSyncSkipsHostNetworkPods(t *testing.T) {
	pods := func() []any {
		return []any{
			hostNetworkPod("node-agent", "kube-system", "192.168.1.10"),
			pod("web-7d9f84c8bf-x1", "prod", "10.1.0.1", map[string]string{"kind": "ReplicaSet", "name": "web-7d9f84c8bf"}),
		}
	}
	replicasets := map[string][]any{"prod": {rs("web-7d9f84c8bf", map[string]string{"kind": "Deployment", "name": "web"})}}
	srv, _ := newFakeKube(t, pods, map[string][]any{}, replicasets)
	c := &Client{baseURL: srv.URL, token: "t", nodeName: "n", cluster: "c", http: srv.Client()}

	items, err := c.sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := items["192.168.1.10"]; ok {
		t.Fatal("hostNetwork Pod 不应进入 IP 映射")
	}
	if len(items) != 1 {
		t.Fatalf("items = %#v", items)
	}
}

// endpoints 按本节点 Pod 所在 namespace 分别查询；仅同 namespace 的 Service 关联成功。
func TestSyncEndpointsPerNamespace(t *testing.T) {
	pods := func() []any {
		return []any{
			pod("api-1", "prod", "10.2.0.1"),
			pod("api-2", "staging", "10.2.0.2"),
		}
	}
	endpoints := map[string][]any{
		"prod":    {ep("prod", "api", "10.2.0.1", "10.2.0.2")}, // 含跨 namespace IP：只应关联同 ns 的 10.2.0.1
		"staging": {ep("staging", "api", "10.2.0.2")},
	}
	var prodCalls, stagingCalls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write := func(items []any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{}, "items": items})
		}
		switch r.URL.Path {
		case "/api/v1/pods":
			write(pods())
		case "/api/v1/namespaces/prod/endpoints":
			prodCalls.Add(1)
			write(endpoints["prod"])
		case "/api/v1/namespaces/staging/endpoints":
			stagingCalls.Add(1)
			write(endpoints["staging"])
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := &Client{baseURL: srv.URL, token: "t", nodeName: "n", cluster: "c", http: srv.Client()}

	items, err := c.sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if prodCalls.Load() != 1 || stagingCalls.Load() != 1 {
		t.Fatalf("endpoints 应按 namespace 各查一次: prod=%d staging=%d", prodCalls.Load(), stagingCalls.Load())
	}
	if got := items["10.2.0.1"].meta.Service; got != "api" {
		t.Fatalf("prod service = %q", got)
	}
	if got := items["10.2.0.2"].meta.Service; got != "api" {
		t.Fatalf("staging service = %q", got)
	}
	// 两个 namespace 均无 ReplicaSet owner：不应发起 RS 查询（default 分支 404 会暴露）
}

// API 403（如 RBAC 被收回）：同步报错但旧快照保留，状态 STALE，采集解析继续。
func TestRunForbiddenKeepsSnapshotAndMarksStale(t *testing.T) {
	var forbiddenMode atomic.Bool
	pods := func() []any {
		return []any{pod("web-1", "prod", "10.3.0.1")}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if forbiddenMode.Load() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/api/v1/pods" {
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{}, "items": pods()})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/") {
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{}, "items": []any{}})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := &Client{baseURL: srv.URL, token: "t", nodeName: "n", cluster: "c", http: srv.Client(), refreshInterval: 10 * time.Millisecond}
	r := NewResolver()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx, r) }()

	waitFor := func(cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("condition not met within deadline")
	}

	waitFor(func() bool { return r.Health().State == StateOK })
	if m := r.Resolve("", "10.3.0.1"); m == nil {
		t.Fatal("同步成功后应可解析")
	}

	forbiddenMode.Store(true) // 模拟 RBAC 收回 / API 403
	waitFor(func() bool { return r.Health().State == StateStale })
	if m := r.Resolve("", "10.3.0.1"); m == nil || m.Pod != "web-1" {
		t.Fatal("403 期间采集解析应继续使用旧快照（STALE）")
	}
	if h := r.Health(); h.SyncFailures == 0 || h.LastError == "" {
		t.Fatalf("失败应计数并记录错误: %#v", h)
	}

	forbiddenMode.Store(false) // 恢复
	waitFor(func() bool { return r.Health().State == StateOK })
	cancel()
	<-done
}

// API 超时：客户端超时报错进入 STALE，不阻塞采集 goroutine。
func TestSyncTimeoutReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{}, "items": []any{}})
	}))
	defer srv.Close()
	c := &Client{baseURL: srv.URL, token: "t", nodeName: "n", cluster: "c",
		http: &http.Client{Timeout: 50 * time.Millisecond}}

	if _, err := c.sync(context.Background()); err == nil {
		t.Fatal("API 超时应如实报错（由 Run 置 STALE），不得静默当空快照")
	}
}
