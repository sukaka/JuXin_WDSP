// G4b（P1-03 §6）：k8smeta 健康接入心跳 metrics 的接线测试。
package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jiuzhang-waf/wdsp-agent/internal/k8smeta"
)

// 元数据解析器存在时：心跳 metrics 携带 k8smeta_state/entries 等健康字段。
func TestMetricsSnapshotK8sMetaHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	a := newTestAgent(t, srv.URL)

	// 默认（auto 且无集群凭据）：k8smeta 字段缺省，不误报状态
	if m := a.metricsSnapshot(); m.K8sMetaState != "" {
		t.Fatalf("默认不应上报 k8smeta_state: %q", m.K8sMetaState)
	}

	r := k8smeta.NewResolver()
	a.k8sResolver = r
	m := a.metricsSnapshot()
	if m.K8sMetaState != string(k8smeta.StateUnavailable) {
		t.Fatalf("解析器从未成功同步应为 UNAVAILABLE: %q", m.K8sMetaState)
	}

	r.Replace(map[string]k8smeta.Metadata{"10.0.0.1": {Cluster: "c", Namespace: "n", Pod: "p", Workload: "w"}})
	m = a.metricsSnapshot()
	if m.K8sMetaState != string(k8smeta.StateOK) || m.K8sMetaEntries != 1 || m.K8sMetaStaleSeconds != 0 {
		t.Fatalf("成功后应为 OK/1 条目: %#v", m)
	}
}

// k8s.enabled=on 但集群凭据不可用（无 resolver）：显式 UNAVAILABLE，不静默缺省。
func TestMetricsSnapshotK8sForcedOnWithoutCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	a := newTestAgent(t, srv.URL)
	a.cfg.K8s.Enabled = "on"

	if m := a.metricsSnapshot(); m.K8sMetaState != string(k8smeta.StateUnavailable) {
		t.Fatalf("k8s=on 且无凭据应显式 UNAVAILABLE: %q", m.K8sMetaState)
	}
}
