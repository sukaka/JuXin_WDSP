// 配置拉取 overrides 解析测试（Phase 4 契约 §2.4：config 响应顶层字段，
// 旧服务端无此字段按空数组；解析失败不阻断配置应用）。
package control

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

func pullWithBody(t *testing.T, body string) (*config.Policy, []config.Override, int64) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	client, err := transport.New(srv.URL, false, "test")
	if err != nil {
		t.Fatal(err)
	}
	var gotPolicy *config.Policy
	var gotOv []config.Override
	var gotVer int64
	l := New(Deps{
		Client:  client,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AgentID: "a1",
		ApplyConfigFn: func(policy *config.Policy, overrides []config.Override, version int64) error {
			gotPolicy, gotOv, gotVer = policy, overrides, version
			return nil
		},
	})
	l.pullAndApply(context.Background(), 7)
	return gotPolicy, gotOv, gotVer
}

func TestPullConfigWithOverrides(t *testing.T) {
	body := `{"version":7,"policy":{"name":"p","capture_level":"L1","capture":{"ports":[8080]}},
		"overrides":[{"id":"o1","match":{"dst_ip":"10.0.0.0/8","dst_port":8443},"capture_level":"L3","expires_at":"2026-09-02T13:00:00Z"}]}`
	policy, ovs, ver := pullWithBody(t, body)
	if policy == nil || policy.Name != "p" {
		t.Fatalf("policy 解析错误: %+v", policy)
	}
	if ver != 7 {
		t.Fatalf("version 错误: %d", ver)
	}
	if len(ovs) != 1 || ovs[0].ID != "o1" || ovs[0].Match.DstIP != "10.0.0.0/8" ||
		ovs[0].Match.DstPort != 8443 || ovs[0].CaptureLevel != config.LevelL3 {
		t.Fatalf("overrides 解析错误: %+v", ovs)
	}
}

func TestPullConfigLegacyServerNoOverridesField(t *testing.T) {
	_, ovs, _ := pullWithBody(t, `{"version":7,"policy":null}`)
	if len(ovs) != 0 {
		t.Fatalf("旧服务端无 overrides 字段应按空数组: %+v", ovs)
	}
}

func TestPullConfigMalformedOverridesNonBlocking(t *testing.T) {
	policy, ovs, _ := pullWithBody(t, `{"version":7,"policy":{"name":"p"},"overrides":{"oops":1}}`)
	if policy == nil {
		t.Fatal("overrides 解析失败不应阻断 policy 应用")
	}
	if len(ovs) != 0 {
		t.Fatalf("解析失败应按空数组: %+v", ovs)
	}
}
