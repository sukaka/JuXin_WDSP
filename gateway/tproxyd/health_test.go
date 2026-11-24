package tproxyd

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHealthEndpointAndProbe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tproxyd.json")
	writeFile(t, path, `{"enabled":true,"listen":"127.0.0.1:0","target":"127.0.0.1:15080"}`)

	stats := &Stats{}
	sup := NewSupervisor(Defaults(), nil, path, 15*time.Millisecond, stats,
		func(cfg Config, st *Stats) (ServerRunner, error) { return NewServer(cfg, st) })
	healthSrv, addr, err := sup.StartHealthServer("127.0.0.1:0")
	if err != nil {
		t.Fatalf("StartHealthServer: %v", err)
	}
	t.Cleanup(func() {
		_ = healthSrv.Close()
		sup.Close()
	})
	go sup.Run()

	waitForSup(t, "listening", func() bool {
		return sup.HealthStatus().Listening
	})

	// 1. /healthz JSON 契约校验（运行态）
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var st HealthStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatalf("decode /healthz: %v", err)
	}
	if !st.OK || !st.Enabled || !st.Listening || st.Listen == "" {
		t.Fatalf("unexpected health status: %+v", st)
	}

	// 2. ProbeHealth 返回 nil
	if err := ProbeHealth(context.Background(), addr); err != nil {
		t.Fatalf("ProbeHealth(running): %v", err)
	}

	// 3. enabled=false 进入空转：仍 HTTP 200 (ok=true)，但 enabled=false, listening=false
	writeFile(t, path, `{"enabled":false}`)
	waitForSup(t, "idle", func() bool {
		hs := sup.HealthStatus()
		return hs.OK && !hs.Enabled && !hs.Listening
	})
	if err := ProbeHealth(context.Background(), addr); err != nil {
		t.Fatalf("ProbeHealth(idle): %v", err)
	}

	// 4. Close 后 /healthz 返回 503，ProbeHealth 失败
	sup.Close()
	if err := ProbeHealth(context.Background(), addr); err == nil {
		t.Fatal("Close 后 ProbeHealth 应返回错误")
	}
}

func TestStatsSummaryIncludesAllCounters(t *testing.T) {
	st := &Stats{}
	st.ConnAccepted.Store(1)
	st.ConnRejected.Store(2)
	st.ActiveConns.Store(3)
	st.BytesToTarget.Store(4)
	st.BytesToClient.Store(5)
	st.OrigDstErrors.Store(6)
	st.DialErrors.Store(7)
	st.HeaderErrors.Store(8)
	st.AcceptErrors.Store(9)
	st.ShutdownForceCx.Store(10)
	st.ConnsProtected.Store(11)
	st.ConnsPassthrough.Store(12)
	st.ConnsUnlistedTLS.Store(13)
	st.SniffErrors.Store(14)
	st.SniffTimeouts.Store(15)
	st.RelayIdleTimeouts.Store(16)

	s := st.Summary()
	for _, want := range []string{
		"accepted=1", "rejected=2", "active=3",
		"c2t=4", "t2c=5",
		"origdst=6", "dial=7", "header=8", "accept=9",
		"force_closed=10",
		"protected=11", "passthrough=12", "unlisted_tls=13", "sniff_err=14", "sniff_timeout=15",
		"relay_idle_timeout=16",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Summary() 缺少 %q: %s", want, s)
		}
	}
}
