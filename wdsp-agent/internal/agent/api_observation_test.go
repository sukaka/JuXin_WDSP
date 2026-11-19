package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/apievent"
	"github.com/jiuzhang-waf/wdsp-agent/internal/buffer"
	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/tapsrc"
	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

type stubAPIObservationServer struct {
	runErr error
	called atomic.Bool
}

func (s *stubAPIObservationServer) Run(context.Context) error {
	s.called.Store(true)
	return s.runErr
}

func (s *stubAPIObservationServer) Close() error { return nil }

func TestAPIObservationServerRunErrorLogged(t *testing.T) {
	server := &stubAPIObservationServer{runErr: errors.New("listener unavailable")}
	logs := &bytes.Buffer{}
	a := &Agent{
		apiServer: server,
		apiQ:      make(chan apievent.Record),
		log:       slog.New(slog.NewTextHandler(logs, nil)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.startAPIObservation(ctx)
	a.wg.Wait()

	if !server.called.Load() {
		t.Fatal("API Observation server was not run")
	}
	if output := logs.String(); !strings.Contains(output, "API Observation 本地接收器异常退出") || !strings.Contains(output, "listener unavailable") {
		t.Fatalf("server Run error was not reported: %s", output)
	}
}

func TestAPIObservationDoesNotSpoolWhenCapabilityDisabled(t *testing.T) {
	buf, err := buffer.Open(filepath.Join(t.TempDir(), "buf"), buffer.DefaultSegmentBytes, 1<<20, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()
	a := &Agent{
		apiQ: make(chan apievent.Record, 1),
		buf:  buf,
		log:  slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	}
	rec := apievent.Record{EventID: "ev-1"}
	a.sendAPIObservationBatch([]apievent.Record{rec})
	a.enqueueAPIObservation(rec)
	if buf.Bytes() != 0 {
		t.Fatalf("observations must not be spooled when !apiV1, buffer bytes=%d", buf.Bytes())
	}
	drops := a.metrics.dropReasonsSnapshot()
	if drops[DropReasonAPIObsNotNegotiated] != 2 {
		t.Fatalf("expected 2 drops for %s, got %+v", DropReasonAPIObsNotNegotiated, drops)
	}
}

func TestFlowBatchPermanentErrorIsolatedNotSpooled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req events.FlowsRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		for _, ev := range req.Events {
			if ev.FlowID == "poison" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":{"code":"INVALID_ARGUMENT","message":"bad flow"}}`))
				return
			}
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.FlowsResponse{Accepted: len(req.Events)})
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.Server = srv.URL
	cfg.AgentID = "agent-1"
	cfg.Credential = "wda_" + strings.Repeat("a", 64)
	stateDir := t.TempDir()
	a, err := New(cfg, filepath.Join(stateDir, "agent.json"), stateDir, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.buf.Close()

	// Verify M-A3 buffer dir derived from stateDir
	if _, err := os.Stat(filepath.Join(stateDir, "buffer")); err != nil {
		t.Fatalf("expected buffer dir under stateDir: %v", err)
	}

	// Live send: 1 good + 1 poison -> good accepted, poison dropped, 0 buffered
	a.sendFlowBatch([]events.FlowEvent{{FlowID: "good-1"}, {FlowID: "poison"}})
	if a.buf.Bytes() != 0 {
		t.Fatalf("permanent flow error must not spool to buffer, got %d bytes", a.buf.Bytes())
	}
	if a.metrics.Accepted.Load() != 1 || a.metrics.dropReasonsSnapshot()[DropReasonPermanentInvalid] != 1 {
		t.Fatalf("unexpected live flow isolation metrics: accepted=%d drops=%+v", a.metrics.Accepted.Load(), a.metrics.dropReasonsSnapshot())
	}

	// Replay path: poison flow in spool does not wedge replay
	if err := a.replayFlowUnit([]events.FlowEvent{{FlowID: "good-2"}, {FlowID: "poison"}}); err != nil {
		t.Fatalf("replayFlowUnit must isolate permanent poison record and return nil, got %v", err)
	}
	if a.metrics.Accepted.Load() != 2 || a.metrics.dropReasonsSnapshot()[DropReasonPermanentInvalid] != 2 {
		t.Fatalf("unexpected replay flow isolation metrics: accepted=%d drops=%+v", a.metrics.Accepted.Load(), a.metrics.dropReasonsSnapshot())
	}
}

func TestMetricsSnapshotPreservesTapDisconnects(t *testing.T) {
	cfg := config.Default()
	cfg.Server = "http://127.0.0.1:1"
	cfg.AgentID = "agent-1"
	cfg.Credential = "wda_" + strings.Repeat("a", 64)
	stateDir := t.TempDir()
	a, err := New(cfg, filepath.Join(stateDir, "agent.json"), stateDir, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.buf.Close()
	tap, err := tapsrc.New("agent-1", tapsrc.Config{AdminAddr: "127.0.0.1:9901", SourceInstance: "inst", ConfigID: "cfg"}, nil, a.log)
	if err != nil {
		t.Fatal(err)
	}
	a.tap = tap
	a.tap.Stats.Disconnects.Add(3)
	a.metrics.SourceDisconnects.Add(2)
	snap := a.metricsSnapshot()
	if snap.SourceDisconnects != 5 {
		t.Fatalf("SourceDisconnects = %d, want 5 (tap 3 + control 2)", snap.SourceDisconnects)
	}
}

func TestAgentShutdownWaitsWorkersBeforeClosingBuffer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/heartbeat") {
			_ = json.NewEncoder(w).Encode(transport.HeartbeatResponse{ServerTime: time.Now().Unix(), DesiredState: "ENABLED", HeartbeatIntervalSeconds: 15})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.Server = srv.URL
	cfg.AgentID = "agent-1"
	cfg.Credential = "wda_" + strings.Repeat("a", 64)
	stateDir := t.TempDir()
	a, err := New(cfg, filepath.Join(stateDir, "agent.json"), stateDir, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent Run did not shut down cleanly")
	}
}
