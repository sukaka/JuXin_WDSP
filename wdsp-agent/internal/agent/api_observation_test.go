package agent

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jiuzhang-waf/wdsp-agent/internal/apievent"
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
