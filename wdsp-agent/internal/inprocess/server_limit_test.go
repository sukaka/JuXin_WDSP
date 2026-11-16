package inprocess

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/apievent"
)

type syncLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type blockingProcessor struct {
	entered chan struct{}
	release chan struct{}
}

func (p *blockingProcessor) ProcessBatch(apievent.CaptureBatch) ([]apievent.Record, error) {
	select {
	case p.entered <- struct{}{}:
	default:
	}
	<-p.release
	return nil, nil
}

func TestLimitRecovery(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "api.sock")
	logs := &syncLogBuffer{}
	processor := &blockingProcessor{entered: make(chan struct{}, maxConnections), release: make(chan struct{})}
	server, err := Listen(socket, 0o600, processor, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- server.Run(ctx) }()
	var connections []net.Conn
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(processor.release) }) }
	defer func() {
		releaseAll()
		for _, conn := range connections {
			_ = conn.Close()
		}
		cancel()
		_ = server.Close()
		select {
		case err := <-runErr:
			if err != nil {
				t.Errorf("server shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down")
		}
	}()

	for i := 0; i < maxConnections; i++ {
		conn, err := net.DialTimeout("unix", socket, time.Second)
		if err != nil {
			t.Fatalf("dial connection %d: %v", i+1, err)
		}
		connections = append(connections, conn)
		writeCaptureRequest(t, conn)
	}
	waitForServerCondition(t, runErr, func() bool { return len(processor.entered) == maxConnections }, "all 64 connections to enter the processor")

	extra, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatalf("dial over-limit connection: %v", err)
	}
	connections = append(connections, extra)
	writeCaptureRequest(t, extra)
	if err := extra.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("over-limit connection should be rejected")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("over-limit connection was not rejected promptly: %v", err)
	}

	waitForServerCondition(t, runErr, func() bool { return server.ConnectionLimitRejections() == 1 }, "the rejection metric")
	waitForServerCondition(t, runErr, func() bool { return strings.Contains(logs.String(), "connection limit reached") }, "the rejection log")
	select {
	case err := <-runErr:
		t.Fatalf("connection limit must not stop HTTP Serve: %v", err)
	default:
	}

	releaseAll()
	for _, conn := range connections[:maxConnections] {
		_ = conn.Close()
	}
	waitForServerCondition(t, runErr, func() bool { return len(server.listener.tokens) == 0 }, "connection tokens to be released")

	recovered, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatalf("dial after recovery: %v", err)
	}
	connections = append(connections, recovered)
	writeCaptureRequest(t, recovered)
	if err := recovered.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(recovered), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("request after recovery: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("status after recovery = %d", response.StatusCode)
	}
	select {
	case err := <-runErr:
		t.Fatalf("server exited after accepting a recovered connection: %v", err)
	default:
	}
}

func writeCaptureRequest(t *testing.T, conn net.Conn) {
	t.Helper()
	body := `{"schema_version":1,"records":[]}`
	request := fmt.Sprintf("POST /v1/api-captures HTTP/1.1\r\nHost: unix\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := io.WriteString(conn, request)
	if err != nil {
		t.Fatalf("write capture request: %v", err)
	}
	if n != len(request) {
		t.Fatalf("short request write: %d/%d", n, len(request))
	}
}

func waitForServerCondition(t *testing.T, runErr <-chan error, condition func() bool, description string) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case err := <-runErr:
			t.Fatalf("server exited while waiting for %s: %v", description, err)
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", description)
		case <-ticker.C:
		}
	}
}
