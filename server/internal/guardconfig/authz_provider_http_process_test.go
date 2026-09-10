package guardconfig

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// TestAuthzProviderHTTPProcess is a test-only resident process used by the
// AUTHZ-01 script. It invokes the production Provider snapshot path once,
// then exposes the resulting wire contract over HTTP until /shutdown. This
// keeps the process boundary real without adding a Provider service to the
// production API surface.
func TestAuthzProviderHTTPProcess(t *testing.T) {
	readyFile := os.Getenv("AUTHZ_PROVIDER_READY_FILE")
	contractFile := os.Getenv("AUTHZ_CONTRACT_OUTPUT")
	if readyFile == "" || contractFile == "" {
		t.Skip("AUTHZ_PROVIDER_READY_FILE and AUTHZ_CONTRACT_OUTPUT are required")
	}

	TestWriteAuthzCrossModuleContract(t)
	contract, err := os.ReadFile(contractFile)
	if err != nil {
		t.Fatalf("read Provider contract: %v", err)
	}
	legacyCompat := loadLegacyAuthzSnapshotFixture(t)

	addr := os.Getenv("AUTHZ_REAL_PROVIDER_ADDR")
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	if strings.HasPrefix(addr, "control:") {
		serveAuthzProviderControl(t, strings.TrimPrefix(addr, "control:"), readyFile, contract, legacyCompat)
		return
	}
	network := "tcp"
	listenAddr := addr
	if strings.HasPrefix(addr, "unix:") {
		network = "unix"
		listenAddr = strings.TrimPrefix(addr, "unix:")
		if listenAddr == "" {
			t.Fatalf("unix Provider endpoint has empty socket path")
		}
		_ = os.Remove(listenAddr)
		defer os.Remove(listenAddr)
	}
	listener, err := net.Listen(network, listenAddr)
	if err != nil {
		t.Fatalf("listen Provider HTTP endpoint: %v", err)
	}
	defer listener.Close()

	var shutdownOnce sync.Once
	shutdown := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("GET /v1/authz/config", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(contract)
	})
	if legacyCompat != nil {
		mux.HandleFunc("GET /v1/authz/legacy-compat", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(legacyCompat)
		})
	}
	mux.HandleFunc("POST /shutdown", func(w http.ResponseWriter, _ *http.Request) {
		shutdownOnce.Do(func() { close(shutdown) })
		w.WriteHeader(http.StatusNoContent)
	})

	server := &http.Server{Handler: mux}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()

	providerURL := "http://" + listener.Addr().String()
	if network == "unix" {
		providerURL = "http://localhost"
	}
	if err := os.WriteFile(readyFile, []byte(providerURL), 0600); err != nil {
		t.Fatalf("write Provider readiness file: %v", err)
	}

	<-shutdown
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown Provider HTTP endpoint: %v", err)
	}
	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Provider HTTP endpoint: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Provider HTTP endpoint did not stop")
	}
}

func loadLegacyAuthzSnapshotFixture(t *testing.T) []byte {
	t.Helper()
	fixturePath := os.Getenv("AUTHZ_LEGACY_SNAPSHOT_INPUT")
	if fixturePath == "" {
		return nil
	}
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read legacy authorization snapshot fixture: %v", err)
	}
	cfg, err := decodeGuardConfigSnapshot(raw)
	if err != nil {
		t.Fatalf("decode legacy authorization snapshot fixture: %v", err)
	}
	if len(cfg.APIAuthzModels) == 0 || cfg.APIAuthzPreviousValid == nil {
		t.Fatal("legacy authorization snapshot fixture must contain current and PreviousValid models")
	}
	compat, err := json.Marshal(struct {
		Models        []gatewayconfig.GuardAuthzObjectModel `json:"models"`
		PreviousValid *gatewayconfig.GuardAuthzSnapshot     `json:"previous_valid"`
	}{Models: cfg.APIAuthzModels, PreviousValid: cfg.APIAuthzPreviousValid})
	if err != nil {
		t.Fatalf("marshal normalized legacy authorization snapshot: %v", err)
	}
	return compat
}

func serveAuthzProviderControl(t *testing.T, controlDir, readyFile string, contract, legacyCompat []byte) {
	t.Helper()
	if controlDir == "" {
		t.Fatal("control Provider endpoint has empty directory")
	}
	if err := os.MkdirAll(controlDir, 0700); err != nil {
		t.Fatalf("create Provider control directory: %v", err)
	}
	requestFile := filepath.Join(controlDir, "request")
	responseFile := filepath.Join(controlDir, "response")
	_ = os.Remove(requestFile)
	_ = os.Remove(responseFile)
	if err := os.WriteFile(readyFile, []byte("control://"+controlDir), 0600); err != nil {
		t.Fatalf("write Provider readiness file: %v", err)
	}

	for {
		request, err := os.ReadFile(requestFile)
		if err != nil {
			if !os.IsNotExist(err) {
				t.Fatalf("read Provider control request: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		_ = os.Remove(requestFile)
		var response []byte
		switch strings.TrimSpace(string(request)) {
		case "GET /healthz":
			response = []byte(`{"status":"ok"}`)
		case "GET /v1/authz/config":
			response = contract
		case "GET /v1/authz/legacy-compat":
			if legacyCompat == nil {
				t.Fatalf("legacy compatibility probe requested without fixture")
			}
			response = legacyCompat
		case "POST /shutdown":
			if err := writeAuthzProviderControlResponse(responseFile, nil); err != nil {
				t.Fatalf("write Provider shutdown response: %v", err)
			}
			return
		default:
			t.Fatalf("unknown Provider control request %q", strings.TrimSpace(string(request)))
		}
		if err := writeAuthzProviderControlResponse(responseFile, response); err != nil {
			t.Fatalf("write Provider control response: %v", err)
		}
	}
}

func writeAuthzProviderControlResponse(responseFile string, response []byte) error {
	temporary := responseFile + ".tmp"
	if err := os.WriteFile(temporary, response, 0600); err != nil {
		return err
	}
	return os.Rename(temporary, responseFile)
}
