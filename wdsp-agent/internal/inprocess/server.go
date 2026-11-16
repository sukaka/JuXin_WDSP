package inprocess

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/apievent"
)

const (
	maxCaptureBodyBytes = 4 << 20
	maxConnections      = 64
)

type Processor interface {
	ProcessBatch(apievent.CaptureBatch) ([]apievent.Record, error)
}

type Server struct {
	path      string
	processor Processor
	log       *slog.Logger
	listener  *limitedListener
	server    *http.Server
	closeOnce sync.Once
}

func Listen(path string, mode os.FileMode, processor Processor, logger *slog.Logger) (*Server, error) {
	if path == "" || processor == nil {
		return nil, errors.New("in-process socket path and processor are required")
	}
	if mode == 0 {
		mode = 0o600
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if conn, err := net.DialTimeout("unix", path, 100*time.Millisecond); err == nil {
		_ = conn.Close()
		return nil, errors.New("in-process socket is already active")
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = listener.Close()
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	limited := &limitedListener{Listener: listener, tokens: make(chan struct{}, maxConnections), log: logger}
	s := &Server{path: path, processor: processor, log: logger, listener: limited}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/api-captures", s.handleCaptures)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	s.server = &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	return s, nil
}

func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- s.server.Serve(s.listener) }()
	select {
	case <-ctx.Done():
		_ = s.Close()
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err = s.server.Shutdown(ctx)
		_ = os.Remove(s.path)
	})
	return err
}

func (s *Server) handleCaptures(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, maxCaptureBodyBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var batch apievent.CaptureBatch
	if err := decoder.Decode(&batch); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_CAPTURE", "invalid local capture")
		return
	}
	if decoder.More() {
		writeError(w, http.StatusBadRequest, "INVALID_CAPTURE", "trailing local capture content")
		return
	}
	records, err := s.processor.ProcessBatch(batch)
	if err != nil {
		s.log.Warn("in-process capture rejected", "error", err)
		writeError(w, http.StatusBadRequest, "INVALID_CAPTURE", "local capture validation failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]int{"accepted_count": len(records)})
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": message})
}

func (s *Server) ConnectionLimitRejections() uint64 {
	return s.listener.rejected.Load()
}

type limitedListener struct {
	net.Listener
	tokens   chan struct{}
	log      *slog.Logger
	rejected atomic.Uint64
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.tokens <- struct{}{}:
			return &limitedConn{Conn: conn, tokens: l.tokens}, nil
		default:
			_ = conn.Close()
			rejected := l.rejected.Add(1)
			l.log.Warn("in-process connection limit reached; connection rejected", "limit", cap(l.tokens), "rejected_total", rejected)
		}
	}
}

type limitedConn struct {
	net.Conn
	tokens chan struct{}
	once   sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.tokens })
	return err
}
