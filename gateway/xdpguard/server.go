package xdpguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Server serves the xdpguard control plane strictly over a Unix Domain Socket (ZERO TCP port).
type Server struct {
	socketPath string
	backend    Backend
	httpServer *http.Server

	mu       sync.Mutex
	listener net.Listener
	closed   bool
}

// ValidateSocketPath validates that the Unix socket path is clean, absolute, and safe.
func ValidateSocketPath(socketPath string) error {
	if socketPath == "" {
		return errors.New("socket path is required")
	}
	if len(socketPath) > 256 {
		return fmt.Errorf("socket path too long (%d bytes, max 256)", len(socketPath))
	}
	for _, r := range socketPath {
		if r < 0x20 || r == 0x7f || r == ' ' || r == '\\' {
			return fmt.Errorf("socket path %q contains disallowed characters", socketPath)
		}
	}
	if strings.Contains(socketPath, "://") || strings.Contains(socketPath, "//") {
		return fmt.Errorf("socket path %q must be a clean filesystem path", socketPath)
	}
	if strings.HasSuffix(socketPath, "/") {
		return fmt.Errorf("socket path %q must not end with /", socketPath)
	}
	if !filepath.IsAbs(socketPath) {
		return fmt.Errorf("socket path %q must be absolute", socketPath)
	}
	cleaned := filepath.Clean(socketPath)
	if cleaned != socketPath {
		return fmt.Errorf("socket path %q must be clean (no .. or redundant separators)", socketPath)
	}
	return nil
}

// NewServer constructs a Unix-only HTTP control server backed by the given Backend.
func NewServer(socketPath string, backend Backend) (*Server, error) {
	if err := ValidateSocketPath(socketPath); err != nil {
		return nil, err
	}
	if backend == nil {
		return nil, errors.New("backend must not be nil")
	}
	s := &Server{
		socketPath: socketPath,
		backend:    backend,
	}
	s.httpServer = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return s, nil
}

// Handler returns the HTTP handler for /healthz, /v1/stats, and /v1/sync.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/v1/stats", s.handleStats)
	mux.HandleFunc("/v1/sync", s.handleSync)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz", "/v1/stats", "/v1/sync":
			mux.ServeHTTP(w, r)
		default:
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})
}

// Listen binds ONLY a Unix Domain Socket (0660), refusing symlinks and non-socket files.
func (s *Server) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return nil
	}

	parent := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return fmt.Errorf("create socket parent directory %q: %w", parent, err)
	}

	if fi, err := os.Lstat(s.socketPath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to bind Unix socket at symlink path %q", s.socketPath)
		}
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to overwrite non-socket path %q", s.socketPath)
		}
		if err := os.Remove(s.socketPath); err != nil {
			return fmt.Errorf("remove stale Unix socket %q: %w", s.socketPath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat socket path %q: %w", s.socketPath, err)
	}

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen unix %q: %w", s.socketPath, err)
	}
	if err := os.Chmod(s.socketPath, 0o660); err != nil {
		_ = ln.Close()
		_ = removeSocketIfSafe(s.socketPath)
		return fmt.Errorf("chmod 0660 unix socket %q: %w", s.socketPath, err)
	}

	s.listener = ln
	s.closed = false
	return nil
}

// Serve runs the HTTP server on the bound Unix Domain Socket until Shutdown/Close.
func (s *Server) Serve() error {
	if err := s.Listen(); err != nil {
		return err
	}
	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()

	err := s.httpServer.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown gracefully stops the Unix HTTP server and removes the socket file.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	err := s.httpServer.Shutdown(ctx)
	_ = removeSocketIfSafe(s.socketPath)
	return err
}

// SocketPath returns the configured Unix socket path.
func (s *Server) SocketPath() string {
	return s.socketPath
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	resp := s.backend.Healthz(r.Context())
	resp.AttachedInterfaces = nonNilStrings(resp.AttachedInterfaces)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	resp := s.backend.Stats(r.Context())
	resp.Interfaces = nonNilInterfaces(resp.Interfaces)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if r.ContentLength > MaxSyncBodyBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
			"error": fmt.Sprintf("request body exceeds %d byte limit", MaxSyncBodyBytes),
		})
		return
	}

	rawBody, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxSyncBodyBytes))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
				"error": fmt.Sprintf("request body exceeds %d byte limit", MaxSyncBodyBytes),
			})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("read request body: %v", err),
		})
		return
	}

	dec := json.NewDecoder(bytes.NewReader(rawBody))
	dec.DisallowUnknownFields()

	var req SyncRequest
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("invalid JSON payload: %v", err),
		})
		return
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "unexpected trailing data after JSON object",
		})
		return
	}

	resp, err := s.backend.Sync(r.Context(), req)
	if err != nil {
		var valErr *ValidationError
		if errors.As(err, &valErr) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": valErr.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	resp.AttachedInterfaces = nonNilStrings(resp.AttachedInterfaces)
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func removeSocketIfSafe(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || fi.Mode()&os.ModeSocket == 0 {
		return nil
	}
	return os.Remove(path)
}
