package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jiuzhang-waf/gateway/xdpguard"
)

func main() {
	// Tighten default file mode creation mask so the Unix socket never opens world-accessible.
	syscall.Umask(0o007)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "xdpguard error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, logOut io.Writer) error {
	fs := flag.NewFlagSet("xdpguard", flag.ContinueOnError)
	fs.SetOutput(logOut)

	socketPath := fs.String("socket", envOrDefault("XDPGUARD_SOCKET", xdpguard.DefaultSocketPath), "Unix Domain Socket path (zero TCP ports)")
	interfacesRaw := fs.String("interfaces", os.Getenv("XDPGUARD_INTERFACES"), "Optional comma-separated default physical interfaces")
	excludeRaw := fs.String("exclude-interfaces", os.Getenv("XDPGUARD_EXCLUDE_INTERFACES"), "Comma-separated management interfaces strictly excluded from XDP")
	attachMode := fs.String("attach-mode", envOrDefault("XDPGUARD_ATTACH_MODE", xdpguard.AttachModeAuto), "Default XDP attach mode: auto|native|generic")
	bpfObj := fs.String("bpf-obj", os.Getenv("XDPGUARD_BPF_OBJ"), "Optional path to pre-compiled CO-RE eBPF ELF object (.o)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}

	logger := log.New(logOut, "xdpguard: ", log.LstdFlags)

	backend, err := xdpguard.NewBackend(xdpguard.BackendOptions{
		BPFObjPath:         strings.TrimSpace(*bpfObj),
		DefaultInterfaces:  parseCSV(*interfacesRaw),
		ExcludedInterfaces: parseCSV(*excludeRaw),
		DefaultAttachMode:  strings.TrimSpace(*attachMode),
	})
	if err != nil {
		return fmt.Errorf("initialize backend: %w", err)
	}
	defer func() {
		if cerr := backend.Close(); cerr != nil {
			logger.Printf("backend close warning: %v", cerr)
		}
	}()

	srv, err := xdpguard.NewServer(strings.TrimSpace(*socketPath), backend)
	if err != nil {
		return fmt.Errorf("initialize unix server: %w", err)
	}
	if err := srv.Listen(); err != nil {
		return fmt.Errorf("listen unix socket: %w", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve()
	}()

	logger.Printf("started unix_socket=%s default_attach_mode=%s excluded_interfaces=%v",
		srv.SocketPath(), strings.TrimSpace(*attachMode), parseCSV(*excludeRaw))

	select {
	case serveErr := <-errCh:
		_ = srv.Shutdown(context.Background())
		return serveErr
	case <-ctx.Done():
		logger.Printf("shutdown signal received; detaching XDP links and removing socket")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Printf("http server shutdown warning: %v", err)
		}
		if err := backend.Close(); err != nil {
			logger.Printf("xdp detach warning: %v", err)
		}
		<-errCh
		logger.Printf("stopped cleanly (fail-open detached)")
		return nil
	}
}

func parseCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
