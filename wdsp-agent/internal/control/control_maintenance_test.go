package control

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

func TestPendingAckDoesNotBlockCertificateMaintenance(t *testing.T) {
	for _, failure := range []string{"ack-unavailable", "persist-failed", "recovered"} {
		t.Run(failure, func(t *testing.T) {
			var attempts, pulls atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.HasSuffix(r.URL.Path, "/heartbeat"):
					_, _ = io.WriteString(w, `{"config_version":8,"heartbeat_interval_seconds":1,"desired_state":"DISABLED"}`)
				case strings.HasSuffix(r.URL.Path, "/config/ack"):
					n := attempts.Add(1)
					if failure == "ack-unavailable" || (failure == "recovered" && n == 1) {
						w.WriteHeader(http.StatusServiceUnavailable)
					} else {
						w.WriteHeader(http.StatusNoContent)
					}
				case strings.HasSuffix(r.URL.Path, "/config"):
					pulls.Add(1)
					_, _ = io.WriteString(w, `{"version":8,"policy":null}`)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()
			client, err := transport.New(srv.URL, false, "test")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			pending, applied := int64(7), int64(7)
			rotations, disabled := 0, 0
			l := New(Deps{
				Client: client, AgentID: "a1", InitialInterval: 1,
				Log:                       slog.New(slog.NewTextHandler(io.Discard, nil)),
				StatusFn:                  func() string { return "ONLINE" },
				MetricsFn:                 func() transport.Metrics { return transport.Metrics{} },
				AppliedVersionFn:          func() int64 { return applied },
				PendingConfigAckVersionFn: func() int64 { return pending },
				MarkConfigAckedFn: func(int64) error {
					if failure == "persist-failed" {
						return errors.New("test persistence failure")
					}
					pending = 0
					return nil
				},
				ApplyConfigFn: func(_ *config.Policy, _ []config.Override, version int64) error {
					if pending != 0 {
						t.Error("旧配置 ACK 未确认就拉取应用新配置")
					}
					applied, pending = version, version
					return nil
				},
				SetEnabledFn: func(enabled bool) {
					if !enabled {
						disabled++
					}
				},
				CheckRotateFn: func(context.Context) {
					rotations++
					if rotations == 2 {
						cancel()
					}
				},
			})
			l.Run(ctx)
			if rotations != 2 || disabled < 2 || attempts.Load() < 2 {
				t.Fatalf("维护被 ACK 阻塞: rotate=%d disabled=%d ack=%d", rotations, disabled, attempts.Load())
			}
			if failure == "recovered" {
				if pulls.Load() != 1 || applied != 8 || pending != 0 {
					t.Fatalf("ACK 恢复后没有正确推进: pulls=%d applied=%d pending=%d", pulls.Load(), applied, pending)
				}
			} else if pulls.Load() != 0 || applied != 7 || pending != 7 {
				t.Fatal("失败 ACK 必须保留待确认状态并阻止后续配置")
			}
		})
	}
}
