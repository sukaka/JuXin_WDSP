package audits

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMaskSensitiveJSON(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		forbidden []string
		want      string
	}{
		{
			name:      "password masked",
			input:     `{"username":"admin","password":"secret123"}`,
			forbidden: []string{"secret123"},
			want:      `"password":"********"`,
		},
		{
			name:      "nested sensitive",
			input:     `{"user":{"password_hash":"abc","token":"xyz"}}`,
			forbidden: []string{"abc", "xyz"},
		},
		{
			name:      "array nested",
			input:     `{"items":[{"session_id":"sid1"},{"name":"ok"}]}`,
			forbidden: []string{"sid1"},
		},
		{
			name:      "invalid json not passed through",
			input:     `not a json {"password":"x"}`,
			forbidden: []string{"x", "password"},
			want:      "(unstructured, masked)",
		},
		{
			name:  "empty",
			input: "",
			want:  "",
		},
		{
			name:      "private key masked",
			input:     `{"private_key":"-----BEGIN"} `,
			forbidden: []string{"BEGIN"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := MaskSensitiveJSON(c.input)
			for _, f := range c.forbidden {
				if strings.Contains(got, f) {
					t.Errorf("MaskSensitiveJSON leaks %q in %q", f, got)
				}
			}
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Errorf("MaskSensitiveJSON = %q, want containing %q", got, c.want)
			}
		})
	}
}

func TestComputeHashDeterministic(t *testing.T) {
	ts := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	h1 := computeHash(ts, "admin", "users", "create", "user", "id1", "SUCCESS", "req1", "prev0")
	h2 := computeHash(ts, "admin", "users", "create", "user", "id1", "SUCCESS", "req1", "prev0")
	if h1 != h2 {
		t.Error("computeHash not deterministic")
	}
	h3 := computeHash(ts, "admin", "users", "create", "user", "id1", "SUCCESS", "req1", "prev1")
	if h1 == h3 {
		t.Error("computeHash ignores previous_hash")
	}
	if len(h1) != 64 {
		t.Errorf("hash length = %d, want 64 (sha256 hex)", len(h1))
	}
}

// TestRecordFailureLogsWarn 持久化失败时：错误原样返回，并记录 Warn 日志；
// 日志带操作类型/actor/错误，不得泄露摘要中的敏感 payload 细节。
func TestRecordFailureLogsWarn(t *testing.T) {
	// 惰性连接池指向不可用端口：Begin 必然立即失败，无需真实数据库。
	pool, err := pgxpool.New(context.Background(), "postgres://127.0.0.1:1/audits_test?connect_timeout=2")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()
	s := NewService(pool)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	in := RecordInput{
		Username:      "admin",
		Module:        "users",
		Action:        "update",
		Result:        ResultSuccess,
		RequestID:     "req-warn",
		BeforeSummary: `{"password":"super-secret"}`,
	}
	recErr := s.Record(context.Background(), in)
	if recErr == nil {
		t.Fatal("Record 应返回持久化错误")
	}
	out := buf.String()
	if !strings.Contains(out, "audit record persist failed") {
		t.Errorf("缺少 Warn 日志: %q", out)
	}
	if !strings.Contains(out, "users") || !strings.Contains(out, "admin") {
		t.Errorf("日志缺少操作类型/actor: %q", out)
	}
	if strings.Contains(out, "super-secret") || strings.Contains(out, "password") {
		t.Errorf("日志泄露敏感 payload 细节: %q", out)
	}
}
