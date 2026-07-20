package audits

import (
	"strings"
	"testing"
	"time"
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
