package apinodes

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestEnsureNodeUpdate(t *testing.T) {
	if err := ensureNodeUpdate(pgconn.NewCommandTag("UPDATE 1")); err != nil {
		t.Fatalf("successful node update returned error: %v", err)
	}
	if err := ensureNodeUpdate(pgconn.NewCommandTag("UPDATE 0")); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("missing node update error = %v, want ErrNodeNotFound", err)
	}
}
