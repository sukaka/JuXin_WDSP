package validation

import (
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestParseExportUUIDs(t *testing.T) {
	id1 := uuid.New()
	id2 := uuid.New()

	t.Run("absent returns nil", func(t *testing.T) {
		ids, err := ParseExportUUIDs(url.Values{}, "ids")
		if err != nil || ids != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", ids, err)
		}
	})

	t.Run("comma separated deduplicated preserving order", func(t *testing.T) {
		q := url.Values{"ids": {id1.String() + ", " + id2.String() + "," + id1.String()}}
		ids, err := ParseExportUUIDs(q, "ids")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ids) != 2 || ids[0] != id1 || ids[1] != id2 {
			t.Fatalf("got %v, want [%s %s]", ids, id1, id2)
		}
	})

	t.Run("repeated query keys supported", func(t *testing.T) {
		q := url.Values{"ids": {id1.String(), id2.String()}}
		ids, err := ParseExportUUIDs(q, "ids")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ids) != 2 || ids[0] != id1 || ids[1] != id2 {
			t.Fatalf("got %v, want [%s %s]", ids, id1, id2)
		}
	})

	t.Run("empty value rejected to prevent accidental full export", func(t *testing.T) {
		for _, raw := range []string{"", "   ", ",,,", " , "} {
			q := url.Values{"ids": {raw}}
			if _, err := ParseExportUUIDs(q, "ids"); err == nil {
				t.Fatalf("raw=%q: expected error, got nil", raw)
			}
		}
	})

	t.Run("invalid uuid rejected", func(t *testing.T) {
		q := url.Values{"ids": {id1.String() + ",not-a-uuid"}}
		if _, err := ParseExportUUIDs(q, "ids"); err == nil {
			t.Fatalf("expected error for invalid uuid, got nil")
		}
	})

	t.Run("exceeds max rejected", func(t *testing.T) {
		parts := make([]string, MaxExportSelectedIDs+1)
		for i := range parts {
			parts[i] = uuid.New().String()
		}
		q := url.Values{"ids": {strings.Join(parts, ",")}}
		if _, err := ParseExportUUIDs(q, "ids"); err == nil {
			t.Fatalf("expected error when count > %d, got nil", MaxExportSelectedIDs)
		}
	})

	t.Run("exact max allowed", func(t *testing.T) {
		parts := make([]string, MaxExportSelectedIDs)
		for i := range parts {
			parts[i] = uuid.New().String()
		}
		q := url.Values{"ids": {strings.Join(parts, ",")}}
		ids, err := ParseExportUUIDs(q, "ids")
		if err != nil {
			t.Fatalf("unexpected error at exact max: %v", err)
		}
		if len(ids) != MaxExportSelectedIDs {
			t.Fatalf("got %d ids, want %d", len(ids), MaxExportSelectedIDs)
		}
	})
}
