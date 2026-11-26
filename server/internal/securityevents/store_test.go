package securityevents

import (
	"strings"
	"testing"
)

func TestGetByIDMatchesSQLIncludesPartitionKey(t *testing.T) {
	if !strings.Contains(getByIDMatchesSQL, "event_id = $1") || !strings.Contains(getByIDMatchesSQL, "event_occurred_at = $2") {
		t.Fatalf("getByIDMatchesSQL must filter by event_id and event_occurred_at for partition pruning: %s", getByIDMatchesSQL)
	}
}
