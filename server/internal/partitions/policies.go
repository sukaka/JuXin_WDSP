package partitions

import (
	"fmt"
	"regexp"
)

// Granularity defines the partitioning bucket size for range-partitioned tables.
type Granularity string

const (
	GranularityDaily   Granularity = "daily"
	GranularityMonthly Granularity = "monthly"
)

const maxPGIdentifierBytes = 63

var validIdentifierPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// PartitionPolicy declares lifecycle management rules for a RANGE-partitioned table.
type PartitionPolicy struct {
	ParentTable   string      // Parent partitioned table name (e.g. "security_events")
	TimeColumn    string      // Partition key timestamp column (e.g. "occurred_at")
	Granularity   Granularity // GranularityDaily | GranularityMonthly
	RetentionDays int         // Fallback retention days (> 0); e.g. 180 for security/access_control events
	SettingsGroup string      // Optional system_settings group (e.g. "logging")
	SettingsKey   string      // Optional system_settings key (e.g. "retention_days")
	PastBuckets   int         // Past buckets to ensure exist (e.g. 2 for monthly -> M-2..M)
	FutureBuckets int         // Future buckets to pre-create (e.g. 3 for monthly -> M+1..M+3)
	Enabled       bool
}

// CleanupPolicy declares indexed batched retention cleanup rules for unpartitioned tables.
type CleanupPolicy struct {
	Table         string // Target table name (e.g. "upstream_health_records")
	TimeColumn    string // Indexed timestamp column
	PKColumn      string // Optional single-column PK ("id"); empty uses PostgreSQL "ctid"
	RetentionDays int    // Default retention days (> 0)
	SettingsGroup string // Optional system_settings group
	SettingsKey   string // Optional system_settings key
	BatchSize     int    // Rows per batch (default 5000)
	MaxBatches    int    // Max batches per sweep (default 20)
	Enabled       bool
}

// Validate checks that the PartitionPolicy contains valid identifiers and bounds.
func (p PartitionPolicy) Validate() error {
	if err := validateIdentifier(p.ParentTable); err != nil {
		return fmt.Errorf("invalid parent table %q: %w", p.ParentTable, err)
	}
	if err := validateIdentifier(p.TimeColumn); err != nil {
		return fmt.Errorf("invalid time column %q: %w", p.TimeColumn, err)
	}
	switch p.Granularity {
	case GranularityDaily, GranularityMonthly:
	default:
		return fmt.Errorf("invalid granularity %q for %s", p.Granularity, p.ParentTable)
	}
	if p.RetentionDays <= 0 {
		return fmt.Errorf("retention days must be > 0 for %s (got %d)", p.ParentTable, p.RetentionDays)
	}
	if p.PastBuckets < 0 {
		return fmt.Errorf("past buckets must be >= 0 for %s (got %d)", p.ParentTable, p.PastBuckets)
	}
	if p.FutureBuckets < 0 {
		return fmt.Errorf("future buckets must be >= 0 for %s (got %d)", p.ParentTable, p.FutureBuckets)
	}
	return nil
}

// Validate checks that the CleanupPolicy contains valid identifiers and bounds.
func (p CleanupPolicy) Validate() error {
	if err := validateIdentifier(p.Table); err != nil {
		return fmt.Errorf("invalid table %q: %w", p.Table, err)
	}
	if err := validateIdentifier(p.TimeColumn); err != nil {
		return fmt.Errorf("invalid time column %q: %w", p.TimeColumn, err)
	}
	if p.PKColumn != "" {
		if err := validateIdentifier(p.PKColumn); err != nil {
			return fmt.Errorf("invalid pk column %q: %w", p.PKColumn, err)
		}
	}
	if p.RetentionDays <= 0 {
		return fmt.Errorf("retention days must be > 0 for %s (got %d)", p.Table, p.RetentionDays)
	}
	return nil
}

func validateIdentifier(name string) error {
	if name == "" {
		return fmt.Errorf("identifier is empty")
	}
	if len(name) > maxPGIdentifierBytes {
		return fmt.Errorf("identifier exceeds %d bytes (%d)", maxPGIdentifierBytes, len(name))
	}
	if !validIdentifierPattern.MatchString(name) {
		return fmt.Errorf("identifier %q contains disallowed characters", name)
	}
	return nil
}

// DefaultPartitionPolicies returns the default partition lifecycle policies (6 Monthly + 7 Daily = 13 total),
// aligned 1:1 with migrations 000243 and 000244.
func DefaultPartitionPolicies() []PartitionPolicy {
	return []PartitionPolicy{
		// --- Monthly partitions (6) ---
		{
			ParentTable:   "security_events",
			TimeColumn:    "occurred_at",
			Granularity:   GranularityMonthly,
			RetentionDays: 180,
			PastBuckets:   2,
			FutureBuckets: 3,
			Enabled:       true,
		},
		{
			ParentTable:   "access_control_events",
			TimeColumn:    "occurred_at",
			Granularity:   GranularityMonthly,
			RetentionDays: 180,
			PastBuckets:   2,
			FutureBuckets: 3,
			Enabled:       true,
		},
		{
			ParentTable:   "security_event_matches",
			TimeColumn:    "event_occurred_at",
			Granularity:   GranularityMonthly,
			RetentionDays: 180,
			PastBuckets:   2,
			FutureBuckets: 3,
			Enabled:       true,
		},
		{
			ParentTable:   "api_runtime_events",
			TimeColumn:    "occurred_at",
			Granularity:   GranularityMonthly,
			RetentionDays: 90,
			PastBuckets:   2,
			FutureBuckets: 3,
			Enabled:       true,
		},
		{
			ParentTable:   "identity_behavior_events",
			TimeColumn:    "occurred_at",
			Granularity:   GranularityMonthly,
			RetentionDays: 90,
			PastBuckets:   2,
			FutureBuckets: 3,
			Enabled:       true,
		},
		{
			ParentTable:   "coverage_observations",
			TimeColumn:    "occurred_at",
			Granularity:   GranularityMonthly,
			RetentionDays: 90,
			PastBuckets:   2,
			FutureBuckets: 3,
			Enabled:       true,
		},
		// --- Daily partitions (7) ---
		{
			ParentTable:   "access_logs",
			TimeColumn:    "occurred_at",
			Granularity:   GranularityDaily,
			RetentionDays: 7,
			SettingsGroup: "logging",
			SettingsKey:   "retention_days",
			PastBuckets:   2,
			FutureBuckets: 14,
			Enabled:       true,
		},
		{
			ParentTable:   "tls_handshake_events",
			TimeColumn:    "occurred_at",
			Granularity:   GranularityDaily,
			RetentionDays: 7,
			SettingsGroup: "logging",
			SettingsKey:   "retention_days",
			PastBuckets:   2,
			FutureBuckets: 14,
			Enabled:       true,
		},
		{
			ParentTable:   "agent_http_events",
			TimeColumn:    "ts",
			Granularity:   GranularityDaily,
			RetentionDays: 7,
			PastBuckets:   2,
			FutureBuckets: 14,
			Enabled:       true,
		},
		{
			ParentTable:   "agent_flow_events",
			TimeColumn:    "ts",
			Granularity:   GranularityDaily,
			RetentionDays: 7,
			PastBuckets:   2,
			FutureBuckets: 14,
			Enabled:       true,
		},
		{
			ParentTable:   "metric_minute_aggregates",
			TimeColumn:    "bucket_start",
			Granularity:   GranularityDaily,
			RetentionDays: 30,
			PastBuckets:   2,
			FutureBuckets: 14,
			Enabled:       true,
		},
		{
			ParentTable:   "source_ip_summaries",
			TimeColumn:    "bucket_start",
			Granularity:   GranularityDaily,
			RetentionDays: 30,
			PastBuckets:   2,
			FutureBuckets: 14,
			Enabled:       true,
		},
		{
			ParentTable:   "uri_security_summaries",
			TimeColumn:    "bucket_start",
			Granularity:   GranularityDaily,
			RetentionDays: 30,
			PastBuckets:   2,
			FutureBuckets: 14,
			Enabled:       true,
		},
	}
}

// DefaultCleanupPolicies returns the default batched cleanup policies for unpartitioned append-only tables (5 total).
// Note: operation_audits is an immutable hash-chained audit trail and must NEVER be cleaned up here.
func DefaultCleanupPolicies() []CleanupPolicy {
	return []CleanupPolicy{
		{
			Table:      "api_authz_candidate_event_receipts",
			TimeColumn: "processed_at",
			PKColumn:   "event_id",
			// candidate_sweep.go queries api_runtime_events LEFT JOIN api_authz_candidate_event_receipts
			// without a time bound on api_runtime_events. Because api_runtime_events uses monthly partitions
			// with 90d retention (oldest kept monthly partition can hold rows up to ~121d old), receipts
			// must be retained >= 120d (180d provides safe margin) so swept events are never re-processed.
			RetentionDays: 180,
			BatchSize:     5000,
			MaxBatches:    20,
			Enabled:       true,
		},
		{
			Table:         "api_schema_violations",
			TimeColumn:    "occurred_at",
			PKColumn:      "id",
			RetentionDays: 90,
			BatchSize:     5000,
			MaxBatches:    20,
			Enabled:       true,
		},
		{
			Table:         "api_authorization_decisions",
			TimeColumn:    "occurred_at",
			PKColumn:      "id",
			RetentionDays: 90,
			BatchSize:     5000,
			MaxBatches:    20,
			Enabled:       true,
		},
		{
			Table:         "behavior_statistics",
			TimeColumn:    "window_start",
			PKColumn:      "id",
			RetentionDays: 90,
			BatchSize:     5000,
			MaxBatches:    20,
			Enabled:       true,
		},
		{
			Table:         "agent_api_observation_asset_events",
			TimeColumn:    "projected_at",
			PKColumn:      "", // composite PK (agent_id, event_id, endpoint_key) -> uses (tableoid, ctid)
			RetentionDays: 30,
			BatchSize:     5000,
			MaxBatches:    20,
			Enabled:       true,
		},
	}
}
