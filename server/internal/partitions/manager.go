// Package partitions manages PostgreSQL 16 range-partitioned table lifecycles
// (pre-creating future partitions, recovering interrupted concurrent detaches via FINALIZE,
// executing non-transactional DETACH PARTITION CONCURRENTLY + DROP TABLE O(1) retention,
// and running indexed batched deletes for unpartitioned retention tables).
package partitions

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/settings"
)

const (
	// DefaultInterval is the default periodic tick interval for Start.
	DefaultInterval = time.Hour

	defaultSettingsTimeout     = 5 * time.Second
	defaultCatalogTimeout      = 10 * time.Second
	defaultDDLTimeout          = 30 * time.Second
	defaultDetachTimeout       = 60 * time.Second
	defaultCleanupBatchTimeout = 30 * time.Second

	defaultBatchSize  = 5000
	defaultMaxBatches = 20
	defaultBatchSleep = 200 * time.Millisecond

	// maxRetentionDays caps extreme retention settings (~4,100 years) so AddDate
	// neither overflows int64 seconds nor produces timestamps before PostgreSQL's 4713 BC limit.
	maxRetentionDays = 1500000
)

// DBExecutor is the narrow PostgreSQL query/exec interface needed by Manager.
// *pgxpool.Pool satisfies this interface directly.
type DBExecutor interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// IntSettingGetter reads dynamic integer retention settings.
// *settings.Service satisfies this interface directly.
type IntSettingGetter interface {
	GetInt(ctx context.Context, group, key string, def int) int
}

// RunResult summarizes one full partition + cleanup lifecycle cycle.
type RunResult struct {
	PartitionsCreated   int
	PartitionsFinalized int
	PartitionsDropped   int
	RowsCleaned         int64
}

// Manager orchestrates PostgreSQL partition pre-creation, expired partition removal,
// and batched row retention cleanup.
type Manager struct {
	db                DBExecutor
	settings          IntSettingGetter
	partitionPolicies []PartitionPolicy
	cleanupPolicies   []CleanupPolicy
	interval          time.Duration
	now               func() time.Time
	logger            *slog.Logger

	settingsTimeout     time.Duration
	catalogTimeout      time.Duration
	ddlTimeout          time.Duration
	detachTimeout       time.Duration
	cleanupBatchTimeout time.Duration
	batchSleep          time.Duration
}

// Option configures Manager behavior.
type Option func(*Manager)

// WithPartitionPolicies overrides the partition policies managed by Manager.
func WithPartitionPolicies(policies []PartitionPolicy) Option {
	return func(m *Manager) {
		cp := make([]PartitionPolicy, len(policies))
		copy(cp, policies)
		m.partitionPolicies = cp
	}
}

// WithCleanupPolicies overrides the batched cleanup policies managed by Manager.
func WithCleanupPolicies(policies []CleanupPolicy) Option {
	return func(m *Manager) {
		cp := make([]CleanupPolicy, len(policies))
		copy(cp, policies)
		m.cleanupPolicies = cp
	}
}

// WithInterval overrides the periodic loop interval used by Start.
func WithInterval(interval time.Duration) Option {
	return func(m *Manager) {
		if interval > 0 {
			m.interval = interval
		}
	}
}

// WithNowFunc overrides the wall-clock source (for deterministic testing).
func WithNowFunc(nowFn func() time.Time) Option {
	return func(m *Manager) {
		if nowFn != nil {
			m.now = nowFn
		}
	}
}

// WithBatchSleep overrides the pause between cleanup batches (0 disables sleep in tests).
func WithBatchSleep(d time.Duration) Option {
	return func(m *Manager) {
		if d >= 0 {
			m.batchSleep = d
		}
	}
}

// WithTimeouts overrides per-operation timeouts (non-positive values keep defaults).
func WithTimeouts(settingsTimeout, catalogTimeout, ddlTimeout, detachTimeout, cleanupTimeout time.Duration) Option {
	return func(m *Manager) {
		if settingsTimeout > 0 {
			m.settingsTimeout = settingsTimeout
		}
		if catalogTimeout > 0 {
			m.catalogTimeout = catalogTimeout
		}
		if ddlTimeout > 0 {
			m.ddlTimeout = ddlTimeout
		}
		if detachTimeout > 0 {
			m.detachTimeout = detachTimeout
		}
		if cleanupTimeout > 0 {
			m.cleanupBatchTimeout = cleanupTimeout
		}
	}
}

// WithLogger overrides the structured logger.
func WithLogger(logger *slog.Logger) Option {
	return func(m *Manager) {
		if logger != nil {
			m.logger = logger
		}
	}
}

// NewManager creates a Manager backed by *pgxpool.Pool and *settings.Service.
// It explicitly guards against typed-nil pointers before binding interfaces.
func NewManager(db *pgxpool.Pool, settingsSvc *settings.Service, opts ...Option) *Manager {
	var exec DBExecutor
	if db != nil {
		exec = db
	}
	var getter IntSettingGetter
	if settingsSvc != nil {
		getter = settingsSvc
	}
	return NewManagerWithDeps(exec, getter, opts...)
}

// NewManagerWithDeps creates a Manager with explicit dependencies for testing or custom wiring.
func NewManagerWithDeps(db DBExecutor, settingsSvc IntSettingGetter, opts ...Option) *Manager {
	m := &Manager{
		db:                  db,
		settings:            settingsSvc,
		partitionPolicies:   DefaultPartitionPolicies(),
		cleanupPolicies:     DefaultCleanupPolicies(),
		interval:            DefaultInterval,
		now:                 func() time.Time { return time.Now().UTC() },
		logger:              slog.Default(),
		settingsTimeout:     defaultSettingsTimeout,
		catalogTimeout:      defaultCatalogTimeout,
		ddlTimeout:          defaultDDLTimeout,
		detachTimeout:       defaultDetachTimeout,
		cleanupBatchTimeout: defaultCleanupBatchTimeout,
		batchSleep:          defaultBatchSleep,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}
	return m
}

// Start executes RunOnce immediately on startup and then ticks periodically until ctx is canceled.
func (m *Manager) Start(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := m.RunOnce(ctx); err != nil && ctx.Err() == nil {
		m.logger.Warn("partition lifecycle initial run finished with errors", "error", err)
	}

	interval := m.interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := m.RunOnce(ctx); err != nil && ctx.Err() == nil {
				m.logger.Warn("partition lifecycle periodic run finished with errors", "error", err)
			}
		}
	}
}

// RunOnce runs EnsurePartitions, DropExpiredPartitions, and CleanupExpiredRows in sequence.
func (m *Manager) RunOnce(ctx context.Context) (RunResult, error) {
	var res RunResult
	if ctx == nil {
		ctx = context.Background()
	}
	if m.db == nil {
		return res, errors.New("partition manager: database executor not configured")
	}

	var errs []error
	created, err := m.EnsurePartitions(ctx)
	res.PartitionsCreated = created
	if err != nil {
		errs = append(errs, err)
	}

	finalized, dropped, err := m.DropExpiredPartitions(ctx)
	res.PartitionsFinalized = finalized
	res.PartitionsDropped = dropped
	if err != nil {
		errs = append(errs, err)
	}

	cleaned, err := m.CleanupExpiredRows(ctx)
	res.RowsCleaned = cleaned
	if err != nil {
		errs = append(errs, err)
	}

	if res.PartitionsCreated > 0 || res.PartitionsFinalized > 0 || res.PartitionsDropped > 0 || res.RowsCleaned > 0 {
		m.logger.Info("partition lifecycle sweep completed",
			"created", res.PartitionsCreated,
			"finalized", res.PartitionsFinalized,
			"dropped", res.PartitionsDropped,
			"rows_cleaned", res.RowsCleaned,
		)
	}
	return res, errors.Join(errs...)
}

// EnsurePartitions creates missing past/current/future UTC partitions for enabled policies.
// Tables that do not exist yet or are not partitioned ('p') are skipped gracefully.
func (m *Manager) EnsurePartitions(ctx context.Context) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if m.db == nil {
		return 0, errors.New("partition manager: database executor not configured")
	}

	var totalCreated int
	var errs []error
	for _, policy := range m.partitionPolicies {
		if !policy.Enabled {
			continue
		}
		if err := policy.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		created, err := m.ensurePolicyPartitions(ctx, policy)
		totalCreated += created
		if err != nil {
			errs = append(errs, fmt.Errorf("ensure partitions for %s: %w", policy.ParentTable, err))
		}
	}
	return totalCreated, errors.Join(errs...)
}

func (m *Manager) ensurePolicyPartitions(ctx context.Context, policy PartitionPolicy) (int, error) {
	schemaName, relkind, exists, err := m.lookupTableRelkind(ctx, policy.ParentTable)
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	if relkind != "p" {
		m.logger.Debug("skipping partition ensure on non-partitioned table",
			"table", policy.ParentTable, "relkind", relkind)
		return 0, nil
	}

	children, err := m.listPartitions(ctx, schemaName, policy.ParentTable)
	if err != nil {
		return 0, err
	}

	existingByName := make(map[string]struct{}, len(children))
	existingFiniteBounds := make([]partitionBound, 0, len(children))
	for _, child := range children {
		existingByName[child.Name] = struct{}{}
		if b, parseErr := parsePartitionBound(child.BoundExpr); parseErr == nil && !b.IsDefault && b.HasLower && b.HasUpper {
			existingFiniteBounds = append(existingFiniteBounds, b)
		}
	}

	nowUTC := m.now().UTC()
	days := m.resolveRetentionDays(ctx, policy.SettingsGroup, policy.SettingsKey, policy.RetentionDays)
	cutoff := retentionCutoff(nowUTC, days)

	base := bucketStartUTC(nowUTC, policy.Granularity)
	created := 0
	var errs []error

	for offset := -policy.PastBuckets; offset <= policy.FutureBuckets; offset++ {
		start, end := bucketRangeUTC(base, policy.Granularity, offset)
		// Avoid creating a partition whose upper bound is already <= retention cutoff.
		if !end.After(cutoff) {
			continue
		}

		partName, err := partitionName(policy.ParentTable, policy.Granularity, start)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		if _, ok := existingByName[partName]; ok {
			continue
		}
		if hasMatchingBounds(existingFiniteBounds, start, end) {
			continue
		}

		ddl := buildCreatePartitionSQL(schemaName, policy.ParentTable, partName, start, end)
		ddlCtx, cancel := context.WithTimeout(ctx, m.ddlTimeout)
		_, execErr := m.db.Exec(ddlCtx, ddl)
		cancel()
		if execErr != nil {
			if isSQLState(execErr, "42P07") {
				existingByName[partName] = struct{}{}
				continue
			}
			errs = append(errs, fmt.Errorf("create partition %s.%s: %w", schemaName, partName, execErr))
			continue
		}
		existingByName[partName] = struct{}{}
		created++
	}

	return created, errors.Join(errs...)
}

// DropExpiredPartitions recovers any interrupted concurrent detaches via FINALIZE and
// detaches+drops expired non-default partitions whose upper bound is <= retention cutoff.
func (m *Manager) DropExpiredPartitions(ctx context.Context) (finalized int, dropped int, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if m.db == nil {
		return 0, 0, errors.New("partition manager: database executor not configured")
	}

	var errs []error
	for _, policy := range m.partitionPolicies {
		if !policy.Enabled {
			continue
		}
		if err := policy.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		f, d, perr := m.dropExpiredForPolicy(ctx, policy)
		finalized += f
		dropped += d
		if perr != nil {
			errs = append(errs, fmt.Errorf("drop expired partitions for %s: %w", policy.ParentTable, perr))
		}
	}
	return finalized, dropped, errors.Join(errs...)
}

func (m *Manager) dropExpiredForPolicy(ctx context.Context, policy PartitionPolicy) (finalized int, dropped int, err error) {
	schemaName, relkind, exists, err := m.lookupTableRelkind(ctx, policy.ParentTable)
	if err != nil {
		return 0, 0, err
	}
	if !exists || relkind != "p" {
		return 0, 0, nil
	}

	children, err := m.listPartitions(ctx, schemaName, policy.ParentTable)
	if err != nil {
		return 0, 0, err
	}
	if len(children) == 0 {
		return 0, 0, nil
	}

	type parsedChild struct {
		entry    partitionEntry
		bound    partitionBound
		parseErr error
	}

	parsed := make([]parsedChild, 0, len(children))
	hasDefault := false
	for _, child := range children {
		b, perr := parsePartitionBound(child.BoundExpr)
		if perr == nil && b.IsDefault {
			hasDefault = true
		}
		parsed = append(parsed, parsedChild{entry: child, bound: b, parseErr: perr})
	}

	nowUTC := m.now().UTC()
	days := m.resolveRetentionDays(ctx, policy.SettingsGroup, policy.SettingsKey, policy.RetentionDays)
	cutoff := retentionCutoff(nowUTC, days)

	var errs []error
	pendingRemains := false

	// Phase A: Recover any inhdetachpending = true partitions via FINALIZE before attempting new DETACHes.
	for _, item := range parsed {
		if !item.entry.DetachPending {
			continue
		}
		finalizeSQL := buildDetachPartitionFinalizeSQL(schemaName, policy.ParentTable, item.entry.Schema, item.entry.Name)
		fCtx, fCancel := context.WithTimeout(ctx, m.detachTimeout)
		_, ferr := m.db.Exec(fCtx, finalizeSQL)
		fCancel()
		if ferr != nil && !isSQLState(ferr, "42P01", "42704") {
			pendingRemains = true
			errs = append(errs, fmt.Errorf("finalize detach %s.%s: %w", item.entry.Schema, item.entry.Name, ferr))
			continue
		}
		finalized++

		if item.parseErr != nil {
			m.logger.Warn("finalized detach on partition with unparseable bound; skipping drop",
				"parent", policy.ParentTable, "partition", item.entry.Name, "bound", item.entry.BoundExpr, "error", item.parseErr)
			continue
		}
		if item.bound.IsDefault || !item.bound.HasUpper || item.bound.Upper.After(cutoff) {
			continue
		}

		dropSQL := buildDropPartitionSQL(item.entry.Schema, item.entry.Name)
		dCtx, dCancel := context.WithTimeout(ctx, m.ddlTimeout)
		_, derr := m.db.Exec(dCtx, dropSQL)
		dCancel()
		if derr != nil && !isSQLState(derr, "42P01", "42704") {
			errs = append(errs, fmt.Errorf("drop finalized partition %s.%s: %w", item.entry.Schema, item.entry.Name, derr))
			continue
		}
		dropped++
		m.logger.Info("dropped finalized expired partition",
			"parent", policy.ParentTable, "partition", item.entry.Name, "upper_utc", item.bound.Upper.UTC())
	}

	if pendingRemains {
		m.logger.Warn("skipping phase B partition detach because pending detach remains unresolved",
			"parent", policy.ParentTable)
		return finalized, dropped, errors.Join(errs...)
	}

	// Phase B: Detach and drop remaining expired non-default partitions.
	for _, item := range parsed {
		if item.entry.DetachPending {
			continue
		}
		if item.parseErr != nil {
			errs = append(errs, fmt.Errorf("parse bound for %s.%s (%q): %w",
				item.entry.Schema, item.entry.Name, item.entry.BoundExpr, item.parseErr))
			continue
		}
		if item.bound.IsDefault || !item.bound.HasUpper || item.bound.Upper.After(cutoff) {
			continue
		}

		detachErr := m.detachPartition(ctx, schemaName, policy.ParentTable, item.entry.Schema, item.entry.Name, hasDefault)
		if detachErr != nil {
			errs = append(errs, fmt.Errorf("detach partition %s.%s: %w", item.entry.Schema, item.entry.Name, detachErr))
			continue
		}

		dropSQL := buildDropPartitionSQL(item.entry.Schema, item.entry.Name)
		dCtx, dCancel := context.WithTimeout(ctx, m.ddlTimeout)
		_, derr := m.db.Exec(dCtx, dropSQL)
		dCancel()
		if derr != nil && !isSQLState(derr, "42P01", "42704") {
			errs = append(errs, fmt.Errorf("drop detached partition %s.%s: %w", item.entry.Schema, item.entry.Name, derr))
			continue
		}
		dropped++
		m.logger.Info("dropped expired partition",
			"parent", policy.ParentTable, "partition", item.entry.Name, "upper_utc", item.bound.Upper.UTC())
	}

	return finalized, dropped, errors.Join(errs...)
}

func (m *Manager) detachPartition(ctx context.Context, schemaName, parentTable, childSchema, childName string, hasDefault bool) error {
	if !hasDefault {
		sql := buildDetachPartitionConcurrentlySQL(schemaName, parentTable, childSchema, childName)
		dCtx, cancel := context.WithTimeout(ctx, m.detachTimeout)
		_, err := m.db.Exec(dCtx, sql)
		cancel()
		if err == nil || isSQLState(err, "42P01", "42704") {
			return nil
		}
		// Defensive fallback: if a DEFAULT partition exists or was attached concurrently (SQLSTATE 55000).
		if !isSQLState(err, "55000") || !strings.Contains(strings.ToLower(err.Error()), "default partition") {
			return err
		}
		m.logger.Warn("concurrent detach blocked by DEFAULT partition, falling back to non-concurrent DETACH",
			"parent", parentTable, "partition", childName)
	} else {
		m.logger.Warn("parent table has DEFAULT partition, using non-concurrent DETACH PARTITION",
			"parent", parentTable, "partition", childName)
	}

	sql := buildDetachPartitionSQL(schemaName, parentTable, childSchema, childName)
	dCtx, cancel := context.WithTimeout(ctx, m.detachTimeout)
	_, err := m.db.Exec(dCtx, sql)
	cancel()
	if isSQLState(err, "42P01", "42704") {
		return nil
	}
	return err
}

// CleanupExpiredRows executes bounded indexed batched deletes on enabled CleanupPolicies.
func (m *Manager) CleanupExpiredRows(ctx context.Context) (int64, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if m.db == nil {
		return 0, errors.New("partition manager: database executor not configured")
	}

	var totalDeleted int64
	var errs []error
	for _, policy := range m.cleanupPolicies {
		if !policy.Enabled {
			continue
		}
		if err := policy.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		deleted, err := m.cleanupPolicyRows(ctx, policy)
		totalDeleted += deleted
		if err != nil {
			errs = append(errs, fmt.Errorf("cleanup rows for %s: %w", policy.Table, err))
		}
	}
	return totalDeleted, errors.Join(errs...)
}

func (m *Manager) cleanupPolicyRows(ctx context.Context, policy CleanupPolicy) (int64, error) {
	schemaName, relkind, exists, err := m.lookupTableRelkind(ctx, policy.Table)
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	if relkind != "r" && relkind != "p" {
		m.logger.Debug("skipping row cleanup on unsupported relation kind",
			"table", policy.Table, "relkind", relkind)
		return 0, nil
	}

	days := m.resolveRetentionDays(ctx, policy.SettingsGroup, policy.SettingsKey, policy.RetentionDays)
	cutoff := retentionCutoff(m.now().UTC(), days)

	batchSize := policy.BatchSize
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}
	maxBatches := policy.MaxBatches
	if maxBatches <= 0 {
		maxBatches = defaultMaxBatches
	}

	deleteSQL := buildBatchedDeleteSQL(schemaName, policy.Table, policy.TimeColumn, policy.PKColumn)
	var total int64

	for batch := 0; batch < maxBatches; batch++ {
		bCtx, cancel := context.WithTimeout(ctx, m.cleanupBatchTimeout)
		tag, err := m.db.Exec(bCtx, deleteSQL, cutoff, batchSize)
		cancel()
		if err != nil {
			if isSQLState(err, "42P01") {
				return total, nil
			}
			return total, err
		}

		affected := tag.RowsAffected()
		total += affected
		if affected < int64(batchSize) {
			return total, nil
		}

		if m.batchSleep > 0 {
			select {
			case <-ctx.Done():
				return total, ctx.Err()
			case <-time.After(m.batchSleep):
			}
		} else if err := ctx.Err(); err != nil {
			return total, err
		}
	}

	m.logger.Warn("cleanup sweep reached max batch cap, remaining rows deferred",
		"table", policy.Table, "deleted", total, "max_batches", maxBatches)
	return total, nil
}

func (m *Manager) resolveRetentionDays(ctx context.Context, group, key string, fallback int) int {
	days := fallback
	if m.settings != nil && group != "" && key != "" {
		sCtx, cancel := context.WithTimeout(ctx, m.settingsTimeout)
		val := m.settings.GetInt(sCtx, group, key, fallback)
		cancel()
		if val > 0 {
			days = val
		}
	}
	if days <= 0 {
		days = fallback
	}
	if days <= 0 {
		days = 180
	}
	return days
}

func retentionCutoff(nowUTC time.Time, days int) time.Time {
	u := nowUTC.UTC()
	if days <= 0 {
		return u
	}
	if days > maxRetentionDays {
		days = maxRetentionDays
	}
	return u.AddDate(0, 0, -days)
}

func (m *Manager) lookupTableRelkind(ctx context.Context, tableName string) (schemaName string, relkind string, exists bool, err error) {
	cCtx, cancel := context.WithTimeout(ctx, m.catalogTimeout)
	defer cancel()

	const query = `
SELECT n.nspname, c.relkind::text
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = current_schema()
  AND c.relname = $1
LIMIT 1`

	err = m.db.QueryRow(cCtx, query, tableName).Scan(&schemaName, &relkind)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	return schemaName, relkind, true, nil
}

type partitionEntry struct {
	Schema        string
	Name          string
	DetachPending bool
	BoundExpr     string
}

func (m *Manager) listPartitions(ctx context.Context, schemaName, parentTable string) ([]partitionEntry, error) {
	cCtx, cancel := context.WithTimeout(ctx, m.catalogTimeout)
	defer cancel()

	const query = `
SELECT cn.nspname, c.relname, i.inhdetachpending, COALESCE(pg_get_expr(c.relpartbound, c.oid), '')
FROM pg_inherits i
JOIN pg_class c ON c.oid = i.inhrelid
JOIN pg_namespace cn ON cn.oid = c.relnamespace
JOIN pg_class p ON p.oid = i.inhparent
JOIN pg_namespace pn ON pn.oid = p.relnamespace
WHERE pn.nspname = $1
  AND p.relname = $2
  AND p.relkind = 'p'
ORDER BY c.relname`

	rows, err := m.db.Query(cCtx, query, schemaName, parentTable)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []partitionEntry
	for rows.Next() {
		var entry partitionEntry
		if err := rows.Scan(&entry.Schema, &entry.Name, &entry.DetachPending, &entry.BoundExpr); err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type partitionBound struct {
	IsDefault bool
	HasLower  bool
	Lower     time.Time
	HasUpper  bool
	Upper     time.Time
}

var rangeBoundPattern = regexp.MustCompile(`(?is)^FOR\s+VALUES\s+FROM\s+\((.+?)\)\s+TO\s+\((.+?)\)$`)

func parsePartitionBound(expr string) (partitionBound, error) {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return partitionBound{}, errors.New("empty partition bound expression")
	}
	if strings.EqualFold(trimmed, "DEFAULT") {
		return partitionBound{IsDefault: true}, nil
	}

	matches := rangeBoundPattern.FindStringSubmatch(trimmed)
	if len(matches) != 3 {
		return partitionBound{}, fmt.Errorf("unrecognized partition bound expression %q", expr)
	}

	lower, hasLower, isMin, isMaxLower, err := parseBoundEndpoint(matches[1])
	if err != nil {
		return partitionBound{}, fmt.Errorf("parse lower bound %q: %w", matches[1], err)
	}
	if isMaxLower {
		return partitionBound{}, fmt.Errorf("invalid lower bound MAXVALUE in %q", expr)
	}

	upper, hasUpper, isMinUpper, isMax, err := parseBoundEndpoint(matches[2])
	if err != nil {
		return partitionBound{}, fmt.Errorf("parse upper bound %q: %w", matches[2], err)
	}
	if isMinUpper {
		return partitionBound{}, fmt.Errorf("invalid upper bound MINVALUE in %q", expr)
	}
	_ = isMin
	_ = isMax

	return partitionBound{
		HasLower: hasLower,
		Lower:    lower,
		HasUpper: hasUpper,
		Upper:    upper,
	}, nil
}

var timestampLayoutsWithTZ = []string{
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02 15:04:05.999999999-07",
	"2006-01-02 15:04:05.999999999Z07:00",
	time.RFC3339Nano,
	time.RFC3339,
}

var timestampLayoutsNoTZ = []string{
	"2006-01-02 15:04:05.999999999",
	"2006-01-02",
}

func parseBoundEndpoint(raw string) (ts time.Time, finite bool, isMin bool, isMax bool, err error) {
	s := strings.TrimSpace(raw)
	if strings.EqualFold(s, "MINVALUE") {
		return time.Time{}, false, true, false, nil
	}
	if strings.EqualFold(s, "MAXVALUE") {
		return time.Time{}, false, false, true, nil
	}

	if strings.HasPrefix(s, "'") {
		lastQuote := strings.LastIndex(s, "'")
		if lastQuote <= 0 {
			return time.Time{}, false, false, false, fmt.Errorf("unterminated quoted bound %q", raw)
		}
		suffix := strings.TrimSpace(s[lastQuote+1:])
		if suffix != "" && !strings.HasPrefix(suffix, "::") {
			return time.Time{}, false, false, false, fmt.Errorf("unexpected trailing token %q in %q", suffix, raw)
		}
		s = strings.ReplaceAll(s[1:lastQuote], "''", "'")
	}
	s = strings.TrimSpace(s)

	for _, layout := range timestampLayoutsWithTZ {
		if parsed, perr := time.Parse(layout, s); perr == nil {
			return parsed.UTC(), true, false, false, nil
		}
	}
	for _, layout := range timestampLayoutsNoTZ {
		if parsed, perr := time.ParseInLocation(layout, s, time.UTC); perr == nil {
			return parsed.UTC(), true, false, false, nil
		}
	}
	return time.Time{}, false, false, false, fmt.Errorf("unsupported timestamp literal %q", s)
}

func bucketStartUTC(t time.Time, granularity Granularity) time.Time {
	u := t.UTC()
	switch granularity {
	case GranularityDaily:
		return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
	default: // GranularityMonthly
		return time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
}

func bucketRangeUTC(base time.Time, granularity Granularity, offset int) (time.Time, time.Time) {
	switch granularity {
	case GranularityDaily:
		start := base.AddDate(0, 0, offset).UTC()
		end := start.AddDate(0, 0, 1).UTC()
		return start, end
	default: // GranularityMonthly
		start := base.AddDate(0, offset, 0).UTC()
		end := start.AddDate(0, 1, 0).UTC()
		return start, end
	}
}

func partitionName(parentTable string, granularity Granularity, start time.Time) (string, error) {
	u := start.UTC()
	var name string
	switch granularity {
	case GranularityDaily:
		name = fmt.Sprintf("%s_%s", parentTable, u.Format("2006_01_02"))
	default:
		name = fmt.Sprintf("%s_%s", parentTable, u.Format("2006_01"))
	}
	if err := validateIdentifier(name); err != nil {
		return "", fmt.Errorf("invalid partition name %q: %w", name, err)
	}
	return name, nil
}

func hasMatchingBounds(bounds []partitionBound, start, end time.Time) bool {
	for _, b := range bounds {
		if b.HasLower && b.HasUpper && b.Lower.Equal(start) && b.Upper.Equal(end) {
			return true
		}
	}
	return false
}

func buildCreatePartitionSQL(schemaName, parentTable, partName string, start, end time.Time) string {
	return fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')",
		pgx.Identifier{schemaName, partName}.Sanitize(),
		pgx.Identifier{schemaName, parentTable}.Sanitize(),
		start.UTC().Format("2006-01-02 15:04:05+00"),
		end.UTC().Format("2006-01-02 15:04:05+00"),
	)
}

func buildDetachPartitionConcurrentlySQL(schemaName, parentTable, childSchema, childName string) string {
	return fmt.Sprintf(
		"ALTER TABLE %s DETACH PARTITION %s CONCURRENTLY",
		pgx.Identifier{schemaName, parentTable}.Sanitize(),
		pgx.Identifier{childSchema, childName}.Sanitize(),
	)
}

func buildDetachPartitionFinalizeSQL(schemaName, parentTable, childSchema, childName string) string {
	return fmt.Sprintf(
		"ALTER TABLE %s DETACH PARTITION %s FINALIZE",
		pgx.Identifier{schemaName, parentTable}.Sanitize(),
		pgx.Identifier{childSchema, childName}.Sanitize(),
	)
}

func buildDetachPartitionSQL(schemaName, parentTable, childSchema, childName string) string {
	return fmt.Sprintf(
		"ALTER TABLE %s DETACH PARTITION %s",
		pgx.Identifier{schemaName, parentTable}.Sanitize(),
		pgx.Identifier{childSchema, childName}.Sanitize(),
	)
}

func buildDropPartitionSQL(childSchema, childName string) string {
	return fmt.Sprintf(
		"DROP TABLE IF EXISTS %s",
		pgx.Identifier{childSchema, childName}.Sanitize(),
	)
}

func buildBatchedDeleteSQL(schemaName, table, timeCol, pkCol string) string {
	tblIdent := pgx.Identifier{schemaName, table}.Sanitize()
	timeIdent := pgx.Identifier{timeCol}.Sanitize()
	if pkCol != "" {
		pkIdent := pgx.Identifier{pkCol}.Sanitize()
		return fmt.Sprintf(
			"DELETE FROM %s WHERE %s IN (SELECT %s FROM %s WHERE %s < $1 LIMIT $2)",
			tblIdent, pkIdent, pkIdent, tblIdent, timeIdent,
		)
	}
	return fmt.Sprintf(
		"DELETE FROM %s WHERE (tableoid, ctid) IN (SELECT tableoid, ctid FROM %s WHERE %s < $1 LIMIT $2)",
		tblIdent, tblIdent, timeIdent,
	)
}

func isSQLState(err error, codes ...string) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	for _, code := range codes {
		if pgErr.Code == code {
			return true
		}
	}
	return false
}
