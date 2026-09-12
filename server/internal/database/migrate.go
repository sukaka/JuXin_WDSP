package database

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// migrationFilePattern 匹配 000001_name.up.sql / 000001_name.down.sql
var migrationFilePattern = regexp.MustCompile(`^(\d{6})_([a-z0-9_]+)\.(up|down)\.sql$`)

type migration struct {
	version int
	name    string
	upSQL   string
	downSQL string
}

// migrationAdvisoryNamespace keeps schema migration locks separate from
// application-level advisory locks. The second key is the migration version,
// so different migrations may still be applied independently.
const migrationAdvisoryNamespace int32 = 0x4a5a5741

// Migrate 执行数据库迁移。
// direction 仅支持 "up"（应用全部未执行迁移）或 "down"（回滚一个版本）。
// 迁移文件从 dir 读取，执行记录保存在 schema_migrations 表。
func Migrate(ctx context.Context, pool *pgxpool.Pool, dir, direction string) error {
	if err := ensureMigrationTable(ctx, pool); err != nil {
		return err
	}
	migrations, err := loadMigrations(dir)
	if err != nil {
		return err
	}

	switch direction {
	case "up":
		applied, err := appliedVersions(ctx, pool)
		if err != nil {
			return err
		}
		for _, m := range migrations {
			if applied[m.version] {
				continue
			}
			if err := applyOne(ctx, pool, m); err != nil {
				return fmt.Errorf("apply migration %06d_%s: %w", m.version, m.name, err)
			}
			fmt.Printf("applied migration %06d_%s\n", m.version, m.name)
		}
		return nil
	case "down":
		applied, err := appliedVersions(ctx, pool)
		if err != nil {
			return err
		}
		// 回滚最高版本
		for i := len(migrations) - 1; i >= 0; i-- {
			m := migrations[i]
			if !applied[m.version] {
				continue
			}
			if m.downSQL == "" {
				return fmt.Errorf("migration %06d_%s has no down file", m.version, m.name)
			}
			if err := rollbackOne(ctx, pool, m); err != nil {
				return fmt.Errorf("rollback migration %06d_%s: %w", m.version, m.name, err)
			}
			fmt.Printf("rolled back migration %06d_%s\n", m.version, m.name)
			return nil
		}
		fmt.Println("no migration to roll back")
		return nil
	default:
		return fmt.Errorf("unsupported migrate direction %q (use up or down)", direction)
	}
}

// MigrateStatus 返回迁移版本状态。
func MigrateStatus(ctx context.Context, pool *pgxpool.Pool, dir string) ([]string, error) {
	if err := ensureMigrationTable(ctx, pool); err != nil {
		return nil, err
	}
	migrations, err := loadMigrations(dir)
	if err != nil {
		return nil, err
	}
	applied, err := appliedVersions(ctx, pool)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range migrations {
		state := "pending"
		if applied[m.version] {
			state = "applied"
		}
		out = append(out, fmt.Sprintf("%06d_%s: %s", m.version, m.name, state))
	}
	return out, nil
}

func ensureMigrationTable(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       VARCHAR(255) NOT NULL,
    applied_at TIMESTAMPTZ  NOT NULL DEFAULT now()
)`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	return nil
}

func loadMigrations(dir string) ([]migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations dir: %w", err)
	}
	byVersion := map[int]*migration{}
	for _, e := range entries {
		match := migrationFilePattern.FindStringSubmatch(e.Name())
		if match == nil {
			continue
		}
		version, _ := strconv.Atoi(match[1])
		m := byVersion[version]
		if m == nil {
			m = &migration{version: version, name: match[2]}
			byVersion[version] = m
		}
		content, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read migration file %s: %w", e.Name(), err)
		}
		if match[3] == "up" {
			m.upSQL = string(content)
		} else {
			m.downSQL = string(content)
		}
	}
	var versions []int
	for v := range byVersion {
		versions = append(versions, v)
	}
	sort.Ints(versions)
	out := make([]migration, 0, len(versions))
	for _, v := range versions {
		m := byVersion[v]
		if m.upSQL == "" {
			return nil, fmt.Errorf("migration %06d_%s missing up file", m.version, m.name)
		}
		out = append(out, *m)
	}
	return out, nil
}

func appliedVersions(ctx context.Context, pool *pgxpool.Pool) (map[int]bool, error) {
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("query schema_migrations: %w", err)
	}
	defer rows.Close()
	out := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

func applyOne(ctx context.Context, pool *pgxpool.Pool, m migration) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Migrate() reads applied versions before opening this transaction. A
	// second control-plane instance can therefore arrive here with the same
	// stale snapshot. The transaction-scoped lock serializes that migration,
	// and the recheck below makes the losing runner a safe no-op.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, $2)`, migrationAdvisoryNamespace, m.version); err != nil {
		return fmt.Errorf("lock migration %06d: %w", m.version, err)
	}
	var alreadyApplied bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, m.version).Scan(&alreadyApplied); err != nil {
		return fmt.Errorf("recheck migration %06d: %w", m.version, err)
	}
	if alreadyApplied {
		return tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx, m.upSQL); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.version, m.name); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func rollbackOne(ctx context.Context, pool *pgxpool.Pool, m migration) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, $2)`, migrationAdvisoryNamespace, m.version); err != nil {
		return fmt.Errorf("lock migration %06d rollback: %w", m.version, err)
	}
	var stillApplied bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, m.version).Scan(&stillApplied); err != nil {
		return fmt.Errorf("recheck migration %06d rollback: %w", m.version, err)
	}
	if !stillApplied {
		return tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx, m.downSQL); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM schema_migrations WHERE version = $1`, m.version); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
