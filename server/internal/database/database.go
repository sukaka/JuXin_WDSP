// Package database 提供主业务数据库连接、方言处理与迁移执行器。
package database

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/config"
)

// PoolProfile 区分连接池用途，隔离前台交互读与后台批量写入/聚合，并为不同场景施加会话级超时护栏。
type PoolProfile string

const (
	// ProfileAPI 前台 HTTP 接口交互池：保障读响应稳定，防单个慢查询长期占坑。
	ProfileAPI PoolProfile = "api"
	// ProfileBackground 后台采集/聚合/巡检/留存清理池：独立连接配额，不饿死前台读。
	ProfileBackground PoolProfile = "background"
	// ProfileMigrate 迁移执行池：取消 statement_timeout，防止大表建索引中途超时中断。
	ProfileMigrate PoolProfile = "migrate"
)

// Connect 建立默认交互数据库连接池并验证连通性（向后兼容既有调用方）。
func Connect(ctx context.Context, cfg config.DBConfig) (*pgxpool.Pool, error) {
	return ConnectWithProfile(ctx, cfg, ProfileAPI)
}

// ConnectWithProfile 按指定用途画像建立数据库连接池并验证连通性。
func ConnectWithProfile(ctx context.Context, cfg config.DBConfig, profile PoolProfile) (*pgxpool.Pool, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.DialectName() != config.DBDialectPostgres {
		return nil, fmt.Errorf("database dialect %q requires its official vendor driver, which is not included in this build", cfg.DialectName())
	}
	poolCfg, err := buildPoolConfig(cfg, profile)
	if err != nil {
		return nil, err
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create pool (%s): %w", profile, err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database (%s): %w", profile, err)
	}
	return pool, nil
}

// buildPoolConfig 根据画像组装 pgxpool 配置与 PostgreSQL 会话级 RuntimeParams（纯逻辑，便于单测）。
func buildPoolConfig(cfg config.DBConfig, profile PoolProfile) (*pgxpool.Config, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	if poolCfg.ConnConfig.RuntimeParams == nil {
		poolCfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	rt := poolCfg.ConnConfig.RuntimeParams

	switch profile {
	case ProfileBackground:
		maxC := cfg.BGMaxConns
		if maxC <= 0 {
			maxC = 16
		}
		minC := cfg.BGMinConns
		if minC <= 0 {
			minC = 2
		}
		if minC > maxC {
			minC = maxC
		}
		poolCfg.MaxConns = maxC
		poolCfg.MinConns = minC
		rt["application_name"] = "jiuzhang-bg"
		if cfg.BGStatementTimeoutMs > 0 {
			rt["statement_timeout"] = strconv.Itoa(cfg.BGStatementTimeoutMs)
		}
		if cfg.LockTimeoutMs > 0 {
			lockMs := cfg.LockTimeoutMs
			if lockMs < 10000 {
				lockMs = 10000
			}
			rt["lock_timeout"] = strconv.Itoa(lockMs)
		}
		if cfg.IdleInTxTimeoutMs > 0 {
			idleMs := cfg.IdleInTxTimeoutMs
			if idleMs < 60000 {
				idleMs = 60000
			}
			rt["idle_in_transaction_session_timeout"] = strconv.Itoa(idleMs)
		}
	case ProfileMigrate:
		poolCfg.MaxConns = 4
		poolCfg.MinConns = 1
		rt["application_name"] = "jiuzhang-migrate"
		rt["statement_timeout"] = "0"
		rt["lock_timeout"] = "30000"
		rt["idle_in_transaction_session_timeout"] = "60000"
	default: // ProfileAPI
		maxC := cfg.MaxConns
		if maxC <= 0 {
			maxC = 32
		}
		minC := cfg.MinConns
		if minC <= 0 {
			minC = 4
		}
		if minC > maxC {
			minC = maxC
		}
		poolCfg.MaxConns = maxC
		poolCfg.MinConns = minC
		rt["application_name"] = "jiuzhang-api"
		if cfg.StatementTimeoutMs > 0 {
			rt["statement_timeout"] = strconv.Itoa(cfg.StatementTimeoutMs)
		}
		if cfg.LockTimeoutMs > 0 {
			rt["lock_timeout"] = strconv.Itoa(cfg.LockTimeoutMs)
		}
		if cfg.IdleInTxTimeoutMs > 0 {
			rt["idle_in_transaction_session_timeout"] = strconv.Itoa(cfg.IdleInTxTimeoutMs)
		}
	}

	poolCfg.MaxConnLifetime = time.Hour
	poolCfg.MaxConnIdleTime = 10 * time.Minute
	poolCfg.HealthCheckPeriod = 30 * time.Second
	return poolCfg, nil
}
