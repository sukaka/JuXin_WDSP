package netconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store 是 PostgreSQL 期望配置仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// Get 读取节点期望配置；无记录时 found=false（不视为错误）。
func (s *Store) Get(ctx context.Context, nodeName string) (Config, time.Time, bool, error) {
	var raw []byte
	var updatedAt time.Time
	err := s.db.QueryRow(ctx, `
SELECT config, updated_at FROM node_network_configs WHERE node_name = $1`, nodeName).Scan(&raw, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Config{}, time.Time{}, false, nil
	}
	if err != nil {
		return Config{}, time.Time{}, false, err
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, time.Time{}, false, fmt.Errorf("解析节点网络配置失败: %w", err)
	}
	cfg.normalize()
	return cfg, updatedAt, true, nil
}

// Save 整体替换节点期望配置（UPSERT；updated_at 由库刷新）。
func (s *Store) Save(ctx context.Context, nodeName string, cfg Config) error {
	cfg.normalize()
	raw, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("序列化节点网络配置失败: %w", err)
	}
	if _, err := s.db.Exec(ctx, `
INSERT INTO node_network_configs (node_name, config) VALUES ($1, $2)
ON CONFLICT (node_name) DO UPDATE SET config = EXCLUDED.config, updated_at = now()`,
		nodeName, raw); err != nil {
		return fmt.Errorf("保存节点网络配置失败: %w", err)
	}
	return nil
}
