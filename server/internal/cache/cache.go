// Package cache 提供 Valkey 客户端（兼容 Redis 协议）。
package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/redis/go-redis/v9"
)

// Client 是 Valkey 客户端封装。
type Client struct {
	rdb *redis.Client
}

// New 建立 Valkey 连接并验证连通性。
func New(ctx context.Context, cfg config.CacheConfig) (*Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr(),
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("ping valkey: %w", err)
	}
	return &Client{rdb: rdb}, nil
}

// Close 关闭连接。
func (c *Client) Close() error {
	return c.rdb.Close()
}

// Redis 返回底层客户端（供各模块构造具体逻辑）。
func (c *Client) Redis() *redis.Client {
	return c.rdb
}

// Get 获取键值，不存在时返回 redis.Nil 错误。
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	return c.rdb.Get(ctx, key).Result()
}

// Set 设置键值与过期时间。
func (c *Client) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return c.rdb.Set(ctx, key, value, ttl).Err()
}

// Del 删除键。
func (c *Client) Del(ctx context.Context, keys ...string) error {
	return c.rdb.Del(ctx, keys...).Err()
}

// Incr 自增并返回新值。
func (c *Client) Incr(ctx context.Context, key string) (int64, error) {
	return c.rdb.Incr(ctx, key).Result()
}

// Expire 设置过期时间。
func (c *Client) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return c.rdb.Expire(ctx, key, ttl).Err()
}

// TTL 获取剩余过期时间。
func (c *Client) TTL(ctx context.Context, key string) (time.Duration, error) {
	return c.rdb.TTL(ctx, key).Result()
}
