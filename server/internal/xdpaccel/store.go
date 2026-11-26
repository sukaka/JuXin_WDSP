// store.go XDP 加速配置持久化（system_settings xdp_acceleration 组）与全局黑名单/保护地址查询。
package xdpaccel

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository 抽象 XDP 配置存储与全局封禁/保护地址读取（*Store 实现，单测可注入 fake）。
type Repository interface {
	GetConfig(ctx context.Context) (*Config, error)
	SaveConfig(ctx context.Context, cfg *Config, updatedBy uuid.UUID) (*Config, error)
	LoadGlobalBlockSources(ctx context.Context) (blacklistAddrs []string, tempBlockIPs []string, protectedAddrs []string, err error)
}

// Store 是基于 PostgreSQL 的 XDP 加速仓储实现。
type Store struct {
	db *pgxpool.Pool
}

var _ Repository = (*Store)(nil)

// NewStore 创建 XDP 加速仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// GetConfig 从 system_settings 的 xdp_acceleration 分组读取当前配置；
// 缺失键使用安全默认值回退，保证 interfaces 始终为非 nil 切片。
func (s *Store) GetConfig(ctx context.Context) (*Config, error) {
	cfg := DefaultConfig()
	rows, err := s.db.Query(ctx, `
SELECT setting_key, setting_value, version, updated_at
FROM system_settings
WHERE setting_group = $1`, SettingsGroup)
	if err != nil {
		return nil, fmt.Errorf("query xdp_acceleration settings: %w", err)
	}
	defer rows.Close()

	var maxVersion int
	var latestUpdated time.Time
	for rows.Next() {
		var key string
		var raw json.RawMessage
		var version int
		var updatedAt time.Time
		if err := rows.Scan(&key, &raw, &version, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan xdp_acceleration setting: %w", err)
		}
		if version > maxVersion {
			maxVersion = version
		}
		if updatedAt.After(latestUpdated) {
			latestUpdated = updatedAt
		}
		switch key {
		case KeyEnabled:
			var b bool
			if err := json.Unmarshal(raw, &b); err == nil {
				cfg.Enabled = b
			}
		case KeySocketPath:
			var str string
			if err := json.Unmarshal(raw, &str); err == nil && strings.TrimSpace(str) != "" {
				cfg.SocketPath = strings.TrimSpace(str)
			}
		case KeyInterfaces:
			var ifaces []string
			if err := json.Unmarshal(raw, &ifaces); err == nil {
				cfg.Interfaces = nonNilStrings(ifaces)
			}
		case KeyAttachMode:
			var mode string
			if err := json.Unmarshal(raw, &mode); err == nil {
				mode = strings.ToLower(strings.TrimSpace(mode))
				if ValidAttachMode(mode) {
					cfg.AttachMode = mode
				}
			}
		case KeySyncIntervalSeconds:
			var sec int
			if err := json.Unmarshal(raw, &sec); err == nil && sec >= MinSyncIntervalSeconds && sec <= MaxSyncIntervalSeconds {
				cfg.SyncIntervalSeconds = sec
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate xdp_acceleration settings: %w", err)
	}
	NormalizeConfig(cfg)
	cfg.Version = maxVersion
	cfg.UpdatedAt = latestUpdated
	return cfg, nil
}

// SaveConfig 在单个数据库事务中原子更新 xdp_acceleration 分组全部 5 个键并返回最新配置。
func (s *Store) SaveConfig(ctx context.Context, cfg *Config, updatedBy uuid.UUID) (*Config, error) {
	if cfg == nil {
		return nil, fmt.Errorf("xdp config is nil")
	}
	NormalizeConfig(cfg)

	enabledRaw, err := json.Marshal(cfg.Enabled)
	if err != nil {
		return nil, err
	}
	socketRaw, err := json.Marshal(cfg.SocketPath)
	if err != nil {
		return nil, err
	}
	ifacesRaw, err := json.Marshal(nonNilStrings(cfg.Interfaces))
	if err != nil {
		return nil, err
	}
	modeRaw, err := json.Marshal(cfg.AttachMode)
	if err != nil {
		return nil, err
	}
	intervalRaw, err := json.Marshal(cfg.SyncIntervalSeconds)
	if err != nil {
		return nil, err
	}

	type kvRow struct {
		key       string
		valueJSON string
		valueType string
		desc      string
	}
	items := []kvRow{
		{KeyEnabled, string(enabledRaw), "boolean", "是否启用内核级 eBPF/XDP 黑名单快速丢包加速（默认关闭，缺省或无特权环境自动回退用户态）"},
		{KeySocketPath, string(socketRaw), "string", "xdpguard 守护进程 Unix Domain Socket 绝对路径（仅限 /var/run/caddy/sidecars/ 或 /run/jiuzhang/）"},
		{KeyInterfaces, string(ifacesRaw), "json", "拟挂载 XDP 的物理业务网卡名称 JSON 数组（拒绝 lo 与容器/虚拟网桥，最多 16 个）"},
		{KeyAttachMode, string(modeRaw), "string", "XDP 网卡挂载模式（auto 优先驱动级 Native 回退 Generic / native / generic）"},
		{KeySyncIntervalSeconds, string(intervalRaw), "integer", "全局 IP 黑名单与全局临时封禁同步至 XDP 的周期（秒，1-300）"},
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin xdp config tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var opID interface{}
	if updatedBy != uuid.Nil {
		opID = updatedBy
	}

	for _, item := range items {
		_, err := tx.Exec(ctx, `
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, is_sensitive, description, updated_by)
VALUES ($1, $2, $3::jsonb, $4, FALSE, $5, $6)
ON CONFLICT (setting_group, setting_key) DO UPDATE
SET setting_value = EXCLUDED.setting_value,
    updated_by    = EXCLUDED.updated_by,
    updated_at    = now(),
    version       = system_settings.version + 1`,
			SettingsGroup, item.key, item.valueJSON, item.valueType, item.desc, opID)
		if err != nil {
			return nil, fmt.Errorf("upsert xdp_acceleration:%s: %w", item.key, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit xdp config tx: %w", err)
	}
	return s.GetConfig(ctx)
}

// LoadGlobalBlockSources 读取全局生效 IP 黑名单、全局生效临时封禁与全部启用保护地址。
// 严格隔离范围：
//   - ip_access_rules 仅取 rule_type='DENY' AND scope_type='GLOBAL' AND application_id IS NULL AND status='ACTIVE'；
//   - temporary_blocks 仅取 application_id IS NULL AND status='ACTIVE' AND block_expires_at > now()，
//     绝不将应用级临时封禁下发至物理网卡内核 XDP 丢包表；
//   - protected_addresses 取全部 status='ENABLED' 记录。
func (s *Store) LoadGlobalBlockSources(ctx context.Context) ([]string, []string, []string, error) {
	blacklist, err := s.listActiveGlobalBlacklist(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	tempBlocks, err := s.listActiveGlobalTempBlocks(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	protected, err := s.listEnabledProtectedAddresses(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	return blacklist, tempBlocks, protected, nil
}

func (s *Store) listActiveGlobalBlacklist(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx, `
SELECT address
FROM ip_access_rules
WHERE rule_type = 'DENY'
  AND scope_type = 'GLOBAL'
  AND application_id IS NULL
  AND status = 'ACTIVE'
  AND deleted_at IS NULL
  AND (effective_from IS NULL OR effective_from <= now())
  AND (effective_until IS NULL OR effective_until > now())`)
	if err != nil {
		return nil, fmt.Errorf("query global ip blacklist rules: %w", err)
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var addr string
		if err := rows.Scan(&addr); err != nil {
			return nil, fmt.Errorf("scan ip blacklist address: %w", err)
		}
		if trimmed := strings.TrimSpace(addr); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out, rows.Err()
}

func (s *Store) listActiveGlobalTempBlocks(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx, `
SELECT host(client_ip)
FROM temporary_blocks
WHERE application_id IS NULL
  AND status = 'ACTIVE'
  AND block_expires_at > now()`)
	if err != nil {
		return nil, fmt.Errorf("query global temporary blocks: %w", err)
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("scan temporary block client_ip: %w", err)
		}
		if trimmed := strings.TrimSpace(ip); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out, rows.Err()
}

func (s *Store) listEnabledProtectedAddresses(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx, `
SELECT COALESCE(address, ''), COALESCE(cidr, '')
FROM protected_addresses
WHERE status = 'ENABLED'`)
	if err != nil {
		return nil, fmt.Errorf("query enabled protected addresses: %w", err)
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var addr, cidr string
		if err := rows.Scan(&addr, &cidr); err != nil {
			return nil, fmt.Errorf("scan protected address: %w", err)
		}
		if trimmed := strings.TrimSpace(addr); trimmed != "" {
			out = append(out, trimmed)
		}
		if trimmed := strings.TrimSpace(cidr); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out, rows.Err()
}
