// servers.go DNS/NTP 服务器系统设置读取与合并（docs/NETWORK_MODES_DESIGN.md §七扩展）：
// network.json 下发契约的 dns_servers/ntp_servers 可选字段来源于 system_settings
// network 组（迁移 000162 种子，管理界面经系统设置 API 维护），在保存/重写
// network.json 的路径上合并进期望配置；空设置 = 不写字段（netmgrd 继承宿主机现状）。
package netconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/jiuzhang-waf/server/internal/sysconsole"
)

// ServersReader 提供 DNS/NTP 服务器系统设置读取（*Store 直查 system_settings
// 实现；MemStore 测试实现）。读失败由调用方降级处理（记日志并忽略，不阻断
// 网络配置保存），故实现方不得把缺记录视为错误。
type ServersReader interface {
	// NetworkServers 返回解析后的 DNS/NTP 服务器列表（nil = 不下发）。
	NetworkServers(ctx context.Context) (dns, ntp []string, err error)
}

// NetworkServers 直查 system_settings network 组两键并解析逗号分隔主机列表。
// 单键缺记录/解析失败仅记 Warn 并按空处理（该键不下发），不阻断其余键与主流程
// （设置值已经 settings.validateServerList 入库校验，此处为防御性降级）。
func (s *Store) NetworkServers(ctx context.Context) (dns, ntp []string, err error) {
	rows, err := s.db.Query(ctx, `
SELECT setting_key, setting_value FROM system_settings
WHERE setting_group = 'network' AND setting_key IN ('dns_servers', 'ntp_servers')`)
	if err != nil {
		return nil, nil, fmt.Errorf("读取 network 组系统设置失败: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var raw []byte
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, nil, fmt.Errorf("读取 network 组系统设置失败: %w", err)
		}
		var str string
		if err := json.Unmarshal(raw, &str); err != nil {
			slog.Warn("parse network setting value failed", "key", key, "error", err)
			continue
		}
		list, err := sysconsole.ParseHostList(str, maxServers)
		if err != nil {
			slog.Warn("parse network server list failed", "key", key, "error", err)
			continue
		}
		switch key {
		case "dns_servers":
			dns = list
		case "ntp_servers":
			ntp = list
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("读取 network 组系统设置失败: %w", err)
	}
	return dns, ntp, nil
}
