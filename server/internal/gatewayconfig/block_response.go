// block_response.go 阶段5 §5.1 自定义 429/阻断响应页面发布注入：
// system_settings block_response 组（迁移 000151 种子四键，空串 = 网关内置默认）
// → GuardConfig.BlockResponse → 网关 jiuzhang_guard block_response 段。
// 读取失败或取值非法如实返回错误（中止发布，与 gateway_runtime 组同一纪律——
// 不静默回退，避免管理面显示与网关行为不一致）；全部为空返回 nil 不下发，
// 网关渲染内置默认模板，与历史版本逐字节一致。
package gatewayconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5/pgxpool"
)

// BlockResponseSettingsGroup 自定义阻断响应设置组（system_settings）。
const BlockResponseSettingsGroup = "block_response"

// block_response 段大小硬上限（字节；与网关 jiuzhang_guard 装配期校验口径一致，
// 与 settings.settingStringMaxLen 保存期上限一致——三处同值，任一收窄需同步）。
const (
	maxBlockResponseTitleBytes   = 128
	maxBlockResponseBodyBytes    = 4096
	maxBlockResponseJSONCode     = 128
	maxBlockResponseJSONMsgBytes = 512
)

// blockResponseCodePattern JSON 错误码字符集（机器可读标识：字母数字与 _ . -）。
var blockResponseCodePattern = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)

// blockResponseFromSettings 由设置键值组装 GuardBlockResponse（纯函数，可测）。
// 未知键忽略（前向兼容）；空串视同缺省不下发；超上限/非法错误码如实报错。
// 全部为空返回 nil（未配置，网关内置默认模板）。
func blockResponseFromSettings(kv map[string]string) (*GuardBlockResponse, error) {
	br := &GuardBlockResponse{}
	configured := false
	for key, raw := range kv {
		switch key {
		case "html_title":
			if len(raw) > maxBlockResponseTitleBytes {
				return nil, fmt.Errorf("block_response.html_title 超过上限 %d 字节：%d", maxBlockResponseTitleBytes, len(raw))
			}
			br.HTMLTitle = raw
		case "html_body":
			if len(raw) > maxBlockResponseBodyBytes {
				return nil, fmt.Errorf("block_response.html_body 超过上限 %d 字节：%d", maxBlockResponseBodyBytes, len(raw))
			}
			br.HTMLBody = raw
		case "json_code":
			if len(raw) > maxBlockResponseJSONCode {
				return nil, fmt.Errorf("block_response.json_code 超过上限 %d 字节：%d", maxBlockResponseJSONCode, len(raw))
			}
			if raw != "" && !blockResponseCodePattern.MatchString(raw) {
				return nil, fmt.Errorf("block_response.json_code 非法取值 %q（仅允许字母数字与 _ . -）", raw)
			}
			br.JSONCode = raw
		case "json_message":
			if len(raw) > maxBlockResponseJSONMsgBytes {
				return nil, fmt.Errorf("block_response.json_message 超过上限 %d 字节：%d", maxBlockResponseJSONMsgBytes, len(raw))
			}
			br.JSONMessage = raw
		default:
			continue // 未识别键忽略（组内新增键由后续版本消费）
		}
		if raw != "" {
			configured = true
		}
	}
	if !configured {
		return nil, nil
	}
	return br, nil
}

// LoadBlockResponse 读取 system_settings block_response 组并组装下发配置。
// 组内无配置行或全部为空串返回 nil（不下发，网关内置默认）；
// 读取失败或取值非法如实返回错误（中止发布，不静默回退）。
func LoadBlockResponse(ctx context.Context, db *pgxpool.Pool) (*GuardBlockResponse, error) {
	rows, err := db.Query(ctx, `
SELECT setting_key, setting_value FROM system_settings WHERE setting_group = $1`,
		BlockResponseSettingsGroup)
	if err != nil {
		return nil, fmt.Errorf("read block_response settings: %w", err)
	}
	defer rows.Close()
	kv := map[string]string{}
	for rows.Next() {
		var key string
		var raw json.RawMessage
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, fmt.Errorf("scan block_response setting: %w", err)
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("block_response.%s 非字符串取值: %w", key, err)
		}
		kv[key] = s
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read block_response settings: %w", err)
	}
	return blockResponseFromSettings(kv)
}
