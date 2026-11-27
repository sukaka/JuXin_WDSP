// block_pages.go 自定义拦截页面多版本配置发布注入（迁移 000251）：
//   - block_page_bindings（启用行）JOIN block_pages / block_page_versions / applications
//     → GuardConfig.BlockPages → 网关 jiuzhang_block_page 错误处理器与 jiuzhang_guard.block_pages 段；
//   - 无任何启用绑定时返回 nil（不下发，网关保持内置 403 blockpage.html 与 429 默认行为逐字节不变）；
//   - 读取或校验失败中止发布（fail-hard，与 LoadBlockResponse 同一纪律）。
package gatewayconfig

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 自定义拦截页场景冻结词表（与 server/internal/blockpages 及 gateway/modules/jiuzhang_guard 同口径）。
const (
	BlockPageSceneDefault       = "DEFAULT"
	BlockPageSceneWAF           = "WAF"
	BlockPageSceneAccessControl = "ACCESS_CONTROL"
	BlockPageSceneRateLimit     = "RATE_LIMIT"

	maxGuardBlockPageHTMLBytes = 65536
)

var validBlockPageScenes = map[string]bool{
	BlockPageSceneDefault:       true,
	BlockPageSceneWAF:           true,
	BlockPageSceneAccessControl: true,
	BlockPageSceneRateLimit:     true,
}

// GuardBlockPageItem 单个生效拦截页的下发契约（已净化 HTML + 状态码与 JSON 覆盖）。
// json tag 为跨分片契约，不得改动。
type GuardBlockPageItem struct {
	PageID      string `json:"page_id"`
	PageName    string `json:"page_name,omitempty"`
	Version     int    `json:"version"`
	StatusCode  int    `json:"status_code,omitempty"`
	HTML        string `json:"html"`
	JSONCode    string `json:"json_code,omitempty"`
	JSONMessage string `json:"json_message,omitempty"`
}

// GuardBlockPagesConfig 网关多版本自定义拦截页配置（全局与按应用/按场景映射）。
// Global 与 Apps 内层键为场景名（DEFAULT / WAF / ACCESS_CONTROL / RATE_LIMIT）；
// Apps 外层键为应用编码（app_code，与 GuardConfig.AppRules 同口径）。
type GuardBlockPagesConfig struct {
	Global map[string]*GuardBlockPageItem            `json:"global,omitempty"`
	Apps   map[string]map[string]*GuardBlockPageItem `json:"apps,omitempty"`
}

// IsEmpty 判断是否无任何生效自定义拦截页配置。
func (c *GuardBlockPagesConfig) IsEmpty() bool {
	if c == nil {
		return true
	}
	if len(c.Global) > 0 {
		return false
	}
	for _, m := range c.Apps {
		if len(m) > 0 {
			return false
		}
	}
	return true
}

// ResolveForApp 按四级优先级为单个应用解析各场景最终生效的拦截页：
//  1. 应用 + 具体场景（app, scene）
//  2. 应用 + 通用默认（app, DEFAULT）
//  3. 全局 + 具体场景（global, scene）
//  4. 全局 + 通用默认（global, DEFAULT）
//
// 返回 nil 表示该应用在所有场景均未配置自定义拦截页。
func (c *GuardBlockPagesConfig) ResolveForApp(appCode string) map[string]*GuardBlockPageItem {
	if c.IsEmpty() {
		return nil
	}
	appMap := c.Apps[appCode]
	out := make(map[string]*GuardBlockPageItem, 4)

	resolveScene := func(scene string) *GuardBlockPageItem {
		if appMap != nil {
			if item := appMap[scene]; item != nil {
				return item
			}
			if scene != BlockPageSceneDefault {
				if item := appMap[BlockPageSceneDefault]; item != nil {
					return item
				}
			}
		}
		if c.Global != nil {
			if item := c.Global[scene]; item != nil {
				return item
			}
			if scene != BlockPageSceneDefault {
				if item := c.Global[BlockPageSceneDefault]; item != nil {
					return item
				}
			}
		}
		return nil
	}

	for _, scene := range []string{
		BlockPageSceneDefault,
		BlockPageSceneWAF,
		BlockPageSceneAccessControl,
		BlockPageSceneRateLimit,
	} {
		if item := resolveScene(scene); item != nil {
			cp := *item
			out[scene] = &cp
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// validateGuardBlockPageItem 校验单个拦截页下发项（发布侧与网关装配期同口径）。
func validateGuardBlockPageItem(scene string, item *GuardBlockPageItem) error {
	if !validBlockPageScenes[scene] {
		return fmt.Errorf("block_pages 非法场景 %q", scene)
	}
	if item == nil {
		return fmt.Errorf("block_pages.%s 不能为空", scene)
	}
	if strings.TrimSpace(item.HTML) == "" {
		return fmt.Errorf("block_pages.%s HTML 内容为空", scene)
	}
	if len(item.HTML) > maxGuardBlockPageHTMLBytes {
		return fmt.Errorf("block_pages.%s HTML 超过上限 %d 字节：%d", scene, maxGuardBlockPageHTMLBytes, len(item.HTML))
	}
	if item.StatusCode != 0 && (item.StatusCode < 400 || item.StatusCode > 599) {
		return fmt.Errorf("block_pages.%s status_code 非法：%d", scene, item.StatusCode)
	}
	if len(item.JSONCode) > maxBlockResponseJSONCode {
		return fmt.Errorf("block_pages.%s json_code 超过上限 %d 字节", scene, maxBlockResponseJSONCode)
	}
	if item.JSONCode != "" && !blockResponseCodePattern.MatchString(item.JSONCode) {
		return fmt.Errorf("block_pages.%s json_code 非法取值 %q", scene, item.JSONCode)
	}
	if len(item.JSONMessage) > maxBlockResponseJSONMsgBytes {
		return fmt.Errorf("block_pages.%s json_message 超过上限 %d 字节", scene, maxBlockResponseJSONMsgBytes)
	}
	return nil
}

// blockPageBindingRow 数据库读取行结构（便于纯函数装配单测）。
type blockPageBindingRow struct {
	AppCode     string // 空串表示全局绑定
	Scene       string
	PageID      string
	PageName    string
	Version     int
	StatusCode  int
	HTML        string
	JSONCode    string
	JSONMessage string
}

func buildGuardBlockPagesConfig(rows []blockPageBindingRow) (*GuardBlockPagesConfig, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	cfg := &GuardBlockPagesConfig{
		Global: map[string]*GuardBlockPageItem{},
		Apps:   map[string]map[string]*GuardBlockPageItem{},
	}
	for _, r := range rows {
		scene := strings.ToUpper(strings.TrimSpace(r.Scene))
		item := &GuardBlockPageItem{
			PageID:      r.PageID,
			PageName:    r.PageName,
			Version:     r.Version,
			StatusCode:  r.StatusCode,
			HTML:        r.HTML,
			JSONCode:    r.JSONCode,
			JSONMessage: r.JSONMessage,
		}
		if err := validateGuardBlockPageItem(scene, item); err != nil {
			return nil, err
		}
		if r.AppCode == "" {
			cfg.Global[scene] = item
		} else {
			if cfg.Apps[r.AppCode] == nil {
				cfg.Apps[r.AppCode] = map[string]*GuardBlockPageItem{}
			}
			cfg.Apps[r.AppCode][scene] = item
		}
	}
	if len(cfg.Global) == 0 {
		cfg.Global = nil
	}
	if len(cfg.Apps) == 0 {
		cfg.Apps = nil
	}
	if cfg.IsEmpty() {
		return nil, nil
	}
	return cfg, nil
}

// LoadBlockPages 从数据库读取全部已启用的自定义拦截页生效绑定并组装下发配置。
// 无启用绑定返回 (nil, nil)；读取或校验失败返回错误中止发布（fail-hard）。
func LoadBlockPages(ctx context.Context, db *pgxpool.Pool) (*GuardBlockPagesConfig, error) {
	rows, err := db.Query(ctx, `
SELECT
	COALESCE(a.code, '') AS app_code,
	b.scene,
	p.id::text AS page_id,
	p.name AS page_name,
	COALESCE(v.version, p.version) AS effective_version,
	COALESCE(v.status_code, p.status_code) AS status_code,
	COALESCE(v.rendered_html, p.rendered_html) AS rendered_html,
	COALESCE(v.json_code, p.json_code) AS json_code,
	COALESCE(v.json_message, p.json_message) AS json_message
FROM block_page_bindings b
JOIN block_pages p ON p.id = b.block_page_id
LEFT JOIN applications a ON a.id = b.application_id
LEFT JOIN block_page_versions v
	ON v.block_page_id = b.block_page_id
	AND v.version = COALESCE(b.pinned_version, p.version)
WHERE b.enabled = TRUE
  AND (b.application_id IS NULL OR (a.id IS NOT NULL AND a.status = 'ACTIVE'))
ORDER BY (b.application_id IS NOT NULL) ASC, COALESCE(a.code, '') ASC, b.scene ASC`)
	if err != nil {
		return nil, fmt.Errorf("read block_page_bindings: %w", err)
	}
	defer rows.Close()

	var list []blockPageBindingRow
	for rows.Next() {
		var r blockPageBindingRow
		if err := rows.Scan(
			&r.AppCode, &r.Scene, &r.PageID, &r.PageName,
			&r.Version, &r.StatusCode, &r.HTML, &r.JSONCode, &r.JSONMessage,
		); err != nil {
			return nil, fmt.Errorf("scan block_page_binding: %w", err)
		}
		list = append(list, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate block_page_bindings: %w", err)
	}
	return buildGuardBlockPagesConfig(list)
}

// buildHostToAppCode 构建站点域名到应用编码的确定性映射（供无 guard 错误链兜底按 Host 归属应用）。
func buildHostToAppCode(apps []AppData) map[string]string {
	out := map[string]string{}
	for _, app := range apps {
		if app.Code == "" {
			continue
		}
		for _, d := range app.Domains {
			h := strings.ToLower(strings.TrimSpace(d.NormalizedHostname))
			if h != "" {
				out[h] = app.Code
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
