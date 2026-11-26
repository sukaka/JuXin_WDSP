// ai_crawl.go AI 爬虫治理策略与离线迷宫 HMAC 签名密钥下发（Phase 9A-2）：
//   - ai_crawl_policies + 启用的 ai_crawler_directories → GuardConfig.AICrawlPolicy（key=应用编码）；
//   - 读取失败中止发布（fail-hard，与 jwt_trust / bot_policy 同口径）；
//   - 迷宫签名密钥存储于加密系统设置 gateway_runtime:ai_crawl_labyrinth_key（32 字节 hex），
//     随发布解密注入 GuardConfig.AICrawlLabyrinthKeyHex，快照经 RedactGuardConfig 与
//     RedactConfigSecrets 脱敏为 "***"，回滚由 replayRuntimeSecrets / reinjectConfigSecrets
//     按当前设置重放，绝不进入 api_policy_version 哈希。
package guardconfig

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

const (
	aiCrawlLabyrinthKeyGroup = GatewayRuntimeSettingsGroup // "gateway_runtime"
	aiCrawlLabyrinthKeyName  = "ai_crawl_labyrinth_key"    // 密文 32 字节 hex
	aiCrawlLabyrinthKeyBytes = 32
)

// AICrawlLister AI 爬虫治理策略读取接口（由 aicrawl.Store 实现）。
type AICrawlLister interface {
	ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardAICrawlPolicy, error)
}

// AICrawlLabyrinthKeyLoader 读取 AI 迷宫 HMAC-SHA256 签名密钥。
// createIfAbsent=false 时仅只读解密已存在密钥（绝不创建新键，供回滚重注入与非迷宫发布共用）；
// createIfAbsent=true 时若设置尚未初始化则原子生成加密密钥并落库。
type AICrawlLabyrinthKeyLoader func(ctx context.Context, createIfAbsent bool) (keyHex string, err error)

// NewAICrawlLabyrinthKeyLoader 构造 AI 迷宫 HMAC 签名密钥加载器：
// 读取 gateway_runtime:ai_crawl_labyrinth_key 并经加密服务解密为 64 位小写 hex；
// 仅当调用方传 createIfAbsent=true 且提供了 createIfAbsentFn+encrypt 时，若密钥尚未存在才原子生成加密落库。
func NewAICrawlLabyrinthKeyLoader(
	get func(ctx context.Context, group, key, def string) string,
	createIfAbsentFn func(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) (bool, error),
	encrypt func(plaintext string) (string, error),
	decrypt func(encoded string) (string, error),
) AICrawlLabyrinthKeyLoader {
	return func(ctx context.Context, createIfAbsent bool) (string, error) {
		if get == nil || decrypt == nil {
			return "", fmt.Errorf("ai crawl labyrinth key loader: settings/encryption 未装配")
		}
		if keyHex, ok, err := readDecryptLabyrinthKey(ctx, get, decrypt); err != nil {
			return "", err
		} else if ok {
			return keyHex, nil
		}
		if !createIfAbsent || createIfAbsentFn == nil || encrypt == nil {
			return "", nil
		}
		return ensureEncryptedLabyrinthKey(ctx, get, createIfAbsentFn, encrypt, decrypt, uuid.Nil)
	}
}

// NewEnsureAICrawlLabyrinthKey 构造按需确保迷宫加密密钥落库的钩子（供 aicrawl.Handler 保存策略时调用）。
func NewEnsureAICrawlLabyrinthKey(
	get func(ctx context.Context, group, key, def string) string,
	createIfAbsent func(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) (bool, error),
	encrypt func(plaintext string) (string, error),
	decrypt func(encoded string) (string, error),
) func(ctx context.Context, operatorID uuid.UUID) error {
	return func(ctx context.Context, operatorID uuid.UUID) error {
		if get == nil || createIfAbsent == nil || encrypt == nil || decrypt == nil {
			return fmt.Errorf("settings/encryption 未装配")
		}
		_, err := ensureEncryptedLabyrinthKey(ctx, get, createIfAbsent, encrypt, decrypt, operatorID)
		return err
	}
}

func readDecryptLabyrinthKey(
	ctx context.Context,
	get func(ctx context.Context, group, key, def string) string,
	decrypt func(encoded string) (string, error),
) (string, bool, error) {
	raw := strings.TrimSpace(get(ctx, aiCrawlLabyrinthKeyGroup, aiCrawlLabyrinthKeyName, ""))
	if raw == "" {
		return "", false, nil
	}
	plain, err := decrypt(raw)
	if err != nil {
		return "", false, fmt.Errorf("decrypt ai crawl labyrinth key: %w", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(plain))
	if err != nil || len(key) != aiCrawlLabyrinthKeyBytes {
		return "", false, fmt.Errorf("ai crawl labyrinth key 格式非法（须 %d 字节 hex）", aiCrawlLabyrinthKeyBytes)
	}
	return hex.EncodeToString(key), true, nil
}

func ensureEncryptedLabyrinthKey(
	ctx context.Context,
	get func(ctx context.Context, group, key, def string) string,
	createIfAbsent func(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) (bool, error),
	encrypt func(plaintext string) (string, error),
	decrypt func(encoded string) (string, error),
	operatorID uuid.UUID,
) (string, error) {
	if keyHex, ok, err := readDecryptLabyrinthKey(ctx, get, decrypt); err != nil {
		return "", err
	} else if ok {
		return keyHex, nil
	}
	buf := make([]byte, aiCrawlLabyrinthKeyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate ai crawl labyrinth key: %w", err)
	}
	generatedHex := hex.EncodeToString(buf)
	cipherText, err := encrypt(generatedHex)
	if err != nil {
		return "", fmt.Errorf("encrypt ai crawl labyrinth key: %w", err)
	}
	created, err := createIfAbsent(ctx, aiCrawlLabyrinthKeyGroup, aiCrawlLabyrinthKeyName, cipherText,
		"AI 迷宫路径 HMAC-SHA256 签名密钥（密文存储，用于签发与校验 /_wdsp/labyrinth/v1/ 路径）", operatorID)
	if err != nil {
		return "", fmt.Errorf("persist ai crawl labyrinth key: %w", err)
	}
	if created {
		return generatedHex, nil
	}
	// 并发写入失败：重读数据库赢家并解密校验
	keyHex, ok, err := readDecryptLabyrinthKey(ctx, get, decrypt)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("ai crawl labyrinth key 并发初始化后重读为空")
	}
	return keyHex, nil
}

// SetAICrawlLister 注入 AI 爬虫治理策略读取（nil 时不下发 ai_crawl_policy 段）。
func (p *Provider) SetAICrawlLister(l AICrawlLister) { p.aiCrawl = l }

// SetAICrawlLabyrinthKeyLoader 注入 AI 迷宫 HMAC 签名密钥加载器。
func (p *Provider) SetAICrawlLabyrinthKeyLoader(l AICrawlLabyrinthKeyLoader) {
	p.aiCrawlLabyrinthKey = l
}

// loadAICrawlPolicy 读取 AI 爬虫治理策略并填充 ai_crawl_policy 段（仅 WDSP 开启时调用）。
// 只要 gateway_runtime:ai_crawl_labyrinth_key 已存在即只读解密填入 cfg.AICrawlLabyrinthKeyHex
// （即使当前无策略或所有应用 labyrinth_enabled=false），以保证回滚含 labyrinth_key_hex:"***"
// 的历史整站快照时 reinjectConfigSecrets 能取到当前密钥；未启用迷宫时绝不新建密钥，
// buildGuardHandler 亦仅对 labyrinth_enabled=true 的应用下发该密钥。
// 读取失败或 PROTECT+Labyrinth 缺签名密钥均中止发布（fail-hard）。
func (p *Provider) loadAICrawlPolicy(ctx context.Context, cfg *gatewayconfig.GuardConfig) error {
	var policies map[string]*gatewayconfig.GuardAICrawlPolicy
	if p.aiCrawl != nil {
		var err error
		policies, err = p.aiCrawl.ListForGuard(ctx)
		if err != nil {
			return fmt.Errorf("list ai crawl policies: %w", err)
		}
	}
	anyLabyrinth := false
	protectLabyrinthApps := []string{}
	for code, pol := range policies {
		if pol == nil {
			continue
		}
		if pol.LabyrinthEnabled {
			anyLabyrinth = true
			if pol.Mode == "PROTECT" {
				protectLabyrinthApps = append(protectLabyrinthApps, code)
			}
		}
	}
	if p.aiCrawlLabyrinthKey != nil {
		keyHex, err := p.aiCrawlLabyrinthKey(ctx, anyLabyrinth)
		if err != nil {
			return fmt.Errorf("load ai crawl labyrinth key: %w", err)
		}
		if keyHex != "" {
			cfg.AICrawlLabyrinthKeyHex = keyHex
		}
	}
	if len(policies) == 0 {
		return nil
	}
	if len(protectLabyrinthApps) > 0 {
		sort.Strings(protectLabyrinthApps)
		if err := checkAICrawlLabyrinthKey(cfg, protectLabyrinthApps); err != nil {
			return err
		}
	}
	cfg.AICrawlPolicy = policies
	return nil
}

func checkAICrawlLabyrinthKey(cfg *gatewayconfig.GuardConfig, protectApps []string) error {
	key := ""
	if cfg != nil {
		key = strings.TrimSpace(cfg.AICrawlLabyrinthKeyHex)
	}
	if key == "" || key == redactPlaceholder {
		return fmt.Errorf(
			"应用 %v 的 AI 爬虫策略为 PROTECT 且启用了 AI 迷宫，但迷宫签名密钥（gateway_runtime.ai_crawl_labyrinth_key）未就绪，拒绝发布",
			protectApps)
	}
	return nil
}

// aiCrawlPolicyForVersionHash 返回剥除 labyrinth_key_hex 秘密字段后的策略拷贝，
// 确保 api_policy_version 哈希覆盖全部策略内容而绝不包含密钥材料。
func aiCrawlPolicyForVersionHash(in map[string]*gatewayconfig.GuardAICrawlPolicy) map[string]*gatewayconfig.GuardAICrawlPolicy {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]*gatewayconfig.GuardAICrawlPolicy, len(in))
	for code, pol := range in {
		if pol == nil {
			continue
		}
		cp := *pol
		cp.LabyrinthKeyHex = ""
		out[code] = &cp
	}
	return out
}
