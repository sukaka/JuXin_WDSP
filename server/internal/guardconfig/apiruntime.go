// apiruntime.go 阶段8 / WDSP 发布通道扩展（P0-03/04/18/21 补全）：
//   - gateway_runtime 组系统设置 → GuardConfig 运行时键（behavior_store/identity_salt 等）；
//   - api_masking_rules 表 enabled 规则 → api_mask_rules 下发（表由迁移 000040 另一分片建立）；
//   - api_policy_version 本次发布 API 防护内容版本戳（确定性哈希）。
package guardconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// GatewayRuntimeSettingsGroup 网关运行时设置组（system_settings，字符串键值；
// 缺省键不下发=网关内置默认值兜底）。组内键见 applyGatewayRuntimeSettings。
const GatewayRuntimeSettingsGroup = "gateway_runtime"

// GatewayRuntimeSettingsLoader 读取 gateway_runtime 组已配置键值（仅返回存在的键；
// app 装配时接线 settings.Service，读取失败时发布失败，不静默回退）。
type GatewayRuntimeSettingsLoader func(ctx context.Context) (map[string]string, error)

// SetGatewayRuntimeSettingsLoader 注入 gateway_runtime 组设置读取（nil 时不下发运行时键）。
func (p *Provider) SetGatewayRuntimeSettingsLoader(fn GatewayRuntimeSettingsLoader) {
	p.runtimeSettingsLoader = fn
}

// applyGatewayRuntime 读取 gateway_runtime 组设置并写入 GuardConfig；
// 读取失败或取值非法如实返回错误（中止发布），不静默回退。
func (p *Provider) applyGatewayRuntime(ctx context.Context, cfg *gatewayconfig.GuardConfig) error {
	if p.runtimeSettingsLoader == nil {
		return nil
	}
	kv, err := p.runtimeSettingsLoader(ctx)
	if err != nil {
		return fmt.Errorf("read gateway runtime settings: %w", err)
	}
	return applyGatewayRuntimeSettings(cfg, kv)
}

// redactPlaceholder 快照脱敏占位符（RedactGuardConfig 产物）。重放/发布时当前设置值
// 为占位符的键视同取不到：不写入——把 "***" 发布出去会被网关拒绝
// （如 tls_session_ticket_key 非 hex 致 Caddy /load 失败）。
const redactPlaceholder = "***"

// applyGatewayRuntimeSettings 将 gateway_runtime 组键值写入 GuardConfig（纯函数，可测）。
// 缺省键/空串值不下发（网关默认兜底）；脱敏占位符视同取不到不写入；无法识别键忽略
// （前向兼容）；取值非法（枚举外词汇/非数字/负数）如实报错，避免管理面显示与网关行为不一致。
func applyGatewayRuntimeSettings(cfg *gatewayconfig.GuardConfig, kv map[string]string) error {
	for key, raw := range kv {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue // 空串视同缺省，不下发
		}
		if v == redactPlaceholder {
			continue // 脱敏占位符视同取不到，不写入（防 *** 被发布到网关）
		}
		switch key {
		case "behavior_store":
			switch strings.ToLower(v) {
			case "memory", "valkey":
				cfg.BehaviorStore = strings.ToLower(v)
			default:
				return fmt.Errorf("gateway_runtime.behavior_store 非法取值 %q（仅支持 memory|valkey）", raw)
			}
		case "identity_salt":
			cfg.IdentitySalt = v
		case "tls_session_ticket_key":
			// TLS 会话票据密钥（HA §7.2）：32 字节 hex（64 位十六进制字符），
			// 非法取值中止发布，不静默降级（与组内其他键同一纪律）
			if len(v) != 64 {
				return fmt.Errorf("gateway_runtime.tls_session_ticket_key 需 32 字节 hex（64 位字符），当前 %d 位", len(v))
			}
			if _, err := hex.DecodeString(v); err != nil {
				return fmt.Errorf("gateway_runtime.tls_session_ticket_key 非合法 hex: %v", err)
			}
			cfg.TLSSessionTicketKey = strings.ToLower(v)
		case "behavior_store_ttl_seconds":
			n, err := parseNonNegativeInt("behavior_store_ttl_seconds", v)
			if err != nil {
				return err
			}
			cfg.BehaviorStoreTTLSeconds = n
		case "credential_ip_spread_limit":
			n, err := parseNonNegativeInt("credential_ip_spread_limit", v)
			if err != nil {
				return err
			}
			cfg.CredentialIPSpreadLimit = n
		case "credential_concurrency_limit":
			n, err := parseNonNegativeInt("credential_concurrency_limit", v)
			if err != nil {
				return err
			}
			cfg.CredentialConcurrencyLimit = n
		case "api_write_rate_per_minute":
			n, err := parseNonNegativeInt("api_write_rate_per_minute", v)
			if err != nil {
				return err
			}
			cfg.APIWriteRatePerMinute = n
		case "api_response_fail_policy":
			switch strings.ToUpper(v) {
			case "FAIL_OPEN", "FAIL_CLOSED":
				cfg.APIResponseFailPolicy = strings.ToUpper(v)
			default:
				return fmt.Errorf("gateway_runtime.api_response_fail_policy 非法取值 %q（仅支持 FAIL_OPEN|FAIL_CLOSED）", raw)
			}
		case "api_response_capture_max_bytes":
			n, err := parseNonNegativeInt("api_response_capture_max_bytes", v)
			if err != nil {
				return err
			}
			// 网关侧硬上限 16MiB；超过即拒绝，避免管理面显示与网关行为不一致
			if n > 16*1024*1024 {
				return fmt.Errorf("gateway_runtime.api_response_capture_max_bytes 超过网关硬上限 16MiB：%d", n)
			}
			cfg.APIResponseCaptureMaxBytes = n
		case "api_llm_allowed_models":
			// W10-LLM / P2-04：LLM 授权模型名单（逗号分隔）；缺省/空串不下发不判定
			models, err := parseLLMAllowedModels(v)
			if err != nil {
				return err
			}
			cfg.APILLMAllowedModels = models
		case "api_grpc_max_frame_bytes":
			// W14-GW / P2-05：gRPC 单帧声明长度上限（字节）；缺省不下发=网关 4MiB 兜底
			n, err := parseNonNegativeInt("api_grpc_max_frame_bytes", v)
			if err != nil {
				return err
			}
			// 网关侧硬上限 64MiB；超过即拒绝，避免管理面显示与网关行为不一致
			if n > 64*1024*1024 {
				return fmt.Errorf("gateway_runtime.api_grpc_max_frame_bytes 超过网关硬上限 64MiB：%d", n)
			}
			cfg.APIGRPCMaxFrameBytes = n
		case "api_grpc_allow_compression":
			// W14-GW / P2-05：gRPC 压缩帧许可；缺省/空串不下发=网关 false 兜底
			switch strings.ToLower(v) {
			case "true":
				cfg.APIGRPCAllowCompression = true
			case "false":
				cfg.APIGRPCAllowCompression = false
			default:
				return fmt.Errorf("gateway_runtime.api_grpc_allow_compression 非法取值 %q（仅支持 true|false）", raw)
			}
		default:
			// 未识别键忽略（组内新增键由后续版本消费）
		}
	}
	// W12-GW / P2-01 最小可行子集：api_file_watermark_* 键组校验后注入
	// （enabled=false/未配置返回 nil 不下发；任一键非法如实报错中止发布）
	wm, err := parseFileWatermarkSettings(kv)
	if err != nil {
		return err
	}
	if wm != nil {
		cfg.APIFileWatermark = wm
	}
	return nil
}

// parseNonNegativeInt 解析非负整数设置（非法取值如实报错）。
func parseNonNegativeInt(key, v string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("gateway_runtime.%s 非数字取值 %q", key, v)
	}
	if n < 0 {
		return 0, fmt.Errorf("gateway_runtime.%s 不允许负数取值 %q", key, v)
	}
	return n, nil
}

// api_llm_allowed_models 名单防误配护栏（条数/单项长度上限）。
const (
	maxLLMAllowedModels   = 256
	maxLLMAllowedModelLen = 128
)

// parseLLMAllowedModels 解析 LLM 授权模型名单（逗号分隔；逐项 trim、去空项、去重保序）。
// 条数/单项长度超护栏如实报错（中止发布），不静默截断——避免管理面显示与网关行为不一致。
// 全部为空项时归一为 nil（视同缺省不下发）。
func parseLLMAllowedModels(v string) ([]string, error) {
	parts := strings.Split(v, ",")
	seen := map[string]bool{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		m := strings.TrimSpace(p)
		if m == "" || seen[m] {
			continue
		}
		if len(m) > maxLLMAllowedModelLen {
			return nil, fmt.Errorf("gateway_runtime.api_llm_allowed_models 单项长度超过 %d", maxLLMAllowedModelLen)
		}
		seen[m] = true
		out = append(out, m)
		if len(out) > maxLLMAllowedModels {
			return nil, fmt.Errorf("gateway_runtime.api_llm_allowed_models 条数超过 %d", maxLLMAllowedModels)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// computeAPIPolicyVersion 计算 api_policy_version（本次发布 API 防护内容版本戳）：
// 冻结模型 + 确认参数约束 + 脱敏规则 + 值级敏感检测规则 + 角色基线 + 字段权限 + 响应结构基线
// + 已确认参数条件关系 + 文件合规规则 + gRPC 描述符集 + 防护模式/事件日志/已知端点/模型版本号
// + JWT 信任策略段（P0-03，策略内容非密钥）+ Bot 挑战策略段（P1-02，策略内容非密钥）
// + API 引擎受限例外段（P0-04，exception_id/version 与规则引用，非密钥）
// + 非密钥 gateway_runtime 行为键 的规范序列化
// sha256（map 键序由 encoding/json 排序，同内容恒得同版本戳）；覆盖面对齐
// gatewayconfig/guard.go 实际下发面，供生效校验与网关回报比对「发布内容与实际生效」。
// 密钥三段（api_scan_verification、api_file_signature、tls_session_ticket_key）与
// identity_salt 盐值为秘密材料，不参与版本戳计算（版本戳会随事件回报，秘密材料的哈希
// 无需暴露；密钥轮换不视为防护内容变更）。
// 新增段与 gRPC 描述符集字段带 omitempty：未下发时序列化与既有版本逐字节一致（版本戳零变化）。
func computeAPIPolicyVersion(cfg *gatewayconfig.GuardConfig) string {
	raw, _ := json.Marshal(struct {
		Schemas             map[string]map[string]string                    `json:"api_formal_schemas"`
		Constraints         map[string][]gatewayconfig.GuardParamConstraint `json:"api_parameter_constraints"`
		MaskRules           []gatewayconfig.GuardMaskRule                   `json:"api_mask_rules"`
		SensitiveValueRules []gatewayconfig.GuardSensitiveValueRule         `json:"api_sensitive_value_rules"`
		RoleBaselines       []gatewayconfig.GuardRoleBaseline               `json:"api_role_baselines"`
		AuthzModels         []gatewayconfig.GuardAuthzObjectModel           `json:"api_authz_models,omitempty"`
		AuthzRelations      []gatewayconfig.GuardAuthzObjectRelation        `json:"api_authz_relations,omitempty"`
		AuthzRoleBaselines  []gatewayconfig.GuardAuthzRoleBaseline          `json:"api_authz_role_baselines,omitempty"`
		FieldPermissions    []gatewayconfig.GuardFieldPermission            `json:"api_field_permissions"`
		ResponseBaselines   []gatewayconfig.GuardResponseBaseline           `json:"api_response_baselines"`
		Relations           []gatewayconfig.GuardParamRelation              `json:"api_parameter_relations"`
		FileComplianceRules []gatewayconfig.GuardFileComplianceRule         `json:"api_file_compliance_rules"`
		GRPCDescriptors     []gatewayconfig.GuardGRPCDescriptor             `json:"api_grpc_descriptors,omitempty"`
		// 以下为本次补齐的已下发未进哈希段（对齐 guard.go 下发面；omitempty 保持缺省零变化）
		ProtectionMode        string                            `json:"api_protection_mode,omitempty"`
		EventsLog             string                            `json:"api_events_log,omitempty"`
		ModelVersions         map[string]string                 `json:"api_formal_model_versions,omitempty"`
		KnownEndpoints        map[string]string                 `json:"api_known_endpoints,omitempty"`
		BehaviorStore         string                            `json:"behavior_store,omitempty"`
		CredentialIPSpread    int                               `json:"credential_ip_spread_limit,omitempty"`
		CredentialConcurrency int                               `json:"credential_concurrency_limit,omitempty"`
		WriteRatePerMinute    int                               `json:"api_write_rate_per_minute,omitempty"`
		ResponseFailPolicy    string                            `json:"api_response_fail_policy,omitempty"`
		ResponseCaptureMax    int                               `json:"api_response_capture_max_bytes,omitempty"`
		LLMAllowedModels      []string                          `json:"api_llm_allowed_models,omitempty"`
		FileWatermark         *gatewayconfig.GuardFileWatermark `json:"api_file_watermark,omitempty"`
		GRPCMaxFrameBytes     int                               `json:"api_grpc_max_frame_bytes,omitempty"`
		GRPCAllowCompression  bool                              `json:"api_grpc_allow_compression,omitempty"`
		// P0-03：JWT 信任策略段（按应用；策略内容非密钥——静态 JWKS 仅公钥——纳入版本戳）
		JWTTrust map[string]*gatewayconfig.GuardJWTTrustPolicy `json:"jwt_trust,omitempty"`
		// P1-02：Bot 挑战策略段（按应用；策略内容非密钥——key_ref 仅引用名——纳入版本戳）
		BotPolicy map[string]*gatewayconfig.GuardBotPolicy `json:"bot_policy,omitempty"`
		// P0-04：API 引擎受限例外段（按应用；exception_id/version 与规则引用非密钥——纳入版本戳）
		APIExceptions map[string][]gatewayconfig.GuardAPIException `json:"api_exceptions,omitempty"`
	}{
		Schemas: cfg.APIFormalSchemas, Constraints: cfg.APIParameterConstraints,
		MaskRules: cfg.APIMaskRules, SensitiveValueRules: cfg.APISensitiveValueRules,
		RoleBaselines: cfg.APIRoleBaselines, FieldPermissions: cfg.APIFieldPermissions,
		AuthzModels: cfg.APIAuthzModels, AuthzRelations: cfg.APIAuthzRelations,
		AuthzRoleBaselines: cfg.APIAuthzRoleBaselines,
		ResponseBaselines:  cfg.APIResponseBaselines, Relations: cfg.APIParameterRelations,
		FileComplianceRules: cfg.APIFileComplianceRules, GRPCDescriptors: cfg.APIGRPCDescriptors,
		ProtectionMode: cfg.APIProtectionMode, EventsLog: cfg.APIEventsLog,
		ModelVersions: cfg.APIFormalModelVersions, KnownEndpoints: cfg.APIKnownEndpoints,
		BehaviorStore: cfg.BehaviorStore, CredentialIPSpread: cfg.CredentialIPSpreadLimit,
		CredentialConcurrency: cfg.CredentialConcurrencyLimit, WriteRatePerMinute: cfg.APIWriteRatePerMinute,
		ResponseFailPolicy: cfg.APIResponseFailPolicy, ResponseCaptureMax: cfg.APIResponseCaptureMaxBytes,
		LLMAllowedModels: cfg.APILLMAllowedModels, FileWatermark: cfg.APIFileWatermark,
		GRPCMaxFrameBytes: cfg.APIGRPCMaxFrameBytes, GRPCAllowCompression: cfg.APIGRPCAllowCompression,
		JWTTrust: cfg.JWTTrust, BotPolicy: cfg.BotPolicy,
		APIExceptions: cfg.APIExceptions,
	})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// MaskRuleLister 脱敏规则读取接口（api_masking_rules 表；包内单测可 fake 错误路径）。
type MaskRuleLister interface {
	ListEnabledMaskRules(ctx context.Context) ([]gatewayconfig.GuardMaskRule, error)
}

// MaskRuleStore api_masking_rules 读取（表由迁移 000040 另一分片建立；按冻结列名读取，
// 列：endpoint_key/field_path/data_type/algorithm/params_json）。
type MaskRuleStore struct {
	db *pgxpool.Pool
}

// NewMaskRuleStore 创建脱敏规则读取仓储。
func NewMaskRuleStore(db *pgxpool.Pool) *MaskRuleStore { return &MaskRuleStore{db: db} }

var _ MaskRuleLister = (*MaskRuleStore)(nil)

// ListEnabledMaskRules 读取 enabled 脱敏规则（按端点与字段路径稳定排序）。
func (s *MaskRuleStore) ListEnabledMaskRules(ctx context.Context) ([]gatewayconfig.GuardMaskRule, error) {
	rows, err := s.db.Query(ctx, `
SELECT endpoint_key, field_path, data_type, algorithm, COALESCE(params_json,'{}'::jsonb)
FROM api_masking_rules
WHERE enabled
ORDER BY endpoint_key, field_path`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardMaskRule{}
	for rows.Next() {
		var r gatewayconfig.GuardMaskRule
		var raw []byte
		if err := rows.Scan(&r.EndpointKey, &r.FieldPath, &r.DataType, &r.Algorithm, &raw); err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &r.Params)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetMaskRuleLister 注入脱敏规则读取（nil 时不下发 api_mask_rules 段）。
func (p *Provider) SetMaskRuleLister(l MaskRuleLister) { p.maskRules = l }

// loadAPIMaskRules 读取启用脱敏规则；未注入或查询失败（如迁移 000040 表尚未建立）
// Warn 并跳过，不阻断发布主流程（与 L7/约束段的「失败中止」纪律不同：脱敏为增量能力，
// 缺失时保持发布通道既有行为）。
func (p *Provider) loadAPIMaskRules(ctx context.Context) []gatewayconfig.GuardMaskRule {
	if p.maskRules == nil {
		return nil
	}
	rules, err := p.maskRules.ListEnabledMaskRules(ctx)
	if err != nil {
		slog.Warn("list api masking rules failed, skip api_mask_rules", "error", err)
		return nil
	}
	if len(rules) == 0 {
		return nil
	}
	return rules
}
