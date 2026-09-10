// provider_replay_test.go GetVersionConfig 回滚重放路径单测（replayRuntimeSecrets，
// 纯函数 + fake，不依赖数据库）：
// 快照脱敏占位/旧值清零后按当前设置重放；清零清单覆盖全部运行时键（含
// tls_session_ticket_key/api_response_fail_policy/api_response_capture_max_bytes）；
// 当前设置取不到的键不写入（含值为脱敏占位符 "***" 的键）；读取/解密失败如实报错
// （回滚也是发布，fail-hard 与 BuildGuardConfig 同纪律）。
package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func TestEnsureAuthzSnapshotKeyReinjectsPreviousValidForBFLAOnlyCurrent(t *testing.T) {
	const currentKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	loads := 0
	p := &Provider{authzObjectHMACKey: func(context.Context) (string, error) {
		loads++
		return currentKey, nil
	}}
	previous := &gatewayconfig.GuardAuthzSnapshot{
		Models:           []gatewayconfig.GuardAuthzObjectModel{{ApplicationID: "app-1", EndpointKey: "GET /orders/{id}"}},
		ObjectHMACKeyHex: redactPlaceholder,
	}
	got, err := p.ensureAuthzSnapshotKey(context.Background(), "", false, previous)
	if err != nil || got != currentKey {
		t.Fatalf("previous-valid key = %q, err = %v; want current runtime key", got, err)
	}
	if loads != 1 {
		t.Fatalf("object HMAC loader calls = %d, want 1", loads)
	}
}

func TestReplayRuntimeSecretsReinjectsAuthzKeyForPreviousValidOnly(t *testing.T) {
	const currentKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	p := &Provider{authzObjectHMACKey: func(context.Context) (string, error) { return currentKey, nil }}
	cfg := &gatewayconfig.GuardConfig{
		APIAuthzPreviousValid: &gatewayconfig.GuardAuthzSnapshot{
			Models:           []gatewayconfig.GuardAuthzObjectModel{{ApplicationID: "app-1", EndpointKey: "GET /orders/{id}"}},
			ObjectHMACKeyHex: redactPlaceholder,
		},
	}
	if err := p.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.APIAuthzObjectHMACKeyHex != currentKey {
		t.Fatalf("current authz key = %q, want runtime key", cfg.APIAuthzObjectHMACKeyHex)
	}
}

// snapshotWithRuntimeSecrets 模拟反序列化后的历史快照：脱敏占位 + 已删除设置的旧值。
func snapshotWithRuntimeSecrets() *gatewayconfig.GuardConfig {
	return &gatewayconfig.GuardConfig{
		BehaviorStore:              "valkey",
		BehaviorStoreTTLSeconds:    720,
		IdentitySalt:               redactPlaceholder,
		TLSSessionTicketKey:        redactPlaceholder, // 快照脱敏占位：不清零会被发布致 Caddy /load 拒绝
		CredentialIPSpreadLimit:    5,
		CredentialConcurrencyLimit: 10,
		APIWriteRatePerMinute:      120,
		APIResponseFailPolicy:      "FAIL_CLOSED",
		APIResponseCaptureMaxBytes: 4096,
		APILLMAllowedModels:        []string{"old-model"},
		APIGRPCMaxFrameBytes:       1024,
		APIGRPCAllowCompression:    true,
		APIScanVerification:        &gatewayconfig.GuardScanVerification{KeyHex: redactPlaceholder},
		APIFileSignature:           &gatewayconfig.GuardFileSignature{Enabled: true, KID: "old-kid", KeyHex: redactPlaceholder},
	}
}

// TestReplayRuntimeSecretsSettingsDeleted 当前设置已删（loader 返回空 map）：
// 快照旧值全部清零，脱敏占位 "***" 不得残留（防占位被发布、回滚被网关拒绝）。
func TestReplayRuntimeSecretsSettingsDeleted(t *testing.T) {
	p := &Provider{
		runtimeSettingsLoader: func(ctx context.Context) (map[string]string, error) { return map[string]string{}, nil },
		scanVerification:      func(ctx context.Context) (string, error) { return "", nil },
		fileSignature:         func(ctx context.Context) (string, string, error) { return "", "", nil },
	}
	cfg := snapshotWithRuntimeSecrets()
	if err := p.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.BehaviorStore != "" || cfg.BehaviorStoreTTLSeconds != 0 || cfg.IdentitySalt != "" ||
		cfg.TLSSessionTicketKey != "" || cfg.CredentialIPSpreadLimit != 0 || cfg.CredentialConcurrencyLimit != 0 ||
		cfg.APIWriteRatePerMinute != 0 || cfg.APIResponseFailPolicy != "" || cfg.APIResponseCaptureMaxBytes != 0 ||
		cfg.APILLMAllowedModels != nil || cfg.APIFileWatermark != nil ||
		cfg.APIGRPCMaxFrameBytes != 0 || cfg.APIGRPCAllowCompression {
		t.Fatalf("快照旧值未清零: %+v", cfg)
	}
	if cfg.APIScanVerification != nil || cfg.APIFileSignature != nil {
		t.Fatalf("密钥段未按当前设置重取（应为未配置不下发）: %+v %+v", cfg.APIScanVerification, cfg.APIFileSignature)
	}
}

// TestReplayRuntimeSecretsReinject 当前设置存在：清零后按当前值重放（含此前遗漏的
// tls_session_ticket_key/api_response_fail_policy/api_response_capture_max_bytes）。
func TestReplayRuntimeSecretsReinject(t *testing.T) {
	const ticketKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	p := &Provider{
		runtimeSettingsLoader: func(ctx context.Context) (map[string]string, error) {
			return map[string]string{
				"behavior_store":                 "memory",
				"tls_session_ticket_key":         ticketKey,
				"api_response_fail_policy":       "FAIL_OPEN",
				"api_response_capture_max_bytes": "2048",
			}, nil
		},
		scanVerification: func(ctx context.Context) (string, error) { return scanTestKeyHex, nil },
		fileSignature:    func(ctx context.Context) (string, string, error) { return "k2026", sigTestKeyHex, nil },
	}
	cfg := snapshotWithRuntimeSecrets()
	if err := p.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.BehaviorStore != "memory" || cfg.TLSSessionTicketKey != ticketKey ||
		cfg.APIResponseFailPolicy != "FAIL_OPEN" || cfg.APIResponseCaptureMaxBytes != 2048 {
		t.Fatalf("当前设置未重放: %+v", cfg)
	}
	// 当前未配置的键保持清零（不得残留快照旧值）
	if cfg.IdentitySalt != "" || cfg.APIWriteRatePerMinute != 0 || cfg.APILLMAllowedModels != nil {
		t.Fatalf("未配置键残留快照旧值: %+v", cfg)
	}
	// 密钥段按当前设置重新解密注入（替换脱敏占位）
	if cfg.APIScanVerification == nil || cfg.APIScanVerification.KeyHex != scanTestKeyHex {
		t.Fatalf("扫描密钥未重取: %+v", cfg.APIScanVerification)
	}
	if cfg.APIFileSignature == nil || cfg.APIFileSignature.KID != "k2026" || cfg.APIFileSignature.KeyHex != sigTestKeyHex {
		t.Fatalf("文件签名密钥未重取: %+v", cfg.APIFileSignature)
	}
}

// TestReplayRuntimeSecretsRedactPlaceholderValue 当前设置值为脱敏占位符（"***"）的键
// 视同取不到：不写入（防 "***" 被发布到网关）。
func TestReplayRuntimeSecretsRedactPlaceholderValue(t *testing.T) {
	p := &Provider{
		runtimeSettingsLoader: func(ctx context.Context) (map[string]string, error) {
			return map[string]string{"tls_session_ticket_key": redactPlaceholder, "identity_salt": redactPlaceholder}, nil
		},
	}
	cfg := snapshotWithRuntimeSecrets()
	if err := p.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.TLSSessionTicketKey != "" || cfg.IdentitySalt != "" {
		t.Fatalf("脱敏占位符不得写入: %+v", cfg)
	}
}

// TestReplayRuntimeSecretsFailHard 读取/解密失败如实返回（回滚发布失败，不静默降级）。
func TestReplayRuntimeSecretsFailHard(t *testing.T) {
	// gateway_runtime 设置读取失败
	p := &Provider{runtimeSettingsLoader: func(ctx context.Context) (map[string]string, error) {
		return nil, errors.New("db down")
	}}
	if err := p.replayRuntimeSecrets(context.Background(), snapshotWithRuntimeSecrets()); err == nil {
		t.Fatal("runtime settings loader failure must error")
	}
	// 扫描密钥解密失败
	p = &Provider{scanVerification: func(ctx context.Context) (string, error) {
		return "", errors.New("decrypt failed")
	}}
	if err := p.replayRuntimeSecrets(context.Background(), snapshotWithRuntimeSecrets()); err == nil {
		t.Fatal("scan verification loader failure must error")
	}
	// 文件签名密钥解密失败
	p = &Provider{fileSignature: func(ctx context.Context) (string, string, error) {
		return "", "", errFileSignatureTest
	}}
	if err := p.replayRuntimeSecrets(context.Background(), snapshotWithRuntimeSecrets()); err == nil {
		t.Fatal("file signature loader failure must error")
	}
}

// TestReplayRuntimeSecretsLoadersNotInjected loader 未注入：快照原样保留（零行为变化，
// 与 BuildGuardConfig 未注入不下发同一语义）。
func TestReplayRuntimeSecretsLoadersNotInjected(t *testing.T) {
	p := &Provider{}
	cfg := snapshotWithRuntimeSecrets()
	if err := p.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.TLSSessionTicketKey != redactPlaceholder || cfg.APIScanVerification == nil ||
		cfg.APIScanVerification.KeyHex != redactPlaceholder {
		t.Fatalf("未注入 loader 时快照不得改动: %+v", cfg)
	}
}
