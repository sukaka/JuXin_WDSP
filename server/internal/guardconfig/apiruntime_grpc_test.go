// apiruntime_grpc_test.go gRPC 帧校验配置下发单测（W14-GW / P2-05，纯函数不依赖数据库）：
// api_grpc_max_frame_bytes / api_grpc_allow_compression 键解析、缺省不下发、
// 非法值与超网关硬上限如实报错（中止发布，不静默回退）。
package guardconfig

import (
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// TestApplyGatewayRuntimeSettingsGRPC 合法键注入；缺省/空串不下发（网关默认兜底）；
// 显式 false 覆盖允许压缩（回到网关默认）。
func TestApplyGatewayRuntimeSettingsGRPC(t *testing.T) {
	// 未配置：零值（不下发，网关 4MiB/不允许压缩兜底）
	cfg := &gatewayconfig.GuardConfig{}
	if err := applyGatewayRuntimeSettings(cfg, map[string]string{}); err != nil {
		t.Fatal(err)
	}
	if cfg.APIGRPCMaxFrameBytes != 0 || cfg.APIGRPCAllowCompression {
		t.Fatalf("defaults must stay zero: %+v", cfg)
	}
	// 合法全量注入
	cfg = &gatewayconfig.GuardConfig{}
	err := applyGatewayRuntimeSettings(cfg, map[string]string{
		"api_grpc_max_frame_bytes":   "8388608",
		"api_grpc_allow_compression": " TRUE ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIGRPCMaxFrameBytes != 8388608 || !cfg.APIGRPCAllowCompression {
		t.Fatalf("grpc settings = %+v", cfg)
	}
	// 显式 false（允许压缩关闭，与网关默认一致）
	cfg = &gatewayconfig.GuardConfig{}
	if err := applyGatewayRuntimeSettings(cfg, map[string]string{"api_grpc_allow_compression": "false"}); err != nil {
		t.Fatal(err)
	}
	if cfg.APIGRPCAllowCompression {
		t.Fatal("explicit false must stay false")
	}
}

// TestApplyGatewayRuntimeSettingsGRPCInvalid 非法取值如实报错。
func TestApplyGatewayRuntimeSettingsGRPCInvalid(t *testing.T) {
	cases := map[string]map[string]string{
		"帧上限非数字":    {"api_grpc_max_frame_bytes": "abc"},
		"帧上限负数":     {"api_grpc_max_frame_bytes": "-1"},
		"帧上限超网关硬上限": {"api_grpc_max_frame_bytes": "134217728"}, // 128MiB > 64MiB
		"压缩许可非法词":   {"api_grpc_allow_compression": "yes"},
	}
	for name, kv := range cases {
		if err := applyGatewayRuntimeSettings(&gatewayconfig.GuardConfig{}, kv); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
	// 恰为 64MiB 硬上限：接受
	if err := applyGatewayRuntimeSettings(&gatewayconfig.GuardConfig{},
		map[string]string{"api_grpc_max_frame_bytes": "67108864"}); err != nil {
		t.Fatalf("64MiB boundary must be accepted: %v", err)
	}
}
