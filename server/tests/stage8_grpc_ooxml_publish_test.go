// stage8_grpc_ooxml_publish_test.go gRPC v1 帧校验配置 + OOXML 水印白名单发布侧端到端
// 贯通测试（W14-GW / P2-05 / P2-01 全格式扩展 下发侧）。
//
// 链路：system_settings gateway_runtime 组
//
//	api_grpc_max_frame_bytes / api_grpc_allow_compression
//	  → 发布通道组装（guardconfig.Provider.BuildGuardConfig，runtimeSettingsLoader
//	    与 app.go 装配同一模式；本测试 loader 按 app.go 名单 + W14 新增键读取）
//	  → GuardConfig.APIGRPCMaxFrameBytes / APIGRPCAllowCompression
//	  → 生成器产出 Caddy JSON：jiuzhang_guard 处理器内 api_grpc_* 键；
//	api_file_watermark_*（content_types 含三个 OOXML MIME）
//	  → GuardConfig.APIFileWatermark → Caddy JSON api_file_watermark 段。
//
// 容错与纪律：缺省键不下发（网关默认兜底，Caddy JSON 无对应键）；
// 非法取值（超网关 64MiB 硬上限）BuildGuardConfig 如实失败（中止发布，不静默回退）。
//
// 注意（装配依赖）：app.go 的 runtimeSettingsLoader 键名单与 settings 可写键名单
// 需集成方补登 api_grpc_* 两键（装配片段见分片报告；api_file_watermark_* 键
// 在 settings 可写名单已登记、loader 名单待补登为 W12 遗留缺口，本测试按补登后口径验证）。
//
// 运行方式（与 make stage8-test-api 一致）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8GRPCOOXMLPublish -count=1
package tests

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/guardconfig"
	"github.com/jiuzhang-waf/server/internal/settings"
)

// s8GRPCRuntimeLoader 按 app.go 同一模式构造 gateway_runtime 设置读取
// （名单 = app.go 既有键 + W14 新增 api_grpc_* 与 api_file_watermark_* 键，
// 即装配片段补登后的口径）。
func s8GRPCRuntimeLoader(env *testEnv) guardconfig.GatewayRuntimeSettingsLoader {
	settingsSvc := settings.NewService(env.db)
	return func(ctx context.Context) (map[string]string, error) {
		out := map[string]string{}
		for _, key := range []string{
			"api_grpc_max_frame_bytes", "api_grpc_allow_compression",
			"api_file_watermark_enabled", "api_file_watermark_template",
			"api_file_watermark_content_types", "api_file_watermark_json_key",
		} {
			v, found, err := settingsSvc.GetStringWithSource(ctx, guardconfig.GatewayRuntimeSettingsGroup, key)
			if err != nil {
				return nil, err
			}
			if found {
				out[key] = v
			}
		}
		return out, nil
	}
}

// s8GRPCProvider 构造接入 gateway_runtime 设置读取的发布组装器。
func s8GRPCProvider(env *testEnv) *guardconfig.Provider {
	p := s8FileCompProvider(env, nil)
	p.SetGatewayRuntimeSettingsLoader(s8GRPCRuntimeLoader(env))
	return p
}

// TestStage8GRPCOOXMLPublishE2E gRPC 帧校验配置与 OOXML 水印白名单下发贯通。
func TestStage8GRPCOOXMLPublishE2E(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	settingsSvc := settings.NewService(env.db)

	// ---------- 1. 缺省：未配置键不下发（网关默认兜底），Caddy JSON 无对应键 ----------
	cfg1, err := s8GRPCProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config: %v", err)
	}
	if cfg1.APIGRPCMaxFrameBytes != 0 || cfg1.APIGRPCAllowCompression || cfg1.APIFileWatermark != nil {
		t.Fatalf("defaults must stay zero: %+v", cfg1)
	}
	j1 := s8GenerateGuardJSON(t, cfg1)
	for _, absent := range []string{"api_grpc_max_frame_bytes", "api_grpc_allow_compression", "api_file_watermark"} {
		if strings.Contains(j1, absent) {
			t.Fatalf("unconfigured key %s must be omitted from caddy json", absent)
		}
	}

	// ---------- 2. 配置键进入下发：GuardConfig 字段与 Caddy JSON 键 ----------
	const docxMIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	const xlsxMIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	const pptxMIME = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	upserts := map[string]string{
		"api_grpc_max_frame_bytes":         "8388608",
		"api_grpc_allow_compression":       "true",
		"api_file_watermark_enabled":       "true",
		"api_file_watermark_template":      "wm ip={ip} d={domain}",
		"api_file_watermark_content_types": "text/plain," + docxMIME + "," + xlsxMIME + "," + pptxMIME,
	}
	for key, value := range upserts {
		if err := settingsSvc.UpsertString(ctx, "gateway_runtime", key, value, "W14 gRPC/OOXML 下发测试", uuid.Nil); err != nil {
			t.Fatalf("upsert %s: %v", key, err)
		}
	}
	cfg2, err := s8GRPCProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config: %v", err)
	}
	if cfg2.APIGRPCMaxFrameBytes != 8388608 || !cfg2.APIGRPCAllowCompression {
		t.Fatalf("grpc settings = %+v", cfg2)
	}
	wm := cfg2.APIFileWatermark
	if wm == nil || !wm.Enabled || wm.TextTemplate != "wm ip={ip} d={domain}" || len(wm.ContentTypes) != 4 {
		t.Fatalf("watermark = %+v", wm)
	}
	j2 := s8GenerateGuardJSON(t, cfg2)
	for _, want := range []string{
		`"api_grpc_max_frame_bytes":8388608`, `"api_grpc_allow_compression":true`,
		`"api_file_watermark"`, `"enabled":true`,
		docxMIME, xlsxMIME, pptxMIME,
	} {
		if !strings.Contains(j2, want) {
			t.Fatalf("caddy json missing %s", want)
		}
	}

	// ---------- 3. 非法取值：超网关 64MiB 硬上限 → 发布失败（不静默回退） ----------
	if err := settingsSvc.UpsertString(ctx, "gateway_runtime", "api_grpc_max_frame_bytes", "134217728", "越限", uuid.Nil); err != nil {
		t.Fatalf("upsert over-cap: %v", err)
	}
	if _, err := s8GRPCProvider(env).BuildGuardConfig(ctx); err == nil {
		t.Fatal("over-cap frame limit must abort publish")
	}
	// 回落合法值后恢复
	if err := settingsSvc.UpsertString(ctx, "gateway_runtime", "api_grpc_max_frame_bytes", "8388608", "恢复", uuid.Nil); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, err := s8GRPCProvider(env).BuildGuardConfig(ctx); err != nil {
		t.Fatalf("restored config must build: %v", err)
	}

	// ---------- 4. 清理：删除设置键后回落缺省（不下发） ----------
	for key := range upserts {
		if _, err := env.db.Exec(ctx,
			`DELETE FROM system_settings WHERE setting_group = 'gateway_runtime' AND setting_key = $1`, key); err != nil {
			t.Fatalf("delete %s: %v", key, err)
		}
	}
	cfg4, err := s8GRPCProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config: %v", err)
	}
	if cfg4.APIGRPCMaxFrameBytes != 0 || cfg4.APIGRPCAllowCompression || cfg4.APIFileWatermark != nil {
		t.Fatalf("deleted keys must fall back to zero: %+v", cfg4)
	}
}
