// runtime_config_test.go APM 运行期配置解析单测（内存 fake 设置源）：
// DB 覆盖优先 / env 兜底 / DB 错误回退 env / DSN 空串行=显式清空语义。
package apm

import (
	"context"
	"errors"
	"testing"
)

// fakeRuntimeSettings 是 runtimeSettingsReader 的可编程内存实现（map 按 group:key 存值）。
type fakeRuntimeSettings struct {
	bools   map[string]bool
	strings map[string]string
	err     error // 统一注入读取错误
}

func (f *fakeRuntimeSettings) GetBoolWithSource(_ context.Context, group, key string) (bool, bool, error) {
	if f.err != nil {
		return false, false, f.err
	}
	v, ok := f.bools[group+":"+key]
	return v, ok, nil
}

func (f *fakeRuntimeSettings) GetStringWithSource(_ context.Context, group, key string) (string, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}
	v, ok := f.strings[group+":"+key]
	return v, ok, nil
}

func TestRuntimeConfigEnabledDBOverridesEnv(t *testing.T) {
	ctx := context.Background()
	// env 关 + DB 开 → 开（界面设置优先）
	rc := NewRuntimeConfig(&fakeRuntimeSettings{bools: map[string]bool{"apm:enabled": true}}, false, "")
	if !rc.Enabled(ctx) {
		t.Error("env=false + DB=true: Enabled 应为 true（DB 覆盖优先）")
	}
	// env 开 + DB 关 → 关
	rc = NewRuntimeConfig(&fakeRuntimeSettings{bools: map[string]bool{"apm:enabled": false}}, true, "")
	if rc.Enabled(ctx) {
		t.Error("env=true + DB=false: Enabled 应为 false（DB 覆盖优先）")
	}
	enabled, source := rc.EnabledWithSource(ctx)
	if enabled || source != sourceUI {
		t.Errorf("EnabledWithSource = %v/%q, want false/%q", enabled, source, sourceUI)
	}
}

func TestRuntimeConfigEnabledEnvFallback(t *testing.T) {
	ctx := context.Background()
	// DB 无行 → env 兜底（来源 env）
	rc := NewRuntimeConfig(&fakeRuntimeSettings{}, true, "")
	enabled, source := rc.EnabledWithSource(ctx)
	if !enabled || source != sourceEnv {
		t.Errorf("env fallback: EnabledWithSource = %v/%q, want true/%q", enabled, source, sourceEnv)
	}
	rc = NewRuntimeConfig(&fakeRuntimeSettings{}, false, "")
	if rc.Enabled(ctx) {
		t.Error("env=false 且无 DB 行: Enabled 应为 false")
	}
}

func TestRuntimeConfigDBErrorFallsBackToEnv(t *testing.T) {
	ctx := context.Background()
	src := &fakeRuntimeSettings{
		err:     errors.New("db down"),
		bools:   map[string]bool{"apm:enabled": false},
		strings: map[string]string{"apm:clickhouse_dsn": "clickhouse://db:9000/apm"},
	}
	rc := NewRuntimeConfig(src, true, "clickhouse://env:9000/apm")
	// DB 错误：如实回退 env（Warn 日志），不因 DB 行内容误导
	if !rc.Enabled(ctx) {
		t.Error("DB 错误时应回退 env=true")
	}
	if dsn := rc.ClickHouseDSN(ctx); dsn != "clickhouse://env:9000/apm" {
		t.Errorf("DB 错误时应回退 env DSN，got %q", dsn)
	}
}

func TestRuntimeConfigDSNPrecedence(t *testing.T) {
	ctx := context.Background()
	// DB 行优先于 env
	rc := NewRuntimeConfig(&fakeRuntimeSettings{
		strings: map[string]string{"apm:clickhouse_dsn": "clickhouse://ui:9000/apm"},
	}, true, "clickhouse://env:9000/apm")
	dsn, found, source := rc.ClickHouseDSNWithSource(ctx)
	if dsn != "clickhouse://ui:9000/apm" || !found || source != sourceUI {
		t.Errorf("DSN = %q/%v/%q, want ui 行优先", dsn, found, source)
	}
	// env 兜底
	rc = NewRuntimeConfig(&fakeRuntimeSettings{}, true, "clickhouse://env:9000/apm")
	dsn, found, source = rc.ClickHouseDSNWithSource(ctx)
	if dsn != "clickhouse://env:9000/apm" || found || source != sourceEnv {
		t.Errorf("env 兜底 DSN = %q/%v/%q", dsn, found, source)
	}
	// 均未配置
	rc = NewRuntimeConfig(&fakeRuntimeSettings{}, true, "")
	dsn, found, source = rc.ClickHouseDSNWithSource(ctx)
	if dsn != "" || found || source != "" {
		t.Errorf("均未配置 DSN = %q/%v/%q, want 空/false/空", dsn, found, source)
	}
}

func TestRuntimeConfigDSNEmptyRowIsExplicitClear(t *testing.T) {
	ctx := context.Background()
	// DB 行存在但值为空串 = 显式清空（不回退 env——管理员明确要求不接数据面）
	rc := NewRuntimeConfig(&fakeRuntimeSettings{
		strings: map[string]string{"apm:clickhouse_dsn": ""},
	}, true, "clickhouse://env:9000/apm")
	dsn, found, source := rc.ClickHouseDSNWithSource(ctx)
	if dsn != "" || !found || source != sourceUI {
		t.Errorf("空串行 = %q/%v/%q, want 空/true/%q（显式清空，不回退 env）", dsn, found, source, sourceUI)
	}
	if rc.ClickHouseDSN(ctx) != "" {
		t.Error("ClickHouseDSN 应为空串（显式清空）")
	}
}
