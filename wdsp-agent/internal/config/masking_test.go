// 策略 masking 段与 max_body_size 钳制测试（Phase 3 契约 §4/§5/§7）。
package config

import (
	"encoding/json"
	"testing"
)

func TestEffectiveMaxBodySize(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{0, DefaultMaxBodySize},
		{-1, DefaultMaxBodySize},
		{1024, 1024},
		{HardMaxBodySize, HardMaxBodySize},
		{HardMaxBodySize + 1, HardMaxBodySize}, // 超硬上限按 10MB 截
		{100 << 20, HardMaxBodySize},
	}
	for _, c := range cases {
		if got := (Limits{MaxBodySize: c.in}).EffectiveMaxBodySize(); got != c.want {
			t.Errorf("MaxBodySize=%d: got %d want %d", c.in, got, c.want)
		}
	}
	if DefaultMaxBodySize != 262144 || HardMaxBodySize != 10485760 {
		t.Errorf("契约默认值被改动: default=%d hard=%d", DefaultMaxBodySize, HardMaxBodySize)
	}
}

func TestMaskingDefaults(t *testing.T) {
	// 整体缺省 → 契约 §5 默认值（逐字）
	var m *Masking
	eff := m.Effective()
	if eff.Headers.Mode != MaskModeMask || eff.Params.Mode != MaskModeMask {
		t.Fatalf("缺省 mode 应为 MASK: %+v", eff)
	}
	wantHeaders := []string{"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}
	wantParams := []string{"password", "passwd", "pwd", "token", "access_token", "refresh_token", "secret", "api_key", "apikey"}
	if !equalSlice(eff.Headers.Names, wantHeaders) {
		t.Fatalf("缺省 header names 错误: %v", eff.Headers.Names)
	}
	if !equalSlice(eff.Params.Names, wantParams) {
		t.Fatalf("缺省 param names 错误: %v", eff.Params.Names)
	}
}

func TestMaskingEffectiveNormalization(t *testing.T) {
	// mode 非法 → 回落 MASK；names 为 null → 默认子段
	m := &Masking{
		Headers: MaskRule{Mode: "BOGUS", Names: nil},
		Params:  MaskRule{Mode: MaskModeNone, Names: []string{"x"}},
	}
	eff := m.Effective()
	if eff.Headers.Mode != MaskModeMask {
		t.Fatalf("非法 mode 应回落 MASK: %q", eff.Headers.Mode)
	}
	if len(eff.Headers.Names) == 0 {
		t.Fatal("names 为 null 应以默认子段补齐")
	}
	if eff.Params.Mode != MaskModeNone || len(eff.Params.Names) != 1 {
		t.Fatalf("合法子段不应被覆盖: %+v", eff.Params)
	}
}

func TestPolicyMaskingJSONRoundTrip(t *testing.T) {
	// 策略 JSON 含 masking 段可解析；缺省段服务端不补齐（omitempty）
	var p Policy
	data := `{"name":"p","capture_level":"L2","masking":{"headers":{"mode":"HASH","names":["cookie"]}}}`
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		t.Fatal(err)
	}
	if p.Masking == nil || p.Masking.Headers.Mode != MaskModeHash {
		t.Fatalf("masking 解析错误: %+v", p.Masking)
	}
	eff := p.Masking.Effective()
	if eff.Params.Mode != MaskModeMask || len(eff.Params.Names) == 0 {
		t.Fatalf("缺省 params 子段应补默认: %+v", eff.Params)
	}
	// 无 masking 段的旧策略
	var p2 Policy
	if err := json.Unmarshal([]byte(`{"name":"old","capture_level":"L1"}`), &p2); err != nil {
		t.Fatal(err)
	}
	if p2.Masking != nil {
		t.Fatal("旧策略 masking 应为 nil（服务端不补齐缺省段）")
	}
	if p2.Masking.Effective().Headers.Mode != MaskModeMask {
		t.Fatal("nil masking 应取契约默认值")
	}
}

func TestEffectiveCaptureLevel(t *testing.T) {
	for lv, want := range map[string]string{"L0": LevelL0, "L1": LevelL1, "L2": LevelL2, "L3": LevelL3, "": LevelL0, "L9": LevelL0} {
		if got := (&Policy{CaptureLevel: lv}).EffectiveCaptureLevel(); got != want {
			t.Errorf("level %q: got %q want %q", lv, got, want)
		}
	}
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
