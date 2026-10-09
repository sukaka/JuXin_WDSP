package detectors

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 判定矩阵：端点状态（CONFIRMED/DISCOVERED/IGNORED/DEPRECATED/ZOMBIE/基线缺失）
// × 模式（OFF/OBSERVE/PROTECT/词表外）全组合期望（设计 §3.2/§4.1）。
func TestCheckAdmission_Matrix(t *testing.T) {
	confirmed := map[string]struct{}{"GET /v1/orders/{id}": {}}
	known := map[string]string{
		"GET /v1/orders/{id}": "CONFIRMED",
		"GET /v1/discovered":  "DISCOVERED",
		"GET /v1/ignored":     "IGNORED",
		"GET /v1/deprecated":  "DEPRECATED",
		"GET /v1/zombie":      "ZOMBIE",
	}
	type want struct {
		ruleID         string // "" = 无 finding
		category       string
		severity       string
		unknownCovered bool
		protectDenied  bool
		assetStatus    string // 期望 evidence 中的 asset_status（"" = 不应存在）
	}
	cases := []struct {
		name     string
		mode     string
		endpoint string
		want     want
	}{
		// 已确认端点：三种模式均放行无 finding
		{"confirmed/OFF", AdmissionModeOff, "GET /v1/orders/{id}", want{}},
		{"confirmed/OBSERVE", AdmissionModeObserve, "GET /v1/orders/{id}", want{}},
		{"confirmed/PROTECT", AdmissionModeProtect, "GET /v1/orders/{id}", want{}},
		// OFF：任何端点状态不判定
		{"OFF/discovered", AdmissionModeOff, "GET /v1/discovered", want{}},
		{"OFF/unknown", AdmissionModeOff, "GET /v1/never-seen", want{}},
		// 词表外/缺失：fail-safe 视为 OFF（不拦截优于误拦截）
		{"invalid-mode/discovered", "BLOCK_ALL", "GET /v1/discovered", want{}},
		{"invalid-mode/unknown", "BLOCK_ALL", "GET /v1/never-seen", want{}},
		{"empty-mode/discovered", "", "GET /v1/discovered", want{}},
		{"lowercase-observe 不归一", "observe", "GET /v1/discovered", want{}}, // 归一在装配层，检测器严格词表
		// OBSERVE：未确认端点 OBSERVE/LOW 仅记录
		{"OBSERVE/discovered", AdmissionModeObserve, "GET /v1/discovered",
			want{"admission.unconfirmed_endpoint", "OBSERVE", "LOW", false, false, "DISCOVERED"}},
		{"OBSERVE/ignored", AdmissionModeObserve, "GET /v1/ignored",
			want{"admission.unconfirmed_endpoint", "OBSERVE", "LOW", false, false, "IGNORED"}},
		{"OBSERVE/deprecated", AdmissionModeObserve, "GET /v1/deprecated",
			want{"admission.unconfirmed_endpoint", "OBSERVE", "LOW", false, false, "DEPRECATED"}},
		{"OBSERVE/zombie", AdmissionModeObserve, "GET /v1/zombie",
			want{"admission.unconfirmed_endpoint", "OBSERVE", "LOW", false, false, "ZOMBIE"}},
		{"OBSERVE/unknown", AdmissionModeObserve, "GET /v1/never-seen",
			want{"admission.unknown_endpoint", "OBSERVE", "LOW", true, false, ""}},
		// PROTECT：未确认端点 BLOCK/HIGH（决策引擎 cat==BLOCK 分支获得阻断资格）
		{"PROTECT/discovered", AdmissionModeProtect, "GET /v1/discovered",
			want{"admission.unconfirmed_endpoint", "BLOCK", "HIGH", false, true, "DISCOVERED"}},
		{"PROTECT/ignored", AdmissionModeProtect, "GET /v1/ignored",
			want{"admission.unconfirmed_endpoint", "BLOCK", "HIGH", false, true, "IGNORED"}},
		{"PROTECT/deprecated", AdmissionModeProtect, "GET /v1/deprecated",
			want{"admission.unconfirmed_endpoint", "BLOCK", "HIGH", false, true, "DEPRECATED"}},
		{"PROTECT/zombie", AdmissionModeProtect, "GET /v1/zombie",
			want{"admission.unconfirmed_endpoint", "BLOCK", "HIGH", false, true, "ZOMBIE"}},
		{"PROTECT/unknown", AdmissionModeProtect, "GET /v1/never-seen",
			want{"admission.unknown_endpoint", "BLOCK", "HIGH", true, true, ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := dsctx.New("t", dsctx.DefaultParseLimits())
			out := CheckAdmission(ctx, tc.endpoint,
				AdmissionPolicy{Mode: tc.mode, Confirmed: confirmed}, known)
			if out.UnknownCovered != tc.want.unknownCovered || out.ProtectDenied != tc.want.protectDenied {
				t.Fatalf("outcome = %+v, want covered=%v denied=%v", out, tc.want.unknownCovered, tc.want.protectDenied)
			}
			if tc.want.ruleID == "" {
				if ctx.MatchCount() != 0 {
					t.Fatalf("expected no finding, got %+v", ctx.CopyMatches())
				}
				return
			}
			m := findMatch(ctx, tc.want.ruleID)
			if m == nil {
				t.Fatalf("expected %s, got %+v", tc.want.ruleID, ctx.CopyMatches())
			}
			if m.Detector != "admission" || m.Category != tc.want.category || m.Severity != tc.want.severity {
				t.Fatalf("bad attrs: %+v", m)
			}
			if m.Evidence["endpoint_key"] != tc.endpoint || m.Evidence["admission_mode"] != tc.mode {
				t.Fatalf("bad evidence: %+v", m.Evidence)
			}
			if got := m.Evidence["asset_status"]; got != tc.want.assetStatus {
				t.Fatalf("asset_status = %q, want %q", got, tc.want.assetStatus)
			}
			if ctx.MatchCount() != 1 {
				t.Fatalf("expected exactly 1 finding, got %+v", ctx.CopyMatches())
			}
		})
	}
}

// 基线未下发（nil known）：不在确认集合即按 unknown 处理（基线完全无此端点语义）。
func TestCheckAdmission_NilBaselineTreatedAsUnknown(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	out := CheckAdmission(ctx, "GET /v1/anything",
		AdmissionPolicy{Mode: AdmissionModeObserve, Confirmed: map[string]struct{}{"GET /v1/x": {}}}, nil)
	m := findMatch(ctx, "admission.unknown_endpoint")
	if m == nil || !out.UnknownCovered {
		t.Fatalf("nil baseline must yield unknown, out=%+v matches=%+v", out, ctx.CopyMatches())
	}
	if _, ok := m.Evidence["asset_status"]; ok {
		t.Fatalf("unknown finding must not carry asset_status: %+v", m.Evidence)
	}
}

// 确认集合为空/nil：PROTECT 下任何端点（含基线内 CONFIRMED 态端点——确认集合才是准入口径）均拒绝。
func TestCheckAdmission_EmptyConfirmedSetDeniesAll(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	out := CheckAdmission(ctx, "GET /v1/orders/{id}",
		AdmissionPolicy{Mode: AdmissionModeProtect},
		map[string]string{"GET /v1/orders/{id}": "CONFIRMED"})
	m := findMatch(ctx, "admission.unconfirmed_endpoint")
	if m == nil || m.Category != "BLOCK" || !out.ProtectDenied {
		t.Fatalf("empty confirmed set must deny, out=%+v matches=%+v", out, ctx.CopyMatches())
	}
}

// 负例：nil 上下文/空端点键不判定不 panic。
func TestCheckAdmission_NilGuards(t *testing.T) {
	p := AdmissionPolicy{Mode: AdmissionModeProtect, Confirmed: map[string]struct{}{}}
	if out := CheckAdmission(nil, "GET /v1/x", p, nil); out != (AdmissionOutcome{}) {
		t.Fatalf("nil ctx must no-op, got %+v", out)
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	if out := CheckAdmission(ctx, "", p, nil); out != (AdmissionOutcome{}) || ctx.MatchCount() != 0 {
		t.Fatalf("empty endpoint key must no-op, out=%+v matches=%+v", out, ctx.CopyMatches())
	}
}

// 并发读安全：策略与基线为 Provision 后只读结构，多请求并发判定不竞态（go test -race）。
func TestCheckAdmission_ConcurrentReads(t *testing.T) {
	p := AdmissionPolicy{Mode: AdmissionModeProtect, Confirmed: map[string]struct{}{"GET /v1/ok": {}}}
	known := map[string]string{"GET /v1/discovered": "DISCOVERED"}
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			for _, ek := range []string{"GET /v1/ok", "GET /v1/discovered", "GET /v1/new"} {
				ctx := dsctx.New("t", dsctx.DefaultParseLimits())
				CheckAdmission(ctx, ek, p, known)
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
