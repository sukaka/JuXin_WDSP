package decision

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestDecideMultiMatchFinalAction(t *testing.T) {
	ctx := dsctx.New("rid-1", dsctx.DefaultParseLimits())
	// detectors only add matches — they do not set FinalAction
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "waf", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50, RuleID: "942100"})
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_schema", Category: "OBSERVE", Severity: "MEDIUM", ScoreDelta: 10, RuleID: "schema.extra_field"})
	if ctx.GetFinalAction() != dsctx.ActionUnset {
		t.Fatal("detectors must not set final action")
	}
	act := Decide(ctx, Input{Mode: ModeProtect})
	if act != dsctx.ActionBlock {
		t.Fatalf("action=%s", act)
	}
	if ctx.GetFinalAction() != dsctx.ActionBlock {
		t.Fatal(ctx.GetFinalAction())
	}
	if ctx.MatchCount() != 2 {
		t.Fatal(ctx.MatchCount())
	}
}

func TestDecideObserveMode(t *testing.T) {
	ctx := dsctx.New("rid-2", dsctx.DefaultParseLimits())
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "waf", Severity: "HIGH", ScoreDelta: 50})
	act := Decide(ctx, Input{Mode: ModeObserve})
	if act != dsctx.ActionObserve {
		t.Fatalf("got %s", act)
	}
}

func TestDecideAllowWhenClean(t *testing.T) {
	ctx := dsctx.New("rid-3", dsctx.DefaultParseLimits())
	act := Decide(ctx, Input{Mode: ModeProtect})
	if act != dsctx.ActionAllow {
		t.Fatal(act)
	}
}

func TestDecideIgnoresInfoIdentity(t *testing.T) {
	ctx := dsctx.New("rid-info", dsctx.DefaultParseLimits())
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "identity", RuleID: "identity.token_present",
		Category: "INFO", Severity: "INFO",
	})
	act := Decide(ctx, Input{Mode: ModeProtect})
	if act != dsctx.ActionAllow {
		t.Fatalf("INFO must not force observe/block, got %s", act)
	}
}

// MASK_RESPONSE 分支：计划非空 + PROTECT → MASK_RESPONSE。
func TestDecideMaskResponseProtect(t *testing.T) {
	ctx := dsctx.New("rid-mask-1", dsctx.DefaultParseLimits())
	ctx.SetResponse(&dsctx.ResponseContext{
		Status: 200,
		TransformPlan: []dsctx.FieldTransform{
			{FieldPath: "user.phone", Algorithm: "MASK", KeepHead: 3, KeepTail: 4},
		},
	})
	// 响应相位为计划追加的 OBSERVE 明细（仅记录语义）
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_response", RuleID: "response.mask_plan", Category: "OBSERVE", Severity: "LOW"})
	act := Decide(ctx, Input{Mode: ModeProtect})
	if act != dsctx.ActionMaskResp {
		t.Fatalf("got %s, want MASK_RESPONSE", act)
	}
	if ctx.GetFinalAction() != dsctx.ActionMaskResp {
		t.Fatal(ctx.GetFinalAction())
	}
}

// MASK_RESPONSE 分支：OBSERVE 模式仅记录，计划不升级为改写动作。
func TestDecideMaskResponseObserveMode(t *testing.T) {
	ctx := dsctx.New("rid-mask-2", dsctx.DefaultParseLimits())
	ctx.SetResponse(&dsctx.ResponseContext{
		Status:        200,
		TransformPlan: []dsctx.FieldTransform{{FieldPath: "user.phone", Algorithm: "HASH"}},
	})
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_response", RuleID: "response.mask_plan", Category: "OBSERVE", Severity: "LOW"})
	act := Decide(ctx, Input{Mode: ModeObserve})
	if act != dsctx.ActionObserve {
		t.Fatalf("OBSERVE mode must not mask, got %s", act)
	}
}

// MASK_RESPONSE 分支：计划为空不改变既有 ALLOW 语义。
func TestDecideMaskResponseEmptyPlan(t *testing.T) {
	ctx := dsctx.New("rid-mask-3", dsctx.DefaultParseLimits())
	ctx.SetResponse(&dsctx.ResponseContext{Status: 200})
	if act := Decide(ctx, Input{Mode: ModeProtect}); act != dsctx.ActionAllow {
		t.Fatalf("empty plan must stay ALLOW, got %s", act)
	}
	// 无 ResponseContext（非 API 流量）同样为零行为变化
	ctx2 := dsctx.New("rid-mask-4", dsctx.DefaultParseLimits())
	if act := Decide(ctx2, Input{Mode: ModeProtect}); act != dsctx.ActionAllow {
		t.Fatalf("nil response must stay ALLOW, got %s", act)
	}
}

// MASK_RESPONSE 分支：阻断类动作优先于脱敏（优先级语义不被破坏）。
func TestDecideMaskResponseBlockPrecedence(t *testing.T) {
	ctx := dsctx.New("rid-mask-5", dsctx.DefaultParseLimits())
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_schema", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50})
	ctx.SetResponse(&dsctx.ResponseContext{
		Status:        200,
		TransformPlan: []dsctx.FieldTransform{{FieldPath: "user.phone", Algorithm: "REMOVE"}},
	})
	if act := Decide(ctx, Input{Mode: ModeProtect}); act != dsctx.ActionBlock {
		t.Fatalf("BLOCK must outrank MASK_RESPONSE, got %s", act)
	}
}

// RATE_LIMIT/TEMP_BLOCK 定案：PROTECT 实断，OBSERVE 降级为 OBSERVE（与 BLOCK 同口径）。
func TestDecideRateLimitTempBlockByMode(t *testing.T) {
	cases := []struct {
		name  string
		match dsctx.DetectorMatch
		mode  Mode
		want  dsctx.FinalAction
	}{
		{
			name:  "rate_limit protect",
			match: dsctx.DetectorMatch{Detector: "api_ratelimit", RuleID: "ratelimit.api_write_rate", Category: "RATE_LIMIT", Severity: "HIGH", ScoreDelta: 30},
			mode:  ModeProtect,
			want:  dsctx.ActionRateLimit,
		},
		{
			name:  "rate_limit observe",
			match: dsctx.DetectorMatch{Detector: "api_ratelimit", RuleID: "ratelimit.api_write_rate", Category: "RATE_LIMIT", Severity: "HIGH", ScoreDelta: 30},
			mode:  ModeObserve,
			want:  dsctx.ActionObserve,
		},
		{
			name:  "temp_block protect",
			match: dsctx.DetectorMatch{Detector: "temp_block", Category: "TEMP_BLOCK", Severity: "HIGH", ScoreDelta: 40},
			mode:  ModeProtect,
			want:  dsctx.ActionTempBlock,
		},
		{
			name:  "temp_block observe",
			match: dsctx.DetectorMatch{Detector: "temp_block", Category: "TEMP_BLOCK", Severity: "HIGH", ScoreDelta: 40},
			mode:  ModeObserve,
			want:  dsctx.ActionObserve,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := dsctx.New("rid-"+tc.name, dsctx.DefaultParseLimits())
			ctx.AddMatch(tc.match)
			if act := Decide(ctx, Input{Mode: tc.mode}); act != tc.want {
				t.Fatalf("got %s, want %s", act, tc.want)
			}
			if ctx.GetFinalAction() != tc.want {
				t.Fatalf("final=%s, want %s", ctx.GetFinalAction(), tc.want)
			}
		})
	}
}

// 优先级：BLOCK 与 RATE_LIMIT 同命中时 BLOCK 优先（BLOCK > TEMP_BLOCK > RATE_LIMIT）。
func TestDecideBlockOutranksRateLimit(t *testing.T) {
	ctx := dsctx.New("rid-prio-1", dsctx.DefaultParseLimits())
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_ratelimit", RuleID: "ratelimit.api_write_rate", Category: "RATE_LIMIT", Severity: "HIGH", ScoreDelta: 30})
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "waf", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50, RuleID: "942100"})
	if act := Decide(ctx, Input{Mode: ModeProtect}); act != dsctx.ActionBlock {
		t.Fatalf("BLOCK must outrank RATE_LIMIT, got %s", act)
	}
	// OBSERVE 模式同命中同样降级为 OBSERVE（非 429/403 实断语义）
	ctx2 := dsctx.New("rid-prio-2", dsctx.DefaultParseLimits())
	ctx2.AddMatch(dsctx.DetectorMatch{Detector: "api_ratelimit", RuleID: "ratelimit.api_write_rate", Category: "RATE_LIMIT", Severity: "HIGH", ScoreDelta: 30})
	ctx2.AddMatch(dsctx.DetectorMatch{Detector: "waf", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50, RuleID: "942100"})
	if act := Decide(ctx2, Input{Mode: ModeObserve}); act != dsctx.ActionObserve {
		t.Fatalf("OBSERVE mode must degrade to OBSERVE, got %s", act)
	}
}

// OBSERVE 类但 Severity=HIGH 的明细（非可信阻断源、ScoreDelta<50）单独命中至少定案 OBSERVE。
func TestDecideObserveClassHighSeverity(t *testing.T) {
	cases := []dsctx.DetectorMatch{
		{Detector: "authentication", RuleID: "auth.jwt_alg_none", Category: "OBSERVE", Severity: "HIGH", ScoreDelta: 25},
		{Detector: "api_authz", RuleID: "authz.bfla_anonymous", Category: "OBSERVE", Severity: "HIGH", ScoreDelta: 30},
		{Detector: "authentication", RuleID: "auth.env_anomaly_stack", Category: "OBSERVE", Severity: "HIGH", ScoreDelta: 20},
	}
	for _, m := range cases {
		ctx := dsctx.New("rid-"+m.RuleID, dsctx.DefaultParseLimits())
		ctx.AddMatch(m)
		if act := Decide(ctx, Input{Mode: ModeProtect}); act != dsctx.ActionObserve {
			t.Fatalf("%s alone must finalize OBSERVE, got %s", m.RuleID, act)
		}
	}
}
