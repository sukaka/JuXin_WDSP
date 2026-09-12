package decision

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// EXC-10 决策重算：被豁免 Finding 保留于 Matches（证据不删、标记可溯源），
// 其余高风险 Finding 仍按既有优先级定案 BLOCK。
func TestDecideExceptionRecalculatesWithRemainingBlock(t *testing.T) {
	ctx := dsctx.New("rid-exc-10", dsctx.DefaultParseLimits())
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_schema", RuleID: "schema.extra_field", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50})
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "waf", RuleID: "942100", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50})

	act := Decide(ctx, Input{
		Mode: ModeProtect,
		Exceptions: []ExceptionRef{{
			ExceptionID: "exc-uuid-1", Version: 2,
			DetectorID: "api_schema", RuleID: "schema.extra_field",
		}},
	})
	if act != dsctx.ActionBlock {
		t.Fatalf("remaining waf BLOCK finding must still finalize BLOCK, got %s", act)
	}
	matches := SnapshotMatches(ctx)
	if len(matches) != 2 {
		t.Fatalf("excepted finding must be retained, matches=%d", len(matches))
	}
	if !matches[0].Excepted || matches[0].ExceptionID != "exc-uuid-1" || matches[0].ExceptionVersion != 2 {
		t.Fatalf("excepted finding not marked: %+v", matches[0])
	}
	if matches[1].Excepted {
		t.Fatalf("non-targeted finding must stay unmarked: %+v", matches[1])
	}
}

// 豁免不产生 ALLOW 粗暴化：被豁免 BLOCK 排除后，其余 OBSERVE 类 Finding 仍定案 OBSERVE。
func TestDecideExceptionNotBlanketAllow(t *testing.T) {
	ctx := dsctx.New("rid-exc-observe", dsctx.DefaultParseLimits())
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_schema", RuleID: "schema.type_mismatch", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50})
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "authentication", RuleID: "auth.jwt_alg_none", Category: "OBSERVE", Severity: "HIGH", ScoreDelta: 25})

	act := Decide(ctx, Input{
		Mode: ModeProtect,
		Exceptions: []ExceptionRef{{
			ExceptionID: "exc-uuid-2", Version: 1,
			DetectorID: "api_schema", RuleID: "schema.type_mismatch",
		}},
	})
	if act != dsctx.ActionObserve {
		t.Fatalf("remaining OBSERVE finding must finalize OBSERVE (not blanket ALLOW), got %s", act)
	}
}

// 全部被豁免时按既有优先级重算为 ALLOW（证据保留，非删除 Finding）。
func TestDecideExceptionAllExceptedAllows(t *testing.T) {
	ctx := dsctx.New("rid-exc-all", dsctx.DefaultParseLimits())
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_parser", RuleID: "parser.multi_value", Category: "OBSERVE", Severity: "MEDIUM", ScoreDelta: 10})

	act := Decide(ctx, Input{
		Mode: ModeProtect,
		Exceptions: []ExceptionRef{{
			ExceptionID: "exc-uuid-3", Version: 1,
			DetectorID: "api_parser", RuleID: "parser.multi_value",
		}},
	})
	if act != dsctx.ActionAllow {
		t.Fatalf("all findings excepted must recompute to ALLOW, got %s", act)
	}
	matches := SnapshotMatches(ctx)
	if len(matches) != 1 || !matches[0].Excepted {
		t.Fatalf("evidence must be retained and marked: %+v", matches)
	}
}

// 被豁免 Finding 的执法类别不贡献：RATE_LIMIT 明细豁免后不再定案 429 类动作。
func TestDecideExceptionExcludesRateLimitContribution(t *testing.T) {
	ctx := dsctx.New("rid-exc-rl", dsctx.DefaultParseLimits())
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_ratelimit", RuleID: "ratelimit.api_write_rate", Category: "RATE_LIMIT", Severity: "HIGH", ScoreDelta: 30})

	// 无例外基线：PROTECT 定案 RATE_LIMIT
	if act := Decide(ctx, Input{Mode: ModeProtect}); act != dsctx.ActionRateLimit {
		t.Fatalf("baseline must be RATE_LIMIT, got %s", act)
	}

	ctx2 := dsctx.New("rid-exc-rl-2", dsctx.DefaultParseLimits())
	ctx2.AddMatch(dsctx.DetectorMatch{Detector: "api_ratelimit", RuleID: "ratelimit.api_write_rate", Category: "RATE_LIMIT", Severity: "HIGH", ScoreDelta: 30})
	act := Decide(ctx2, Input{
		Mode: ModeProtect,
		Exceptions: []ExceptionRef{{
			ExceptionID: "exc-uuid-4", Version: 1,
			DetectorID: "api_ratelimit", RuleID: "ratelimit.api_write_rate",
		}},
	})
	if act != dsctx.ActionAllow {
		t.Fatalf("excepted RATE_LIMIT contribution must be excluded, got %s", act)
	}
}

// 多例外优先级：同一 Finding 命中多条例外引用时先入例外优先（输入序），打标可溯源。
func TestDecideExceptionFirstRefWins(t *testing.T) {
	ctx := dsctx.New("rid-exc-prio", dsctx.DefaultParseLimits())
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_schema", RuleID: "schema.extra_field", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50})

	act := Decide(ctx, Input{
		Mode: ModeProtect,
		Exceptions: []ExceptionRef{
			{ExceptionID: "exc-first", Version: 1, DetectorID: "api_schema", RuleID: "schema.extra_field"},
			{ExceptionID: "exc-second", Version: 7, DetectorID: "api_schema", RuleID: "schema.extra_field"},
		},
	})
	if act != dsctx.ActionAllow {
		t.Fatalf("got %s", act)
	}
	m := SnapshotMatches(ctx)[0]
	if m.ExceptionID != "exc-first" || m.ExceptionVersion != 1 {
		t.Fatalf("first matching exception must win, got id=%q version=%d", m.ExceptionID, m.ExceptionVersion)
	}
}

// 多例外分治：不同 Finding 由各自例外豁免，互不串扰。
func TestDecideExceptionDistinctFindings(t *testing.T) {
	ctx := dsctx.New("rid-exc-distinct", dsctx.DefaultParseLimits())
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_schema", RuleID: "schema.a", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50})
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_parser", RuleID: "parser.b", Category: "OBSERVE", Severity: "MEDIUM", ScoreDelta: 10})
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_schema", RuleID: "schema.c", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50})

	act := Decide(ctx, Input{
		Mode: ModeProtect,
		Exceptions: []ExceptionRef{
			{ExceptionID: "exc-a", Version: 1, DetectorID: "api_schema", RuleID: "schema.a"},
			{ExceptionID: "exc-b", Version: 3, DetectorID: "api_parser", RuleID: "parser.b"},
		},
	})
	if act != dsctx.ActionBlock {
		t.Fatalf("non-excepted schema.c must still BLOCK, got %s", act)
	}
	matches := SnapshotMatches(ctx)
	if !matches[0].Excepted || matches[0].ExceptionID != "exc-a" {
		t.Fatalf("schema.a marking wrong: %+v", matches[0])
	}
	if !matches[1].Excepted || matches[1].ExceptionID != "exc-b" || matches[1].ExceptionVersion != 3 {
		t.Fatalf("parser.b marking wrong: %+v", matches[1])
	}
	if matches[2].Excepted {
		t.Fatalf("schema.c must stay unmarked: %+v", matches[2])
	}
}

// 钉版语义：ref.ModelVersion 非空时必须等于 Finding.ModelVersion；为空不限版本。
func TestDecideExceptionModelVersionPin(t *testing.T) {
	mk := func(modelVersion string) *dsctx.RequestContext {
		ctx := dsctx.New("rid-exc-mv", dsctx.DefaultParseLimits())
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "api_schema", RuleID: "schema.extra_field",
			Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50,
			ModelVersion: modelVersion,
		})
		return ctx
	}

	// 钉版一致 → 豁免
	ctx := mk("mv-2026-09")
	act := Decide(ctx, Input{Mode: ModeProtect, Exceptions: []ExceptionRef{
		{ExceptionID: "e1", Version: 1, DetectorID: "api_schema", RuleID: "schema.extra_field", ModelVersion: "mv-2026-09"},
	}})
	if act != dsctx.ActionAllow || !SnapshotMatches(ctx)[0].Excepted {
		t.Fatalf("pinned version match must except, act=%s", act)
	}

	// 钉版不一致 → 不豁免
	ctx = mk("mv-old")
	act = Decide(ctx, Input{Mode: ModeProtect, Exceptions: []ExceptionRef{
		{ExceptionID: "e1", Version: 1, DetectorID: "api_schema", RuleID: "schema.extra_field", ModelVersion: "mv-2026-09"},
	}})
	if act != dsctx.ActionBlock || SnapshotMatches(ctx)[0].Excepted {
		t.Fatalf("pinned version mismatch must not except, act=%s", act)
	}

	// 不限版本（空 ModelVersion）→ 豁免任意版本
	ctx = mk("mv-anything")
	act = Decide(ctx, Input{Mode: ModeProtect, Exceptions: []ExceptionRef{
		{ExceptionID: "e1", Version: 1, DetectorID: "api_schema", RuleID: "schema.extra_field"},
	}})
	if act != dsctx.ActionAllow || !SnapshotMatches(ctx)[0].Excepted {
		t.Fatalf("unpinned ref must except any model version, act=%s", act)
	}
}

// 精确匹配语义：detector_id/rule_id 大小写与子串均不模糊匹配。
func TestDecideExceptionExactMatchOnly(t *testing.T) {
	cases := []ExceptionRef{
		{ExceptionID: "e", Version: 1, DetectorID: "API_SCHEMA", RuleID: "schema.extra_field"},   // 大小写不同
		{ExceptionID: "e", Version: 1, DetectorID: "api_schema", RuleID: "schema.extra"},         // 子串
		{ExceptionID: "e", Version: 1, DetectorID: "api_schema", RuleID: "schema.extra_field.x"}, // 超串
		{ExceptionID: "e", Version: 1, DetectorID: "waf", RuleID: "schema.extra_field"},          // detector 不同
	}
	for i, ref := range cases {
		ctx := dsctx.New("rid-exc-exact", dsctx.DefaultParseLimits())
		ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_schema", RuleID: "schema.extra_field", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50})
		act := Decide(ctx, Input{Mode: ModeProtect, Exceptions: []ExceptionRef{ref}})
		if act != dsctx.ActionBlock {
			t.Fatalf("case %d: non-exact ref must not except, got %s", i, act)
		}
		if SnapshotMatches(ctx)[0].Excepted {
			t.Fatalf("case %d: finding must stay unmarked", i)
		}
	}
}

// 幂等：重复 Decide 不重复打标、不改写既有标记，定案稳定。
func TestDecideExceptionIdempotentRepeatDecide(t *testing.T) {
	ctx := dsctx.New("rid-exc-idem", dsctx.DefaultParseLimits())
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_schema", RuleID: "schema.extra_field", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50})
	in := Input{Mode: ModeProtect, Exceptions: []ExceptionRef{
		{ExceptionID: "exc-uuid", Version: 2, DetectorID: "api_schema", RuleID: "schema.extra_field"},
	}}
	if act := Decide(ctx, in); act != dsctx.ActionAllow {
		t.Fatalf("first decide got %s", act)
	}
	if act := Decide(ctx, in); act != dsctx.ActionAllow {
		t.Fatalf("second decide got %s", act)
	}
	matches := SnapshotMatches(ctx)
	if len(matches) != 1 || !matches[0].Excepted || matches[0].ExceptionID != "exc-uuid" || matches[0].ExceptionVersion != 2 {
		t.Fatalf("repeat decide must keep single stable marking: %+v", matches)
	}
}

// 预打标兼容：进入 Decide 前已被打标的 Finding（异常重入路径）同样从定案排除。
func TestDecideRespectsPreMarkedExcepted(t *testing.T) {
	ctx := dsctx.New("rid-exc-premark", dsctx.DefaultParseLimits())
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_schema", RuleID: "schema.extra_field", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50})
	if !ctx.MarkMatchExcepted(0, "api_schema", "schema.extra_field", "exc-pre", 1) {
		t.Fatal("pre-mark failed")
	}
	// 不带例外重算：既有标记仍生效（标记语义属于 Finding 而非单次 Decide 入参）
	if act := Decide(ctx, Input{Mode: ModeProtect}); act != dsctx.ActionAllow {
		t.Fatalf("pre-marked finding must be excluded from decision, got %s", act)
	}
}

// OBSERVE 模式降级语义不受例外影响：未豁免 BLOCK 明细在 OBSERVE 模式仍降级 OBSERVE。
func TestDecideExceptionObserveModeDegradeUnchanged(t *testing.T) {
	ctx := dsctx.New("rid-exc-obsmode", dsctx.DefaultParseLimits())
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_schema", RuleID: "schema.a", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50})
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_schema", RuleID: "schema.b", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50})
	act := Decide(ctx, Input{
		Mode: ModeObserve,
		Exceptions: []ExceptionRef{
			{ExceptionID: "e", Version: 1, DetectorID: "api_schema", RuleID: "schema.a"},
		},
	})
	if act != dsctx.ActionObserve {
		t.Fatalf("OBSERVE mode degrade must be unchanged, got %s", act)
	}
	if !SnapshotMatches(ctx)[0].Excepted || SnapshotMatches(ctx)[1].Excepted {
		t.Fatal("marking wrong in observe mode")
	}
}

// 回归钉住：同一输入在 Exceptions 为 nil / 空切片时输出与现状逐字节一致，
// 且任何 Finding 不被打标（空例外集零行为变化）。
func TestDecideEmptyExceptionsRegression(t *testing.T) {
	build := func() *dsctx.RequestContext {
		ctx := dsctx.New("rid-exc-reg", dsctx.DefaultParseLimits())
		ctx.AddMatch(dsctx.DetectorMatch{Detector: "waf", RuleID: "942100", Category: "BLOCK", Severity: "HIGH", ScoreDelta: 50})
		ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_schema", RuleID: "schema.extra_field", Category: "OBSERVE", Severity: "MEDIUM", ScoreDelta: 10})
		ctx.AddMatch(dsctx.DetectorMatch{Detector: "identity", RuleID: "identity.token_present", Category: "INFO", Severity: "INFO"})
		ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_ratelimit", RuleID: "ratelimit.api_write_rate", Category: "RATE_LIMIT", Severity: "HIGH", ScoreDelta: 30})
		return ctx
	}

	base := build()
	baseAction := Decide(base, Input{Mode: ModeProtect})
	baseMatches := SnapshotMatches(base)

	for name, exceptions := range map[string][]ExceptionRef{"nil": nil, "empty": {}} {
		ctx := build()
		act := Decide(ctx, Input{Mode: ModeProtect, Exceptions: exceptions})
		if act != baseAction {
			t.Fatalf("%s exceptions: action=%s, want identical to baseline %s", name, act, baseAction)
		}
		matches := SnapshotMatches(ctx)
		if len(matches) != len(baseMatches) {
			t.Fatalf("%s exceptions: matches len=%d, want %d", name, len(matches), len(baseMatches))
		}
		for i := range matches {
			if matches[i].Excepted {
				t.Fatalf("%s exceptions: match[%d] must not be marked", name, i)
			}
			if matches[i].Detector != baseMatches[i].Detector || matches[i].RuleID != baseMatches[i].RuleID ||
				matches[i].Category != baseMatches[i].Category || matches[i].ScoreDelta != baseMatches[i].ScoreDelta {
				t.Fatalf("%s exceptions: match[%d] diverged: %+v vs %+v", name, i, matches[i], baseMatches[i])
			}
		}
	}
	if baseAction != dsctx.ActionBlock {
		t.Fatalf("baseline sanity: got %s, want BLOCK", baseAction)
	}
}
